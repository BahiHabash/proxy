//! Connection handler: performs protocol detection, then routes to
//! SOCKS5 or HTTP CONNECT. Relays bytes without logging identifying
//! connection metadata.

use crate::config::Config;
use crate::destination::{self, ConnectError, DestinationPolicy};
use crate::http_tunnel;
use crate::relay::{RelayConfig, RelayContext, RelayEngine};
use crate::resource::ResourceGovernor;
use crate::session::{ConnectionState, ProtocolKind, Session};
use crate::socks5::{
    self, HandshakeError, REP_CONNECTION_NOT_ALLOWED, REP_CONNECTION_REFUSED,
    REP_GENERAL_FAILURE, REP_HOST_UNREACHABLE, REP_NETWORK_UNREACHABLE, REP_SUCCESS,
};
use std::io::ErrorKind;
use tokio::net::TcpStream;
use tokio::time::{Duration, timeout};
use tracing::{Instrument, debug, info, info_span, warn};

/// Handle one client session end-to-end.
///
/// Peeks the first byte of the incoming stream to detect the protocol:
/// - `0x05` → SOCKS5 (full auth + CONNECT handshake)
/// - `0x43` (`C`) → HTTP CONNECT tunnel
/// - HTTP method bytes (`G`, `P`, `H`, `D`, `O`) → plain HTTP forwarding
/// - anything else → rejected immediately (silent close)
pub async fn handle_client(
    client: TcpStream,
    config: &Config,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let resources = ResourceGovernor::new(1);
    let permit = resources.acquire_session().await?;
    let session = Session::new(permit);
    handle_session(session, client, config).await
}

pub async fn handle_session(
    mut session: Session,
    client: TcpStream,
    config: &Config,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let _ = client.set_nodelay(true);
    // ── Protocol detection via peek ────────────────────────────
    session.set_state(ConnectionState::DetectingProtocol);
    let mut peek_buf = [0u8; 1];
    let detection_timeout = Duration::from_secs(config.protocol_detection_timeout_secs.max(1));
    let n = match timeout(detection_timeout, client.peek(&mut peek_buf)).await {
        Ok(result) => result?,
        Err(_elapsed) => {
            warn!(
                status = "PROTOCOL_DETECTION_TIMEOUT",
                "Client did not send protocol byte before timeout"
            );
            return Ok(());
        }
    };
    if n == 0 {
        // Client disconnected before sending any data.
        session.set_state(ConnectionState::Closed);
        return Ok(());
    }

    let result = match peek_buf[0] {
        0x05 => {
            session.set_protocol(ProtocolKind::Socks5);
            handle_socks5(&mut session, client, config).await
        }
        b'C' => {
            session.set_protocol(ProtocolKind::HttpConnect);
            debug!(status = "HTTP_CONNECT_DETECTED", "Routing to HTTP CONNECT handler");
            http_tunnel::handle_http_connect(&mut session, client, config).await
        }
        // Plain HTTP method bytes sent by clients that route http:// through
        // the proxy (e.g. Node.js proxy-from-env, MCP SSE connections).
        // We implement a basic forward-proxy: read the full request, connect
        // to the target host extracted from the absolute-form URI or Host
        // header, write the request verbatim, and relay the response.
        b'G' | b'P' | b'H' | b'D' | b'O' => {
            session.set_protocol(ProtocolKind::PlainHttp);
            debug!(status = "PLAIN_HTTP_DETECTED", "Routing to HTTP forward-proxy handler");
            http_tunnel::handle_plain_http(&mut session, client, config).await
        }
        other => {
            warn!(
                byte = format!("{:#04x}", other),
                status = "UNKNOWN_PROTOCOL",
                "Rejected connection: unrecognized protocol byte"
            );
            Ok(())
        }
    };

    session.set_state(ConnectionState::Closed);
    result
}



/// Handle one SOCKS5 client session end-to-end.
async fn handle_socks5(
    session: &mut Session,
    mut client: TcpStream,
    config: &Config,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    session.set_state(ConnectionState::Handshaking);
    let handshake_timeout = Duration::from_secs(config.socks5_handshake_timeout_secs.max(1));
    let target = match timeout(
        handshake_timeout,
        socks5::handshake(
            &mut client,
            &config.auth_username,
            &config.auth_password,
        ),
    )
    .await
    {
        Ok(Ok(target)) => target,
        Ok(Err(error)) => {
            if matches!(error, HandshakeError::AuthFailed) {
                session.mark_auth_failed();
            }
            log_handshake_error(&error);
            return Ok(());
        }
        Err(_elapsed) => {
            warn!(status = "SOCKS5_HANDSHAKE_TIMEOUT", "SOCKS5 handshake timed out");
            return Ok(());
        }
    };
    session.mark_authenticated();
    session.set_target(target.host(), target.port());

    let span = info_span!("socks5_tunnel", host = %target.host(), port = target.port());

    async {
        // Prevent proxy loop if the target is the proxy itself
        if target.port() == config.bind_port && (target.host() == "127.0.0.1" || target.host() == "::1" || target.host() == "localhost" || target.host() == config.bind_host) {
            warn!(status = "LOOP_DETECTED", "Rejected connection to proxy itself");
            let _ = socks5::send_reply(&mut client, REP_CONNECTION_NOT_ALLOWED).await;
            return Ok(());
        }

        let policy = DestinationPolicy::new(config.allow_private_destinations);
        if let Err(error) = policy.validate_host(&target.host(), target.port()) {
            let _ = socks5::send_reply(&mut client, REP_CONNECTION_NOT_ALLOWED).await;
            warn!(
                status = "DESTINATION_BLOCKED",
                reason = %error,
                "Rejected SOCKS5 destination by policy"
            );
            return Ok(());
        }

        debug!(status = "REQUEST_ACCEPTED", "CONNECT request accepted");

        session.set_state(ConnectionState::Connecting);
        let connect_timeout = Duration::from_secs(config.upstream_connection_timeout_sec);
        let upstream = match destination::connect_tcp(
            &target.host(),
            target.port(),
            connect_timeout,
            policy,
        )
        .await
        {
            Ok(stream) => {
                socks5::send_reply(&mut client, REP_SUCCESS).await?;
                debug!(status = "CONNECTED", "Upstream connection established");
                stream
            }
            Err(ConnectError::Connect(error)) => {
                let reply = match error.kind() {
                    ErrorKind::ConnectionRefused => REP_CONNECTION_REFUSED,
                    ErrorKind::AddrNotAvailable | ErrorKind::ConnectionAborted => {
                        REP_HOST_UNREACHABLE
                    }
                    _ if error.to_string().contains("unreachable") => REP_NETWORK_UNREACHABLE,
                    _ => REP_GENERAL_FAILURE,
                };
                let _ = socks5::send_reply(&mut client, reply).await;
                warn!(
                    status = "CONNECT_FAILED",
                    error_kind = ?error.kind(),
                    "Failed to connect upstream"
                );
                return Ok(());
            }
            Err(ConnectError::Resolve(error)) => {
                let _ = socks5::send_reply(&mut client, REP_HOST_UNREACHABLE).await;
                warn!(
                    status = "RESOLVE_FAILED",
                    error_kind = ?error.kind(),
                    "Failed to resolve upstream"
                );
                return Ok(());
            }
            Err(ConnectError::Blocked) => {
                let _ = socks5::send_reply(&mut client, REP_CONNECTION_NOT_ALLOWED).await;
                warn!(status = "DESTINATION_BLOCKED", "Rejected SOCKS5 destination by policy");
                return Ok(());
            }
            Err(ConnectError::Timeout) => {
                let _ = socks5::send_reply(&mut client, REP_GENERAL_FAILURE).await;
                warn!(status = "CONNECT_TIMEOUT", "Upstream connection timed out");
                return Ok(());
            }
        };

        session.set_state(ConnectionState::Relaying);
        let relay = RelayEngine::new(RelayConfig::new(
            config.relay_buffer_bytes,
            Duration::from_secs(config.idle_timeout_secs),
            Duration::from_secs(config.relay_write_timeout_secs.max(1)),
        ));
        let _outcome = relay
            .relay(
                client,
                upstream,
                RelayContext {
                    session_id: session.id(),
                    protocol: session.protocol(),
                    target: session.target().cloned(),
                    cancellation: session.cancellation(),
                },
            )
            .await;

        info!(status = "CLOSED", "SOCKS5 session complete");
        Ok(())
    }
    .instrument(span)
    .await
}

fn log_handshake_error(error: &HandshakeError) {
    match error {
        HandshakeError::AuthFailed => {
            warn!(status = "AUTH_FAILED", "Authentication rejected");
        }
        _ => {
            warn!(
                status = "HANDSHAKE_FAILED",
                error = %error,
                "SOCKS5 handshake failed"
            );
        }
    }
}

