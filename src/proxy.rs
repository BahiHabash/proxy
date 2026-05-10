//! Connection handler: performs the SOCKS5 handshake, opens the upstream
//! connection, and relays bytes without logging identifying connection
//! metadata.

use crate::config::Config;
use crate::socks5::{
    self, HandshakeError, REP_CONNECTION_REFUSED, REP_GENERAL_FAILURE, REP_HOST_UNREACHABLE,
    REP_NETWORK_UNREACHABLE, REP_SUCCESS, TargetAddr,
};
use std::io::{self, ErrorKind};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::task::JoinError;
use tokio::time::{Duration, timeout};
use tracing::{Instrument, error, info, info_span, warn};

/// Handle one SOCKS5 client session end-to-end.
pub async fn handle_client(
    mut client: TcpStream,
    config: &Config,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let span = info_span!("session");

    async {
        let target = match socks5::handshake(
            &mut client,
            &config.auth_username,
            &config.auth_password,
        )
        .await
        {
            Ok(target) => target,
            Err(error) => {
                log_handshake_error(&error);
                return Ok(());
            }
        };

        info!(status = "REQUEST_ACCEPTED", "CONNECT request accepted");

        let connect_timeout = Duration::from_secs(config.upstream_connection_timeout_sec);
        let upstream_result = match &target {
            TargetAddr::Domain(host, port) => {
                timeout(
                    connect_timeout,
                    TcpStream::connect(format!("{}:{}", host, port)),
                )
                .await
            }
            TargetAddr::Ip4(ip, port) => {
                timeout(connect_timeout, TcpStream::connect((*ip, *port))).await
            }
            TargetAddr::Ip6(ip, port) => {
                timeout(connect_timeout, TcpStream::connect((*ip, *port))).await
            }
        };

        let upstream = match upstream_result {
            Ok(Ok(stream)) => {
                socks5::send_reply(&mut client, REP_SUCCESS).await?;
                info!(status = "CONNECTED", "Upstream connection established");
                stream
            }
            Ok(Err(error)) => {
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
            Err(_elapsed) => {
                let _ = socks5::send_reply(&mut client, REP_GENERAL_FAILURE).await;
                warn!(status = "CONNECT_TIMEOUT", "Upstream connection timed out");
                return Ok(());
            }
        };

        let (client_rd, client_wr) = client.into_split();
        let (upstream_rd, upstream_wr) = upstream.into_split();
        let idle_timeout = Duration::from_secs(config.idle_timeout_secs);

        let upload = tokio::spawn(relay_with_idle(
            client_rd,
            upstream_wr,
            idle_timeout,
            "upload",
        ));
        let download = tokio::spawn(relay_with_idle(
            upstream_rd,
            client_wr,
            idle_timeout,
            "download",
        ));

        let (upload_result, download_result) = tokio::join!(upload, download);
        log_relay_result("upload", upload_result);
        log_relay_result("download", download_result);

        info!(status = "CLOSED", "Session complete");
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

async fn relay_with_idle<R, W>(
    mut reader: R,
    mut writer: W,
    idle_timeout: Duration,
    direction: &'static str,
) -> io::Result<()>
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
{
    let mut buffer = [0_u8; 8192];

    loop {
        let bytes_read = match timeout(idle_timeout, reader.read(&mut buffer)).await {
            Ok(Ok(0)) => break,
            Ok(Ok(bytes_read)) => bytes_read,
            Ok(Err(error)) => {
                let _ = writer.shutdown().await;
                return Err(error);
            }
            Err(_elapsed) => {
                warn!(
                    direction = direction,
                    status = "IDLE_TIMEOUT",
                    "Idle timeout; closing relay"
                );
                break;
            }
        };

        if let Err(error) = writer.write_all(&buffer[..bytes_read]).await {
            let _ = writer.shutdown().await;
            return Err(error);
        }
    }

    writer.shutdown().await
}

fn log_relay_result(direction: &'static str, result: Result<io::Result<()>, JoinError>) {
    match result {
        Ok(Ok(())) => {}
        Ok(Err(error)) => {
            warn!(
                direction = direction,
                status = "RELAY_ERROR",
                error_kind = ?error.kind(),
                "Relay closed after I/O error"
            );
        }
        Err(error) => {
            error!(
                direction = direction,
                status = "RELAY_TASK_FAILED",
                error = %error,
                "Relay task failed"
            );
        }
    }
}
