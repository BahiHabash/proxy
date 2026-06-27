//! HTTP CONNECT tunnel handler.
//!
//! This module provides support for HTTP CONNECT proxy requests (used for
//! HTTPS tunnelling). Clients are authenticated via Proxy-Authorization
//! Basic header using the same credentials as the SOCKS5 handler.

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use crate::config::Config;
use crate::proxy;
use std::io;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{Duration, timeout};
use tracing::{debug, info, warn, Instrument, info_span};

const MAX_HEADER_BYTES: usize = 8192;
const CONNECTION_ESTABLISHED: &[u8] = b"HTTP/1.1 200 Connection Established\r\n\r\n";
const BAD_REQUEST: &[u8] = b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";
const HEADER_TOO_LARGE: &[u8] = b"HTTP/1.1 431 Request Header Fields Too Large\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";
const BAD_GATEWAY: &[u8] = b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";
const GATEWAY_TIMEOUT: &[u8] = b"HTTP/1.1 504 Gateway Timeout\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";
const FORBIDDEN: &[u8] = b"HTTP/1.1 403 Forbidden\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";

/// 407 with keep-alive — sent when we challenge the client to provide credentials.
/// We do NOT include `Connection: close` so the client can retry on the same socket.
const PROXY_AUTH_REQUIRED: &[u8] =
    b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"proxy\"\r\nContent-Length: 0\r\n\r\n";

/// 407 with close — sent after too many failed attempts.
const PROXY_AUTH_REQUIRED_CLOSE: &[u8] =
    b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"proxy\"\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectTarget {
    pub host: String,
    pub port: u16,
}

/// Handle an HTTP CONNECT tunnel request.
///
/// Authenticates the client via `Proxy-Authorization: Basic` header
/// using the same credentials configured for SOCKS5.
///
/// RFC 7235 compliance: after a 407 the connection is kept alive so the
/// client (e.g. Node.js/npm) can retry CONNECT with credentials on the
/// same TCP socket without reconnecting.
pub async fn handle_http_connect(
    mut client: TcpStream,
    config: &Config,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // RFC 7235: after a 407 the proxy keeps the connection open so the
    // client can retry on the same TCP socket with credentials.
    // Node.js / npm (and many other HTTP stacks) rely on this: they never
    // open a second connection after a 407; they just re-send CONNECT on
    // the same one.
    //
    // However, some clients (e.g. undici, the engine behind Codex CLI) do NOT
    // support 407 retry on the same connection — they close the socket after a
    // 407 and open a fresh one with credentials. To avoid holding dead slots
    // open for `upstream_connection_timeout_sec` (30s) × N concurrent init
    // connections, we use a short 2-second timeout on retry reads: if the
    // client closed after 407 we detect EOF fast and the new connection
    // (which arrives with credentials already set) gets served immediately.
    const MAX_AUTH_ATTEMPTS: u8 = 3;
    const RETRY_READ_TIMEOUT_SECS: u64 = 2;
    let mut auth_attempts: u8 = 0;

    let target = loop {
        // ── Read full HTTP header ──────────────────────────────────
        // First attempt uses the full connection timeout; subsequent attempts
        // (after a 407 challenge) use a short timeout so dead connections
        // are cleaned up quickly.
        let header_timeout = if auth_attempts == 0 {
            Duration::from_secs(config.upstream_connection_timeout_sec)
        } else {
            Duration::from_secs(RETRY_READ_TIMEOUT_SECS)
        };
        let header = match read_connect_header(&mut client, header_timeout).await? {
            Some(header) => header,
            None => return Ok(()),
        };

        // ── Parse CONNECT target ───────────────────────────────────
        let target = match parse_connect_target(&header) {
            Some(target) => target,
            None => {
                warn!(status = "BAD_REQUEST", "Invalid HTTP CONNECT request");
                write_error_response(&mut client, BAD_REQUEST).await?;
                return Ok(());
            }
        };

        // ── Authenticate via Proxy-Authorization header ────────────
        let header_str = String::from_utf8_lossy(&header);
        match parse_proxy_auth(&header_str) {
            Some((user, pass)) if user == config.auth_username && pass == config.auth_password => {
                // Auth OK — proceed to tunnel
                break target;
            }
            Some(_) => {
                auth_attempts += 1;
                warn!(
                    status = "AUTH_FAILED",
                    attempt = auth_attempts,
                    "HTTP CONNECT authentication rejected"
                );
                if auth_attempts >= MAX_AUTH_ATTEMPTS {
                    // Too many failures — close the connection
                    write_error_response(&mut client, PROXY_AUTH_REQUIRED_CLOSE).await?;
                    return Ok(());
                }
                // Keep connection alive — client can retry with correct credentials
                write_response(&mut client, PROXY_AUTH_REQUIRED).await?;
            }
            None => {
                auth_attempts += 1;
                warn!(
                    status = "AUTH_MISSING",
                    attempt = auth_attempts,
                    "HTTP CONNECT missing Proxy-Authorization header"
                );
                if auth_attempts >= MAX_AUTH_ATTEMPTS {
                    write_error_response(&mut client, PROXY_AUTH_REQUIRED_CLOSE).await?;
                    return Ok(());
                }
                // Keep connection alive — client is expected to retry with credentials
                write_response(&mut client, PROXY_AUTH_REQUIRED).await?;
            }
        }
    };

    let span = info_span!("http_tunnel", host = %target.host, port = target.port);

    async {
        // Prevent proxy loop if the target is the proxy itself
        if target.port == config.bind_port
            && (target.host == "127.0.0.1"
                || target.host == "::1"
                || target.host == "localhost"
                || target.host == config.bind_host)
        {
            warn!(
                status = "LOOP_DETECTED",
                "Rejected connection to proxy itself"
            );
            write_error_response(&mut client, FORBIDDEN).await?;
            return Ok(());
        }

        debug!(status = "HTTP_CONNECT", "HTTP CONNECT request accepted");

        let connect_timeout = Duration::from_secs(config.upstream_connection_timeout_sec);
        let upstream = match timeout(
            connect_timeout,
            TcpStream::connect(format!("{}:{}", target.host, target.port)),
        )
        .await
        {
            Ok(Ok(stream)) => stream,
            Ok(Err(error)) => {
                warn!(
                    status = "UPSTREAM_FAILED",
                    error_kind = ?error.kind(),
                    "Failed to connect upstream for HTTP tunnel"
                );
                write_error_response(&mut client, BAD_GATEWAY).await?;
                return Ok(());
            }
            Err(_elapsed) => {
                warn!(status = "UPSTREAM_TIMEOUT", "Upstream connection timed out");
                write_error_response(&mut client, GATEWAY_TIMEOUT).await?;
                return Ok(());
            }
        };

        write_response(&mut client, CONNECTION_ESTABLISHED).await?;
        debug!(status = "TUNNEL_ESTABLISHED", "HTTP tunnel established");

        relay_with_idle(
            client,
            upstream,
            Duration::from_secs(config.idle_timeout_secs),
        )
        .await;

        info!(status = "TUNNEL_CLOSED", "HTTP tunnel closed");

        Ok(())
    }
    .instrument(span)
    .await
}

async fn read_connect_header(
    client: &mut TcpStream,
    idle_timeout: Duration,
) -> io::Result<Option<Vec<u8>>> {
    let mut header = Vec::with_capacity(512);
    let mut byte = [0_u8; 1];

    loop {
        let read = match timeout(idle_timeout, client.read(&mut byte)).await {
            Ok(result) => result?,
            Err(_elapsed) => {
                warn!(status = "HEADER_TIMEOUT", "HTTP CONNECT header timed out");
                return Ok(None);
            }
        };

        if read == 0 {
            return Ok(None);
        }

        header.push(byte[0]);
        if header.len() > MAX_HEADER_BYTES {
            write_error_response(client, HEADER_TOO_LARGE).await?;
            return Ok(None);
        }

        if header.ends_with(b"\r\n\r\n") || header.ends_with(b"\n\n") {
            return Ok(Some(header));
        }
    }
}

fn parse_connect_target(header: &[u8]) -> Option<ConnectTarget> {
    let header = std::str::from_utf8(header).ok()?;
    let request_line = header.lines().next()?;
    let mut parts = request_line.split_whitespace();

    let method = parts.next()?;
    if !method.eq_ignore_ascii_case("CONNECT") {
        return None;
    }

    let authority = parts.next()?;
    let version = parts.next()?;
    // Accept HTTP/1.0 and HTTP/1.1 — some AI tooling wrappers (e.g. older
    // curl builds, Codex CLI helpers) send HTTP/1.0 CONNECT requests.
    if version != "HTTP/1.1" && version != "HTTP/1.0" {
        return None;
    }
    if parts.next().is_some() {
        return None;
    }

    let (host, port) = parse_authority(authority, Some(443))?;
    Some(ConnectTarget { host, port })
}

/// Extract username and password from the `Proxy-Authorization: Basic <b64>` header.
///
/// Fully case-insensitive on both the header name and the `Basic` scheme —
/// many HTTP clients and AI agent frameworks (e.g. Codex CLI, LangChain HTTP
/// adapters) send lowercase or mixed-case variants.
fn parse_proxy_auth(header: &str) -> Option<(String, String)> {
    // "proxy-authorization:" is exactly 20 characters.
    const HEADER_NAME: &str = "proxy-authorization:";

    for line in header.lines() {
        let line = line.trim();
        if line.len() <= HEADER_NAME.len() {
            continue;
        }
        let (prefix, rest) = line.split_at(HEADER_NAME.len());
        if !prefix.eq_ignore_ascii_case(HEADER_NAME) {
            continue;
        }
        let value = rest.trim();
        // Accept both "Basic " and "basic " (RFC 7235 is case-insensitive on scheme)
        let b64 = if value.len() > 6 && value[..6].eq_ignore_ascii_case("basic ") {
            value[6..].trim()
        } else {
            continue;
        };
        let decoded = BASE64.decode(b64).ok()?;
        let decoded_str = String::from_utf8(decoded).ok()?;
        // Split on the first ':' only — passwords may contain colons (RFC 7617)
        let (user, pass) = decoded_str.split_once(':')?;
        return Some((user.to_string(), pass.to_string()));
    }
    None
}

fn parse_authority(authority: &str, default_port: Option<u16>) -> Option<(String, u16)> {
    if authority.is_empty() {
        return None;
    }

    if authority.starts_with('[') {
        let bracket_end = authority.find(']')?;
        let host = &authority[..=bracket_end];
        if authority.as_bytes().get(bracket_end + 1) == Some(&b':') {
            let port = authority[bracket_end + 2..].parse().ok()?;
            return Some((host.to_string(), port));
        } else if let Some(p) = default_port {
            return Some((host.to_string(), p));
        } else {
            return None;
        }
    }

    if let Some(colon) = authority.rfind(':') {
        let host = &authority[..colon];
        if host.is_empty() || host.contains(':') {
            return None;
        }
        let port = authority[colon + 1..].parse().ok()?;
        Some((host.to_string(), port))
    } else {
        let host = authority;
        if host.is_empty() || host.contains(':') {
            return None;
        }
        if let Some(p) = default_port {
            Some((host.to_string(), p))
        } else {
            None
        }
    }
}

async fn write_response(client: &mut TcpStream, response: &[u8]) -> io::Result<()> {
    client.write_all(response).await?;
    client.flush().await
}

async fn write_error_response(client: &mut TcpStream, response: &[u8]) -> io::Result<()> {
    client.write_all(response).await?;
    client.flush().await?;
    let _ = client.shutdown().await;
    Ok(())
}

async fn relay_with_idle(client: TcpStream, upstream: TcpStream, idle_timeout: Duration) {
    let (client_rd, client_wr) = client.into_split();
    let (upstream_rd, upstream_wr) = upstream.into_split();

    let upload = tokio::spawn(proxy::relay_with_idle(
        client_rd,
        upstream_wr,
        idle_timeout,
        "http_upload",
    ));
    let download = tokio::spawn(proxy::relay_with_idle(
        upstream_rd,
        client_wr,
        idle_timeout,
        "http_download",
    ));

    let _ = tokio::join!(upload, download);
}

/// Forward-proxy handler for plain `http://` requests.
///
/// Called when the first byte is a plain HTTP method (`G`, `P`, `H`, `D`, `O`).
/// Clients like Node.js `proxy-from-env` route ALL traffic (both `http://` and
/// `https://`) through `HTTPS_PROXY`. For `http://` targets they send the full
/// request in absolute-form (`GET http://host/path HTTP/1.1`) to the proxy
/// rather than using `CONNECT`.
///
/// This handler:
/// 1. Reads the full request header.
/// 2. Checks `Proxy-Authorization` (same credentials as CONNECT).
/// 3. Extracts the target host/port from the absolute-form URI or `Host` header.
/// 4. Connects to the upstream and writes the rewritten request (origin-form).
/// 5. Relays the response back to the client.
pub async fn handle_plain_http(
    mut client: TcpStream,
    config: &Config,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Read the full HTTP request header.
    let header = match read_connect_header(
        &mut client,
        Duration::from_secs(config.upstream_connection_timeout_sec),
    )
    .await?
    {
        Some(h) => h,
        None => return Ok(()),
    };

    let header_str = match std::str::from_utf8(&header) {
        Ok(s) => s,
        Err(_) => {
            write_error_response(&mut client, BAD_REQUEST).await?;
            return Ok(());
        }
    };

    // ── Authenticate ─────────────────────────────────────────────
    match parse_proxy_auth(header_str) {
        Some((user, pass)) if user == config.auth_username && pass == config.auth_password => {}
        Some(_) => {
            warn!(status = "AUTH_FAILED", "Plain HTTP proxy authentication rejected");
            write_error_response(&mut client, PROXY_AUTH_REQUIRED_CLOSE).await?;
            return Ok(());
        }
        None => {
            warn!(status = "AUTH_MISSING", "Plain HTTP proxy missing Proxy-Authorization");
            write_error_response(&mut client, PROXY_AUTH_REQUIRED_CLOSE).await?;
            return Ok(());
        }
    }

    // ── Parse request line to extract target ────────────────────
    // Expected: `METHOD http://host[:port]/path HTTP/1.x`
    let request_line = match header_str.lines().next() {
        Some(l) => l,
        None => {
            write_error_response(&mut client, BAD_REQUEST).await?;
            return Ok(());
        }
    };
    let mut parts = request_line.split_whitespace();
    let method = match parts.next() { Some(m) => m, None => { write_error_response(&mut client, BAD_REQUEST).await?; return Ok(()); } };
    let uri    = match parts.next() { Some(u) => u, None => { write_error_response(&mut client, BAD_REQUEST).await?; return Ok(()); } };
    let version = match parts.next() { Some(v) => v, None => { write_error_response(&mut client, BAD_REQUEST).await?; return Ok(()); } };

    // Strip scheme to get authority + path
    let without_scheme = if let Some(rest) = uri.strip_prefix("http://") {
        rest
    } else {
        // Not an absolute-form URI — fall back to Host header
        uri
    };

    // Split authority from path: "host:port/path" → ("host:port", "/path")
    let (authority, path) = if let Some(idx) = without_scheme.find('/') {
        (&without_scheme[..idx], &without_scheme[idx..])
    } else {
        (without_scheme, "/")
    };

    // Parse host and port
    let (host, port) = match parse_authority(authority, Some(80)) {
        Some(hp) => hp,
        None => {
            // Fall back to Host header
            let host_line = header_str
                .lines()
                .find(|l| l.len() > 5 && l[..5].eq_ignore_ascii_case("host:"));
            match host_line.and_then(|l| parse_authority(l[5..].trim(), Some(80))) {
                Some(hp) => hp,
                None => {
                    warn!(status = "BAD_REQUEST", "Could not determine target host for plain HTTP");
                    write_error_response(&mut client, BAD_REQUEST).await?;
                    return Ok(());
                }
            }
        }
    };

    let span = info_span!("http_forward", host = %host, port = port);

    async move {
        let connect_timeout = Duration::from_secs(config.upstream_connection_timeout_sec);
        let mut upstream = match timeout(
            connect_timeout,
            TcpStream::connect(format!("{}:{}", host, port)),
        )
        .await
        {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => {
                warn!(status = "UPSTREAM_FAILED", error_kind = ?e.kind(), "Plain HTTP upstream connect failed");
                write_error_response(&mut client, BAD_GATEWAY).await?;
                return Ok(());
            }
            Err(_) => {
                warn!(status = "UPSTREAM_TIMEOUT", "Plain HTTP upstream connect timed out");
                write_error_response(&mut client, GATEWAY_TIMEOUT).await?;
                return Ok(());
            }
        };

        // Rewrite the request: replace absolute-form URI with origin-form,
        // strip Proxy-Authorization and Proxy-Connection headers.
        let rewritten = rewrite_plain_http_request(method, path, version, header_str);
        if let Err(e) = upstream.write_all(rewritten.as_bytes()).await {
            warn!(status = "UPSTREAM_WRITE_FAILED", error_kind = ?e.kind(), "Failed to write request to upstream");
            write_error_response(&mut client, BAD_GATEWAY).await?;
            return Ok(());
        }

        debug!(status = "HTTP_FORWARD", host = %host, port = port, "Plain HTTP request forwarded");

        relay_with_idle(client, upstream, Duration::from_secs(config.idle_timeout_secs)).await;

        info!(status = "HTTP_FORWARD_CLOSED", "Plain HTTP forward session closed");
        Ok(())
    }
    .instrument(span)
    .await
}

/// Rewrite a plain HTTP request for forwarding:
/// - Replace absolute-form URI with origin-form (`/path`)
/// - Remove `Proxy-Authorization` and `Proxy-Connection` hop-by-hop headers
fn rewrite_plain_http_request(method: &str, path: &str, version: &str, header: &str) -> String {
    let mut out = format!("{} {} {}\r\n", method, path, version);
    // Skip the first line (request line) and rebuild headers
    for line in header.lines().skip(1) {
        let lower = line.to_ascii_lowercase();
        if lower.starts_with("proxy-authorization:") || lower.starts_with("proxy-connection:") {
            continue; // Strip proxy-specific headers before forwarding
        }
        out.push_str(line);
        out.push_str("\r\n");
    }
    out
}
