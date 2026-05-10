//! HTTP CONNECT tunnel handler.
//!
//! This module provides a fallback for clients that send HTTP CONNECT
//! requests instead of speaking SOCKS5. Because this path bypasses
//! SOCKS5 username/password authentication, connections are restricted
//! to loopback clients (`127.0.0.1` / `::1`) only.

use crate::config::Config;
use std::net::IpAddr;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::time::{Duration, timeout};
use tracing::{info, warn};

/// Maximum number of header bytes we are willing to buffer before
/// giving up. Prevents a malicious client from consuming memory.
const MAX_HEADER_BYTES: usize = 8192;

/// HTTP response sent back once the upstream tunnel is established.
const CONNECTION_ESTABLISHED: &[u8] = b"HTTP/1.1 200 Connection Established\r\n\r\n";

/// Handle an HTTP CONNECT tunnel request.
///
/// # Security
///
/// This handler **only** accepts connections from loopback addresses
/// (`127.0.0.1` or `::1`). Any other source IP is immediately rejected.
/// This prevents the proxy from becoming an open relay when deployed on
/// a public VPS.
pub async fn handle_http_connect(
    mut client: TcpStream,
    config: &Config,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // ── Security: reject non-loopback clients ──────────────────
    let peer_ip = client.peer_addr()?.ip();
    if !is_loopback(&peer_ip) {
        warn!(
            peer = %peer_ip,
            status = "REJECTED",
            "HTTP CONNECT rejected: non-loopback client"
        );
        client
            .write_all(b"HTTP/1.1 403 Forbidden\r\n\r\n")
            .await?;
        return Ok(());
    }

    // ── Read HTTP headers ──────────────────────────────────────
    let mut reader = BufReader::new(&mut client);
    let mut header_buf = String::with_capacity(512);
    let mut total_bytes = 0usize;

    loop {
        let mut line = String::new();
        let n = reader.read_line(&mut line).await?;
        if n == 0 {
            // Client disconnected before sending complete headers.
            return Ok(());
        }
        total_bytes += n;
        if total_bytes > MAX_HEADER_BYTES {
            client
                .write_all(b"HTTP/1.1 431 Request Header Fields Too Large\r\n\r\n")
                .await
                .ok();
            return Ok(());
        }
        // Blank line terminates headers.
        if line == "\r\n" || line == "\n" {
            break;
        }
        header_buf.push_str(&line);
    }
    // We are done borrowing `client` through `reader` here.

    // ── Parse CONNECT target ───────────────────────────────────
    let (host, port) = match parse_connect_target(&header_buf) {
        Some(parsed) => parsed,
        None => {
            warn!(
                status = "BAD_REQUEST",
                "Could not parse CONNECT target from HTTP request"
            );
            client
                .write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n")
                .await?;
            return Ok(());
        }
    };

    info!(
        status = "HTTP_CONNECT",
        host = %host,
        port = port,
        "HTTP CONNECT request accepted"
    );

    // ── Connect to upstream ────────────────────────────────────
    let connect_timeout = Duration::from_secs(config.upstream_connection_timeout_sec);
    let upstream = match timeout(
        connect_timeout,
        TcpStream::connect(format!("{}:{}", host, port)),
    )
    .await
    {
        Ok(Ok(stream)) => stream,
        Ok(Err(e)) => {
            warn!(
                status = "UPSTREAM_FAILED",
                error = %e,
                "Failed to connect to upstream for HTTP tunnel"
            );
            client
                .write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
                .await?;
            return Ok(());
        }
        Err(_elapsed) => {
            warn!(status = "UPSTREAM_TIMEOUT", "Upstream connection timed out");
            client
                .write_all(b"HTTP/1.1 504 Gateway Timeout\r\n\r\n")
                .await?;
            return Ok(());
        }
    };

    // ── Signal success and relay ───────────────────────────────
    client.write_all(CONNECTION_ESTABLISHED).await?;
    info!(status = "TUNNEL_ESTABLISHED", "HTTP tunnel established, relaying bytes");

    let mut upstream = upstream;
    match tokio::io::copy_bidirectional(&mut client, &mut upstream).await {
        Ok((up, down)) => {
            info!(
                status = "TUNNEL_CLOSED",
                uploaded_bytes = up,
                downloaded_bytes = down,
                "HTTP tunnel closed"
            );
        }
        Err(e) => {
            // Normal: one side closed the connection.
            if e.kind() != std::io::ErrorKind::NotConnected {
                warn!(
                    status = "TUNNEL_ERROR",
                    error = %e,
                    "HTTP tunnel relay error"
                );
            }
        }
    }

    Ok(())
}

/// Check whether an IP is a loopback address.
fn is_loopback(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_loopback(),
        IpAddr::V6(v6) => v6.is_loopback(),
    }
}

/// Extract (host, port) from the first line of an HTTP CONNECT request.
///
/// Expected format: `CONNECT host:port HTTP/1.x\r\n`
fn parse_connect_target(headers: &str) -> Option<(String, u16)> {
    let first_line = headers.lines().next()?;
    let mut parts = first_line.split_whitespace();

    let method = parts.next()?;
    if !method.eq_ignore_ascii_case("CONNECT") {
        return None;
    }

    let authority = parts.next()?;

    // authority is "host:port" — the host may be an IPv6 literal in brackets.
    if let Some(bracket_end) = authority.find(']') {
        // IPv6: [::1]:port
        let host = &authority[..=bracket_end];
        let port_str = authority.get(bracket_end + 2..)?; // skip "]:"
        let port = port_str.parse().ok()?;
        Some((host.to_string(), port))
    } else {
        // IPv4 or domain: host:port
        let colon = authority.rfind(':')?;
        let host = &authority[..colon];
        let port: u16 = authority[colon + 1..].parse().ok()?;
        Some((host.to_string(), port))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_domain() {
        let headers = "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n";
        let (host, port) = parse_connect_target(headers).unwrap();
        assert_eq!(host, "example.com");
        assert_eq!(port, 443);
    }

    #[test]
    fn parse_ip() {
        let headers = "CONNECT 192.168.1.1:8080 HTTP/1.1\r\n";
        let (host, port) = parse_connect_target(headers).unwrap();
        assert_eq!(host, "192.168.1.1");
        assert_eq!(port, 8080);
    }

    #[test]
    fn parse_ipv6() {
        let headers = "CONNECT [::1]:443 HTTP/1.1\r\n";
        let (host, port) = parse_connect_target(headers).unwrap();
        assert_eq!(host, "[::1]");
        assert_eq!(port, 443);
    }

    #[test]
    fn parse_bad_method() {
        let headers = "GET / HTTP/1.1\r\n";
        assert!(parse_connect_target(headers).is_none());
    }
}
