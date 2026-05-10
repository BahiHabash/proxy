//! HTTP CONNECT tunnel handler.
//!
//! This module provides a fallback for local clients that send HTTP CONNECT
//! requests instead of speaking SOCKS5.

use crate::config::Config;
use crate::proxy;
use std::io;
use std::net::IpAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{Duration, timeout};
use tracing::{debug, info, warn, Instrument, info_span};

const MAX_HEADER_BYTES: usize = 8192;
const CONNECTION_ESTABLISHED: &[u8] = b"HTTP/1.1 200 Connection Established\r\n\r\n";
const FORBIDDEN: &[u8] = b"HTTP/1.1 403 Forbidden\r\n\r\n";
const BAD_REQUEST: &[u8] = b"HTTP/1.1 400 Bad Request\r\n\r\n";
const HEADER_TOO_LARGE: &[u8] = b"HTTP/1.1 431 Request Header Fields Too Large\r\n\r\n";
const BAD_GATEWAY: &[u8] = b"HTTP/1.1 502 Bad Gateway\r\n\r\n";
const GATEWAY_TIMEOUT: &[u8] = b"HTTP/1.1 504 Gateway Timeout\r\n\r\n";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectTarget {
    pub host: String,
    pub port: u16,
}

/// Handle an HTTP CONNECT tunnel request.
///
/// This path is intentionally limited to loopback clients because it does not
/// use SOCKS5 username/password authentication.
pub async fn handle_http_connect(
    mut client: TcpStream,
    config: &Config,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if !is_loopback(&client.peer_addr()?.ip()) {
        warn!(
            status = "REJECTED",
            "HTTP CONNECT rejected: non-loopback client"
        );
        write_response(&mut client, FORBIDDEN).await?;
        return Ok(());
    }

    let header =
        match read_connect_header(&mut client, Duration::from_secs(config.idle_timeout_secs))
            .await?
        {
            Some(header) => header,
            None => return Ok(()),
        };

    let target = match parse_connect_target(&header) {
        Some(target) => target,
        None => {
            warn!(status = "BAD_REQUEST", "Invalid HTTP CONNECT request");
            write_response(&mut client, BAD_REQUEST).await?;
            return Ok(());
        }
    };

    let span = info_span!("http_tunnel", host = %target.host, port = target.port);
    
    async {
        // Prevent proxy loop if the target is the proxy itself
        if target.port == config.bind_port && (target.host == "127.0.0.1" || target.host == "::1" || target.host == "localhost" || target.host == config.bind_host) {
            warn!(status = "LOOP_DETECTED", "Rejected connection to proxy itself");
            write_response(&mut client, FORBIDDEN).await?;
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
                write_response(&mut client, BAD_GATEWAY).await?;
                return Ok(());
            }
            Err(_elapsed) => {
                warn!(status = "UPSTREAM_TIMEOUT", "Upstream connection timed out");
                write_response(&mut client, GATEWAY_TIMEOUT).await?;
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
            write_response(client, HEADER_TOO_LARGE).await?;
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
    if !version.starts_with("HTTP/") || parts.next().is_some() {
        return None;
    }

    let (host, port) = parse_authority(authority)?;
    Some(ConnectTarget { host, port })
}

fn parse_authority(authority: &str) -> Option<(String, u16)> {
    if authority.is_empty() {
        return None;
    }

    if authority.starts_with('[') {
        let bracket_end = authority.find(']')?;
        if authority.as_bytes().get(bracket_end + 1) != Some(&b':') {
            return None;
        }
        let host = &authority[..=bracket_end];
        let port = authority[bracket_end + 2..].parse().ok()?;
        return Some((host.to_string(), port));
    }

    let colon = authority.rfind(':')?;
    let host = &authority[..colon];
    if host.is_empty() || host.contains(':') {
        return None;
    }
    let port = authority[colon + 1..].parse().ok()?;
    Some((host.to_string(), port))
}

async fn write_response(client: &mut TcpStream, response: &[u8]) -> io::Result<()> {
    client.write_all(response).await?;
    client.flush().await
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

fn is_loopback(ip: &IpAddr) -> bool {
    ip.is_loopback()
}
