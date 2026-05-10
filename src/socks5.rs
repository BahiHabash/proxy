//! SOCKS5 protocol implementation (RFC 1928 + RFC 1929).
//!
//! This module handles the byte-level handshake, authentication,
//! and connection-request parsing. It operates entirely on raw TCP
//! bytes and never inspects payload data (which is TLS-encrypted
//! for HTTPS destinations).

use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

// ─── Constants ──────────────────────────────────────────────────

const SOCKS_VERSION: u8 = 0x05;

// Authentication methods
const AUTH_USERNAME_PASSWORD: u8 = 0x02;
const AUTH_NO_ACCEPTABLE: u8 = 0xFF;

// Address types
const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;

// Commands
const CMD_CONNECT: u8 = 0x01;

// Reply codes
pub const REP_SUCCESS: u8 = 0x00;
pub const REP_GENERAL_FAILURE: u8 = 0x01;
pub const REP_CONNECTION_NOT_ALLOWED: u8 = 0x02;
pub const REP_NETWORK_UNREACHABLE: u8 = 0x03;
pub const REP_HOST_UNREACHABLE: u8 = 0x04;
pub const REP_CONNECTION_REFUSED: u8 = 0x05;
pub const REP_TTL_EXPIRED: u8 = 0x06;
pub const REP_COMMAND_NOT_SUPPORTED: u8 = 0x07;
pub const REP_ADDRESS_TYPE_NOT_SUPPORTED: u8 = 0x08;

// ─── Types ──────────────────────────────────────────────────────

/// Parsed destination from the SOCKS5 CONNECT request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TargetAddr {
    Ip4(Ipv4Addr, u16),
    Ip6(Ipv6Addr, u16),
    Domain(String, u16),
}

impl fmt::Display for TargetAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TargetAddr::Ip4(ip, port) => write!(f, "{}:{}", ip, port),
            TargetAddr::Ip6(ip, port) => write!(f, "[{}]:{}", ip, port),
            TargetAddr::Domain(host, port) => write!(f, "{}:{}", host, port),
        }
    }
}

impl TargetAddr {
    pub fn host(&self) -> String {
        match self {
            TargetAddr::Ip4(ip, _) => ip.to_string(),
            TargetAddr::Ip6(ip, _) => format!("[{}]", ip),
            TargetAddr::Domain(host, _) => host.clone(),
        }
    }

    pub fn port(&self) -> u16 {
        match self {
            TargetAddr::Ip4(_, p) | TargetAddr::Ip6(_, p) | TargetAddr::Domain(_, p) => *p,
        }
    }
}

/// Errors that can occur during the SOCKS5 handshake.
#[derive(Debug, thiserror::Error)]
pub enum HandshakeError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Invalid SOCKS version: {0:#04x} (expected 0x05)")]
    BadVersion(u8),
    #[error("Client does not support username/password authentication")]
    NoAcceptableAuth,
    #[error("Authentication failed")]
    AuthFailed,
    #[error("Invalid auth sub-negotiation version: {0:#04x}")]
    BadAuthVersion(u8),
    #[error("Unsupported command: {0:#04x} (only CONNECT is supported)")]
    UnsupportedCommand(u8),
    #[error("Unsupported address type: {0:#04x}")]
    UnsupportedAddrType(u8),
}

// ─── Handshake ──────────────────────────────────────────────────

/// Perform the full SOCKS5 handshake:
/// 1. Method negotiation → require username/password
/// 2. Authenticate against configured credentials
/// 3. Parse CONNECT request → return target address
pub async fn handshake(
    stream: &mut TcpStream,
    expected_user: &str,
    expected_pass: &str,
) -> Result<TargetAddr, HandshakeError> {
    // ── Step 1: Method selection ────────────────────────────────
    let version = stream.read_u8().await?;
    if version != SOCKS_VERSION {
        return Err(HandshakeError::BadVersion(version));
    }

    let nmethods = stream.read_u8().await?;
    let mut methods = vec![0u8; nmethods as usize];
    stream.read_exact(&mut methods).await?;

    if !methods.contains(&AUTH_USERNAME_PASSWORD) {
        // Tell client: no acceptable methods
        stream
            .write_all(&[SOCKS_VERSION, AUTH_NO_ACCEPTABLE])
            .await?;
        return Err(HandshakeError::NoAcceptableAuth);
    }

    // Tell client: use username/password
    stream
        .write_all(&[SOCKS_VERSION, AUTH_USERNAME_PASSWORD])
        .await?;

    // ── Step 2: Username/Password sub-negotiation (RFC 1929) ───
    let auth_ver = stream.read_u8().await?;
    if auth_ver != 0x01 {
        return Err(HandshakeError::BadAuthVersion(auth_ver));
    }

    let ulen = stream.read_u8().await? as usize;
    let mut uname = vec![0u8; ulen];
    stream.read_exact(&mut uname).await?;

    let plen = stream.read_u8().await? as usize;
    let mut passwd = vec![0u8; plen];
    stream.read_exact(&mut passwd).await?;

    let user_ok = uname.as_slice() == expected_user.as_bytes();
    let pass_ok = passwd.as_slice() == expected_pass.as_bytes();

    if !(user_ok && pass_ok) {
        // 0x01 = auth failure
        stream.write_all(&[0x01, 0x01]).await?;
        return Err(HandshakeError::AuthFailed);
    }

    // 0x00 = auth success
    stream.write_all(&[0x01, 0x00]).await?;

    // ── Step 3: CONNECT request ────────────────────────────────
    let ver = stream.read_u8().await?;
    if ver != SOCKS_VERSION {
        return Err(HandshakeError::BadVersion(ver));
    }

    let cmd = stream.read_u8().await?;
    let _rsv = stream.read_u8().await?; // reserved byte

    let atyp = stream.read_u8().await?;
    let target = match atyp {
        ATYP_IPV4 => {
            let mut buf = [0u8; 4];
            stream.read_exact(&mut buf).await?;
            let port = stream.read_u16().await?;
            TargetAddr::Ip4(Ipv4Addr::from(buf), port)
        }
        ATYP_DOMAIN => {
            let len = stream.read_u8().await? as usize;
            let mut buf = vec![0u8; len];
            stream.read_exact(&mut buf).await?;
            let port = stream.read_u16().await?;
            let domain = String::from_utf8_lossy(&buf).to_string();
            TargetAddr::Domain(domain, port)
        }
        ATYP_IPV6 => {
            let mut buf = [0u8; 16];
            stream.read_exact(&mut buf).await?;
            let port = stream.read_u16().await?;
            TargetAddr::Ip6(Ipv6Addr::from(buf), port)
        }
        _ => {
            send_reply(stream, REP_ADDRESS_TYPE_NOT_SUPPORTED).await?;
            return Err(HandshakeError::UnsupportedAddrType(atyp));
        }
    };

    if cmd != CMD_CONNECT {
        send_reply(stream, REP_COMMAND_NOT_SUPPORTED).await?;
        return Err(HandshakeError::UnsupportedCommand(cmd));
    }

    Ok(target)
}

/// Send a SOCKS5 reply to the client.
///
/// Uses a minimal BND.ADDR of 0.0.0.0:0 — the client doesn't
/// need the actual bound address for CONNECT requests.
pub async fn send_reply(stream: &mut TcpStream, reply: u8) -> std::io::Result<()> {
    //  +----+-----+-------+------+----------+----------+
    //  |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
    //  +----+-----+-------+------+----------+----------+
    let response = [
        SOCKS_VERSION,
        reply,
        0x00,      // RSV
        ATYP_IPV4, // BND.ADDR type
        0,
        0,
        0,
        0, // BND.ADDR = 0.0.0.0
        0,
        0, // BND.PORT = 0
    ];
    stream.write_all(&response).await?;
    stream.flush().await
}
