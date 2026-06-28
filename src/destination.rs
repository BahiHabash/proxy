use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use tokio::net::{TcpStream, lookup_host};
use tokio::time::{Duration, timeout};

#[derive(Debug, Clone, Copy)]
pub struct DestinationPolicy {
    allow_private_destinations: bool,
}

impl DestinationPolicy {
    pub fn new(allow_private_destinations: bool) -> Self {
        Self {
            allow_private_destinations,
        }
    }

    pub fn validate_host(&self, host: &str, port: u16) -> Result<(), ConnectError> {
        if port == 0 {
            return Err(ConnectError::Blocked);
        }

        let host = normalize_host(host);
        if host.eq_ignore_ascii_case("localhost") {
            return self.allow_private();
        }

        if let Ok(ip) = host.parse::<IpAddr>() {
            self.validate_ip(ip)?;
        }

        Ok(())
    }

    fn validate_addr(&self, addr: SocketAddr) -> Result<(), ConnectError> {
        self.validate_ip(addr.ip())?;
        if addr.port() == 0 {
            return Err(ConnectError::Blocked);
        }
        Ok(())
    }

    fn validate_ip(&self, ip: IpAddr) -> Result<(), ConnectError> {
        if self.allow_private_destinations {
            return Ok(());
        }

        let blocked = match ip {
            IpAddr::V4(ip) => is_blocked_ipv4(ip),
            IpAddr::V6(ip) => is_blocked_ipv6(ip),
        };

        if blocked {
            Err(ConnectError::Blocked)
        } else {
            Ok(())
        }
    }

    fn allow_private(&self) -> Result<(), ConnectError> {
        if self.allow_private_destinations {
            Ok(())
        } else {
            Err(ConnectError::Blocked)
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ConnectError {
    #[error("destination blocked by policy")]
    Blocked,
    #[error("destination resolution failed: {0}")]
    Resolve(#[source] io::Error),
    #[error("upstream connection failed: {0}")]
    Connect(#[source] io::Error),
    #[error("upstream connection timed out")]
    Timeout,
}

pub async fn connect_tcp(
    host: &str,
    port: u16,
    timeout_duration: Duration,
    policy: DestinationPolicy,
) -> Result<TcpStream, ConnectError> {
    match timeout(timeout_duration, connect_tcp_inner(host, port, policy)).await {
        Ok(result) => result,
        Err(_) => Err(ConnectError::Timeout),
    }
}

async fn connect_tcp_inner(
    host: &str,
    port: u16,
    policy: DestinationPolicy,
) -> Result<TcpStream, ConnectError> {
    policy.validate_host(host, port)?;

    let normalized_host = normalize_host(host);
    if let Ok(ip) = normalized_host.parse::<IpAddr>() {
        let addr = SocketAddr::new(ip, port);
        policy.validate_addr(addr)?;
        return connect_addr(addr).await;
    }

    let resolved = lookup_host((normalized_host.as_str(), port))
        .await
        .map_err(ConnectError::Resolve)?;
    let mut allowed = Vec::new();
    for addr in resolved {
        if policy.validate_addr(addr).is_ok() {
            allowed.push(addr);
        }
    }

    if allowed.is_empty() {
        return Err(ConnectError::Blocked);
    }

    connect_addrs(&allowed).await
}

async fn connect_addr(addr: SocketAddr) -> Result<TcpStream, ConnectError> {
    let stream = TcpStream::connect(addr).await.map_err(ConnectError::Connect)?;
    let _ = stream.set_nodelay(true);
    Ok(stream)
}

async fn connect_addrs(addrs: &[SocketAddr]) -> Result<TcpStream, ConnectError> {
    let stream = TcpStream::connect(addrs)
        .await
        .map_err(ConnectError::Connect)?;
    let _ = stream.set_nodelay(true);
    Ok(stream)
}

fn normalize_host(host: &str) -> String {
    let trimmed = host.trim();
    if trimmed.starts_with('[') && trimmed.ends_with(']') {
        trimmed[1..trimmed.len() - 1].to_string()
    } else {
        trimmed.to_string()
    }
}

fn is_blocked_ipv4(ip: Ipv4Addr) -> bool {
    ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || ip.is_unspecified()
        || ip.is_multicast()
        || ip.is_broadcast()
        || ip.octets()[0] == 0
        || ip.octets()[0] == 100 && (64..=127).contains(&ip.octets()[1])
        || ip.octets()[0] == 169 && ip.octets()[1] == 254
        || ip.octets()[0] >= 224
}

fn is_blocked_ipv6(ip: Ipv6Addr) -> bool {
    ip.is_loopback()
        || ip.is_unspecified()
        || ip.is_multicast()
        || (ip.segments()[0] & 0xfe00) == 0xfc00
        || (ip.segments()[0] & 0xffc0) == 0xfe80
}

#[cfg(test)]
mod tests {
    use super::{ConnectError, DestinationPolicy};
    use std::net::IpAddr;

    #[test]
    fn blocks_private_destinations_by_default() {
        let policy = DestinationPolicy::new(false);
        assert!(matches!(
            policy.validate_host("127.0.0.1", 443),
            Err(ConnectError::Blocked)
        ));
        assert!(matches!(
            policy.validate_host("localhost", 443),
            Err(ConnectError::Blocked)
        ));
        assert!(matches!(
            policy.validate_host("169.254.169.254", 80),
            Err(ConnectError::Blocked)
        ));
        assert!(matches!(
            policy.validate_host("10.0.0.1", 443),
            Err(ConnectError::Blocked)
        ));
    }

    #[test]
    fn allows_public_destinations_by_default() {
        let policy = DestinationPolicy::new(false);
        assert!(policy.validate_host("8.8.8.8", 443).is_ok());
        assert!(policy.validate_host("api.openai.com", 443).is_ok());
    }

    #[test]
    fn private_destinations_can_be_enabled_for_local_testing() {
        let policy = DestinationPolicy::new(true);
        assert!(policy.validate_host("127.0.0.1", 443).is_ok());
        assert!(policy.validate_host("[::1]", 443).is_ok());
        assert!(policy.validate_host("localhost", 443).is_ok());
    }

    #[test]
    fn blocks_zero_port() {
        let policy = DestinationPolicy::new(true);
        assert!(matches!(
            policy.validate_host("8.8.8.8", 0),
            Err(ConnectError::Blocked)
        ));
    }

    #[test]
    fn ipv6_unique_local_is_blocked() {
        let policy = DestinationPolicy::new(false);
        let ip = "fc00::1".parse::<IpAddr>().unwrap();
        assert!(policy.validate_ip(ip).is_err());
    }
}
