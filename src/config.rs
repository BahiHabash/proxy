use crate::logging::SizeRotatingFile;
use std::env;
use tracing_subscriber::{EnvFilter, fmt, prelude::*};

/// Runtime configuration sourced from environment variables.
#[derive(Debug, Clone)]
pub struct Config {
    /// Address to bind (e.g. "0.0.0.0")
    pub bind_host: String,
    /// Port to listen on
    pub bind_port: u16,
    /// SOCKS5 authentication username
    pub auth_username: String,
    /// SOCKS5 authentication password
    pub auth_password: String,
    /// Idle socket timeout in seconds (both halves)
    pub idle_timeout_secs: u64,
    /// Log format: "json" for structured, anything else for pretty-print
    pub log_format: String,
    /// Upstream connection timeout in seconds
    pub upstream_connection_timeout_sec: u64,
    /// Per-direction relay buffer size in bytes
    pub relay_buffer_bytes: usize,
    /// Timeout for a stalled relay write
    pub relay_write_timeout_secs: u64,
    /// Maximum concurrently active accepted client sessions
    pub max_connections: usize,
    /// Timeout for receiving the first protocol byte
    pub protocol_detection_timeout_secs: u64,
    /// Timeout for the SOCKS5 negotiation and request handshake
    pub socks5_handshake_timeout_secs: u64,
    /// Timeout for reading HTTP proxy request headers
    pub http_header_timeout_secs: u64,
    /// Delay after accept errors, especially descriptor exhaustion
    pub accept_error_backoff_ms: u64,
    /// Minimum seconds between repeated accept-error log entries
    pub accept_error_log_interval_secs: u64,
    /// Emit logs to stdout/stderr-compatible writer
    pub log_to_stdout: bool,
    /// Emit logs to a bounded local file
    pub log_to_file: bool,
    /// Directory used when file logging is enabled
    pub log_dir: String,
    /// Maximum bytes for the active file log before rotation
    pub log_max_file_bytes: u64,
    /// Maximum rotated file count to retain
    pub log_max_files: usize,
    /// Allow upstream destinations in private/local/link-local address ranges
    pub allow_private_destinations: bool,
    /// Maximum seconds to wait for active sessions during graceful shutdown
    pub shutdown_timeout_secs: u64,
}

impl Config {
    /// Build config from environment variables with sensible defaults.
    ///
    /// # Environment Variables
    ///
    /// | Variable              | Default       | Description                         |
    /// |-----------------------|---------------|-------------------------------------|
    /// | `PROXY_HOST`          | `0.0.0.0`     | Bind address                        |
    /// | `PROXY_PORT`          | `1080`        | Bind port                           |
    /// | `PROXY_USER`          | *(required)*  | SOCKS5 username                     |
    /// | `PROXY_PASS`          | *(required)*  | SOCKS5 password                     |
    /// | `IDLE_TIMEOUT_SECS`   | `300`         | Idle timeout before socket close    |
    /// | `RUST_LOG`            | `info`        | Tracing filter directive            |
    /// | `LOG_FORMAT`          | `pretty`      | `json` for structured logs          |
    pub fn from_env() -> Self {
        let auth_username =
            env::var("PROXY_USER").expect("PROXY_USER environment variable is required");
        let auth_password =
            env::var("PROXY_PASS").expect("PROXY_PASS environment variable is required");

        Config {
            bind_host: env::var("PROXY_HOST").unwrap_or_else(|_| "0.0.0.0".into()),
            bind_port: env::var("PROXY_PORT")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(1080),
            auth_username,
            auth_password,
            idle_timeout_secs: env::var("IDLE_TIMEOUT_SECS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(300),
            log_format: env::var("LOG_FORMAT").unwrap_or_else(|_| "pretty".into()),
            upstream_connection_timeout_sec: env::var("UPSTREAM_CONNECTION_TIMEOUT_SEC")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(30),
            relay_buffer_bytes: env::var("RELAY_BUFFER_BYTES")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(16 * 1024),
            relay_write_timeout_secs: env::var("RELAY_WRITE_TIMEOUT_SECS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(60),
            max_connections: env::var("MAX_CONNECTIONS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(1024),
            protocol_detection_timeout_secs: env::var("PROTOCOL_DETECTION_TIMEOUT_SECS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(5),
            socks5_handshake_timeout_secs: env::var("SOCKS5_HANDSHAKE_TIMEOUT_SECS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(10),
            http_header_timeout_secs: env::var("HTTP_HEADER_TIMEOUT_SECS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(10),
            accept_error_backoff_ms: env::var("ACCEPT_ERROR_BACKOFF_MS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(250),
            accept_error_log_interval_secs: env::var("ACCEPT_ERROR_LOG_INTERVAL_SECS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(5),
            log_to_stdout: parse_bool_env("LOG_TO_STDOUT", true),
            log_to_file: parse_bool_env("LOG_TO_FILE", false),
            log_dir: env::var("LOG_DIR").unwrap_or_else(|_| "logs".into()),
            log_max_file_bytes: env::var("LOG_MAX_FILE_BYTES")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(10 * 1024 * 1024),
            log_max_files: env::var("LOG_MAX_FILES")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(5),
            allow_private_destinations: parse_bool_env("ALLOW_PRIVATE_DESTINATIONS", false),
            shutdown_timeout_secs: env::var("SHUTDOWN_TIMEOUT_SECS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(30),
        }
    }

    /// Full bind address string.
    pub fn bind_addr(&self) -> String {
        format!("{}:{}", self.bind_host, self.bind_port)
    }

    /// Initialize the global tracing subscriber.
    pub fn init_logging(&self) -> Option<tracing_appender::non_blocking::WorkerGuard> {
        let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

        let file_writer = if self.log_to_file {
            match SizeRotatingFile::new(
                &self.log_dir,
                "proxy.log",
                self.log_max_file_bytes,
                self.log_max_files,
            ) {
                Ok(writer) => Some(tracing_appender::non_blocking(writer)),
                Err(error) => {
                    eprintln!("Failed to initialize file logging: {}", error);
                    None
                }
            }
        } else {
            None
        };

        let stdout_enabled = self.log_to_stdout || file_writer.is_none();

        match (self.log_format.as_str(), stdout_enabled, file_writer) {
            ("json", true, Some((non_blocking, guard))) => {
                tracing_subscriber::registry()
                    .with(filter)
                    .with(fmt::layer().json().with_writer(std::io::stdout))
                    .with(fmt::layer().json().with_writer(non_blocking))
                    .init();
                Some(guard)
            }
            ("json", false, Some((non_blocking, guard))) => {
                tracing_subscriber::registry()
                    .with(filter)
                    .with(fmt::layer().json().with_writer(non_blocking))
                    .init();
                Some(guard)
            }
            ("json", _, None) => {
                tracing_subscriber::registry()
                    .with(filter)
                    .with(fmt::layer().json().with_writer(std::io::stdout))
                    .init();
                None
            }
            (_, true, Some((non_blocking, guard))) => {
                tracing_subscriber::registry()
                    .with(filter)
                    .with(fmt::layer().pretty().with_writer(std::io::stdout))
                    .with(fmt::layer().pretty().with_writer(non_blocking))
                    .init();
                Some(guard)
            }
            (_, false, Some((non_blocking, guard))) => {
                tracing_subscriber::registry()
                    .with(filter)
                    .with(fmt::layer().pretty().with_writer(non_blocking))
                    .init();
                Some(guard)
            }
            (_, _, None) => {
                tracing_subscriber::registry()
                    .with(filter)
                    .with(fmt::layer().pretty().with_writer(std::io::stdout))
                    .init();
                None
            }
        }
    }
}

fn parse_bool_env(name: &str, default: bool) -> bool {
    match env::var(name) {
        Ok(value) => matches!(
            value.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        ),
        Err(_) => default,
    }
}
