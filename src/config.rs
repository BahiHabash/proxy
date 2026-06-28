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
        }
    }

    /// Full bind address string.
    pub fn bind_addr(&self) -> String {
        format!("{}:{}", self.bind_host, self.bind_port)
    }

    /// Initialize the global tracing subscriber.
    pub fn init_logging(&self) -> tracing_appender::non_blocking::WorkerGuard {
        let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

        // Ensure the logs directory exists to prevent "os error 2" when building the rolling file appender
        if let Err(e) = std::fs::create_dir_all("logs") {
            eprintln!("Failed to create logs directory: {}", e);
        }

        let file_appender = tracing_appender::rolling::Builder::new()
            .rotation(tracing_appender::rolling::Rotation::DAILY)
            .filename_prefix("proxy.log")
            .max_log_files(5)
            .build("logs")
            .expect("failed to initialize rolling file appender");

        let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);

        if self.log_format == "json" {
            tracing_subscriber::registry()
                .with(filter)
                .with(fmt::layer().json().with_writer(non_blocking))
                .with(fmt::layer().json().with_writer(std::io::stdout))
                .init();
        } else {
            tracing_subscriber::registry()
                .with(filter)
                .with(fmt::layer().pretty().with_writer(non_blocking))
                .with(fmt::layer().pretty().with_writer(std::io::stdout))
                .init();
        }

        guard
    }
}
