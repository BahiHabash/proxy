use socks5_proxy::{config::Config, proxy};
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::Notify;
use tracing::{error, info};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Will not fail; falls back to defaults.
    let _ = dotenvy::dotenv();

    let config = Config::from_env();
    config.init_logging();

    info!(
        bind = %config.bind_addr(),
        idle_timeout_secs = config.idle_timeout_secs,
        "SOCKS5 proxy starting"
    );

    let listener = TcpListener::bind(config.bind_addr()).await?;
    info!(addr = %listener.local_addr()?, "Listening for connections");

    let config = Arc::new(config);

    // ---------- graceful shutdown ----------
    let shutdown = Arc::new(Notify::new());
    {
        let shutdown = Arc::clone(&shutdown);
        ctrlc::set_handler(move || {
            info!("Shutdown signal received; draining connections");
            shutdown.notify_waiters();
        })?;
    }

    loop {
        tokio::select! {
            _ = shutdown.notified() => {
                info!("Shutting down gracefully");
                break;
            }
            result = listener.accept() => {
                match result {
                    Ok((stream, _peer)) => {
                        let cfg = Arc::clone(&config);
                        tokio::spawn(async move {
                            if let Err(e) = proxy::handle_client(stream, &cfg).await {
                                error!(error = %e, "Session failed");
                            }
                        });
                    }
                    Err(e) => {
                        error!(error = %e, "Accept failed");
                    }
                }
            }
        }
    }

    Ok(())
}
