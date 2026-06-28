use proxy::config::Config;
use proxy::proxy as proxy_handler;
use proxy::resource::ResourceGovernor;
use proxy::session::{Session, SessionCancellation};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;
use tokio::net::TcpListener;
use tokio::sync::watch;
use tokio::task::JoinSet;
use tokio::time::{Duration, sleep};
use tracing::{error, info, warn};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Will not fail; falls back to defaults.
    let _ = dotenvy::dotenv();

    let config = Config::from_env();
    let _log_guard = config.init_logging();

    info!(
        bind = %config.bind_addr(),
        idle_timeout_secs = config.idle_timeout_secs,
        max_connections = config.max_connections,
        allow_private_destinations = config.allow_private_destinations,
        "SOCKS5 proxy starting"
    );

    let listener = TcpListener::bind(config.bind_addr()).await?;
    info!(addr = %listener.local_addr()?, "Listening for connections");

    let accept_backoff = Duration::from_millis(config.accept_error_backoff_ms.max(1));
    let mut accept_error_log = LogThrottle::new(Duration::from_secs(
        config.accept_error_log_interval_secs.max(1),
    ));
    let resources = ResourceGovernor::new(config.max_connections);
    let shutdown_timeout = Duration::from_secs(config.shutdown_timeout_secs.max(1));
    let config = Arc::new(config);
    let mut sessions: JoinSet<(u64, Result<(), String>)> = JoinSet::new();
    let mut active_sessions: HashMap<u64, SessionCancellation> = HashMap::new();

    // ---------- graceful shutdown ----------
    let (shutdown_tx, mut shutdown_rx) = watch::channel(false);
    {
        let shutdown_tx = shutdown_tx.clone();
        ctrlc::set_handler(move || {
            let _ = shutdown_tx.send(true);
        })?;
    }

    let mut shutting_down = false;
    loop {
        if shutting_down {
            break;
        }

        tokio::select! {
            _ = wait_for_shutdown(&mut shutdown_rx) => {
                info!(
                    active_sessions = active_sessions.len(),
                    "Shutdown signal received; draining active sessions"
                );
                shutting_down = true;
            }
            Some(result) = sessions.join_next(), if !sessions.is_empty() => {
                handle_finished_session(result, &mut active_sessions);
            }
            permit = resources.acquire_session() => {
                let permit = match permit {
                    Ok(permit) => permit,
                    Err(_) => {
                        warn!("Resource governor closed; stopping listener");
                        break;
                    }
                };

                let mut accept_shutdown_rx = shutdown_rx.clone();
                let result = tokio::select! {
                    _ = wait_for_shutdown(&mut accept_shutdown_rx) => {
                        drop(permit);
                        info!(
                            active_sessions = active_sessions.len(),
                            "Shutdown signal received; stopping listener"
                        );
                        shutting_down = true;
                        continue;
                    }
                    result = listener.accept() => result,
                };
                match result {
                    Ok((stream, _peer)) => {
                        let _ = stream.set_nodelay(true);
                        let cfg = Arc::clone(&config);
                        let session = Session::new(permit);
                        let session_id = session.id().get();
                        active_sessions.insert(session_id, session.cancellation());
                        sessions.spawn(async move {
                            let result = proxy_handler::handle_session(session, stream, &cfg)
                                .await
                                .map_err(|error| error.to_string());
                            (session_id, result)
                        });
                    }
                    Err(e) => {
                        drop(permit);
                        if let Some(suppressed) = accept_error_log.should_log() {
                            error!(
                                error = %e,
                                suppressed,
                                "Accept failed"
                            );
                        }
                        sleep(accept_backoff).await;
                    }
                }
            }
        }
    }

    if !active_sessions.is_empty() {
        info!(
            active_sessions = active_sessions.len(),
            timeout_secs = shutdown_timeout.as_secs(),
            "Cancelling active sessions"
        );
        for cancellation in active_sessions.values() {
            cancellation.cancel();
        }

        let drain_deadline = sleep(shutdown_timeout);
        tokio::pin!(drain_deadline);
        while !sessions.is_empty() {
            tokio::select! {
                result = sessions.join_next() => {
                    if let Some(result) = result {
                        handle_finished_session(result, &mut active_sessions);
                    } else {
                        break;
                    }
                }
                _ = &mut drain_deadline => {
                    warn!(
                        active_sessions = active_sessions.len(),
                        "Shutdown drain timed out; remaining sessions will be dropped"
                    );
                    break;
                }
            }
        }
    }

    info!("Shutdown complete");
    Ok(())
}

async fn wait_for_shutdown(shutdown: &mut watch::Receiver<bool>) {
    if *shutdown.borrow() {
        return;
    }

    while shutdown.changed().await.is_ok() {
        if *shutdown.borrow() {
            return;
        }
    }
}

fn handle_finished_session(
    result: Result<(u64, Result<(), String>), tokio::task::JoinError>,
    active_sessions: &mut HashMap<u64, SessionCancellation>,
) {
    match result {
        Ok((session_id, Ok(()))) => {
            active_sessions.remove(&session_id);
        }
        Ok((session_id, Err(error))) => {
            active_sessions.remove(&session_id);
            error!(session_id, error = %error, "Session failed");
        }
        Err(error) => {
            error!(error = %error, "Session task failed");
        }
    }
}

struct LogThrottle {
    interval: Duration,
    next_log_at: Instant,
    suppressed: u64,
}

impl LogThrottle {
    fn new(interval: Duration) -> Self {
        Self {
            interval,
            next_log_at: Instant::now(),
            suppressed: 0,
        }
    }

    fn should_log(&mut self) -> Option<u64> {
        let now = Instant::now();
        if now >= self.next_log_at {
            let suppressed = self.suppressed;
            self.suppressed = 0;
            self.next_log_at = now + self.interval;
            Some(suppressed)
        } else {
            self.suppressed = self.suppressed.saturating_add(1);
            None
        }
    }
}
