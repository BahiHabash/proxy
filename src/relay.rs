use crate::session::{ProtocolKind, SessionCancellation, SessionId, TargetInfo};
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicU64, Ordering},
};
use std::time::Instant;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::Notify;
use tokio::time::{Duration, sleep, timeout};
use tracing::{debug, warn};

#[derive(Debug, Clone)]
pub struct RelayConfig {
    pub buffer_size: usize,
    pub idle_timeout: Duration,
    pub write_timeout: Duration,
}

impl RelayConfig {
    pub fn new(buffer_size: usize, idle_timeout: Duration, write_timeout: Duration) -> Self {
        Self {
            buffer_size: buffer_size.max(1024),
            idle_timeout,
            write_timeout,
        }
    }
}

#[derive(Clone)]
pub struct RelayContext {
    pub session_id: SessionId,
    pub protocol: ProtocolKind,
    pub target: Option<TargetInfo>,
    pub cancellation: SessionCancellation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayDirection {
    Upload,
    Download,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelayCloseReason {
    Completed,
    IdleTimeout,
    Cancelled,
    WriteTimeout { direction: RelayDirection },
    ReadError { direction: RelayDirection },
    WriteError { direction: RelayDirection },
    JoinError,
}

#[derive(Debug, Clone)]
pub struct RelayOutcome {
    pub close_reason: RelayCloseReason,
    pub uploaded_bytes: u64,
    pub downloaded_bytes: u64,
    pub duration: Duration,
}

#[derive(Clone)]
pub struct RelayEngine {
    config: RelayConfig,
}

impl RelayEngine {
    pub fn new(config: RelayConfig) -> Self {
        Self { config }
    }

    pub async fn relay<A, B>(&self, client: A, upstream: B, context: RelayContext) -> RelayOutcome
    where
        A: AsyncRead + AsyncWrite + Unpin + Send + 'static,
        B: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let started = Instant::now();
        let cancel = Arc::new(RelayCancel::default());
        let last_activity_ms = Arc::new(AtomicU64::new(0));

        let (client_rd, client_wr) = tokio::io::split(client);
        let (upstream_rd, upstream_wr) = tokio::io::split(upstream);

        debug!(
            session_id = context.session_id.get(),
            protocol = ?context.protocol,
            "Relay started"
        );

        let external_cancel = {
            let cancel = Arc::clone(&cancel);
            let cancellation = context.cancellation.clone();
            tokio::spawn(async move {
                cancellation.cancelled().await;
                cancel.cancel(CancelCause::External);
            })
        };

        let watchdog = {
            let cancel = Arc::clone(&cancel);
            let last_activity_ms = Arc::clone(&last_activity_ms);
            let idle_timeout = self.config.idle_timeout;
            tokio::spawn(async move {
                idle_watchdog(started, idle_timeout, last_activity_ms, cancel).await;
            })
        };

        let upload = tokio::spawn(relay_direction(
            client_rd,
            upstream_wr,
            RelayDirection::Upload,
            self.config.buffer_size,
            self.config.write_timeout,
            started,
            Arc::clone(&last_activity_ms),
            Arc::clone(&cancel),
        ));
        let download = tokio::spawn(relay_direction(
            upstream_rd,
            client_wr,
            RelayDirection::Download,
            self.config.buffer_size,
            self.config.write_timeout,
            started,
            Arc::clone(&last_activity_ms),
            Arc::clone(&cancel),
        ));

        let (upload_result, download_result) = tokio::join!(upload, download);
        external_cancel.abort();
        watchdog.abort();

        let upload_result = upload_result.unwrap_or(DirectionResult {
            reason: DirectionCloseReason::JoinError,
            bytes: 0,
        });
        let download_result = download_result.unwrap_or(DirectionResult {
            reason: DirectionCloseReason::JoinError,
            bytes: 0,
        });

        let close_reason = close_reason(
            upload_result.reason,
            download_result.reason,
            cancel.cause(),
        );
        if !matches!(close_reason, RelayCloseReason::Completed | RelayCloseReason::Cancelled) {
            warn!(
                session_id = context.session_id.get(),
                reason = ?close_reason,
                "Relay closed with non-clean reason"
            );
        } else {
            debug!(
                session_id = context.session_id.get(),
                reason = ?close_reason,
                "Relay closed"
            );
        }

        RelayOutcome {
            close_reason,
            uploaded_bytes: upload_result.bytes,
            downloaded_bytes: download_result.bytes,
            duration: started.elapsed(),
        }
    }
}

#[derive(Default)]
struct RelayCancel {
    cancelled: AtomicBool,
    cause: AtomicU64,
    notify: Notify,
}

impl RelayCancel {
    fn cancel(&self, cause: CancelCause) {
        let _ = self.cause.compare_exchange(
            CancelCause::None.as_u64(),
            cause.as_u64(),
            Ordering::Relaxed,
            Ordering::Relaxed,
        );
        self.cancelled.store(true, Ordering::Release);
        self.notify.notify_waiters();
    }

    fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }

    async fn cancelled(&self) {
        if self.is_cancelled() {
            return;
        }

        loop {
            let notified = self.notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();

            if self.is_cancelled() {
                return;
            }

            notified.await;
            if self.is_cancelled() {
                return;
            }
        }
    }

    fn cause(&self) -> CancelCause {
        CancelCause::from_u64(self.cause.load(Ordering::Relaxed))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CancelCause {
    None,
    Idle,
    External,
    Error,
}

impl CancelCause {
    fn as_u64(self) -> u64 {
        match self {
            CancelCause::None => 0,
            CancelCause::Idle => 1,
            CancelCause::External => 2,
            CancelCause::Error => 3,
        }
    }

    fn from_u64(value: u64) -> Self {
        match value {
            1 => CancelCause::Idle,
            2 => CancelCause::External,
            3 => CancelCause::Error,
            _ => CancelCause::None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DirectionCloseReason {
    Eof,
    Cancelled,
    WriteTimeout,
    ReadError,
    WriteError,
    JoinError,
}

#[derive(Debug)]
struct DirectionResult {
    reason: DirectionCloseReason,
    bytes: u64,
}

async fn relay_direction<R, W>(
    mut reader: R,
    mut writer: W,
    direction: RelayDirection,
    buffer_size: usize,
    write_timeout: Duration,
    started: Instant,
    last_activity_ms: Arc<AtomicU64>,
    cancel: Arc<RelayCancel>,
) -> DirectionResult
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
{
    let mut buffer = vec![0_u8; buffer_size];
    let mut bytes_total = 0_u64;

    loop {
        let bytes_read = tokio::select! {
            _ = cancel.cancelled() => {
                return DirectionResult { reason: DirectionCloseReason::Cancelled, bytes: bytes_total };
            }
            result = reader.read(&mut buffer) => {
                match result {
                    Ok(0) => {
                        let _ = writer.shutdown().await;
                        return DirectionResult { reason: DirectionCloseReason::Eof, bytes: bytes_total };
                    }
                    Ok(n) => n,
                    Err(error) => {
                        warn!(direction = ?direction, error_kind = ?error.kind(), "Relay read error");
                        cancel.cancel(CancelCause::Error);
                        let _ = writer.shutdown().await;
                        return DirectionResult { reason: DirectionCloseReason::ReadError, bytes: bytes_total };
                    }
                }
            }
        };

        mark_activity(started, &last_activity_ms);

        let write = timeout(write_timeout, writer.write_all(&buffer[..bytes_read])).await;
        match write {
            Ok(Ok(())) => {
                bytes_total += bytes_read as u64;
                mark_activity(started, &last_activity_ms);
            }
            Ok(Err(error)) => {
                warn!(direction = ?direction, error_kind = ?error.kind(), "Relay write error");
                cancel.cancel(CancelCause::Error);
                let _ = writer.shutdown().await;
                return DirectionResult {
                    reason: DirectionCloseReason::WriteError,
                    bytes: bytes_total,
                };
            }
            Err(_) => {
                warn!(direction = ?direction, "Relay write timed out");
                cancel.cancel(CancelCause::Error);
                let _ = writer.shutdown().await;
                return DirectionResult {
                    reason: DirectionCloseReason::WriteTimeout,
                    bytes: bytes_total,
                };
            }
        }

        if cancel.is_cancelled() {
            return DirectionResult {
                reason: DirectionCloseReason::Cancelled,
                bytes: bytes_total,
            };
        }
    }
}

async fn idle_watchdog(
    started: Instant,
    idle_timeout: Duration,
    last_activity_ms: Arc<AtomicU64>,
    cancel: Arc<RelayCancel>,
) {
    if idle_timeout.is_zero() {
        return;
    }

    let check_every = (idle_timeout / 4).clamp(Duration::from_millis(100), Duration::from_secs(1));
    loop {
        sleep(check_every).await;
        if cancel.is_cancelled() {
            return;
        }

        let elapsed_ms = started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64;
        let last = last_activity_ms.load(Ordering::Relaxed);
        let idle_for = elapsed_ms.saturating_sub(last);
        if idle_for >= idle_timeout.as_millis().min(u128::from(u64::MAX)) as u64 {
            cancel.cancel(CancelCause::Idle);
            return;
        }
    }
}

fn mark_activity(started: Instant, last_activity_ms: &AtomicU64) {
    let elapsed_ms = started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64;
    last_activity_ms.store(elapsed_ms, Ordering::Relaxed);
}

fn close_reason(
    upload: DirectionCloseReason,
    download: DirectionCloseReason,
    cancel_cause: CancelCause,
) -> RelayCloseReason {
    use DirectionCloseReason as D;

    match (upload, download) {
        (D::WriteTimeout, _) => RelayCloseReason::WriteTimeout {
            direction: RelayDirection::Upload,
        },
        (_, D::WriteTimeout) => RelayCloseReason::WriteTimeout {
            direction: RelayDirection::Download,
        },
        (D::ReadError, _) => RelayCloseReason::ReadError {
            direction: RelayDirection::Upload,
        },
        (_, D::ReadError) => RelayCloseReason::ReadError {
            direction: RelayDirection::Download,
        },
        (D::WriteError, _) => RelayCloseReason::WriteError {
            direction: RelayDirection::Upload,
        },
        (_, D::WriteError) => RelayCloseReason::WriteError {
            direction: RelayDirection::Download,
        },
        (D::JoinError, _) | (_, D::JoinError) => RelayCloseReason::JoinError,
        (D::Cancelled, D::Cancelled) => match cancel_cause {
            CancelCause::Idle => RelayCloseReason::IdleTimeout,
            _ => RelayCloseReason::Cancelled,
        },
        (D::Eof, D::Eof) => RelayCloseReason::Completed,
        (D::Eof, D::Cancelled) | (D::Cancelled, D::Eof) => RelayCloseReason::Completed,
    }
}

#[cfg(test)]
mod tests {
    use super::{RelayCloseReason, RelayConfig, RelayContext, RelayDirection, RelayEngine};
    use crate::resource::ResourceGovernor;
    use crate::session::{ProtocolKind, Session};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::time::{Duration, timeout};

    async fn context() -> RelayContext {
        let governor = ResourceGovernor::new(1);
        let permit = governor.acquire_session().await.unwrap();
        let session = Session::new(permit);
        RelayContext {
            session_id: session.id(),
            protocol: ProtocolKind::Socks5,
            target: None,
            cancellation: session.cancellation(),
        }
    }

    #[tokio::test]
    async fn relays_bidirectional_bytes() {
        let (mut client_side, proxy_client) = tokio::io::duplex(1024);
        let (proxy_upstream, mut upstream_side) = tokio::io::duplex(1024);
        let engine = RelayEngine::new(RelayConfig::new(
            1024,
            Duration::from_secs(5),
            Duration::from_secs(5),
        ));
        let relay = tokio::spawn(async move { engine.relay(proxy_client, proxy_upstream, context().await).await });

        client_side.write_all(b"ping").await.unwrap();
        let mut upstream_buf = [0_u8; 4];
        upstream_side.read_exact(&mut upstream_buf).await.unwrap();
        assert_eq!(&upstream_buf, b"ping");

        upstream_side.write_all(b"pong").await.unwrap();
        let mut client_buf = [0_u8; 4];
        client_side.read_exact(&mut client_buf).await.unwrap();
        assert_eq!(&client_buf, b"pong");

        client_side.shutdown().await.unwrap();
        upstream_side.shutdown().await.unwrap();
        let outcome = relay.await.unwrap();
        assert_eq!(outcome.close_reason, RelayCloseReason::Completed);
        assert_eq!(outcome.uploaded_bytes, 4);
        assert_eq!(outcome.downloaded_bytes, 4);
    }

    #[tokio::test]
    async fn active_download_keeps_quiet_upload_alive() {
        let (mut client_side, proxy_client) = tokio::io::duplex(1024);
        let (proxy_upstream, mut upstream_side) = tokio::io::duplex(1024);
        let engine = RelayEngine::new(RelayConfig::new(
            1024,
            Duration::from_millis(120),
            Duration::from_secs(5),
        ));
        let relay = tokio::spawn(async move { engine.relay(proxy_client, proxy_upstream, context().await).await });

        for index in 0..5_u8 {
            upstream_side.write_all(&[index]).await.unwrap();
            let mut byte = [0_u8; 1];
            timeout(Duration::from_secs(1), client_side.read_exact(&mut byte))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(byte[0], index);
            tokio::time::sleep(Duration::from_millis(60)).await;
        }

        upstream_side.shutdown().await.unwrap();
        client_side.shutdown().await.unwrap();
        let outcome = relay.await.unwrap();
        assert_eq!(outcome.close_reason, RelayCloseReason::Completed);
        assert_eq!(outcome.downloaded_bytes, 5);
    }

    #[tokio::test]
    async fn write_stall_times_out() {
        let (_client_side, proxy_client) = tokio::io::duplex(64);
        let (proxy_upstream, mut upstream_side) = tokio::io::duplex(8192);
        let engine = RelayEngine::new(RelayConfig::new(
            1024,
            Duration::from_secs(5),
            Duration::from_millis(100),
        ));
        let relay = tokio::spawn(async move { engine.relay(proxy_client, proxy_upstream, context().await).await });

        upstream_side.write_all(&vec![42_u8; 4096]).await.unwrap();
        let outcome = timeout(Duration::from_secs(2), relay)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            outcome.close_reason,
            RelayCloseReason::WriteTimeout {
                direction: RelayDirection::Download,
            }
        );
    }

    #[tokio::test]
    async fn external_cancellation_stops_relay() {
        let (_client_side, proxy_client) = tokio::io::duplex(1024);
        let (proxy_upstream, _upstream_side) = tokio::io::duplex(1024);
        let context = context().await;
        let cancellation = context.cancellation.clone();
        let engine = RelayEngine::new(RelayConfig::new(
            1024,
            Duration::from_secs(5),
            Duration::from_secs(5),
        ));
        let relay = tokio::spawn(async move { engine.relay(proxy_client, proxy_upstream, context).await });

        tokio::task::yield_now().await;
        cancellation.cancel();
        let outcome = timeout(Duration::from_secs(1), relay)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(outcome.close_reason, RelayCloseReason::Cancelled);
    }

    #[tokio::test]
    async fn cancellation_before_relay_starts_is_observed() {
        let (_client_side, proxy_client) = tokio::io::duplex(1024);
        let (proxy_upstream, _upstream_side) = tokio::io::duplex(1024);
        let context = context().await;
        context.cancellation.cancel();
        let engine = RelayEngine::new(RelayConfig::new(
            1024,
            Duration::from_secs(5),
            Duration::from_secs(5),
        ));

        let outcome = timeout(
            Duration::from_secs(1),
            engine.relay(proxy_client, proxy_upstream, context),
        )
        .await
        .unwrap();
        assert_eq!(outcome.close_reason, RelayCloseReason::Cancelled);
    }
}
