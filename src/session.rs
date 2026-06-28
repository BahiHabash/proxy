use crate::resource::SessionPermit;
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicU64, Ordering},
};
use std::time::Instant;
use tokio::sync::Notify;

static NEXT_SESSION_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionId(u64);

impl SessionId {
    pub fn get(self) -> u64 {
        self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolKind {
    Unknown,
    Socks5,
    HttpConnect,
    PlainHttp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthState {
    Unauthenticated,
    Authenticated,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    Accepted,
    DetectingProtocol,
    Handshaking,
    Connecting,
    Relaying,
    Closing,
    Closed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetInfo {
    pub host: String,
    pub port: u16,
}

#[derive(Clone)]
pub struct SessionCancellation {
    inner: Arc<SessionCancellationInner>,
}

struct SessionCancellationInner {
    cancelled: AtomicBool,
    notify: Notify,
}

impl SessionCancellation {
    fn new() -> Self {
        Self {
            inner: Arc::new(SessionCancellationInner {
                cancelled: AtomicBool::new(false),
                notify: Notify::new(),
            }),
        }
    }

    pub fn cancel(&self) {
        let was_cancelled = self.inner.cancelled.swap(true, Ordering::Release);
        if !was_cancelled {
            self.inner.notify.notify_waiters();
        }
    }

    pub fn is_cancelled(&self) -> bool {
        self.inner.cancelled.load(Ordering::Acquire)
    }

    pub async fn cancelled(&self) {
        if self.is_cancelled() {
            return;
        }

        loop {
            let notified = self.inner.notify.notified();
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
}

/// Per-client lifecycle metadata and resource ownership.
///
/// Session intentionally stores no payload bytes, headers, prompts, responses,
/// or stream buffers. It owns only operational state needed to manage one
/// isolated client connection.
pub struct Session {
    id: SessionId,
    started_at: Instant,
    protocol: ProtocolKind,
    auth_state: AuthState,
    target: Option<TargetInfo>,
    state: ConnectionState,
    cancellation: SessionCancellation,
    _permit: SessionPermit,
}

impl Session {
    pub fn new(permit: SessionPermit) -> Self {
        Self {
            id: SessionId(NEXT_SESSION_ID.fetch_add(1, Ordering::Relaxed)),
            started_at: Instant::now(),
            protocol: ProtocolKind::Unknown,
            auth_state: AuthState::Unauthenticated,
            target: None,
            state: ConnectionState::Accepted,
            cancellation: SessionCancellation::new(),
            _permit: permit,
        }
    }

    pub fn id(&self) -> SessionId {
        self.id
    }

    pub fn protocol(&self) -> ProtocolKind {
        self.protocol
    }

    pub fn auth_state(&self) -> AuthState {
        self.auth_state
    }

    pub fn target(&self) -> Option<&TargetInfo> {
        self.target.as_ref()
    }

    pub fn state(&self) -> ConnectionState {
        self.state
    }

    pub fn age(&self) -> std::time::Duration {
        self.started_at.elapsed()
    }

    pub fn set_protocol(&mut self, protocol: ProtocolKind) {
        self.protocol = protocol;
    }

    pub fn set_state(&mut self, state: ConnectionState) {
        self.state = state;
    }

    pub fn mark_authenticated(&mut self) {
        self.auth_state = AuthState::Authenticated;
    }

    pub fn mark_auth_failed(&mut self) {
        self.auth_state = AuthState::Failed;
    }

    pub fn set_target(&mut self, host: impl Into<String>, port: u16) {
        self.target = Some(TargetInfo {
            host: host.into(),
            port,
        });
    }

    pub fn cancel(&self) {
        self.cancellation.cancel();
    }

    pub fn cancellation(&self) -> SessionCancellation {
        self.cancellation.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::{AuthState, ConnectionState, ProtocolKind, Session};
    use crate::resource::ResourceGovernor;

    #[tokio::test]
    async fn tracks_lifecycle_metadata_without_payload_state() {
        let governor = ResourceGovernor::new(1);
        let permit = governor.acquire_session().await.unwrap();
        let mut session = Session::new(permit);

        assert_eq!(session.protocol(), ProtocolKind::Unknown);
        assert_eq!(session.auth_state(), AuthState::Unauthenticated);
        assert_eq!(session.state(), ConnectionState::Accepted);
        assert!(session.target().is_none());

        session.set_protocol(ProtocolKind::Socks5);
        session.set_state(ConnectionState::Handshaking);
        session.mark_authenticated();
        session.set_target("example.com", 443);

        assert_eq!(session.protocol(), ProtocolKind::Socks5);
        assert_eq!(session.auth_state(), AuthState::Authenticated);
        assert_eq!(session.state(), ConnectionState::Handshaking);
        assert_eq!(session.target().unwrap().host, "example.com");
        assert_eq!(session.target().unwrap().port, 443);
    }

    #[tokio::test]
    async fn cancellation_is_durable_state() {
        let governor = ResourceGovernor::new(1);
        let permit = governor.acquire_session().await.unwrap();
        let session = Session::new(permit);
        let cancellation = session.cancellation();

        session.cancel();

        assert!(cancellation.is_cancelled());
        cancellation.cancelled().await;
    }
}
