use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

/// Owns admission-control resources for client sessions.
///
/// This is deliberately small in Phase 2: active session ownership is made
/// explicit now, while future phases can add handshake/rate-limit permits here.
#[derive(Clone)]
pub struct ResourceGovernor {
    active_sessions: Arc<Semaphore>,
    active_count: Arc<AtomicUsize>,
}

impl ResourceGovernor {
    pub fn new(max_sessions: usize) -> Self {
        Self {
            active_sessions: Arc::new(Semaphore::new(max_sessions.max(1))),
            active_count: Arc::new(AtomicUsize::new(0)),
        }
    }

    pub async fn acquire_session(&self) -> Result<SessionPermit, ResourceError> {
        let permit = self
            .active_sessions
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| ResourceError::Closed)?;
        self.active_count.fetch_add(1, Ordering::Relaxed);

        Ok(SessionPermit {
            _permit: permit,
            active_count: Arc::clone(&self.active_count),
        })
    }

    pub fn active_sessions(&self) -> usize {
        self.active_count.load(Ordering::Relaxed)
    }

    pub fn available_sessions(&self) -> usize {
        self.active_sessions.available_permits()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ResourceError {
    #[error("resource governor is closed")]
    Closed,
}

pub struct SessionPermit {
    _permit: OwnedSemaphorePermit,
    active_count: Arc<AtomicUsize>,
}

impl Drop for SessionPermit {
    fn drop(&mut self) {
        self.active_count.fetch_sub(1, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::ResourceGovernor;
    use tokio::time::{Duration, timeout};

    #[tokio::test]
    async fn session_permit_is_released_on_drop() {
        let governor = ResourceGovernor::new(1);
        let first = governor.acquire_session().await.unwrap();
        assert_eq!(governor.active_sessions(), 1);
        assert_eq!(governor.available_sessions(), 0);

        let blocked = timeout(Duration::from_millis(50), governor.acquire_session()).await;
        assert!(blocked.is_err());

        drop(first);
        let second = timeout(Duration::from_secs(1), governor.acquire_session())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(governor.active_sessions(), 1);
        drop(second);
        assert_eq!(governor.active_sessions(), 0);
    }
}
