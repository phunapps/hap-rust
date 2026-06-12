//! Self-healing session: a [`Reconnector`] that mints fresh sessions, the
//! [`ConnectionState`] callers observe, and the [`ReconnectingSession`] that
//! keeps a swappable current session and waits out reconnects on foreground ops.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use tokio::sync::{broadcast, watch};

use hap_transport::TransportError;

use crate::error::{HapError, Result};
use crate::handle::{Session, SessionResponse};

/// A fresh secure session plus the accessory's current config number, if known.
pub struct Reconnected {
    /// The new session.
    pub session: Arc<dyn Session>,
    /// The accessory's `c#` (config number) from discovery, if it surfaced.
    pub config_number: Option<u32>,
}

/// Mints a fresh secure session on demand (re-discover + Pair Verify).
#[doc(hidden)]
#[async_trait]
pub trait Reconnector: Send + Sync {
    /// Re-establish the secure session.
    ///
    /// # Errors
    /// Any [`HapError`] from discovery or Pair Verify.
    async fn reconnect(&self) -> Result<Reconnected>;
}

/// Observable connection state for health reporting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectionState {
    /// A live secure session is up.
    Connected,
    /// The session dropped; a reconnect attempt is in flight.
    Reconnecting {
        /// 1-based attempt counter since the last `Connected`.
        attempt: u32,
    },
    /// No session and no attempt currently running.
    Disconnected,
}

/// Whether a transport error means the session is gone (vs. an application error).
pub(crate) fn is_session_dead(err: &HapError) -> bool {
    // A real network drop (Wi-Fi loss, accessory reboot) surfaces as a socket
    // `Io` error (broken pipe, timed out, reset) just as often as the explicit
    // channel-closed variants — hardware testing showed foreground ops getting
    // raw `Io` errors during an outage. Treat all of these as "session gone" so a
    // foreground op waits for the supervisor's reconnect instead of leaking the
    // raw error.
    matches!(
        err,
        HapError::Transport(
            TransportError::ConnectionClosed
                | TransportError::SessionClosed
                | TransportError::NoResponse
                | TransportError::Io(_)
        )
    )
}

/// Backoff schedule: 1s, 2s, 4s, … capped at 30s.
pub(crate) fn backoff(attempt: u32) -> Duration {
    let secs = 1u64
        .checked_shl(attempt.saturating_sub(1))
        .unwrap_or(30)
        .min(30);
    Duration::from_secs(secs.max(1))
}

/// How long a foreground op waits for the supervisor to restore the session
/// before giving up with `ConnectionLost`.
const FOREGROUND_WAIT: Duration = Duration::from_secs(35);

/// Holds the live session behind a `watch` channel so the supervisor task can
/// swap it and foreground ops can wait for a fresh one. Exposes the
/// `ConnectionState` broadcast.
pub(crate) struct ReconnectingSession {
    current_tx: watch::Sender<Arc<dyn Session>>,
    current_rx: watch::Receiver<Arc<dyn Session>>,
    reconnector: Box<dyn Reconnector>,
    state_tx: broadcast::Sender<ConnectionState>,
}

impl ReconnectingSession {
    pub(crate) fn new(initial: Arc<dyn Session>, reconnector: Box<dyn Reconnector>) -> Self {
        let (current_tx, current_rx) = watch::channel(initial);
        let (state_tx, _) = broadcast::channel(16);
        Self {
            current_tx,
            current_rx,
            reconnector,
            state_tx,
        }
    }

    /// The current session (cheap Arc clone).
    pub(crate) fn current(&self) -> Arc<dyn Session> {
        self.current_rx.borrow().clone()
    }

    /// Publish a freshly reconnected session, waking foreground waiters.
    pub(crate) fn publish(&self, s: Arc<dyn Session>) {
        let _ = self.current_tx.send(s);
    }

    /// Run the reconnector once.
    pub(crate) async fn reconnect(&self) -> Result<Reconnected> {
        self.reconnector.reconnect().await
    }

    pub(crate) fn set_state(&self, st: ConnectionState) {
        let _ = self.state_tx.send(st);
    }

    pub(crate) fn subscribe_state(&self) -> broadcast::Receiver<ConnectionState> {
        self.state_tx.subscribe()
    }

    /// Run a request; if the current session is dead, wait (bounded) for the
    /// supervisor task to publish a fresh session, then retry on it once.
    /// Returns [`HapError::ConnectionLost`] if no fresh session arrives in time.
    pub(crate) async fn request(
        &self,
        method: &str,
        path: &str,
        content_type: &str,
        body: &[u8],
    ) -> Result<SessionResponse> {
        let sess = self.current();
        match sess.request(method, path, content_type, body).await {
            Ok(r) => Ok(r),
            Err(e) if is_session_dead(&e) => {
                let mut rx = self.current_tx.subscribe();
                loop {
                    let fresh = rx.borrow_and_update().clone();
                    if !Arc::ptr_eq(&fresh, &sess) {
                        return fresh.request(method, path, content_type, body).await;
                    }
                    // Wait (bounded) for the supervisor to publish a new session.
                    // Any timeout or closed channel means it never arrived.
                    if !matches!(
                        tokio::time::timeout(FOREGROUND_WAIT, rx.changed()).await,
                        Ok(Ok(()))
                    ) {
                        return Err(HapError::ConnectionLost);
                    }
                }
            }
            Err(e) => Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::is_session_dead;
    use crate::error::HapError;

    #[test]
    fn io_and_closed_errors_are_session_dead() {
        // A real Wi-Fi drop surfaces as an Io error; it must count as dead.
        assert!(is_session_dead(&HapError::Transport(
            hap_transport::error_test_support::io_disconnected()
        )));
        assert!(is_session_dead(&HapError::Transport(
            hap_transport::error_test_support::session_closed()
        )));
        // An application-level error is NOT a dead session.
        assert!(!is_session_dead(&HapError::Http { status: 400 }));
    }
}
