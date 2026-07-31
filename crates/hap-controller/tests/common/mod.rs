//! Shared in-memory test doubles for the `hap-controller` integration tests: a
//! [`PairingStore`] and a [`Session`] that replay canned JSON and capture writes.

// CLAUDE.md test-code carve-out: unwrap/expect allowed with justification.
#![allow(clippy::unwrap_used, clippy::expect_used)]
// Shared test helpers: not every test file uses every item, and `pub` here is
// reachable only within each test binary (no downstream crate).
#![allow(dead_code, unreachable_pub)]

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use tokio::sync::mpsc;

use hap_controller::{
    AccessoryHandle, PairingStore, Session, SessionResponse, StoredAccessory, StoredTransport,
};
use hap_crypto::{AccessoryPairing, ControllerKeypair};

/// Load a fixture from `test-vectors/accessories/` (two levels up from the crate).
pub fn fixture(name: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("test-vectors/accessories")
        .join(name);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

/// An inert [`StoredAccessory`] for store-list tests. The `ltpk` is a placeholder
/// — these tests never exercise the accessory key cryptographically, they only
/// assert the store lists / forgets the pairing id.
pub fn sample_pairing(id: &str) -> StoredAccessory {
    StoredAccessory {
        pairing: AccessoryPairing {
            pairing_id: id.to_string(),
            ltpk: [0u8; 32],
        },
        transport: StoredTransport::Ip {
            addr: "127.0.0.1:0".parse().unwrap(),
        },
    }
}

/// An in-memory [`PairingStore`]. Seed it with whatever a test needs.
#[derive(Default)]
pub struct MockStore {
    controller: Mutex<Option<ControllerKeypair>>,
    pairings: Mutex<HashMap<String, StoredAccessory>>,
}

impl MockStore {
    /// Empty store: no controller identity yet, no pairings.
    pub fn new() -> Self {
        Self::default()
    }

    /// Seed a pairing so `paired`/`connect` have something to find.
    #[must_use]
    pub fn with_pairing(self, entry: StoredAccessory) -> Self {
        self.pairings
            .lock()
            .unwrap()
            .insert(entry.pairing.pairing_id.clone(), entry);
        self
    }
}

#[async_trait]
impl PairingStore for MockStore {
    async fn load_controller(&self) -> hap_pairing::Result<Option<ControllerKeypair>> {
        Ok(self.controller.lock().unwrap().clone())
    }

    async fn save_controller(&self, k: &ControllerKeypair) -> hap_pairing::Result<()> {
        *self.controller.lock().unwrap() = Some(k.clone());
        Ok(())
    }

    async fn load_pairings(&self) -> hap_pairing::Result<Vec<StoredAccessory>> {
        Ok(self.pairings.lock().unwrap().values().cloned().collect())
    }

    async fn save_pairing(&self, a: &StoredAccessory) -> hap_pairing::Result<()> {
        self.pairings
            .lock()
            .unwrap()
            .insert(a.pairing.pairing_id.clone(), a.clone());
        Ok(())
    }

    async fn delete_pairing(&self, id: &str) -> hap_pairing::Result<()> {
        self.pairings.lock().unwrap().remove(id);
        Ok(())
    }
}

/// Shared record of every `(path, body)` written via the mock session.
pub type PutLog = Arc<Mutex<Vec<(String, Vec<u8>)>>>;

/// A handle that, when `kill()` is called, sets the dead flag AND drops
/// the live event sender so the supervisor's current `recv()` returns `None`.
pub struct KillSwitch(
    Arc<std::sync::atomic::AtomicBool>,
    Arc<Mutex<Option<mpsc::Sender<Vec<u8>>>>>,
);

impl KillSwitch {
    /// Mark the session as dead and close the live event channel.
    pub fn kill(&self) {
        self.0.store(true, std::sync::atomic::Ordering::Relaxed);
        // Drop the sender so the supervisor's recv() returns None immediately.
        if let Ok(mut guard) = self.1.lock() {
            *guard = None;
        }
    }
}

/// A [`Session`]-shaped double: returns canned JSON for `GET`, records `PUT`
/// bodies, and lets a test inject `EVENT/1.0` pushes onto the pump channel.
pub struct MockSession {
    gets: HashMap<String, (u16, Vec<u8>)>,
    puts: PutLog,
    /// The event sender stored behind a Mutex<Option> so `KillSwitch::kill()`
    /// can drop it to close the live event receiver.
    event_tx: Arc<Mutex<Option<mpsc::Sender<Vec<u8>>>>>,
    event_rx: Mutex<Option<mpsc::Receiver<Vec<u8>>>>,
    dead: Arc<std::sync::atomic::AtomicBool>,
    hang: bool,
}

impl MockSession {
    pub fn new() -> Self {
        let (event_tx, event_rx) = mpsc::channel(16);
        Self {
            gets: HashMap::new(),
            puts: Arc::new(Mutex::new(Vec::new())),
            event_tx: Arc::new(Mutex::new(Some(event_tx))),
            event_rx: Mutex::new(Some(event_rx)),
            dead: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            hang: false,
        }
    }

    /// Make every `request` hang forever (simulates a silently-dropped link).
    #[must_use]
    pub fn hanging(mut self) -> Self {
        self.hang = true;
        self
    }

    /// Register the `(status, body)` returned for a `GET` of `path`.
    #[must_use]
    pub fn with_get(mut self, path: &str, status: u16, body: &str) -> Self {
        self.gets
            .insert(path.to_string(), (status, body.as_bytes().to_vec()));
        self
    }

    /// A shared handle to every `(path, body)` the code under test wrote.
    pub fn put_recorder(&self) -> PutLog {
        self.puts.clone()
    }

    /// A sender that feeds raw `EVENT/1.0` bodies to the handle's event pump.
    ///
    /// # Panics
    /// Panics if called after the session has been killed (the sender is gone).
    pub fn event_injector(&self) -> mpsc::Sender<Vec<u8>> {
        self.event_tx
            .lock()
            .unwrap()
            .clone()
            .expect("event_injector called after session was killed")
    }

    /// A handle to flip this session to "dead" and close the live event channel.
    pub fn kill_switch(&self) -> KillSwitch {
        KillSwitch(self.dead.clone(), self.event_tx.clone())
    }
}

#[async_trait]
impl Session for MockSession {
    async fn request(
        &self,
        method: &str,
        path: &str,
        _content_type: &str,
        body: &[u8],
    ) -> hap_controller::Result<SessionResponse> {
        if self.dead.load(std::sync::atomic::Ordering::Relaxed) {
            return Err(hap_controller::HapError::Transport(
                hap_transport::error_test_support::session_closed(),
            ));
        }
        if self.hang {
            std::future::pending::<()>().await;
        }
        match method {
            "GET" => {
                let (status, body) = self.gets.get(path).cloned().unwrap_or((404, Vec::new()));
                Ok(SessionResponse { status, body })
            }
            "PUT" => {
                self.puts
                    .lock()
                    .unwrap()
                    .push((path.to_string(), body.to_vec()));
                // Accessories answer a successful write with 204 No Content.
                Ok(SessionResponse {
                    status: 204,
                    body: Vec::new(),
                })
            }
            _ => Ok(SessionResponse {
                status: 405,
                body: Vec::new(),
            }),
        }
    }

    fn take_events(&self) -> mpsc::Receiver<Vec<u8>> {
        if self.dead.load(std::sync::atomic::Ordering::Relaxed) {
            // Return an already-closed receiver: create a channel and drop the sender.
            let (_tx, rx) = mpsc::channel(1);
            return rx;
        }
        self.event_rx.lock().unwrap().take().unwrap_or_else(|| {
            // Already taken: hand back an immediately-closed receiver.
            let (_tx, rx) = mpsc::channel(1);
            rx
        })
    }
}

/// A [`Reconnector`] that hands out a fixed sequence of sessions (each paired
/// with its own config number), returning
/// [`hap_controller::HapError::ConnectionLost`] once the list is exhausted.
pub struct MockReconnector {
    sessions: std::sync::Mutex<std::vec::IntoIter<(MockSession, Option<u32>)>>,
}

impl MockReconnector {
    /// Build a reconnector where every session returns the same `config_number`.
    #[allow(clippy::unnecessary_box_returns)]
    pub fn new(sessions: Vec<MockSession>, config_number: Option<u32>) -> Box<Self> {
        let pairs: Vec<(MockSession, Option<u32>)> =
            sessions.into_iter().map(|s| (s, config_number)).collect();
        Box::new(Self {
            sessions: std::sync::Mutex::new(pairs.into_iter()),
        })
    }

    /// Build a reconnector where each session carries its own config number
    /// (for c#-refresh tests).
    #[allow(clippy::unnecessary_box_returns)]
    pub fn with_config_numbers(pairs: Vec<(MockSession, Option<u32>)>) -> Box<Self> {
        Box::new(Self {
            sessions: std::sync::Mutex::new(pairs.into_iter()),
        })
    }
}

#[async_trait]
impl hap_controller::Reconnector for MockReconnector {
    async fn reconnect(&self) -> hap_controller::Result<hap_controller::Reconnected> {
        let next = self.sessions.lock().unwrap().next();
        match next {
            Some((s, cn)) => Ok(hap_controller::Reconnected {
                session: std::sync::Arc::new(s),
                config_number: cn,
            }),
            None => Err(hap_controller::HapError::ConnectionLost),
        }
    }
}

/// Wrap a [`MockSession`] in an [`AccessoryHandle`] via the hidden test seam.
/// Must be called from within a Tokio runtime (it spawns the event pump).
pub fn handle_with_session(session: MockSession) -> AccessoryHandle {
    AccessoryHandle::from_session(Box::new(session))
}

/// Wrap a [`MockSession`] plus a [`MockReconnector`] in an [`AccessoryHandle`]
/// via the hidden reconnect test seam. Must be called from within a Tokio runtime.
pub fn handle_with_reconnector(
    initial: MockSession,
    reconnector: Box<MockReconnector>,
) -> AccessoryHandle {
    AccessoryHandle::from_parts(std::sync::Arc::new(initial), reconnector)
}
