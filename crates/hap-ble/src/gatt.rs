//! The GATT I/O seam. `GattConnection` is the boundary the rest of the crate is
//! written against; `MockGatt` drives it in CI, `BluestConnection` (see bluest_gatt) on hardware.
//!
//! The `MockGatt` type is a testing seam — exempt from semver guarantees.

use crate::error::Result;
use async_trait::async_trait;
use tokio::sync::mpsc;

/// The HAP Characteristic-Instance-ID GATT descriptor. Each HAP characteristic
/// carries one; its value is the characteristic's 16-bit instance id (LE), which
/// HAP-BLE PDUs address by.
pub(crate) const HAP_INSTANCE_ID_DESC: &str = "dc46f0fe-81d2-4616-b5d9-6abdd796939a";

/// The HAP Service-Instance-ID characteristic (read-only, no descriptor) that
/// appears in every HAP service; its value is the service's 16-bit instance id.
pub(crate) const HAP_SERVICE_ID_CHAR: &str = "e604e95d-a759-4817-87d3-aa005083a0d1";

/// The HAP Service-Signature characteristic. One appears in *every* HAP service
/// (they all share this UUID); it is a service-level signature, not a model
/// characteristic. It is skipped when building the accessory model, and kept in
/// the enumerated tree only under the Protocol-Information service, where its
/// instance id is the generate-broadcast-key request target.
pub(crate) const SERVICE_SIGNATURE_CHAR: &str = "000000a5-0000-1000-8000-0026bb765291";

/// The HAP Protocol-Information service. Its Service-Signature characteristic is
/// the target of the Protocol-Configuration generate-broadcast-key request.
pub(crate) const PROTOCOL_INFO_SERVICE: &str = "000000a2-0000-1000-8000-0026bb765291";

/// Read a 16-bit little-endian value from the first two bytes, if present.
pub(crate) fn u16_le(v: &[u8]) -> Option<u16> {
    match v {
        [lo, hi, ..] => Some(u16::from_le_bytes([*lo, *hi])),
        _ => None,
    }
}

/// One GATT characteristic discovered on the accessory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GattCharacteristic {
    /// The 128-bit characteristic UUID (canonical 36-char string).
    pub uuid: String,
    /// The HAP characteristic instance id (from its Instance-ID descriptor).
    pub iid: u16,
}

/// One GATT service and its characteristics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GattService {
    /// The 128-bit service UUID (canonical 36-char string).
    pub uuid: String,
    /// The HAP service instance id.
    pub iid: u16,
    /// Characteristics under this service.
    pub characteristics: Vec<GattCharacteristic>,
}

/// The transport seam: read/write/subscribe a characteristic and enumerate the
/// GATT database. One real impl (`bluest`), one mock (tests).
#[async_trait]
pub trait GattConnection: Send + Sync {
    /// Write a value to a characteristic identified by its UUID.
    async fn write(&self, char_uuid: &str, value: &[u8]) -> Result<()>;
    /// Read a characteristic's current value by UUID.
    async fn read(&self, char_uuid: &str) -> Result<Vec<u8>>;
    /// Subscribe to notifications on a characteristic; the receiver yields raw
    /// notification payloads.
    async fn subscribe(&self, char_uuid: &str) -> Result<mpsc::Receiver<Vec<u8>>>;
    /// Read one characteristic's HAP instance id (its Instance-ID descriptor)
    /// without walking the whole tree — used to address the pairing
    /// characteristics before the (slow) full database sweep.
    async fn instance_id(&self, char_uuid: &str) -> Result<u16>;
    /// Enumerate the accessory's services and characteristics (with iids).
    async fn enumerate(&self) -> Result<Vec<GattService>>;
    /// The maximum bytes that fit in a single GATT write — the HAP-BLE PDU
    /// fragment size. Backends that can't determine the negotiated MTU return a
    /// conservative default.
    async fn max_write(&self) -> usize {
        DEFAULT_FRAGMENT_SIZE
    }
    /// A monotonically increasing link-generation counter that advances on every
    /// reconnect. A secure session minted at generation *g* is invalidated when
    /// the accessory drops the link (the count moves past *g*), so the holder
    /// must re-run Pair Verify before its next encrypted operation. Backends
    /// without a reconnect supervisor never invalidate sessions and return 0.
    async fn generation(&self) -> u64 {
        0
    }
    /// Release the active link. A sleepy HAP accessory only advertises and
    /// emits encrypted broadcasts while disconnected, so a caller watching for
    /// sleepy events must disconnect after setup. Default no-op for backends and
    /// mocks with no live link.
    async fn disconnect(&self) {}
}

/// A raw advertisement observed by a backend scanner: the Apple (0x004C)
/// manufacturer-data bytes. Parsed into a [`crate::advert::HapAdvert`] by callers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawAdvert {
    /// Apple manufacturer-data payload (the bytes after the 0x004C company id).
    pub manufacturer_data: Vec<u8>,
}

/// A source of continuous BLE advertisements, used post-pairing to receive
/// sleepy-device events with no active connection. Separate from
/// [`GattConnection`] (the connected I/O seam) so each has one responsibility.
/// Backends without a scanner return an immediately-closed receiver.
#[async_trait]
pub trait AdvertSource: Send + Sync {
    /// Stream Apple HAP advertisements as they arrive.
    ///
    /// # Errors
    /// Returns [`crate::error::BleError`] on backend scanner failures.
    async fn watch_adverts(&self) -> Result<mpsc::Receiver<RawAdvert>> {
        let (_tx, rx) = mpsc::channel(1);
        Ok(rx)
    }
}

/// Conservative HAP-BLE fragment size when the negotiated ATT MTU is unknown;
/// fits any MTU >= 183.
pub(crate) const DEFAULT_FRAGMENT_SIZE: usize = 180;

/// An in-memory `GattConnection` for tests. Reads return the last written value
/// per characteristic; `subscribe` returns a channel whose `Sender` is exposed
/// via [`MockGatt::notifier`] so tests can push events; `enumerate` returns a
/// seeded service list. Optionally, per-characteristic canned read responses can
/// be queued with [`MockGatt::queue_read`] (FIFO) to script request/response.
#[cfg(any(test, feature = "test-support"))]
pub struct MockGatt {
    values: std::sync::Mutex<std::collections::HashMap<String, Vec<u8>>>,
    queued:
        std::sync::Mutex<std::collections::HashMap<String, std::collections::VecDeque<Vec<u8>>>>,
    services: std::sync::Mutex<Vec<GattService>>,
    senders: std::sync::Mutex<std::collections::HashMap<String, mpsc::Sender<Vec<u8>>>>,
    generation: std::sync::atomic::AtomicU64,
    advert_tx: mpsc::Sender<RawAdvert>,
    advert_rx: std::sync::Mutex<Option<mpsc::Receiver<RawAdvert>>>,
    /// UUID -> gate that the next `read` of that characteristic awaits.
    blocked:
        std::sync::Mutex<std::collections::HashMap<String, std::sync::Arc<tokio::sync::Notify>>>,
}

#[cfg(any(test, feature = "test-support"))]
impl Default for MockGatt {
    fn default() -> Self {
        let (advert_tx, advert_rx) = mpsc::channel(16);
        Self {
            values: std::sync::Mutex::new(std::collections::HashMap::new()),
            queued: std::sync::Mutex::new(std::collections::HashMap::new()),
            services: std::sync::Mutex::new(Vec::new()),
            senders: std::sync::Mutex::new(std::collections::HashMap::new()),
            generation: std::sync::atomic::AtomicU64::new(0),
            advert_tx,
            advert_rx: std::sync::Mutex::new(Some(advert_rx)),
            blocked: std::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }
}

#[cfg(any(test, feature = "test-support"))]
#[allow(clippy::unwrap_used)] // test double: lock poisoning is not a real concern in single-process tests
impl MockGatt {
    /// Create a new empty mock GATT device.
    pub fn new() -> Self {
        Self::default()
    }

    /// Seed this mock with a service list.
    ///
    /// # Panics
    ///
    /// Panics if the internal service list lock is poisoned (should never happen
    /// in a single-threaded test).
    #[must_use]
    pub fn with_services(self, services: Vec<GattService>) -> Self {
        *self.services.lock().unwrap() = services;
        self
    }

    /// Queue a canned response that the next `read` of `char_uuid` returns
    /// instead of the last-written value.
    ///
    /// # Panics
    ///
    /// Panics if the internal queued reads lock is poisoned (should never happen
    /// in a single-threaded test).
    #[allow(dead_code)] // used by later tasks (PDU transport / pairing / db)
    pub fn queue_read(&self, char_uuid: &str, value: Vec<u8>) {
        self.queued
            .lock()
            .unwrap()
            .entry(char_uuid.to_string())
            .or_default()
            .push_back(value);
    }

    /// A sender that pushes a notification to subscribers of `char_uuid`.
    ///
    /// # Panics
    ///
    /// Panics if the internal senders lock is poisoned (should never happen in a
    /// single-threaded test).
    #[allow(dead_code)] // used by later tasks (events)
    pub fn notifier(&self, char_uuid: &str) -> Option<mpsc::Sender<Vec<u8>>> {
        self.senders.lock().unwrap().get(char_uuid).cloned()
    }

    /// Advance the link generation, simulating a reconnect that invalidated any
    /// secure session minted at an earlier generation.
    #[allow(dead_code)] // used by the reconnect tests
    pub fn bump_generation(&self) {
        // No panics: the generation counter does not use locks.
        self.generation
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }

    /// A sender that pushes a raw advert to a `watch_adverts` subscriber.
    #[allow(dead_code)] // used by later tasks (broadcast / disconnected-event poll)
    pub fn advert_sender(&self) -> mpsc::Sender<RawAdvert> {
        // No panics: we simply clone a channel sender.
        self.advert_tx.clone()
    }

    /// Make the next `read` of `char_uuid` await the returned `Notify` before
    /// serving its (queued or last-written) value — simulates a slow read
    /// (e.g. a reconnect-read) so tests can assert other work is not blocked.
    ///
    /// # Panics
    ///
    /// Panics if the internal blocked reads lock is poisoned (should never happen
    /// in a single-threaded test).
    #[allow(dead_code)] // used by the poll-off-advert-task tests
    pub fn block_next_read(&self, char_uuid: &str) -> std::sync::Arc<tokio::sync::Notify> {
        let gate = std::sync::Arc::new(tokio::sync::Notify::new());
        self.blocked
            .lock()
            .unwrap()
            .insert(char_uuid.to_string(), gate.clone());
        gate
    }
}

#[cfg(any(test, feature = "test-support"))]
#[allow(clippy::unwrap_used)] // test double: lock poisoning is not a real concern in single-process tests
#[async_trait]
impl AdvertSource for MockGatt {
    async fn watch_adverts(&self) -> Result<mpsc::Receiver<RawAdvert>> {
        // Hand out the single receiver once; a closed one thereafter.
        self.advert_rx.lock().unwrap().take().map_or_else(
            || {
                let (_tx, rx) = mpsc::channel(1);
                Ok(rx)
            },
            Ok,
        )
    }
}

#[cfg(any(test, feature = "test-support"))]
#[allow(clippy::unwrap_used)] // test double: lock poisoning is not a real concern in single-process tests
#[async_trait]
impl GattConnection for MockGatt {
    async fn instance_id(&self, char_uuid: &str) -> Result<u16> {
        self.services
            .lock()
            .unwrap()
            .iter()
            .flat_map(|s| &s.characteristics)
            .find(|c| c.uuid.eq_ignore_ascii_case(char_uuid))
            .map(|c| c.iid)
            .ok_or(crate::error::BleError::CharacteristicNotFound { aid: 0, iid: 0 })
    }

    async fn write(&self, char_uuid: &str, value: &[u8]) -> Result<()> {
        self.values
            .lock()
            .unwrap()
            .insert(char_uuid.to_string(), value.to_vec());
        Ok(())
    }

    async fn read(&self, char_uuid: &str) -> Result<Vec<u8>> {
        let gate = self.blocked.lock().unwrap().remove(char_uuid);
        if let Some(gate) = gate {
            gate.notified().await;
        }
        if let Some(q) = self.queued.lock().unwrap().get_mut(char_uuid) {
            if let Some(v) = q.pop_front() {
                return Ok(v);
            }
        }
        Ok(self
            .values
            .lock()
            .unwrap()
            .get(char_uuid)
            .cloned()
            .unwrap_or_default())
    }

    async fn subscribe(&self, char_uuid: &str) -> Result<mpsc::Receiver<Vec<u8>>> {
        let (tx, rx) = mpsc::channel(8);
        self.senders
            .lock()
            .unwrap()
            .insert(char_uuid.to_string(), tx);
        Ok(rx)
    }

    async fn enumerate(&self) -> Result<Vec<GattService>> {
        Ok(self.services.lock().unwrap().clone())
    }

    async fn generation(&self) -> u64 {
        self.generation.load(std::sync::atomic::Ordering::SeqCst)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[allow(clippy::unwrap_used)]
    async fn mock_echoes_written_value_on_read() {
        let gatt = MockGatt::new();
        gatt.write("char-a", &[1, 2, 3]).await.unwrap();
        assert_eq!(gatt.read("char-a").await.unwrap(), vec![1, 2, 3]);
    }

    #[tokio::test]
    #[allow(clippy::unwrap_used)]
    async fn mock_enumerate_returns_seeded_db() {
        let svc = GattService {
            uuid: "svc".into(),
            iid: 1,
            characteristics: vec![GattCharacteristic {
                uuid: "c".into(),
                iid: 2,
            }],
        };
        let gatt = MockGatt::new().with_services(vec![svc.clone()]);
        assert_eq!(gatt.enumerate().await.unwrap(), vec![svc]);
    }
}
