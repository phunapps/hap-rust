//! The GATT I/O seam. `GattConnection` is the boundary the rest of the crate is
//! written against; `MockGatt` drives it in CI, `BluestConnection` (see bluest_gatt) on hardware.

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
}

/// Conservative HAP-BLE fragment size when the negotiated ATT MTU is unknown;
/// fits any MTU >= 183.
pub(crate) const DEFAULT_FRAGMENT_SIZE: usize = 180;

/// An in-memory `GattConnection` for tests. Reads return the last written value
/// per characteristic; `subscribe` returns a channel whose `Sender` is exposed
/// via [`MockGatt::notifier`] so tests can push events; `enumerate` returns a
/// seeded service list. Optionally, per-characteristic canned read responses can
/// be queued with [`MockGatt::queue_read`] (FIFO) to script request/response.
#[cfg(test)]
#[derive(Default)]
pub(crate) struct MockGatt {
    values: std::sync::Mutex<std::collections::HashMap<String, Vec<u8>>>,
    queued:
        std::sync::Mutex<std::collections::HashMap<String, std::collections::VecDeque<Vec<u8>>>>,
    services: std::sync::Mutex<Vec<GattService>>,
    senders: std::sync::Mutex<std::collections::HashMap<String, mpsc::Sender<Vec<u8>>>>,
}

#[cfg(test)]
#[allow(clippy::unwrap_used)] // test double: lock poisoning is not a real concern in single-process tests
impl MockGatt {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn with_services(self, services: Vec<GattService>) -> Self {
        *self.services.lock().unwrap() = services;
        self
    }

    /// Queue a canned response that the next `read` of `char_uuid` returns
    /// instead of the last-written value.
    #[allow(dead_code)] // used by later tasks (PDU transport / pairing / db)
    pub(crate) fn queue_read(&self, char_uuid: &str, value: Vec<u8>) {
        self.queued
            .lock()
            .unwrap()
            .entry(char_uuid.to_string())
            .or_default()
            .push_back(value);
    }

    /// A sender that pushes a notification to subscribers of `char_uuid`.
    #[allow(dead_code)] // used by later tasks (events)
    pub(crate) fn notifier(&self, char_uuid: &str) -> Option<mpsc::Sender<Vec<u8>>> {
        self.senders.lock().unwrap().get(char_uuid).cloned()
    }
}

#[cfg(test)]
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
