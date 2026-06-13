//! The GATT I/O seam. `GattConnection` is the boundary the rest of the crate is
//! written against; `MockGatt` drives it in CI, `BtleplugConnection` on hardware.

use crate::error::Result;
use async_trait::async_trait;
use tokio::sync::mpsc;

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
/// GATT database. One real impl (`btleplug`), one mock (tests).
#[async_trait]
pub trait GattConnection: Send + Sync {
    /// Write a value to a characteristic identified by its UUID.
    async fn write(&self, char_uuid: &str, value: &[u8]) -> Result<()>;
    /// Read a characteristic's current value by UUID.
    async fn read(&self, char_uuid: &str) -> Result<Vec<u8>>;
    /// Subscribe to notifications on a characteristic; the receiver yields raw
    /// notification payloads.
    async fn subscribe(&self, char_uuid: &str) -> Result<mpsc::Receiver<Vec<u8>>>;
    /// Enumerate the accessory's services and characteristics.
    async fn enumerate(&self) -> Result<Vec<GattService>>;
}

/// An in-memory `GattConnection` for tests. Reads return the last written value
/// per characteristic; `subscribe` returns a channel whose `Sender` is exposed
/// via [`MockGatt::notifier`] so tests can push events; `enumerate` returns a
/// seeded service list. Optionally, per-characteristic canned read responses can
/// be queued with [`MockGatt::queue_read`] (FIFO) to script request/response.
#[cfg(test)]
#[derive(Default)]
pub(crate) struct MockGatt {
    values: std::sync::Mutex<std::collections::HashMap<String, Vec<u8>>>,
    queued: std::sync::Mutex<std::collections::HashMap<String, std::collections::VecDeque<Vec<u8>>>>,
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
            characteristics: vec![GattCharacteristic { uuid: "c".into(), iid: 2 }],
        };
        let gatt = MockGatt::new().with_services(vec![svc.clone()]);
        assert_eq!(gatt.enumerate().await.unwrap(), vec![svc]);
    }
}
