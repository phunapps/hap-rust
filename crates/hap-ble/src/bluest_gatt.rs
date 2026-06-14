//! A [`GattConnection`] backed by the `bluest` crate, with a **reconnect-and-
//! resume supervisor**: sleepy HAP accessories drop the link every few
//! operations during the long attribute-database sweep, so each operation
//! reconnects (re-discovering its characteristic handles by UUID) and retries
//! on a clean disconnect, resuming where it left off.

use crate::error::{BleError, Result};
use crate::gatt::{
    u16_le, GattCharacteristic, GattConnection, GattService, HAP_INSTANCE_ID_DESC,
    HAP_SERVICE_ID_CHAR,
};
use async_trait::async_trait;
use bluest::{Adapter, Characteristic, Device};
use std::collections::HashMap;
use tokio::sync::{mpsc, Mutex};

/// Total reconnects allowed across a connection's lifetime (a runaway backstop).
const MAX_RECONNECTS: u32 = 60;

// By value for ergonomic `.map_err(be)`; the error is only formatted.
#[allow(clippy::needless_pass_by_value)]
fn be(e: bluest::Error) -> BleError {
    BleError::Backend(e.to_string())
}

/// Whether a backend error means the link dropped (so reconnecting may recover).
fn is_disconnect(e: &BleError) -> bool {
    match e {
        BleError::Disconnected => true,
        BleError::Backend(m) => {
            let m = m.to_ascii_lowercase();
            m.contains("disconnect") || m.contains("not connected") || m.contains("not available")
        }
        _ => false,
    }
}

/// The discovered structure of one service: its UUID and its characteristics'
/// UUIDs (stable across reconnects, unlike the bluest handles).
#[derive(Clone)]
struct ServiceShape {
    uuid: String,
    char_uuids: Vec<String>,
}

/// A `GattConnection` over a connected `bluest` [`Device`] that reconnects and
/// retries on a dropped link.
pub struct BluestConnection {
    adapter: Adapter,
    device: Device,
    /// Lowercased characteristic UUID -> the (current) bluest handle.
    chars: Mutex<HashMap<String, Characteristic>>,
    /// The service/characteristic UUID structure (stable across reconnects).
    shape: Vec<ServiceShape>,
    reconnects: Mutex<u32>,
}

impl BluestConnection {
    /// Wrap an already-connected device, discovering its services and
    /// characteristics.
    ///
    /// # Errors
    /// Returns [`BleError::Backend`] on a bluest discovery failure.
    pub async fn new(adapter: Adapter, device: Device) -> Result<Self> {
        let (chars, shape) = Self::discover(&device).await?;
        Ok(Self {
            adapter,
            device,
            chars: Mutex::new(chars),
            shape,
            reconnects: Mutex::new(0),
        })
    }

    async fn discover(
        device: &Device,
    ) -> Result<(HashMap<String, Characteristic>, Vec<ServiceShape>)> {
        let mut chars = HashMap::new();
        let mut shape = Vec::new();
        for svc in device.discover_services().await.map_err(be)? {
            let mut char_uuids = Vec::new();
            for ch in svc.discover_characteristics().await.map_err(be)? {
                let uuid = ch.uuid().to_string().to_ascii_lowercase();
                char_uuids.push(uuid.clone());
                chars.insert(uuid, ch);
            }
            shape.push(ServiceShape {
                uuid: svc.uuid().to_string(),
                char_uuids,
            });
        }
        Ok((chars, shape))
    }

    /// Re-establish the link and rebuild the characteristic handle map. The
    /// UUID structure ([`shape`](Self::shape)) is unchanged.
    async fn reconnect(&self) -> Result<()> {
        {
            let mut n = self.reconnects.lock().await;
            if *n >= MAX_RECONNECTS {
                return Err(BleError::Disconnected);
            }
            *n += 1;
        }
        let _ = self.adapter.disconnect_device(&self.device).await;
        let _ = self.adapter.wait_available().await;
        self.adapter
            .connect_device(&self.device)
            .await
            .map_err(be)?;
        let (fresh, _shape) = Self::discover(&self.device).await?;
        *self.chars.lock().await = fresh;
        Ok(())
    }

    /// Look up the current handle for a characteristic UUID.
    async fn handle(&self, char_uuid: &str) -> Result<Characteristic> {
        self.chars
            .lock()
            .await
            .get(&char_uuid.to_ascii_lowercase())
            .cloned()
            .ok_or(BleError::MalformedPdu("gatt characteristic not found"))
    }

    /// Read a characteristic's HAP instance-id descriptor, reconnecting on drop.
    async fn read_iid(&self, char_uuid: &str) -> Result<Option<u16>> {
        loop {
            let ch = self.handle(char_uuid).await?;
            let attempt = async {
                let descriptors = ch.discover_descriptors().await.map_err(be)?;
                let Some(desc) = descriptors.iter().find(|d| {
                    d.uuid()
                        .to_string()
                        .eq_ignore_ascii_case(HAP_INSTANCE_ID_DESC)
                }) else {
                    return Ok(None);
                };
                Ok(u16_le(&desc.read().await.map_err(be)?))
            }
            .await;
            match attempt {
                Ok(v) => return Ok(v),
                Err(ref e) if is_disconnect(e) => self.reconnect().await?,
                Err(e) => return Err(e),
            }
        }
    }
}

#[async_trait]
impl GattConnection for BluestConnection {
    async fn instance_id(&self, char_uuid: &str) -> Result<u16> {
        self.read_iid(char_uuid)
            .await?
            .ok_or(BleError::MalformedPdu("no instance id descriptor"))
    }

    async fn write(&self, char_uuid: &str, value: &[u8]) -> Result<()> {
        loop {
            let ch = self.handle(char_uuid).await?;
            match ch.write(value).await.map_err(be) {
                Ok(()) => return Ok(()),
                Err(ref e) if is_disconnect(e) => self.reconnect().await?,
                Err(e) => return Err(e),
            }
        }
    }

    async fn read(&self, char_uuid: &str) -> Result<Vec<u8>> {
        loop {
            let ch = self.handle(char_uuid).await?;
            match ch.read().await.map_err(be) {
                Ok(v) => return Ok(v),
                Err(ref e) if is_disconnect(e) => self.reconnect().await?,
                Err(e) => return Err(e),
            }
        }
    }

    async fn subscribe(&self, char_uuid: &str) -> Result<mpsc::Receiver<Vec<u8>>> {
        let ch = self.handle(char_uuid).await?;
        let (tx, rx) = mpsc::channel(16);
        tokio::spawn(async move {
            use tokio_stream::StreamExt as _;
            if let Ok(mut stream) = ch.notify().await {
                while let Some(item) = stream.next().await {
                    let Ok(v) = item else { break };
                    if tx.send(v).await.is_err() {
                        break;
                    }
                }
            }
        });
        Ok(rx)
    }

    async fn enumerate(&self) -> Result<Vec<GattService>> {
        let mut services = Vec::new();
        for svc in &self.shape {
            let mut characteristics = Vec::new();
            for char_uuid in &svc.char_uuids {
                // The Service-Instance-ID characteristic is not a HAP
                // characteristic; its value would need a paired read.
                if char_uuid.eq_ignore_ascii_case(HAP_SERVICE_ID_CHAR) {
                    continue;
                }
                // Per-characteristic resilient instance-id read: resumes the
                // sweep across the device's periodic disconnects.
                if let Some(iid) = self.read_iid(char_uuid).await? {
                    characteristics.push(GattCharacteristic {
                        uuid: char_uuid.clone(),
                        iid,
                    });
                }
            }
            services.push(GattService {
                uuid: svc.uuid.clone(),
                iid: 0,
                characteristics,
            });
        }
        Ok(services)
    }
}
