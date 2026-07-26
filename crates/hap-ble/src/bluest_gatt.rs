//! A [`GattConnection`] backed by the `bluest` crate, with a **reconnect-and-
//! resume supervisor**: sleepy HAP accessories drop the link every few
//! operations during the long attribute-database sweep, so each operation
//! reconnects (re-discovering its characteristic handles by UUID) and retries
//! on a clean disconnect, resuming where it left off.

use crate::error::{BleError, Result};
use crate::gatt::{
    u16_le, AdvertSource, GattCharacteristic, GattConnection, GattService, RawAdvert,
    HAP_INSTANCE_ID_DESC, HAP_SERVICE_ID_CHAR,
};
use crate::scan_gate::ScanGate;
use async_trait::async_trait;
use bluest::error::ErrorKind;
use bluest::{Adapter, Characteristic, Device};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, Mutex};

/// Per-attempt timeout for re-establishing the link (connect + service
/// discovery). On macOS a `connect_device` attempted while a scan is running can
/// hang indefinitely; bounding it (as aiohomekit does via `bleak_retry_connector`)
/// turns a wedged connect into a failed attempt the backstop can retry.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Per-attempt timeout for the pre-connect teardown (disconnect + adapter
/// wait). On the pause-ack-timeout escape path these run while a scan may
/// still be live and can hang exactly like the connect; bounding them turns
/// that into a failed attempt the backstop retries instead of a wedge that
/// blocks every later operation behind the scan gate's lock.
const TEARDOWN_TIMEOUT: Duration = Duration::from_secs(5);

/// The HAP Service-Signature characteristic — appears in *every* service. Only
/// the one in the Protocol Information service is addressable/used; the rest are
/// dropped during discovery so the (UUID-keyed) handle map doesn't collide and
/// the generate-broadcast-key write reaches the correct characteristic.
const SERVICE_SIGNATURE_CHAR: &str = "000000a5-0000-1000-8000-0026bb765291";
/// The HAP Protocol Information service — the one whose Service-Signature char is
/// the generate-broadcast-key target (matches aiohomekit's service-scoped lookup).
const PROTOCOL_INFO_SERVICE: &str = "000000a2-0000-1000-8000-0026bb765291";

/// Consecutive reconnects allowed *within a single operation* before it gives up
/// (a runaway backstop). This bounds one stuck read/write, not the connection's
/// lifetime — a sleepy accessory may legitimately drop the link on most
/// operations, so a healthy long-lived subscription can far exceed this in
/// aggregate; only a link that will not stay up for one op long enough to make
/// progress trips it.
const MAX_OP_RECONNECTS: u32 = 8;

/// Map a bluest error to a [`BleError`], classifying link-loss conditions as
/// [`BleError::Disconnected`] (so the supervisor reconnects) from bluest's typed
/// [`ErrorKind`] rather than by string-matching. A [`Timeout`](ErrorKind::Timeout)
/// is treated as a disconnect: on some platforms a dropped link surfaces as a
/// read/write timeout, and a reconnect+retry against a merely-slow accessory is
/// cheap and self-correcting. A [`NotFound`](ErrorKind::NotFound) is too: on
/// macOS an operation against a slept accessory's stale characteristic handle
/// reports it, and the reconnect re-discovers the handles.
// By value for ergonomic `.map_err(be)`.
#[allow(clippy::needless_pass_by_value)]
pub(crate) fn be(e: bluest::Error) -> BleError {
    match e.kind() {
        ErrorKind::NotConnected
        | ErrorKind::AdapterUnavailable
        | ErrorKind::ConnectionFailed
        | ErrorKind::ServiceChanged
        | ErrorKind::NotReady
        | ErrorKind::NotFound
        | ErrorKind::Timeout => BleError::Disconnected,
        _ => BleError::Backend(e.to_string()),
    }
}

/// Whether an error means the link dropped (so reconnecting may recover).
fn is_disconnect(e: &BleError) -> bool {
    matches!(e, BleError::Disconnected)
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
    /// Increments on every reconnect — also the backstop count. A change since a
    /// secure session was established means the accessory dropped that session.
    generation: AtomicU64,
    /// Coordinates the continuous advert scan with connects: on macOS
    /// CoreBluetooth a connect cannot complete while a scan is running, so
    /// `reconnect`/`disconnect` pause the scan for their duration.
    scan_gate: Arc<ScanGate>,
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
            generation: AtomicU64::new(0),
            scan_gate: ScanGate::new(),
        })
    }

    /// Release the active GATT link. A sleepy HAP accessory only advertises and
    /// emits encrypted broadcasts while disconnected, and on macOS CoreBluetooth
    /// filters a connected peripheral out of scan results — so a caller watching
    /// for sleepy events must disconnect after setup. A subsequent encrypted
    /// operation (e.g. a disconnected-event poll read) transparently reconnects
    /// via the supervisor.
    pub async fn disconnect(&self) {
        // Pause the scan for the teardown: on macOS a disconnect cannot
        // complete while a scan is running.
        let _scan_pause = self.scan_gate.pause().await;
        let _ = tokio::time::timeout(
            TEARDOWN_TIMEOUT,
            self.adapter.disconnect_device(&self.device),
        )
        .await;
    }

    async fn discover(
        device: &Device,
    ) -> Result<(HashMap<String, Characteristic>, Vec<ServiceShape>)> {
        let mut chars = HashMap::new();
        let mut shape = Vec::new();
        for svc in device.discover_services().await.map_err(be)? {
            let svc_uuid = svc.uuid().to_string().to_ascii_lowercase();
            let is_protocol_info = svc_uuid == PROTOCOL_INFO_SERVICE;
            let mut char_uuids = Vec::new();
            for ch in svc.discover_characteristics().await.map_err(be)? {
                let uuid = ch.uuid().to_string().to_ascii_lowercase();
                char_uuids.push(uuid.clone());
                // The Service-Signature char exists in every service and they all
                // share one UUID; keep only the Protocol Information service's so
                // the UUID-keyed handle map resolves the generate-broadcast-key
                // target deterministically (and survives reconnects, unlike an
                // iid-keyed map that would need a re-sweep).
                if uuid == SERVICE_SIGNATURE_CHAR && !is_protocol_info {
                    continue;
                }
                chars.insert(uuid, ch);
            }
            shape.push(ServiceShape {
                uuid: svc.uuid().to_string(),
                char_uuids,
            });
        }
        Ok((chars, shape))
    }

    /// Re-establish the link and rebuild the characteristic handle map, advancing
    /// the link [`generation`](Self::generation). The UUID structure
    /// ([`shape`](Self::shape)) is unchanged.
    async fn reconnect(&self) -> Result<()> {
        self.generation.fetch_add(1, Ordering::SeqCst);
        // Own the radio for the whole teardown + connect: on macOS
        // CoreBluetooth a connect (or disconnect/wait_available) cannot
        // complete while a scan is running. The guard resumes the scan when
        // dropped — on success and on every error path alike.
        let _scan_pause = self.scan_gate.pause().await;
        let _ = tokio::time::timeout(TEARDOWN_TIMEOUT, async {
            let _ = self.adapter.disconnect_device(&self.device).await;
            let _ = self.adapter.wait_available().await;
        })
        .await;
        // Bound the connect + service discovery: a connect attempted while a scan
        // is running can wedge on macOS, so a timeout surfaces as a recoverable
        // disconnect that the per-operation backstop retries rather than hanging.
        let establish = async {
            self.adapter
                .connect_device(&self.device)
                .await
                .map_err(be)?;
            Self::discover(&self.device).await
        };
        let (fresh, _shape) = tokio::time::timeout(CONNECT_TIMEOUT, establish)
            .await
            .map_err(|_| BleError::Disconnected)??;
        *self.chars.lock().await = fresh;
        Ok(())
    }

    /// Reconnect for one in-flight operation, giving up once a single operation
    /// has forced [`MAX_OP_RECONNECTS`] reconnects without making progress (the
    /// link will not stay up long enough to complete it). `attempts` is the
    /// per-operation reconnect count, owned by the caller's retry loop — it does
    /// not bound the connection's lifetime.
    async fn reconnect_bounded(&self, attempts: &mut u32) -> Result<()> {
        *attempts += 1;
        if *attempts > MAX_OP_RECONNECTS {
            return Err(BleError::Disconnected);
        }
        self.reconnect().await
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
        let mut attempts = 0;
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
                Err(ref e) if is_disconnect(e) => self.reconnect_bounded(&mut attempts).await?,
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

    async fn max_write(&self) -> usize {
        // The MTU is connection-wide, so any characteristic's max write works.
        let ch = self.chars.lock().await.values().next().cloned();
        ch.and_then(|c| c.max_write_len().ok())
            .map_or(crate::gatt::DEFAULT_FRAGMENT_SIZE, |n| n.clamp(20, 512))
    }

    async fn generation(&self) -> u64 {
        self.generation.load(Ordering::SeqCst)
    }

    async fn write(&self, char_uuid: &str, value: &[u8]) -> Result<()> {
        let mut attempts = 0;
        loop {
            let ch = self.handle(char_uuid).await?;
            match ch.write(value).await.map_err(be) {
                Ok(()) => return Ok(()),
                Err(ref e) if is_disconnect(e) => self.reconnect_bounded(&mut attempts).await?,
                Err(e) => return Err(e),
            }
        }
    }

    async fn read(&self, char_uuid: &str) -> Result<Vec<u8>> {
        let mut attempts = 0;
        loop {
            let ch = self.handle(char_uuid).await?;
            match ch.read().await.map_err(be) {
                Ok(v) => return Ok(v),
                Err(ref e) if is_disconnect(e) => self.reconnect_bounded(&mut attempts).await?,
                Err(e) => return Err(e),
            }
        }
    }

    // Connected GATT notify is BEST-EFFORT: the spawned task ends when the
    // notification stream ends (a link drop). It is deliberately NOT re-armed and
    // does NOT reconnect — a sleepy accessory intentionally drops idle links, so
    // auto-reconnecting here causes a reconnect storm (validated on hardware).
    // Durable events come from the advertisement channels (broadcast +
    // disconnected-event poll); the session re-verifies lazily on the next read.
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
                // The Service-Signature char is a service-level signature, not a
                // model characteristic — skip it (it also shares a UUID across
                // services, so reading it here would yield duplicate iids).
                if char_uuid.eq_ignore_ascii_case(SERVICE_SIGNATURE_CHAR) {
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

/// Apple's Bluetooth company identifier; HAP advertisements live under it.
const APPLE_COMPANY_ID: u16 = 0x004C;

#[async_trait]
impl AdvertSource for BluestConnection {
    /// Stream Apple HAP advertisements by running a continuous adapter scan.
    ///
    /// Spawns a background task that feeds every Apple (company id `0x004C`)
    /// manufacturer-data frame into the returned channel. Forwarding is
    /// best-effort: frames are dropped when the receiver falls behind, not
    /// queued unboundedly, to ensure the task never blocks on backpressure
    /// and can always respond to a pause request. While a connect owns the
    /// radio (the [`ScanGate`] is paused) the task drops its scan stream and
    /// restarts it on resume. The task stops for good when the receiver is
    /// dropped or the adapter's scan stream ends.
    ///
    /// Intended for a single active watcher per connection: concurrent scan tasks
    /// would share one scanning flag and corrupt the pause-ack protocol.
    ///
    /// # Errors
    /// Returns [`crate::error::BleError`] on adapter/scan failures.
    async fn watch_adverts(&self) -> Result<mpsc::Receiver<RawAdvert>> {
        let adapter = self.adapter.clone();
        let gate = self.scan_gate.clone();
        let (tx, rx) = mpsc::channel(32);
        tokio::spawn(async move {
            use tokio_stream::StreamExt as _;
            let mut pause = gate.pause_watch();
            loop {
                // Hold off while a connect owns the radio.
                while *pause.borrow_and_update() {
                    if pause.changed().await.is_err() {
                        return;
                    }
                }
                let Ok(mut scan) = adapter.scan(&[]).await else {
                    return;
                };
                gate.set_scanning(true);
                let stopped_for_pause = loop {
                    tokio::select! {
                        changed = pause.changed() => {
                            match changed {
                                Ok(()) if *pause.borrow_and_update() => break true,
                                Ok(()) => {}
                                Err(_) => break false,
                            }
                        }
                        adv = scan.next() => {
                            let Some(adv) = adv else { break false };
                            let Some(md) = adv.adv_data.manufacturer_data else {
                                continue;
                            };
                            if md.company_id != APPLE_COMPANY_ID {
                                continue;
                            }
                            // Non-blocking send: a stalled consumer must not
                            // wedge this task inside an await where it cannot
                            // see a pause request. Adverts are a lossy,
                            // repeating medium — dropping a frame under
                            // backpressure is safe; holding the radio is not.
                            match tx.try_send(RawAdvert {
                                manufacturer_data: md.data,
                            }) {
                                Ok(()) | Err(mpsc::error::TrySendError::Full(_)) => {}
                                Err(mpsc::error::TrySendError::Closed(_)) => {
                                    break false; // receiver dropped — stop scanning
                                }
                            }
                        }
                    }
                };
                drop(scan);
                gate.set_scanning(false);
                if !stopped_for_pause {
                    return;
                }
            }
        });
        Ok(rx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A slept accessory's stale handle surfaces as bluest `NotFound` on
    /// macOS; it must classify as a recoverable disconnect so the supervisor
    /// reconnects (safe only because reconnect pauses the scan and bounds the
    /// connect).
    #[test]
    fn not_found_maps_to_disconnected() {
        let e = bluest::Error::from(ErrorKind::NotFound);
        assert!(matches!(be(e), BleError::Disconnected));
    }
}
