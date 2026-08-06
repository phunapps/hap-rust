//! The cold-arm connect seam: obtain a ready, post-Pair-Verify accessory for a
//! stored BLE pairing, keyed by HAP device id. Injectable so the cold-arm path
//! is testable with a mock, above the live crypto handshake.

use crate::accessory::BleAccessory;
use crate::error::Result;
use hap_crypto::{AccessoryPairing, ControllerKeypair};
use std::sync::Arc;
use std::time::Duration;

/// Format a 6-byte HAP device id as lowercase colon-separated hex, matching
/// [`crate::discovery::DiscoveredBleAccessory::device_id`]'s format. `hap-ble`
/// has no dependency on `hap-pairing` (dependencies flow strictly downward and
/// no new ones are added here), so this is a small local equivalent of
/// `hap_pairing::format_device_id`.
fn format_device_id(id: [u8; 6]) -> String {
    use std::fmt::Write as _;
    id.iter().fold(String::new(), |mut s, b| {
        if !s.is_empty() {
            s.push(':');
        }
        let _ = write!(s, "{b:02x}");
        s
    })
}

/// Establishes a connected, verified [`BleAccessory`] for a stored pairing.
#[async_trait::async_trait]
pub trait SleepyConnector: Send + Sync {
    /// Scan for `device_id`, connect, run Pair Verify with `pairing`, and return
    /// a ready accessory with its advert source set. Blocks until the device
    /// advertises.
    ///
    /// # Errors
    /// [`crate::error::BleError`] on scan/connect/verify failure.
    async fn connect(
        &self,
        device_id: [u8; 6],
        pairing: &AccessoryPairing,
        broadcast: Option<crate::broadcast_state::BleBroadcastState>,
    ) -> Result<BleAccessory>;
}

/// The real bluest-backed connector: retrying scan-by-device-id, then
/// `connect_gatt` -> `BleController::connect` -> `set_advert_source`.
pub struct BluestSleepyConnector {
    keypair: ControllerKeypair,
    /// How long each scan-for-the-device attempt runs before retrying.
    scan_window: Duration,
}

impl BluestSleepyConnector {
    /// Create a connector using this controller's long-term identity.
    #[must_use]
    pub fn new(keypair: ControllerKeypair) -> Self {
        Self {
            keypair,
            scan_window: Duration::from_secs(15),
        }
    }
}

#[async_trait::async_trait]
impl SleepyConnector for BluestSleepyConnector {
    async fn connect(
        &self,
        device_id: [u8; 6],
        pairing: &AccessoryPairing,
        broadcast: Option<crate::broadcast_state::BleBroadcastState>,
    ) -> Result<BleAccessory> {
        let wanted = format_device_id(device_id);
        // Retry scan-by-device-id until the sleepy device advertises. One scan
        // at a time (each attempt drops its stream before the next); the scan is
        // the "wait for first advert".
        loop {
            if let Some(found) = crate::scan(self.scan_window)
                .await?
                .into_iter()
                .find(|d| d.device_id.eq_ignore_ascii_case(&wanted))
            {
                let conn = crate::connect_gatt(&found).await?;
                let advert: Arc<dyn crate::gatt::AdvertSource> = conn.clone();
                let ble = crate::BleController::new(self.keypair.clone());
                let mut accessory = ble
                    .connect(
                        conn as Arc<dyn crate::gatt::GattConnection>,
                        pairing,
                        broadcast,
                    )
                    .await?;
                accessory.set_advert_source(advert);
                return Ok(accessory);
            }
            // not seen this window — loop and scan again
        }
    }
}
