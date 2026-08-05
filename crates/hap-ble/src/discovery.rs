//! BLE discovery: parse the HAP manufacturer advertisement and scan for
//! accessories.

use crate::bluest_gatt::{be, BluestConnection};
use crate::error::{BleError, Result};
use bluest::Adapter;
use std::sync::Arc;
use std::time::Duration;
use tokio_stream::StreamExt as _;

/// Apple's Bluetooth company identifier; HAP advertisements live under it.
const APPLE_COMPANY_ID: u16 = 0x004C;

/// Scan for HAP accessories advertising over BLE for `timeout`.
///
/// # Errors
/// Returns [`BleError::Backend`] on adapter/scan failures.
pub async fn scan(timeout: Duration) -> Result<Vec<DiscoveredBleAccessory>> {
    let adapter = Adapter::default()
        .await
        .ok_or(BleError::AccessoryNotFound)?;
    adapter.wait_available().await.map_err(be)?;
    let mut stream = adapter.scan(&[]).await.map_err(be)?;

    let mut found = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let deadline = tokio::time::Instant::now() + timeout;
    while let Ok(Some(adv)) = tokio::time::timeout_at(deadline, stream.next()).await {
        let Some(mfg) = adv.adv_data.manufacturer_data else {
            continue;
        };
        if mfg.company_id != APPLE_COMPANY_ID {
            continue;
        }
        if let Some(acc) = parse_hap_advert(&mfg.data, adv.device.id().to_string()) {
            if seen.insert(acc.peripheral_id.clone()) {
                found.push(acc);
            }
        }
    }
    Ok(found)
}

/// Connect to a discovered accessory and return a resilient GATT link.
///
/// # Errors
/// Returns [`BleError`] on connect/discovery failure.
pub async fn connect_gatt(accessory: &DiscoveredBleAccessory) -> Result<Arc<BluestConnection>> {
    let adapter = Adapter::default()
        .await
        .ok_or(BleError::AccessoryNotFound)?;
    adapter.wait_available().await.map_err(be)?;
    // A fresh adapter only knows peripherals it has itself scanned, so we scan
    // here to locate the target (sleepy accessories advertise intermittently).
    let mut stream = adapter.scan(&[]).await.map_err(be)?;
    let mut device = None;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(40);
    while let Ok(Some(adv)) = tokio::time::timeout_at(deadline, stream.next()).await {
        if adv.device.id().to_string() == accessory.peripheral_id {
            device = Some(adv.device);
            break;
        }
    }
    drop(stream);
    let device = device.ok_or(BleError::AccessoryNotFound)?;
    adapter.connect_device(&device).await.map_err(be)?;
    Ok(Arc::new(BluestConnection::new(adapter, device).await?))
}

/// A HAP accessory found while scanning over BLE.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveredBleAccessory {
    /// The BLE peripheral identifier (platform-specific address/UUID string)
    /// used to reconnect to this device.
    pub peripheral_id: String,
    /// The HAP device id (6-byte address, lowercase colon-separated hex).
    pub device_id: String,
    /// The accessory category identifier (ACID).
    pub category: u16,
    /// The HAP global state number (GSN) from the advertisement.
    pub global_state_number: u16,
    /// The configuration number (`c#`); a change means the DB changed.
    pub config_number: u8,
    /// Whether the accessory advertises as already paired.
    pub paired: bool,
    /// The accessory's setup hash from the advertisement (4 bytes at `[15..19]`),
    /// if the advert is long enough to include it. Used to precisely match a
    /// scanned QR to this accessory.
    pub setup_hash: Option<[u8; 4]>,
}

/// Parse a HAP manufacturer-data payload (the bytes after the 0x004C company id)
/// into a [`DiscoveredBleAccessory`]. Returns `None` if it is not a HAP advert.
pub(crate) fn parse_hap_advert(
    mfg: &[u8],
    peripheral_id: String,
) -> Option<DiscoveredBleAccessory> {
    // Minimum length 15 for the base discovery payload (through compat version).
    if mfg.len() < 15 {
        return None;
    }
    let parsed = crate::advert::HapAdvert::parse(mfg)?;
    let crate::advert::HapAdvert::Regular {
        device_id,
        gsn,
        paired,
    } = parsed
    else {
        return None;
    };
    let device_id_str = {
        use std::fmt::Write as _;
        device_id.iter().fold(String::new(), |mut s, b| {
            if !s.is_empty() {
                s.push(':');
            }
            let _ = write!(s, "{b:02x}");
            s
        })
    };
    let category = u16::from_le_bytes([mfg[9], mfg[10]]);
    let config_number = mfg[13];
    let setup_hash = if mfg.len() >= 19 {
        Some([mfg[15], mfg[16], mfg[17], mfg[18]])
    } else {
        None
    };
    Some(DiscoveredBleAccessory {
        peripheral_id,
        device_id: device_id_str,
        category,
        global_state_number: gsn,
        config_number,
        paired,
        setup_hash,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // A HAP manufacturer-data payload (Apple company id 0x004C). Layout:
    // [0]=0x06 (HomeKit type), [1]=STL (subtype<<5 | length=17), [2]=status flags,
    // [3..9]=device id (6 bytes), [9..11]=ACID category (u16 LE),
    // [11..13]=GSN (u16 LE), [13]=config number, [14]=compatible version,
    // [15..17]=setup hash.
    fn sample_mfg() -> Vec<u8> {
        let mut v = vec![0x06, (1 << 5) | 0x11, 0x01];
        v.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]); // device id
        v.extend_from_slice(&5u16.to_le_bytes()); // category 5
        v.extend_from_slice(&7u16.to_le_bytes()); // GSN 7
        v.push(2); // config number
        v.push(2); // compatible version
        v.extend_from_slice(&[0x12, 0x34]); // setup hash
        v
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn parses_hap_manufacturer_data() {
        let d = parse_hap_advert(&sample_mfg(), "11:22:33:44:55:66".into()).unwrap();
        assert_eq!(d.device_id, "aa:bb:cc:dd:ee:ff");
        assert_eq!(d.category, 5);
        assert_eq!(d.global_state_number, 7);
        assert_eq!(d.config_number, 2);
        assert_eq!(d.peripheral_id, "11:22:33:44:55:66");
        // status flag bit0 set in our sample = the "not paired" advertisement.
        assert!(!d.paired);
        // sample_mfg() is 17 bytes, so setup_hash is None.
        assert_eq!(d.setup_hash, None);
    }

    #[test]
    fn rejects_non_hap_advert() {
        assert!(parse_hap_advert(&[0x01, 0x02], "x".into()).is_none());
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn parses_setup_hash_when_present() {
        // 0x06 advert: type, STL, SF, device_id[6], ACID[2], GSN[2], config,
        // compat, setup_hash[4]  → 19 bytes.
        let mfg = [
            0x06, 0x31, 0x01, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, // type/stl/sf/devid
            0x0A, 0x00, // ACID (category 10)
            0x05, 0x00, // GSN
            0x02, // config number
            0x02, // compatible version
            0x5c, 0x8a, 0x27, 0x40, // setup hash
        ];
        let d = parse_hap_advert(&mfg, "periph-1".into()).unwrap();
        assert_eq!(d.setup_hash, Some([0x5c, 0x8a, 0x27, 0x40]));
        assert_eq!(d.device_id, "aa:bb:cc:dd:ee:ff"); // NOTE: parser lowercases
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn setup_hash_absent_on_short_advert() {
        // 17-byte advert (no 4-byte hash) → setup_hash None, still parses.
        let mfg = [
            0x06, 0x31, 0x01, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x0A, 0x00, 0x05, 0x00, 0x02,
            0x02, 0x12, 0x34,
        ];
        let d = parse_hap_advert(&mfg, "periph-1".into()).unwrap();
        assert_eq!(d.setup_hash, None);
    }
}
