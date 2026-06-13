//! BLE discovery: parse the HAP manufacturer advertisement and scan for
//! accessories.

use crate::error::Result;
use crate::gatt::BtleplugConnection;
use btleplug::api::{Central, Manager as _, Peripheral as _, ScanFilter};
use btleplug::platform::Manager;
use std::sync::Arc;
use std::time::Duration;

/// Apple's Bluetooth company identifier; HAP advertisements live under it.
const APPLE_COMPANY_ID: u16 = 0x004C;

/// Scan for HAP accessories advertising over BLE for `timeout`.
///
/// # Errors
/// Returns [`crate::error::BleError::Bluetooth`] on adapter/scan failures.
pub async fn scan(timeout: Duration) -> Result<Vec<DiscoveredBleAccessory>> {
    let manager = Manager::new().await?;
    let adapters = manager.adapters().await?;
    let central = adapters
        .into_iter()
        .next()
        .ok_or(crate::error::BleError::AccessoryNotFound)?;
    central.start_scan(ScanFilter::default()).await?;
    tokio::time::sleep(timeout).await;

    let mut found = Vec::new();
    for p in central.peripherals().await? {
        let Some(props) = p.properties().await? else { continue };
        if let Some(mfg) = props.manufacturer_data.get(&APPLE_COMPANY_ID) {
            if let Some(acc) = parse_hap_advert(mfg, p.id().to_string()) {
                found.push(acc);
            }
        }
    }
    central.stop_scan().await?;
    Ok(found)
}

/// Connect to a discovered accessory and return a GATT link to it.
///
/// # Errors
/// Returns [`crate::error::BleError`] on connect/discovery failure.
pub async fn connect_gatt(accessory: &DiscoveredBleAccessory) -> Result<Arc<BtleplugConnection>> {
    let manager = Manager::new().await?;
    let central = manager
        .adapters()
        .await?
        .into_iter()
        .next()
        .ok_or(crate::error::BleError::AccessoryNotFound)?;
    for p in central.peripherals().await? {
        if p.id().to_string() == accessory.peripheral_id {
            p.connect().await?;
            p.discover_services().await?;
            return Ok(Arc::new(BtleplugConnection::new(p)));
        }
    }
    Err(crate::error::BleError::AccessoryNotFound)
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
}

/// Parse a HAP manufacturer-data payload (the bytes after the 0x004C company id)
/// into a [`DiscoveredBleAccessory`]. Returns `None` if it is not a HAP advert.
pub(crate) fn parse_hap_advert(mfg: &[u8], peripheral_id: String) -> Option<DiscoveredBleAccessory> {
    // Byte 0 must be the HomeKit advertising type (0x06); minimum length 17.
    if mfg.len() < 17 || mfg[0] != 0x06 {
        return None;
    }
    let status = mfg[2];
    let device_id = {
        use std::fmt::Write as _;
        mfg[3..9].iter().fold(String::new(), |mut s, b| {
            if !s.is_empty() {
                s.push(':');
            }
            let _ = write!(s, "{b:02x}");
            s
        })
    };
    let category = u16::from_le_bytes([mfg[9], mfg[10]]);
    let global_state_number = u16::from_le_bytes([mfg[11], mfg[12]]);
    let config_number = mfg[13];
    // Status-flag bit 0 set = "not paired" advertisement (the pairing flag is
    // inverted on the wire). Confirmed against hardware in a later task.
    let paired = status & 0x01 == 0;
    Some(DiscoveredBleAccessory {
        peripheral_id,
        device_id,
        category,
        global_state_number,
        config_number,
        paired,
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
    }

    #[test]
    fn rejects_non_hap_advert() {
        assert!(parse_hap_advert(&[0x01, 0x02], "x".into()).is_none());
    }
}
