//! [`Discovered`]: one discovery result type across transports.

use hap_transport::DiscoveredAccessory;

/// An accessory found by [`HapController::discover`](crate::HapController::discover),
/// on whichever transport answered.
#[derive(Debug, Clone)]
pub enum Discovered {
    /// Found via mDNS (`_hap._tcp`) — HAP over IP.
    Ip(DiscoveredAccessory),
    /// Found via a BLE scan — HAP over Bluetooth LE.
    #[cfg(feature = "ble")]
    Ble(hap_ble::DiscoveredBleAccessory),
}

impl Discovered {
    /// The stable accessory identifier (IP: the `id` TXT record; BLE: the HAP
    /// device id string). This is the id [`connect`](crate::HapController::connect)
    /// and the pairing store use.
    #[must_use]
    pub fn id(&self) -> &str {
        match self {
            Self::Ip(d) => &d.id,
            #[cfg(feature = "ble")]
            Self::Ble(d) => &d.device_id,
        }
    }

    /// A human-readable name. BLE advertisements carry none, so the BLE arm
    /// falls back to the device-id string.
    #[must_use]
    pub fn name(&self) -> &str {
        match self {
            Self::Ip(d) => &d.name,
            #[cfg(feature = "ble")]
            Self::Ble(d) => &d.device_id,
        }
    }

    /// Whether the accessory reports itself as already paired.
    #[must_use]
    pub fn paired(&self) -> bool {
        match self {
            Self::Ip(d) => d.paired,
            #[cfg(feature = "ble")]
            Self::Ble(d) => d.paired,
        }
    }

    /// The HAP accessory category id.
    #[must_use]
    pub fn category(&self) -> u16 {
        match self {
            Self::Ip(d) => d.category,
            #[cfg(feature = "ble")]
            Self::Ble(d) => d.category,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn ip_accessors_pass_through() -> Result<(), Box<dyn std::error::Error>> {
        let mut txt = HashMap::new();
        txt.insert("id".to_string(), "AA:BB".to_string());
        let addr: std::net::SocketAddr = "10.0.0.2:80".parse()?;
        let acc =
            hap_transport::discovery_test_support::parse_txt("plug._hap._tcp.local.", addr, &txt)?;
        let d = Discovered::Ip(acc);
        assert_eq!(d.id(), "AA:BB");
        assert_eq!(d.name(), "plug");
        assert!(d.paired()); // sf defaults to 0, so (0 & 0x1) == 0 is true
        assert_eq!(d.category(), 0); // ci defaults to 0
        Ok(())
    }

    #[cfg(feature = "ble")]
    #[test]
    fn ble_name_falls_back_to_device_id() {
        let d = Discovered::Ble(hap_ble::DiscoveredBleAccessory {
            peripheral_id: "p".into(),
            device_id: "59:fa:bc:61:09:d2".into(),
            category: 10,
            global_state_number: 1,
            config_number: 1,
            paired: true,
            setup_hash: None,
        });
        assert_eq!(d.id(), "59:fa:bc:61:09:d2");
        assert_eq!(d.name(), "59:fa:bc:61:09:d2");
        assert!(d.paired());
        assert_eq!(d.category(), 10);
    }
}
