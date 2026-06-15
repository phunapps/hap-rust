//! Typed HAP-BLE advertisement parsing (manufacturer-data, company id 0x004C).
//! Two relevant types: regular HAP advert (0x06) and encrypted notification
//! (0x11). The 0x06 device id and 0x11 advertising id are the stable HAP Device
//! ID we match accessories by (NOT the platform BLE address).

/// A parsed HAP advertisement of interest to the controller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HapAdvert {
    /// Regular HAP advertisement (type 0x06): carries the device id and GSN.
    Regular {
        /// The accessory's 6-byte HAP Device ID.
        device_id: [u8; 6],
        /// Global State Number (bumps on every event while paired).
        gsn: u16,
        /// True if the accessory reports itself paired (status bit0 clear).
        paired: bool,
    },
    /// Encrypted broadcast notification (type 0x11): an encrypted value change.
    EncryptedNotification {
        /// The 6-byte advertising identifier (also the AEAD AAD).
        advertising_id: [u8; 6],
        /// Ciphertext with the 16-byte Poly1305 tag appended.
        payload: Vec<u8>,
    },
}

impl HapAdvert {
    /// Parse Apple (0x004C) HAP manufacturer-data. Returns `None` for non-HAP or
    /// malformed/too-short input.
    #[must_use]
    pub fn parse(mfg: &[u8]) -> Option<Self> {
        match mfg.first()? {
            0x06 if mfg.len() >= 13 => {
                let mut device_id = [0u8; 6];
                device_id.copy_from_slice(&mfg[3..9]);
                let gsn = u16::from_le_bytes([mfg[11], mfg[12]]);
                let paired = mfg[2] & 0x01 == 0;
                Some(Self::Regular { device_id, gsn, paired })
            }
            0x11 if mfg.len() >= 8 => {
                let mut advertising_id = [0u8; 6];
                advertising_id.copy_from_slice(&mfg[2..8]);
                Some(Self::EncryptedNotification {
                    advertising_id,
                    payload: mfg[8..].to_vec(),
                })
            }
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    #[allow(clippy::unwrap_used)]
    fn parses_regular_0x06_advert() {
        let mfg = [0x06, 0x21, 0x01, 1, 2, 3, 4, 5, 6, 0x01, 0x00, 0x05, 0x00, 0x01, 0x00];
        let a = HapAdvert::parse(&mfg).unwrap();
        match a {
            HapAdvert::Regular { device_id, gsn, paired } => {
                assert_eq!(device_id, [1, 2, 3, 4, 5, 6]);
                assert_eq!(gsn, 5);
                assert!(!paired);
            }
            HapAdvert::EncryptedNotification { .. } => panic!("expected Regular"),
        }
    }
    #[test]
    #[allow(clippy::unwrap_used)]
    fn parses_encrypted_0x11_advert() {
        let mfg = [0x11, 0x00, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 9, 9, 9];
        let a = HapAdvert::parse(&mfg).unwrap();
        match a {
            HapAdvert::EncryptedNotification { advertising_id, payload } => {
                assert_eq!(advertising_id, [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
                assert_eq!(payload, vec![9, 9, 9]);
            }
            HapAdvert::Regular { .. } => panic!("expected EncryptedNotification"),
        }
    }
    #[test]
    fn rejects_short_advert() {
        assert!(HapAdvert::parse(&[0x06, 0x21]).is_none());
    }
}
