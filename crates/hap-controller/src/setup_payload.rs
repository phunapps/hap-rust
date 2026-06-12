//! Parsing of the `X-HM://` HomeKit setup payload (the string a setup QR encodes).

use crate::error::{HapError, Result};

/// Pairing-capability flags from a setup payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SetupFlags {
    /// Supports IP (Wi-Fi/Ethernet) pairing.
    pub ip: bool,
    /// Supports BLE pairing. Not derivable from the standard `X-HM://` IP
    /// payload; always `false` here.
    pub ble: bool,
    /// Supports NFC pairing. Not derivable from the standard `X-HM://` IP
    /// payload; always `false` here.
    pub nfc: bool,
}

/// A decoded HomeKit setup payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetupPayload {
    /// The eight-digit setup code, normalized (no hyphens).
    pub setup_code: String,
    /// HAP accessory category identifier.
    pub category: u16,
    /// The 4-character setup id, if present.
    pub setup_id: Option<String>,
    /// Pairing-capability flags.
    pub flags: SetupFlags,
}

impl SetupPayload {
    /// Parse an `X-HM://` setup URI: `X-HM://` + a 9-char base-36 payload + an
    /// optional 4-char setup id.
    ///
    /// # Errors
    /// [`HapError::InvalidSetupPayload`] if the prefix is missing or the 9-char
    /// payload is not valid base-36.
    pub fn parse(uri: &str) -> Result<Self> {
        let rest = uri
            .strip_prefix("X-HM://")
            .ok_or(HapError::InvalidSetupPayload)?;
        if rest.len() < 9 {
            return Err(HapError::InvalidSetupPayload);
        }
        let (payload_str, setup_id_str) = rest.split_at(9);
        let full =
            u64::from_str_radix(payload_str, 36).map_err(|_| HapError::InvalidSetupPayload)?;
        let value_low = full & 0xFFFF_FFFF;
        let value_high = full >> 32;
        let setup_code_num = value_low & 0x7FF_FFFF;
        let ip = (value_low >> 28) & 1 == 1;
        let category = u16::try_from((value_high << 1) | ((value_low >> 31) & 1))
            .map_err(|_| HapError::InvalidSetupPayload)?;
        let setup_code = format!("{setup_code_num:08}");
        let setup_id = if setup_id_str.is_empty() {
            None
        } else {
            Some(setup_id_str.to_string())
        };
        Ok(Self {
            setup_code,
            category,
            setup_id,
            flags: SetupFlags {
                ip,
                ble: false,
                nfc: false,
            },
        })
    }
}
