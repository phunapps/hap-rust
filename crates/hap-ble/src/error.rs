//! The crate-wide error type.

/// Errors from the BLE transport.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum BleError {
    /// Malformed TLV8 in a PDU body or pairing message.
    #[error("TLV8 error: {0}")]
    Tlv8(#[from] hap_tlv8::Tlv8Error),
    /// A pairing or AEAD crypto operation failed.
    #[error("crypto error: {0}")]
    Crypto(#[from] hap_crypto::CryptoError),
    /// The accessory attribute model could not be built or coerced.
    #[error("model error: {0}")]
    Model(#[from] hap_model::ModelError),
    /// An underlying Bluetooth (btleplug) error.
    #[error("bluetooth error: {0}")]
    Bluetooth(#[from] btleplug::Error),
    /// No accessory matched the discovery filter.
    #[error("accessory not found")]
    AccessoryNotFound,
    /// The requested characteristic is not in the accessory's database.
    #[error("characteristic (aid={aid}, iid={iid}) not found")]
    CharacteristicNotFound {
        /// Accessory instance id.
        aid: u64,
        /// Characteristic instance id.
        iid: u64,
    },
    /// A received HAP-BLE PDU was malformed.
    #[error("malformed HAP-BLE PDU: {0}")]
    MalformedPdu(&'static str),
    /// The accessory rejected a pairing step with a non-zero status.
    #[error("accessory rejected pairing (status {0})")]
    PairingRejected(u8),
    /// The BLE link dropped mid-operation.
    #[error("the accessory disconnected")]
    Disconnected,
    /// An error from the BLE backend (transport-library specific).
    #[error("BLE backend error: {0}")]
    Backend(String),
}

/// The crate result alias.
pub type Result<T> = core::result::Result<T, BleError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tlv8_error_converts_via_from() {
        // A lower-crate error must convert into BleError through `?`.
        fn inner() -> Result<()> {
            let _ = hap_tlv8::Tlv8Map::parse(&[0x01])?; // truncated TLV -> Tlv8Error
            Ok(())
        }
        #[allow(clippy::unwrap_used)] // test code: error path is the whole point
        let err = inner().unwrap_err();
        assert!(matches!(err, BleError::Tlv8(_)));
    }

    #[test]
    fn char_not_found_displays_ids() {
        let e = BleError::CharacteristicNotFound { aid: 1, iid: 9 };
        assert_eq!(e.to_string(), "characteristic (aid=1, iid=9) not found");
    }
}
