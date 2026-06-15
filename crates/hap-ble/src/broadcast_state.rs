//! Persistable HAP-BLE broadcast material: the broadcast key + last-seen GSN.
//! Returned from pairing and accepted back on reconnect so a caller can resume
//! encrypted-broadcast decryption across process restarts (see the controller).

use hap_crypto::BroadcastKey;

/// Broadcast-notification material for one accessory, persistable by the caller.
/// Holds a secret ([`BroadcastKey`] is zeroized on drop).
#[derive(Clone)]
pub struct BleBroadcastState {
    /// The broadcast decryption key.
    pub key: BroadcastKey,
    /// The last Global State Number observed/decrypted (0 when freshly minted).
    pub gsn: u16,
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn new_state_has_zero_gsn_and_key_roundtrips() {
        let raw = [0x42u8; 32];
        let state = BleBroadcastState {
            key: BroadcastKey::from_bytes(raw),
            gsn: 0,
        };
        assert_eq!(state.gsn, 0);
        assert_eq!(state.key.as_bytes(), &raw);
    }

    #[test]
    fn gsn_can_be_updated() {
        let state = BleBroadcastState {
            key: BroadcastKey::from_bytes([0u8; 32]),
            gsn: 7,
        };
        assert_eq!(state.gsn, 7);
    }

    #[test]
    fn clone_preserves_key_and_gsn() {
        let raw = [0x11u8; 32];
        let state = BleBroadcastState {
            key: BroadcastKey::from_bytes(raw),
            gsn: 99,
        };
        let cloned = state.clone();
        assert_eq!(cloned.gsn, 99);
        assert_eq!(cloned.key.as_bytes(), &raw);
    }
}
