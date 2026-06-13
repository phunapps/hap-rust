//! The encrypted BLE session: seal outgoing PDUs and open incoming ones with
//! the Pair-Verify `SessionKeys` and per-direction counters.

use crate::error::Result;
use hap_crypto::SessionKeys;

/// Build a 12-byte BLE session nonce from a 64-bit counter: four zero bytes
/// followed by the little-endian counter.
fn nonce(counter: u64) -> [u8; 12] {
    let mut n = [0u8; 12];
    n[4..].copy_from_slice(&counter.to_le_bytes());
    n
}

/// An established BLE secure session. Seals whole PDUs with the controller's
/// `write_key` and opens responses with the `read_key`, each direction carrying
/// its own monotonically increasing counter.
pub(crate) struct BleSession {
    keys: SessionKeys,
    send_counter: u64,
    recv_counter: u64,
}

impl BleSession {
    /// Create a session from Pair-Verify keys, both counters at zero.
    pub(crate) fn new(keys: SessionKeys) -> Self {
        Self { keys, send_counter: 0, recv_counter: 0 }
    }

    /// Encrypt an outgoing PDU and advance the send counter.
    ///
    /// # Errors
    /// Returns [`crate::error::BleError::Crypto`] if the AEAD seal fails.
    pub(crate) fn seal(&mut self, pdu: &[u8]) -> Result<Vec<u8>> {
        let out = hap_crypto::aead::chacha20poly1305_seal(
            &self.keys.write_key,
            &nonce(self.send_counter),
            &[],
            pdu,
        )?;
        self.send_counter += 1;
        Ok(out)
    }

    /// Decrypt an incoming PDU and advance the receive counter.
    ///
    /// # Errors
    /// Returns [`crate::error::BleError::Crypto`] if authentication fails.
    pub(crate) fn open(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        let out = hap_crypto::aead::chacha20poly1305_open(
            &self.keys.read_key,
            &nonce(self.recv_counter),
            &[],
            data,
        )?;
        self.recv_counter += 1;
        Ok(out)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use hap_crypto::SessionKeys;

    #[test]
    fn seal_then_peer_open_roundtrips() {
        // Controller seals with write_key/send_counter; the peer opens with the
        // same key as its read_key and the same counter.
        let keys = SessionKeys { read_key: [7u8; 32], write_key: [9u8; 32] };
        let mut ctrl = BleSession::new(keys);
        let pdu = vec![0x00, 0x03, 0x11, 0x03, 0x02];

        let sealed = ctrl.seal(&pdu).unwrap();
        assert_ne!(sealed, pdu);
        assert_eq!(sealed.len(), pdu.len() + 16); // + Poly1305 tag

        // Peer side: read with controller's write_key, counter 0.
        let opened =
            hap_crypto::aead::chacha20poly1305_open(&[9u8; 32], &nonce(0), &[], &sealed).unwrap();
        assert_eq!(opened, pdu);
    }

    #[test]
    fn counters_advance_per_message() {
        let keys = SessionKeys { read_key: [1u8; 32], write_key: [2u8; 32] };
        let mut s = BleSession::new(keys);
        let a = s.seal(&[1, 2, 3]).unwrap();
        let b = s.seal(&[1, 2, 3]).unwrap();
        assert_ne!(a, b); // same plaintext, different nonce -> different ciphertext
    }

    #[test]
    fn open_uses_read_key_and_recv_counter() {
        let keys = SessionKeys { read_key: [5u8; 32], write_key: [6u8; 32] };
        let mut s = BleSession::new(keys);
        // Simulate the accessory sealing with the controller's read_key, counter 0.
        let cipher =
            hap_crypto::aead::chacha20poly1305_seal(&[5u8; 32], &nonce(0), &[], &[9, 9]).unwrap();
        assert_eq!(s.open(&cipher).unwrap(), vec![9, 9]);
    }
}
