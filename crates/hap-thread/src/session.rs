//! The CoAP secure session: the post-Pair-Verify record layer.
//!
//! Unlike the HAP IP transport (which frames each ≤1024-byte block as
//! `len‖ciphertext‖tag` with the length as AAD), CoAP encrypts the **whole**
//! payload as a single ChaCha20-Poly1305 message with **empty AAD**. There are
//! three directional keys, each with its own monotonic 64-bit counter:
//!
//! - controller→accessory requests use the **write** key / send counter,
//! - accessory→controller responses use the **read** key / recv counter,
//! - accessory→controller *events* use the CoAP-only **event** key / counter.
//!
//! The 96-bit nonce is four zero bytes followed by the little-endian 64-bit
//! counter (matching aiohomekit's `struct.pack("=4xQ", counter)`). Counters
//! start at 0 and increment by one after each message in their direction.

use hap_crypto::aead::{chacha20poly1305_open, chacha20poly1305_seal};
use hap_crypto::SessionKeys;

use crate::error::Result;

/// The nonce for message `counter`: `[0;4] ‖ counter.to_le_bytes()`.
fn counter_nonce(counter: u64) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[4..].copy_from_slice(&counter.to_le_bytes());
    nonce
}

/// The cryptographic state of a verified CoAP session: three directional keys
/// and their independent message counters. Pure crypto — no transport.
pub(crate) struct CoapSession {
    read_key: [u8; 32],
    write_key: [u8; 32],
    // The event channel is derived and ready now; it is consumed by the inbound
    // event server (MT-2) and exercised by tests here.
    #[cfg_attr(not(test), allow(dead_code))]
    event_key: [u8; 32],
    send_ctr: u64,
    recv_ctr: u64,
    #[cfg_attr(not(test), allow(dead_code))]
    event_ctr: u64,
}

impl CoapSession {
    /// Build a session from the Pair-Verify control keys and the CoAP event key.
    /// All counters start at 0.
    pub(crate) fn new(keys: &SessionKeys, event_key: [u8; 32]) -> Self {
        Self {
            read_key: keys.read_key,
            write_key: keys.write_key,
            event_key,
            send_ctr: 0,
            recv_ctr: 0,
            event_ctr: 0,
        }
    }

    /// Encrypt a controller→accessory request payload and advance the send
    /// counter. Returns `ciphertext ‖ tag`.
    ///
    /// # Errors
    /// [`crate::ThreadError::Crypto`] on an internal AEAD failure.
    pub(crate) fn seal_request(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let nonce = counter_nonce(self.send_ctr);
        let ct = chacha20poly1305_seal(&self.write_key, &nonce, &[], plaintext)?;
        self.send_ctr = self.send_ctr.wrapping_add(1);
        Ok(ct)
    }

    /// Decrypt an accessory→controller response and advance the recv counter.
    ///
    /// # Errors
    /// [`crate::ThreadError::Crypto`] if authentication fails (wrong key,
    /// tampered ciphertext, or counter desync).
    pub(crate) fn open_response(&mut self, ciphertext_and_tag: &[u8]) -> Result<Vec<u8>> {
        let nonce = counter_nonce(self.recv_ctr);
        let pt = chacha20poly1305_open(&self.read_key, &nonce, &[], ciphertext_and_tag)?;
        self.recv_ctr = self.recv_ctr.wrapping_add(1);
        Ok(pt)
    }

    /// Decrypt an accessory→controller event push and advance the event
    /// counter (the CoAP-only reverse channel).
    ///
    /// # Errors
    /// [`crate::ThreadError::Crypto`] if authentication fails.
    #[cfg_attr(not(test), allow(dead_code))] // consumed by the event server (MT-2)
    pub(crate) fn open_event(&mut self, ciphertext_and_tag: &[u8]) -> Result<Vec<u8>> {
        let nonce = counter_nonce(self.event_ctr);
        let pt = chacha20poly1305_open(&self.event_key, &nonce, &[], ciphertext_and_tag)?;
        self.event_ctr = self.event_ctr.wrapping_add(1);
        Ok(pt)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    fn hex32(s: &str) -> [u8; 32] {
        let mut out = [0u8; 32];
        for (i, b) in out.iter_mut().enumerate() {
            *b = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap_or(0);
        }
        out
    }

    fn keys() -> SessionKeys {
        // The synthetic control keys aiohomekit derives from shared secret 00..1f.
        SessionKeys {
            read_key: hex32("c09403ef8aa6c5045cbd8cf9bf3e665b2caed623af2be0e87c8f80f519914d3d"),
            write_key: hex32("c3ca130c7033dbe5e7ff7f91d117ead869bac476994c7a48ca170c111136ed96"),
        }
    }

    #[test]
    fn nonce_is_four_zeros_then_le_counter() {
        assert_eq!(counter_nonce(0), [0u8; 12]);
        let mut expected = [0u8; 12];
        expected[4] = 1;
        assert_eq!(counter_nonce(1), expected);
    }

    #[test]
    fn seal_request_matches_aiohomekit_and_advances_counter() {
        // Cross-verified against aiohomekit's ChaCha20Poly1305 with empty AAD and
        // the [0;4]++ctr nonce, for plaintext = a CharRead PDU.
        let pt = [0x00u8, 0x03, 0x00, 0x01, 0x00, 0x00, 0x00];
        let mut s = CoapSession::new(&keys(), [0u8; 32]);
        let ct0 = s.seal_request(&pt).unwrap();
        assert_eq!(
            ct0,
            hex::decode("298d1fa5de3bc3fb47f4a26cc72b9b6412d67bcf8a1519").unwrap()
        );
        // Counter advanced → the same plaintext now encrypts differently.
        let ct1 = s.seal_request(&pt).unwrap();
        assert_eq!(
            ct1,
            hex::decode("8132559d2380c8dc87414b6323c329017ea836f9ee77c6").unwrap()
        );
    }

    #[test]
    fn open_response_decrypts_aiohomekit_ciphertext() {
        let mut s = CoapSession::new(&keys(), [0u8; 32]);
        let ct = hex::decode("464a405687be9e43bcdccf9e74e0e0d9e4bf22498ee7").unwrap();
        let pt = s.open_response(&ct).unwrap();
        assert_eq!(pt, vec![0x02, 0x00, 0x00, 0x01, 0x00, 0x2A]);
    }

    #[test]
    fn round_trip_between_two_matched_sessions() {
        // Controller seals with write_key/send_ctr; the "accessory" opens with
        // the same write_key and its own recv counter — model that with a session
        // whose read_key == our write_key.
        let mut ctrl = CoapSession::new(&keys(), [0u8; 32]);
        let acc_keys = SessionKeys {
            read_key: keys().write_key,
            write_key: keys().read_key,
        };
        let mut acc = CoapSession::new(&acc_keys, [0u8; 32]);
        for msg in [b"hello".as_slice(), b"world", b"third"] {
            let ct = ctrl.seal_request(msg).unwrap();
            assert_eq!(acc.open_response(&ct).unwrap(), msg);
        }
    }

    #[test]
    fn open_event_decrypts_aiohomekit_ciphertext() {
        // Event key aiohomekit derives from shared secret 00..1f, and a one-record
        // event payload [reserved=0][iid=0x000A][len=1][body=0x01] it encrypts at
        // event counter 0.
        let event_key = hex32("37c286d4ae336aeead7048a00b7762b642653d0e8aa691d4d3b7f0cf621db796");
        let mut s = CoapSession::new(&keys(), event_key);
        let ct = hex::decode("354e1ad199fa7d58c5b267bdee6603c48e38e7d523ce").unwrap();
        let pt = s.open_event(&ct).unwrap();
        assert_eq!(pt, hex::decode("000a00010001").unwrap());
    }

    #[test]
    fn wrong_counter_fails_to_open() {
        let mut ctrl = CoapSession::new(&keys(), [0u8; 32]);
        let acc_keys = SessionKeys {
            read_key: keys().write_key,
            write_key: keys().read_key,
        };
        let mut acc = CoapSession::new(&acc_keys, [0u8; 32]);
        let _ = ctrl.seal_request(b"first").unwrap(); // advances ctrl.send_ctr to 1
        let ct = ctrl.seal_request(b"second").unwrap(); // sealed at counter 1
                                                        // acc.recv_ctr is still 0 → nonce mismatch → auth failure.
        assert!(acc.open_response(&ct).is_err());
    }
}
