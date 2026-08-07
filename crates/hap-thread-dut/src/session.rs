//! The accessory side of the CoAP secure session.
//!
//! Mirrors `hap-thread`'s controller session with the directions reversed: the
//! controller seals requests with the **write** key and opens responses with
//! the **read** key, so the accessory **opens requests with the write key** and
//! **seals responses with the read key**. Events (accessory→controller) use the
//! dedicated event key. Empty AAD, whole-payload framing, `[0;4]‖counter` nonce
//! — all identical to the controller.

use hap_crypto::aead::{chacha20poly1305_open, chacha20poly1305_seal};

use crate::error::Result;
use crate::hap::nonce_counter;

/// A verified session's keys and per-direction counters (accessory side).
pub(crate) struct AccessorySession {
    read_key: [u8; 32],
    write_key: [u8; 32],
    /// The event channel key (accessory→controller reverse PUT).
    event_key: [u8; 32],
    recv_ctr: u64,
    send_ctr: u64,
    event_ctr: u64,
}

impl AccessorySession {
    /// Build a session from the three derived keys. Counters start at 0.
    pub(crate) fn new(read_key: [u8; 32], write_key: [u8; 32], event_key: [u8; 32]) -> Self {
        Self {
            read_key,
            write_key,
            event_key,
            recv_ctr: 0,
            send_ctr: 0,
            event_ctr: 0,
        }
    }

    /// Decrypt a controller→accessory request (sealed by the controller with the
    /// write key) and advance the recv counter.
    ///
    /// # Errors
    /// [`crate::DutError::Crypto`] if authentication fails.
    pub(crate) fn open_request(&mut self, ciphertext_and_tag: &[u8]) -> Result<Vec<u8>> {
        let nonce = nonce_counter(self.recv_ctr);
        let pt = chacha20poly1305_open(&self.write_key, &nonce, &[], ciphertext_and_tag)?;
        self.recv_ctr = self.recv_ctr.wrapping_add(1);
        Ok(pt)
    }

    /// Encrypt an accessory→controller response (the controller opens it with
    /// the read key) and advance the send counter.
    ///
    /// # Errors
    /// [`crate::DutError::Crypto`] on an internal AEAD failure.
    pub(crate) fn seal_response(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let nonce = nonce_counter(self.send_ctr);
        let ct = chacha20poly1305_seal(&self.read_key, &nonce, &[], plaintext)?;
        self.send_ctr = self.send_ctr.wrapping_add(1);
        Ok(ct)
    }

    /// Encrypt an accessory→controller **event** payload (the controller opens it
    /// with the event key) and advance the event counter. The event channel has
    /// its own key and counter, independent of request/response traffic.
    ///
    /// # Errors
    /// [`crate::DutError::Crypto`] on an internal AEAD failure.
    pub(crate) fn seal_event(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let nonce = nonce_counter(self.event_ctr);
        let ct = chacha20poly1305_seal(&self.event_key, &nonce, &[], plaintext)?;
        self.event_ctr = self.event_ctr.wrapping_add(1);
        Ok(ct)
    }
}
