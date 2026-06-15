//! HAP-BLE broadcast-notification encryption key. The accessory broadcasts
//! encrypted value changes in its advertisements while disconnected; the
//! controller decrypts them with this key, derived once per broadcast-key
//! generation and persisted as pairing material.
//!
//! Broadcasts use a ChaCha20-Poly1305 construction with a **4-byte truncated
//! Poly1305 tag** (HomeKit-specific), so `open` composes the `chacha20` and
//! `poly1305` component crates rather than the 16-byte `aead`.

use crate::error::{CryptoError, Result};
use crate::kdf::hkdf_sha512;
use zeroize::{Zeroize, ZeroizeOnDrop};

const BROADCAST_INFO: &[u8] = b"Broadcast-Encryption-Key";

/// A 32-byte ChaCha20-Poly1305 key for decrypting encrypted broadcast
/// notifications. Zeroized on drop; its `Debug` is redacted.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct BroadcastKey([u8; 32]);

impl core::fmt::Debug for BroadcastKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("BroadcastKey(<redacted>)")
    }
}

impl BroadcastKey {
    /// Derive the broadcast key via HKDF-SHA512, info `"Broadcast-Encryption-Key"`.
    /// `ikm` is the Pair-Verify shared secret; `salt` the controller LTPK.
    ///
    /// # Errors
    /// [`CryptoError`] on an HKDF length error (never for 32-byte output).
    pub fn derive(ikm: &[u8], salt: &[u8]) -> Result<Self> {
        let mut out = [0u8; 32];
        hkdf_sha512(ikm, salt, BROADCAST_INFO, &mut out)?;
        Ok(Self(out))
    }

    /// Wrap raw key bytes (restored from persisted broadcast state).
    #[must_use]
    pub fn from_bytes(key: [u8; 32]) -> Self {
        Self(key)
    }

    /// The raw key bytes, for caller persistence. Handle as a secret.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Encrypt `plaintext` into a broadcast payload `ciphertext || tag[:4]` for
    /// `gsn`, binding the 6-byte `advertising_id` as AAD. Uses the HAP 4-byte
    /// partial Poly1305 tag — the symmetric counterpart of [`BroadcastKey::open`].
    ///
    /// The returned `Vec<u8>` is `ciphertext || 4-byte-tag`, ready to append to a
    /// `0x11` advertisement after the advertising id. Primarily useful for tests
    /// and tooling (an accessory seals; a controller opens).
    #[must_use]
    pub fn seal(&self, gsn: u16, plaintext: &[u8], advertising_id: &[u8; 6]) -> Vec<u8> {
        use chacha20::cipher::{KeyIvInit, StreamCipher};
        use poly1305::universal_hash::{KeyInit, UniversalHash};

        // Same 12-byte IETF nonce as `open`.
        let mut nonce = [0u8; 12];
        nonce[4..].copy_from_slice(&u64::from(gsn).to_le_bytes());

        let mut cipher = chacha20::ChaCha20::new(
            chacha20::Key::from_slice(&self.0),
            chacha20::Nonce::from_slice(&nonce),
        );
        // Block 0: derive the Poly1305 one-time key.
        let mut poly_block = zeroize::Zeroizing::new([0u8; 64]);
        cipher.apply_keystream(&mut *poly_block);

        // Encrypt at block 1 (cipher already positioned there).
        let mut ciphertext = plaintext.to_vec();
        cipher.apply_keystream(&mut ciphertext);

        // Compute the RFC 8439 MAC over the ciphertext.
        let mut mac = poly1305::Poly1305::new(poly1305::Key::from_slice(&poly_block[..32]));
        mac.update_padded(&mac_data(advertising_id, &ciphertext));
        let full_tag = mac.finalize();

        // Append the first 4 bytes of the Poly1305 tag (HAP broadcast convention).
        ciphertext.extend_from_slice(&full_tag.as_slice()[..4]);
        ciphertext
    }

    /// Decrypt one encrypted broadcast payload `combined_text` (= `ciphertext ||
    /// tag[:4]`) for `gsn`, binding the 6-byte `advertising_id` as AAD. Uses the
    /// HAP 4-byte partial Poly1305 tag.
    ///
    /// # Errors
    /// [`CryptoError::Aead`] if the partial tag does not match (wrong
    /// key/gsn/aad or tampered payload) or the input is too short.
    pub fn open(
        &self,
        gsn: u16,
        combined_text: &[u8],
        advertising_id: &[u8; 6],
    ) -> Result<Vec<u8>> {
        use chacha20::cipher::{KeyIvInit, StreamCipher};
        use poly1305::universal_hash::{KeyInit, UniversalHash};
        use subtle::ConstantTimeEq;

        if combined_text.len() < 4 {
            return Err(CryptoError::Aead);
        }
        // Build the 12-byte IETF nonce: 4 zero bytes then gsn as u64 little-endian.
        let mut nonce = [0u8; 12];
        nonce[4..].copy_from_slice(&u64::from(gsn).to_le_bytes());

        let (ciphertext, tag4) = combined_text.split_at(combined_text.len() - 4);

        // Derive the Poly1305 one-time key from ChaCha20 block 0 (64 bytes).
        let mut cipher = chacha20::ChaCha20::new(
            chacha20::Key::from_slice(&self.0),
            chacha20::Nonce::from_slice(&nonce),
        );
        // Zeroized on drop: the block-0 keystream contains the Poly1305 one-time
        // key (secret-derived material).
        let mut poly_block = zeroize::Zeroizing::new([0u8; 64]);
        cipher.apply_keystream(&mut *poly_block);

        // Compute the RFC 8439 MAC over (aad || pad16 || ciphertext || pad16 ||
        // le64(aad_len) || le64(ciphertext_len)).
        let mut mac = poly1305::Poly1305::new(poly1305::Key::from_slice(&poly_block[..32]));
        mac.update_padded(&mac_data(advertising_id, ciphertext));
        let full_tag = mac.finalize();

        // Constant-time compare only the first 4 bytes of the Poly1305 tag.
        if full_tag.as_slice()[..4].ct_eq(tag4).unwrap_u8() != 1 {
            return Err(CryptoError::Aead);
        }

        // Decrypt: cipher is already positioned at block 1 after the key-gen block.
        let mut plaintext = ciphertext.to_vec();
        cipher.apply_keystream(&mut plaintext);
        Ok(plaintext)
    }
}

/// RFC 8439 AEAD MAC input: `aad || pad16 || ciphertext || pad16 ||
/// le64(aad_len) || le64(ciphertext_len)`, block-aligned.
fn mac_data(aad: &[u8], ciphertext: &[u8]) -> Vec<u8> {
    let mut d = Vec::new();
    d.extend_from_slice(aad);
    while d.len() % 16 != 0 {
        d.push(0);
    }
    d.extend_from_slice(ciphertext);
    while d.len() % 16 != 0 {
        d.push(0);
    }
    d.extend_from_slice(&(aad.len() as u64).to_le_bytes());
    d.extend_from_slice(&(ciphertext.len() as u64).to_le_bytes());
    d
}

#[cfg(test)]
// Test code only: CLAUDE.md carves out `unwrap`/`expect` for tests.
// A failed `unwrap` here is itself a test failure.
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len() / 2)
            .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap())
            .collect()
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn derive_matches_aiohomekit_vector() {
        let v: serde_json::Value = serde_json::from_str(include_str!(
            "../../../test-vectors/ble-broadcast/derive.json"
        ))
        .unwrap();
        let key = BroadcastKey::derive(
            &hex(v["ikm_hex"].as_str().unwrap()),
            &hex(v["salt_hex"].as_str().unwrap()),
        )
        .unwrap();
        assert_eq!(key.as_bytes(), &hex(v["key_hex"].as_str().unwrap())[..]);
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn open_matches_aiohomekit_partial_tag_vector() {
        let v: serde_json::Value = serde_json::from_str(include_str!(
            "../../../test-vectors/ble-broadcast/open.json"
        ))
        .unwrap();
        let mut k = [0u8; 32];
        k.copy_from_slice(&hex(v["key_hex"].as_str().unwrap()));
        let mut aid = [0u8; 6];
        aid.copy_from_slice(&hex(v["advertising_id_hex"].as_str().unwrap()));
        let key = BroadcastKey::from_bytes(k);
        let pt = key
            .open(
                u16::try_from(v["gsn"].as_u64().unwrap()).unwrap(),
                &hex(v["combined_text_hex"].as_str().unwrap()),
                &aid,
            )
            .unwrap();
        assert_eq!(pt, hex(v["plaintext_hex"].as_str().unwrap()));
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn seal_then_open_round_trip() {
        let key = BroadcastKey::from_bytes([0xABu8; 32]);
        let aid: [u8; 6] = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];
        let plaintext = b"hello world!";
        let sealed = key.seal(42, plaintext, &aid);
        let recovered = key.open(42, &sealed, &aid).unwrap();
        assert_eq!(recovered, plaintext);
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn open_rejects_wrong_key() {
        let v: serde_json::Value = serde_json::from_str(include_str!(
            "../../../test-vectors/ble-broadcast/open.json"
        ))
        .unwrap();
        let mut aid = [0u8; 6];
        aid.copy_from_slice(&hex(v["advertising_id_hex"].as_str().unwrap()));
        let key = BroadcastKey::from_bytes([0u8; 32]); // wrong key
        assert!(key
            .open(
                u16::try_from(v["gsn"].as_u64().unwrap()).unwrap(),
                &hex(v["combined_text_hex"].as_str().unwrap()),
                &aid,
            )
            .is_err());
    }
}
