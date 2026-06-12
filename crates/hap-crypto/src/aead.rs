//! ChaCha20-Poly1305 authenticated encryption for Pair Setup.
//!
//! HomeKit uses the IETF construction of ChaCha20-Poly1305 (RFC 8439): a
//! 256-bit key, a 96-bit (12-byte) nonce, and a 128-bit (16-byte) Poly1305
//! authentication tag appended to the ciphertext. The encrypted M5/M6 sub-TLVs
//! of Pair Setup are sealed with this AEAD.
//!
//! The primitive is never reimplemented; it comes from the RustCrypto
//! [`chacha20poly1305`] crate.
//!
//! # HAP nonce layout
//!
//! HAP builds the 12-byte nonce as four leading zero bytes followed by an
//! 8-byte ASCII label (the 64-bit counter region is left-zero-padded and the
//! label occupies its low bytes):
//!
//! ```text
//! byte:  0 1 2 3 | 4 5 6 7 8 9 10 11
//!        0 0 0 0 |    label[0..8]
//! ```
//!
//! For example the M5 label `b"PS-Msg05"` (exactly 8 bytes) yields the nonce
//! `[0, 0, 0, 0, b'P', b'S', b'-', b'M', b's', b'g', b'0', b'5']`. Labels
//! shorter than 8 bytes occupy the low bytes of the 8-byte region, leaving the
//! remaining high bytes zero. See [`hap_nonce`].

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};

use crate::error::{CryptoError, Result};

/// Build a 12-byte HAP nonce: four zero bytes followed by an 8-byte counter
/// region whose low bytes hold `label` (left-zero-padded if `label` is shorter
/// than 8 bytes). See the [module docs](self) for the exact layout.
///
/// Labels longer than 8 bytes are truncated to their first 8 bytes; HAP labels
/// (e.g. `b"PS-Msg05"`) are always exactly 8 bytes.
#[allow(dead_code)] // Consumed by the Pair Setup M5/M6 steps (Chunk C).
pub(crate) fn hap_nonce(label: &[u8]) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    let n = label.len().min(8);
    // Place the label in the low bytes of the 8-byte counter region (bytes
    // 4..12), leaving any unused high bytes zero.
    nonce[4..4 + n].copy_from_slice(&label[..n]);
    nonce
}

/// Encrypt `plaintext` with ChaCha20-Poly1305 under `key`/`nonce`, binding
/// `aad`, returning `ciphertext || tag` (the 16-byte Poly1305 tag is appended).
///
/// # Errors
///
/// Returns [`CryptoError::Aead`] only on an internal AEAD usage error; for
/// well-formed in-memory inputs (as used by Pair Setup) encryption does not
/// fail.
#[allow(dead_code)] // Consumed by the Pair Setup M5 step (Chunk C).
pub(crate) fn encrypt(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    cipher
        .encrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| CryptoError::Aead)
}

/// Decrypt `ciphertext_and_tag` (ciphertext with the 16-byte Poly1305 tag
/// appended) with ChaCha20-Poly1305 under `key`/`nonce`, verifying `aad`,
/// returning the recovered plaintext.
///
/// # Errors
///
/// Returns [`CryptoError::Aead`] if authentication fails — a wrong key, a
/// tampered ciphertext or tag, mismatched `aad`, or input shorter than the
/// 16-byte tag.
#[allow(dead_code)] // Consumed by the Pair Setup M6 step (Chunk C).
pub(crate) fn decrypt(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    ciphertext_and_tag: &[u8],
) -> Result<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    cipher
        .decrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: ciphertext_and_tag,
                aad,
            },
        )
        .map_err(|_| CryptoError::Aead)
}

#[cfg(test)]
// Test code only: CLAUDE.md carves out `unwrap`/`expect` for tests with a
// documented justification. A failed `unwrap` here is itself a test failure.
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn h(s: &str) -> Vec<u8> {
        hex::decode(s).unwrap()
    }

    // RFC 8439 §2.8.2 "Example and Test Vector for AEAD_CHACHA20_POLY1305".
    // The plaintext is the ASCII sentence given in the RFC; key, nonce, AAD,
    // ciphertext and tag are the published hex octet sequences.
    const RFC8439_PLAINTEXT: &[u8] =
        b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
    const RFC8439_KEY: &str = "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f";
    const RFC8439_NONCE: &str = "070000004041424344454647";
    const RFC8439_AAD: &str = "50515253c0c1c2c3c4c5c6c7";
    const RFC8439_CIPHERTEXT: &str = "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116";
    const RFC8439_TAG: &str = "1ae10b594f09e26a7e902ecbd0600691";

    fn key() -> [u8; 32] {
        h(RFC8439_KEY).try_into().unwrap()
    }
    fn nonce() -> [u8; 12] {
        h(RFC8439_NONCE).try_into().unwrap()
    }

    #[test]
    fn encrypt_matches_rfc8439_vector() {
        let aad = h(RFC8439_AAD);
        let mut expected = h(RFC8439_CIPHERTEXT);
        expected.extend_from_slice(&h(RFC8439_TAG));

        let out = encrypt(&key(), &nonce(), &aad, RFC8439_PLAINTEXT).unwrap();
        assert_eq!(out, expected);
    }

    #[test]
    fn decrypt_matches_rfc8439_vector() {
        let aad = h(RFC8439_AAD);
        let mut ct = h(RFC8439_CIPHERTEXT);
        ct.extend_from_slice(&h(RFC8439_TAG));

        let plain = decrypt(&key(), &nonce(), &aad, &ct).unwrap();
        assert_eq!(plain, RFC8439_PLAINTEXT);
    }

    #[test]
    fn round_trip() {
        let k = [0x42u8; 32];
        let n = hap_nonce(b"PS-Msg05");
        let aad = b"aad bytes";
        let msg = b"the M5 sub-TLV plaintext";
        let sealed = encrypt(&k, &n, aad, msg).unwrap();
        let opened = decrypt(&k, &n, aad, &sealed).unwrap();
        assert_eq!(opened, msg);
    }

    #[test]
    fn decrypt_rejects_tampered_tag() {
        let aad = h(RFC8439_AAD);
        let mut ct = h(RFC8439_CIPHERTEXT);
        ct.extend_from_slice(&h(RFC8439_TAG));
        // Flip the last bit of the tag.
        let last = ct.len() - 1;
        ct[last] ^= 0x01;
        assert!(matches!(
            decrypt(&key(), &nonce(), &aad, &ct),
            Err(CryptoError::Aead)
        ));
    }

    #[test]
    fn decrypt_rejects_tampered_ciphertext() {
        let aad = h(RFC8439_AAD);
        let mut ct = h(RFC8439_CIPHERTEXT);
        ct.extend_from_slice(&h(RFC8439_TAG));
        // Flip the first ciphertext byte.
        ct[0] ^= 0x01;
        assert!(matches!(
            decrypt(&key(), &nonce(), &aad, &ct),
            Err(CryptoError::Aead)
        ));
    }

    #[test]
    fn decrypt_rejects_wrong_aad() {
        let mut ct = h(RFC8439_CIPHERTEXT);
        ct.extend_from_slice(&h(RFC8439_TAG));
        assert!(matches!(
            decrypt(&key(), &nonce(), b"wrong aad", &ct),
            Err(CryptoError::Aead)
        ));
    }

    #[test]
    fn hap_nonce_layout() {
        // 8-byte label fills the counter region's low bytes; first 4 are zero.
        assert_eq!(
            hap_nonce(b"PS-Msg05"),
            [0, 0, 0, 0, b'P', b'S', b'-', b'M', b's', b'g', b'0', b'5']
        );
        // Short label is left-zero-padded within the 8-byte region.
        assert_eq!(
            hap_nonce(b"abc"),
            [0, 0, 0, 0, b'a', b'b', b'c', 0, 0, 0, 0, 0]
        );
        // Empty label yields an all-zero nonce.
        assert_eq!(hap_nonce(b""), [0u8; 12]);
    }
}
