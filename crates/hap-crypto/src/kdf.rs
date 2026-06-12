//! HKDF-SHA512 key derivation.
//!
//! HomeKit Accessory Protocol (HAP) Pair Setup derives the ChaCha20-Poly1305
//! key for the M5/M6 encrypted sub-TLVs from the SRP-6a shared secret using
//! HKDF (RFC 5869) instantiated with SHA-512 — salt `"Pair-Setup-Encrypt-Salt"`,
//! info `"Pair-Setup-Encrypt-Info"`, 32-byte output. This module provides the
//! generic HKDF-SHA512 primitive only; the HAP-specific salt/info constants are
//! wired in by the Pair Setup message-flow layer.
//!
//! The primitive itself is never reimplemented: extraction and expansion come
//! from the RustCrypto [`hkdf`] crate over [`sha2::Sha512`].

use hkdf::Hkdf;
use sha2::Sha512;

use crate::error::{CryptoError, Result};

/// Derive `out.len()` bytes with HKDF-SHA512 (RFC 5869): extract a pseudo-random
/// key from `ikm` salted with `salt`, then expand it with `info` into `out`.
///
/// An empty `salt` is treated by HKDF as a string of `HashLen` zero bytes, per
/// RFC 5869 §2.2.
///
/// # Errors
///
/// Returns [`CryptoError::Kdf`] if `out.len()` exceeds the HKDF-SHA512 maximum
/// output length of `255 * 64 = 16320` bytes (the only failure mode of HKDF
/// expansion).
pub(crate) fn hkdf_sha512(ikm: &[u8], salt: &[u8], info: &[u8], out: &mut [u8]) -> Result<()> {
    let hk = Hkdf::<Sha512>::new(Some(salt), ikm);
    hk.expand(info, out)
        .map_err(|_| CryptoError::Kdf("requested output length exceeds 255 * HashLen"))
}

#[cfg(test)]
// Test code only: CLAUDE.md carves out `unwrap`/`expect` for tests with a
// documented justification. A failed `unwrap` here is itself a test failure.
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    // Published HKDF-HMAC-SHA512 known-answer vectors. RFC 5869 itself only
    // publishes SHA-256/SHA-1 vectors; these use the identical RFC 5869 Test
    // Case 1 and Test Case 2 inputs computed for SHA-512 by the widely-used
    // brycx test-vector generation suite:
    //   https://github.com/brycx/Test-Vector-Generation
    //   (HKDF/hkdf-hmac-sha2-test-vectors.md), themselves cross-checked against
    //   multiple HKDF implementations.

    fn h(s: &str) -> Vec<u8> {
        hex::decode(s).unwrap()
    }

    #[test]
    fn hkdf_sha512_rfc5869_case1() {
        let ikm = h("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        let salt = h("000102030405060708090a0b0c");
        let info = h("f0f1f2f3f4f5f6f7f8f9");
        let expected = h(
            "832390086cda71fb47625bb5ceb168e4c8e26a1a16ed34d9fc7fe92c1481579338da362cb8d9f925d7cb",
        );

        let mut out = vec![0u8; 42];
        hkdf_sha512(&ikm, &salt, &info, &mut out).unwrap();
        assert_eq!(out, expected);
    }

    #[test]
    fn hkdf_sha512_rfc5869_case2_long() {
        let ikm = h("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f");
        let salt = h("606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf");
        let info = h("b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
        let expected = h("ce6c97192805b346e6161e821ed165673b84f400a2b514b2fe23d84cd189ddf1b695b48cbd1c8388441137b3ce28f16aa64ba33ba466b24df6cfcb021ecff235f6a2056ce3af1de44d572097a8505d9e7a93");

        let mut out = vec![0u8; 82];
        hkdf_sha512(&ikm, &salt, &info, &mut out).unwrap();
        assert_eq!(out, expected);
    }

    #[test]
    fn hkdf_sha512_rejects_overlong_output() {
        // Max HKDF-SHA512 output is 255 * 64 = 16320 bytes.
        let mut out = vec![0u8; 255 * 64 + 1];
        let err = hkdf_sha512(b"ikm", b"salt", b"info", &mut out);
        assert!(matches!(err, Err(CryptoError::Kdf(_))));
    }
}
