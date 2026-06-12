//! Ed25519 controller long-term identity keypair for Pair Setup.
//!
//! The controller holds a long-term Ed25519 keypair (the controller's "long-term
//! public key", LTPK) that identifies it to accessories across pairings. During
//! Pair Setup M5 the controller signs its pairing material with this key; the
//! accessory stores the LTPK and verifies future sessions against it.
//!
//! The Ed25519 primitive is never reimplemented; it comes from
//! [`ed25519_dalek`].

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use rand_core::OsRng;

use crate::error::{CryptoError, Result};

/// A controller's long-term Ed25519 identity used across pairings.
///
/// `id` is the controller's pairing identifier (`iOSDevicePairingID`) — an
/// arbitrary UTF-8 string the accessory stores alongside the public key.
pub struct ControllerKeypair {
    /// The controller's pairing identifier.
    pub id: String,
    signing: SigningKey,
}

impl ControllerKeypair {
    /// Generate a fresh random Ed25519 keypair bound to `id`, using the
    /// operating system CSPRNG ([`OsRng`]).
    #[must_use]
    pub fn generate(id: String) -> Self {
        let signing = SigningKey::generate(&mut OsRng);
        Self { id, signing }
    }

    /// Reconstruct a keypair deterministically from a stored 32-byte Ed25519
    /// seed bound to `id`.
    ///
    /// Used by the test/replay harness and by persistence layers that store the
    /// raw seed. The same `seed` always yields the same keypair.
    #[must_use]
    pub fn from_seed(id: String, seed: [u8; 32]) -> Self {
        Self {
            id,
            signing: SigningKey::from_bytes(&seed),
        }
    }

    /// The controller's long-term public key (LTPK): the 32-byte Ed25519 public
    /// key.
    #[must_use]
    pub fn ltpk(&self) -> [u8; 32] {
        self.signing.verifying_key().to_bytes()
    }

    /// Sign `msg` with the controller's Ed25519 key, producing a 64-byte
    /// detached signature.
    #[must_use]
    pub fn sign(&self, msg: &[u8]) -> [u8; 64] {
        self.signing.sign(msg).to_bytes()
    }
}

/// Verify an Ed25519 `sig` over `msg` against a 32-byte public key `ltpk`.
///
/// Uses `ed25519-dalek`'s strict verification (rejecting small-order /
/// non-canonical public keys).
///
/// # Errors
///
/// Returns [`CryptoError::Signature`] if `ltpk` is not a valid Ed25519 public
/// key or if the signature does not verify over `msg`.
pub fn verify_ed25519(ltpk: &[u8; 32], msg: &[u8], sig: &[u8; 64]) -> Result<()> {
    let vk = VerifyingKey::from_bytes(ltpk).map_err(|_| CryptoError::Signature)?;
    let signature = Signature::from_bytes(sig);
    vk.verify_strict(msg, &signature)
        .map_err(|_| CryptoError::Signature)
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

    // RFC 8032 §7.1 "Test Vectors for Ed25519", TEST 2 (1-byte message).
    const RFC8032_SEED: &str = "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb";
    const RFC8032_PUBLIC: &str = "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c";
    const RFC8032_MESSAGE: &str = "72";
    const RFC8032_SIGNATURE: &str = "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00";

    fn seed() -> [u8; 32] {
        h(RFC8032_SEED).try_into().unwrap()
    }

    #[test]
    fn from_seed_matches_rfc8032_public_key() {
        let kp = ControllerKeypair::from_seed("controller".to_string(), seed());
        assert_eq!(kp.ltpk().to_vec(), h(RFC8032_PUBLIC));
    }

    #[test]
    fn sign_matches_rfc8032_signature() {
        let kp = ControllerKeypair::from_seed("controller".to_string(), seed());
        let sig = kp.sign(&h(RFC8032_MESSAGE));
        assert_eq!(sig.to_vec(), h(RFC8032_SIGNATURE));
    }

    #[test]
    fn verify_accepts_rfc8032_signature() {
        let ltpk: [u8; 32] = h(RFC8032_PUBLIC).try_into().unwrap();
        let sig: [u8; 64] = h(RFC8032_SIGNATURE).try_into().unwrap();
        assert!(verify_ed25519(&ltpk, &h(RFC8032_MESSAGE), &sig).is_ok());
    }

    #[test]
    fn verify_rejects_flipped_signature_bit() {
        let ltpk: [u8; 32] = h(RFC8032_PUBLIC).try_into().unwrap();
        let mut sig: [u8; 64] = h(RFC8032_SIGNATURE).try_into().unwrap();
        sig[0] ^= 0x01;
        assert!(matches!(
            verify_ed25519(&ltpk, &h(RFC8032_MESSAGE), &sig),
            Err(CryptoError::Signature)
        ));
    }

    #[test]
    fn verify_rejects_tampered_message() {
        let ltpk: [u8; 32] = h(RFC8032_PUBLIC).try_into().unwrap();
        let sig: [u8; 64] = h(RFC8032_SIGNATURE).try_into().unwrap();
        assert!(matches!(
            verify_ed25519(&ltpk, b"different message", &sig),
            Err(CryptoError::Signature)
        ));
    }

    #[test]
    fn generate_then_sign_verify_roundtrips() {
        let kp = ControllerKeypair::generate("aa:bb:cc".to_string());
        assert_eq!(kp.ltpk().len(), 32);
        let msg = b"pair-setup signing material";
        let sig = kp.sign(msg);
        assert!(verify_ed25519(&kp.ltpk(), msg, &sig).is_ok());
    }
}
