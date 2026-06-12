//! X25519 (Curve25519) ephemeral Diffie-Hellman for Pair Verify (M3).
//!
//! HomeKit Pair Verify opens each session with a fresh ephemeral X25519 key
//! exchange: the controller sends an ephemeral public key in M1, the accessory
//! replies with its own in M2, and both sides derive the same 32-byte shared
//! secret. That shared secret is the input keying material for the HKDF-SHA512
//! derivation of the Pair-Verify encryption key and the directional session
//! keys (handled elsewhere in M3).
//!
//! The curve arithmetic is never reimplemented here; it comes from the vetted
//! [`x25519_dalek`] crate. This module only adapts the primitive to the
//! fixed-size byte shapes the protocol code needs and pins it to the published
//! RFC 7748 known-answer vector.
//!
//! X25519 is infallible for the fixed 32-byte inputs used here, so nothing in
//! this module returns a `Result`.

use x25519_dalek::{PublicKey, StaticSecret};

/// An ephemeral X25519 keypair for a single Pair Verify exchange.
///
/// "Ephemeral" here means *per session*: a new keypair is generated with
/// [`EphemeralKeypair::generate`] for each Pair Verify run and discarded once
/// the session keys are derived. [`EphemeralKeypair::from_secret`] reconstructs
/// a keypair from a fixed scalar for deterministic tests and trace replay.
///
/// The underlying secret is held as a [`StaticSecret`] (which zeroizes on drop)
/// rather than exposed as raw bytes; only the public key and the computed shared
/// secret leave this type.
pub struct EphemeralKeypair {
    secret: StaticSecret,
    public: [u8; 32],
}

impl EphemeralKeypair {
    /// Generate a fresh random ephemeral keypair using the operating system
    /// CSPRNG.
    ///
    /// This is the constructor production code uses; every Pair Verify session
    /// gets its own keypair.
    #[must_use]
    pub fn generate() -> Self {
        let secret = StaticSecret::random();
        let public = PublicKey::from(&secret).to_bytes();
        Self { secret, public }
    }

    /// Reconstruct a keypair from a fixed 32-byte secret scalar.
    ///
    /// The scalar is clamped internally by X25519, so any 32-byte value is
    /// accepted and the resulting public key matches the X25519 definition.
    /// This is the deterministic path used to replay captured traces and to
    /// assert the RFC 7748 known-answer vector; production code calls
    /// [`EphemeralKeypair::generate`] instead.
    #[must_use]
    pub fn from_secret(scalar: [u8; 32]) -> Self {
        let secret = StaticSecret::from(scalar);
        let public = PublicKey::from(&secret).to_bytes();
        Self { secret, public }
    }

    /// This keypair's X25519 public key — the 32 bytes sent on the wire.
    #[must_use]
    pub fn public(&self) -> [u8; 32] {
        self.public
    }

    /// Compute the X25519 shared secret against the peer's 32-byte public key.
    ///
    /// Both sides of a Pair Verify exchange derive the same value:
    /// `DH(self_secret, peer_public) == DH(peer_secret, self_public)`.
    #[must_use]
    pub fn diffie_hellman(&self, peer_public: &[u8; 32]) -> [u8; 32] {
        let peer = PublicKey::from(*peer_public);
        self.secret.diffie_hellman(&peer).to_bytes()
    }
}

/// Compute an X25519 shared secret from a raw 32-byte secret scalar and a peer's
/// 32-byte public key.
///
/// A free-function convenience equivalent to
/// `EphemeralKeypair::from_secret(secret).diffie_hellman(peer_public)`, useful
/// where only the shared secret is needed (e.g. trace replay) without holding a
/// keypair.
#[must_use]
pub fn x25519_shared(secret: &[u8; 32], peer_public: &[u8; 32]) -> [u8; 32] {
    let secret = StaticSecret::from(*secret);
    let peer = PublicKey::from(*peer_public);
    secret.diffie_hellman(&peer).to_bytes()
}

#[cfg(test)]
// Test code only: CLAUDE.md carves out `unwrap`/`expect` for tests with a
// documented justification. A failed `unwrap` here is itself a test failure.
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn h(s: &str) -> [u8; 32] {
        hex::decode(s).unwrap().try_into().unwrap()
    }

    // RFC 7748 §6.1 "Curve25519" known-answer vector. The published hex literals
    // for Alice's and Bob's private/public keys and the resulting shared secret
    // K. See <https://www.rfc-editor.org/rfc/rfc7748#section-6.1>.
    const ALICE_PRIV: &str = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a";
    const ALICE_PUB: &str = "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a";
    const BOB_PRIV: &str = "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb";
    const BOB_PUB: &str = "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f";
    const SHARED_K: &str = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742";

    #[test]
    fn alice_public_matches_rfc7748() {
        assert_eq!(
            EphemeralKeypair::from_secret(h(ALICE_PRIV)).public(),
            h(ALICE_PUB)
        );
    }

    #[test]
    fn bob_public_matches_rfc7748() {
        assert_eq!(
            EphemeralKeypair::from_secret(h(BOB_PRIV)).public(),
            h(BOB_PUB)
        );
    }

    #[test]
    fn alice_dh_bob_pub_matches_rfc7748_k() {
        let alice = EphemeralKeypair::from_secret(h(ALICE_PRIV));
        assert_eq!(alice.diffie_hellman(&h(BOB_PUB)), h(SHARED_K));
    }

    #[test]
    fn bob_dh_alice_pub_matches_rfc7748_k() {
        let bob = EphemeralKeypair::from_secret(h(BOB_PRIV));
        assert_eq!(bob.diffie_hellman(&h(ALICE_PUB)), h(SHARED_K));
    }

    #[test]
    fn dh_is_symmetric() {
        let alice = EphemeralKeypair::from_secret(h(ALICE_PRIV));
        let bob = EphemeralKeypair::from_secret(h(BOB_PRIV));
        assert_eq!(
            alice.diffie_hellman(&bob.public()),
            bob.diffie_hellman(&alice.public())
        );
    }

    #[test]
    fn free_function_matches_rfc7748_k() {
        assert_eq!(x25519_shared(&h(ALICE_PRIV), &h(BOB_PUB)), h(SHARED_K));
        assert_eq!(x25519_shared(&h(BOB_PRIV), &h(ALICE_PUB)), h(SHARED_K));
    }

    #[test]
    fn generate_then_exchange_roundtrips() {
        let alice = EphemeralKeypair::generate();
        let bob = EphemeralKeypair::generate();
        assert_eq!(alice.public().len(), 32);
        assert_eq!(
            alice.diffie_hellman(&bob.public()),
            bob.diffie_hellman(&alice.public())
        );
    }
}
