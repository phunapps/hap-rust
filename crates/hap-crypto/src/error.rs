//! Error type for `hap-crypto`.
//!
//! [`CryptoError`] is the canonical error returned across the whole Pair Setup
//! (M2) and Pair Verify (M3) surface. It is `#[non_exhaustive]`; later chunks
//! add variants for the KDF/AEAD/Ed25519 message flow and the state machine
//! without it being a breaking change.

use thiserror::Error;

/// All failure modes of `hap-crypto`.
///
/// Only the variants needed by the current implementation chunk are present;
/// the enum is `#[non_exhaustive]` so further variants can be added later.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum CryptoError {
    /// An SRP-6a parameter was rejected: a public key was zero mod `N` (an
    /// `A == 0` / `B == 0` abort per RFC 5054), or a field had an invalid
    /// length for the active group.
    #[error("invalid SRP parameter: {0}")]
    SrpBadParameters(&'static str),

    /// An SRP proof failed to verify (the peer's `M2` did not match the value
    /// computed locally), or the scrambling parameter `u` was zero — both are
    /// SRP-6a abort conditions.
    #[error("SRP proof verification failed (aborting the exchange)")]
    SrpProofMismatch,

    /// A value could not be encoded to, or decoded from, its wire byte form
    /// (e.g. a big-endian field that did not fit its fixed length).
    #[error("crypto value encoding error: {0}")]
    Encoding(&'static str),

    /// A response TLV8 body could not be decoded.
    #[error("malformed TLV8 in pairing message: {0}")]
    Tlv(#[from] hap_tlv8::Tlv8Error),

    /// HKDF key derivation failed (the requested output length exceeded the
    /// HKDF-SHA512 maximum of `255 * 64` bytes).
    #[error("HKDF-SHA512 key derivation failed: {0}")]
    Kdf(&'static str),

    /// ChaCha20-Poly1305 authenticated encryption or decryption failed: a tag
    /// mismatch on decrypt (wrong key or tampered ciphertext/AAD), or an
    /// encryption-time usage error.
    #[error("ChaCha20-Poly1305 AEAD operation failed (authentication or usage error)")]
    Aead,

    /// An Ed25519 signature failed to verify, or a public key / signature was
    /// malformed (e.g. not a valid curve point).
    #[error("Ed25519 signature verification failed")]
    Signature,
}

/// `Result<T, CryptoError>` for the crate.
pub type Result<T> = core::result::Result<T, CryptoError>;
