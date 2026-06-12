//! The single error type the whole `hap-rust` library surfaces to consumers.
//!
//! [`HapError`] flattens every lower-crate error behind one enum so callers
//! match (or `?`-propagate) one type. Each lower error is reachable via its
//! own variant with a `#[from]` conversion, so `?` works transparently across
//! the crate boundaries.

use thiserror::Error;

/// Every failure mode `hap-controller` (and the crates beneath it) can produce.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum HapError {
    /// A TLV8 encode/decode failure from `hap-tlv8`.
    #[error("TLV8 error: {0}")]
    Tlv8(#[from] hap_tlv8::Tlv8Error),

    /// A pairing/session cryptography failure from `hap-crypto`
    /// (SRP-6a, Pair Verify, AEAD, key derivation).
    #[error("crypto error: {0}")]
    Crypto(#[from] hap_crypto::CryptoError),

    /// A transport failure from `hap-transport`
    /// (mDNS discovery, HAP-HTTP, the record layer, event channel).
    #[error("transport error: {0}")]
    Transport(#[from] hap_transport::TransportError),

    /// A pairing-orchestration or persistence failure from `hap-pairing`
    /// (Pair Setup / Pair Verify state machines, `/pairings`, the store).
    #[error("pairing error: {0}")]
    Pairing(#[from] hap_pairing::PairingError),

    /// An accessory-database failure from `hap-model`
    /// (`/accessories` JSON parse, characteristic read/write, type lookup).
    #[error("model error: {0}")]
    Model(#[from] hap_model::ModelError),

    /// The requested accessory id is not present in the pairing store.
    #[error("no pairing found for accessory id `{0}`")]
    UnknownAccessory(String),

    /// The requested `(aid, iid)` was not found in the cached accessory tree.
    #[error("characteristic (aid={aid}, iid={iid}) not found")]
    CharacteristicNotFound {
        /// Accessory id within the accessory tree.
        aid: u64,
        /// Instance id of the characteristic.
        iid: u64,
    },

    /// A setup code was malformed (not the eight-digit `XXX-XX-XXX` form).
    #[error("invalid setup code (expected 8 digits as XXX-XX-XXX)")]
    InvalidSetupCode,

    /// The accessory answered a request with a non-success HTTP status. The
    /// secure session completed, but the accessory rejected the operation at
    /// the HTTP layer (per-characteristic failures surface as
    /// [`HapError::Model`] instead).
    #[error("accessory returned HTTP status {status}")]
    Http {
        /// The HTTP status code the accessory returned.
        status: u16,
    },

    /// The secure session dropped and could not be re-established within the
    /// foreground reconnect window. The background reconnect loop keeps trying;
    /// retry the operation shortly.
    #[error("connection lost; reconnect in progress")]
    ConnectionLost,

    /// An `X-HM://` setup payload was structurally invalid.
    #[error("invalid setup payload (expected an X-HM:// URI)")]
    InvalidSetupPayload,
}

/// `Result<T, HapError>` — the public result alias for the whole library.
pub type Result<T> = core::result::Result<T, HapError>;
