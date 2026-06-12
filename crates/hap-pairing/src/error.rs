//! Error type for `hap-pairing`.
//!
//! [`PairingError`] wraps the failure modes of the three lower crates plus the
//! protocol-level errors that only arise when orchestrating them (an accessory
//! returning a `kTLVType_Error`, a malformed `/pairings` response, an absent
//! persisted record, and so on).

use thiserror::Error;

/// All errors `hap-pairing` can produce.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum PairingError {
    /// A TLV8 encode/decode failure in a pairing message.
    #[error("tlv8 error: {0}")]
    Tlv8(#[from] hap_tlv8::Tlv8Error),

    /// A crypto state-machine failure (SRP proof mismatch, signature
    /// verification failure, key derivation error, and so on).
    #[error("crypto error: {0}")]
    Crypto(#[from] hap_crypto::CryptoError),

    /// A transport failure (connection, HTTP framing, record layer).
    #[error("transport error: {0}")]
    Transport(#[from] hap_transport::TransportError),

    /// Persistence (read/write/parse of the store) failed.
    #[error("store error: {0}")]
    Store(String),

    /// The accessory replied with a `kTLVType_Error` (type 0x07) during a
    /// pairing exchange. The wrapped value is the HAP error code (e.g.
    /// `0x02` = Authentication, `0x06` = MaxTries, `0x07` = Busy).
    #[error("accessory returned pairing error code 0x{0:02x}")]
    Accessory(u8),

    /// A pairing response was structurally invalid (missing a required TLV
    /// item, an unexpected state value, a wrong-length key, etc.).
    #[error("malformed pairing response: {0}")]
    Malformed(&'static str),

    /// The requested accessory/pairing was not found in the store.
    #[error("no stored pairing for accessory id {0:?}")]
    UnknownAccessory(String),
}

/// `Result<T, PairingError>` for convenience.
pub type Result<T> = core::result::Result<T, PairingError>;
