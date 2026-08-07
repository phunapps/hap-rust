//! Error type for the HAP-over-Thread reference accessory.

use thiserror::Error;

/// Failure modes of the reference accessory.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum DutError {
    /// A socket / IO operation failed.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    /// A cryptographic operation failed.
    #[error("crypto error: {0}")]
    Crypto(#[from] hap_crypto::CryptoError),

    /// A TLV8 body could not be parsed.
    #[error("tlv8 error: {0}")]
    Tlv8(#[from] hap_tlv8::Tlv8Error),

    /// A protocol invariant was violated by an incoming request.
    #[error("protocol error: {0}")]
    Protocol(&'static str),
}

/// A `Result` specialized to [`DutError`].
pub type Result<T> = std::result::Result<T, DutError>;
