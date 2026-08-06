//! Error type for `hap-thread`.

use thiserror::Error;

/// All failure modes of the HAP Thread (CoAP) transport.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ThreadError {
    /// An underlying socket / IO operation failed.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    /// A CoAP message could not be built, sent, or parsed (transport-level).
    #[error("coap error: {0}")]
    Coap(String),

    /// The accessory returned a non-success CoAP response code (e.g. not the
    /// expected `2.04 Changed`). The raw code string is included.
    #[error("unexpected coap response code: {0}")]
    CoapCode(String),

    /// mDNS browsing failed to start or run.
    #[error("mdns error: {0}")]
    Mdns(String),

    /// A discovered service was missing a TXT key required to build a
    /// [`crate::DiscoveredThreadAccessory`] (the offending key name is included).
    #[error("discovery: missing or invalid TXT key `{0}`")]
    DiscoveryTxt(String),

    /// A HAP PDU could not be decoded (too short, truncated body, bad control).
    #[error("malformed HAP PDU: {0}")]
    MalformedPdu(&'static str),

    /// The accessory reported a non-zero HAP PDU status for a request.
    #[error("accessory returned HAP status {0}")]
    PduStatus(u8),

    /// The secure session is gone (the accessory returned `4.04 Not Found` or
    /// authentication failed); the caller must re-run Pair Verify.
    #[error("secure session expired — re-verify required")]
    SessionExpired,

    /// A cryptographic operation (pairing, key derivation, AEAD) failed.
    #[error("crypto error: {0}")]
    Crypto(#[from] hap_crypto::CryptoError),

    /// A TLV8 body could not be parsed.
    #[error("tlv8 error: {0}")]
    Tlv8(#[from] hap_tlv8::Tlv8Error),

    /// An accessory-model value could not be parsed (UUID, format, …).
    #[error("model error: {0}")]
    Model(String),

    /// A pairing-store operation failed while persisting or loading a pairing.
    #[error("pairing store error: {0}")]
    Store(String),
}

/// A `Result` specialized to [`ThreadError`].
pub type Result<T> = std::result::Result<T, ThreadError>;
