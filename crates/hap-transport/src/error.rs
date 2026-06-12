//! Error type for `hap-transport`.

use thiserror::Error;

/// All failure modes of the HAP IP transport.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum TransportError {
    /// An underlying socket / IO operation failed.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    /// mDNS browsing failed to start or run.
    #[error("mdns error: {0}")]
    Mdns(String),

    /// A discovered service was missing a TXT key required to build a
    /// [`crate::DiscoveredAccessory`] (the offending key name is included).
    #[error("discovery: missing or invalid TXT key `{0}`")]
    DiscoveryTxt(String),

    /// The peer's HTTP/1.1 (or EVENT/1.0) message could not be parsed.
    #[error("malformed HAP HTTP message: {0}")]
    MalformedHttp(String),

    /// The peer announced a transfer encoding this codec does not support.
    #[error("unsupported transfer encoding: {0}")]
    UnsupportedEncoding(String),

    /// A record-layer frame's length prefix was outside the legal range
    /// (a single block is at most 1024 bytes of plaintext).
    #[error("invalid record frame length: {0}")]
    InvalidFrameLength(usize),

    /// ChaCha20-Poly1305 authentication failed when opening a record frame —
    /// a tampered, replayed, or wrong-key frame.
    #[error("record decryption failed (bad auth tag)")]
    Decrypt,

    /// The connection was closed by the peer mid-message.
    #[error("connection closed by peer")]
    ConnectionClosed,

    /// The reader task terminated, so no further responses can arrive.
    #[error("secure session reader task ended")]
    SessionClosed,

    /// A response was expected on the secure session but the channel from the
    /// reader task closed first.
    #[error("no response: reader channel closed")]
    NoResponse,
}

/// `Result<T, TransportError>` for convenience.
pub type Result<T> = core::result::Result<T, TransportError>;
