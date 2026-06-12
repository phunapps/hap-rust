//! HomeKit Accessory Protocol **IP transport**.
//!
//! This is Milestone 4 (M4) of the `hap-rust` roadmap. It is currently an empty
//! skeleton: the public API lands in the M4 implementation plan.
//!
//! # Scope (M4)
//!
//! - **mDNS discovery** of `_hap._tcp` services, parsing the HAP TXT record
//!   (`id`, `c#` config number, `s#` state, `sf`/`ff` flags, `md` model,
//!   `ci` category). Wraps `mdns-sd`.
//! - **HAP HTTP/1.1 layer** with HAP's content types
//!   (`application/pairing+tlv8`, `application/hap+json`) and the asynchronous
//!   `EVENT/1.0` message the accessory pushes over the same connection.
//! - **Secure record layer.** After Pair Verify, every HTTP message is framed
//!   as one or more records: a 2-byte little-endian length used as AAD, the
//!   payload encrypted with ChaCha20-Poly1305 under the directional session key
//!   with a 64-bit counter nonce, and a 16-byte auth tag.
//!
//! Depends on [`hap_crypto`] (the record layer uses session keys) and
//! [`hap_tlv8`].

#![forbid(unsafe_code)]

mod connection;
mod discovery;
mod error;
mod http;
mod record;
mod session;

pub use error::{Result, TransportError};

pub use discovery::{discover, DiscoveredAccessory};
#[doc(hidden)]
pub use discovery::discovery_test_support;

pub use http::HapResponse;
#[doc(hidden)]
pub use http::http_test_support;

pub use connection::HapConnection;

pub use hap_crypto::SessionKeys;

pub use session::{EventNotification, SecureSession};
#[doc(hidden)]
pub use session::session_test_support;

#[doc(hidden)]
pub use record::record_test_support;
