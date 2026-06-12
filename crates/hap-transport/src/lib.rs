//! HomeKit Accessory Protocol (HAP) **IP transport**, controller side.
//!
//! Milestone 4 (M4) of the `hap-rust` roadmap. This crate is the network
//! boundary a HAP controller uses:
//!
//! - [`discover`] — browse `_hap._tcp.local.` over mDNS and parse each
//!   accessory's TXT record (`id`, `c#`, `s#`, `sf`/`ff`, `md`, `ci`) into a
//!   [`DiscoveredAccessory`]. Wraps `mdns-sd`.
//! - [`HapConnection`] — a Tokio TCP connection that speaks plaintext HAP
//!   HTTP/1.1 (with HAP's `application/pairing+tlv8` / `application/hap+json`
//!   content types) for the pre-session pairing endpoints (`/pair-setup`,
//!   `/pair-verify`).
//! - [`SecureSession`] — the same connection after Pair Verify, with every HTTP
//!   message wrapped in the ChaCha20-Poly1305 record layer (a 2-byte
//!   little-endian length used as AAD, the payload encrypted under the
//!   directional session key with a 4-zero + 64-bit little-endian counter
//!   nonce, then a 16-byte tag) and asynchronous [`EventNotification`] pushes
//!   demultiplexed onto an mpsc channel.
//!
//! The pairing and session-key cryptography lives in [`hap_crypto`] (M3); this
//! crate only frames and transports bytes. Higher layers (`hap-pairing` M5,
//! `hap-controller` M7) drive this API.
//!
//! # Example (shape only)
//!
//! ```no_run
//! # use std::time::Duration;
//! # async fn run() -> hap_transport::Result<()> {
//! let found = hap_transport::discover(Duration::from_secs(3)).await?;
//! let acc = found.into_iter().find(|a| !a.paired).expect("an unpaired accessory");
//! let mut conn = hap_transport::HapConnection::connect(acc.addr).await?;
//! // ... drive Pair Setup / Pair Verify via `conn.request(...)` (hap-pairing) ...
//! # Ok(()) }
//! ```
//!
//! The example uses `expect`; real controller code propagates the `Result`.

#![forbid(unsafe_code)]

mod connection;
mod discovery;
mod error;
mod http;
mod record;
mod session;

pub use error::{Result, TransportError};

#[doc(hidden)]
pub use discovery::discovery_test_support;
pub use discovery::{discover, DiscoveredAccessory};

#[doc(hidden)]
pub use http::http_test_support;
pub use http::HapResponse;

pub use connection::HapConnection;

pub use hap_crypto::SessionKeys;

#[doc(hidden)]
pub use session::session_test_support;
pub use session::{EventNotification, SecureSession};

#[doc(hidden)]
pub use record::record_test_support;
