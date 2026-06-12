//! High-level HomeKit Accessory Protocol (HAP) **controller** API.
//!
//! This is Milestone 7 — the v1.0 entry point for `hap-rust`. It composes the
//! lower crates ([`hap_tlv8`], [`hap_crypto`], [`hap_transport`],
//! [`hap_pairing`], [`hap_model`]) behind two types:
//!
//! - [`HapController`] — discover, pair, connect, and manage pairings.
//! - [`AccessoryHandle`] — read, write, and subscribe to one accessory's
//!   characteristics, with an async [`Stream`](tokio_stream::Stream) of events.
//!
//! # Quickstart
//!
//! ```no_run
//! use std::time::Duration;
//! use hap_controller::{HapController, JsonFileStore};
//!
//! # async fn run() -> hap_controller::Result<()> {
//! let store = JsonFileStore::new("./homekit-pairings.json");
//! let mut controller = HapController::new(store).await?;
//!
//! let found = controller.discover(Duration::from_secs(5)).await?;
//! let plug = &found[0];
//! let mut handle = controller.pair(plug, "123-45-678").await?;
//!
//! // Toggle the first On characteristic we can find.
//! // (See `examples/pair_and_toggle.rs` for the full version.)
//! # Ok(())
//! # }
//! ```
//!
//! The doc-test above uses `?` against the library's [`Result`]; real code
//! propagates it the same way. Library code in this crate never uses
//! `unwrap`/`expect`.

#![forbid(unsafe_code)]

mod controller;
mod error;
mod event;
mod handle;

pub use controller::HapController;
pub use error::{HapError, Result};
pub use event::CharacteristicEvent;
pub use handle::AccessoryHandle;

// The transport seam that makes `read`/`write`/`subscribe`/`events` testable
// against a mock. Not part of the supported public API — hidden from docs and
// only named by this crate's own integration tests.
#[doc(hidden)]
pub use handle::{Session, SessionResponse};

// Re-export the lower-crate types that appear in this crate's public
// signatures, so consumers depend only on `hap-controller`.
pub use hap_model::{
    Accessory, CharValue, Characteristic, CharacteristicType, Service, ServiceType,
};
pub use hap_pairing::{JsonFileStore, PairingStore, StoredAccessory};
pub use hap_transport::DiscoveredAccessory;
