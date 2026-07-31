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
//!
//! # Transports
//!
//! By default, `discover` searches only mDNS (IP via `_hap._tcp`). To include
//! Bluetooth LE results, enable the `ble` cargo feature:
//!
//! ```toml
//! [dependencies]
//! hap-controller = { version = "2.0", features = ["ble"] }
//! ```
//!
//! With the `ble` feature, [`discover`](HapController::discover) returns
//! [`Discovered`] variants for both IP and BLE accessories, and you can
//! [`pair`](HapController::pair) with either. Operations on
//! [`AccessoryHandle`] (read, write, subscribe, and events) work identically
//! across both transports; batch reads/writes loop sequentially on BLE.
//!
//! The following operations return [`HapError::UnsupportedByTransport`] on BLE:
//!
//! | Operation | IP | BLE | Note |
//! |-----------|:--:|:---:|------|
//! | `read` / `write` | ✓ | ✓ | Batch reads/writes loop on BLE |
//! | `subscribe` | ✓ | ✓ | Event polling on BLE via `events()` |
//! | `unsubscribe` | ✓ | ✗ | Not in HAP-BLE spec |
//! | `write_timed` | ✓ | ✗ | Not in HAP-BLE spec |
//! | `write_with_response` | ✓ | ✗ | Not in HAP-BLE spec |
//! | `identify` | ✓ | ✗ | not in this milestone |
//! | `list_pairings` / `add_pairing` | ✓ | ✗ | Not in HAP-BLE spec |
//! | `remove_pairing` | ✓ | ✓ | removes this controller's own pairing |
//!
//! ## BLE Lifecycle
//!
//! For BLE accessories, after pairing you will want to:
//!
//! 1. **Start broadcasts** (for your own observation or to test integrations):
//!    call `enable_broadcasts`.
//! 2. **Watch sleepy events**: call `watch_sleepy_events`
//!    to monitor the device's wake-sleep pattern.
//! 3. **Persist state**: call [`HapController::save_state`] to write BLE broadcast
//!    material (signing key + latest GSN counter) to the pairing store.
//!    Recommended before shutdown so a later `connect` resumes broadcast
//!    dedup at the latest GSN; without it, already-seen events may re-emit.

#![forbid(unsafe_code)]

mod controller;
mod discovered;
mod error;
mod event;
mod handle;
mod reconnect;
mod setup_payload;
mod unified;

pub use controller::HapController;
pub use discovered::Discovered;
pub use error::{HapError, Result};
pub use event::CharacteristicEvent;
pub use reconnect::ConnectionState;
pub use setup_payload::{SetupFlags, SetupPayload};
pub use unified::AccessoryHandle;

// The reconnection seam: a [`Reconnector`] mints fresh sessions on demand.
// Not part of the supported public API — hidden from docs and named only by
// this crate's own reconnect tests.
#[doc(hidden)]
pub use reconnect::{Reconnected, Reconnector};

// The transport seam that makes `read`/`write`/`subscribe`/`events` testable
// against a mock. Not part of the supported public API — hidden from docs and
// only named by this crate's own integration tests.
#[doc(hidden)]
pub use handle::{Session, SessionResponse};

// Re-export the lower-crate types that appear in this crate's public
// signatures, so consumers depend only on `hap-controller`.
pub use hap_model::{
    Accessory, CharValue, Characteristic, CharacteristicType, HapStatus, Service, ServiceType,
};
pub use hap_pairing::{
    JsonFileStore, PairingInfo, PairingStore, StoredAccessory, StoredBroadcast, StoredTransport,
};
pub use hap_transport::DiscoveredAccessory;
