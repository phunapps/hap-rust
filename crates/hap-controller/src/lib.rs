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
//! ## QR / setup-payload pairing
//!
//! A HomeKit setup QR encodes an `X-HM://` URI: a setup code, category, flags,
//! and (usually) a 4-character setup id — but never an address or a BLE
//! identifier. **Discovery is always required; there is no QR-only path.**
//! [`SetupPayload::parse`] decodes the URI, and matching against what
//! discovery finds is precise (a setup-hash identity check) when the payload
//! has a setup id and the accessory advertises a hash, and falls back to a
//! category-plausible match otherwise.
//!
//! The one-call flow:
//!
//! ```no_run
//! use std::time::Duration;
//! use hap_controller::{HapController, JsonFileStore, SetupPayload};
//!
//! # async fn run() -> hap_controller::Result<()> {
//! let payload = SetupPayload::parse("X-HM://0032T2N7OSX")?;
//! let store = JsonFileStore::new("./homekit-pairings.json");
//! let mut controller = HapController::new(store).await?;
//! let mut handle = controller
//!     .pair_with_payload(&payload, Duration::from_secs(30))
//!     .await?;
//! # let _ = handle.accessories().await?;
//! # Ok(())
//! # }
//! ```
//!
//! [`pair_with_payload`](HapController::pair_with_payload) re-scans on a
//! retry window until exactly one accessory matches, then pairs it with the
//! payload's setup code. If discovery keeps finding several
//! category-plausible candidates and no hash can disambiguate them, it
//! returns [`HapError::AmbiguousMatch`]; if the window elapses with no match
//! at all, [`HapError::NoMatchingAccessory`]. It never tries the setup code
//! against more than one accessory.
//!
//! To drive discovery and matching yourself — for example, to show the user
//! candidates before pairing — run your own loop with `discover`,
//! [`SetupPayload::match_kind`], and [`pair`](HapController::pair):
//!
//! ```no_run
//! use std::time::Duration;
//! use hap_controller::{HapController, JsonFileStore, SetupPayload};
//!
//! # async fn run() -> hap_controller::Result<()> {
//! let payload = SetupPayload::parse("X-HM://0032T2N7OSX")?;
//! let store = JsonFileStore::new("./homekit-pairings.json");
//! let mut controller = HapController::new(store).await?;
//!
//! let found = controller.discover(Duration::from_secs(8)).await?;
//! if let Some(target) = found.iter().find(|d| payload.match_kind(d).is_some()) {
//!     let mut handle = controller.pair(target, &payload.setup_code).await?;
//!     # let _ = handle.accessories().await?;
//! }
//! # Ok(())
//! # }
//! ```
//!
//! `match_kind` (and `pair_with_payload`'s matching) is symmetric across
//! transports — the same precise-vs-category logic applies whether the
//! discovered accessory is IP or, with the `ble` feature enabled, `Discovered::Ble`.
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
//!
//! ## Sleepy BLE sensors
//!
//! A "sleepy" accessory drops its BLE link between events and communicates
//! change through advertisements instead — there are two ways to arm a
//! watch, depending on whether you already have a connected handle:
//!
//! - **Already connected:** after [`pair`](HapController::pair) or
//!   [`connect`](HapController::connect), call
//!   `handle.watch_sleepy_events(poll_iids)` to arm live events on that
//!   connected handle, self-sourcing the advert source and device id from
//!   the connection.
//! - **Cold, after a reboot:** with only a stored pairing (no live
//!   connection), call `controller.watch_sleepy(id, poll_iids)`. It returns
//!   immediately — there is no blocking connect on the calling task. A
//!   background task waits for the device's next advertisement, connects
//!   once, enables broadcasts, disconnects so the device keeps advertising,
//!   and arms the watch; events then stream on the returned watch's
//!   `events()`. Each event auto-persists the latest GSN/broadcast state, so
//!   a later reboot does not re-emit already-seen events. Call
//!   `SleepyWatch::save_state` to force-flush that state early (for example,
//!   before an orderly shutdown); it is a no-op before the background task
//!   has connected.
//!
//! Both paths are feature-gated behind `ble`.

#![forbid(unsafe_code)]

mod controller;
mod discover_until;
mod discovered;
mod error;
mod event;
mod handle;
mod payload_match;
mod reconnect;
mod setup_payload;
#[cfg(feature = "ble")]
mod sleepy;
mod unified;

pub use controller::HapController;
pub use discovered::Discovered;
pub use error::{HapError, Result};
pub use event::CharacteristicEvent;
pub use payload_match::PayloadMatch;
pub use reconnect::ConnectionState;
pub use setup_payload::{SetupFlags, SetupPayload};
#[cfg(feature = "ble")]
pub use sleepy::SleepyWatch;
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
