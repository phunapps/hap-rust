//! HomeKit Accessory Protocol — pairing orchestration.
//!
//! This is Milestone 5 of the `hap-rust` roadmap, and the first milestone that
//! pairs a real accessory end to end. It wires the byte-verified crypto state
//! machines from [`hap_crypto`] to the real network transport in
//! [`hap_transport`]:
//!
//! - [`pair`] drives **Pair Setup** (SRP-6a, steps M1–M6) over a
//!   [`HapConnection`](hap_transport::HapConnection), returning the resulting
//!   [`AccessoryPairing`](hap_crypto::AccessoryPairing) and a live
//!   [`SecureSession`](hap_transport::SecureSession).
//! - [`connect`] drives **Pair Verify** (X25519 + Ed25519, steps M1–M4) from a
//!   stored pairing, returning a fresh [`SecureSession`].
//! - [`PairingsAdmin`] manages pairings (`add` / `remove` / `list`) over the
//!   `/pairings` endpoint of an established session.
//! - [`PairingStore`] (and the bundled [`JsonFileStore`]) persists the
//!   controller's long-term identity and its known accessories across restart.
//!
//! # Example
//!
//! ```no_run
//! # async fn run() -> Result<(), hap_pairing::PairingError> {
//! use hap_pairing::{pair, JsonFileStore, PairingStore, StoredAccessory};
//! use hap_transport::HapConnection;
//!
//! let store = JsonFileStore::new("controller.json");
//! let controller = match store.load_controller().await? {
//!     Some(c) => c,
//!     None => {
//!         let c = hap_crypto::ControllerKeypair::generate("my-controller".to_string());
//!         store.save_controller(&c).await?;
//!         c
//!     }
//! };
//!
//! let addr = "192.0.2.10:51826".parse().expect("valid addr");
//! let conn = HapConnection::connect(addr).await?;
//! let (pairing, _session) = pair(conn, "123-45-678", &controller).await?;
//! store.save_pairing(&StoredAccessory { pairing, addr }).await?;
//! # Ok(()) }
//! ```

#![forbid(unsafe_code)]

mod error;
mod pairings;
mod setup;
mod store;
mod verify;
mod wire;

pub use error::{PairingError, Result};
pub use pairings::{PairingInfo, PairingsAdmin};
pub use setup::pair;
pub use store::{JsonFileStore, PairingStore, StoredAccessory};
pub use verify::connect;
