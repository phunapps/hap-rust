//! HomeKit Accessory Protocol (HAP) **Thread transport**, controller side.
//!
//! HAP-over-Thread is not a distinct application protocol: a Thread accessory
//! speaks the same HAP PDUs as HAP-BLE, carried in **CoAP messages over
//! UDP/IPv6**. This crate is the CoAP application layer a controller uses once
//! an accessory is reachable on a Thread network:
//!
//! - [`discover`] — browse `_hap._udp.local.` and parse each accessory's TXT
//!   record into a [`DiscoveredThreadAccessory`].
//! - PDU codec ([`pdu`]) — encode/decode HAP request/response PDUs (the same
//!   framing HAP-BLE uses), including the batched form CoAP relies on.
//! - CoAP transport ([`coap`]) — POST HAP payloads to the accessory's CoAP
//!   resources (`/0` identify, `/1` pair-setup, `/2` pair-verify, `/` for all
//!   encrypted post-verify traffic) behind a swappable `coap::CoapTransport`
//!   seam with a real UDP implementation and a mock for tests.
//! - Secure session ([`session`]) — the post-Pair-Verify ChaCha20-Poly1305
//!   record layer (three directional keys, empty AAD, whole-payload framing).
//!
//! The pairing and session-key cryptography lives in [`hap_crypto`]; the
//! accessory data model in [`hap_model`]; persistence in `hap_pairing`. This
//! crate reuses all of them and adds only the CoAP-specific transport.
//!
//! # Scope
//! Commissioning an accessory onto a Thread network (Border Router + BLE
//! credential provisioning) is out of scope; this crate assumes the accessory
//! is already reachable and discoverable via `_hap._udp`.
#![forbid(unsafe_code)]

pub mod accessory;
pub mod coap;
pub mod controller;
pub mod database;
pub mod discovery;
pub mod error;
pub mod pairing;
pub mod pdu;
pub mod session;

pub use accessory::ThreadAccessory;
pub use controller::ThreadController;
pub use database::decode_database;
pub use discovery::{discover, DiscoveredThreadAccessory};
pub use error::{Result, ThreadError};
