//! HomeKit Accessory Protocol pairing **orchestration**.
//!
//! This is Milestone 5 (M5) of the `hap-rust` roadmap — the headline
//! "first pure-Rust HomeKit controller pairs a real accessory" milestone. It is
//! currently an empty skeleton: the public API lands in the M5 implementation
//! plan.
//!
//! # Scope (M5)
//!
//! - Drives the Pair Setup (M1–M6) and Pair Verify (M1–M4) state machines using
//!   [`hap_tlv8`], [`hap_crypto`], and [`hap_transport`].
//! - Pairing management — `add`, `remove`, `list` pairings via the `/pairings`
//!   endpoint.
//! - A persistence trait so a controller can store and restore its long-term
//!   keys and the set of known accessories.
//!
//! From M5 onward we test against real accessories and record each one in
//! `docs/tested-devices.md`.
//!
//! Depends on [`hap_tlv8`], [`hap_crypto`], and [`hap_transport`].

#![forbid(unsafe_code)]
