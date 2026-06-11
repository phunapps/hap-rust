//! High-level HomeKit (HAP) **controller** API — the `hap-rust` v1.0 surface.
//!
//! This is Milestone 7 (M7) of the `hap-rust` roadmap. It is currently an empty
//! skeleton: the public API lands in the M7 implementation plan.
//!
//! # Scope (M7)
//!
//! - `HapController` — discover, pair (QR / setup code), connect, disconnect.
//! - Read / write characteristics by accessory + characteristic id.
//! - Subscribe to characteristic changes, surfaced as async streams of events.
//! - Pairing persistence — create, persist, restore the controller identity and
//!   its accessories.
//! - Comprehensive examples and an `aiohomekit` → `hap-rust` migration guide.
//!
//! Composes [`hap_tlv8`], [`hap_crypto`], [`hap_transport`], [`hap_pairing`],
//! and [`hap_model`] behind one ergonomic, documented API.

#![forbid(unsafe_code)]
