//! HomeKit Accessory Protocol pairing **cryptography**.
//!
//! This crate covers Milestones 2 and 3 (M2, M3) of the `hap-rust` roadmap. It
//! is currently an empty skeleton: the public API lands in the M2/M3
//! implementation plans.
//!
//! # Scope
//!
//! - **M2 — Pair Setup (SRP-6a).** The controller proves knowledge of the
//!   accessory's 8-digit setup code without sending it, using SRP-6a (RFC 5054,
//!   3072-bit group, SHA-512), HKDF-SHA512 key derivation, ChaCha20-Poly1305
//!   for the encrypted sub-TLVs, and an Ed25519 long-term keypair (`LTPK`).
//! - **M3 — Pair Verify (X25519 + Ed25519).** Establishes a fresh session from
//!   an existing pairing via X25519 ephemeral ECDH and Ed25519 signatures
//!   verified against the stored `LTPK`, deriving the directional session keys
//!   (`Control-Read` / `Control-Write`).
//!
//! We never implement cryptographic primitives — AEAD, HKDF, SHA-512, Ed25519,
//! and X25519 come from vetted crates; SRP big-integer math from a vetted
//! bigint crate. We implement the *protocols* on top. The primitive provider is
//! selected in the M2 plan and pinned in `[workspace.dependencies]` then.
//!
//! Correctness is established by byte-for-byte cross-verification of every
//! SRP-6a intermediate value and every pairing message against captured
//! `aiohomekit` traces and the HAP spec's SRP test vectors, plus interoperable
//! pairing against real accessories and negative-path tests. See `CLAUDE.md`
//! ("Crypto verification") for why this project does **not** gate crypto
//! publishes on external review.
//!
//! Depends on [`hap_tlv8`] (pairing messages are TLV8).

#![forbid(unsafe_code)]

mod aead;
mod error;
mod kdf;
mod keys;
mod pair_setup;
mod pair_verify;
mod srp;
mod tlv_types;
mod x25519;

pub use error::{CryptoError, Result};
pub use keys::{verify_ed25519, ControllerKeypair};
pub use pair_setup::{AccessoryPairing, PairSetupClient, PairSetupStep};
pub use pair_verify::{PairVerifyClient, PairVerifyStep, SessionKeys};
pub use x25519::{x25519_shared, EphemeralKeypair};
