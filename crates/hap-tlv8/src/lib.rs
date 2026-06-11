//! HomeKit Accessory Protocol **TLV8** encoding and decoding.
//!
//! This is Milestone 1 (M1) of the `hap-rust` roadmap. It is currently an
//! empty skeleton: the public API lands in the M1 implementation plan.
//!
//! # Scope (M1)
//!
//! TLV8 is HAP's pairing wire format: a sequence of
//! `(type: u8, length: u8, value: [u8; length])` items. The crate will provide:
//!
//! - a streaming/collecting reader and a writer for these items,
//! - automatic **255-byte fragmentation** (values longer than 255 bytes split
//!   across consecutive items of the same type; the reader concatenates them),
//! - separator handling for repeated structures, and
//! - typed accessors for the common value shapes (integer, bytes, string,
//!   nested TLV8) plus a `Tlv8Error`.
//!
//! Correctness is established against TLV8 vectors captured from `aiohomekit`
//! pairing exchanges (see `test-vectors/tlv8/`), plus `proptest` round-trips
//! and a fuzz target on the reader.
//!
//! This crate has no `hap-*` dependencies.

#![forbid(unsafe_code)]
