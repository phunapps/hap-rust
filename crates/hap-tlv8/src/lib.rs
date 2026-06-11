//! HomeKit Accessory Protocol (HAP) TLV8 encoding and decoding.
//!
//! This is Milestone 1 of the `hap-rust` roadmap. Every later milestone
//! (`hap-crypto`, `hap-transport`, …) depends on the types defined here:
//! the pairing exchange messages are TLV8.
//!
//! # The format
//!
//! A TLV8 stream is a sequence of items, each `(type: u8, length: u8, value)`.
//! Two rules make it more than a trivial format:
//!
//! - **Fragmentation.** A value longer than 255 bytes is split across
//!   consecutive items of the *same* type; the reader concatenates them.
//!   [`Tlv8Writer::push`] fragments automatically; [`Tlv8Reader::parse`]
//!   reassembles.
//! - **Separators.** A zero-length item of type [`SEPARATOR`] (`0xFF`)
//!   delimits repeated structures.
//!
//! Integers are encoded little-endian at a fixed width per field
//! ([`Tlv8Writer::push_u8`] → 1 byte, [`Tlv8Writer::push_u16`] → 2 bytes, and
//! so on); there is no minimal-width trimming, because HAP integer
//! characteristics declare their width.
//!
//! # Fragmentation
//!
//! A logical value longer than 255 bytes is encoded as consecutive items of
//! the same type. Because a full 255-byte item means "more follows", a value
//! whose length is a non-zero exact multiple of 255 is terminated by a
//! zero-length item of the same type. For example, a 256-byte value of type
//! `0x09` encodes as `[0x09, 0xFF, <255 bytes>, 0x09, 0x01, <1 byte>]`, and a
//! 255-byte value as `[0x09, 0xFF, <255 bytes>, 0x09, 0x00]`. The reader
//! reverses this transparently.
//!
//! # Usage
//!
//! ```
//! use hap_tlv8::{Tlv8Writer, Tlv8Reader};
//!
//! let mut bytes = Vec::new();
//! let mut w = Tlv8Writer::new(&mut bytes);
//! w.push(0x01, &[0xAB, 0xCD]);
//! assert_eq!(bytes, [0x01, 0x02, 0xAB, 0xCD]);
//!
//! let items = Tlv8Reader::parse(&bytes).unwrap();
//! assert_eq!(items, vec![(0x01, vec![0xAB, 0xCD])]);
//! ```
//!
//! The doc-test uses `unwrap()`; real library code must propagate the
//! [`Result`] instead.

#![forbid(unsafe_code)]

mod error;
mod map;
mod reader;
mod writer;

pub use error::{Result, Tlv8Error};
pub use map::Tlv8Map;
pub use reader::Tlv8Reader;
pub use writer::Tlv8Writer;

/// TLV8 separator type (`kTLVType_Separator`). A zero-length item of this
/// type delimits repeated structures, such as a list of pairings.
pub const SEPARATOR: u8 = 0xFF;
