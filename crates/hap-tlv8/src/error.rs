//! Error type for `hap-tlv8`.
//!
//! [`Tlv8Error`] covers every failure mode of [`crate::Tlv8Reader`] and the
//! typed getters on [`crate::Tlv8Map`]. The writer never fails: it appends to
//! a `Vec<u8>` and fragments automatically, so it has no error path.

use thiserror::Error;

/// All errors `hap-tlv8` can produce.
#[derive(Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum Tlv8Error {
    /// The reader reached the end of the input before a declared value's
    /// bytes were available (a truncated item).
    #[error("unexpected end of input: declared length exceeds remaining bytes")]
    UnexpectedEof,

    /// A typed getter was asked for an integer width that does not match the
    /// number of bytes stored for that type (for example `get_u16` on a
    /// 3-byte value).
    #[error("integer value has {actual} bytes, too large for the requested {requested}-byte width")]
    IntegerTooLarge {
        /// The width in bytes the caller requested (1, 2, 4, or 8).
        requested: usize,
        /// The number of value bytes actually stored for the type.
        actual: usize,
    },
}

/// `Result<T, Tlv8Error>` for convenience.
pub type Result<T> = core::result::Result<T, Tlv8Error>;
