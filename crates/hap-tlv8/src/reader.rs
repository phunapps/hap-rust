//! TLV8 decoder.
//!
//! [`Tlv8Reader::parse`] walks a byte slice and returns the items it contains.
//! In phase 2 it reassembles fragmented values (consecutive items of the same
//! type are concatenated); in phase 1 it returns one entry per item, which is
//! equivalent for streams where each type appears once and no value exceeds
//! 255 bytes.

use crate::error::{Result, Tlv8Error};

/// Stateless TLV8 decoder entry point.
pub struct Tlv8Reader;

impl Tlv8Reader {
    /// Parse a TLV8 byte stream into `(type, value)` items.
    ///
    /// In phase 1 each TLV8 item becomes one returned entry. Phase 2 adds
    /// fragment reassembly so consecutive same-type items are concatenated.
    ///
    /// # Errors
    ///
    /// Returns [`Tlv8Error::UnexpectedEof`] if an item declares a length that
    /// runs past the end of the input.
    pub fn parse(bytes: &[u8]) -> Result<Vec<(u8, Vec<u8>)>> {
        let mut items = Vec::new();
        let mut pos = 0;
        while pos < bytes.len() {
            let ty = bytes[pos];
            let len = *bytes.get(pos + 1).ok_or(Tlv8Error::UnexpectedEof)? as usize;
            let start = pos + 2;
            let end = start.checked_add(len).ok_or(Tlv8Error::UnexpectedEof)?;
            let value = bytes.get(start..end).ok_or(Tlv8Error::UnexpectedEof)?;
            items.push((ty, value.to_vec()));
            pos = end;
        }
        Ok(items)
    }
}

#[cfg(test)]
// CLAUDE.md test-code carve-out: unwrap/expect allowed with documented reason.
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn parse_empty_input_yields_no_items() {
        assert_eq!(Tlv8Reader::parse(&[]).unwrap(), vec![]);
    }

    #[test]
    fn parse_single_short_item() {
        let items = Tlv8Reader::parse(&[0x01, 0x02, 0xAB, 0xCD]).unwrap();
        assert_eq!(items, vec![(0x01, vec![0xAB, 0xCD])]);
    }

    #[test]
    fn parse_zero_length_item() {
        let items = Tlv8Reader::parse(&[0x06, 0x00]).unwrap();
        assert_eq!(items, vec![(0x06, vec![])]);
    }

    #[test]
    fn parse_two_distinct_types() {
        let items = Tlv8Reader::parse(&[0x01, 0x01, 0xAA, 0x02, 0x01, 0xBB]).unwrap();
        assert_eq!(items, vec![(0x01, vec![0xAA]), (0x02, vec![0xBB])]);
    }

    #[test]
    fn parse_truncated_value_errors() {
        // declares length 2 but only one value byte present
        let err = Tlv8Reader::parse(&[0x01, 0x02, 0xAA]).unwrap_err();
        assert_eq!(err, Tlv8Error::UnexpectedEof);
    }

    #[test]
    fn parse_missing_length_byte_errors() {
        let err = Tlv8Reader::parse(&[0x01]).unwrap_err();
        assert_eq!(err, Tlv8Error::UnexpectedEof);
    }
}
