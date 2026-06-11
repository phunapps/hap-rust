//! TLV8 decoder.
//!
//! [`Tlv8Reader::parse`] walks a byte slice and returns the items it contains,
//! reassembling fragmented values: consecutive items of the same type are
//! concatenated while the run stays open (each fragment exactly 255 bytes means
//! more follows). The [`crate::SEPARATOR`] (`0xFF`) item is always kept as its
//! own distinct entry and never reassembled.

use crate::error::{Result, Tlv8Error};

/// Stateless TLV8 decoder entry point.
pub struct Tlv8Reader;

impl Tlv8Reader {
    /// Parse a TLV8 byte stream into reassembled `(type, value)` items.
    ///
    /// Consecutive items of the same type are concatenated into one logical
    /// value while the run stays open (each fragment exactly 255 bytes means
    /// more follows); a sub-255 fragment closes the run. The
    /// [`crate::SEPARATOR`] (`0xFF`) item is kept as its own `(0xFF, vec![])`
    /// entry and never reassembled.
    ///
    /// # Errors
    ///
    /// Returns [`Tlv8Error::UnexpectedEof`] if an item declares a length that
    /// runs past the end of the input.
    pub fn parse(bytes: &[u8]) -> Result<Vec<(u8, Vec<u8>)>> {
        let mut items: Vec<(u8, Vec<u8>)> = Vec::new();
        // The run currently being accumulated, and whether it is still "open"
        // (i.e. its last fragment was exactly 255 bytes, so more may follow).
        let mut open_run: Option<(u8, bool)> = None;
        let mut pos = 0;
        while pos < bytes.len() {
            let ty = bytes[pos];
            let len = *bytes.get(pos + 1).ok_or(Tlv8Error::UnexpectedEof)? as usize;
            let start = pos + 2;
            let end = start.checked_add(len).ok_or(Tlv8Error::UnexpectedEof)?;
            let value = bytes.get(start..end).ok_or(Tlv8Error::UnexpectedEof)?;
            pos = end;

            // The separator is never reassembled; it ends any open run and is
            // pushed as its own item.
            if ty == crate::SEPARATOR {
                open_run = None;
                items.push((ty, value.to_vec()));
                continue;
            }

            let continues = matches!(open_run, Some((run_ty, true)) if run_ty == ty);
            if continues {
                // Append to the last item's value.
                if let Some(last) = items.last_mut() {
                    last.1.extend_from_slice(value);
                }
            } else {
                items.push((ty, value.to_vec()));
            }
            // The run stays open only while fragments are full-width (255).
            open_run = Some((ty, len == 255));
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

    #[test]
    fn parse_reassembles_256_byte_value() {
        // Build the writer-side framing for a 256-byte value of type 0x09.
        let mut stream = vec![0x09, 0xFF];
        stream.extend((0u8..=254).collect::<Vec<u8>>()); // 255 bytes
        stream.extend([0x09, 0x01, 0xFF]); // continuation: 1 byte (0xFF)
        let items = Tlv8Reader::parse(&stream).unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].0, 0x09);
        assert_eq!(items[0].1.len(), 256);
        assert_eq!(items[0].1, (0..=u8::MAX).collect::<Vec<u8>>());
    }

    #[test]
    fn parse_reassembles_exact_255_with_terminator() {
        let mut stream = vec![0x09, 0xFF];
        stream.extend(vec![0x42_u8; 255]);
        stream.extend([0x09, 0x00]); // terminating zero-length item
        let items = Tlv8Reader::parse(&stream).unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].0, 0x09);
        assert_eq!(items[0].1, vec![0x42; 255]);
    }

    #[test]
    fn parse_reassembles_510_byte_value() {
        let mut stream = vec![0x09, 0xFF];
        stream.extend(vec![0xAB_u8; 255]);
        stream.extend([0x09, 0xFF]);
        stream.extend(vec![0xAB_u8; 255]);
        stream.extend([0x09, 0x00]); // terminator
        let items = Tlv8Reader::parse(&stream).unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].1, vec![0xAB; 510]);
    }

    #[test]
    fn parse_does_not_merge_two_short_items_of_same_type() {
        // A 1-byte item is < 255, so the run ends. A following same-type item
        // is a distinct logical value, not a continuation.
        let items = Tlv8Reader::parse(&[0x09, 0x01, 0xAA, 0x09, 0x01, 0xBB]).unwrap();
        assert_eq!(items, vec![(0x09, vec![0xAA]), (0x09, vec![0xBB])]);
    }

    #[test]
    fn parse_keeps_separator_as_distinct_item() {
        // value(type 1) sep value(type 1) — two pairings delimited by 0xFF.
        let stream = [0x01, 0x01, 0xAA, 0xFF, 0x00, 0x01, 0x01, 0xBB];
        let items = Tlv8Reader::parse(&stream).unwrap();
        assert_eq!(
            items,
            vec![(0x01, vec![0xAA]), (0xFF, vec![]), (0x01, vec![0xBB])]
        );
    }
}
