//! Convenience wrapper over parsed TLV8 items with typed getters.
//!
//! [`Tlv8Map`] owns the reassembled `(type, value)` items produced by
//! [`crate::Tlv8Reader::parse`] and offers ergonomic lookup. [`Tlv8Map::get`]
//! returns the raw value bytes of the *first* item with a matching type; the
//! `get_uN` helpers decode fixed-width little-endian integers.
//!
//! Nested TLV8 values are returned as raw bytes by [`Tlv8Map::get`]; re-parse
//! them with [`Tlv8Map::parse`].

use crate::error::{Result, Tlv8Error};
use crate::reader::Tlv8Reader;

/// An owned, queryable view over reassembled TLV8 items.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tlv8Map {
    items: Vec<(u8, Vec<u8>)>,
}

impl Tlv8Map {
    /// Parse a TLV8 byte stream and wrap the reassembled items.
    ///
    /// # Errors
    ///
    /// Propagates any [`Tlv8Error`] from [`Tlv8Reader::parse`].
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        Ok(Self::from_items(Tlv8Reader::parse(bytes)?))
    }

    /// Wrap an already-parsed item list (no validation).
    pub fn from_items(items: Vec<(u8, Vec<u8>)>) -> Self {
        Self { items }
    }

    /// Borrow the underlying items in stream order.
    pub fn items(&self) -> &[(u8, Vec<u8>)] {
        &self.items
    }

    /// Consume the map and return the underlying items.
    pub fn into_items(self) -> Vec<(u8, Vec<u8>)> {
        self.items
    }

    /// Value bytes of the first item with type `ty`, if present.
    pub fn get(&self, ty: u8) -> Option<&[u8]> {
        self.items
            .iter()
            .find(|(t, _)| *t == ty)
            .map(|(_, v)| v.as_slice())
    }

    fn get_uint(&self, ty: u8, width: usize) -> Result<Option<u64>> {
        let Some(bytes) = self.get(ty) else {
            return Ok(None);
        };
        if bytes.len() > width {
            return Err(Tlv8Error::IntegerTooLarge {
                requested: width,
                actual: bytes.len(),
            });
        }
        let mut buf = [0u8; 8];
        buf[..bytes.len()].copy_from_slice(bytes);
        Ok(Some(u64::from_le_bytes(buf)))
    }

    /// Decode the first item of type `ty` as a `u8`.
    ///
    /// # Errors
    ///
    /// [`Tlv8Error::IntegerTooLarge`] if the stored value has more than 1 byte.
    pub fn get_u8(&self, ty: u8) -> Result<Option<u8>> {
        // value is masked to a single byte by the width=1 length check above.
        #[allow(clippy::cast_possible_truncation)]
        Ok(self.get_uint(ty, 1)?.map(|v| v as u8))
    }

    /// Decode the first item of type `ty` as a little-endian `u16`.
    ///
    /// # Errors
    ///
    /// [`Tlv8Error::IntegerTooLarge`] if the stored value has more than 2 bytes.
    pub fn get_u16(&self, ty: u8) -> Result<Option<u16>> {
        // high bytes are guaranteed zero by the width=2 length check above.
        #[allow(clippy::cast_possible_truncation)]
        Ok(self.get_uint(ty, 2)?.map(|v| v as u16))
    }

    /// Decode the first item of type `ty` as a little-endian `u32`.
    ///
    /// # Errors
    ///
    /// [`Tlv8Error::IntegerTooLarge`] if the stored value has more than 4 bytes.
    pub fn get_u32(&self, ty: u8) -> Result<Option<u32>> {
        // high bytes are guaranteed zero by the width=4 length check above.
        #[allow(clippy::cast_possible_truncation)]
        Ok(self.get_uint(ty, 4)?.map(|v| v as u32))
    }

    /// Decode the first item of type `ty` as a little-endian `u64`.
    ///
    /// # Errors
    ///
    /// [`Tlv8Error::IntegerTooLarge`] if the stored value has more than 8 bytes.
    pub fn get_u64(&self, ty: u8) -> Result<Option<u64>> {
        self.get_uint(ty, 8)
    }
}

#[cfg(test)]
// CLAUDE.md test-code carve-out: unwrap/expect allowed with documented reason.
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::Tlv8Error;

    #[test]
    fn get_returns_first_matching_value() {
        let map = Tlv8Map::parse(&[0x01, 0x02, 0xAB, 0xCD, 0x02, 0x01, 0xEE]).unwrap();
        assert_eq!(map.get(0x01), Some(&[0xAB, 0xCD][..]));
        assert_eq!(map.get(0x02), Some(&[0xEE][..]));
        assert_eq!(map.get(0x09), None);
    }

    #[test]
    fn get_u8_decodes_single_byte() {
        let map = Tlv8Map::parse(&[0x02, 0x01, 0x2A]).unwrap();
        assert_eq!(map.get_u8(0x02).unwrap(), Some(0x2A));
        assert_eq!(map.get_u8(0x09).unwrap(), None);
    }

    #[test]
    fn get_u16_decodes_le() {
        let map = Tlv8Map::parse(&[0x03, 0x02, 0x34, 0x12]).unwrap();
        assert_eq!(map.get_u16(0x03).unwrap(), Some(0x1234));
    }

    #[test]
    fn get_u32_decodes_le() {
        let map = Tlv8Map::parse(&[0x04, 0x04, 0xBE, 0xBA, 0xFE, 0xCA]).unwrap();
        assert_eq!(map.get_u32(0x04).unwrap(), Some(0xCAFE_BABE));
    }

    #[test]
    fn get_u64_decodes_le() {
        let bytes = [0x05, 0x08, 0xEF, 0xCD, 0xAB, 0x89, 0x67, 0x45, 0x23, 0x01];
        let map = Tlv8Map::parse(&bytes).unwrap();
        assert_eq!(map.get_u64(0x05).unwrap(), Some(0x0123_4567_89AB_CDEF));
    }

    #[test]
    fn get_uint_accepts_shorter_than_width() {
        // a 1-byte value read as u32 zero-extends.
        let map = Tlv8Map::parse(&[0x04, 0x01, 0x07]).unwrap();
        assert_eq!(map.get_u32(0x04).unwrap(), Some(7));
    }

    #[test]
    fn get_u16_rejects_oversized_value() {
        let map = Tlv8Map::parse(&[0x03, 0x03, 0x01, 0x02, 0x03]).unwrap();
        assert_eq!(
            map.get_u16(0x03).unwrap_err(),
            Tlv8Error::IntegerTooLarge {
                requested: 2,
                actual: 3
            }
        );
    }

    #[test]
    fn from_items_and_into_items_round_trip() {
        let items = vec![(0x01_u8, vec![0xAA]), (0x02, vec![0xBB, 0xCC])];
        let map = Tlv8Map::from_items(items.clone());
        assert_eq!(map.items(), &items[..]);
        assert_eq!(map.into_items(), items);
    }
}
