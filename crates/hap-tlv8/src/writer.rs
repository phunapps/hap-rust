//! TLV8 encoder appending to a caller-provided `Vec<u8>`.
//!
//! [`Tlv8Writer::push`] writes one logical value as one or more TLV8 items,
//! fragmenting values longer than 255 bytes (phase 2). The integer helpers
//! write fixed-width little-endian payloads — HAP integer fields are fixed
//! width, so there is no minimal-width trimming.

/// A TLV8 encoder that appends to a borrowed `Vec<u8>`.
///
/// The writer borrows the output buffer mutably for its lifetime; drop the
/// writer to release the borrow.
pub struct Tlv8Writer<'a> {
    out: &'a mut Vec<u8>,
}

impl<'a> Tlv8Writer<'a> {
    /// Construct a writer that appends to `out`.
    pub fn new(out: &'a mut Vec<u8>) -> Self {
        Self { out }
    }

    /// Write a logical value as one TLV8 item. Phase 1 assumes
    /// `value.len() <= 255`; phase 2 replaces this body with the
    /// auto-fragmenting version.
    pub fn push(&mut self, ty: u8, value: &[u8]) {
        debug_assert!(value.len() <= 255, "phase 1 push handles <= 255 bytes");
        self.out.push(ty);
        // value.len() <= 255 is guaranteed by the caller in phase 1.
        #[allow(clippy::cast_possible_truncation)]
        self.out.push(value.len() as u8);
        self.out.extend_from_slice(value);
    }

    /// Write an unsigned 8-bit integer as a 1-byte item.
    pub fn push_u8(&mut self, ty: u8, v: u8) {
        self.push(ty, &v.to_le_bytes());
    }

    /// Write an unsigned 16-bit integer as a 2-byte little-endian item.
    pub fn push_u16(&mut self, ty: u8, v: u16) {
        self.push(ty, &v.to_le_bytes());
    }

    /// Write an unsigned 32-bit integer as a 4-byte little-endian item.
    pub fn push_u32(&mut self, ty: u8, v: u32) {
        self.push(ty, &v.to_le_bytes());
    }

    /// Write an unsigned 64-bit integer as an 8-byte little-endian item.
    pub fn push_u64(&mut self, ty: u8, v: u64) {
        self.push(ty, &v.to_le_bytes());
    }

    /// Write a string as its UTF-8 bytes. Long strings fragment via `push`.
    pub fn push_str(&mut self, ty: u8, v: &str) {
        self.push(ty, v.as_bytes());
    }
}

#[cfg(test)]
// CLAUDE.md test-code carve-out: unwrap/expect allowed with documented reason.
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn push_short_value_emits_type_len_value() {
        let mut buf = Vec::new();
        let mut w = Tlv8Writer::new(&mut buf);
        w.push(0x01, &[0xAB, 0xCD]);
        assert_eq!(buf, [0x01, 0x02, 0xAB, 0xCD]);
    }

    #[test]
    fn push_empty_value_emits_zero_length_item() {
        let mut buf = Vec::new();
        let mut w = Tlv8Writer::new(&mut buf);
        w.push(0x06, &[]);
        assert_eq!(buf, [0x06, 0x00]);
    }

    #[test]
    fn push_exactly_255_bytes_single_item() {
        let mut buf = Vec::new();
        let mut w = Tlv8Writer::new(&mut buf);
        // 255 is the max single-item length; phase 1 does not yet add a
        // terminating fragment (that arrives in phase 2). For now we assert
        // the single-item framing for a sub-256 value of length 255.
        let value = vec![0x42_u8; 255];
        w.push(0x09, &value);
        assert_eq!(buf.len(), 2 + 255);
        assert_eq!(buf[0], 0x09);
        assert_eq!(buf[1], 0xFF);
        assert!(buf[2..].iter().all(|&b| b == 0x42));
    }

    #[test]
    fn push_u8_emits_one_le_byte() {
        let mut buf = Vec::new();
        let mut w = Tlv8Writer::new(&mut buf);
        w.push_u8(0x02, 0x2A);
        assert_eq!(buf, [0x02, 0x01, 0x2A]);
    }

    #[test]
    fn push_u16_emits_two_le_bytes() {
        let mut buf = Vec::new();
        let mut w = Tlv8Writer::new(&mut buf);
        w.push_u16(0x03, 0x1234);
        assert_eq!(buf, [0x03, 0x02, 0x34, 0x12]);
    }

    #[test]
    fn push_u32_emits_four_le_bytes() {
        let mut buf = Vec::new();
        let mut w = Tlv8Writer::new(&mut buf);
        w.push_u32(0x04, 0xCAFE_BABE);
        assert_eq!(buf, [0x04, 0x04, 0xBE, 0xBA, 0xFE, 0xCA]);
    }

    #[test]
    fn push_u64_emits_eight_le_bytes() {
        let mut buf = Vec::new();
        let mut w = Tlv8Writer::new(&mut buf);
        w.push_u64(0x05, 0x0123_4567_89AB_CDEF);
        assert_eq!(
            buf,
            [0x05, 0x08, 0xEF, 0xCD, 0xAB, 0x89, 0x67, 0x45, 0x23, 0x01]
        );
    }

    #[test]
    fn push_str_emits_utf8_bytes() {
        let mut buf = Vec::new();
        let mut w = Tlv8Writer::new(&mut buf);
        w.push_str(0x07, "Pair");
        // "Pair" = [0x50, 0x61, 0x69, 0x72], length 4.
        assert_eq!(buf, [0x07, 0x04, 0x50, 0x61, 0x69, 0x72]);
    }
}
