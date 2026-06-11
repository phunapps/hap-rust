//! TLV8 encoder appending to a caller-provided `Vec<u8>`.
//!
//! [`Tlv8Writer::push`] writes one logical value as one or more TLV8 items,
//! fragmenting values longer than 255 bytes. The integer helpers
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

    /// Write a logical value as one or more TLV8 items, fragmenting any value
    /// longer than 255 bytes into consecutive items of the same type.
    ///
    /// A 255-byte item means "more of this type follows", so when the value's
    /// length is a non-zero exact multiple of 255 a terminating zero-length
    /// item of the same type is appended to mark the end of the run. The
    /// matching reader ([`crate::Tlv8Reader::parse`]) reverses this.
    pub fn push(&mut self, ty: u8, value: &[u8]) {
        if value.is_empty() {
            self.out.push(ty);
            self.out.push(0);
            return;
        }
        let mut last_chunk_len = 0usize;
        for chunk in value.chunks(255) {
            self.out.push(ty);
            // chunk.len() is at most 255, so the cast cannot truncate.
            #[allow(clippy::cast_possible_truncation)]
            self.out.push(chunk.len() as u8);
            self.out.extend_from_slice(chunk);
            last_chunk_len = chunk.len();
        }
        // If the final chunk was exactly 255 bytes, the reader would expect
        // the run to continue. Append a zero-length terminator of this type.
        if last_chunk_len == 255 {
            self.out.push(ty);
            self.out.push(0);
        }
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

    /// Write a zero-length separator item ([`crate::SEPARATOR`], `0xFF`) used
    /// to delimit repeated structures such as a list of pairings.
    pub fn push_separator(&mut self) {
        self.out.push(crate::SEPARATOR);
        self.out.push(0);
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
    fn push_256_bytes_fragments_255_then_1() {
        let mut buf = Vec::new();
        let mut w = Tlv8Writer::new(&mut buf);
        let value: Vec<u8> = (0..=u8::MAX).collect();
        // value = 0x00,0x01,...,0xFF (256 bytes)
        w.push(0x09, &value);
        // header of first item
        assert_eq!(&buf[0..2], &[0x09, 0xFF]);
        // 255 value bytes 0x00..=0xFE
        assert_eq!(&buf[2..257], &(0u8..=254).collect::<Vec<u8>>()[..]);
        // header of second item: type 0x09, length 1
        assert_eq!(&buf[257..259], &[0x09, 0x01]);
        // last value byte 0xFF
        assert_eq!(buf[259], 0xFF);
        assert_eq!(buf.len(), 260);
    }

    #[test]
    fn push_exactly_255_appends_terminating_zero_length_item() {
        let mut buf = Vec::new();
        let mut w = Tlv8Writer::new(&mut buf);
        let value = vec![0x42_u8; 255];
        w.push(0x09, &value);
        assert_eq!(&buf[0..2], &[0x09, 0xFF]);
        assert!(buf[2..257].iter().all(|&b| b == 0x42));
        // terminating zero-length item
        assert_eq!(&buf[257..259], &[0x09, 0x00]);
        assert_eq!(buf.len(), 259);
    }

    #[test]
    fn push_510_bytes_two_full_fragments_then_terminator() {
        let mut buf = Vec::new();
        let mut w = Tlv8Writer::new(&mut buf);
        let value = vec![0xAB_u8; 510];
        w.push(0x09, &value);
        assert_eq!(&buf[0..2], &[0x09, 0xFF]);
        assert_eq!(&buf[257..259], &[0x09, 0xFF]);
        assert_eq!(&buf[514..516], &[0x09, 0x00]);
        assert_eq!(buf.len(), 516);
    }

    #[test]
    fn push_300_bytes_fragments_255_then_45() {
        let mut buf = Vec::new();
        let mut w = Tlv8Writer::new(&mut buf);
        let value = vec![0x01_u8; 300];
        w.push(0x09, &value);
        assert_eq!(&buf[0..2], &[0x09, 0xFF]);
        // second item length = 300 - 255 = 45 = 0x2D
        assert_eq!(&buf[257..259], &[0x09, 0x2D]);
        assert_eq!(buf.len(), 2 + 255 + 2 + 45);
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

    #[test]
    fn push_separator_emits_ff_zero() {
        let mut buf = Vec::new();
        let mut w = Tlv8Writer::new(&mut buf);
        w.push_separator();
        assert_eq!(buf, [0xFF, 0x00]);
    }

    #[test]
    fn write_then_parse_round_trips_with_separator_and_fragment() {
        use crate::Tlv8Reader;
        let big = vec![0x07_u8; 300];
        let mut buf = Vec::new();
        {
            let mut w = Tlv8Writer::new(&mut buf);
            w.push(0x01, &[0xAA]);
            w.push_separator();
            w.push(0x01, &big);
        }
        let items = Tlv8Reader::parse(&buf).unwrap();
        assert_eq!(items, vec![(0x01, vec![0xAA]), (0xFF, vec![]), (0x01, big)]);
    }
}
