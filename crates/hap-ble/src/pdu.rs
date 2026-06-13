//! HAP-BLE PDU framing: encode requests, decode responses, fragment/reassemble,
//! and the body param TLV + GATT format maps. Pure logic — no I/O.

use crate::error::{BleError, Result};

/// HAP-BLE PDU opcodes used by this transport.
// Variant names match the HAP-BLE spec verbatim and share the `Characteristic`
// prefix intentionally — renaming them would diverge from the spec.
#[allow(clippy::enum_variant_names)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpCode {
    /// Read a characteristic's signature (type, properties, format).
    // Used by future tasks (signature read); suppress dead_code until then.
    #[allow(dead_code)]
    CharacteristicSignatureRead = 0x01,
    /// Write a characteristic value.
    CharacteristicWrite = 0x02,
    /// Read a characteristic value.
    CharacteristicRead = 0x03,
}

/// HAP body param type bytes (the TLV8 carried inside a PDU body).
pub mod param {
    /// The characteristic value.
    pub const VALUE: u8 = 0x01;
    /// The characteristic type UUID.
    // Used by future tasks (signature read); suppress dead_code until then.
    #[allow(dead_code)]
    pub const CHAR_TYPE: u8 = 0x04;
    /// HAP characteristic properties descriptor (u16 LE bitmask).
    // Used by future tasks (signature read); suppress dead_code until then.
    #[allow(dead_code)]
    pub const PROPERTIES: u8 = 0x0A;
    /// GATT presentation format descriptor (7 bytes).
    // Used by future tasks (signature read); suppress dead_code until then.
    #[allow(dead_code)]
    pub const PRESENTATION_FORMAT: u8 = 0x0C;
}

/// Encode a request PDU first fragment (header + optional body), unfragmented.
/// Fragmentation for large bodies is applied separately by [`fragment`].
pub fn encode_request(op: OpCode, tid: u8, iid: u16, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(7 + body.len());
    out.push(0x00); // control: request, first fragment
    out.push(op as u8);
    out.push(tid);
    out.extend_from_slice(&iid.to_le_bytes());
    if !body.is_empty() {
        let len = u16::try_from(body.len()).unwrap_or(u16::MAX);
        out.extend_from_slice(&len.to_le_bytes());
        out.extend_from_slice(body);
    }
    out
}

/// Wrap a raw value in a `Value` (0x01) param TLV8 — the body of a read/write.
pub fn encode_value_param(value: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut w = hap_tlv8::Tlv8Writer::new(&mut out);
    w.push(param::VALUE, value);
    out
}

/// Extract the `Value` (0x01) param from a PDU body, if present.
///
/// # Errors
/// Returns [`BleError::Tlv8`] if the body is not valid TLV8, or
/// [`BleError::MalformedPdu`] if the value param is absent.
pub fn value_param(body: &[u8]) -> Result<Vec<u8>> {
    let map = hap_tlv8::Tlv8Map::parse(body)?;
    map.get(param::VALUE)
        .map(<[u8]>::to_vec)
        .ok_or(BleError::MalformedPdu("missing value param (0x01)"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_bodyless_request() {
        // Characteristic-Read (0x03), TID 0x11, iid 0x0203, no body.
        let pdu = encode_request(OpCode::CharacteristicRead, 0x11, 0x0203, &[]);
        assert_eq!(pdu, vec![0x00, 0x03, 0x11, 0x03, 0x02]);
    }

    #[test]
    fn encodes_request_with_body() {
        // Characteristic-Write (0x02), TID 0x22, iid 0x0001, body = [0xAA,0xBB].
        let pdu = encode_request(OpCode::CharacteristicWrite, 0x22, 0x0001, &[0xAA, 0xBB]);
        assert_eq!(
            pdu,
            vec![0x00, 0x02, 0x22, 0x01, 0x00, 0x02, 0x00, 0xAA, 0xBB]
        );
    }

    #[test]
    #[allow(clippy::unwrap_used)] // test code: roundtrip success is the whole point
    fn value_param_roundtrip() {
        let body = encode_value_param(&[0x01, 0x02, 0x03]);
        let got = value_param(&body).unwrap();
        assert_eq!(got, vec![0x01, 0x02, 0x03]);
    }
}
