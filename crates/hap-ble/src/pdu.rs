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

/// A decoded response PDU (already reassembled from its fragments).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    /// Transaction id echoed from the request.
    pub tid: u8,
    /// HAP status byte (0 = success).
    pub status: u8,
    /// The response body (may be empty); for reads this is a param TLV8.
    pub body: Vec<u8>,
}

/// Decode a fully-reassembled response PDU.
///
/// # Errors
/// Returns [`BleError::MalformedPdu`] if the PDU is too short or its declared
/// body length exceeds the available bytes.
pub fn decode_response(pdu: &[u8]) -> Result<Response> {
    if pdu.len() < 3 {
        return Err(BleError::MalformedPdu("response shorter than 3 bytes"));
    }
    let tid = pdu[1];
    let status = pdu[2];
    let body = if pdu.len() > 3 {
        if pdu.len() < 5 {
            return Err(BleError::MalformedPdu("response body length truncated"));
        }
        let len = usize::from(u16::from_le_bytes([pdu[3], pdu[4]]));
        let start = 5;
        if pdu.len() < start + len {
            return Err(BleError::MalformedPdu("response body shorter than declared"));
        }
        pdu[start..start + len].to_vec()
    } else {
        Vec::new()
    };
    Ok(Response { tid, status, body })
}

/// Split a PDU into GATT-sized fragments. `frag_size` is the maximum bytes per
/// GATT write (typically ATT MTU − 3). The first fragment keeps the PDU header;
/// each continuation is `0x80` ++ TID ++ next body chunk.
pub fn fragment(pdu: &[u8], frag_size: usize) -> Vec<Vec<u8>> {
    let frag_size = frag_size.max(3);
    if pdu.len() <= frag_size {
        return vec![pdu.to_vec()];
    }
    let tid = pdu[2];
    let mut frags = vec![pdu[..frag_size].to_vec()];
    let mut rest = &pdu[frag_size..];
    let cont_payload = frag_size.saturating_sub(2).max(1);
    while !rest.is_empty() {
        let take = rest.len().min(cont_payload);
        let mut f = Vec::with_capacity(2 + take);
        f.push(0x80); // continuation, request
        f.push(tid);
        f.extend_from_slice(&rest[..take]);
        frags.push(f);
        rest = &rest[take..];
    }
    frags
}

/// Reassemble fragments produced by an accessory: the first fragment is the
/// full header; each continuation (`0x82`/`0x80` ++ TID ++ chunk) appends its
/// chunk after stripping the 2-byte continuation header.
///
/// # Errors
/// Returns [`BleError::MalformedPdu`] if a continuation fragment is too short.
pub fn reassemble(frags: &[Vec<u8>]) -> Result<Vec<u8>> {
    let mut out = match frags.first() {
        Some(first) => first.clone(),
        None => return Err(BleError::MalformedPdu("no fragments to reassemble")),
    };
    for f in &frags[1..] {
        if f.len() < 2 {
            return Err(BleError::MalformedPdu("continuation fragment too short"));
        }
        out.extend_from_slice(&f[2..]);
    }
    Ok(out)
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

    #[test]
    #[allow(clippy::unwrap_used)] // test code: success is the whole point
    fn decodes_bodyless_response() {
        // control=0x02, TID=0x11, status=0x00, no body.
        let resp = decode_response(&[0x02, 0x11, 0x00]).unwrap();
        assert_eq!(resp.tid, 0x11);
        assert_eq!(resp.status, 0x00);
        assert!(resp.body.is_empty());
    }

    #[test]
    #[allow(clippy::unwrap_used)] // test code: success is the whole point
    fn decodes_response_with_body() {
        // control=0x02, TID=0x11, status=0x00, len=2, body=[0xDE,0xAD].
        let resp = decode_response(&[0x02, 0x11, 0x00, 0x02, 0x00, 0xDE, 0xAD]).unwrap();
        assert_eq!(resp.status, 0x00);
        assert_eq!(resp.body, vec![0xDE, 0xAD]);
    }

    #[test]
    fn rejects_short_response() {
        assert!(matches!(
            decode_response(&[0x02, 0x11]),
            Err(crate::error::BleError::MalformedPdu(_))
        ));
    }

    #[test]
    #[allow(clippy::unwrap_used)] // test code: roundtrip success is the whole point
    fn fragments_and_reassembles_a_large_pdu() {
        // A 300-byte PDU at MTU body-size 100 must split, then reassemble.
        let pdu: Vec<u8> = (0..300u32).map(|i| u8::try_from(i % 251).unwrap()).collect();
        let frags = fragment(&pdu, 100);
        assert!(frags.len() > 1);
        // First fragment keeps the original header byte; continuations start 0x80.
        assert_eq!(frags[0][0], pdu[0]);
        assert_eq!(frags[1][0], 0x80);
        let back = reassemble(&frags).unwrap();
        assert_eq!(back, pdu);
    }

    #[test]
    fn single_fragment_when_it_fits() {
        let pdu = vec![0x00, 0x03, 0x11, 0x03, 0x02];
        let frags = fragment(&pdu, 100);
        assert_eq!(frags.len(), 1);
        assert_eq!(frags[0], pdu);
    }
}
