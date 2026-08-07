//! Accessory-side HAP PDU codec: decode requests, encode responses.
//!
//! The mirror of `hap-thread`'s controller codec. A request is
//! `control(0x00) ‖ opcode ‖ tid ‖ iid(u16 LE) ‖ len(u16 LE) ‖ body`; a response
//! is `control(0x02) ‖ tid ‖ status ‖ len(u16 LE) ‖ body`. Requests may be
//! batched (several concatenated PDUs in one payload); responses are likewise
//! concatenated, tid-for-tid.

use crate::error::{DutError, Result};

/// HAP opcodes this accessory answers.
pub(crate) const OP_CHAR_WRITE: u8 = 0x02;
pub(crate) const OP_CHAR_READ: u8 = 0x03;
/// `HAP-Protocol-Read-Database` — the whole `0x09` attribute database.
pub(crate) const OP_READ_DATABASE: u8 = 0x09;

/// HAP PDU status codes.
pub(crate) const STATUS_SUCCESS: u8 = 0;
pub(crate) const STATUS_UNSUPPORTED: u8 = 1;
pub(crate) const STATUS_INVALID_INSTANCE_ID: u8 = 4;

/// The `kTLVHAPParamValue` TLV8 type carrying a characteristic value.
const PARAM_VALUE: u8 = 0x01;

/// A decoded request PDU.
pub(crate) struct Request {
    pub opcode: u8,
    pub tid: u8,
    pub iid: u16,
    pub body: Vec<u8>,
}

/// Decode one or more concatenated request PDUs from `pdu`.
///
/// # Errors
/// [`DutError::Protocol`] if any PDU is truncated.
pub(crate) fn decode_requests(pdu: &[u8]) -> Result<Vec<Request>> {
    let mut out = Vec::new();
    let mut off = 0;
    while off < pdu.len() {
        let rest = &pdu[off..];
        if rest.len() < 7 {
            return Err(DutError::Protocol(
                "request PDU shorter than its 7-byte header",
            ));
        }
        // rest[0] is the control byte (request); we do not need its bits here.
        let opcode = rest[1];
        let tid = rest[2];
        let iid = u16::from_le_bytes([rest[3], rest[4]]);
        let len = usize::from(u16::from_le_bytes([rest[5], rest[6]]));
        let end = 7 + len;
        if rest.len() < end {
            return Err(DutError::Protocol("request body shorter than declared"));
        }
        out.push(Request {
            opcode,
            tid,
            iid,
            body: rest[7..end].to_vec(),
        });
        off += end;
    }
    Ok(out)
}

/// Encode a response PDU (`control(0x02) ‖ tid ‖ status ‖ len ‖ body`).
pub(crate) fn encode_response(tid: u8, status: u8, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(5 + body.len());
    out.push(0x02); // control: response
    out.push(tid);
    out.push(status);
    let len = u16::try_from(body.len()).unwrap_or(u16::MAX);
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(body);
    out
}

/// Wrap a raw value in a `kTLVHAPParamValue` (0x01) TLV8 — a read response body.
pub(crate) fn value_body(value: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut w = hap_tlv8::Tlv8Writer::new(&mut out);
    w.push(PARAM_VALUE, value);
    out
}

/// Extract the `kTLVHAPParamValue` (0x01) from a write request body.
///
/// # Errors
/// [`DutError::Tlv8`] if the body is not valid TLV8; [`DutError::Protocol`] if
/// the value param is absent.
pub(crate) fn extract_value(body: &[u8]) -> Result<Vec<u8>> {
    let map = hap_tlv8::Tlv8Map::parse(body)?;
    map.get(PARAM_VALUE)
        .map(<[u8]>::to_vec)
        .ok_or(DutError::Protocol("write body missing value param"))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn decode_a_batched_read_then_write() {
        // A CharRead (0x03) tid0 iid0x0009 empty, then a CharWrite (0x02) tid1
        // iid0x0009 body=[0xAA].
        let pdu = vec![
            0x00, 0x03, 0x00, 0x09, 0x00, 0x00, 0x00, // read
            0x00, 0x02, 0x01, 0x09, 0x00, 0x01, 0x00, 0xAA, // write, len1
        ];
        let reqs = decode_requests(&pdu).unwrap();
        assert_eq!(reqs.len(), 2);
        assert_eq!((reqs[0].opcode, reqs[0].tid, reqs[0].iid), (0x03, 0, 9));
        assert!(reqs[0].body.is_empty());
        assert_eq!((reqs[1].opcode, reqs[1].tid, reqs[1].iid), (0x02, 1, 9));
        assert_eq!(reqs[1].body, vec![0xAA]);
    }

    #[test]
    fn response_and_value_round_trip() {
        let body = value_body(&[0x01]);
        let resp = encode_response(3, STATUS_SUCCESS, &body);
        assert_eq!(resp[0], 0x02); // response control
        assert_eq!(resp[1], 3); // tid
        assert_eq!(resp[2], STATUS_SUCCESS);
        assert_eq!(extract_value(&body).unwrap(), vec![0x01]);
    }
}
