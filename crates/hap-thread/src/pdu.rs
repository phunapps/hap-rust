//! HAP PDU framing for the CoAP transport.
//!
//! HAP-over-CoAP carries the **same PDU format as HAP-BLE**: a request is
//! `control(0x00) ‖ opcode ‖ tid ‖ iid(u16 LE) ‖ len(u16 LE) ‖ body`, and a
//! response is `control ‖ tid ‖ status ‖ len(u16 LE) ‖ body` with the response
//! bit set in the control byte. Two CoAP-specific details distinguish this from
//! [`hap_ble`](https://docs.rs/hap-ble)'s codec:
//!
//! - The length field is **always present**, even for an empty body (BLE omits
//!   it). This matches aiohomekit's `encode_pdu`
//!   (`struct.pack("<BBBHH", 0, opcode, tid, iid, len) + data`).
//! - Requests are commonly **batched** ([`encode_all`]): several PDUs are
//!   concatenated in one CoAP payload, each tagged with its list index as the
//!   transaction id, and the response is likewise several concatenated PDUs
//!   ([`decode_all`]).
//!
//! There is no fragmentation here — CoAP handles payloads larger than a single
//! frame via block-wise transfer, so the PDU layer treats each request and
//! response as one contiguous byte string.
//!
//! This is pure logic — no I/O.

use crate::error::{Result, ThreadError};

/// HAP PDU opcodes used by the CoAP transport (values match the HAP-BLE spec).
// Variants share the `Char`/`Serv` prefixes intentionally — the names track the
// spec, and not every opcode is exercised yet.
#[allow(clippy::enum_variant_names, dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OpCode {
    /// Read a characteristic's signature (unused on CoAP — see [`ReadDatabase`]).
    ///
    /// [`ReadDatabase`]: OpCode::ReadDatabase
    CharSigRead = 0x01,
    /// Write a characteristic value.
    CharWrite = 0x02,
    /// Read a characteristic value.
    CharRead = 0x03,
    /// Timed write.
    CharTimedWrite = 0x04,
    /// Execute a prepared (timed) write.
    CharExecWrite = 0x05,
    /// Read a service's signature (unused on CoAP).
    ServSigRead = 0x06,
    /// Read the entire accessory database in one response (CoAP uses this in
    /// place of the per-characteristic signature reads BLE performs).
    ReadDatabase = 0x09,
    /// Subscribe to a characteristic's disconnected-event notifications.
    Subscribe = 0x0B,
    /// Unsubscribe from a characteristic's notifications.
    Unsubscribe = 0x0C,
}

/// HAP body-param TLV8 type bytes carried inside a PDU body.
pub(crate) mod param {
    /// The characteristic value (`kTLVHAPParamValue`). Read responses carry the
    /// value under this type; writes wrap the value in it.
    pub(crate) const VALUE: u8 = 0x01;
}

/// The 5-byte response header (`control ‖ tid ‖ status ‖ len(u16 LE)`).
const RESPONSE_HEADER_LEN: usize = 5;

/// Encode a single request PDU. The length field is always written (including
/// `0` for an empty body), per the CoAP PDU form.
pub(crate) fn encode_request(op: OpCode, tid: u8, iid: u16, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(RESPONSE_HEADER_LEN + body.len());
    out.push(0x00); // control: request, first (and only) fragment
    out.push(op as u8);
    out.push(tid);
    out.extend_from_slice(&iid.to_le_bytes());
    // The wire length field is u16; HAP PDU bodies are always well within that.
    // A body that overflowed would corrupt the PDU, so assert the invariant in
    // debug builds (unreachable for real characteristic values).
    debug_assert!(
        u16::try_from(body.len()).is_ok(),
        "HAP PDU body exceeds the u16 length field"
    );
    let len = u16::try_from(body.len()).unwrap_or(u16::MAX);
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(body);
    out
}

/// Encode several PDUs into one batched request payload. Each entry is
/// `(iid, body)`; the transaction id is the entry's index (matching
/// aiohomekit's `encode_all_pdus`), so [`decode_all`] can be started at tid `0`.
pub(crate) fn encode_all(op: OpCode, entries: &[(u16, Vec<u8>)]) -> Vec<u8> {
    let mut out = Vec::new();
    debug_assert!(
        entries.len() <= 256,
        "batched request exceeds the u8 transaction-id space (256)"
    );
    for (idx, (iid, body)) in entries.iter().enumerate() {
        // A batch never exceeds 256 entries in practice; index is the tid.
        let tid = u8::try_from(idx).unwrap_or(u8::MAX);
        out.extend_from_slice(&encode_request(op, tid, *iid, body));
    }
    out
}

/// Wrap a raw characteristic value in a `Value` (`0x01`) param TLV8 — the body
/// form a Characteristic-Write PDU expects.
pub(crate) fn encode_value_body(value: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut w = hap_tlv8::Tlv8Writer::new(&mut out);
    w.push(param::VALUE, value);
    out
}

/// A decoded response PDU.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Response {
    /// Transaction id echoed from the request.
    pub tid: u8,
    /// HAP status byte (`0` = success).
    pub status: u8,
    /// The response body (may be empty). For a read this is a param TLV8 whose
    /// `Value` (`0x01`) entry holds the characteristic value.
    pub body: Vec<u8>,
}

impl Response {
    /// Extract the `Value` (`0x01`) param from the body, or an empty slice if
    /// the body carries no such param (an empty read result).
    ///
    /// # Errors
    /// Returns [`ThreadError::Tlv8`] if the body is not valid TLV8.
    pub(crate) fn value(&self) -> Result<Vec<u8>> {
        if self.body.is_empty() {
            return Ok(Vec::new());
        }
        let map = hap_tlv8::Tlv8Map::parse(&self.body)?;
        Ok(map
            .get(param::VALUE)
            .map(<[u8]>::to_vec)
            .unwrap_or_default())
    }
}

/// Decode one response PDU from the front of `pdu`, returning the response and
/// the number of bytes it consumed (`5 + body_len`).
///
/// # Errors
/// Returns [`ThreadError::MalformedPdu`] if the PDU is shorter than its 5-byte
/// header, if the control byte lacks the response bit, or if the declared body
/// length exceeds the available bytes.
fn decode_one(pdu: &[u8]) -> Result<(Response, usize)> {
    if pdu.len() < RESPONSE_HEADER_LEN {
        return Err(ThreadError::MalformedPdu(
            "response shorter than its 5-byte header",
        ));
    }
    let control = pdu[0];
    // The response bit (bit 1) must be set; bits 1..=3 encode the fragment/kind
    // and for a plain response are exactly `0b010`.
    if control & 0b0000_1110 != 0b0000_0010 {
        return Err(ThreadError::MalformedPdu(
            "control byte does not have the response bit set",
        ));
    }
    let tid = pdu[1];
    let status = pdu[2];
    let len = usize::from(u16::from_le_bytes([pdu[3], pdu[4]]));
    let end = RESPONSE_HEADER_LEN
        .checked_add(len)
        .ok_or(ThreadError::MalformedPdu("response length overflow"))?;
    if pdu.len() < end {
        return Err(ThreadError::MalformedPdu(
            "response body shorter than declared",
        ));
    }
    let body = pdu[RESPONSE_HEADER_LEN..end].to_vec();
    Ok((Response { tid, status, body }, end))
}

/// Decode a single response PDU, requiring it to consume the whole slice. Used
/// by tests; the transport path always uses the batched [`decode_all`].
///
/// # Errors
/// Returns [`ThreadError::MalformedPdu`] as [`decode_one`] does.
#[cfg(test)]
pub(crate) fn decode_response(pdu: &[u8]) -> Result<Response> {
    let (resp, _consumed) = decode_one(pdu)?;
    Ok(resp)
}

/// Decode a batched response payload into its constituent PDUs, in order.
///
/// # Errors
/// Returns [`ThreadError::MalformedPdu`] if any PDU in the batch is malformed or
/// its transaction id does not match its position (the batch is tagged
/// `tid = index`, as [`encode_all`] emits and aiohomekit's `decode_all_pdus`
/// checks) — results are position-aligned with the request, so a misordered
/// batch must not be accepted silently.
pub(crate) fn decode_all(pdu: &[u8]) -> Result<Vec<Response>> {
    let mut out = Vec::new();
    let mut offset = 0;
    while offset < pdu.len() {
        let (resp, consumed) = decode_one(&pdu[offset..])?;
        let expected_tid = u8::try_from(out.len()).unwrap_or(u8::MAX);
        if resp.tid != expected_tid {
            return Err(ThreadError::MalformedPdu(
                "batched response transaction id does not match its position",
            ));
        }
        out.push(resp);
        offset += consumed;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn encode_request_always_writes_length_even_when_empty() {
        // Characteristic-Read (0x03), tid 0x11, iid 0x0203, empty body:
        // control=0x00, op=0x03, tid=0x11, iid=03 02 (LE), len=00 00 (LE).
        let pdu = encode_request(OpCode::CharRead, 0x11, 0x0203, &[]);
        assert_eq!(pdu, vec![0x00, 0x03, 0x11, 0x03, 0x02, 0x00, 0x00]);
    }

    #[test]
    fn encode_request_with_body() {
        // Write (0x02), tid 0x22, iid 0x0001, body [0xAA,0xBB].
        let pdu = encode_request(OpCode::CharWrite, 0x22, 0x0001, &[0xAA, 0xBB]);
        assert_eq!(
            pdu,
            vec![0x00, 0x02, 0x22, 0x01, 0x00, 0x02, 0x00, 0xAA, 0xBB]
        );
    }

    #[test]
    fn encode_all_tags_each_pdu_with_its_index() {
        // Two reads batched: tids 0 and 1, iids 0x0010 and 0x0020, empty bodies.
        let batch = encode_all(
            OpCode::CharRead,
            &[(0x0010, Vec::new()), (0x0020, Vec::new())],
        );
        assert_eq!(
            batch,
            vec![
                0x00, 0x03, 0x00, 0x10, 0x00, 0x00, 0x00, // tid 0, iid 0x0010
                0x00, 0x03, 0x01, 0x20, 0x00, 0x00, 0x00, // tid 1, iid 0x0020
            ]
        );
    }

    #[test]
    fn decode_response_reads_header_and_body() {
        // control=0x02 (response bit), tid=0x11, status=0x00, len=2, body=DE AD.
        let resp = decode_response(&[0x02, 0x11, 0x00, 0x02, 0x00, 0xDE, 0xAD]).unwrap();
        assert_eq!(resp.tid, 0x11);
        assert_eq!(resp.status, 0x00);
        assert_eq!(resp.body, vec![0xDE, 0xAD]);
    }

    #[test]
    fn decode_response_rejects_missing_response_bit() {
        // control=0x00 (a request-shaped control) must be rejected as a response.
        let err = decode_response(&[0x00, 0x11, 0x00, 0x00, 0x00]);
        assert!(matches!(err, Err(ThreadError::MalformedPdu(_))));
    }

    #[test]
    fn decode_response_rejects_truncated_body() {
        // Declares len=4 but only 1 body byte present.
        let err = decode_response(&[0x02, 0x11, 0x00, 0x04, 0x00, 0xDE]);
        assert!(matches!(err, Err(ThreadError::MalformedPdu(_))));
    }

    #[test]
    fn decode_all_splits_a_batched_response() {
        // Two responses: (tid0, status0, body=[0x01]) and (tid1, status0, empty).
        let buf = vec![
            0x02, 0x00, 0x00, 0x01, 0x00, 0x01, // tid0, len1, body 0x01
            0x02, 0x01, 0x00, 0x00, 0x00, // tid1, len0
        ];
        let all = decode_all(&buf).unwrap();
        assert_eq!(all.len(), 2);
        assert_eq!(all[0].tid, 0x00);
        assert_eq!(all[0].body, vec![0x01]);
        assert_eq!(all[1].tid, 0x01);
        assert!(all[1].body.is_empty());
    }

    #[test]
    fn decode_all_rejects_misordered_tids() {
        // Two responses tagged tid 0 then tid 5 — the second's tid ≠ its index 1.
        let buf = vec![
            0x02, 0x00, 0x00, 0x00, 0x00, // tid0, len0
            0x02, 0x05, 0x00, 0x00, 0x00, // tid5 at position 1 → mismatch
        ];
        assert!(matches!(
            decode_all(&buf),
            Err(ThreadError::MalformedPdu(_))
        ));
    }

    #[test]
    fn value_wrap_and_extract_round_trip() {
        let body = encode_value_body(&[0x01, 0x02, 0x03]);
        let resp = Response {
            tid: 0,
            status: 0,
            body,
        };
        assert_eq!(resp.value().unwrap(), vec![0x01, 0x02, 0x03]);
    }

    #[test]
    fn value_of_empty_body_is_empty() {
        let resp = Response {
            tid: 0,
            status: 0,
            body: Vec::new(),
        };
        assert_eq!(resp.value().unwrap(), Vec::<u8>::new());
    }
}
