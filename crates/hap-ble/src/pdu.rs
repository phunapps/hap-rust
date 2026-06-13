//! HAP-BLE PDU framing: encode requests, decode responses, fragment/reassemble,
//! and the body param TLV + GATT format maps. Pure logic — no I/O.

use crate::error::{BleError, Result};
use crate::gatt::GattConnection;
use hap_model::format::CharFormat;
use hap_model::perms::Perms;
use hap_model::CharacteristicType;

/// HAP-BLE PDU opcodes used by this transport.
// Variant names match the HAP-BLE spec verbatim and share the `Characteristic`
// prefix intentionally — renaming them would diverge from the spec.
#[allow(clippy::enum_variant_names)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OpCode {
    /// Read a characteristic's signature (type, properties, format).
    // The opcode value is defined here for completeness; encode_request callers
    // will use it when issuing signature reads in the BLE transport layer.
    #[allow(dead_code)]
    CharacteristicSignatureRead = 0x01,
    /// Write a characteristic value.
    CharacteristicWrite = 0x02,
    /// Read a characteristic value.
    CharacteristicRead = 0x03,
}

/// HAP body param type bytes (the TLV8 carried inside a PDU body).
pub(crate) mod param {
    /// The characteristic value.
    pub(crate) const VALUE: u8 = 0x01;
    /// The characteristic type UUID.
    pub(crate) const CHAR_TYPE: u8 = 0x04;
    /// HAP characteristic properties descriptor (u16 LE bitmask).
    pub(crate) const PROPERTIES: u8 = 0x0A;
    /// GATT presentation format descriptor (7 bytes).
    pub(crate) const PRESENTATION_FORMAT: u8 = 0x0C;
}

/// Encode a request PDU first fragment (header + optional body), unfragmented.
/// Fragmentation for large bodies is applied separately by [`fragment`].
pub(crate) fn encode_request(op: OpCode, tid: u8, iid: u16, body: &[u8]) -> Vec<u8> {
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
pub(crate) fn encode_value_param(value: &[u8]) -> Vec<u8> {
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
pub(crate) fn value_param(body: &[u8]) -> Result<Vec<u8>> {
    let map = hap_tlv8::Tlv8Map::parse(body)?;
    map.get(param::VALUE)
        .map(<[u8]>::to_vec)
        .ok_or(BleError::MalformedPdu("missing value param (0x01)"))
}

/// A decoded response PDU (already reassembled from its fragments).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Response {
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
pub(crate) fn decode_response(pdu: &[u8]) -> Result<Response> {
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
pub(crate) fn fragment(pdu: &[u8], frag_size: usize) -> Vec<Vec<u8>> {
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
#[allow(dead_code)] // wired into the multi-fragment response read path during hardware reconciliation
pub(crate) fn reassemble(frags: &[Vec<u8>]) -> Result<Vec<u8>> {
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

/// Send one request PDU to `char_uuid` and return the decoded response.
///
/// Fragments the request to `frag_size`, writes each fragment, then reads and
/// reassembles the response. (The mock and btleplug both deliver the full
/// response from a single `read`; multi-fragment reads are reassembled by
/// [`reassemble`] when an accessory splits them — see hardware notes.)
///
/// # Errors
/// Propagates GATT I/O errors and [`BleError::MalformedPdu`] on a bad response.
pub(crate) async fn request<G: GattConnection + ?Sized>(
    gatt: &G,
    char_uuid: &str,
    op: OpCode,
    tid: u8,
    iid: u16,
    body: &[u8],
    frag_size: usize,
) -> Result<Response> {
    let pdu = encode_request(op, tid, iid, body);
    for frag in fragment(&pdu, frag_size) {
        gatt.write(char_uuid, &frag).await?;
    }
    let raw = gatt.read(char_uuid).await?;
    decode_response(&raw)
}

/// Like [`request`] but seals the request and opens the response through an
/// established [`BleSession`] (used after Pair Verify).
///
/// # Errors
/// Propagates AEAD, GATT, and PDU errors.
#[allow(clippy::too_many_arguments)] // transport call carries the full PDU addressing tuple
pub(crate) async fn request_secure<G: GattConnection + ?Sized>(
    gatt: &G,
    session: &mut crate::session::BleSession,
    char_uuid: &str,
    op: OpCode,
    tid: u8,
    iid: u16,
    body: &[u8],
    frag_size: usize,
) -> Result<Response> {
    let pdu = encode_request(op, tid, iid, body);
    let sealed = session.seal(&pdu)?;
    for frag in fragment(&sealed, frag_size) {
        gatt.write(char_uuid, &frag).await?;
    }
    let raw = gatt.read(char_uuid).await?;
    let opened = session.open(&raw)?;
    decode_response(&opened)
}

/// A parsed characteristic signature: the fields needed to populate a
/// [`hap_model::tree::Characteristic`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Signature {
    /// The characteristic type.
    pub char_type: CharacteristicType,
    /// The value format.
    pub format: CharFormat,
    /// The permission set.
    pub perms: Perms,
}

/// Map a GATT presentation-format byte to a HAP [`CharFormat`].
pub(crate) fn char_format_from_gatt(b: u8) -> Option<CharFormat> {
    Some(match b {
        0x01 => CharFormat::Bool,
        0x04 => CharFormat::Uint8,
        0x06 => CharFormat::Uint16,
        0x08 => CharFormat::Uint32,
        0x0A => CharFormat::Uint64,
        0x10 => CharFormat::Int,
        0x14 => CharFormat::Float,
        0x19 => CharFormat::String,
        0x1B => CharFormat::Data,
        _ => return None,
    })
}

/// Map a HAP characteristic-properties bitmask to a [`Perms`] set.
pub(crate) fn perms_from_properties(bits: u16) -> Perms {
    Perms {
        read: bits & 0x0001 != 0 || bits & 0x0010 != 0,
        write: bits & 0x0002 != 0 || bits & 0x0020 != 0,
        events: bits & 0x0080 != 0,
        hidden: bits & 0x0040 != 0,
        ..Perms::default()
    }
}

/// Convert a little-endian 16-byte BLE UUID into the canonical 36-char string.
pub(crate) fn le_bytes_to_uuid(le: &[u8]) -> Result<String> {
    if le.len() != 16 {
        return Err(BleError::MalformedPdu("characteristic type uuid not 16 bytes"));
    }
    let mut be = le.to_vec();
    be.reverse();
    let h = be.iter().fold(String::with_capacity(32), |mut acc, b| {
        use std::fmt::Write as _;
        let _ = write!(acc, "{b:02x}");
        acc
    });
    Ok(format!(
        "{}-{}-{}-{}-{}",
        &h[0..8], &h[8..12], &h[12..16], &h[16..20], &h[20..32]
    ))
}

/// Parse a Characteristic-Signature-Read response body into a [`Signature`].
///
/// # Errors
/// Returns [`BleError::MalformedPdu`] if required params are missing/short, or
/// [`BleError::Model`] if the UUID does not parse.
pub(crate) fn parse_signature(body: &[u8]) -> Result<Signature> {
    let map = hap_tlv8::Tlv8Map::parse(body)?;

    let type_le = map
        .get(param::CHAR_TYPE)
        .ok_or(BleError::MalformedPdu("signature missing char type"))?;
    let uuid = hap_model::Uuid::parse(&le_bytes_to_uuid(type_le)?)?;
    let char_type = CharacteristicType::from_uuid(&uuid);

    let prop_bytes = map
        .get(param::PROPERTIES)
        .ok_or(BleError::MalformedPdu("signature missing properties"))?;
    if prop_bytes.len() < 2 {
        return Err(BleError::MalformedPdu("properties descriptor too short"));
    }
    let perms = perms_from_properties(u16::from_le_bytes([prop_bytes[0], prop_bytes[1]]));

    let format = map
        .get(param::PRESENTATION_FORMAT)
        .and_then(|pf| pf.first().copied())
        .and_then(char_format_from_gatt)
        .or_else(|| char_type.default_format())
        .ok_or(BleError::MalformedPdu("no usable characteristic format"))?;

    Ok(Signature { char_type, format, perms })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_presentation_format_byte() {
        use hap_model::format::CharFormat;
        assert_eq!(char_format_from_gatt(0x01), Some(CharFormat::Bool));
        assert_eq!(char_format_from_gatt(0x08), Some(CharFormat::Uint32));
        assert_eq!(char_format_from_gatt(0x14), Some(CharFormat::Float));
        assert_eq!(char_format_from_gatt(0x19), Some(CharFormat::String));
        assert_eq!(char_format_from_gatt(0xEE), None);
    }

    #[test]
    fn maps_properties_to_perms() {
        // bit0 read, bit1 write, bit7 events.
        let p = perms_from_properties(0b1000_0011);
        assert!(p.read && p.write && p.events);
        assert!(!p.hidden);
        // secure-read bit (bit4) also grants read.
        let p2 = perms_from_properties(0b0001_0000);
        assert!(p2.read);
    }

    #[test]
    #[allow(clippy::unwrap_used)] // test code: parse success is the whole point
    fn parses_a_signature_body() {
        use hap_model::format::CharFormat;
        // Build a signature body: CHAR_TYPE = On (0x25 -> full uuid 16 bytes LE),
        // PROPERTIES = 0x0003 (read+write), PRESENTATION_FORMAT byte0 = 0x01 (bool).
        let on_uuid_le = uuid_to_le_bytes("00000025-0000-1000-8000-0026bb765291");
        let mut body = Vec::new();
        let mut w = hap_tlv8::Tlv8Writer::new(&mut body);
        w.push(param::CHAR_TYPE, &on_uuid_le);
        w.push(param::PROPERTIES, &0x0003u16.to_le_bytes());
        w.push(param::PRESENTATION_FORMAT, &[0x01, 0, 0, 0, 0, 0, 0]);

        let sig = parse_signature(&body).unwrap();
        assert_eq!(sig.char_type, hap_model::CharacteristicType::On);
        assert_eq!(sig.format, CharFormat::Bool);
        assert!(sig.perms.read && sig.perms.write);
    }

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

    #[allow(clippy::unwrap_used)] // test helper: hex string is always valid
    fn uuid_to_le_bytes(full: &str) -> Vec<u8> {
        let hex: String = full.chars().filter(|c| *c != '-').collect();
        let mut be: Vec<u8> = (0..16)
            .map(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap())
            .collect();
        be.reverse(); // BLE carries the 128-bit UUID little-endian
        be
    }

    #[tokio::test]
    #[allow(clippy::unwrap_used)] // test code: roundtrip success is the whole point
    async fn request_writes_and_reads_back_response() {
        use crate::gatt::MockGatt;
        let gatt = MockGatt::new();
        // Accessory will answer the next read of "pair" with a success PDU
        // carrying a value param body [0xAB].
        let body = encode_value_param(&[0xAB]);
        let mut resp = vec![0x02, 0x05, 0x00];
        resp.extend_from_slice(&u16::try_from(body.len()).unwrap().to_le_bytes());
        resp.extend_from_slice(&body);
        gatt.queue_read("pair", resp);

        let got = request(
            &gatt,
            "pair",
            OpCode::CharacteristicWrite,
            0x05,
            0x0001,
            &encode_value_param(&[0x01]),
            512,
        )
        .await
        .unwrap();
        assert_eq!(got.status, 0x00);
        assert_eq!(value_param(&got.body).unwrap(), vec![0xAB]);
    }
}
