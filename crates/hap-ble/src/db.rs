//! Build a typed [`hap_model`] accessory tree from BLE characteristic
//! signatures (BLE has no `/accessories` JSON).

use crate::error::{BleError, Result};
use crate::gatt::GattConnection;
use crate::pdu::{self, OpCode};
use crate::session::BleSession;
use hap_model::format::{CharFormat, CharValue};
use hap_model::tree::{Accessory, Characteristic, Service};
use hap_model::{ServiceType, Uuid};

/// Map a GATT service UUID string to a [`ServiceType`]. `from_uuid` returns
/// `Unknown(uuid)` for non-HAP types. btleplug yields valid 128-bit UUID
/// strings, so the parse-error arm is unreachable in practice.
fn service_type_of(uuid: &str) -> ServiceType {
    match Uuid::parse(uuid) {
        Ok(u) => ServiceType::from_uuid(&u),
        Err(_) => ServiceType::Unknown(
            Uuid::parse("00000000").unwrap_or_else(|_| unreachable!("zero uuid parses")),
        ),
    }
}

/// Issue a Characteristic-Signature-Read for every characteristic in the GATT
/// database and assemble a single [`Accessory`] (aid 1 — BLE accessories are
/// not bridges in this milestone).
///
/// When `encrypted` is true, signature PDUs are sealed/opened through
/// `session`; before Pair Verify they are sent in the clear.
///
/// # Errors
/// Propagates GATT, PDU, and model errors.
pub(crate) async fn build_db<G: GattConnection + ?Sized>(
    gatt: &G,
    session: &mut BleSession,
    frag_size: usize,
    encrypted: bool,
) -> Result<Vec<Accessory>> {
    let gatt_services = gatt.enumerate().await?;
    let mut services = Vec::new();
    let mut tid: u8 = 0;

    for gs in gatt_services {
        let svc_type = service_type_of(&gs.uuid);
        let mut chars = Vec::new();
        for gc in gs.characteristics {
            tid = tid.wrapping_add(1);
            let resp = if encrypted {
                pdu::request_secure(
                    gatt,
                    session,
                    &gc.uuid,
                    OpCode::CharacteristicSignatureRead,
                    tid,
                    gc.iid,
                    &[],
                    frag_size,
                )
                .await?
            } else {
                pdu::request(
                    gatt,
                    &gc.uuid,
                    OpCode::CharacteristicSignatureRead,
                    tid,
                    gc.iid,
                    &[],
                    frag_size,
                )
                .await?
            };
            let sig = pdu::parse_signature(&resp.body)?;
            chars.push(Characteristic {
                iid: u64::from(gc.iid),
                char_type: sig.char_type,
                format: sig.format,
                perms: sig.perms,
                value: None,
                unit: None,
                min_value: None,
                max_value: None,
                min_step: None,
                max_len: None,
            });
        }
        services.push(Service {
            iid: u64::from(gs.iid),
            service_type: svc_type,
            characteristics: chars,
        });
    }

    Ok(vec![Accessory { aid: 1, services }])
}

/// Decode a raw BLE characteristic value to a typed [`CharValue`] per its
/// [`CharFormat`]. Integers and floats are little-endian.
///
/// # Errors
/// Returns [`BleError::MalformedPdu`] if the bytes are too short for the format.
pub(crate) fn decode_value(format: CharFormat, raw: &[u8]) -> Result<CharValue> {
    let need = |n: usize| -> Result<()> {
        if raw.len() < n {
            Err(BleError::MalformedPdu(
                "value shorter than its format width",
            ))
        } else {
            Ok(())
        }
    };
    Ok(match format {
        CharFormat::Bool => {
            need(1)?;
            CharValue::Bool(raw[0] != 0)
        }
        CharFormat::Uint8 => {
            need(1)?;
            CharValue::Uint(u64::from(raw[0]))
        }
        CharFormat::Uint16 => {
            need(2)?;
            CharValue::Uint(u64::from(u16::from_le_bytes([raw[0], raw[1]])))
        }
        CharFormat::Uint32 => {
            need(4)?;
            CharValue::Uint(u64::from(u32::from_le_bytes([
                raw[0], raw[1], raw[2], raw[3],
            ])))
        }
        CharFormat::Uint64 => {
            need(8)?;
            let mut b = [0u8; 8];
            b.copy_from_slice(&raw[..8]);
            CharValue::Uint(u64::from_le_bytes(b))
        }
        CharFormat::Int => {
            need(4)?;
            CharValue::Int(i64::from(i32::from_le_bytes([
                raw[0], raw[1], raw[2], raw[3],
            ])))
        }
        CharFormat::Float => {
            need(4)?;
            CharValue::Float(f64::from(f32::from_le_bytes([
                raw[0], raw[1], raw[2], raw[3],
            ])))
        }
        CharFormat::String => CharValue::Str(String::from_utf8_lossy(raw).into_owned()),
        // CharFormat is #[non_exhaustive]; Tlv8, Data, and any future format
        // we don't model yet are surfaced as opaque bytes rather than a hard error.
        _ => CharValue::Bytes(raw.to_vec()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gatt::{GattCharacteristic, GattService, MockGatt};
    use crate::session::BleSession;
    use hap_crypto::SessionKeys;
    use hap_model::format::CharFormat;

    #[allow(clippy::unwrap_used)]
    fn sig_body() -> Vec<u8> {
        // On characteristic (0x25): read+write, bool.
        let on_le = {
            let hex = "00000025000010008000".to_string() + "0026bb765291";
            let mut b: Vec<u8> = (0..16)
                .map(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap())
                .collect();
            b.reverse();
            b
        };
        let mut body = Vec::new();
        let mut w = hap_tlv8::Tlv8Writer::new(&mut body);
        w.push(crate::pdu::param::CHAR_TYPE, &on_le);
        w.push(crate::pdu::param::PROPERTIES, &0x0003u16.to_le_bytes());
        w.push(
            crate::pdu::param::PRESENTATION_FORMAT,
            &[0x01, 0, 0, 0, 0, 0, 0],
        );
        body
    }

    #[allow(clippy::unwrap_used)]
    #[test]
    fn decodes_values_by_format() {
        use hap_model::format::{CharFormat, CharValue};
        assert_eq!(
            decode_value(CharFormat::Bool, &[0x01]).unwrap(),
            CharValue::Bool(true)
        );
        assert_eq!(
            decode_value(CharFormat::Bool, &[0x00]).unwrap(),
            CharValue::Bool(false)
        );
        assert_eq!(
            decode_value(CharFormat::Uint8, &[0x2A]).unwrap(),
            CharValue::Uint(42)
        );
        assert_eq!(
            decode_value(CharFormat::Uint16, &[0x01, 0x01]).unwrap(),
            CharValue::Uint(257)
        );
        assert_eq!(
            decode_value(CharFormat::Int, &[0xFF, 0xFF, 0xFF, 0xFF]).unwrap(),
            CharValue::Int(-1)
        );
        assert_eq!(
            decode_value(CharFormat::String, b"hi").unwrap(),
            CharValue::Str("hi".into())
        );
        assert_eq!(
            decode_value(CharFormat::Data, &[1, 2, 3]).unwrap(),
            CharValue::Bytes(vec![1, 2, 3])
        );
    }

    #[allow(clippy::unwrap_used)]
    #[test]
    fn float_decodes_le() {
        use hap_model::format::{CharFormat, CharValue};
        let v = decode_value(CharFormat::Float, &1.5f32.to_le_bytes()).unwrap();
        assert_eq!(v, CharValue::Float(1.5));
    }

    #[allow(clippy::unwrap_used)]
    #[tokio::test]
    async fn builds_tree_from_signatures() {
        let svc = GattService {
            uuid: "0000004a-0000-1000-8000-0026bb765291".into(), // a HAP service
            iid: 10,
            characteristics: vec![GattCharacteristic {
                uuid: "00000025-0000-1000-8000-0026bb765291".into(),
                iid: 11,
            }],
        };
        let gatt = MockGatt::new().with_services(vec![svc]);
        // The signature read of the char returns a success PDU wrapping sig_body.
        let body = sig_body();
        let mut resp = vec![0x02, 0x01, 0x00];
        resp.extend_from_slice(&u16::try_from(body.len()).unwrap().to_le_bytes());
        resp.extend_from_slice(&body);
        gatt.queue_read("00000025-0000-1000-8000-0026bb765291", resp);

        let mut session = BleSession::new(SessionKeys {
            read_key: [0; 32],
            write_key: [0; 32],
        });
        let accs = build_db(&gatt, &mut session, 512, /*encrypted=*/ false)
            .await
            .unwrap();
        assert_eq!(accs.len(), 1);
        let ch = &accs[0].services[0].characteristics[0];
        assert_eq!(ch.iid, 11);
        assert_eq!(ch.format, CharFormat::Bool);
        assert!(ch.perms.read && ch.perms.write);
    }
}
