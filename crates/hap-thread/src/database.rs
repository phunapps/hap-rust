//! Decode the raw `0x09` accessory-database response into a typed
//! [`hap_model`] tree.
//!
//! HAP-over-Thread returns the whole attribute database in one `ReadDatabase`
//! (`0x09`) response, whose body is a **nested HAP TLV8** structure. This module
//! walks it into `hap_model::tree::Accessory` values. The grammar (TLV type →
//! meaning), mirroring aiohomekit's `Pdu09*` structs:
//!
//! ```text
//! 0x18  Accessories        list of 0x19
//!   0x19  Accessory          one accessory
//!     0x1A  aid (u16)
//!     0x16  Services          list of 0x15
//!       0x15  Service           one service
//!         0x06  type (u128 LE)
//!         0x07  iid (u16)
//!         0x14  Characteristics  list of 0x13
//!           0x13  Characteristic  one characteristic
//!             0x04  type (u128 LE)
//!             0x05  iid (u16)
//!             0x0A  properties (u16)  → perms
//!             0x0C  presentation fmt  → format + unit
//!         0x0F  service properties
//!         0x10  linked services
//! ```
//!
//! List items are separated by a zero-type TLV; long values fragment across
//! consecutive same-type items ([`hap_tlv8`] reassembles both). Cross-verified
//! against aiohomekit's `Pdu09Database` on a captured real Onvis SMS2 body
//! (`test-vectors/thread-coap/onvis-sms2-0x09.bin`).

use hap_model::{
    Accessory, CharFormat, Characteristic, CharacteristicType, Perms, Service, ServiceType, Uuid,
};
use hap_tlv8::Tlv8Map;

use crate::error::{Result, ThreadError};

/// TLV type numbers of the `0x09` database grammar.
mod ty {
    pub(super) const ACCESSORIES: u8 = 0x18;
    pub(super) const ACCESSORY: u8 = 0x19;
    pub(super) const ACC_IID: u8 = 0x1A;
    pub(super) const SERVICES: u8 = 0x16;
    pub(super) const SERVICE: u8 = 0x15;
    pub(super) const SVC_TYPE: u8 = 0x06;
    pub(super) const SVC_IID: u8 = 0x07;
    pub(super) const CHARS: u8 = 0x14;
    pub(super) const CHAR: u8 = 0x13;
    pub(super) const CHR_TYPE: u8 = 0x04;
    pub(super) const CHR_IID: u8 = 0x05;
    pub(super) const CHR_PROPS: u8 = 0x0A;
    pub(super) const PRES_FMT: u8 = 0x0C;
}

/// Decode a raw `0x09` database body into its typed accessory tree.
///
/// # Errors
/// [`ThreadError::Tlv8`] if the TLV structure is malformed; [`ThreadError::Model`]
/// if a `type` UUID cannot be formed.
pub fn decode_database(raw: &[u8]) -> Result<Vec<Accessory>> {
    let map = Tlv8Map::parse(raw)?;
    let accessories = map.get(ty::ACCESSORIES).unwrap_or(&[]);
    list_items(accessories, ty::ACCESSORY)?
        .iter()
        .map(|bytes| decode_accessory(bytes))
        .collect()
}

fn decode_accessory(bytes: &[u8]) -> Result<Accessory> {
    let map = Tlv8Map::parse(bytes)?;
    let aid = u64::from(map.get_u16(ty::ACC_IID)?.unwrap_or(0));
    let services_value = map.get(ty::SERVICES).unwrap_or(&[]);
    let services = list_items(services_value, ty::SERVICE)?
        .iter()
        .map(|b| decode_service(b))
        .collect::<Result<Vec<_>>>()?;
    Ok(Accessory { aid, services })
}

fn decode_service(bytes: &[u8]) -> Result<Service> {
    let map = Tlv8Map::parse(bytes)?;
    let iid = u64::from(map.get_u16(ty::SVC_IID)?.unwrap_or(0));
    let service_type = ServiceType::from_uuid(&type_uuid(map.get(ty::SVC_TYPE).unwrap_or(&[]))?);
    let chars_value = map.get(ty::CHARS).unwrap_or(&[]);
    let characteristics = list_items(chars_value, ty::CHAR)?
        .iter()
        .map(|b| decode_characteristic(b))
        .collect::<Result<Vec<_>>>()?;
    Ok(Service {
        iid,
        service_type,
        characteristics,
    })
}

fn decode_characteristic(bytes: &[u8]) -> Result<Characteristic> {
    let map = Tlv8Map::parse(bytes)?;
    let iid = u64::from(map.get_u16(ty::CHR_IID)?.unwrap_or(0));
    let char_type =
        CharacteristicType::from_uuid(&type_uuid(map.get(ty::CHR_TYPE).unwrap_or(&[]))?);
    let properties = map.get_u16(ty::CHR_PROPS)?.unwrap_or(0);
    let (format, unit) = format_and_unit(map.get(ty::PRES_FMT));
    Ok(Characteristic {
        iid,
        char_type,
        format,
        perms: perms_from(properties),
        // The 0x09 database carries structure, not values.
        value: None,
        unit,
        min_value: None,
        max_value: None,
        min_step: None,
        max_len: None,
    })
}

/// Collect every item of `item_type` from a container value (each already
/// fragmentation-reassembled), skipping the zero-type list separators.
fn list_items(value: &[u8], item_type: u8) -> Result<Vec<Vec<u8>>> {
    let map = Tlv8Map::parse(value)?;
    Ok(map
        .items()
        .iter()
        .filter(|(t, _)| *t == item_type)
        .map(|(_, v)| v.clone())
        .collect())
}

/// Turn a `0x09` `type` field (a little-endian `u128`) into a [`Uuid`]. A HAP
/// short type (high 12 bytes zero) becomes the HAP-base UUID; anything else is
/// treated as a full 128-bit UUID (its bytes are little-endian on the wire).
fn type_uuid(bytes: &[u8]) -> Result<Uuid> {
    let mut le = [0u8; 16];
    let n = bytes.len().min(16);
    le[..n].copy_from_slice(&bytes[..n]);

    let s = if le[4..].iter().all(|&b| b == 0) {
        format!("{:x}", u32::from_le_bytes([le[0], le[1], le[2], le[3]]))
    } else {
        let mut be = le;
        be.reverse();
        format!(
            "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            be[0], be[1], be[2], be[3], be[4], be[5], be[6], be[7], be[8], be[9], be[10], be[11],
            be[12], be[13], be[14], be[15],
        )
    };
    Uuid::parse(&s).map_err(|e| ThreadError::Model(e.to_string()))
}

/// Map the HAP characteristic properties bitfield to [`Perms`].
fn perms_from(p: u16) -> Perms {
    Perms {
        read: p & (0x0001 | 0x0010) != 0,   // paired or secure read
        write: p & (0x0002 | 0x0020) != 0,  // paired or secure write
        events: p & (0x0080 | 0x0100) != 0, // connected or disconnected events
        additional_authorization: p & 0x0004 != 0,
        timed_write: p & 0x0008 != 0,
        hidden: p & 0x0040 != 0,
        write_response: false,
    }
}

/// Decode a GATT presentation-format descriptor into a [`CharFormat`] and an
/// optional unit string (matching aiohomekit's `data_type_str`/`data_unit_str`).
fn format_and_unit(pf: Option<&[u8]>) -> (CharFormat, Option<String>) {
    let Some(pf) = pf else {
        return (CharFormat::Data, None);
    };
    let format = match pf.first().copied() {
        Some(0x01) => CharFormat::Bool,
        Some(0x04) => CharFormat::Uint8,
        Some(0x06) => CharFormat::Uint16,
        Some(0x08) => CharFormat::Uint32,
        Some(0x0A) => CharFormat::Uint64,
        Some(0x10) => CharFormat::Int,
        Some(0x14) => CharFormat::Float,
        Some(0x19) => CharFormat::String,
        _ => CharFormat::Data,
    };
    let unit = pf
        .get(2..4)
        .map(|u| u16::from_le_bytes([u[0], u[1]]))
        .and_then(|code| match code {
            0x272F => Some("celsius"),
            0x27AD => Some("percentage"),
            0x2700 => Some("unitless"),
            0x2731 => Some("lux"),
            0x2703 => Some("seconds"),
            0x2763 => Some("arcdegrees"),
            _ => None,
        })
        .map(String::from);
    (format, unit)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn onvis_0x09() -> Option<Vec<u8>> {
        let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../test-vectors/thread-coap/onvis-sms2-0x09.bin");
        std::fs::read(p).ok()
    }

    #[test]
    fn type_uuid_short_and_custom() {
        // MotionDetected short type 0x22 → HAP-base UUID.
        let mut le = [0u8; 16];
        le[0] = 0x22;
        assert_eq!(
            type_uuid(&le).unwrap().as_full(),
            "00000022-0000-1000-8000-0026bb765291"
        );
        assert_eq!(
            CharacteristicType::from_uuid(&type_uuid(&le).unwrap()),
            CharacteristicType::MotionDetected
        );
    }

    #[test]
    fn decodes_the_real_onvis_database() {
        let Some(raw) = onvis_0x09() else {
            eprintln!("skipping: no onvis-sms2-0x09.bin");
            return;
        };
        let accs = decode_database(&raw).expect("0x09 must decode");
        assert_eq!(accs.len(), 1, "one accessory");
        let acc = &accs[0];
        assert_eq!(acc.aid, 1);

        // Every characteristic, flattened, matched against the aiohomekit decode.
        let chars: Vec<(u64, &CharacteristicType)> = acc
            .services
            .iter()
            .flat_map(|s| s.characteristics.iter().map(|c| (c.iid, &c.char_type)))
            .collect();

        // The well-known SMS2 characteristics (iid + type), from aiohomekit.
        let find = |iid: u64| chars.iter().find(|(i, _)| *i == iid).map(|(_, t)| *t);
        assert_eq!(find(3074), Some(&CharacteristicType::MotionDetected));
        assert_eq!(find(2723), Some(&CharacteristicType::CurrentTemperature));
        assert_eq!(
            find(2643),
            Some(&CharacteristicType::CurrentRelativeHumidity)
        );
        assert_eq!(find(225), Some(&CharacteristicType::BatteryLevel));
        assert_eq!(find(227), Some(&CharacteristicType::StatusLowBattery));

        // The MotionSensor service is present and MotionDetected is event-capable.
        let motion_svc = acc
            .services
            .iter()
            .find(|s| s.service_type == ServiceType::MotionSensor)
            .expect("MotionSensor service");
        let motion = motion_svc
            .characteristics
            .iter()
            .find(|c| c.char_type == CharacteristicType::MotionDetected)
            .expect("MotionDetected char");
        assert!(motion.perms.events, "MotionDetected supports events");
        assert!(motion.perms.read, "MotionDetected is readable");
    }
}
