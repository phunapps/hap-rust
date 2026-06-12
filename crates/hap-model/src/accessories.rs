//! The `/accessories` response parser.

use crate::error::Result;
use crate::generated::{CharacteristicType, ServiceType};
use crate::tree::{
    Accessory, Characteristic, Service, WireAccessories, WireCharacteristic, WireService,
};

/// Parse the body of a `GET /accessories` response into the typed tree.
///
/// # Errors
/// - [`crate::ModelError::Json`] if the bytes are not the expected JSON shape.
/// - [`crate::ModelError::MalformedUuid`] for an unparseable `type`.
/// - [`crate::ModelError::ValueType`] / [`crate::ModelError::ValueRange`] /
///   [`crate::ModelError::Base64`] if a present `value` does not match its
///   declared `format`.
pub fn parse_accessories(json: &[u8]) -> Result<Vec<Accessory>> {
    let wire: WireAccessories = serde_json::from_slice(json)?;
    wire.accessories
        .into_iter()
        .map(|a| {
            Ok(Accessory {
                aid: a.aid,
                services: a
                    .services
                    .into_iter()
                    .map(convert_service)
                    .collect::<Result<Vec<_>>>()?,
            })
        })
        .collect()
}

fn convert_service(s: WireService) -> Result<Service> {
    Ok(Service {
        iid: s.iid,
        service_type: ServiceType::from_uuid(&s.type_),
        characteristics: s
            .characteristics
            .into_iter()
            .map(convert_characteristic)
            .collect::<Result<Vec<_>>>()?,
    })
}

fn convert_characteristic(c: WireCharacteristic) -> Result<Characteristic> {
    let value = match c.value {
        Some(ref v) => Some(c.format.value_from_json(v)?),
        None => None,
    };
    Ok(Characteristic {
        iid: c.iid,
        char_type: CharacteristicType::from_uuid(&c.type_),
        format: c.format,
        perms: c.perms,
        value,
        unit: c.unit,
        min_value: c.min_value,
        max_value: c.max_value,
        min_step: c.min_step,
        max_len: c.max_len,
    })
}
