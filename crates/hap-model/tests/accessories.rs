//! `parse_accessories` against literal JSON and the captured vector.

// Test-code carve-out: unwrap/expect allowed with this documented justification.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use hap_model::{
    parse_accessories, CharFormat, CharValue, CharacteristicType, ModelError, ServiceType,
};
use std::path::PathBuf;

#[test]
fn parses_minimal_single_characteristic() {
    let body = br#"{"accessories":[{"aid":1,"services":[
        {"iid":1,"type":"3E","characteristics":[
            {"iid":2,"type":"23","format":"string","perms":["pr"],"value":"Lamp"}
        ]}
    ]}]}"#;
    let acc = parse_accessories(body).unwrap();
    assert_eq!(acc.len(), 1);
    assert_eq!(acc[0].aid, 1);
    let svc = &acc[0].services[0];
    assert_eq!(svc.iid, 1);
    assert_eq!(svc.service_type, ServiceType::AccessoryInformation);
    let ch = &svc.characteristics[0];
    assert_eq!(ch.char_type, CharacteristicType::Name);
    assert_eq!(ch.format, CharFormat::String);
    assert!(ch.perms.read && !ch.perms.write);
    assert_eq!(ch.value, Some(CharValue::Str("Lamp".to_string())));
}

#[test]
fn decodes_on_characteristic_and_constraints() {
    let body = br#"{"accessories":[{"aid":1,"services":[
        {"iid":7,"type":"43","characteristics":[
            {"iid":8,"type":"25","format":"bool","perms":["pr","pw","ev"],"value":true},
            {"iid":9,"type":"8","format":"int","perms":["pr","pw","ev"],
             "value":50,"unit":"percentage","minValue":0,"maxValue":100,"minStep":1}
        ]}
    ]}]}"#;
    let acc = parse_accessories(body).unwrap();
    let svc = &acc[0].services[0];
    assert_eq!(svc.service_type, ServiceType::LightBulb);
    let on = &svc.characteristics[0];
    assert_eq!(on.char_type, CharacteristicType::On);
    assert_eq!(on.value, Some(CharValue::Bool(true)));
    let bright = &svc.characteristics[1];
    assert_eq!(bright.char_type, CharacteristicType::Brightness);
    assert_eq!(bright.value, Some(CharValue::Int(50)));
    assert_eq!(bright.unit.as_deref(), Some("percentage"));
    assert_eq!(bright.max_value, Some(100.0));
    assert_eq!(bright.min_step, Some(1.0));
}

#[test]
fn vendor_uuid_becomes_unknown() {
    let body = br#"{"accessories":[{"aid":1,"services":[
        {"iid":1,"type":"00112233-4455-6677-8899-aabbccddeeff","characteristics":[]}
    ]}]}"#;
    let acc = parse_accessories(body).unwrap();
    assert!(matches!(
        acc[0].services[0].service_type,
        ServiceType::Unknown(_)
    ));
}

#[test]
fn value_violating_format_is_rejected() {
    // uint8 with value 999 must error.
    let body = br#"{"accessories":[{"aid":1,"services":[
        {"iid":1,"type":"43","characteristics":[
            {"iid":2,"type":"6A","format":"uint8","perms":["pr"],"value":999}
        ]}
    ]}]}"#;
    assert!(matches!(
        parse_accessories(body),
        Err(ModelError::ValueRange { .. })
    ));
}

#[test]
fn captured_lightbulb_vector_parses() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("test-vectors/accessories/lightbulb.json");
    let body = std::fs::read(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    let acc = parse_accessories(&body).unwrap();
    assert_eq!(acc[0].aid, 1);
    // The bulb's On characteristic exists and is readable+writable+eventable.
    let on = acc[0]
        .services
        .iter()
        .flat_map(|s| &s.characteristics)
        .find(|c| c.char_type == CharacteristicType::On)
        .expect("On characteristic present");
    assert!(on.perms.read && on.perms.write && on.perms.events);
}
