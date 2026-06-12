//! Catalog breadth + value-semantics spot checks for the generated types.
#![allow(clippy::unwrap_used, clippy::expect_used)]
use hap_model::{CharFormat, CharacteristicType, ServiceType, Unit, Uuid};

#[test]
fn catalog_has_expected_breadth() {
    for short in ["43", "47", "49", "45", "4A", "41", "8A", "80"] {
        let u = Uuid::parse(short).unwrap();
        assert!(
            !matches!(ServiceType::from_uuid(&u), ServiceType::Unknown(_)),
            "service short {short} should be named"
        );
    }
    for short in ["25", "1E", "33", "11", "6A", "68"] {
        let u = Uuid::parse(short).unwrap();
        assert!(
            !matches!(
                CharacteristicType::from_uuid(&u),
                CharacteristicType::Unknown(_)
            ),
            "characteristic short {short} should be named"
        );
    }
}

#[test]
fn value_semantics_are_populated() {
    assert_eq!(
        CharacteristicType::On.default_format(),
        Some(CharFormat::Bool)
    );
    assert_eq!(
        CharacteristicType::CurrentTemperature.unit(),
        Some(Unit::Celsius)
    );
    assert_eq!(
        CharacteristicType::LockTargetState.valid_values(),
        Some(&[(0_i64, "Unsecured"), (1, "Secured")][..])
    );
    assert_eq!(
        CharacteristicType::TargetHeatingCoolingState.valid_values(),
        Some(&[(0_i64, "Off"), (1, "Heat"), (2, "Cool"), (3, "Auto")][..])
    );
}
