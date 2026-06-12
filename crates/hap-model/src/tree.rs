//! The typed accessory attribute tree: [`Accessory`] → [`Service`] →
//! [`Characteristic`].

use crate::format::{CharFormat, CharValue};
use crate::generated::{CharacteristicType, ServiceType};
use crate::perms::Perms;
use serde::Deserialize;

/// One accessory in the bridge/accessory database.
#[derive(Debug, Clone, PartialEq)]
pub struct Accessory {
    /// Accessory instance id (unique within the response).
    pub aid: u64,
    /// The accessory's services.
    pub services: Vec<Service>,
}

/// One service on an accessory.
#[derive(Debug, Clone, PartialEq)]
pub struct Service {
    /// Service instance id (unique within the accessory).
    pub iid: u64,
    /// The HAP service type (decoded from the short `type` UUID).
    pub service_type: ServiceType,
    /// The service's characteristics.
    pub characteristics: Vec<Characteristic>,
}

/// One characteristic on a service.
#[derive(Debug, Clone, PartialEq)]
pub struct Characteristic {
    /// Characteristic instance id (unique within the accessory).
    pub iid: u64,
    /// The HAP characteristic type (decoded from the short `type` UUID).
    pub char_type: CharacteristicType,
    /// The value format.
    pub format: CharFormat,
    /// Permissions.
    pub perms: Perms,
    /// The current value, if the accessory included one and it decoded under
    /// `format`. `None` if absent.
    pub value: Option<CharValue>,
    /// Optional unit string (e.g. `"percentage"`, `"celsius"`).
    pub unit: Option<String>,
    /// Optional minimum value constraint.
    pub min_value: Option<f64>,
    /// Optional maximum value constraint.
    pub max_value: Option<f64>,
    /// Optional step constraint.
    pub min_step: Option<f64>,
    /// Optional maximum length (for string/data formats).
    pub max_len: Option<u64>,
}

// ---- wire structs (private; mirror the JSON exactly) ----

#[derive(Debug, Deserialize)]
pub(crate) struct WireAccessories {
    pub accessories: Vec<WireAccessory>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct WireAccessory {
    pub aid: u64,
    pub services: Vec<WireService>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct WireService {
    pub iid: u64,
    #[serde(rename = "type")]
    pub type_: crate::uuid::Uuid,
    pub characteristics: Vec<WireCharacteristic>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct WireCharacteristic {
    pub iid: u64,
    #[serde(rename = "type")]
    pub type_: crate::uuid::Uuid,
    pub format: CharFormat,
    pub perms: Perms,
    #[serde(default)]
    pub value: Option<serde_json::Value>,
    #[serde(default)]
    pub unit: Option<String>,
    #[serde(default, rename = "minValue")]
    pub min_value: Option<f64>,
    #[serde(default, rename = "maxValue")]
    pub max_value: Option<f64>,
    #[serde(default, rename = "minStep")]
    pub min_step: Option<f64>,
    #[serde(default, rename = "maxLen")]
    pub max_len: Option<u64>,
}
