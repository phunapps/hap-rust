//! HomeKit Accessory Protocol (HAP) **Bluetooth LE** transport.
//!
//! Discover, pair with, read from, and stream events off a HomeKit accessory
//! over BLE, reusing the pairing crypto from [`hap_crypto`], the TLV8 codec
//! from [`hap_tlv8`], and the attribute model from [`hap_model`].
//!
//! This is Milestone A: a standalone transport. Unifying it with the IP
//! [`hap_controller`] under one `HapController` is Milestone B.
#![forbid(unsafe_code)]

mod error;
mod gatt;
mod pdu;
mod session;
mod pairing;
mod db;
mod discovery;
mod accessory;
mod controller;

pub use error::{BleError, Result};
pub use gatt::{BtleplugConnection, GattCharacteristic, GattConnection, GattService};
pub use pdu::{char_format_from_gatt, decode_response, encode_request, encode_value_param, fragment, parse_signature, perms_from_properties, reassemble, request, request_secure, value_param, OpCode, Response, Signature};
pub use pdu::param;
pub use session::BleSession;
pub use pairing::{exchange, pair_setup, pair_verify};
pub use db::{build_db, decode_value};
pub use discovery::{connect_gatt, parse_hap_advert, scan, DiscoveredBleAccessory};
pub use accessory::{BleAccessory, CharacteristicEvent};
pub use controller::BleController;
// Public re-exports of lower-crate types that appear in this crate's API.
pub use hap_crypto::{AccessoryPairing, ControllerKeypair};
pub use hap_model::{
    format::{CharFormat, CharValue},
    tree::{Accessory, Characteristic, Service},
    CharacteristicType, ServiceType,
};
