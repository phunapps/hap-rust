//! HomeKit Accessory Protocol (HAP) **Bluetooth LE** transport.
//!
//! Discover, pair with, read from, and stream events off a HomeKit accessory
//! over BLE, reusing the pairing crypto from [`hap_crypto`], the TLV8 codec
//! from [`hap_tlv8`], and the attribute model from [`hap_model`].
//!
//! This is Milestone A: a standalone transport. Unifying it with the IP
//! `hap_controller` under one `HapController` is Milestone B.
#![forbid(unsafe_code)]

mod accessory;
mod bluest_gatt;
mod controller;
mod db;
mod discovery;
mod error;
mod gatt;
mod pairing;
mod pdu;
mod session;

pub use accessory::{BleAccessory, CharacteristicEvent};
pub use bluest_gatt::BluestConnection;
pub use controller::BleController;
pub use discovery::{connect_gatt, scan, DiscoveredBleAccessory};
pub use error::{BleError, Result};
pub use gatt::{GattCharacteristic, GattConnection, GattService};

// Lower-crate types that appear in this crate's public API.
pub use hap_crypto::{AccessoryPairing, ControllerKeypair};
pub use hap_model::{
    format::{CharFormat, CharValue},
    tree::{Accessory, Characteristic, Service},
    CharacteristicType, ServiceType,
};
