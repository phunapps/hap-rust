//! HomeKit Accessory Protocol (HAP) **Bluetooth LE** transport.
//!
//! Discover, pair with, read from, and stream events off a HomeKit accessory
//! over BLE, reusing the pairing crypto from [`hap_crypto`], the TLV8 codec
//! from [`hap_tlv8`], and the attribute model from [`hap_model`].
//!
//! The transport-unified API lives in [`hap_controller`] (feature `ble`);
//! this crate remains usable standalone.
#![forbid(unsafe_code)]

mod accessory;
mod advert;
mod bluest_gatt;
mod broadcast_state;
mod controller;
mod db;
mod discovery;
mod error;
mod gatt;
mod pairing;
mod pdu;
mod scan_gate;
mod session;
mod sleepy;
mod thread;

/// Test-support seam: the in-memory GATT mock and a ready-made accessory
/// fixture. Compiled for this crate's own tests and for consumers that enable
/// the `test-support` feature. **Exempt from semver guarantees.**
#[cfg(any(test, feature = "test-support"))]
pub mod test_support;

pub use accessory::{BleAccessory, CharacteristicEvent};
pub use advert::HapAdvert;
pub use bluest_gatt::BluestConnection;
pub use broadcast_state::BleBroadcastState;
pub use controller::{BleController, Paired};
pub use discovery::{connect_gatt, scan, DiscoveredBleAccessory};
pub use error::{BleError, Result};
pub use gatt::{AdvertSource, GattCharacteristic, GattConnection, GattService, RawAdvert};
pub use sleepy::{BluestSleepyConnector, SleepyConnector};
pub use thread::ThreadDataset;

// Lower-crate types that appear in this crate's public API.
pub use hap_crypto::{AccessoryPairing, BroadcastKey, ControllerKeypair};
pub use hap_model::{
    format::{CharFormat, CharValue},
    tree::{Accessory, Characteristic, Service},
    CharacteristicType, ServiceType,
};
