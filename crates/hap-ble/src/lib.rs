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
mod pdu;

pub use error::{BleError, Result};
pub use pdu::{decode_response, encode_request, encode_value_param, fragment, reassemble, value_param, OpCode, Response};
pub use pdu::param;
