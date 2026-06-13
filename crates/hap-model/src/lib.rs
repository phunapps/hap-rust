//! HomeKit accessory attribute database — Milestone 6 of `hap-rust`.
//!
//! `hap-model` is transport-agnostic. It parses the `/accessories` JSON into
//! a typed [`Accessory`] → [`Service`] → [`Characteristic`] tree and builds /
//! parses the `/characteristics` request and response bodies. It never touches
//! the network: the controller (`hap-controller`, M7) executes the requests
//! this crate produces over a secure session.
//!
//! # Example
//!
//! ```
//! use hap_model::parse_accessories;
//!
//! let body = br#"{"accessories":[{"aid":1,"services":[
//!     {"iid":1,"type":"3E","characteristics":[
//!         {"iid":2,"type":"23","format":"string","perms":["pr"],"value":"Lamp"}
//!     ]}
//! ]}]}"#;
//! let accessories = parse_accessories(body).unwrap();
//! assert_eq!(accessories[0].aid, 1);
//! ```
//!
//! The doc-test uses `unwrap()`; real library code must propagate the
//! [`Result`] instead.

#![forbid(unsafe_code)]

pub mod database;
pub mod error;
pub mod format;
pub mod perms;
pub mod status;
pub mod tree;
pub mod unit;
pub mod uuid;

mod accessories;
mod characteristics;
mod generated;

pub use accessories::parse_accessories;
pub use characteristics::{
    build_prepare_request, build_read_request, build_subscribe_request, build_timed_write_request,
    build_write_request, build_write_request_with_response, parse_read_response, CharRead,
};
pub use database::{AccessoryDatabase, Request, RequestExecutor};
pub use error::{ModelError, Result};
pub use format::{CharFormat, CharValue};
pub use generated::{CharacteristicType, ServiceType};
pub use perms::Perms;
pub use status::HapStatus;
pub use tree::{Accessory, Characteristic, Service};
pub use unit::Unit;
pub use uuid::Uuid;
