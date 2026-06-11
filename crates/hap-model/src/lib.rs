//! HomeKit Accessory Protocol **attribute database**.
//!
//! This is Milestone 6 (M6) of the `hap-rust` roadmap. It is currently an empty
//! skeleton: the public API lands in the M6 implementation plan.
//!
//! # Scope (M6)
//!
//! - Parses the `/accessories` JSON into a typed
//!   `Accessory → Service → Characteristic` tree.
//! - Reads and writes characteristics via `/characteristics`.
//! - Models characteristic formats (`bool`, `uint8/16/32/64`, `int`, `float`,
//!   `string`, `tlv8`, `data`), permissions, units, and value constraints.
//! - The HAP-defined service and characteristic **type tables** (UUIDs, names,
//!   metadata) are **code-generated** in `xtask` from a captured metadata
//!   source, the same approach matter-rust used for clusters.
//!
//! Depends on [`hap_tlv8`] (for the `tlv8` characteristic format) plus a JSON
//! layer (`serde` / `serde_json`); otherwise standalone.

#![forbid(unsafe_code)]
