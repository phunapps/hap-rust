//! HomeKit Accessory Protocol pairing TLV8 type and value constants.
//!
//! Pair Setup (and later Pair Verify) exchange [TLV8](hap_tlv8) messages whose
//! item *types* and a handful of enumerated *values* are fixed by the HAP
//! specification (chapter 5, "Pairing"). This module names them so the message
//! layer reads against the spec rather than against bare hex.
//!
//! These mirror `aiohomekit`'s `TLV` constants exactly; the values are
//! cross-checked against the captured Pair Setup trace under `test-vectors/`.

/// `kTLVType_Method` — the pairing method requested in M1.
pub(crate) const METHOD: u8 = 0x00;
/// `kTLVType_Identifier` — a UTF-8 pairing identifier (controller or accessory).
pub(crate) const IDENTIFIER: u8 = 0x01;
/// `kTLVType_Salt` — the 16-byte SRP salt the accessory sends in M2.
pub(crate) const SALT: u8 = 0x02;
/// `kTLVType_PublicKey` — an SRP public ephemeral (`A`/`B`) or an Ed25519 LTPK.
pub(crate) const PUBLIC_KEY: u8 = 0x03;
/// `kTLVType_Proof` — an SRP proof (`M1` from the controller, `M2` from the
/// accessory).
pub(crate) const PROOF: u8 = 0x04;
/// `kTLVType_EncryptedData` — a ChaCha20-Poly1305 sealed sub-TLV (M5/M6).
pub(crate) const ENCRYPTED_DATA: u8 = 0x05;
/// `kTLVType_State` — the pairing state (`M1`..`M6`).
pub(crate) const STATE: u8 = 0x06;
/// `kTLVType_Error` — an error code returned by the accessory.
pub(crate) const ERROR: u8 = 0x07;
/// `kTLVType_Signature` — an Ed25519 detached signature (M5/M6 sub-TLVs).
pub(crate) const SIGNATURE: u8 = 0x0A;

/// `kTLVMethod_PairSetup` — Pair Setup without MFi/Apple authentication.
pub(crate) const METHOD_PAIR_SETUP: u8 = 0x00;

/// Pair Setup state values, M1 through M6 (`kTLVType_State` payloads).
pub(crate) const STATE_M1: u8 = 1;
/// M2 — accessory's SRP start response (salt + `B`).
pub(crate) const STATE_M2: u8 = 2;
/// M3 — controller's SRP verify request (`A` + proof `M1`).
pub(crate) const STATE_M3: u8 = 3;
/// M4 — accessory's SRP verify response (proof `M2`).
pub(crate) const STATE_M4: u8 = 4;
/// M5 — controller's exchange request (encrypted controller sub-TLV).
pub(crate) const STATE_M5: u8 = 5;
/// M6 — accessory's exchange response (encrypted accessory sub-TLV).
pub(crate) const STATE_M6: u8 = 6;
