//! Shared HAP constants and crypto helpers for the accessory side.
//!
//! These mirror the values `hap-crypto` uses on the controller side so the two
//! agree byte-for-byte: TLV8 type numbers, the HKDF salt/info strings, and the
//! nonce construction. Primitives come from vetted crates (`hkdf`/`sha2`); this
//! module only wires them into the HAP protocol shapes.

use hkdf::Hkdf;
use sha2::Sha512;

use crate::error::{DutError, Result};

/// HAP pairing TLV8 type numbers (HAP spec, chapter 5).
pub(crate) mod tlv {
    pub(crate) const IDENTIFIER: u8 = 0x01;
    pub(crate) const PUBLIC_KEY: u8 = 0x03;
    pub(crate) const ENCRYPTED_DATA: u8 = 0x05;
    pub(crate) const STATE: u8 = 0x06;
    pub(crate) const ERROR: u8 = 0x07;
    pub(crate) const SIGNATURE: u8 = 0x0A;

    pub(crate) const STATE_M1: u8 = 1;
    pub(crate) const STATE_M2: u8 = 2;
    pub(crate) const STATE_M3: u8 = 3;
    pub(crate) const STATE_M4: u8 = 4;

    /// `kTLVError_Authentication` (2) — signature/decrypt failure.
    pub(crate) const ERROR_AUTHENTICATION: u8 = 0x02;
}

/// HKDF salt/info strings (HAP, chapter 5), identical to `hap-crypto`.
pub(crate) const PV_ENCRYPT_SALT: &[u8] = b"Pair-Verify-Encrypt-Salt";
pub(crate) const PV_ENCRYPT_INFO: &[u8] = b"Pair-Verify-Encrypt-Info";
pub(crate) const CONTROL_SALT: &[u8] = b"Control-Salt";
pub(crate) const CONTROL_READ_INFO: &[u8] = b"Control-Read-Encryption-Key";
pub(crate) const CONTROL_WRITE_INFO: &[u8] = b"Control-Write-Encryption-Key";
pub(crate) const EVENT_SALT: &[u8] = b"Event-Salt";
pub(crate) const EVENT_READ_INFO: &[u8] = b"Event-Read-Encryption-Key";

/// Pair-Verify sub-TLV encryption nonce labels.
pub(crate) const NONCE_PV_M2: &[u8] = b"PV-Msg02";
pub(crate) const NONCE_PV_M3: &[u8] = b"PV-Msg03";

/// A 96-bit nonce with an 8-byte ASCII `label` in the counter region (4 zero
/// pad bytes then the label) — matches `hap_crypto`'s `hap_nonce`.
pub(crate) fn nonce_label(label: &[u8]) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    let n = label.len().min(8);
    nonce[4..4 + n].copy_from_slice(&label[..n]);
    nonce
}

/// A 96-bit session nonce: four zero bytes then the little-endian 64-bit
/// `counter` — matches `hap-thread`'s CoAP session nonce.
pub(crate) fn nonce_counter(counter: u64) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[4..].copy_from_slice(&counter.to_le_bytes());
    nonce
}

/// Derive a 32-byte key with HKDF-SHA512 (RFC 5869).
///
/// # Errors
/// [`DutError::Protocol`] if HKDF expansion fails (unreachable for a 32-byte
/// output).
pub(crate) fn hkdf32(ikm: &[u8], salt: &[u8], info: &[u8]) -> Result<[u8; 32]> {
    let hk = Hkdf::<Sha512>::new(Some(salt), ikm);
    let mut out = [0u8; 32];
    hk.expand(info, &mut out)
        .map_err(|_| DutError::Protocol("HKDF expand failed"))?;
    Ok(out)
}
