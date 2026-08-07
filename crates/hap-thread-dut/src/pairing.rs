//! The accessory side of HAP Pair Verify (M1–M4).
//!
//! The mirror of `hap_crypto::PairVerifyClient`: on M1 the accessory generates
//! an ephemeral X25519 key, signs `accessoryEph ‖ accessoryID ‖ controllerEph`
//! with its long-term Ed25519 key, and returns M2; on M3 it verifies the
//! controller's signature against the paired controller's LTPK and derives the
//! session keys. Byte layout, nonces, and HKDF salts all match the client.

use hap_crypto::aead::{chacha20poly1305_open, chacha20poly1305_seal};
use hap_crypto::{verify_ed25519, ControllerKeypair, EphemeralKeypair};
use hap_tlv8::{Tlv8Map, Tlv8Writer};

use crate::error::{DutError, Result};
use crate::hap::{self, tlv};
use crate::session::AccessorySession;

/// State carried between M1 and M3 of a Pair Verify exchange.
pub(crate) struct VerifyInProgress {
    accessory_eph_pub: [u8; 32],
    controller_eph_pub: [u8; 32],
    shared: [u8; 32],
    pv_key: [u8; 32],
}

/// Handle M1 (`State=1`, controller ephemeral `PublicKey`) and produce M2
/// (`State=2`, accessory ephemeral `PublicKey`, encrypted `{ Identifier,
/// Signature }`), plus the in-progress state for M3.
///
/// # Errors
/// [`DutError::Protocol`] / [`DutError::Tlv8`] if M1 is malformed;
/// [`DutError::Crypto`] on a crypto failure.
pub(crate) fn handle_m1(
    accessory_keypair: &ControllerKeypair,
    accessory_id: &str,
    m1: &[u8],
) -> Result<(Vec<u8>, VerifyInProgress)> {
    let map = Tlv8Map::parse(m1)?;
    expect_state(&map, tlv::STATE_M1)?;
    let controller_eph_pub: [u8; 32] = map
        .get(tlv::PUBLIC_KEY)
        .ok_or(DutError::Protocol("M1 missing controller ephemeral key"))?
        .try_into()
        .map_err(|_| DutError::Protocol("M1 ephemeral key not 32 bytes"))?;

    let accessory_eph = EphemeralKeypair::generate();
    let accessory_eph_pub = accessory_eph.public();
    let shared = accessory_eph.diffie_hellman(&controller_eph_pub);
    let pv_key = hap::hkdf32(&shared, hap::PV_ENCRYPT_SALT, hap::PV_ENCRYPT_INFO)?;

    // Sign accessoryEph ‖ accessoryID ‖ controllerEph.
    let id = accessory_id.as_bytes();
    let mut signed = Vec::with_capacity(32 + id.len() + 32);
    signed.extend_from_slice(&accessory_eph_pub);
    signed.extend_from_slice(id);
    signed.extend_from_slice(&controller_eph_pub);
    let signature = accessory_keypair.sign(&signed);

    // Encrypt the { Identifier, Signature } sub-TLV under pv_key / PV-Msg02.
    let mut sub = Vec::new();
    let mut sw = Tlv8Writer::new(&mut sub);
    sw.push(tlv::IDENTIFIER, id);
    sw.push(tlv::SIGNATURE, &signature);
    let sealed = chacha20poly1305_seal(&pv_key, &hap::nonce_label(hap::NONCE_PV_M2), &[], &sub)?;

    let mut m2 = Vec::new();
    let mut w = Tlv8Writer::new(&mut m2);
    w.push_u8(tlv::STATE, tlv::STATE_M2);
    w.push(tlv::PUBLIC_KEY, &accessory_eph_pub);
    w.push(tlv::ENCRYPTED_DATA, &sealed);

    Ok((
        m2,
        VerifyInProgress {
            accessory_eph_pub,
            controller_eph_pub,
            shared,
            pv_key,
        },
    ))
}

/// Handle M3 (`State=3`, encrypted `{ Identifier, Signature }`): decrypt, verify
/// the controller's signature against `controller_ltpk`, and produce M4
/// (`State=4`) plus the established [`AccessorySession`].
///
/// On a verification failure it returns `Ok` with an M4 carrying an
/// authentication error TLV and `None` session (so the caller still replies),
/// rather than an `Err`.
///
/// # Errors
/// [`DutError`] if M3 is structurally malformed or a crypto op fails
/// unexpectedly (a *signature* mismatch is reported in-band, not as an `Err`).
pub(crate) fn handle_m3(
    progress: &VerifyInProgress,
    controller_id: &str,
    controller_ltpk: &[u8; 32],
    m3: &[u8],
) -> Result<(Vec<u8>, Option<AccessorySession>)> {
    let map = Tlv8Map::parse(m3)?;
    expect_state(&map, tlv::STATE_M3)?;
    let encrypted = map
        .get(tlv::ENCRYPTED_DATA)
        .ok_or(DutError::Protocol("M3 missing encrypted data"))?;

    let Ok(plaintext) = chacha20poly1305_open(
        &progress.pv_key,
        &hap::nonce_label(hap::NONCE_PV_M3),
        &[],
        encrypted,
    ) else {
        return Ok((error_m4(), None));
    };
    let sub = Tlv8Map::parse(&plaintext)?;
    let identifier = sub
        .get(tlv::IDENTIFIER)
        .ok_or(DutError::Protocol("M3 sub-TLV missing identifier"))?;
    let signature: [u8; 64] = match sub.get(tlv::SIGNATURE).and_then(|s| s.try_into().ok()) {
        Some(s) => s,
        None => return Ok((error_m4(), None)),
    };

    // The controller id must be the paired one; verify its signature over
    // controllerEph ‖ controllerID ‖ accessoryEph.
    let mut signed = Vec::with_capacity(32 + identifier.len() + 32);
    signed.extend_from_slice(&progress.controller_eph_pub);
    signed.extend_from_slice(identifier);
    signed.extend_from_slice(&progress.accessory_eph_pub);
    if identifier != controller_id.as_bytes()
        || verify_ed25519(controller_ltpk, &signed, &signature).is_err()
    {
        return Ok((error_m4(), None));
    }

    let read_key = hap::hkdf32(&progress.shared, hap::CONTROL_SALT, hap::CONTROL_READ_INFO)?;
    let write_key = hap::hkdf32(&progress.shared, hap::CONTROL_SALT, hap::CONTROL_WRITE_INFO)?;
    let event_key = hap::hkdf32(&progress.shared, hap::EVENT_SALT, hap::EVENT_READ_INFO)?;

    let mut m4 = Vec::new();
    let mut w = Tlv8Writer::new(&mut m4);
    w.push_u8(tlv::STATE, tlv::STATE_M4);
    Ok((
        m4,
        Some(AccessorySession::new(read_key, write_key, event_key)),
    ))
}

/// An M4 carrying an authentication error.
fn error_m4() -> Vec<u8> {
    let mut out = Vec::new();
    let mut w = Tlv8Writer::new(&mut out);
    w.push_u8(tlv::STATE, tlv::STATE_M4);
    w.push_u8(tlv::ERROR, tlv::ERROR_AUTHENTICATION);
    out
}

fn expect_state(map: &Tlv8Map, want: u8) -> Result<()> {
    match map.get_u8(tlv::STATE)? {
        Some(s) if s == want => Ok(()),
        _ => Err(DutError::Protocol("unexpected pairing State")),
    }
}
