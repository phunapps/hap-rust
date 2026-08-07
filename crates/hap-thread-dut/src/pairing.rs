//! The accessory side of HAP Pair Setup (M1–M6) and Pair Verify (M1–M4).
//!
//! **Pair Verify** mirrors `hap_crypto::PairVerifyClient`: on M1 the accessory
//! generates an ephemeral X25519 key, signs `accessoryEph ‖ accessoryID ‖
//! controllerEph` with its long-term Ed25519 key, and returns M2; on M3 it
//! verifies the controller's signature against the paired controller's LTPK and
//! derives the session keys.
//!
//! **Pair Setup** mirrors `hap_crypto::PairSetupClient`: the SRP-6a exchange of
//! M1–M4 (via [`HapPairSetupSrpServer`]) authenticates the shared setup code,
//! then M5/M6 exchange and verify long-term keys — the accessory learns the
//! controller's LTPK (stored as the pairing) and returns its own. Byte layout,
//! nonces, and HKDF salts all match the client.

use hap_crypto::aead::{chacha20poly1305_open, chacha20poly1305_seal};
use hap_crypto::{verify_ed25519, ControllerKeypair, EphemeralKeypair, HapPairSetupSrpServer};
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

// ---- Pair Setup (M1–M6), the accessory side of `hap_crypto::PairSetupClient` ----

/// A controller pairing learned in M5: its pairing id and long-term public key.
pub(crate) type ControllerPairing = (String, [u8; 32]);

/// State carried between the messages of a Pair Setup exchange.
pub(crate) enum SetupInProgress {
    /// After M2: the SRP server (verifier + `B`), awaiting the controller's M3
    /// (`A` + proof `M1`).
    AwaitingM3 { server: HapPairSetupSrpServer },
    /// After M4: the SRP session key `K`, awaiting the controller's M5 (its
    /// encrypted long-term key + signature).
    AwaitingM5 { session_key: Vec<u8> },
}

/// Handle Pair Setup M1 (`State=1, Method=PairSetup`) and produce M2
/// (`State=2, Salt=s, PublicKey=B`) plus the in-progress state for M3.
///
/// # Errors
/// [`DutError::Protocol`] / [`DutError::Tlv8`] if M1 is malformed or requests an
/// unsupported method; [`DutError::Crypto`] if the SRP server cannot be built.
pub(crate) fn handle_setup_m1(setup_code: &str, m1: &[u8]) -> Result<(Vec<u8>, SetupInProgress)> {
    let map = Tlv8Map::parse(m1)?;
    expect_state(&map, tlv::STATE_M1)?;
    // Only Pair Setup (Method=0) is supported. A missing Method is tolerated
    // (some controllers omit it); any other value is rejected.
    match map.get_u8(tlv::METHOD)? {
        None | Some(tlv::METHOD_PAIR_SETUP) => {}
        Some(_) => return Err(DutError::Protocol("unsupported pairing Method in M1")),
    }

    let (server, salt) = HapPairSetupSrpServer::new(setup_code)?;
    let b_pub = server.b_pub_bytes();

    let mut m2 = Vec::new();
    let mut w = Tlv8Writer::new(&mut m2);
    w.push_u8(tlv::STATE, tlv::STATE_M2);
    w.push(tlv::SALT, &salt);
    w.push(tlv::PUBLIC_KEY, &b_pub);

    Ok((m2, SetupInProgress::AwaitingM3 { server }))
}

/// Handle Pair Setup M3 (`State=3, PublicKey=A, Proof=M1`): derive the SRP
/// session key from `A`, verify `M1`, and produce M4 (`State=4, Proof=M2`).
///
/// On success returns M4 and `Some(session_key)` to carry into M5. A wrong setup
/// code (an `M1` that does not verify, or an SRP-invalid `A`) returns an M4
/// carrying an authentication error and `None`, so the caller still replies.
///
/// # Errors
/// [`DutError`] if M3 is structurally malformed.
pub(crate) fn handle_setup_m3(
    server: &HapPairSetupSrpServer,
    m3: &[u8],
) -> Result<(Vec<u8>, Option<Vec<u8>>)> {
    let map = Tlv8Map::parse(m3)?;
    expect_state(&map, tlv::STATE_M3)?;
    let a_pub = map
        .get(tlv::PUBLIC_KEY)
        .ok_or(DutError::Protocol("M3 missing controller public key A"))?;
    let m1 = map
        .get(tlv::PROOF)
        .ok_or(DutError::Protocol("M3 missing controller proof M1"))?;

    // An SRP-invalid `A` aborts in-band, not as an error.
    let Ok(session_key) = server.session_key(a_pub) else {
        return Ok((error_m4(), None));
    };
    match server.verify_m1_prove_m2(a_pub, m1) {
        Ok(m2_proof) => {
            let mut m4 = Vec::new();
            let mut w = Tlv8Writer::new(&mut m4);
            w.push_u8(tlv::STATE, tlv::STATE_M4);
            w.push(tlv::PROOF, &m2_proof);
            Ok((m4, Some(session_key)))
        }
        Err(_) => Ok((error_m4(), None)),
    }
}

/// Handle Pair Setup M5 (`State=5, EncryptedData`): decrypt the controller
/// sub-TLV, verify its signature, and produce M6 (`State=6, EncryptedData`).
///
/// On success returns M6 and `Some((controllerID, controllerLTPK))` — the
/// pairing the caller must store. A decrypt or signature failure returns an M6
/// carrying an authentication error and `None`.
///
/// # Errors
/// [`DutError`] if M5 is structurally malformed or a crypto derivation fails.
pub(crate) fn handle_setup_m5(
    session_key: &[u8],
    accessory_keypair: &ControllerKeypair,
    accessory_id: &str,
    m5: &[u8],
) -> Result<(Vec<u8>, Option<ControllerPairing>)> {
    let map = Tlv8Map::parse(m5)?;
    expect_state(&map, tlv::STATE_M5)?;
    let encrypted = map
        .get(tlv::ENCRYPTED_DATA)
        .ok_or(DutError::Protocol("M5 missing encrypted data"))?;

    let enc_key = hap::hkdf32(session_key, hap::PS_ENCRYPT_SALT, hap::PS_ENCRYPT_INFO)?;
    let Ok(plaintext) = chacha20poly1305_open(
        &enc_key,
        &hap::nonce_label(hap::NONCE_PS_M5),
        &[],
        encrypted,
    ) else {
        return Ok((error_m6(), None));
    };

    let sub = Tlv8Map::parse(&plaintext)?;
    let controller_id = sub
        .get(tlv::IDENTIFIER)
        .ok_or(DutError::Protocol("M5 sub-TLV missing identifier"))?;
    let Some(controller_ltpk) = sub
        .get(tlv::PUBLIC_KEY)
        .and_then(|k| <[u8; 32]>::try_from(k).ok())
    else {
        return Ok((error_m6(), None));
    };
    let Some(signature) = sub
        .get(tlv::SIGNATURE)
        .and_then(|s| <[u8; 64]>::try_from(s).ok())
    else {
        return Ok((error_m6(), None));
    };

    // Verify Ed25519(controllerLTPK, iOSDeviceX ‖ controllerID ‖ controllerLTPK).
    let ios_device_x = hap::hkdf32(
        session_key,
        hap::PS_CONTROLLER_SIGN_SALT,
        hap::PS_CONTROLLER_SIGN_INFO,
    )?;
    let mut signed = Vec::with_capacity(ios_device_x.len() + controller_id.len() + 32);
    signed.extend_from_slice(&ios_device_x);
    signed.extend_from_slice(controller_id);
    signed.extend_from_slice(&controller_ltpk);
    if verify_ed25519(&controller_ltpk, &signed, &signature).is_err() {
        return Ok((error_m6(), None));
    }
    let Ok(controller_id) = String::from_utf8(controller_id.to_vec()) else {
        return Ok((error_m6(), None));
    };

    // Build M6: sign AccessoryX ‖ accessoryID ‖ accessoryLTPK, seal the sub-TLV.
    let accessory_x = hap::hkdf32(
        session_key,
        hap::PS_ACCESSORY_SIGN_SALT,
        hap::PS_ACCESSORY_SIGN_INFO,
    )?;
    let accessory_ltpk = accessory_keypair.ltpk();
    let id = accessory_id.as_bytes();
    let mut acc_signed = Vec::with_capacity(accessory_x.len() + id.len() + accessory_ltpk.len());
    acc_signed.extend_from_slice(&accessory_x);
    acc_signed.extend_from_slice(id);
    acc_signed.extend_from_slice(&accessory_ltpk);
    let acc_sig = accessory_keypair.sign(&acc_signed);

    let mut acc_sub = Vec::new();
    let mut sw = Tlv8Writer::new(&mut acc_sub);
    sw.push(tlv::IDENTIFIER, id);
    sw.push(tlv::PUBLIC_KEY, &accessory_ltpk);
    sw.push(tlv::SIGNATURE, &acc_sig);
    let sealed =
        chacha20poly1305_seal(&enc_key, &hap::nonce_label(hap::NONCE_PS_M6), &[], &acc_sub)?;

    let mut m6 = Vec::new();
    let mut w = Tlv8Writer::new(&mut m6);
    w.push_u8(tlv::STATE, tlv::STATE_M6);
    w.push(tlv::ENCRYPTED_DATA, &sealed);

    Ok((m6, Some((controller_id, controller_ltpk))))
}

/// An M6 carrying an authentication error.
fn error_m6() -> Vec<u8> {
    let mut out = Vec::new();
    let mut w = Tlv8Writer::new(&mut out);
    w.push_u8(tlv::STATE, tlv::STATE_M6);
    w.push_u8(tlv::ERROR, tlv::ERROR_AUTHENTICATION);
    out
}

fn expect_state(map: &Tlv8Map, want: u8) -> Result<()> {
    match map.get_u8(tlv::STATE)? {
        Some(s) if s == want => Ok(()),
        _ => Err(DutError::Protocol("unexpected pairing State")),
    }
}
