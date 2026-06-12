//! Pairings management over the `/pairings` endpoint (add / remove / list).
//!
//! These exchanges run as TLV8 over an established [`SecureSession`]. No new
//! cryptography: `kTLVType_Method` selects the operation, and add/remove carry
//! the target Identifier / PublicKey / Permissions.
//!
//! note: the [`PairingsAdmin`] replay tests live in an in-module
//! `#[cfg(test)] mod tests` (added in Task 7), not under `tests/`, because the
//! [`PairingSession`] seam is crate-private and cannot be named from an
//! out-of-crate integration test.

use hap_tlv8::{Tlv8Reader, Tlv8Writer, SEPARATOR};
use hap_transport::SecureSession;

use crate::error::{PairingError, Result};
use crate::wire::PairingSession;

/// The HAP pairings-management endpoint.
const PAIRINGS: &str = "/pairings";

// kTLVType values used by /pairings (HAP spec, "Add/Remove/List Pairings").
const TLV_METHOD: u8 = 0x00;
const TLV_IDENTIFIER: u8 = 0x01;
const TLV_PUBLIC_KEY: u8 = 0x03;
const TLV_STATE: u8 = 0x06;
const TLV_ERROR: u8 = 0x07;
const TLV_PERMISSIONS: u8 = 0x0b;

// kTLVType_Method values.
const METHOD_ADD: u8 = 3;
const METHOD_REMOVE: u8 = 4;
const METHOD_LIST: u8 = 5;

// kTLVType_State values: every /pairings request is M1, the reply is M2.
const STATE_M1: u8 = 0x01;
const STATE_M2: u8 = 0x02;

// kTLVType_Permissions: admin (can manage pairings) vs regular user.
const PERM_ADMIN: u8 = 0x01;
const PERM_USER: u8 = 0x00;

/// One pairing as reported by [`PairingsAdmin::list`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairingInfo {
    /// The controller/accessory pairing identifier.
    pub id: String,
    /// The Ed25519 long-term public key (32 bytes).
    pub ltpk: [u8; 32],
    /// Whether this pairing has admin (pairing-management) permission.
    pub admin: bool,
}

/// Manages the accessory's list of pairings over an established
/// [`SecureSession`].
///
/// Wraps a mutable borrow of the session; create one per batch of operations
/// and drop it to release the session.
pub struct PairingsAdmin<'a> {
    session: &'a mut dyn PairingSession,
}

impl<'a> PairingsAdmin<'a> {
    /// Wrap a secure session for pairings management.
    #[must_use]
    pub fn new(session: &'a mut SecureSession) -> Self {
        Self { session }
    }

    /// Wrap any [`PairingSession`] (the seam used by replay tests).
    ///
    /// Unused until the in-module replay tests land in Task 7; allowed to be
    /// dead in the meantime so the crate builds cleanly under `-D warnings`.
    #[cfg(test)]
    #[allow(dead_code)]
    pub(crate) fn with_session(session: &'a mut dyn PairingSession) -> Self {
        Self { session }
    }

    /// Add a pairing for another controller (`id` + its `ltpk`), granting admin
    /// permission when `admin` is true. Requires this session's controller to
    /// already hold admin permission on the accessory.
    ///
    /// # Errors
    /// [`PairingError::Accessory`] if the accessory rejects the request;
    /// [`PairingError::Malformed`] if the reply is not a well-formed M2;
    /// [`PairingError::Transport`]/[`PairingError::Tlv8`] on I/O or decode failure.
    pub async fn add(&mut self, id: &str, ltpk: [u8; 32], admin: bool) -> Result<()> {
        let mut body = Vec::new();
        {
            let mut w = Tlv8Writer::new(&mut body);
            w.push_u8(TLV_STATE, STATE_M1);
            w.push_u8(TLV_METHOD, METHOD_ADD);
            w.push(TLV_IDENTIFIER, id.as_bytes());
            w.push(TLV_PUBLIC_KEY, &ltpk);
            w.push_u8(TLV_PERMISSIONS, if admin { PERM_ADMIN } else { PERM_USER });
        }
        let reply = self.session.put_tlv8(PAIRINGS, &body).await?;
        expect_m2_ok(&reply)
    }

    /// Remove the pairing identified by `id`.
    ///
    /// # Errors
    /// As for [`add`](Self::add).
    pub async fn remove(&mut self, id: &str) -> Result<()> {
        let mut body = Vec::new();
        {
            let mut w = Tlv8Writer::new(&mut body);
            w.push_u8(TLV_STATE, STATE_M1);
            w.push_u8(TLV_METHOD, METHOD_REMOVE);
            w.push(TLV_IDENTIFIER, id.as_bytes());
        }
        let reply = self.session.put_tlv8(PAIRINGS, &body).await?;
        expect_m2_ok(&reply)
    }

    /// List every pairing the accessory knows about.
    ///
    /// # Errors
    /// [`PairingError::Accessory`] on a rejected request; [`PairingError::Malformed`]
    /// if the reply state is wrong or a public key is not 32 bytes; transport/tlv8
    /// errors on I/O or decode failure.
    pub async fn list(&mut self) -> Result<Vec<PairingInfo>> {
        let mut body = Vec::new();
        {
            let mut w = Tlv8Writer::new(&mut body);
            w.push_u8(TLV_STATE, STATE_M1);
            w.push_u8(TLV_METHOD, METHOD_LIST);
        }
        let reply = self.session.put_tlv8(PAIRINGS, &body).await?;
        parse_list_reply(&reply)
    }
}

/// Decode an add/remove reply: reject a `kTLVType_Error`, then require state M2.
///
/// # Errors
/// [`PairingError::Accessory`] if the reply carries a `kTLVType_Error` code;
/// [`PairingError::Malformed`] if the error TLV is empty or the state is not M2;
/// [`PairingError::Tlv8`] if the body does not parse.
fn expect_m2_ok(body: &[u8]) -> Result<()> {
    let items = Tlv8Reader::parse(body)?;
    if let Some((_, err)) = items.iter().find(|(ty, _)| *ty == TLV_ERROR) {
        let code = *err
            .first()
            .ok_or(PairingError::Malformed("empty error tlv"))?;
        return Err(PairingError::Accessory(code));
    }
    let state = items
        .iter()
        .find(|(ty, _)| *ty == TLV_STATE)
        .and_then(|(_, v)| v.first().copied());
    if state == Some(STATE_M2) {
        Ok(())
    } else {
        Err(PairingError::Malformed("expected pairings reply state M2"))
    }
}

/// Flush the current `(id, ltpk, admin)` triplet into `out`: push it if all
/// three fields are present, no-op if none are, error if only some are. Resets
/// the three fields to `None` either way.
///
/// # Errors
/// [`PairingError::Malformed`] if the triplet is partially filled.
fn flush_pairing(
    out: &mut Vec<PairingInfo>,
    id: &mut Option<String>,
    ltpk: &mut Option<[u8; 32]>,
    admin: &mut Option<bool>,
) -> Result<()> {
    match (id.take(), ltpk.take(), admin.take()) {
        (Some(id), Some(ltpk), Some(admin)) => {
            out.push(PairingInfo { id, ltpk, admin });
            Ok(())
        }
        (None, None, None) => Ok(()),
        _ => Err(PairingError::Malformed("incomplete pairing entry")),
    }
}

/// Decode a list reply into [`PairingInfo`] entries.
///
/// The reply is an ordered TLV8 sequence: a leading State item, then one
/// `(Identifier, PublicKey, Permissions)` group per pairing, groups split by a
/// `0xFF` separator (the final group has no trailing separator).
///
/// # Errors
/// [`PairingError::Accessory`] if the reply carries a `kTLVType_Error` code;
/// [`PairingError::Malformed`] if the state is not M2, a public key is not 32
/// bytes, an identifier is not valid UTF-8, or a group is incomplete;
/// [`PairingError::Tlv8`] if the body does not parse.
fn parse_list_reply(body: &[u8]) -> Result<Vec<PairingInfo>> {
    let items = Tlv8Reader::parse(body)?;
    if let Some((_, err)) = items.iter().find(|(ty, _)| *ty == TLV_ERROR) {
        let code = *err
            .first()
            .ok_or(PairingError::Malformed("empty error tlv"))?;
        return Err(PairingError::Accessory(code));
    }
    let state = items
        .iter()
        .find(|(ty, _)| *ty == TLV_STATE)
        .and_then(|(_, v)| v.first().copied());
    if state != Some(STATE_M2) {
        return Err(PairingError::Malformed("expected pairings reply state M2"));
    }

    let mut out: Vec<PairingInfo> = Vec::new();
    let mut id: Option<String> = None;
    let mut ltpk: Option<[u8; 32]> = None;
    let mut admin: Option<bool> = None;

    for (ty, value) in &items {
        match *ty {
            SEPARATOR => flush_pairing(&mut out, &mut id, &mut ltpk, &mut admin)?,
            TLV_IDENTIFIER => {
                id = Some(
                    String::from_utf8(value.clone())
                        .map_err(|_| PairingError::Malformed("pairing identifier is not utf-8"))?,
                );
            }
            TLV_PUBLIC_KEY => {
                let key: [u8; 32] = value
                    .as_slice()
                    .try_into()
                    .map_err(|_| PairingError::Malformed("pairing public key is not 32 bytes"))?;
                ltpk = Some(key);
            }
            TLV_PERMISSIONS => {
                admin = Some((value.first().copied().unwrap_or(0) & PERM_ADMIN) != 0);
            }
            // TLV_STATE / TLV_METHOD / anything else: ignore.
            _ => {}
        }
    }
    flush_pairing(&mut out, &mut id, &mut ltpk, &mut admin)?;

    Ok(out)
}
