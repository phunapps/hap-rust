//! Pair Verify orchestration (`connect`).

use std::time::Duration;

use hap_crypto::{
    AccessoryPairing, ControllerKeypair, PairVerifyClient, PairVerifyStep, SessionKeys,
};
use hap_transport::{discover, HapConnection, SecureSession};

use crate::error::{PairingError, Result};
use crate::setup::check_tlv_error;
use crate::store::StoredAccessory;
use crate::wire::PairingConn;

/// The HAP Pair Verify endpoint.
const PAIR_VERIFY: &str = "/pair-verify";

/// How long to browse `_hap._tcp` when the stored address no longer resolves.
const DISCOVERY_TIMEOUT: Duration = Duration::from_secs(5);

/// Establish a secure session with a previously-paired accessory.
///
/// Dials the accessory's stored address; if that fails, falls back to an mDNS
/// browse and matches the responder whose id equals the stored pairing id. Then
/// runs Pair Verify (X25519 + Ed25519, steps M1–M4) authenticated against the
/// stored accessory LTPK and upgrades the connection to a [`SecureSession`].
///
/// # Errors
/// - [`PairingError::UnknownAccessory`] if the stored address fails and no
///   matching accessory is found on the network.
/// - [`PairingError::Crypto`] if the accessory's Ed25519 signature does not
///   verify against the stored LTPK (a wrong or revoked pairing).
/// - [`PairingError::Transport`] if the accessory cannot be reached.
pub async fn connect(
    accessory: &StoredAccessory,
    controller: &ControllerKeypair,
) -> Result<SecureSession> {
    let conn = if let Ok(c) = HapConnection::connect(accessory.addr).await {
        c
    } else {
        let found = discover(DISCOVERY_TIMEOUT).await?;
        let dev = found
            .into_iter()
            .find(|d| d.id == accessory.pairing.pairing_id)
            .ok_or_else(|| PairingError::UnknownAccessory(accessory.pairing.pairing_id.clone()))?;
        HapConnection::connect(dev.addr).await?
    };
    connect_over(conn, &accessory.pairing, controller).await
}

/// Run Pair Verify over an already-open connection and upgrade to a session.
/// Shared by [`connect`] and by [`pair`](crate::pair) (right after Pair Setup).
///
/// # Errors
/// See [`connect`] (minus the discovery/`UnknownAccessory` path).
pub(crate) async fn connect_over(
    conn: HapConnection,
    pairing: &AccessoryPairing,
    controller: &ControllerKeypair,
) -> Result<SecureSession> {
    let mut conn = conn;
    let keys = run_pair_verify(&mut conn, pairing, controller).await?;
    Ok(conn.upgrade(keys))
}

/// The transport-agnostic Pair Verify loop, exercised against the replay mock.
///
/// # Errors
/// [`PairingError::Accessory`] on a `kTLVType_Error` reply; [`PairingError::Crypto`]
/// if the accessory signature fails to verify; [`PairingError::Transport`] on I/O.
pub(crate) async fn run_pair_verify<C: PairingConn + ?Sized>(
    conn: &mut C,
    pairing: &AccessoryPairing,
    controller: &ControllerKeypair,
) -> Result<SessionKeys> {
    let mut client = PairVerifyClient::new(controller, pairing);
    let mut request = client.start();
    loop {
        let response = conn.post_tlv8(PAIR_VERIFY, &request).await?;
        check_tlv_error(&response)?;
        match client.handle(&response)? {
            PairVerifyStep::Send(next) => request = next,
            PairVerifyStep::Done(keys) => return Ok(keys),
        }
    }
}
