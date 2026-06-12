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
    drive_pair_verify(conn, PairVerifyClient::new(controller, pairing)).await
}

/// Drive Pair Verify to completion over `conn` using an already-constructed
/// client. Split out from [`run_pair_verify`] so replay tests can inject a
/// deterministic-ephemeral client.
///
/// # Errors
/// [`PairingError::Accessory`] on a `kTLVType_Error` reply; [`PairingError::Crypto`]
/// if the accessory signature fails to verify; [`PairingError::Transport`] on I/O.
pub(crate) async fn drive_pair_verify<C: PairingConn + ?Sized>(
    conn: &mut C,
    mut client: PairVerifyClient,
) -> Result<SessionKeys> {
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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    //! Pair Verify loop tests driven against the captured M1/M2/M4 trace.
    //!
    //! Pair Verify is fully replayable: the captured fixtures pin the controller
    //! ephemeral (`ios_eph_priv.bin`) and the accessory identity, and the session
    //! keys derive only from the X25519 shared secret. We assert the derived
    //! [`SessionKeys`] equal the captured control keys (no live `SecureSession` is
    //! built — frame round-tripping is already covered by hap-transport in M4).

    use std::path::Path;

    use hap_crypto::{AccessoryPairing, ControllerKeypair, PairVerifyClient};

    use super::drive_pair_verify;
    use crate::error::PairingError;
    use crate::test_support::{Exchange, Replay};

    /// Read a pair-verify fixture relative to the workspace `test-vectors`.
    fn load(name: &str) -> Option<Vec<u8>> {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../test-vectors/pair-verify")
            .join(name);
        std::fs::read(path).ok()
    }

    /// Read a 32-byte pair-verify fixture.
    fn load32(name: &str) -> Option<[u8; 32]> {
        load(name).and_then(|v| v.try_into().ok())
    }

    /// Reconstruct the accessory pairing from the captured identity fixtures.
    fn accessory_from_fixtures() -> Option<AccessoryPairing> {
        let pairing_id = String::from_utf8(load("accessory_id.txt")?)
            .ok()?
            .trim()
            .to_string();
        let ltpk = load32("accessory_ltpk.bin")?;
        Some(AccessoryPairing { pairing_id, ltpk })
    }

    /// The throwaway controller identity used when the trace was captured.
    fn trace_controller() -> ControllerKeypair {
        ControllerKeypair::from_seed("ABCDEF01-2345-6789".to_string(), [7u8; 32])
    }

    #[tokio::test]
    async fn pair_verify_replays_trace_to_matching_session_keys() {
        let (
            Some(accessory),
            Some(eph_priv),
            Some(m1),
            Some(m2),
            Some(m4),
            Some(read),
            Some(write),
        ) = (
            accessory_from_fixtures(),
            load32("ios_eph_priv.bin"),
            load("m1.bin"),
            load("m2.bin"),
            load("m4.bin"),
            load32("control_read_encryption_key.bin"),
            load32("control_write_encryption_key.bin"),
        )
        else {
            eprintln!(
                "skipping pair_verify_replays_trace_to_matching_session_keys: fixtures absent"
            );
            return;
        };
        let controller = trace_controller();
        let client = PairVerifyClient::new_with_ephemeral(&controller, &accessory, eph_priv);
        // M1 is byte-reproducible; the M3 request bytes depend on the
        // uncommitted controller LTSK, so skip the byte assertion there.
        let mut replay = Replay::new(vec![
            Exchange {
                path: "/pair-verify",
                expect_request: Some(m1),
                response: m2,
            },
            Exchange {
                path: "/pair-verify",
                expect_request: None,
                response: m4,
            },
        ]);
        let keys = drive_pair_verify(&mut replay, client)
            .await
            .expect("pair verify replay should reach Done");
        // The derived session keys equalling the captured control keys is the
        // proof the loop produced correct keys (no live session round-trip).
        assert_eq!(keys.read_key, read, "read_key mismatch");
        assert_eq!(keys.write_key, write, "write_key mismatch");
        assert!(replay.is_drained());
    }

    #[tokio::test]
    async fn pair_verify_rejects_tampered_accessory_signature() {
        let (Some(accessory), Some(eph_priv), Some(m1), Some(mut m2)) = (
            accessory_from_fixtures(),
            load32("ios_eph_priv.bin"),
            load("m1.bin"),
            load("m2.bin"),
        ) else {
            eprintln!("skipping pair_verify_rejects_tampered_accessory_signature: fixtures absent");
            return;
        };
        // Flip the last byte: it lands in the M2 AEAD tag, so auth fails.
        let last = m2.len() - 1;
        m2[last] ^= 0x01;
        let controller = trace_controller();
        let client = PairVerifyClient::new_with_ephemeral(&controller, &accessory, eph_priv);
        let mut replay = Replay::new(vec![Exchange {
            path: "/pair-verify",
            expect_request: Some(m1),
            response: m2,
        }]);
        let result = drive_pair_verify(&mut replay, client).await;
        assert!(
            matches!(result, Err(PairingError::Crypto(_))),
            "expected Crypto error, got {result:?}"
        );
    }
}
