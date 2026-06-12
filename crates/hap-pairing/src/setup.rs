//! Pair Setup orchestration (`pair`).

use hap_crypto::{AccessoryPairing, ControllerKeypair, PairSetupClient, PairSetupStep};
use hap_transport::{HapConnection, SecureSession};

use crate::error::{PairingError, Result};
use crate::verify::connect_over;
use crate::wire::PairingConn;

/// The HAP Pair Setup endpoint.
const PAIR_SETUP: &str = "/pair-setup";

/// kTLVType_Error (type 0x07): present in a pairing reply when the accessory
/// rejects the exchange.
const K_TLV_TYPE_ERROR: u8 = 0x07;

/// Pair with an accessory: run Pair Setup (SRP-6a, steps M1–M6) over `conn`
/// using the `setup_code`, then immediately establish a secure session via
/// Pair Verify, returning the [`AccessoryPairing`] (persist it with a
/// [`PairingStore`](crate::PairingStore)) and a ready-to-use [`SecureSession`].
///
/// # Errors
/// - [`PairingError::Accessory`] if the accessory rejects the setup code
///   (typically `0x02` Authentication) or is busy (`0x07`).
/// - [`PairingError::Crypto`] if an SRP proof or encrypted sub-TLV fails to verify.
/// - [`PairingError::Transport`] on a connection/HTTP failure.
pub async fn pair(
    conn: HapConnection,
    setup_code: &str,
    controller: &ControllerKeypair,
) -> Result<(AccessoryPairing, SecureSession)> {
    let mut conn = conn;
    let pairing = run_pair_setup(&mut conn, setup_code, controller).await?;
    // Pair Verify over the same open connection yields the session.
    let session = connect_over(conn, &pairing, controller).await?;
    Ok((pairing, session))
}

/// The transport-agnostic Pair Setup loop, exercised against the replay mock in
/// tests. Drives [`PairSetupClient`] over any [`PairingConn`].
///
/// # Errors
/// See [`pair`]. Surfaces a `kTLVType_Error` reply as [`PairingError::Accessory`].
pub(crate) async fn run_pair_setup<C: PairingConn + ?Sized>(
    conn: &mut C,
    setup_code: &str,
    controller: &ControllerKeypair,
) -> Result<AccessoryPairing> {
    let mut client = PairSetupClient::new(setup_code, controller.clone())?;
    let mut request = client.start();
    loop {
        let response = conn.post_tlv8(PAIR_SETUP, &request).await?;
        check_tlv_error(&response)?;
        match client.handle(&response)? {
            PairSetupStep::Send(next) => request = next,
            PairSetupStep::Done(pairing) => return Ok(pairing),
        }
    }
}

/// Inspect a pairing response for a `kTLVType_Error` (type 0x07) item and, if
/// present, surface it as [`PairingError::Accessory`].
///
/// Shared with [`verify`](crate::verify). Returns `Ok(())` when no error item
/// is present (the normal case).
///
/// # Errors
/// [`PairingError::Accessory`] if the response carries a `kTLVType_Error`;
/// [`PairingError::Tlv8`] if the body is not valid TLV8.
pub(crate) fn check_tlv_error(body: &[u8]) -> Result<()> {
    let map = hap_tlv8::Tlv8Map::parse(body)?;
    if let Some(code) = map.get(K_TLV_TYPE_ERROR).and_then(<[u8]>::first) {
        return Err(PairingError::Accessory(*code));
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    //! Pair Setup loop tests.
    //!
    //! Only the deterministic M1 request and the accessory-error surfacing are
    //! exercised offline. The full M1–M6 setup loop is validated by the
    //! real-device runbook (Task 8): the captured aiohomekit setup trace does
    //! not pin the controller's SRP ephemeral `a` or its LTSK, so the loop
    //! cannot be replayed to completion without a live accessory.

    use std::path::Path;

    use hap_crypto::ControllerKeypair;
    use hap_tlv8::Tlv8Writer;

    use super::run_pair_setup;
    use crate::error::PairingError;
    use crate::test_support::{Exchange, Replay};

    /// Read a pair-setup fixture relative to the workspace `test-vectors`.
    fn load_setup(name: &str) -> Option<Vec<u8>> {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../test-vectors/pair-setup")
            .join(name);
        std::fs::read(path).ok()
    }

    /// Build an accessory error reply: State=M2 then kTLVType_Error=`code`.
    fn error_reply(code: u8) -> Vec<u8> {
        let mut body = Vec::new();
        let mut w = Tlv8Writer::new(&mut body);
        w.push_u8(0x06, 0x02);
        w.push_u8(0x07, code);
        body
    }

    #[tokio::test]
    async fn pair_setup_sends_m1_then_surfaces_accessory_error() {
        let Some(m1) = load_setup("m1.bin") else {
            eprintln!("skipping pair_setup_sends_m1_then_surfaces_accessory_error: fixture absent");
            return;
        };
        let mut replay = Replay::new(vec![Exchange {
            path: "/pair-setup",
            expect_request: Some(m1),
            response: error_reply(0x02),
        }]);
        let controller = ControllerKeypair::generate("ctl".to_string());
        let result = run_pair_setup(&mut replay, "123-45-678", &controller).await;
        assert!(
            matches!(result, Err(PairingError::Accessory(0x02))),
            "expected Accessory(0x02), got {result:?}"
        );
        assert!(replay.is_drained());
    }

    #[tokio::test]
    async fn pair_setup_propagates_tlv_error_code() {
        let Some(m1) = load_setup("m1.bin") else {
            eprintln!("skipping pair_setup_propagates_tlv_error_code: fixture absent");
            return;
        };
        let mut replay = Replay::new(vec![Exchange {
            path: "/pair-setup",
            expect_request: Some(m1),
            response: error_reply(0x06),
        }]);
        let controller = ControllerKeypair::generate("ctl".to_string());
        let result = run_pair_setup(&mut replay, "123-45-678", &controller).await;
        assert!(
            matches!(result, Err(PairingError::Accessory(0x06))),
            "expected Accessory(0x06), got {result:?}"
        );
        assert!(replay.is_drained());
    }
}
