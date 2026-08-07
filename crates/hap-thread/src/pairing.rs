//! Pair Setup and Pair Verify over CoAP.
//!
//! Both reuse the transport-agnostic state machines in [`hap_crypto`]; CoAP is
//! merely the pipe. Each controller message is a raw TLV8 body POSTed to the
//! pairing resource (`/1` for setup, `/2` for verify), and the accessory's
//! `2.04 Changed` response payload is the next TLV8 fed back into the client:
//!
//! ```text
//! out = client.start()
//! loop:
//!   reply = POST(resource, out).changed_payload()
//!   match client.handle(reply): Send(next) => out = next; Done(x) => return x
//! ```
//!
//! No HAP PDU framing is involved in pairing (unlike the encrypted control
//! channel) — the payloads are bare TLV8, exactly as aiohomekit posts them.

use hap_crypto::{
    AccessoryPairing, ControllerKeypair, PairSetupClient, PairSetupStep, PairVerifyClient,
    PairVerifyStep, SessionKeys,
};

use crate::coap::{CoapTransport, PATH_PAIR_SETUP, PATH_PAIR_VERIFY};
use crate::error::Result;

/// Run Pair Setup over CoAP, returning the established [`AccessoryPairing`] to
/// persist.
///
/// # Errors
/// Propagates transport, CoAP-code, and pairing-crypto failures (a wrong setup
/// code surfaces as a [`crate::ThreadError::Crypto`]).
pub(crate) async fn pair_setup<T: CoapTransport + ?Sized>(
    transport: &T,
    setup_code: &str,
    controller: ControllerKeypair,
) -> Result<AccessoryPairing> {
    let mut client = PairSetupClient::new(setup_code, controller)?;
    let mut out = client.start();
    loop {
        let reply = transport
            .post(PATH_PAIR_SETUP, &out)
            .await?
            .changed_payload()?;
        match client.handle(&reply)? {
            PairSetupStep::Send(next) => out = next,
            PairSetupStep::Done(pairing) => return Ok(pairing),
        }
    }
}

/// Run Pair Verify over CoAP against an already-paired accessory, returning the
/// control-channel [`SessionKeys`] and the CoAP event key.
///
/// # Errors
/// Propagates transport, CoAP-code, and verify-crypto failures.
pub(crate) async fn pair_verify<T: CoapTransport + ?Sized>(
    transport: &T,
    controller: &ControllerKeypair,
    accessory: &AccessoryPairing,
) -> Result<(SessionKeys, [u8; 32])> {
    pair_verify_with_client(transport, PairVerifyClient::new(controller, accessory)).await
}

/// Drive a pre-built [`PairVerifyClient`] over CoAP. Split out so a test (or a
/// hardware bring-up harness) can inject a client built with a captured
/// ephemeral key via [`PairVerifyClient::new_with_ephemeral`] and replay a real
/// trace through a mock transport.
pub(crate) async fn pair_verify_with_client<T: CoapTransport + ?Sized>(
    transport: &T,
    mut client: PairVerifyClient,
) -> Result<(SessionKeys, [u8; 32])> {
    let mut out = client.start();
    let keys = loop {
        let reply = transport
            .post(PATH_PAIR_VERIFY, &out)
            .await?
            .changed_payload()?;
        match client.handle(&reply)? {
            PairVerifyStep::Send(next) => out = next,
            PairVerifyStep::Done(keys) => break keys,
        }
    };
    // The event key is derived from the same Pair-Verify shared secret; the
    // client retains it after Done.
    let event_key = client.event_key()?;
    Ok((keys, event_key))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use crate::coap::{CoapResponse, MockCoapTransport};
    use crate::error::ThreadError;

    fn controller() -> ControllerKeypair {
        ControllerKeypair::generate("AA:BB:CC:DD:EE:FF".into())
    }

    #[tokio::test]
    async fn pair_setup_posts_m1_to_resource_1() {
        let mock = MockCoapTransport::new();
        // Return a session-gone code so the flow stops after M1 without needing a
        // full SRP trace; we are asserting the transport wiring, not the crypto.
        mock.queue(CoapResponse {
            code: (4, 4),
            payload: vec![],
        });
        let err = pair_setup(&mock, "123-45-678", controller()).await;
        assert!(matches!(err, Err(ThreadError::SessionExpired)));

        let reqs = mock.requests();
        assert_eq!(reqs.len(), 1);
        assert_eq!(reqs[0].0, "1"); // posted to /1
        assert!(
            !reqs[0].1.is_empty(),
            "M1 payload should be a non-empty TLV8"
        );
    }

    #[tokio::test]
    async fn pair_verify_posts_m1_to_resource_2_and_maps_not_found() {
        let mock = MockCoapTransport::new();
        mock.queue(CoapResponse {
            code: (4, 4),
            payload: vec![],
        });
        // A throwaway accessory pairing is enough to build the M1 request; the
        // flow aborts at the 4.04 before any signature is checked.
        let ctrl = controller();
        let client = PairVerifyClient::new(&ctrl, &sample_accessory_pairing());
        let err = pair_verify_with_client(&mock, client).await;
        assert!(matches!(err, Err(ThreadError::SessionExpired)));

        let reqs = mock.requests();
        assert_eq!(reqs.len(), 1);
        assert_eq!(reqs[0].0, "2"); // posted to /2
        assert!(!reqs[0].1.is_empty());
    }

    /// A structurally-valid [`AccessoryPairing`] for wiring tests. The key need
    /// not correspond to a real accessory — Pair Verify aborts at the transport
    /// (`4.04`) before any signature check in these tests.
    fn sample_accessory_pairing() -> AccessoryPairing {
        AccessoryPairing {
            pairing_id: "11:22:33:44:55:66".into(),
            ltpk: controller().ltpk(),
        }
    }
}
