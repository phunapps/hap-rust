//! Drive Pair Setup / Pair Verify (from `hap_crypto`) over the pairing GATT
//! characteristic. Each TLV8 step is the Value param of a write PDU; the
//! response's Value param is fed back to the state machine.

use crate::error::{BleError, Result};
use crate::gatt::GattConnection;
use crate::pdu::{self, OpCode};
use crate::session::BleSession;
use hap_crypto::{
    AccessoryPairing, ControllerKeypair, PairSetupClient, PairSetupStep, PairVerifyClient,
    PairVerifyStep,
};

/// Send one pairing TLV8 to the pairing characteristic and return the
/// accessory's reply TLV8 (the Value param of a success response PDU).
///
/// # Errors
/// [`BleError::PairingRejected`] on a non-zero PDU status; otherwise GATT or
/// TLV/PDU errors.
pub async fn exchange<G: GattConnection + ?Sized>(
    gatt: &G,
    char_uuid: &str,
    tid: u8,
    iid: u16,
    tlv: &[u8],
    frag_size: usize,
) -> Result<Vec<u8>> {
    let body = pdu::encode_value_param(tlv);
    let resp =
        pdu::request(gatt, char_uuid, OpCode::CharacteristicWrite, tid, iid, &body, frag_size)
            .await?;
    if resp.status != 0 {
        return Err(BleError::PairingRejected(resp.status));
    }
    pdu::value_param(&resp.body)
}

/// Run Pair Setup over BLE, returning the accessory pairing on success.
///
/// # Errors
/// Propagates pairing/crypto/GATT errors.
pub async fn pair_setup<G: GattConnection + ?Sized>(
    gatt: &G,
    char_uuid: &str,
    iid: u16,
    setup_code: &str,
    controller: ControllerKeypair,
    frag_size: usize,
) -> Result<AccessoryPairing> {
    let mut client = PairSetupClient::new(setup_code, controller)?;
    let mut tid: u8 = 0;
    let mut out = client.start();
    loop {
        tid = tid.wrapping_add(1);
        let reply = exchange(gatt, char_uuid, tid, iid, &out, frag_size).await?;
        match client.handle(&reply)? {
            PairSetupStep::Send(next) => out = next,
            PairSetupStep::Done(pairing) => return Ok(pairing),
        }
    }
}

/// Run Pair Verify over BLE, returning an established [`BleSession`].
///
/// # Errors
/// Propagates pairing/crypto/GATT errors.
pub async fn pair_verify<G: GattConnection + ?Sized>(
    gatt: &G,
    char_uuid: &str,
    iid: u16,
    controller: &ControllerKeypair,
    accessory: &AccessoryPairing,
    frag_size: usize,
) -> Result<BleSession> {
    let mut client = PairVerifyClient::new(controller, accessory);
    let mut tid: u8 = 0;
    let mut out = client.start();
    loop {
        tid = tid.wrapping_add(1);
        let reply = exchange(gatt, char_uuid, tid, iid, &out, frag_size).await?;
        match client.handle(&reply)? {
            PairVerifyStep::Send(next) => out = next,
            PairVerifyStep::Done(keys) => return Ok(BleSession::new(keys)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gatt::MockGatt;

    #[tokio::test]
    #[allow(clippy::unwrap_used)]
    async fn exchange_wraps_tlv_in_pdu_and_unwraps_response() {
        // The accessory echoes our TLV8 back inside a success response PDU.
        let gatt = MockGatt::new();
        let our_tlv = vec![0x06, 0x01, 0x02]; // a fake state TLV8 (kTLVType_State=6, M2)
        let body = crate::pdu::encode_value_param(&our_tlv);
        let mut resp = vec![0x02, 0x01, 0x00];
        resp.extend_from_slice(&(u16::try_from(body.len()).unwrap()).to_le_bytes());
        resp.extend_from_slice(&body);
        gatt.queue_read("pairing-char", resp);

        let out = exchange(&gatt, "pairing-char", 0x01, 0x0001, &our_tlv, 512)
            .await
            .unwrap();
        assert_eq!(out, our_tlv);
    }

    #[tokio::test]
    #[allow(clippy::unwrap_used)]
    async fn exchange_surfaces_nonzero_status_as_rejection() {
        let gatt = MockGatt::new();
        gatt.queue_read("pairing-char", vec![0x02, 0x01, 0x06]); // status 6
        let err = exchange(&gatt, "pairing-char", 0x01, 0x0001, &[0x00], 512)
            .await
            .unwrap_err();
        assert!(matches!(err, crate::error::BleError::PairingRejected(6)));
    }
}
