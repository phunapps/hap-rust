//! The BLE controller entry point: own the controller identity, scan, pair, and
//! connect.

use crate::accessory::BleAccessory;
use crate::broadcast_state::BleBroadcastState;
use crate::discovery::DiscoveredBleAccessory;
use crate::error::Result;
use crate::pairing;
use hap_crypto::AccessoryPairing;
use hap_crypto::ControllerKeypair;
use std::sync::Arc;

/// The HAP Pairing-Service characteristic UUIDs (HAP-defined, fixed).
const PAIR_SETUP_CHAR: &str = "0000004c-0000-1000-8000-0026bb765291";
const PAIR_VERIFY_CHAR: &str = "0000004e-0000-1000-8000-0026bb765291";
const PAIRINGS_CHAR: &str = "00000050-0000-1000-8000-0026bb765291";
/// The HAP Service-Signature characteristic (one per service); the
/// Protocol-Configuration "generate broadcast key" request is written here.
const SERVICE_SIGNATURE_CHAR: &str = "000000a5-0000-1000-8000-0026bb765291";
/// Protocol-Configuration TLV body that asks the accessory to generate a
/// broadcast encryption key (type `GenerateBroadcastEncryptionKey` = 0x01, len 0).
const GENERATE_BROADCAST_KEY_BODY: [u8; 2] = [0x01, 0x00];

/// The result of a successful BLE pairing.
pub struct Paired {
    /// The connected accessory handle.
    pub accessory: BleAccessory,
    /// The long-term pairing — persist this.
    pub pairing: AccessoryPairing,
    /// Broadcast material — persist this to resume broadcasts across restarts.
    pub broadcast: BleBroadcastState,
}

/// A BLE HAP controller: holds the long-term controller identity used for
/// pairing and verification.
pub struct BleController {
    keypair: ControllerKeypair,
}

impl BleController {
    /// Create a controller from a long-term identity.
    pub fn new(keypair: ControllerKeypair) -> Self {
        Self { keypair }
    }

    /// Generate a fresh controller identity with the given pairing id.
    pub fn generate(id: String) -> Self {
        Self {
            keypair: ControllerKeypair::generate(id),
        }
    }

    /// The controller's pairing identity.
    pub fn keypair(&self) -> &ControllerKeypair {
        &self.keypair
    }

    /// Pair with a discovered accessory: run Pair Setup, then Pair Verify, then
    /// build the attribute database. Returns a [`Paired`] containing the ready
    /// accessory handle, the persisted [`AccessoryPairing`], and initial
    /// broadcast material.
    ///
    /// # Errors
    /// Propagates connection, pairing, and model errors.
    pub async fn pair(
        &self,
        gatt: Arc<dyn crate::gatt::GattConnection>,
        _accessory: &DiscoveredBleAccessory,
        setup_code: &str,
    ) -> Result<Paired> {
        // Pair first (reading only the Pair-Setup characteristic's iid, one
        // descriptor read) — the long database sweep must not run before the
        // stateful Pair Setup handshake, which can't survive a mid-handshake
        // reconnect.
        let frag = gatt.max_write().await;
        let setup_iid = gatt.instance_id(PAIR_SETUP_CHAR).await?;
        let pairing = pairing::pair_setup(
            gatt.as_ref(),
            PAIR_SETUP_CHAR,
            setup_iid,
            setup_code,
            self.keypair.clone(),
            frag,
        )
        .await?;
        let accessory = self.verify_and_build(gatt, &pairing, 0).await?;
        let broadcast = accessory.broadcast_state().await;
        Ok(Paired {
            accessory,
            pairing,
            broadcast,
        })
    }

    /// Connect to an already-paired accessory via Pair Verify, then build the DB.
    ///
    /// `broadcast` is optional previously-persisted broadcast state. Its `gsn`
    /// seeds `last_gsn` so the accessory handle does not re-emit already-seen
    /// events after a restart. The key in `broadcast` is the previously-persisted
    /// one — Pair Verify derives a fresh per-session broadcast key, which becomes
    /// the accessory's current key.
    ///
    /// # NOTE
    /// Decrypting pre-connect broadcasts with the persisted key (vs the fresh
    /// per-session key derived here) is a documented follow-up task — the fresh
    /// key covers forward broadcasts.
    ///
    /// # Errors
    /// Propagates connection, verify, and model errors.
    pub async fn connect(
        &self,
        gatt: Arc<dyn crate::gatt::GattConnection>,
        pairing: &AccessoryPairing,
        broadcast: Option<BleBroadcastState>,
    ) -> Result<BleAccessory> {
        let initial_gsn = broadcast.as_ref().map_or(0, |b| b.gsn);
        self.verify_and_build(gatt, pairing, initial_gsn).await
    }

    async fn verify_and_build(
        &self,
        gatt: Arc<dyn crate::gatt::GattConnection>,
        pairing: &AccessoryPairing,
        initial_gsn: u16,
    ) -> Result<BleAccessory> {
        // After pairing, walk the full tree (resilient) for iids, then build the
        // typed database from UNENCRYPTED characteristic-signature reads — HAP
        // reads the database structure after Pair Setup but before Pair Verify
        // (no secure session yet). The resilient GattConnection reconnects +
        // resumes through the accessory's periodic disconnects.
        let frag = gatt.max_write().await;
        let services = gatt.enumerate().await?;
        let accessories = crate::db::build_db(gatt.as_ref(), &services, frag).await?;

        // Now establish the secure session for value reads / events.
        let verify_iid = iid_of(&services, PAIR_VERIFY_CHAR)?;
        let (mut session, broadcast_key) = pairing::pair_verify(
            gatt.as_ref(),
            PAIR_VERIFY_CHAR,
            verify_iid,
            &self.keypair,
            pairing,
            frag,
        )
        .await?;

        // Best-effort: ask the accessory to generate its broadcast encryption key
        // so it emits encrypted broadcast notifications while disconnected. An
        // accessory that doesn't support broadcasts (or whose Service-Signature
        // characteristic we can't address) just won't broadcast — the
        // disconnected-event poll still delivers durable events. Failure here must
        // not abort pairing, so it is ignored.
        if let Ok(sig_iid) = iid_of(&services, SERVICE_SIGNATURE_CHAR) {
            let _ = crate::pdu::request_secure(
                gatt.as_ref(),
                &mut session,
                SERVICE_SIGNATURE_CHAR,
                crate::pdu::OpCode::ProtocolConfig,
                1,
                sig_iid,
                &GENERATE_BROADCAST_KEY_BODY,
                frag,
            )
            .await;
        }
        // The generation the session was minted at — a later reconnect past this
        // means the accessory dropped the session and the BleAccessory must
        // re-verify before its next encrypted op (events surviving a reconnect).
        let session_generation = gatt.generation().await;
        let pairings_iid = iid_of(&services, PAIRINGS_CHAR)?;
        let ctx = crate::accessory::SecureContext {
            session,
            session_generation,
            keypair: self.keypair.clone(),
            pairing: pairing.clone(),
            verify_char: PAIR_VERIFY_CHAR.to_string(),
            verify_iid,
            pairings_char: PAIRINGS_CHAR.to_string(),
            pairings_iid,
            broadcast_key,
            initial_gsn,
        };
        Ok(BleAccessory::new(gatt, ctx, frag, &services, accessories))
    }
}

/// Find a characteristic's HAP instance id by UUID in an enumerated GATT tree.
fn iid_of(services: &[crate::gatt::GattService], char_uuid: &str) -> Result<u16> {
    services
        .iter()
        .flat_map(|s| &s.characteristics)
        .find(|c| c.uuid.eq_ignore_ascii_case(char_uuid))
        .map(|c| c.iid)
        .ok_or(crate::error::BleError::CharacteristicNotFound { aid: 0, iid: 0 })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_sets_identity() {
        let c = BleController::generate("11:22:33:44:55:66".into());
        assert_eq!(c.keypair().id, "11:22:33:44:55:66");
    }
}
