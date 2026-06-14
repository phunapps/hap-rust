//! The BLE controller entry point: own the controller identity, scan, pair, and
//! connect.

use crate::accessory::BleAccessory;
use crate::discovery::DiscoveredBleAccessory;
use crate::error::Result;
use crate::pairing;
use crate::session::BleSession;
use hap_crypto::AccessoryPairing;
use hap_crypto::ControllerKeypair;
use std::sync::Arc;

/// The HAP Pairing-Service characteristic UUIDs (HAP-defined, fixed).
const PAIR_SETUP_CHAR: &str = "0000004c-0000-1000-8000-0026bb765291";
const PAIR_VERIFY_CHAR: &str = "0000004e-0000-1000-8000-0026bb765291";

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
    /// build the attribute database. Returns a ready [`BleAccessory`] and the
    /// persisted [`AccessoryPairing`].
    ///
    /// # Errors
    /// Propagates connection, pairing, and model errors.
    pub async fn pair(
        &self,
        gatt: Arc<dyn crate::gatt::GattConnection>,
        _accessory: &DiscoveredBleAccessory,
        setup_code: &str,
    ) -> Result<(BleAccessory, AccessoryPairing)> {
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
        let acc = self.verify_and_build(gatt, &pairing).await?;
        Ok((acc, pairing))
    }

    /// Connect to an already-paired accessory via Pair Verify, then build the DB.
    ///
    /// # Errors
    /// Propagates connection, verify, and model errors.
    pub async fn connect(
        &self,
        gatt: Arc<dyn crate::gatt::GattConnection>,
        pairing: &AccessoryPairing,
    ) -> Result<BleAccessory> {
        self.verify_and_build(gatt, pairing).await
    }

    async fn verify_and_build(
        &self,
        gatt: Arc<dyn crate::gatt::GattConnection>,
        pairing: &AccessoryPairing,
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
        let session: BleSession = pairing::pair_verify(
            gatt.as_ref(),
            PAIR_VERIFY_CHAR,
            verify_iid,
            &self.keypair,
            pairing,
            frag,
        )
        .await?;
        Ok(BleAccessory::new(
            gatt,
            session,
            frag,
            &services,
            accessories,
        ))
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
