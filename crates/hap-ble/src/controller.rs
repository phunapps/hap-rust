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

/// Default GATT fragment size before MTU negotiation (conservative).
const DEFAULT_FRAG_SIZE: usize = 512;

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
        // Read just the Pair-Setup characteristic's instance id (one descriptor
        // read) — pairing must not wait on a full tree walk, which is slow and
        // fragile on sleepy accessories.
        let setup_iid = gatt.instance_id(PAIR_SETUP_CHAR).await?;
        let pairing = pairing::pair_setup(
            gatt.as_ref(),
            PAIR_SETUP_CHAR,
            setup_iid,
            setup_code,
            self.keypair.clone(),
            DEFAULT_FRAG_SIZE,
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
        let verify_iid = gatt.instance_id(PAIR_VERIFY_CHAR).await?;
        let session: BleSession = pairing::pair_verify(
            gatt.as_ref(),
            PAIR_VERIFY_CHAR,
            verify_iid,
            &self.keypair,
            pairing,
            DEFAULT_FRAG_SIZE,
        )
        .await?;
        // Now that the session is up, walk the full tree (resolving every iid)
        // and build the typed database from characteristic signatures.
        let services = gatt.enumerate().await?;
        let mut acc = BleAccessory::new(gatt, session, DEFAULT_FRAG_SIZE, services);
        acc.refresh_db(/*encrypted=*/ true).await?;
        Ok(acc)
    }
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
