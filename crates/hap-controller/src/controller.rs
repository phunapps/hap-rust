//! [`HapController`]: the top-level handle. Owns the pairing store and the
//! controller's long-term identity; produces [`AccessoryHandle`]s.

use std::time::Duration;

use hap_crypto::ControllerKeypair;
use hap_pairing::{PairingStore, PairingsAdmin, StoredAccessory};
use hap_transport::{DiscoveredAccessory, HapConnection};

use crate::error::{HapError, Result};
use crate::handle::AccessoryHandle;

/// The pairing id assigned to a freshly created controller identity.
///
/// HAP identifies a controller by an opaque string; a single on-disk store
/// holds one controller identity, so a stable default is sufficient. Override
/// it by pre-seeding the store with a [`ControllerKeypair`] of your choosing.
const DEFAULT_CONTROLLER_ID: &str = "hap-rust-controller";

/// The single high-level entry point for controlling HomeKit accessories.
///
/// Construct one with [`HapController::new`], passing a [`PairingStore`] (use
/// [`crate::JsonFileStore`] for on-disk persistence). The controller loads an
/// existing controller identity from the store, or creates and persists a fresh
/// one on first run.
pub struct HapController {
    store: Box<dyn PairingStore + Send + Sync>,
    keypair: ControllerKeypair,
    /// Snapshot of the stored accessory ids, kept in sync by `pair`/
    /// `remove_pairing` so the synchronous [`paired`](Self::paired) accessor
    /// need not touch the async store. Assumes this process is the sole writer
    /// of the store (the v1.0 single-controller model).
    cached_ids: Vec<String>,
}

impl HapController {
    /// Open a controller over `store`, loading or creating the controller's
    /// long-term Ed25519 identity.
    ///
    /// # Errors
    ///
    /// Returns [`HapError::Pairing`] if the store cannot be read or the new
    /// identity cannot be persisted.
    pub async fn new(store: impl PairingStore + Send + Sync + 'static) -> Result<Self> {
        let store: Box<dyn PairingStore + Send + Sync> = Box::new(store);
        let keypair = if let Some(kp) = store.load_controller().await? {
            kp
        } else {
            let kp = ControllerKeypair::generate(DEFAULT_CONTROLLER_ID.to_string());
            store.save_controller(&kp).await?;
            kp
        };
        let cached_ids = store
            .load_pairings()
            .await?
            .into_iter()
            .map(|s| s.pairing.pairing_id)
            .collect();
        Ok(Self {
            store,
            keypair,
            cached_ids,
        })
    }

    /// Discover `_hap._tcp` accessories on the local network for up to
    /// `timeout`.
    ///
    /// # Errors
    ///
    /// Returns [`HapError::Transport`] if the mDNS browse fails.
    pub async fn discover(&self, timeout: Duration) -> Result<Vec<DiscoveredAccessory>> {
        Ok(hap_transport::discover(timeout).await?)
    }

    /// The accessory ids of every pairing currently in the store.
    ///
    /// This is a synchronous snapshot maintained by [`pair`](Self::pair) and
    /// [`remove_pairing`](Self::remove_pairing); it assumes this controller is
    /// the only writer of the underlying store.
    pub fn paired(&self) -> Vec<String> {
        self.cached_ids.clone()
    }

    /// Pair with a freshly discovered accessory using its eight-digit setup
    /// code, persist the resulting pairing, and return a connected handle.
    ///
    /// The setup code accepts the hyphenated label form (`123-45-678`) or the
    /// bare eight digits.
    ///
    /// # Errors
    ///
    /// [`HapError::InvalidSetupCode`] for a malformed code; [`HapError::Transport`]
    /// if the accessory cannot be reached; [`HapError::Pairing`] or
    /// [`HapError::Crypto`] if Pair Setup / Pair Verify fail.
    pub async fn pair(
        &mut self,
        accessory: &DiscoveredAccessory,
        setup_code: &str,
    ) -> Result<AccessoryHandle> {
        let normalized = normalize_setup_code(setup_code)?;
        let conn = HapConnection::connect(accessory.addr).await?;
        // `pair` runs Pair Setup (SRP-6a) then Pair Verify over the same
        // connection, returning the pairing and a live secure session.
        let (pairing, session) = hap_pairing::pair(conn, &normalized, &self.keypair).await?;
        let stored = StoredAccessory {
            pairing,
            addr: accessory.addr,
        };
        self.store.save_pairing(&stored).await?;
        let id = stored.pairing.pairing_id.clone();
        if !self.cached_ids.contains(&id) {
            self.cached_ids.push(id);
        }
        Ok(AccessoryHandle::connect(session))
    }

    /// Open a new secure session to an already-paired accessory.
    ///
    /// # Errors
    ///
    /// [`HapError::UnknownAccessory`] if `accessory_id` is not in the store;
    /// otherwise [`HapError::Pairing`] / [`HapError::Crypto`] /
    /// [`HapError::Transport`] if Pair Verify or the connection fail.
    pub async fn connect(&self, accessory_id: &str) -> Result<AccessoryHandle> {
        let stored = self.load_stored(accessory_id).await?;
        let session = hap_pairing::connect(&stored, &self.keypair).await?;
        Ok(AccessoryHandle::connect(session))
    }

    /// Remove a pairing both from the accessory (`/pairings` remove of this
    /// controller's own identity) and from the local store.
    ///
    /// # Errors
    ///
    /// [`HapError::UnknownAccessory`] if not paired; [`HapError::Transport`] /
    /// [`HapError::Pairing`] if reaching the accessory or the remote removal
    /// fails.
    pub async fn remove_pairing(&mut self, accessory_id: &str) -> Result<()> {
        let stored = self.load_stored(accessory_id).await?;
        let mut session = hap_pairing::connect(&stored, &self.keypair).await?;
        {
            let mut admin = PairingsAdmin::new(&mut session);
            admin.remove(&self.keypair.id).await?;
        }
        self.store.delete_pairing(accessory_id).await?;
        self.cached_ids.retain(|id| id != accessory_id);
        Ok(())
    }

    /// Load the stored pairing for `accessory_id`, or [`HapError::UnknownAccessory`].
    async fn load_stored(&self, accessory_id: &str) -> Result<StoredAccessory> {
        self.store
            .load_pairings()
            .await?
            .into_iter()
            .find(|s| s.pairing.pairing_id == accessory_id)
            .ok_or_else(|| HapError::UnknownAccessory(accessory_id.to_string()))
    }
}

/// Normalize a setup code to the canonical eight `XXXXXXXX` digits, accepting
/// the `XXX-XX-XXX` hyphenated form HAP prints on accessory labels.
fn normalize_setup_code(code: &str) -> Result<String> {
    let digits: String = code.chars().filter(char::is_ascii_digit).collect();
    if digits.len() == 8 {
        Ok(digits)
    } else {
        Err(HapError::InvalidSetupCode)
    }
}
