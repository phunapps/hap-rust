//! [`HapController`]: the top-level handle. Owns the pairing store and the
//! controller's long-term identity; produces [`AccessoryHandle`]s.

use std::sync::Arc;
use std::time::Duration;

use hap_crypto::ControllerKeypair;
#[cfg(feature = "ble")]
use hap_pairing::StoredBroadcast;
use hap_pairing::{PairingStore, PairingsAdmin, StoredAccessory, StoredTransport};
use hap_transport::{DiscoveredAccessory, HapConnection};

use crate::discovered::Discovered;
use crate::error::{HapError, Result};
use crate::handle::IpHandle;
use crate::unified::AccessoryHandle;

/// Re-establishes a secure session for an [`AccessoryHandle`] by re-running
/// Pair Verify against the stored pairing. Owned by the handle's supervisor.
struct PairingReconnector {
    stored: StoredAccessory,
    keypair: ControllerKeypair,
}

#[async_trait::async_trait]
impl crate::reconnect::Reconnector for PairingReconnector {
    async fn reconnect(&self) -> Result<crate::reconnect::Reconnected> {
        // Best-effort: read the accessory's current config number (c#) from mDNS
        // so the handle can refresh its cached DB when the config changes.
        let config_number = hap_transport::discover(std::time::Duration::from_secs(3))
            .await
            .ok()
            .and_then(|found| {
                found
                    .into_iter()
                    .find(|d| d.id == self.stored.pairing.pairing_id)
                    .map(|d| d.config_number)
            });
        let session = hap_pairing::connect(&self.stored, &self.keypair).await?;
        Ok(crate::reconnect::Reconnected {
            session: Arc::new(session),
            config_number,
        })
    }
}

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
    request_timeout: std::time::Duration,
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
            request_timeout: crate::handle::DEFAULT_REQUEST_TIMEOUT,
        })
    }

    /// Set the per-request timeout for handles created after this call
    /// (default 10s). Bounds how long a foreground read/write waits on a
    /// silently-dropped connection before failing with [`HapError::ConnectionLost`].
    pub fn set_request_timeout(&mut self, timeout: std::time::Duration) {
        self.request_timeout = timeout;
    }

    /// Discover accessories on every enabled transport for up to `timeout`:
    /// an mDNS browse and (with the `ble` feature) a BLE scan run
    /// concurrently. If one transport's scan fails while the other succeeds,
    /// the successful side is returned; if both fail, the IP error surfaces.
    ///
    /// # Errors
    ///
    /// [`HapError::Transport`] / `HapError::Ble` as above.
    pub async fn discover(&self, timeout: Duration) -> Result<Vec<Discovered>> {
        #[cfg(feature = "ble")]
        {
            let (ip, ble) = tokio::join!(hap_transport::discover(timeout), hap_ble::scan(timeout));
            let mut out: Vec<Discovered> = Vec::new();
            let mut ip_err = None;
            match ip {
                Ok(found) => out.extend(found.into_iter().map(Discovered::Ip)),
                Err(e) => ip_err = Some(HapError::from(e)),
            }
            match ble {
                Ok(found) => out.extend(found.into_iter().map(Discovered::Ble)),
                Err(e) => {
                    if let Some(ip_err) = ip_err {
                        // Both transports failed: surface the IP error.
                        let _ = e;
                        return Err(ip_err);
                    }
                }
            }
            // A successful BLE scan (even an empty one) means the BLE side
            // did not fail, so it masks an IP-side error per the doc above:
            // "if one transport's scan fails while the other succeeds, the
            // successful side is returned". Only a BLE *failure* falls
            // through to the both-failed check above.
            Ok(out)
        }
        #[cfg(not(feature = "ble"))]
        {
            Ok(hap_transport::discover(timeout)
                .await?
                .into_iter()
                .map(Discovered::Ip)
                .collect())
        }
    }

    /// Discover `_hap._tcp` accessories on the local network for up to
    /// `timeout`. IP only; see [`discover`](Self::discover) for a unified method.
    ///
    /// # Errors
    ///
    /// Returns [`HapError::Transport`] if the mDNS browse fails.
    pub async fn discover_ip(&self, timeout: Duration) -> Result<Vec<DiscoveredAccessory>> {
        Ok(hap_transport::discover(timeout).await?)
    }

    /// Discover only BLE accessories (typed escape hatch).
    ///
    /// # Errors
    /// [`HapError::Ble`] if the scan fails.
    #[cfg(feature = "ble")]
    pub async fn discover_ble(
        &self,
        timeout: Duration,
    ) -> Result<Vec<hap_ble::DiscoveredBleAccessory>> {
        Ok(hap_ble::scan(timeout).await?)
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
    /// bare eight digits (BLE setup-code normalization happens inside
    /// `hap-ble`).
    ///
    /// # Errors
    ///
    /// [`HapError::InvalidSetupCode`] for a malformed code; [`HapError::Transport`]
    /// if the accessory cannot be reached; [`HapError::Pairing`] or
    /// [`HapError::Crypto`] if Pair Setup / Pair Verify fail. With the `ble`
    /// feature, pairing a BLE-discovered accessory can also fail with
    /// `HapError::Ble` or `HapError::UnknownAccessory` (an unparseable
    /// advertised device id).
    pub async fn pair(
        &mut self,
        accessory: &Discovered,
        setup_code: &str,
    ) -> Result<AccessoryHandle> {
        match accessory {
            Discovered::Ip(ip) => self.pair_ip(ip, setup_code).await,
            #[cfg(feature = "ble")]
            Discovered::Ble(ble) => self.pair_ble(ble, setup_code).await,
        }
    }

    async fn pair_ip(
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
            transport: StoredTransport::Ip {
                addr: accessory.addr,
            },
        };
        self.store.save_pairing(&stored).await?;
        let id = stored.pairing.pairing_id.clone();
        if !self.cached_ids.contains(&id) {
            self.cached_ids.push(id);
        }
        let reconnector = Box::new(PairingReconnector {
            stored: stored.clone(),
            keypair: self.keypair.clone(),
        });
        Ok(AccessoryHandle::from_ip(IpHandle::connect(
            Arc::new(session),
            reconnector,
            self.request_timeout,
        )))
    }

    #[cfg(feature = "ble")]
    async fn pair_ble(
        &mut self,
        accessory: &hap_ble::DiscoveredBleAccessory,
        setup_code: &str,
    ) -> Result<AccessoryHandle> {
        let device_id = hap_pairing::parse_device_id(&accessory.device_id)
            .ok_or_else(|| HapError::UnknownAccessory(accessory.device_id.clone()))?;
        let gatt = hap_ble::connect_gatt(accessory).await?;
        let ble = hap_ble::BleController::new(self.keypair.clone());
        let paired = ble
            .pair(
                gatt as Arc<dyn hap_ble::GattConnection>,
                accessory,
                setup_code,
            )
            .await?;
        let stored = StoredAccessory {
            pairing: paired.pairing,
            transport: StoredTransport::Ble {
                device_id,
                broadcast: Some(StoredBroadcast {
                    key: paired.broadcast.key.clone(),
                    gsn: paired.broadcast.gsn,
                }),
            },
        };
        self.store.save_pairing(&stored).await?;
        let id = stored.pairing.pairing_id.clone();
        if !self.cached_ids.contains(&id) {
            self.cached_ids.push(id);
        }
        Ok(AccessoryHandle::from_ble(paired.accessory))
    }

    /// How long [`connect`](Self::connect) scans for a stored BLE accessory's
    /// advertisement before giving up.
    #[cfg(feature = "ble")]
    const BLE_CONNECT_SCAN: Duration = Duration::from_secs(10);

    /// Open a new secure session to an already-paired accessory.
    ///
    /// # Errors
    ///
    /// [`HapError::UnknownAccessory`] if `accessory_id` is not in the store;
    /// otherwise [`HapError::Pairing`] / [`HapError::Crypto`] /
    /// [`HapError::Transport`] if Pair Verify or the connection fail. With the
    /// `ble` feature, a stored BLE accessory that cannot be found within the
    /// scan window fails with `HapError::Ble`; without it, connecting to a
    /// stored BLE accessory fails with [`HapError::UnsupportedByTransport`].
    pub async fn connect(&self, accessory_id: &str) -> Result<AccessoryHandle> {
        let stored = self.load_stored(accessory_id).await?;
        match &stored.transport {
            StoredTransport::Ip { .. } => self.connect_ip(stored).await,
            #[cfg(feature = "ble")]
            StoredTransport::Ble {
                device_id,
                broadcast,
            } => {
                self.connect_ble(&stored, *device_id, broadcast.clone())
                    .await
            }
            #[cfg(not(feature = "ble"))]
            StoredTransport::Ble { .. } => Err(HapError::UnsupportedByTransport(
                "connect (enable the `ble` feature)",
            )),
        }
    }

    async fn connect_ip(&self, stored: StoredAccessory) -> Result<AccessoryHandle> {
        let session = hap_pairing::connect(&stored, &self.keypair).await?;
        let reconnector = Box::new(PairingReconnector {
            stored,
            keypair: self.keypair.clone(),
        });
        Ok(AccessoryHandle::from_ip(IpHandle::connect(
            Arc::new(session),
            reconnector,
            self.request_timeout,
        )))
    }

    #[cfg(feature = "ble")]
    async fn connect_ble(
        &self,
        stored: &StoredAccessory,
        device_id: [u8; 6],
        broadcast: Option<StoredBroadcast>,
    ) -> Result<AccessoryHandle> {
        let wanted = hap_pairing::format_device_id(&device_id);
        let found = hap_ble::scan(Self::BLE_CONNECT_SCAN)
            .await?
            .into_iter()
            .find(|d| d.device_id.eq_ignore_ascii_case(&wanted))
            .ok_or(HapError::Ble(hap_ble::BleError::AccessoryNotFound))?;
        let gatt = hap_ble::connect_gatt(&found).await?;
        let ble = hap_ble::BleController::new(self.keypair.clone());
        let state = broadcast.map(|b| hap_ble::BleBroadcastState {
            key: b.key,
            gsn: b.gsn,
        });
        let accessory = ble
            .connect(
                gatt as Arc<dyn hap_ble::GattConnection>,
                &stored.pairing,
                state,
            )
            .await?;
        Ok(AccessoryHandle::from_ble(accessory))
    }

    /// Remove a pairing both from the accessory (`/pairings` remove of this
    /// controller's own identity) and from the local store.
    ///
    /// # Errors
    ///
    /// [`HapError::UnknownAccessory`] if not paired; [`HapError::Transport`] /
    /// [`HapError::Pairing`] if reaching the accessory or the remote removal
    /// fails. With the `ble` feature, removing a BLE pairing can also fail
    /// with `HapError::Ble`.
    pub async fn remove_pairing(&mut self, accessory_id: &str) -> Result<()> {
        let stored = self.load_stored(accessory_id).await?;
        // `load_stored` may have matched case-insensitively or via the BLE
        // device-id fallback; use the record's own canonical id for every
        // operation below so the store delete and cache retain compare
        // exactly, not against whatever casing/form the caller passed in.
        let canonical_id = stored.pairing.pairing_id.clone();
        match &stored.transport {
            StoredTransport::Ip { .. } => {
                let mut session = hap_pairing::connect(&stored, &self.keypair).await?;
                let mut admin = PairingsAdmin::new(&mut session);
                admin.remove(&self.keypair.id).await?;
            }
            #[cfg(feature = "ble")]
            StoredTransport::Ble { .. } => {
                let mut handle = self.connect(&canonical_id).await?;
                let controller_id = self.keypair.id.clone();
                let Some(b) = handle.as_ble() else {
                    return Err(HapError::UnsupportedByTransport("remove_pairing"));
                };
                b.remove_pairing(&controller_id).await?;
            }
            #[cfg(not(feature = "ble"))]
            StoredTransport::Ble { .. } => {
                return Err(HapError::UnsupportedByTransport(
                    "remove_pairing (enable the `ble` feature)",
                ));
            }
        }
        self.store.delete_pairing(&canonical_id).await?;
        self.cached_ids.retain(|id| id != &canonical_id);
        Ok(())
    }

    /// List every controller currently paired to the accessory.
    ///
    /// # Errors
    ///
    /// [`HapError::UnknownAccessory`] if `accessory_id` is not in the store;
    /// [`HapError::UnsupportedByTransport`] for a BLE-paired accessory (HAP-BLE
    /// has no `/pairings` list operation in this milestone); otherwise
    /// [`HapError::Pairing`]/[`HapError::Crypto`]/[`HapError::Transport`].
    pub async fn list_pairings(&self, accessory_id: &str) -> Result<Vec<hap_pairing::PairingInfo>> {
        let stored = self.load_stored(accessory_id).await?;
        if matches!(stored.transport, StoredTransport::Ble { .. }) {
            return Err(HapError::UnsupportedByTransport("list_pairings"));
        }
        let mut session = hap_pairing::connect(&stored, &self.keypair).await?;
        let mut admin = PairingsAdmin::new(&mut session);
        Ok(admin.list().await?)
    }

    /// Ask an unpaired accessory to identify itself (blink/beep) before pairing.
    ///
    /// HAP only permits this on an UNPAIRED accessory; a paired accessory rejects
    /// it (surfaced as [`HapError::Http`]).
    ///
    /// # Errors
    ///
    /// [`HapError::Transport`] if the accessory cannot be reached;
    /// [`HapError::Http`] if it rejects the request. Identifying a
    /// BLE-discovered accessory returns [`HapError::UnsupportedByTransport`]
    /// (HAP-BLE has no pre-pairing identify PDU in this milestone).
    pub async fn identify(&self, accessory: &Discovered) -> Result<()> {
        match accessory {
            Discovered::Ip(ip) => self.identify_ip(ip).await,
            #[cfg(feature = "ble")]
            Discovered::Ble(_) => Err(HapError::UnsupportedByTransport("identify")),
        }
    }

    async fn identify_ip(&self, accessory: &DiscoveredAccessory) -> Result<()> {
        let mut conn = HapConnection::connect(accessory.addr).await?;
        let resp = conn
            .request("POST", "/identify", "application/hap+json", b"")
            .await?;
        if !(200..300).contains(&resp.status) {
            return Err(HapError::Http {
                status: resp.status,
            });
        }
        Ok(())
    }

    /// Register another controller's long-term public key on the accessory
    /// (multi-admin). `controller_id` and `ltpk` identify the controller added.
    ///
    /// # Errors
    ///
    /// [`HapError::UnknownAccessory`] if `accessory_id` is not in the store;
    /// [`HapError::UnsupportedByTransport`] for a BLE-paired accessory (HAP-BLE
    /// has no `/pairings` add operation in this milestone); otherwise
    /// [`HapError::Pairing`]/[`HapError::Crypto`]/[`HapError::Transport`].
    pub async fn add_pairing(
        &self,
        accessory_id: &str,
        controller_id: &str,
        ltpk: [u8; 32],
        admin: bool,
    ) -> Result<()> {
        let stored = self.load_stored(accessory_id).await?;
        if matches!(stored.transport, StoredTransport::Ble { .. }) {
            return Err(HapError::UnsupportedByTransport("add_pairing"));
        }
        let mut session = hap_pairing::connect(&stored, &self.keypair).await?;
        let mut a = PairingsAdmin::new(&mut session);
        a.add(controller_id, ltpk, admin).await?;
        Ok(())
    }

    /// Persist a handle's refreshable state. Today that is BLE broadcast
    /// material (key + latest GSN); on an IP handle this is a no-op. Call it
    /// before shutdown or after long event-watch sessions so a later
    /// [`connect`](Self::connect) resumes broadcast decryption without
    /// re-emitting already-seen events.
    ///
    /// # Errors
    ///
    /// [`HapError::UnknownAccessory`] if the handle's pairing is not in the
    /// store; [`HapError::Pairing`] on store write failure.
    // Async for API symmetry with the `ble`-enabled build (below): without the
    // `ble` feature there is no refreshable state to persist, so this arm is a
    // no-op with no `.await`.
    #[cfg_attr(not(feature = "ble"), allow(clippy::unused_async))]
    pub async fn save_state(&self, handle: &AccessoryHandle) -> Result<()> {
        #[cfg(feature = "ble")]
        if let (Some(id), Some(state)) = (handle.pairing_id(), handle.broadcast_state().await) {
            let mut stored = self.load_stored(id).await?;
            if let StoredTransport::Ble { broadcast, .. } = &mut stored.transport {
                *broadcast = Some(StoredBroadcast {
                    key: state.key,
                    gsn: state.gsn,
                });
            }
            self.store.save_pairing(&stored).await?;
        }
        #[cfg(not(feature = "ble"))]
        let _ = handle;
        Ok(())
    }

    /// Load the stored pairing matching `accessory_id`, or
    /// [`HapError::UnknownAccessory`].
    ///
    /// The `pairing_id` match is ASCII-case-insensitive: BLE accessory ids
    /// surface in two casings — [`Discovered::id`] yields the lowercase
    /// advertised device-id string, while the store keys BLE records by the
    /// accessory-cased Pair Setup id captured at `pair` time. If no
    /// `pairing_id` matches and `accessory_id` parses as a BLE device-id
    /// string, this falls back to matching a stored BLE record's
    /// `device_id` bytes, so either casing or either id form finds the
    /// same record.
    async fn load_stored(&self, accessory_id: &str) -> Result<StoredAccessory> {
        let all = self.store.load_pairings().await?;
        if let Some(found) = all
            .iter()
            .find(|s| s.pairing.pairing_id.eq_ignore_ascii_case(accessory_id))
        {
            return Ok(found.clone());
        }
        if let Some(bytes) = hap_pairing::parse_device_id(accessory_id) {
            if let Some(found) = all.iter().find(|s| {
                matches!(&s.transport, StoredTransport::Ble { device_id, .. } if *device_id == bytes)
            }) {
                return Ok(found.clone());
            }
        }
        Err(HapError::UnknownAccessory(accessory_id.to_string()))
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
