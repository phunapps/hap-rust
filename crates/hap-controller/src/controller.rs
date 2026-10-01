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
use crate::payload_match::PayloadMatch;
use crate::setup_payload::SetupPayload;
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
    store: Arc<dyn PairingStore + Send + Sync>,
    keypair: ControllerKeypair,
    /// Snapshot of the stored accessory ids, kept in sync by `pair`/
    /// `remove_pairing`/`forget_pairing` so the synchronous [`paired`](Self::paired) accessor
    /// need not touch the async store. Assumes this process is the sole writer
    /// of the store (the v1.0 single-controller model).
    cached_ids: Vec<String>,
    request_timeout: std::time::Duration,
    /// Serializes exclusive use of the (single) BLE radio across background
    /// sleepy watches so their cold connects do not overlap. Held only for the
    /// duration of a connect + arm, not for the lifetime of a watch.
    #[cfg(feature = "ble")]
    radio_lock: Arc<tokio::sync::Mutex<()>>,
    /// The cold-arm connect seam. Defaults to the real bluest-backed connector;
    /// overridable via [`set_sleepy_connector_for_tests`](Self::set_sleepy_connector_for_tests).
    #[cfg(feature = "ble")]
    sleepy_connector: Arc<dyn hap_ble::SleepyConnector>,
}

/// The outcome of matching a scanned payload against discovered accessories.
#[derive(Debug)]
enum Selection<'a> {
    One(&'a Discovered),
    None,
    Ambiguous(Vec<String>),
}

/// Prefer a unique `Exact` match; else a unique `Category` match; else
/// `None`/`Ambiguous`. Paired accessories are ignored (`match_kind` does not
/// filter them, so filter here).
fn select_match<'a>(found: &'a [Discovered], payload: &SetupPayload) -> Selection<'a> {
    let unpaired = || found.iter().filter(|d| !d.paired());
    let exact: Vec<&Discovered> = unpaired()
        .filter(|d| payload.match_kind(d) == Some(PayloadMatch::Exact))
        .collect();
    if exact.len() == 1 {
        return Selection::One(exact[0]);
    }
    if exact.len() > 1 {
        return Selection::Ambiguous(exact.iter().map(|d| d.id().to_string()).collect());
    }
    let cat: Vec<&Discovered> = unpaired()
        .filter(|d| payload.match_kind(d) == Some(PayloadMatch::Category))
        .collect();
    match cat.len() {
        0 => Selection::None,
        1 => Selection::One(cat[0]),
        _ => Selection::Ambiguous(cat.iter().map(|d| d.id().to_string()).collect()),
    }
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
        let store: Arc<dyn PairingStore + Send + Sync> = Arc::new(store);
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
            #[cfg(feature = "ble")]
            sleepy_connector: Arc::new(hap_ble::BluestSleepyConnector::new(keypair.clone())),
            store,
            keypair,
            cached_ids,
            request_timeout: crate::handle::DEFAULT_REQUEST_TIMEOUT,
            #[cfg(feature = "ble")]
            radio_lock: Arc::new(tokio::sync::Mutex::new(())),
        })
    }

    /// Inject a custom sleepy connect seam (test double). Mirrors
    /// `from_ble_for_tests`; not part of the supported public API.
    #[doc(hidden)]
    #[cfg(feature = "ble")]
    pub fn set_sleepy_connector_for_tests(&mut self, c: Arc<dyn hap_ble::SleepyConnector>) {
        self.sleepy_connector = c;
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

    /// Discover accessories on every enabled transport, returning **as soon
    /// as** `stop` says so instead of always waiting out the full window.
    ///
    /// Both transports (mDNS, and with the `ble` feature a BLE scan) run
    /// concurrently and report incrementally. Results are deduplicated by
    /// accessory id (ASCII case-insensitive, so the same accessory heard on
    /// both transports counts once; the first sighting wins), and `stop` is
    /// called once per newly-seen accessory. When `stop` returns `true` the
    /// method returns everything found so far immediately, and the underlying
    /// scans are torn down (the mDNS browse is shut down; the BLE scan stream
    /// and its adapter are dropped, releasing the central — on Linux, the
    /// D-Bus session). If `stop` never matches, this behaves like
    /// [`discover`](Self::discover): everything found within `timeout` is
    /// returned.
    ///
    /// # Errors
    ///
    /// Matches [`discover`](Self::discover): if one transport fails to start
    /// while the other starts, the working side's results are returned; if
    /// both fail, the IP-side [`HapError::Transport`] error surfaces.
    /// Transport failures *after* a scan has started end that transport's
    /// stream silently.
    pub async fn discover_until<F>(&self, timeout: Duration, stop: F) -> Result<Vec<Discovered>>
    where
        F: FnMut(&Discovered) -> bool,
    {
        let (tx, rx) = tokio::sync::mpsc::channel::<Discovered>(16);
        #[cfg(feature = "ble")]
        {
            let (ip, ble) = tokio::join!(
                hap_transport::discover_stream(timeout),
                hap_ble::scan_stream(timeout)
            );
            let (ip, ble) = match (ip, ble) {
                // Both transports failed to start: surface the IP error.
                (Err(ip_err), Err(_ble_err)) => return Err(ip_err.into()),
                (ip, ble) => (ip.ok(), ble.ok()),
            };
            if let Some(mut ip_rx) = ip {
                let tx = tx.clone();
                tokio::spawn(async move {
                    while let Some(d) = ip_rx.recv().await {
                        if tx.send(Discovered::Ip(d)).await.is_err() {
                            break; // early exit: dropping ip_rx stops the browse
                        }
                    }
                });
            }
            if let Some(mut ble_rx) = ble {
                let tx = tx.clone();
                tokio::spawn(async move {
                    while let Some(d) = ble_rx.recv().await {
                        if tx.send(Discovered::Ble(d)).await.is_err() {
                            break; // early exit: dropping ble_rx stops the scan
                        }
                    }
                });
            }
        }
        #[cfg(not(feature = "ble"))]
        {
            let mut ip_rx = hap_transport::discover_stream(timeout).await?;
            let tx = tx.clone();
            tokio::spawn(async move {
                while let Some(d) = ip_rx.recv().await {
                    if tx.send(Discovered::Ip(d)).await.is_err() {
                        break; // early exit: dropping ip_rx stops the browse
                    }
                }
            });
        }
        // Drop the local sender so the merged channel closes once every
        // forwarder finishes (i.e. when the discovery window elapses).
        drop(tx);
        Ok(crate::discover_until::collect_until(rx, stop).await)
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
    /// This is a synchronous snapshot maintained by [`pair`](Self::pair),
    /// [`remove_pairing`](Self::remove_pairing), and
    /// [`forget_pairing`](Self::forget_pairing); it assumes this controller is
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
        let advert: Arc<dyn hap_ble::AdvertSource> = gatt.clone();
        let ble = hap_ble::BleController::new(self.keypair.clone());
        let mut paired = ble
            .pair(
                gatt as Arc<dyn hap_ble::GattConnection>,
                accessory,
                setup_code,
            )
            .await?;
        paired.accessory.set_advert_source(advert);
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

    /// Discover on the enabled transports (retrying within `timeout` for sleepy
    /// BLE devices), identify the single accessory the scanned setup payload
    /// refers to, and pair it with the payload's setup code.
    ///
    /// # Errors
    /// [`HapError::NoMatchingAccessory`] if none matched within `timeout`;
    /// [`HapError::AmbiguousMatch`] if several category-plausible accessories
    /// matched with no setup hash to disambiguate; otherwise the usual
    /// pairing/transport/crypto errors from [`pair`](Self::pair). Since
    /// discovery retries in windows until `timeout`, `AmbiguousMatch`'s
    /// candidates are always from the single most recent ambiguous scan
    /// round, not accumulated across the whole retry loop.
    pub async fn pair_with_payload(
        &mut self,
        payload: &SetupPayload,
        timeout: Duration,
    ) -> Result<AccessoryHandle> {
        const SCAN_WINDOW: Duration = Duration::from_secs(8);
        let deadline = tokio::time::Instant::now() + timeout;
        let mut last_ambiguous: Option<Vec<String>> = None;
        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            let window = remaining.min(SCAN_WINDOW);
            let found = self.discover(window).await?;
            let chosen = match select_match(&found, payload) {
                Selection::One(d) => Some(d.clone()),
                Selection::Ambiguous(ids) => {
                    last_ambiguous = Some(ids);
                    None
                }
                Selection::None => None,
            };
            if let Some(target) = chosen {
                return self.pair(&target, &payload.setup_code).await;
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(match last_ambiguous {
                    Some(candidates) => HapError::AmbiguousMatch { candidates },
                    None => HapError::NoMatchingAccessory,
                });
            }
        }
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
            StoredTransport::Ip { .. } => {
                connect_ip(stored, self.keypair.clone(), self.request_timeout).await
            }
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

    /// Wait until a stored pairing can be reached, then open a secure session
    /// to it and return a handle exactly like [`connect`](Self::connect).
    ///
    /// For a **BLE** pairing this waits — with no internal timeout — until the
    /// accessory next advertises, then connects and runs Pair Verify. It is
    /// meant for sleepy accessories, which advertise rarely when idle, so a
    /// bounded [`connect`](Self::connect) scan usually misses them. Bound the
    /// wait yourself with `tokio::time::timeout`. For an **IP** pairing there
    /// is nothing to wait for: it behaves exactly like `connect`.
    ///
    /// `accessory_id` resolves as it does for `connect`
    /// (ASCII-case-insensitive, with the BLE device-id fallback).
    ///
    /// # The returned future does not borrow the controller
    ///
    /// The future is `Send + 'static` and owns everything it needs, so a wait
    /// that may last hours does not keep `&self` borrowed. If you serialize
    /// controller calls behind a mutex, create the future while holding the
    /// lock, release the lock, then await (or `tokio::spawn`) the future.
    /// Nothing is done until the future is first polled: the stored pairing
    /// is read then, and later changes to it — including
    /// [`forget_pairing`](Self::forget_pairing) — do not affect or end a wait
    /// already in progress.
    ///
    /// # Waiting and retrying (BLE)
    ///
    /// A sleepy accessory is often heard and then gone again before the link
    /// comes up. Those failures (`BleError::AccessoryNotFound`,
    /// `BleError::Disconnected`, `BleError::Backend`) are not returned: the
    /// wait goes back to listening for the next advertisement. That includes a
    /// missing or unavailable Bluetooth adapter, so only the caller's timeout
    /// bounds the wait.
    ///
    /// Waits for different accessories do not block one another, nor other
    /// controller calls: each listens on its own scan. Run at most one wait
    /// per accessory, and do not combine one with
    /// [`watch_sleepy`](Self::watch_sleepy) for the same accessory while that
    /// watch is still connecting — both would connect to the one peripheral.
    /// On macOS a BLE connect cannot complete while a scan is running on the
    /// same connection; whether another wait's scan can stall a connect there
    /// has not been validated on hardware.
    ///
    /// # Cancellation
    ///
    /// Dropping the future abandons the wait. While it is listening for the
    /// advertisement that stops the scan and leaves nothing behind. If it is
    /// dropped after the link came up but before the handle was returned (the
    /// connect, database read and Pair Verify), the link is released on macOS;
    /// on Linux (`BlueZ`) it stays up until the accessory drops it.
    ///
    /// # Errors
    ///
    /// [`HapError::UnknownAccessory`] if `accessory_id` is not in the store.
    /// For an IP pairing, the errors of [`connect`](Self::connect). For a BLE
    /// pairing, `HapError::Ble` once the accessory was reached but the session
    /// could not be established for a reason that waiting will not fix — for
    /// example it rejected Pair Verify because the pairing was removed.
    /// Without the `ble` feature, a BLE pairing fails with
    /// [`HapError::UnsupportedByTransport`].
    pub fn connect_when_advertised(
        &self,
        accessory_id: &str,
    ) -> impl std::future::Future<Output = Result<AccessoryHandle>> + Send + 'static {
        let store = self.store.clone();
        let keypair = self.keypair.clone();
        let request_timeout = self.request_timeout;
        #[cfg(feature = "ble")]
        let connector = self.sleepy_connector.clone();
        let accessory_id = accessory_id.to_string();
        async move {
            let stored = load_stored(store.as_ref(), &accessory_id).await?;
            match &stored.transport {
                StoredTransport::Ip { .. } => connect_ip(stored, keypair, request_timeout).await,
                #[cfg(feature = "ble")]
                StoredTransport::Ble {
                    device_id,
                    broadcast,
                } => {
                    connect_ble_when_advertised(
                        connector.as_ref(),
                        *device_id,
                        &stored.pairing,
                        broadcast.as_ref(),
                    )
                    .await
                }
                #[cfg(not(feature = "ble"))]
                StoredTransport::Ble { .. } => Err(HapError::UnsupportedByTransport(
                    "connect_when_advertised (enable the `ble` feature)",
                )),
            }
        }
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
        let advert: Arc<dyn hap_ble::AdvertSource> = gatt.clone();
        let ble = hap_ble::BleController::new(self.keypair.clone());
        let state = broadcast.map(|b| hap_ble::BleBroadcastState {
            key: b.key,
            gsn: b.gsn,
        });
        let mut accessory = ble
            .connect(
                gatt as Arc<dyn hap_ble::GattConnection>,
                &stored.pairing,
                state,
            )
            .await?;
        accessory.set_advert_source(advert);
        Ok(AccessoryHandle::from_ble(accessory))
    }

    /// Remove a pairing both from the accessory (`/pairings` remove of this
    /// controller's own identity) and from the local store.
    ///
    /// The remote removal runs first. If it fails, nothing local is changed:
    /// the pairing stays in the store and in [`paired`](Self::paired), so the
    /// call can be retried. To drop the local record anyway, follow up with
    /// [`forget_pairing`](Self::forget_pairing).
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

    /// Forget a pairing locally WITHOUT contacting the accessory: delete it
    /// from the store and drop it from the [`paired`](Self::paired) snapshot.
    ///
    /// Use it after [`remove_pairing`](Self::remove_pairing) has failed, when
    /// the caller has decided to give up on the accessory anyway (it went
    /// unreachable, or a sleepy BLE accessory dropped off right after Pair
    /// Setup). **The accessory still trusts this controller** and will need a
    /// factory reset before it can be paired again, so prefer `remove_pairing`
    /// whenever the accessory can be reached.
    ///
    /// `accessory_id` resolves exactly as it does for `remove_pairing`:
    /// ASCII-case-insensitively, with the BLE device-id fallback. Idempotent:
    /// an id with no stored pairing is `Ok(())`, and any stale `paired()` entry
    /// for it is dropped.
    ///
    /// An [`AccessoryHandle`] or sleepy watch already open for the accessory
    /// is not closed by this call; drop it yourself.
    ///
    /// # Errors
    ///
    /// [`HapError::Pairing`] if the store cannot be read or the record cannot
    /// be deleted; in that case the `paired()` snapshot is left unchanged.
    pub async fn forget_pairing(&mut self, accessory_id: &str) -> Result<()> {
        match self.load_stored(accessory_id).await {
            Ok(stored) => {
                let canonical_id = stored.pairing.pairing_id;
                self.store.delete_pairing(&canonical_id).await?;
                self.cached_ids.retain(|id| id != &canonical_id);
            }
            // Nothing in the store to delete. The snapshot can still list the
            // id if the record was removed behind this controller's back.
            Err(HapError::UnknownAccessory(_)) => {
                self.cached_ids
                    .retain(|id| !id.eq_ignore_ascii_case(accessory_id));
            }
            Err(e) => return Err(e),
        }
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

    /// Cold-arm an advert-driven sleepy watch from a stored BLE pairing,
    /// returning immediately without blocking on the connect.
    ///
    /// The returned [`SleepyWatch`](crate::SleepyWatch) is armed by a background
    /// task that waits for the device's next advertisement, connects once
    /// (serialized against other sleepy watches by an internal radio mutex),
    /// enables broadcasts for `poll_iids`, disconnects so the sleepy device
    /// advertises again, arms the self-sourcing advert watch, and pumps its
    /// events into [`SleepyWatch::events`](crate::SleepyWatch::events) —
    /// auto-persisting each event's GSN to the store. Because the cold connect
    /// blocks until the device advertises (possibly minutes), it runs inside the
    /// background task; this method itself never blocks on the radio.
    ///
    /// `poll_iids` are the `(aid, iid)` characteristics to read back off a
    /// GSN-bump advertisement.
    ///
    /// An unreachable or permanently-absent device holds the shared radio lock
    /// for the entire wait until it advertises, so it can block other pending
    /// `watch_sleepy` cold connects from proceeding; at most one watch per
    /// accessory is expected.
    ///
    /// # Errors
    /// [`HapError::UnknownAccessory`] if `accessory_id` is not in the store;
    /// [`HapError::UnsupportedByTransport`] if the stored pairing is not BLE.
    #[cfg(feature = "ble")]
    pub async fn watch_sleepy(
        &self,
        accessory_id: &str,
        poll_iids: Vec<(u64, u64)>,
    ) -> Result<crate::sleepy::SleepyWatch> {
        let stored = self.load_stored(accessory_id).await?;
        let (device_id, broadcast) = match &stored.transport {
            StoredTransport::Ble {
                device_id,
                broadcast,
            } => (*device_id, broadcast.clone()),
            StoredTransport::Ip { .. } => {
                return Err(HapError::UnsupportedByTransport("watch_sleepy"));
            }
        };
        Ok(crate::sleepy::spawn_watch(
            self.sleepy_connector.clone(),
            self.store.clone(),
            self.radio_lock.clone(),
            stored.pairing.pairing_id.clone(),
            stored.pairing.clone(),
            device_id,
            broadcast,
            poll_iids,
        ))
    }

    /// Load the stored pairing matching `accessory_id`; see [`load_stored`].
    async fn load_stored(&self, accessory_id: &str) -> Result<StoredAccessory> {
        load_stored(self.store.as_ref(), accessory_id).await
    }
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
///
/// A free function (not a method) so [`HapController::connect_when_advertised`]
/// can run it inside a future that does not borrow the controller.
async fn load_stored(
    store: &(dyn PairingStore + Send + Sync),
    accessory_id: &str,
) -> Result<StoredAccessory> {
    let all = store.load_pairings().await?;
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

/// Open a secure IP session to `stored` and wrap it in a reconnecting handle.
async fn connect_ip(
    stored: StoredAccessory,
    keypair: ControllerKeypair,
    request_timeout: Duration,
) -> Result<AccessoryHandle> {
    let session = hap_pairing::connect(&stored, &keypair).await?;
    let reconnector = Box::new(PairingReconnector { stored, keypair });
    Ok(AccessoryHandle::from_ip(IpHandle::connect(
        Arc::new(session),
        reconnector,
        request_timeout,
    )))
}

/// How long [`connect_ble_when_advertised`] pauses before listening again
/// after the accessory was lost mid-connect, so a connector that fails fast is
/// not spun.
#[cfg(feature = "ble")]
const ADVERT_RETRY_BACKOFF: Duration = Duration::from_secs(2);

/// Wait for a stored BLE accessory to advertise, then connect and Pair-Verify.
///
/// The connector blocks until the device is heard. Failures that only mean
/// "it went back to sleep before the link came up" send the wait back to
/// listening; anything else (a rejected Pair Verify, a malformed response) is
/// returned, because waiting longer will not change it.
#[cfg(feature = "ble")]
async fn connect_ble_when_advertised(
    connector: &dyn hap_ble::SleepyConnector,
    device_id: [u8; 6],
    pairing: &hap_crypto::AccessoryPairing,
    broadcast: Option<&StoredBroadcast>,
) -> Result<AccessoryHandle> {
    loop {
        let state = broadcast.map(|b| hap_ble::BleBroadcastState {
            key: b.key.clone(),
            gsn: b.gsn,
        });
        match connector.connect(device_id, pairing, state).await {
            Ok(accessory) => return Ok(AccessoryHandle::from_ble(accessory)),
            Err(
                hap_ble::BleError::AccessoryNotFound
                | hap_ble::BleError::Disconnected
                | hap_ble::BleError::Backend(_),
            ) => tokio::time::sleep(ADVERT_RETRY_BACKOFF).await,
            Err(e) => return Err(e.into()),
        }
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

#[cfg(all(test, feature = "ble"))]
#[allow(clippy::unwrap_used)]
#[allow(
    clippy::unreadable_literal,
    clippy::items_after_statements,
    clippy::decimal_bitwise_operands
)] // brief's verbatim X-HM test-encoder helper; style-only, no assertions weakened
mod tests {
    use super::*;

    // Build a payload with a known setup_id + category + code (via the same
    // X-HM encoder used in the setup_payload/payload_match tests).
    fn payload(setup_id: &str, category: u16) -> SetupPayload {
        // setup_code value is irrelevant to matching; use 11122333.
        let value: u64 = ((u64::from(category)) << 31) | (0x2u64 << 27) | 11122333u64;
        const D: &[u8; 36] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        let mut buf = [b'0'; 9];
        let mut v = value;
        for i in (0..9).rev() {
            buf[i] = D[(v % 36) as usize];
            v /= 36;
        }
        let uri = format!(
            "X-HM://{}{setup_id}",
            String::from_utf8(buf.to_vec()).unwrap()
        );
        SetupPayload::parse(&uri).unwrap()
    }

    fn ble(device_id: &str, category: u16, setup_hash: Option<[u8; 4]>) -> Discovered {
        Discovered::Ble(hap_ble::DiscoveredBleAccessory {
            peripheral_id: "p".into(),
            device_id: device_id.into(),
            category,
            global_state_number: 0,
            config_number: 0,
            paired: false,
            setup_hash,
        })
    }

    #[test]
    fn select_prefers_exact_then_unique_category() {
        let hash = hap_crypto::setup_hash("7OSX", "AA:BB:CC:DD:EE:FF");
        let exact = ble("aa:bb:cc:dd:ee:ff", 10, Some(hash));
        let other = ble("11:22:33:44:55:66", 10, None); // same category, no hash
        let p = payload("7OSX", 10);

        // Exact wins even though `other` is a category match.
        match select_match(&[exact.clone(), other.clone()], &p) {
            Selection::One(d) => assert_eq!(d.id(), "aa:bb:cc:dd:ee:ff"),
            s => panic!("expected One, got {s:?}"),
        }
        // No exact, two category matches → Ambiguous.
        let other2 = ble("77:88:99:aa:bb:cc", 10, None);
        match select_match(&[other, other2], &p) {
            Selection::Ambiguous(ids) => assert_eq!(ids.len(), 2),
            s => panic!("expected Ambiguous, got {s:?}"),
        }
        // Nothing matches (wrong category) → None.
        assert!(matches!(
            select_match(&[ble("aa:bb:cc:dd:ee:ff", 99, None)], &p),
            Selection::None
        ));
    }

    #[test]
    fn select_ignores_paired_accessories() {
        let mut d = ble("aa:bb:cc:dd:ee:ff", 10, None);
        if let Discovered::Ble(b) = &mut d {
            b.paired = true;
        }
        assert!(matches!(
            select_match(&[d], &payload("7OSX", 10)),
            Selection::None
        ));
    }
}
