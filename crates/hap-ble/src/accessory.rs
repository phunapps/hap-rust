//! The public per-accessory handle: typed find/read/subscribe/events over an
//! established session.

use crate::broadcast_state::BleBroadcastState;
use crate::db;
use crate::error::{BleError, Result};
use crate::gatt::{GattConnection, GattService};
use crate::pairing;
use crate::pdu::{self, OpCode};
use crate::session::BleSession;
use hap_crypto::{AccessoryPairing, ControllerKeypair};
use hap_model::format::{CharFormat, CharValue};
use hap_model::tree::Accessory;
use hap_model::{CharacteristicType, ServiceType};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio_stream::StreamExt as _;

/// Whether `new` is a newer GSN than `last` under HAP's u16 wraparound
/// (RFC 1982 serial-number arithmetic): newer iff the forward distance is
/// non-zero and within the first half of the range.
fn gsn_is_newer(new: u16, last: u16) -> bool {
    let diff = new.wrapping_sub(last);
    diff != 0 && diff < 0x8000
}

/// Parse a colon-separated hex device id (`"59:fa:bc:61:09:d2"`), matching
/// the HAP pairing-id format. `hap-ble` has no dependency on `hap-pairing`
/// (dependencies flow strictly downward and no new ones are added here), so
/// this mirrors `hap_pairing::parse_device_id`'s logic locally rather than
/// pulling in the crate.
fn parse_device_id(s: &str) -> Option<[u8; 6]> {
    let mut out = [0u8; 6];
    let mut parts = s.split(':');
    for slot in &mut out {
        let p = parts.next()?;
        if p.len() != 2 {
            return None;
        }
        *slot = u8::from_str_radix(p, 16).ok()?;
    }
    parts.next().is_none().then_some(out)
}

/// The maximum number of mid-operation re-verify retries before giving up — a
/// backstop against a link that reconnects on every attempt.
const MAX_REVIVE_RETRIES: u32 = 3;

/// HAP-BLE Characteristic-Configuration body enabling encrypted broadcasts:
/// Properties (TLV 0x01, u16 LE = 1) + Broadcast-Interval (TLV 0x02 = 1).
const ENABLE_BROADCAST_BODY: [u8; 7] = [0x01, 0x02, 0x01, 0x00, 0x02, 0x01, 0x01];

/// A characteristic value-change event.
#[derive(Debug, Clone, PartialEq)]
pub struct CharacteristicEvent {
    /// Accessory instance id.
    pub aid: u64,
    /// Characteristic instance id.
    pub iid: u64,
    /// The decoded new value.
    pub value: CharValue,
}

/// The encrypted-session state shared between foreground reads and the
/// background event tasks (each event-triggered read also advances the session).
struct Secure {
    session: BleSession,
    tid: u8,
    /// The link generation at which `session` was established. When the
    /// connection's generation advances past this (a reconnect), the accessory
    /// has dropped the session and it must be re-minted via Pair Verify.
    generation: u64,
}

/// Everything needed to re-establish a secure session (re-run Pair Verify) after
/// a reconnect invalidates the accessory's session. Shared with event tasks.
struct Reviver {
    keypair: ControllerKeypair,
    pairing: AccessoryPairing,
    verify_char: String,
    verify_iid: u16,
    frag_size: usize,
}

/// The post-Pair-Verify material a [`BleAccessory`] needs: the live secure
/// session and the addresses/keys to re-mint it (Pair Verify) or manage pairings
/// (the Pairing-Pairings characteristic). Bundled so [`BleAccessory::new`] takes
/// one descriptive value rather than a long positional argument list.
pub(crate) struct SecureContext {
    /// The session established by Pair Verify.
    pub session: BleSession,
    /// The link generation `session` was minted at (see [`Secure::generation`]).
    pub session_generation: u64,
    /// This controller's long-term identity (to re-run Pair Verify).
    pub keypair: ControllerKeypair,
    /// The accessory's pairing (to re-run Pair Verify).
    pub pairing: AccessoryPairing,
    /// The Pair-Verify characteristic UUID and instance id.
    pub verify_char: String,
    pub verify_iid: u16,
    /// The Pairing-Pairings characteristic UUID and instance id (RemovePairing).
    pub pairings_char: String,
    pub pairings_iid: u16,
    /// The broadcast decryption key derived during Pair Verify.
    pub broadcast_key: hap_crypto::BroadcastKey,
    /// Initial GSN to seed `last_gsn` from a previously-persisted state.
    pub initial_gsn: u16,
}

/// If the link has reconnected since the secure session was minted, the
/// accessory dropped that session — re-run Pair Verify and adopt the fresh keys
/// (resetting the transaction counter). A no-op when the session is still live.
async fn revive_if_stale(
    gatt: &dyn GattConnection,
    s: &mut Secure,
    reviver: &Reviver,
) -> Result<()> {
    if gatt.generation().await <= s.generation {
        return Ok(());
    }
    let (session, _bkey) = pairing::pair_verify(
        gatt,
        &reviver.verify_char,
        reviver.verify_iid,
        &reviver.keypair,
        &reviver.pairing,
        reviver.frag_size,
    )
    .await?;
    s.session = session;
    s.tid = 0;
    // Capture the generation *after* the handshake: Pair Verify itself fails if
    // the link drops mid-handshake, so reaching here means this is current.
    s.generation = gatt.generation().await;
    Ok(())
}

// kTLVType values for the Pairing-Pairings (Add/Remove/List) exchange.
mod pairings_tlv {
    pub(super) const STATE: u8 = 0x06;
    pub(super) const METHOD: u8 = 0x00;
    pub(super) const IDENTIFIER: u8 = 0x01;
    pub(super) const ERROR: u8 = 0x07;
    pub(super) const STATE_M1: u8 = 0x01;
    pub(super) const STATE_M2: u8 = 0x02;
    pub(super) const METHOD_REMOVE: u8 = 0x04;
}

/// Encode a RemovePairing request (State M1, Method 4, Identifier) as the TLV8
/// carried in the Pairing-Pairings characteristic's Value param.
fn encode_remove_pairing(controller_id: &str) -> Vec<u8> {
    let mut out = Vec::new();
    let mut w = hap_tlv8::Tlv8Writer::new(&mut out);
    w.push_u8(pairings_tlv::STATE, pairings_tlv::STATE_M1);
    w.push_u8(pairings_tlv::METHOD, pairings_tlv::METHOD_REMOVE);
    w.push(pairings_tlv::IDENTIFIER, controller_id.as_bytes());
    out
}

/// Validate a RemovePairing reply: reject a `kTLVType_Error`, then require the
/// reply state to be M2.
fn expect_remove_m2(tlv: &[u8]) -> Result<()> {
    let map = hap_tlv8::Tlv8Map::parse(tlv)?;
    if let Some(err) = map.get(pairings_tlv::ERROR) {
        return Err(BleError::PairingRejected(err.first().copied().unwrap_or(1)));
    }
    match map
        .get(pairings_tlv::STATE)
        .and_then(|s| s.first().copied())
    {
        Some(pairings_tlv::STATE_M2) => Ok(()),
        _ => Err(BleError::MalformedPdu("remove-pairing reply not state M2")),
    }
}

/// Decide whether an event for `(iid, gsn)` should be emitted and record it in
/// the dedup map. Exactly one emission per `(iid, gsn)`; the stored GSN is
/// never downgraded — an out-of-order poll completion racing a newer broadcast
/// must not clobber the broadcast's record (RFC 1982 serial order, matching
/// [`gsn_is_newer`]).
/// The exactly-once guarantee for a GSN older than the stored record relies on
/// the callers' monotonic gating (`last_gsn`); the map alone does not suppress
/// repeats of an older GSN.
async fn dedup_should_emit(emitted: &Mutex<HashMap<u64, u16>>, iid: u64, gsn: u16) -> bool {
    let mut e = emitted.lock().await;
    let prev = e.get(&iid).copied();
    if prev == Some(gsn) {
        return false;
    }
    if prev.is_none_or(|p| gsn_is_newer(gsn, p)) {
        e.insert(iid, gsn);
    }
    true
}

/// Issue one encrypted Characteristic-Read and return the raw value bytes,
/// re-establishing the secure session if a reconnect invalidated it (before the
/// read, and again if the link drops mid-read — retried a bounded number of
/// times).
async fn read_char_raw(
    gatt: &dyn GattConnection,
    secure: &Mutex<Secure>,
    reviver: &Reviver,
    uuid: &str,
    iid: u64,
    frag_size: usize,
) -> Result<Vec<u8>> {
    let iid16 = u16::try_from(iid).map_err(|_| BleError::CharacteristicNotFound { aid: 0, iid })?;
    let mut s = secure.lock().await;
    let mut attempts = 0;
    loop {
        revive_if_stale(gatt, &mut s, reviver).await?;
        s.tid = s.tid.wrapping_add(1);
        let tid = s.tid;
        match pdu::request_secure(
            gatt,
            &mut s.session,
            uuid,
            OpCode::CharacteristicRead,
            tid,
            iid16,
            &[],
            frag_size,
        )
        .await
        {
            Ok(resp) => return pdu::value_param(&resp.body),
            // A reconnect during the read kills the session mid-stream; if the
            // generation advanced, re-verify and retry rather than surfacing the
            // transient failure.
            Err(e) => {
                attempts += 1;
                if attempts < MAX_REVIVE_RETRIES && gatt.generation().await > s.generation {
                    continue;
                }
                return Err(e);
            }
        }
    }
}

/// Issue one encrypted Characteristic-Write carrying `value_bytes`,
/// re-establishing the secure session exactly as [`read_char_raw`] does.
///
/// # Errors
/// [`BleError::CharacteristicNotFound`] if iid overflows u16; otherwise from
/// [`pdu::request_secure`], crypto, or reconnection failures.
async fn write_char_raw(
    gatt: &dyn GattConnection,
    secure: &Mutex<Secure>,
    reviver: &Reviver,
    uuid: &str,
    iid: u64,
    value_bytes: &[u8],
    frag_size: usize,
) -> Result<()> {
    let iid16 = u16::try_from(iid).map_err(|_| BleError::CharacteristicNotFound { aid: 0, iid })?;
    let body = pdu::encode_write_body(value_bytes);
    let mut s = secure.lock().await;
    let mut attempts = 0;
    loop {
        revive_if_stale(gatt, &mut s, reviver).await?;
        s.tid = s.tid.wrapping_add(1);
        let tid = s.tid;
        match pdu::request_secure(
            gatt,
            &mut s.session,
            uuid,
            OpCode::CharacteristicWrite,
            tid,
            iid16,
            &body,
            frag_size,
        )
        .await
        {
            Ok(resp) if resp.status != 0 => return Err(BleError::RequestRejected(resp.status)),
            Ok(_) => return Ok(()),
            Err(e) => {
                attempts += 1;
                if attempts < MAX_REVIVE_RETRIES && gatt.generation().await > s.generation {
                    continue;
                }
                return Err(e);
            }
        }
    }
}

/// A connected BLE accessory: holds the GATT link, the secure session, the
/// cached attribute database, and a map from (aid, iid) to GATT characteristic
/// UUID for issuing PDUs.
pub struct BleAccessory {
    gatt: Arc<dyn GattConnection>,
    secure: Arc<Mutex<Secure>>,
    reviver: Arc<Reviver>,
    /// The Pairing-Pairings characteristic (UUID, instance id) for RemovePairing.
    pairings: (String, u16),
    frag_size: usize,
    accessories: Vec<Accessory>,
    /// (aid, iid) -> characteristic UUID, format.
    chars: HashMap<(u64, u64), (String, CharFormat)>,
    events_tx: tokio::sync::broadcast::Sender<CharacteristicEvent>,
    /// Background event-forwarding tasks, aborted when the handle is dropped.
    tasks: Vec<tokio::task::JoinHandle<()>>,
    /// The last GSN seen in a regular advertisement; shared with catch-up poll tasks.
    last_gsn: Arc<Mutex<u16>>,
    /// Dedup map of `iid → last-emitted GSN`; shared with catch-up poll tasks.
    /// Bounded to one entry per characteristic (unlike a `HashSet` that grows forever).
    emitted: Arc<Mutex<HashMap<u64, u16>>>,
    /// The broadcast decryption key derived during the most recent Pair Verify.
    broadcast_key: hap_crypto::BroadcastKey,
    /// The advert source (the connection itself), set by the controller after
    /// connect so `watch_sleepy_events` can self-source it. `None` on handles
    /// built without one.
    advert_source: Option<Arc<dyn crate::gatt::AdvertSource>>,
}

impl Drop for BleAccessory {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

impl BleAccessory {
    /// Wrap an established GATT link + session with a pre-built attribute
    /// database (fetched unencrypted before Pair Verify). Builds the
    /// `(aid, iid) -> (uuid, format)` map used to address characteristics.
    ///
    /// `ctx` carries the established secure session plus the material to re-mint
    /// it (Pair Verify) after a reconnect and to manage pairings.
    pub(crate) fn new(
        gatt: Arc<dyn GattConnection>,
        ctx: SecureContext,
        frag_size: usize,
        gatt_services: &[GattService],
        accessories: Vec<Accessory>,
    ) -> Self {
        let (events_tx, _) = tokio::sync::broadcast::channel(64);
        // `accessories` models a single accessory (aid 1 — BLE accessories are
        // not bridges in this milestone), so characteristic iids are unique and
        // a plain iid->uuid map is sufficient.
        let mut uuid_by_iid: HashMap<u64, String> = HashMap::new();
        for gs in gatt_services {
            for gc in &gs.characteristics {
                uuid_by_iid.insert(u64::from(gc.iid), gc.uuid.clone());
            }
        }
        let mut chars = HashMap::new();
        for acc in &accessories {
            for svc in &acc.services {
                for ch in &svc.characteristics {
                    if let Some(uuid) = uuid_by_iid.get(&ch.iid) {
                        chars.insert((acc.aid, ch.iid), (uuid.clone(), ch.format));
                    }
                }
            }
        }
        Self {
            gatt,
            secure: Arc::new(Mutex::new(Secure {
                session: ctx.session,
                tid: 0,
                generation: ctx.session_generation,
            })),
            reviver: Arc::new(Reviver {
                keypair: ctx.keypair,
                pairing: ctx.pairing,
                verify_char: ctx.verify_char,
                verify_iid: ctx.verify_iid,
                frag_size,
            }),
            pairings: (ctx.pairings_char, ctx.pairings_iid),
            frag_size,
            accessories,
            chars,
            events_tx,
            tasks: Vec::new(),
            last_gsn: Arc::new(Mutex::new(ctx.initial_gsn)),
            emitted: Arc::new(Mutex::new(HashMap::new())),
            broadcast_key: ctx.broadcast_key,
            advert_source: None,
        }
    }

    /// The cached attribute database.
    pub fn accessories(&self) -> &[Accessory] {
        &self.accessories
    }

    /// The current persistable broadcast material (key + latest GSN). Persist
    /// this so a later `connect` can resume broadcast decryption.
    pub async fn broadcast_state(&self) -> BleBroadcastState {
        BleBroadcastState {
            key: self.broadcast_key.clone(),
            gsn: *self.last_gsn.lock().await,
        }
    }

    /// Find the `(aid, iid)` of a characteristic by service + characteristic
    /// type.
    ///
    /// # Errors
    /// [`BleError::CharacteristicNotFound`] if no match exists.
    // Take the type enums by value for caller ergonomics and to match the IP
    // `hap-controller::find` signature (the two unify in Milestone B).
    #[allow(clippy::needless_pass_by_value)]
    pub fn find(&self, svc: ServiceType, chr: CharacteristicType) -> Result<(u64, u64)> {
        for acc in &self.accessories {
            for service in &acc.services {
                if service.service_type == svc {
                    for ch in &service.characteristics {
                        if ch.char_type == chr {
                            return Ok((acc.aid, ch.iid));
                        }
                    }
                }
            }
        }
        Err(BleError::CharacteristicNotFound { aid: 0, iid: 0 })
    }

    /// Read a characteristic value, decoded to its declared format.
    ///
    /// # Errors
    /// [`BleError::CharacteristicNotFound`] if unknown; otherwise GATT/PDU/crypto.
    pub async fn read(&mut self, aid: u64, iid: u64) -> Result<CharValue> {
        let (uuid, format) = self
            .chars
            .get(&(aid, iid))
            .cloned()
            .ok_or(BleError::CharacteristicNotFound { aid, iid })?;
        let raw = read_char_raw(
            self.gatt.as_ref(),
            &self.secure,
            &self.reviver,
            &uuid,
            iid,
            self.frag_size,
        )
        .await?;
        db::decode_value(format, &raw)
    }

    /// Remove a pairing by controller pairing id. Pass this controller's own id
    /// to un-pair this controller; pass another controller's id (this session
    /// must hold admin permission) to remove that one.
    ///
    /// Runs as an encrypted RemovePairing (State M1, Method 4) write to the
    /// accessory's Pairing-Pairings characteristic; a reconnect-invalidated
    /// session is re-verified first.
    ///
    /// Removing this controller's **own** pairing is a special case: the
    /// accessory removes the pairing and tears down the secure session as part
    /// of the same operation, so the encrypted M2 response is frequently lost or
    /// undecryptable (the link drops, or the reply is no longer sealed under the
    /// now-defunct session). Per the HAP self-removal semantics, once the request
    /// has been written the removal has taken effect, so a transport/crypto
    /// failure *reading the response* on self-removal is reported as success.
    ///
    /// # Errors
    /// [`BleError::PairingRejected`] if the accessory rejects the request (PDU
    /// status or a `kTLVType_Error` in the M2 reply); otherwise GATT/PDU/crypto
    /// errors (except the tolerated self-removal teardown described above).
    pub async fn remove_pairing(&mut self, controller_id: &str) -> Result<()> {
        let (uuid, iid) = self.pairings.clone();
        let removing_self = controller_id == self.reviver.keypair.id;
        let tlv = encode_remove_pairing(controller_id);
        let body = pdu::encode_write_body(&tlv);
        let mut s = self.secure.lock().await;
        revive_if_stale(self.gatt.as_ref(), &mut s, &self.reviver).await?;
        s.tid = s.tid.wrapping_add(1);
        let tid = s.tid;
        let result = pdu::request_secure(
            self.gatt.as_ref(),
            &mut s.session,
            &uuid,
            OpCode::CharacteristicWrite,
            tid,
            iid,
            &body,
            self.frag_size,
        )
        .await;
        match result {
            Ok(resp) if resp.status != 0 => Err(BleError::PairingRejected(resp.status)),
            Ok(resp) => expect_remove_m2(&pdu::value_param(&resp.body)?),
            // The request was written, but reading the sealed M2 back failed.
            // On self-removal that is the expected session teardown — the
            // pairing is gone — so swallow the teardown-shaped error.
            Err(BleError::Disconnected | BleError::Crypto(_)) if removing_self => Ok(()),
            Err(e) => Err(e),
        }
    }

    /// Write a characteristic value, encoded per its declared format, over the
    /// encrypted session (re-verified after a reconnect, like [`Self::read`]).
    ///
    /// # Errors
    /// [`BleError::CharacteristicNotFound`] if unknown;
    /// [`BleError::RequestRejected`] if the accessory returns a non-zero PDU
    /// status; [`BleError::MalformedPdu`] if `value` does not match the
    /// characteristic's format; otherwise GATT/crypto errors.
    pub async fn write(&mut self, aid: u64, iid: u64, value: CharValue) -> Result<()> {
        let (uuid, format) = self
            .chars
            .get(&(aid, iid))
            .cloned()
            .ok_or(BleError::CharacteristicNotFound { aid, iid })?;
        let bytes = db::encode_value(format, &value)?;
        write_char_raw(
            self.gatt.as_ref(),
            &self.secure,
            &self.reviver,
            &uuid,
            iid,
            &bytes,
            self.frag_size,
        )
        .await
    }

    /// The accessory's HAP pairing id (as stored in the pairing record).
    #[must_use]
    pub fn pairing_id(&self) -> &str {
        &self.reviver.pairing.pairing_id
    }

    /// Enable encrypted broadcast notifications for the given characteristic
    /// instance ids (the HAP BLE accessory id is always 1). Each is an encrypted
    /// Characteristic-Configuration write (Properties + Broadcast-Interval). Call
    /// this **while connected**, before disconnecting to receive sleepy events —
    /// without it the accessory will not emit `0x11` encrypted broadcasts. A
    /// characteristic that does not support broadcasts is skipped; per-write
    /// failures are tolerated (best-effort).
    ///
    /// # Errors
    /// Propagates a session re-verify failure.
    pub async fn enable_broadcasts(&mut self, iids: &[u64]) -> Result<()> {
        let mut s = self.secure.lock().await;
        for &iid in iids {
            let Some((uuid, _)) = self.chars.get(&(1, iid)).cloned() else {
                continue;
            };
            let Ok(iid16) = u16::try_from(iid) else {
                continue;
            };
            revive_if_stale(self.gatt.as_ref(), &mut s, &self.reviver).await?;
            s.tid = s.tid.wrapping_add(1);
            let tid = s.tid;
            let _ = pdu::request_secure(
                self.gatt.as_ref(),
                &mut s.session,
                &uuid,
                OpCode::CharacteristicConfig,
                tid,
                iid16,
                &ENABLE_BROADCAST_BODY,
                self.frag_size,
            )
            .await;
        }
        Ok(())
    }

    /// Release the underlying link (so the sleepy accessory advertises again).
    /// A no-op on backends without a live link.
    pub async fn disconnect(&self) {
        self.gatt.disconnect().await;
    }

    /// Subscribe to value-change events for a characteristic. HAP-BLE connected
    /// events use the GATT notification only as a **trigger**: when it fires we
    /// issue an encrypted Characteristic-Read for the new value and publish it
    /// on [`BleAccessory::events`].
    ///
    /// # Errors
    /// [`BleError::CharacteristicNotFound`] if unknown; otherwise GATT errors.
    ///
    /// Connected events are best-effort: if the link drops, this GATT
    /// subscription ends and is not re-armed (re-arming a sleepy device storms).
    /// Durable updates arrive via [`BleAccessory::events`] from the broadcast and
    /// disconnected-event channels.
    pub async fn subscribe(&mut self, aid: u64, iid: u64) -> Result<()> {
        let (uuid, format) = self
            .chars
            .get(&(aid, iid))
            .cloned()
            .ok_or(BleError::CharacteristicNotFound { aid, iid })?;
        let mut rx = self.gatt.subscribe(&uuid).await?;
        let tx = self.events_tx.clone();
        let gatt = self.gatt.clone();
        let secure = self.secure.clone();
        let reviver = self.reviver.clone();
        let frag_size = self.frag_size;
        let task = tokio::spawn(async move {
            // The notification carries no value; it signals "read me".
            while rx.recv().await.is_some() {
                if let Ok(raw) =
                    read_char_raw(gatt.as_ref(), &secure, &reviver, &uuid, iid, frag_size).await
                {
                    if let Ok(value) = db::decode_value(format, &raw) {
                        let _ = tx.send(CharacteristicEvent { aid, iid, value });
                    }
                }
            }
        });
        self.tasks.push(task);
        Ok(())
    }

    /// Watch advertisements and deliver disconnected-event updates. Two paths:
    ///
    /// - **Regular (0x06) advertisements:** when the accessory's GSN bumps, read
    ///   each polled characteristic and publish its value on
    ///   [`BleAccessory::events`]. Events are deduplicated by `(iid, gsn)`.
    ///   The poll runs on its own task fed by a watch channel, so bumps coalesce.
    /// - **Encrypted broadcast (0x11) advertisements:** decrypt the value directly
    ///   from the advertisement using the stored [`hap_crypto::BroadcastKey`] and
    ///   publish it — no GATT connection needed.
    ///
    /// The advert source is supplied by the caller (the same backend object that
    /// provides the GATT connection).
    ///
    /// # Errors
    /// [`BleError`] if the advert source cannot start.
    #[allow(clippy::too_many_lines)]
    pub async fn watch_sleepy_events_with_source(
        &mut self,
        advert_source: Arc<dyn crate::gatt::AdvertSource>,
        device_id: [u8; 6],
        poll_iids: Vec<(u64, u64)>,
    ) -> Result<()> {
        // Pre-resolve poll targets to (aid, iid, uuid, format) so the task needs no
        // access to self.chars.
        let mut targets = Vec::new();
        for (aid, iid) in poll_iids {
            if let Some((uuid, format)) = self.chars.get(&(aid, iid)).cloned() {
                targets.push((aid, iid, uuid, format));
            }
        }
        // Build an iid→format map for the 0x11 broadcast-decrypt path.
        let formats: std::collections::HashMap<u64, CharFormat> = self
            .chars
            .iter()
            .map(|((_, iid), (_, f))| (*iid, *f))
            .collect();
        let broadcast_key = self.broadcast_key.clone();

        let mut adverts = advert_source.watch_adverts().await?;

        // The catch-up poll runs on its own task, fed the latest bumped GSN
        // through a watch channel: the advert loop must never block on GATT
        // I/O (a reconnect-read pauses the advert scan and can take seconds),
        // and a burst of bumps coalesces into one poll of the latest GSN.
        let (poll_tx, mut poll_rx) = tokio::sync::watch::channel(0u16);
        if !targets.is_empty() {
            let gatt = self.gatt.clone();
            let secure = self.secure.clone();
            let reviver = self.reviver.clone();
            let frag = self.frag_size;
            let poll_events = self.events_tx.clone();
            let poll_emitted = self.emitted.clone();
            let poll_task = tokio::spawn(async move {
                while poll_rx.changed().await.is_ok() {
                    let gsn = *poll_rx.borrow_and_update();
                    for (aid, iid, uuid, format) in &targets {
                        if let Ok(raw_val) =
                            read_char_raw(gatt.as_ref(), &secure, &reviver, uuid, *iid, frag).await
                        {
                            if let Ok(value) = db::decode_value(*format, &raw_val) {
                                if dedup_should_emit(&poll_emitted, *iid, gsn).await {
                                    let _ = poll_events.send(CharacteristicEvent {
                                        aid: *aid,
                                        iid: *iid,
                                        value,
                                    });
                                }
                            }
                        }
                    }
                }
            });
            self.tasks.push(poll_task);
        }

        let tx = self.events_tx.clone();
        let last_gsn = self.last_gsn.clone();
        let emitted = self.emitted.clone();
        let advert_task = tokio::spawn(async move {
            while let Some(raw) = adverts.recv().await {
                match crate::advert::HapAdvert::parse(&raw.manufacturer_data) {
                    Some(crate::advert::HapAdvert::Regular {
                        device_id: d, gsn, ..
                    }) => {
                        if d != device_id {
                            continue;
                        }
                        {
                            let mut lg = last_gsn.lock().await;
                            if !gsn_is_newer(gsn, *lg) {
                                continue;
                            }
                            *lg = gsn;
                        }
                        // Hand the bump to the poll task. A dropped receiver
                        // (no poll targets) is fine.
                        let _ = poll_tx.send(gsn);
                    }
                    Some(crate::advert::HapAdvert::EncryptedNotification {
                        advertising_id,
                        payload,
                    }) => {
                        if advertising_id != device_id {
                            continue;
                        }
                        let start = *last_gsn.lock().await;
                        // GSN candidates per aiohomekit: next, current, then a
                        // forward window up to +100.
                        let candidates = std::iter::once(start.wrapping_add(1))
                            .chain(std::iter::once(start))
                            .chain((2..=100u16).map(|d| start.wrapping_add(d)));
                        for gsn in candidates {
                            let Ok(pt) = broadcast_key.open(gsn, &payload, &advertising_id) else {
                                continue;
                            };
                            if pt.len() < 12 {
                                continue;
                            }
                            if u16::from_le_bytes([pt[0], pt[1]]) != gsn {
                                continue;
                            }
                            // stale duplicate: not newer than start — ignore.
                            if !gsn_is_newer(gsn, start) {
                                break;
                            }
                            let iid = u64::from(u16::from_le_bytes([pt[2], pt[3]]));
                            // Advance last_gsn now — the device's state
                            // genuinely moved, even if the iid is unknown or
                            // the value fails to decode.
                            {
                                let mut lg = last_gsn.lock().await;
                                *lg = gsn;
                            }
                            let Some(format) = formats.get(&iid).copied() else {
                                break;
                            };
                            if let Ok(value) = db::decode_value(format, &pt[4..12]) {
                                if dedup_should_emit(&emitted, iid, gsn).await {
                                    let _ = tx.send(CharacteristicEvent { aid: 1, iid, value });
                                }
                            }
                            break;
                        }
                    }
                    _ => {}
                }
            }
        });
        self.tasks.push(advert_task);
        Ok(())
    }

    /// Provide the advert source (the connection) so the self-sourcing
    /// [`watch_sleepy_events`](Self::watch_sleepy_events) can use it.
    pub fn set_advert_source(&mut self, src: Arc<dyn crate::gatt::AdvertSource>) {
        self.advert_source = Some(src);
    }

    /// Watch for sleepy-device events, self-sourcing the advert source (set via
    /// [`set_advert_source`](Self::set_advert_source)) and the device id (from
    /// the pairing id). Arms the same machinery as
    /// [`watch_sleepy_events_with_source`](Self::watch_sleepy_events_with_source).
    ///
    /// # Errors
    /// [`BleError::NoAdvertSource`] if no source was set; [`BleError::Backend`]
    /// if the stored pairing id cannot be parsed as a device id; otherwise
    /// advert/GATT errors.
    pub async fn watch_sleepy_events(&mut self, poll_iids: Vec<(u64, u64)>) -> Result<()> {
        let src = self.advert_source.clone().ok_or(BleError::NoAdvertSource)?;
        let device_id =
            parse_device_id(self.reviver.pairing.pairing_id.as_str()).ok_or_else(|| {
                BleError::Backend("malformed pairing id; cannot derive device id".into())
            })?;
        self.watch_sleepy_events_with_source(src, device_id, poll_iids)
            .await
    }

    /// An async stream of characteristic events. Each call returns a fresh
    /// subscriber to the shared event channel.
    pub fn events(&self) -> impl tokio_stream::Stream<Item = CharacteristicEvent> {
        tokio_stream::wrappers::BroadcastStream::new(self.events_tx.subscribe())
            .filter_map(std::result::Result::ok)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::ble_accessory_with_db;

    #[tokio::test]
    #[allow(clippy::unwrap_used)]
    async fn find_locates_characteristic() {
        let (h, _g) = ble_accessory_with_db().await;
        let (aid, iid) = h
            .find(ServiceType::LightBulb, CharacteristicType::On)
            .unwrap();
        assert_eq!((aid, iid), (1, 11));
    }

    #[tokio::test]
    #[allow(clippy::unwrap_used)]
    async fn find_missing_errors() {
        let (h, _g) = ble_accessory_with_db().await;
        let err = h
            .find(ServiceType::LightBulb, CharacteristicType::Brightness)
            .unwrap_err();
        assert!(matches!(err, BleError::CharacteristicNotFound { .. }));
    }

    #[test]
    fn encode_remove_pairing_matches_hap_layout() {
        // State M1, Method RemovePairing(4), Identifier "c2".
        let tlv = encode_remove_pairing("c2");
        assert_eq!(
            tlv,
            vec![0x06, 0x01, 0x01, 0x00, 0x01, 0x04, 0x01, 0x02, b'c', b'2']
        );
    }

    #[test]
    fn expect_remove_m2_accepts_m2_and_rejects_error() {
        assert!(expect_remove_m2(&[0x06, 0x01, 0x02]).is_ok());
        // A kTLVType_Error (0x07) is surfaced as a rejection with its code.
        assert!(matches!(
            expect_remove_m2(&[0x07, 0x01, 0x02]),
            Err(BleError::PairingRejected(2))
        ));
        // Anything that is not state M2 is malformed.
        assert!(matches!(
            expect_remove_m2(&[0x06, 0x01, 0x01]),
            Err(BleError::MalformedPdu(_))
        ));
    }

    #[tokio::test]
    #[allow(clippy::unwrap_used)]
    async fn remove_pairing_writes_request_and_accepts_m2() {
        let (mut h, gatt) = ble_accessory_with_db().await;

        // The accessory replies to the encrypted RemovePairing write with a
        // sealed success PDU whose value param is a State-M2 TLV8.
        let m2 = vec![0x06, 0x01, 0x02];
        let vbody = crate::pdu::encode_value_param(&m2);
        let mut plain = vec![0x02, 0x01, 0x00];
        plain.extend_from_slice(&u16::try_from(vbody.len()).unwrap().to_le_bytes());
        plain.extend_from_slice(&vbody);
        let sealed =
            hap_crypto::aead::chacha20poly1305_seal(&[0u8; 32], &[0u8; 12], &[], &plain).unwrap();
        gatt.queue_read("00000050-0000-1000-8000-0026bb765291", sealed);

        h.remove_pairing("AE:EC:86:C0:BF:D7").await.unwrap();
    }

    #[tokio::test]
    #[allow(clippy::unwrap_used)]
    async fn remove_own_pairing_tolerates_session_teardown() {
        // ble_accessory_with_db pairs as controller id "test-controller".
        let (mut h, gatt) = ble_accessory_with_db().await;
        // The accessory tears down the session as it removes us, so the reply is
        // not validly sealed — open() fails with a crypto error. Removing our OWN
        // id must still succeed (the removal took effect on write).
        gatt.queue_read("00000050-0000-1000-8000-0026bb765291", vec![0u8; 24]);
        h.remove_pairing("test-controller").await.unwrap();
    }

    #[tokio::test]
    #[allow(clippy::unwrap_used)]
    async fn remove_other_pairing_propagates_teardown_error() {
        // The same undecryptable reply when removing a DIFFERENT controller must
        // NOT be swallowed — only self-removal tolerates a teardown.
        let (mut h, gatt) = ble_accessory_with_db().await;
        gatt.queue_read("00000050-0000-1000-8000-0026bb765291", vec![0u8; 24]);
        let err = h.remove_pairing("some-other-controller").await.unwrap_err();
        assert!(matches!(err, BleError::Crypto(_)));
    }

    #[tokio::test]
    #[allow(clippy::unwrap_used)]
    async fn subscribe_then_event_decodes_value() {
        use tokio_stream::StreamExt as _;
        let (mut h, gatt) = ble_accessory_with_db().await;

        // A HAP-BLE connected event is a bare notification (trigger) followed by
        // an encrypted Characteristic-Read. Queue the sealed read response the
        // accessory would return (zero session keys, recv counter 0).
        let mut plain = vec![0x02, 0x01, 0x00];
        let vbody = crate::pdu::encode_value_param(&[0x01]); // Bool true
        plain.extend_from_slice(&u16::try_from(vbody.len()).unwrap().to_le_bytes());
        plain.extend_from_slice(&vbody);
        let sealed =
            hap_crypto::aead::chacha20poly1305_seal(&[0u8; 32], &[0u8; 12], &[], &plain).unwrap();
        gatt.queue_read("00000025-0000-1000-8000-0026bb765291", sealed);

        h.subscribe(1, 11).await.unwrap();
        let mut events = h.events();

        // Push the (empty) notification trigger.
        gatt.notifier("00000025-0000-1000-8000-0026bb765291")
            .unwrap()
            .send(Vec::new())
            .await
            .unwrap();

        let ev = events.next().await.unwrap();
        assert_eq!(ev.iid, 11);
        assert_eq!(ev.value, hap_model::format::CharValue::Bool(true));
    }

    #[tokio::test]
    #[allow(clippy::unwrap_used)]
    async fn gsn_bump_triggers_disconnected_event_read() {
        use tokio_stream::StreamExt as _;
        let (mut h, gatt) = ble_accessory_with_db().await;

        // The catch-up poll will issue an encrypted read for iid 11; queue the sealed
        // response (zero session keys, recv counter 0) decoding to Bool(true).
        let mut plain = vec![0x02, 0x01, 0x00];
        let vbody = crate::pdu::encode_value_param(&[0x01]);
        plain.extend_from_slice(&u16::try_from(vbody.len()).unwrap().to_le_bytes());
        plain.extend_from_slice(&vbody);
        let sealed =
            hap_crypto::aead::chacha20poly1305_seal(&[0u8; 32], &[0u8; 12], &[], &plain).unwrap();
        gatt.queue_read("00000025-0000-1000-8000-0026bb765291", sealed);

        let advert_source: std::sync::Arc<dyn crate::gatt::AdvertSource> = gatt.clone();
        h.watch_sleepy_events_with_source(advert_source, [1, 2, 3, 4, 5, 6], vec![(1, 11)])
            .await
            .unwrap();
        let mut events = h.events();

        // Push a 0x06 advert for device [1..6] with GSN 9 (a bump from 0).
        gatt.advert_sender()
            .send(crate::gatt::RawAdvert {
                manufacturer_data: vec![
                    0x06, 0x21, 0x01, 1, 2, 3, 4, 5, 6, 0x01, 0x00, 0x09, 0x00, 0x01, 0x00,
                ],
            })
            .await
            .unwrap();

        let ev = events.next().await.unwrap();
        assert_eq!(ev.iid, 11);
        assert_eq!(ev.value, hap_model::format::CharValue::Bool(true));
    }

    #[tokio::test]
    #[allow(clippy::unwrap_used)]
    async fn encrypted_broadcast_0x11_decrypts_and_emits_event() {
        use tokio_stream::StreamExt as _;
        // ble_accessory_with_db sets broadcast_key = BroadcastKey::from_bytes([0u8; 32]).
        let (mut h, gatt) = ble_accessory_with_db().await;

        // Seal a 12-byte broadcast plaintext: gsn=1, iid=11 (LightBulb On, Bool),
        // value bytes = [0x01, 0, 0, 0, 0, 0, 0, 0] (Bool true).
        let key = hap_crypto::BroadcastKey::from_bytes([0u8; 32]);
        let aid_bytes: [u8; 6] = [1, 2, 3, 4, 5, 6];
        let mut pt = Vec::new();
        pt.extend_from_slice(&1u16.to_le_bytes()); // gsn = 1
        pt.extend_from_slice(&11u16.to_le_bytes()); // iid = 11
        pt.extend_from_slice(&[0x01, 0, 0, 0, 0, 0, 0, 0]); // value: Bool true
        let sealed = key.seal(1, &pt, &aid_bytes);

        // Build a 0x11 manufacturer-data frame: [0x11, 0x00, aid[0..6], sealed...]
        let mut mfg = vec![0x11u8, 0x00];
        mfg.extend_from_slice(&aid_bytes);
        mfg.extend_from_slice(&sealed);

        let advert_source: std::sync::Arc<dyn crate::gatt::AdvertSource> = gatt.clone();
        // poll_iids is empty — broadcast path needs no poll targets.
        h.watch_sleepy_events_with_source(advert_source, aid_bytes, vec![])
            .await
            .unwrap();
        let mut events = h.events();

        gatt.advert_sender()
            .send(crate::gatt::RawAdvert {
                manufacturer_data: mfg,
            })
            .await
            .unwrap();

        let ev = events.next().await.unwrap();
        assert_eq!(ev.aid, 1);
        assert_eq!(ev.iid, 11);
        assert_eq!(ev.value, hap_model::format::CharValue::Bool(true));
    }

    #[test]
    fn gsn_is_newer_handles_wraparound() {
        assert!(gsn_is_newer(6, 5));
        assert!(!gsn_is_newer(5, 5));
        assert!(!gsn_is_newer(4, 5));
        assert!(gsn_is_newer(1, 65535)); // wrap 65535 -> 1
        assert!(!gsn_is_newer(65535, 1)); // not newer across the wrap
    }

    #[tokio::test]
    #[allow(clippy::unwrap_used)]
    async fn same_change_via_poll_and_broadcast_emits_once() {
        use tokio_stream::StreamExt as _;
        let (mut h, gatt) = ble_accessory_with_db().await;

        // Queue the sealed Characteristic-Read response the poll will issue for
        // iid 11 (same setup as gsn_bump_triggers_disconnected_event_read).
        let mut plain = vec![0x02, 0x01, 0x00];
        let vbody = crate::pdu::encode_value_param(&[0x01]);
        plain.extend_from_slice(&u16::try_from(vbody.len()).unwrap().to_le_bytes());
        plain.extend_from_slice(&vbody);
        let sealed =
            hap_crypto::aead::chacha20poly1305_seal(&[0u8; 32], &[0u8; 12], &[], &plain).unwrap();
        gatt.queue_read("00000025-0000-1000-8000-0026bb765291", sealed);

        let advert_source: std::sync::Arc<dyn crate::gatt::AdvertSource> = gatt.clone();
        h.watch_sleepy_events_with_source(advert_source, [1, 2, 3, 4, 5, 6], vec![(1, 11)])
            .await
            .unwrap();
        let mut events = h.events();

        // Send 0x06 advert first (GSN 9) — triggers the poll → reads iid 11 → emits event.
        gatt.advert_sender()
            .send(crate::gatt::RawAdvert {
                manufacturer_data: vec![
                    0x06, 0x21, 0x01, 1, 2, 3, 4, 5, 6, 0x01, 0x00, 0x09, 0x00, 0x01, 0x00,
                ],
            })
            .await
            .unwrap();

        // Wait for the poll-triggered event.
        let ev = events.next().await.unwrap();
        assert_eq!(ev.iid, 11);
        assert_eq!(ev.value, hap_model::format::CharValue::Bool(true));

        // Now send a 0x11 broadcast for the same GSN 9 / iid 11 — must be deduped.
        let key = hap_crypto::BroadcastKey::from_bytes([0u8; 32]);
        let aid_bytes: [u8; 6] = [1, 2, 3, 4, 5, 6];
        let mut pt = Vec::new();
        pt.extend_from_slice(&9u16.to_le_bytes()); // gsn = 9
        pt.extend_from_slice(&11u16.to_le_bytes()); // iid = 11
        pt.extend_from_slice(&[0x01, 0, 0, 0, 0, 0, 0, 0]); // value: Bool true
        let sealed_bc = key.seal(9, &pt, &aid_bytes);

        let mut mfg = vec![0x11u8, 0x00];
        mfg.extend_from_slice(&aid_bytes);
        mfg.extend_from_slice(&sealed_bc);

        gatt.advert_sender()
            .send(crate::gatt::RawAdvert {
                manufacturer_data: mfg,
            })
            .await
            .unwrap();

        // The second event (same iid=11, gsn=9) must be deduped — no second emit.
        let timeout_result =
            tokio::time::timeout(std::time::Duration::from_millis(200), events.next()).await;
        assert!(
            timeout_result.is_err(),
            "expected dedup to suppress the duplicate 0x11 broadcast event, but got one"
        );
    }

    /// The advert loop must not block on the catch-up poll's GATT read: while
    /// a poll read is stalled (e.g. a scan-pausing reconnect), a 0x11
    /// broadcast must still decrypt and emit. Regression test for running poll
    /// reads off the advert task.
    #[tokio::test]
    #[allow(clippy::unwrap_used)]
    async fn broadcast_delivered_while_poll_read_blocked() {
        use tokio_stream::StreamExt as _;
        let (mut h, gatt) = ble_accessory_with_db().await;

        // Stall the poll's encrypted read of iid 11 until released; queue the
        // sealed Bool(true) response it eventually returns.
        let release = gatt.block_next_read("00000025-0000-1000-8000-0026bb765291");
        let mut plain = vec![0x02, 0x01, 0x00];
        let vbody = crate::pdu::encode_value_param(&[0x01]);
        plain.extend_from_slice(&u16::try_from(vbody.len()).unwrap().to_le_bytes());
        plain.extend_from_slice(&vbody);
        let sealed =
            hap_crypto::aead::chacha20poly1305_seal(&[0u8; 32], &[0u8; 12], &[], &plain).unwrap();
        gatt.queue_read("00000025-0000-1000-8000-0026bb765291", sealed);

        let advert_source: std::sync::Arc<dyn crate::gatt::AdvertSource> = gatt.clone();
        h.watch_sleepy_events_with_source(advert_source, [1, 2, 3, 4, 5, 6], vec![(1, 11)])
            .await
            .unwrap();
        let mut events = h.events();

        // 0x06 bump to GSN 9 — the poll starts its read and stalls on the gate.
        gatt.advert_sender()
            .send(crate::gatt::RawAdvert {
                manufacturer_data: vec![
                    0x06, 0x21, 0x01, 1, 2, 3, 4, 5, 6, 0x01, 0x00, 0x09, 0x00, 0x01, 0x00,
                ],
            })
            .await
            .unwrap();

        // A 0x11 broadcast for GSN 10 carrying Bool(false) — the advert loop
        // must process it while the poll read is still stalled.
        let key = hap_crypto::BroadcastKey::from_bytes([0u8; 32]);
        let aid_bytes: [u8; 6] = [1, 2, 3, 4, 5, 6];
        let mut pt = Vec::new();
        pt.extend_from_slice(&10u16.to_le_bytes()); // gsn = 10
        pt.extend_from_slice(&11u16.to_le_bytes()); // iid = 11
        pt.extend_from_slice(&[0x00, 0, 0, 0, 0, 0, 0, 0]); // Bool false
        let sealed_bc = key.seal(10, &pt, &aid_bytes);
        let mut mfg = vec![0x11u8, 0x00];
        mfg.extend_from_slice(&aid_bytes);
        mfg.extend_from_slice(&sealed_bc);
        gatt.advert_sender()
            .send(crate::gatt::RawAdvert {
                manufacturer_data: mfg,
            })
            .await
            .unwrap();

        // The broadcast event (Bool(false)) must arrive FIRST: the poll read is
        // still blocked. With the old inline poll this times out because the
        // advert loop is stuck inside the read.
        let ev = tokio::time::timeout(std::time::Duration::from_secs(2), events.next())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(ev.iid, 11);
        assert_eq!(ev.value, hap_model::format::CharValue::Bool(false));

        // Release the stalled read; the poll's event (GSN 9, Bool(true)) follows.
        release.notify_one();
        let ev2 = tokio::time::timeout(std::time::Duration::from_secs(2), events.next())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(ev2.iid, 11);
        assert_eq!(ev2.value, hap_model::format::CharValue::Bool(true));
    }

    // ── negative-path tests for sleepy-device event handling ─────────────────

    /// A 0x06 advert from a foreign device id must be silently dropped — no
    /// event emitted, no panic.
    #[tokio::test]
    #[allow(clippy::unwrap_used)]
    async fn foreign_device_advert_ignored() {
        use tokio_stream::StreamExt as _;
        let (mut h, gatt) = ble_accessory_with_db().await;

        let advert_source: std::sync::Arc<dyn crate::gatt::AdvertSource> = gatt.clone();
        // watch_sleepy_events expects device_id [1,2,3,4,5,6]
        h.watch_sleepy_events_with_source(advert_source, [1, 2, 3, 4, 5, 6], vec![(1, 11)])
            .await
            .unwrap();
        let mut events = h.events();

        // Send a 0x06 advert whose device_id is [9,9,9,9,9,9] — a foreign device.
        gatt.advert_sender()
            .send(crate::gatt::RawAdvert {
                manufacturer_data: vec![
                    0x06, 0x21, 0x01, 9, 9, 9, 9, 9, 9, 0x01, 0x00, 0x09, 0x00, 0x01, 0x00,
                ],
            })
            .await
            .unwrap();

        let timeout_result =
            tokio::time::timeout(std::time::Duration::from_millis(200), events.next()).await;
        assert!(
            timeout_result.is_err(),
            "foreign device advert must not emit an event, but one was received"
        );
    }

    /// A 0x11 broadcast replayed at the same GSN that was already processed must
    /// be silently dropped — stale-GSN dedup.
    #[tokio::test]
    #[allow(clippy::unwrap_used)]
    async fn stale_gsn_broadcast_ignored() {
        use tokio_stream::StreamExt as _;
        let (mut h, gatt) = ble_accessory_with_db().await;

        let key = hap_crypto::BroadcastKey::from_bytes([0u8; 32]);
        let aid_bytes: [u8; 6] = [1, 2, 3, 4, 5, 6];

        // Plaintext: gsn=5, iid=11, value=Bool(true)
        // Layout: [gsn_le: 2B][iid_le: 2B][value: 8B]
        let mut pt = Vec::new();
        pt.extend_from_slice(&5u16.to_le_bytes()); // gsn = 5
        pt.extend_from_slice(&11u16.to_le_bytes()); // iid = 11
        pt.extend_from_slice(&[0x01, 0, 0, 0, 0, 0, 0, 0]); // Bool true
        let sealed = key.seal(5, &pt, &aid_bytes);

        let mut mfg = vec![0x11u8, 0x00];
        mfg.extend_from_slice(&aid_bytes);
        mfg.extend_from_slice(&sealed);

        let advert_source: std::sync::Arc<dyn crate::gatt::AdvertSource> = gatt.clone();
        h.watch_sleepy_events_with_source(advert_source, aid_bytes, vec![])
            .await
            .unwrap();
        let mut events = h.events();

        // First delivery — GSN 5 is fresh (last_gsn starts at 0).
        gatt.advert_sender()
            .send(crate::gatt::RawAdvert {
                manufacturer_data: mfg.clone(),
            })
            .await
            .unwrap();

        let ev = events.next().await.unwrap();
        assert_eq!(ev.iid, 11);
        assert_eq!(ev.value, hap_model::format::CharValue::Bool(true));

        // Second delivery — identical GSN 5 is now stale.
        gatt.advert_sender()
            .send(crate::gatt::RawAdvert {
                manufacturer_data: mfg,
            })
            .await
            .unwrap();

        let timeout_result =
            tokio::time::timeout(std::time::Duration::from_millis(200), events.next()).await;
        assert!(
            timeout_result.is_err(),
            "duplicate GSN 5 broadcast must not emit a second event"
        );
    }

    /// A 0x11 broadcast sealed with the wrong key must be silently dropped — all
    /// GSN candidate decrypts fail the 4-byte tag check, so no event, no panic.
    #[tokio::test]
    #[allow(clippy::unwrap_used)]
    async fn wrong_broadcast_key_ignored() {
        use tokio_stream::StreamExt as _;
        // ble_accessory_with_db installs broadcast_key = BroadcastKey::from_bytes([0u8;32])
        let (mut h, gatt) = ble_accessory_with_db().await;

        // Seal with the WRONG key ([0xFF;32]).
        let wrong_key = hap_crypto::BroadcastKey::from_bytes([0xFF; 32]);
        let aid_bytes: [u8; 6] = [1, 2, 3, 4, 5, 6];

        let mut pt = Vec::new();
        pt.extend_from_slice(&1u16.to_le_bytes());
        pt.extend_from_slice(&11u16.to_le_bytes());
        pt.extend_from_slice(&[0x01, 0, 0, 0, 0, 0, 0, 0]);
        let sealed = wrong_key.seal(1, &pt, &aid_bytes);

        let mut mfg = vec![0x11u8, 0x00];
        mfg.extend_from_slice(&aid_bytes);
        mfg.extend_from_slice(&sealed);

        let advert_source: std::sync::Arc<dyn crate::gatt::AdvertSource> = gatt.clone();
        h.watch_sleepy_events_with_source(advert_source, aid_bytes, vec![])
            .await
            .unwrap();
        let mut events = h.events();

        gatt.advert_sender()
            .send(crate::gatt::RawAdvert {
                manufacturer_data: mfg,
            })
            .await
            .unwrap();

        let timeout_result =
            tokio::time::timeout(std::time::Duration::from_millis(200), events.next()).await;
        assert!(
            timeout_result.is_err(),
            "wrong-key broadcast must not emit any event (all candidate opens fail)"
        );
    }

    /// A 0x11 advert whose payload is too short (< 4 bytes after the advertising
    /// id) must be silently dropped — `BroadcastKey::open` returns `Err` on
    /// `< 4` bytes, so no event, no panic.
    #[tokio::test]
    #[allow(clippy::unwrap_used)]
    async fn malformed_0x11_advert_ignored() {
        use tokio_stream::StreamExt as _;
        let (mut h, gatt) = ble_accessory_with_db().await;

        let advert_source: std::sync::Arc<dyn crate::gatt::AdvertSource> = gatt.clone();
        h.watch_sleepy_events_with_source(advert_source, [1, 2, 3, 4, 5, 6], vec![])
            .await
            .unwrap();
        let mut events = h.events();

        // advertising_id present, only 2 payload bytes — too short for open().
        let manufacturer_data = vec![0x11, 0x00, 1, 2, 3, 4, 5, 6, 0xAA, 0xBB];
        gatt.advert_sender()
            .send(crate::gatt::RawAdvert { manufacturer_data })
            .await
            .unwrap();

        let timeout_result =
            tokio::time::timeout(std::time::Duration::from_millis(200), events.next()).await;
        assert!(
            timeout_result.is_err(),
            "malformed (too-short payload) 0x11 advert must not emit any event"
        );
    }

    /// A 0x11 broadcast where the embedded GSN in the plaintext does NOT match
    /// the nonce GSN must be silently dropped — the self-consistency check
    /// (`u16::from_le_bytes(pt[0..2]) == gsn`) fails, so no emit.
    #[tokio::test]
    #[allow(clippy::unwrap_used)]
    async fn broadcast_value_self_inconsistent_gsn_ignored() {
        use tokio_stream::StreamExt as _;
        let (mut h, gatt) = ble_accessory_with_db().await;

        let key = hap_crypto::BroadcastKey::from_bytes([0u8; 32]);
        let aid_bytes: [u8; 6] = [1, 2, 3, 4, 5, 6];

        // Plaintext embeds gsn=3 but is sealed at nonce gsn=7.
        // After decryption succeeds at candidate gsn=7, the guard
        // `u16::from_le_bytes([pt[0], pt[1]]) != gsn` fires (3 != 7) → no emit.
        let mut pt = Vec::new();
        pt.extend_from_slice(&3u16.to_le_bytes()); // embedded gsn = 3 (mismatches nonce)
        pt.extend_from_slice(&11u16.to_le_bytes()); // iid = 11
        pt.extend_from_slice(&[0x01, 0, 0, 0, 0, 0, 0, 0]); // Bool true
        let sealed = key.seal(7, &pt, &aid_bytes); // sealed at nonce gsn=7

        let mut mfg = vec![0x11u8, 0x00];
        mfg.extend_from_slice(&aid_bytes);
        mfg.extend_from_slice(&sealed);

        let advert_source: std::sync::Arc<dyn crate::gatt::AdvertSource> = gatt.clone();
        h.watch_sleepy_events_with_source(advert_source, aid_bytes, vec![])
            .await
            .unwrap();
        let mut events = h.events();

        gatt.advert_sender()
            .send(crate::gatt::RawAdvert {
                manufacturer_data: mfg,
            })
            .await
            .unwrap();

        let timeout_result =
            tokio::time::timeout(std::time::Duration::from_millis(200), events.next()).await;
        assert!(
            timeout_result.is_err(),
            "self-inconsistent GSN (embedded 3 != nonce 7) must not emit any event"
        );
    }

    #[tokio::test]
    #[allow(clippy::unwrap_used)]
    async fn read_after_reconnect_re_verifies_before_using_session() {
        let (mut h, gatt) = ble_accessory_with_db().await;

        // Queue a perfectly valid sealed read response (recv counter 0) — it
        // would decode cleanly if the session were used directly.
        let mut plain = vec![0x02, 0x01, 0x00];
        let vbody = crate::pdu::encode_value_param(&[0x01]);
        plain.extend_from_slice(&u16::try_from(vbody.len()).unwrap().to_le_bytes());
        plain.extend_from_slice(&vbody);
        let sealed =
            hap_crypto::aead::chacha20poly1305_seal(&[0u8; 32], &[0u8; 12], &[], &plain).unwrap();
        gatt.queue_read("00000025-0000-1000-8000-0026bb765291", sealed);

        // Simulate a reconnect: the accessory dropped the session. The read must
        // now re-run Pair Verify *before* touching the session. The mock can't
        // complete that handshake, so the read surfaces an error rather than
        // silently decoding with the dead session.
        gatt.bump_generation();
        let err = h.read(1, 11).await.unwrap_err();
        assert!(
            !matches!(err, BleError::CharacteristicNotFound { .. }),
            "expected a verify/transport error from the re-verify attempt, got {err:?}"
        );
    }

    #[tokio::test]
    async fn dedup_emits_once_per_gsn_and_never_downgrades() {
        let emitted = Mutex::new(HashMap::new());
        // Fresh (iid, gsn): emit and record.
        assert!(dedup_should_emit(&emitted, 11, 9).await);
        // Same gsn again: suppressed.
        assert!(!dedup_should_emit(&emitted, 11, 9).await);
        // Newer gsn: emit, record moves forward.
        assert!(dedup_should_emit(&emitted, 11, 10).await);
        // Out-of-order older gsn (stalled poll racing a broadcast): still
        // emits (distinct gsn) but must NOT downgrade the stored record …
        assert!(dedup_should_emit(&emitted, 11, 9).await);
        // … so a repeat of the newest gsn stays suppressed.
        assert!(!dedup_should_emit(&emitted, 11, 10).await);
        // Wraparound: 1 is newer than 65535 in RFC 1982 order.
        assert!(dedup_should_emit(&emitted, 12, 65535).await);
        assert!(dedup_should_emit(&emitted, 12, 1).await);
        assert!(!dedup_should_emit(&emitted, 12, 1).await);
    }

    #[tokio::test]
    #[allow(clippy::unwrap_used)]
    async fn write_sends_secure_pdu_and_accepts_success() {
        let (mut h, gatt) = ble_accessory_with_db().await;
        // Sealed empty success response (control, tid, status=0), zero keys.
        let plain = vec![0x02, 0x01, 0x00];
        let sealed =
            hap_crypto::aead::chacha20poly1305_seal(&[0u8; 32], &[0u8; 12], &[], &plain).unwrap();
        gatt.queue_read("00000025-0000-1000-8000-0026bb765291", sealed);
        h.write(1, 11, hap_model::format::CharValue::Bool(true))
            .await
            .unwrap();
    }

    #[tokio::test]
    #[allow(clippy::unwrap_used)]
    async fn write_surfaces_nonzero_pdu_status() {
        let (mut h, gatt) = ble_accessory_with_db().await;
        let plain = vec![0x02, 0x01, 0x06]; // status 6 = invalid request
        let sealed =
            hap_crypto::aead::chacha20poly1305_seal(&[0u8; 32], &[0u8; 12], &[], &plain).unwrap();
        gatt.queue_read("00000025-0000-1000-8000-0026bb765291", sealed);
        let err = h
            .write(1, 11, hap_model::format::CharValue::Bool(true))
            .await
            .unwrap_err();
        assert!(matches!(err, BleError::RequestRejected(6)));
    }

    #[tokio::test]
    #[allow(clippy::unwrap_used)]
    async fn pairing_id_exposes_the_stored_pairing() {
        let (h, _g) = ble_accessory_with_db().await;
        assert_eq!(h.pairing_id(), "AE:EC:86:C0:BF:D7");
    }

    #[tokio::test]
    #[allow(clippy::unwrap_used)]
    async fn disconnect_is_callable_on_the_accessory() {
        let (h, _g) = ble_accessory_with_db().await;
        h.disconnect().await; // MockGatt uses the default no-op; must compile + run
    }

    #[tokio::test]
    #[allow(clippy::unwrap_used)]
    async fn self_sourcing_watch_errors_without_source() {
        let (mut h, _g) = ble_accessory_with_db().await;
        // No advert source set → must error, never silently no-op.
        let err = h.watch_sleepy_events(vec![(1, 11)]).await.unwrap_err();
        assert!(matches!(err, BleError::NoAdvertSource));
    }

    #[tokio::test]
    #[allow(clippy::unwrap_used)]
    async fn self_sourcing_watch_emits_via_set_source() {
        use tokio_stream::StreamExt as _;
        let (mut h, gatt) = ble_accessory_with_db().await;
        // fixture pairing id is "AE:EC:86:C0:BF:D7" → device_id AE:EC:86:C0:BF:D7
        h.set_advert_source(gatt.clone() as std::sync::Arc<dyn crate::gatt::AdvertSource>);
        // queue the sealed read the poll will issue for iid 11 (Bool true)
        let mut plain = vec![0x02, 0x01, 0x00];
        let vbody = crate::pdu::encode_value_param(&[0x01]);
        plain.extend_from_slice(&u16::try_from(vbody.len()).unwrap().to_le_bytes());
        plain.extend_from_slice(&vbody);
        let sealed =
            hap_crypto::aead::chacha20poly1305_seal(&[0u8; 32], &[0u8; 12], &[], &plain).unwrap();
        gatt.queue_read("00000025-0000-1000-8000-0026bb765291", sealed);
        h.watch_sleepy_events(vec![(1, 11)]).await.unwrap();
        let mut events = h.events();
        // 0x06 advert for device AE:EC:86:C0:BF:D7 (0xAE,0xEC,0x86,0xC0,0xBF,0xD7), GSN 9
        gatt.advert_sender()
            .send(crate::gatt::RawAdvert {
                manufacturer_data: vec![
                    0x06, 0x21, 0x01, 0xAE, 0xEC, 0x86, 0xC0, 0xBF, 0xD7, 0x01, 0x00, 0x09, 0x00,
                    0x01, 0x00,
                ],
            })
            .await
            .unwrap();
        let ev = events.next().await.unwrap();
        assert_eq!((ev.aid, ev.iid), (1, 11));
    }
}
