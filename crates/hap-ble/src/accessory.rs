//! The public per-accessory handle: typed find/read/subscribe/events over an
//! established session.

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

/// The maximum number of mid-operation re-verify retries before giving up — a
/// backstop against a link that reconnects on every attempt.
const MAX_REVIVE_RETRIES: u32 = 3;

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
    let session = pairing::pair_verify(
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

/// A connected BLE accessory: holds the GATT link, the secure session, the
/// cached attribute database, and a map from (aid, iid) to GATT characteristic
/// UUID for issuing PDUs.
pub struct BleAccessory {
    gatt: Arc<dyn GattConnection>,
    secure: Arc<Mutex<Secure>>,
    reviver: Arc<Reviver>,
    frag_size: usize,
    accessories: Vec<Accessory>,
    /// (aid, iid) -> characteristic UUID, format.
    chars: HashMap<(u64, u64), (String, CharFormat)>,
    events_tx: tokio::sync::broadcast::Sender<CharacteristicEvent>,
    /// Background event-forwarding tasks, aborted when the handle is dropped.
    tasks: Vec<tokio::task::JoinHandle<()>>,
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
    /// `session_generation` is the link generation at which `session` was
    /// minted, and `verify_iid` / `keypair` / `pairing` are the material to
    /// re-run Pair Verify if a reconnect later invalidates the session.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        gatt: Arc<dyn GattConnection>,
        session: BleSession,
        session_generation: u64,
        frag_size: usize,
        gatt_services: &[GattService],
        accessories: Vec<Accessory>,
        keypair: ControllerKeypair,
        pairing: AccessoryPairing,
        verify_char: String,
        verify_iid: u16,
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
                session,
                tid: 0,
                generation: session_generation,
            })),
            reviver: Arc::new(Reviver {
                keypair,
                pairing,
                verify_char,
                verify_iid,
                frag_size,
            }),
            frag_size,
            accessories,
            chars,
            events_tx,
            tasks: Vec::new(),
        }
    }

    /// The cached attribute database.
    pub fn accessories(&self) -> &[Accessory] {
        &self.accessories
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

    /// Subscribe to value-change events for a characteristic. HAP-BLE connected
    /// events use the GATT notification only as a **trigger**: when it fires we
    /// issue an encrypted Characteristic-Read for the new value and publish it
    /// on [`BleAccessory::events`].
    ///
    /// # Errors
    /// [`BleError::CharacteristicNotFound`] if unknown; otherwise GATT errors.
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
    use crate::gatt::{GattCharacteristic, GattService, MockGatt};
    use hap_crypto::SessionKeys;

    #[allow(clippy::unwrap_used)]
    fn on_le() -> Vec<u8> {
        let hex = "00000025000010008000".to_string() + "0026bb765291";
        let mut b: Vec<u8> = (0..16)
            .map(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap())
            .collect();
        b.reverse();
        b
    }

    fn on_service() -> GattService {
        GattService {
            uuid: "00000043-0000-1000-8000-0026bb765291".into(), // LightBulb
            iid: 10,
            characteristics: vec![GattCharacteristic {
                uuid: "00000025-0000-1000-8000-0026bb765291".into(), // On
                iid: 11,
            }],
        }
    }

    #[allow(clippy::unwrap_used)]
    fn sig_resp() -> Vec<u8> {
        let mut body = Vec::new();
        let mut w = hap_tlv8::Tlv8Writer::new(&mut body);
        w.push(crate::pdu::param::CHAR_TYPE, &on_le());
        w.push(crate::pdu::param::PROPERTIES, &0x0083u16.to_le_bytes()); // read+write+events
        w.push(
            crate::pdu::param::PRESENTATION_FORMAT,
            &[0x01, 0, 0, 0, 0, 0, 0],
        );
        let mut resp = vec![0x02, 0x01, 0x00];
        resp.extend_from_slice(&u16::try_from(body.len()).unwrap().to_le_bytes());
        resp.extend_from_slice(&body);
        resp
    }

    #[allow(clippy::unwrap_used)]
    async fn handle_with_db() -> (BleAccessory, Arc<MockGatt>) {
        let gatt = Arc::new(MockGatt::new().with_services(vec![on_service()]));
        gatt.queue_read("00000025-0000-1000-8000-0026bb765291", sig_resp());
        let session = BleSession::new(SessionKeys {
            read_key: [0; 32],
            write_key: [0; 32],
        });
        let services = gatt.enumerate().await.unwrap();
        let accessories = crate::db::build_db(gatt.as_ref(), &services, 512)
            .await
            .unwrap();
        let h = BleAccessory::new(
            gatt.clone(),
            session,
            0,
            512,
            &services,
            accessories,
            ControllerKeypair::generate("test-controller".into()),
            AccessoryPairing {
                pairing_id: "AE:EC:86:C0:BF:D7".into(),
                ltpk: [0; 32],
            },
            "0000004e-0000-1000-8000-0026bb765291".into(),
            1,
        );
        (h, gatt)
    }

    #[tokio::test]
    #[allow(clippy::unwrap_used)]
    async fn find_locates_characteristic() {
        let (h, _g) = handle_with_db().await;
        let (aid, iid) = h
            .find(ServiceType::LightBulb, CharacteristicType::On)
            .unwrap();
        assert_eq!((aid, iid), (1, 11));
    }

    #[tokio::test]
    #[allow(clippy::unwrap_used)]
    async fn find_missing_errors() {
        let (h, _g) = handle_with_db().await;
        let err = h
            .find(ServiceType::LightBulb, CharacteristicType::Brightness)
            .unwrap_err();
        assert!(matches!(err, BleError::CharacteristicNotFound { .. }));
    }

    #[tokio::test]
    #[allow(clippy::unwrap_used)]
    async fn subscribe_then_event_decodes_value() {
        use tokio_stream::StreamExt as _;
        let (mut h, gatt) = handle_with_db().await;

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
    async fn read_after_reconnect_re_verifies_before_using_session() {
        let (mut h, gatt) = handle_with_db().await;

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
}
