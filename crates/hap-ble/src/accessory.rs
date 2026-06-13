//! The public per-accessory handle: typed find/read/subscribe/events over an
//! established session.

use crate::db;
use crate::error::{BleError, Result};
use crate::gatt::GattConnection;
use crate::pdu::{self, OpCode};
use hap_model::format::{CharFormat, CharValue};
use hap_model::tree::Accessory;
use hap_model::{CharacteristicType, ServiceType};
use std::collections::HashMap;
use std::sync::Arc;
use crate::session::BleSession;
use tokio_stream::StreamExt as _;

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

/// A connected BLE accessory: holds the GATT link, the secure session, the
/// cached attribute database, and a map from (aid, iid) to GATT characteristic
/// UUID for issuing PDUs.
pub struct BleAccessory {
    gatt: Arc<dyn GattConnection>,
    session: BleSession,
    frag_size: usize,
    accessories: Vec<Accessory>,
    /// (aid, iid) -> characteristic UUID, format.
    chars: HashMap<(u64, u64), (String, CharFormat)>,
    tid: u8,
    events_tx: tokio::sync::broadcast::Sender<CharacteristicEvent>,
}

impl BleAccessory {
    /// Wrap an established GATT link + session. Call [`BleAccessory::refresh_db`]
    /// before use.
    pub(crate) fn new(gatt: Arc<dyn GattConnection>, session: BleSession, frag_size: usize) -> Self {
        let (events_tx, _) = tokio::sync::broadcast::channel(64);
        Self {
            gatt,
            session,
            frag_size,
            accessories: Vec::new(),
            chars: HashMap::new(),
            tid: 0,
            events_tx,
        }
    }

    /// (Re)build the cached attribute database from characteristic signatures.
    ///
    /// # Errors
    /// Propagates GATT/PDU/model errors.
    pub async fn refresh_db(&mut self, encrypted: bool) -> Result<()> {
        self.accessories =
            db::build_db(self.gatt.as_ref(), &mut self.session, self.frag_size, encrypted).await?;
        self.chars.clear();
        let gatt_services = self.gatt.enumerate().await?;
        let mut uuid_by_iid: HashMap<u64, String> = HashMap::new();
        for gs in gatt_services {
            for gc in gs.characteristics {
                uuid_by_iid.insert(u64::from(gc.iid), gc.uuid);
            }
        }
        for acc in &self.accessories {
            for svc in &acc.services {
                for ch in &svc.characteristics {
                    if let Some(uuid) = uuid_by_iid.get(&ch.iid) {
                        self.chars
                            .insert((acc.aid, ch.iid), (uuid.clone(), ch.format));
                    }
                }
            }
        }
        Ok(())
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
        self.tid = self.tid.wrapping_add(1);
        let iid16 = u16::try_from(iid).unwrap_or(0);
        let resp = pdu::request_secure(
            self.gatt.as_ref(),
            &mut self.session,
            &uuid,
            OpCode::CharacteristicRead,
            self.tid,
            iid16,
            &[],
            self.frag_size,
        )
        .await?;
        let raw = pdu::value_param(&resp.body)?;
        db::decode_value(format, &raw)
    }

    /// Subscribe to value-change events for a characteristic. The accessory's
    /// notifications are decoded and published on [`BleAccessory::events`]. For
    /// this milestone, notification payloads are treated as unencrypted
    /// read-style PDUs (connected-event security is reconciled on hardware
    /// later).
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
        tokio::spawn(async move {
            while let Some(raw) = rx.recv().await {
                if let Ok(resp) = pdu::decode_response(&raw) {
                    if let Ok(value_bytes) = pdu::value_param(&resp.body) {
                        if let Ok(value) = db::decode_value(format, &value_bytes) {
                            let _ = tx.send(CharacteristicEvent { aid, iid, value });
                        }
                    }
                }
            }
        });
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
        w.push(crate::pdu::param::PRESENTATION_FORMAT, &[0x01, 0, 0, 0, 0, 0, 0]);
        let mut resp = vec![0x02, 0x01, 0x00];
        resp.extend_from_slice(&u16::try_from(body.len()).unwrap().to_le_bytes());
        resp.extend_from_slice(&body);
        resp
    }

    #[allow(clippy::unwrap_used)]
    async fn handle_with_db() -> (BleAccessory, Arc<MockGatt>) {
        let gatt = Arc::new(MockGatt::new().with_services(vec![on_service()]));
        gatt.queue_read("00000025-0000-1000-8000-0026bb765291", sig_resp());
        let session = BleSession::new(SessionKeys { read_key: [0; 32], write_key: [0; 32] });
        let mut h = BleAccessory::new(gatt.clone(), session, 512);
        h.refresh_db(/*encrypted=*/ false).await.unwrap();
        (h, gatt)
    }

    #[tokio::test]
    #[allow(clippy::unwrap_used)]
    async fn find_locates_characteristic() {
        let (h, _g) = handle_with_db().await;
        let (aid, iid) = h.find(ServiceType::LightBulb, CharacteristicType::On).unwrap();
        assert_eq!((aid, iid), (1, 11));
    }

    #[tokio::test]
    #[allow(clippy::unwrap_used)]
    async fn find_missing_errors() {
        let (h, _g) = handle_with_db().await;
        let err = h.find(ServiceType::LightBulb, CharacteristicType::Brightness).unwrap_err();
        assert!(matches!(err, BleError::CharacteristicNotFound { .. }));
    }

    #[tokio::test]
    #[allow(clippy::unwrap_used)]
    async fn subscribe_then_event_decodes_value() {
        use tokio_stream::StreamExt as _;
        let (mut h, gatt) = handle_with_db().await;
        h.subscribe(1, 11).await.unwrap();
        let mut events = h.events();

        // The accessory pushes a notification: a Characteristic-Read-style
        // response PDU (unencrypted in this test) with value param [0x01].
        let body = crate::pdu::encode_value_param(&[0x01]);
        let mut notif = vec![0x02, 0x00, 0x00];
        notif.extend_from_slice(&u16::try_from(body.len()).unwrap().to_le_bytes());
        notif.extend_from_slice(&body);
        gatt.notifier("00000025-0000-1000-8000-0026bb765291")
            .unwrap()
            .send(notif)
            .await
            .unwrap();

        let ev = events.next().await.unwrap();
        assert_eq!(ev.iid, 11);
        assert_eq!(ev.value, hap_model::format::CharValue::Bool(true));
    }
}
