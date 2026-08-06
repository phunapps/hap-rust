//! Test-support seam: the in-memory GATT mock and a ready-made accessory
//! fixture. Compiled for this crate's own tests and for consumers that enable
//! the `test-support` feature. **Exempt from semver guarantees.**

use crate::accessory::BleAccessory;
use crate::accessory::SecureContext;
use crate::gatt::{GattCharacteristic, GattConnection, GattService};
use crate::session::BleSession;
use hap_crypto::SessionKeys;
use std::sync::Arc;

pub use crate::gatt::MockGatt;

/// UUID of the HAP On characteristic (the single characteristic in the fixture).
const ON_CHAR_UUID: &str = "00000025-0000-1000-8000-0026bb765291";

/// UUID of the Pair Verify characteristic.
const VERIFY_CHAR_UUID: &str = "0000004e-0000-1000-8000-0026bb765291";

/// UUID of the Pairing-Pairings characteristic.
const PAIRINGS_CHAR_UUID: &str = "00000050-0000-1000-8000-0026bb765291";

#[allow(clippy::unwrap_used)] // test-support fixture: failures here are test failures
fn on_le() -> Vec<u8> {
    let hex = "00000025000010008000".to_string() + "0026bb765291";
    let mut b: Vec<u8> = (0..16)
        .map(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap())
        .collect();
    b.reverse();
    b
}

#[allow(clippy::unwrap_used)] // test-support fixture: failures here are test failures
fn on_service() -> GattService {
    GattService {
        uuid: "00000043-0000-1000-8000-0026bb765291".into(), // LightBulb
        iid: 10,
        characteristics: vec![GattCharacteristic {
            uuid: ON_CHAR_UUID.into(), // On
            iid: 11,
        }],
    }
}

#[allow(clippy::unwrap_used)] // test-support fixture: failures here are test failures
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

/// Build a paired-looking accessory over the mock GATT device with one
/// LightBulb/On characteristic (aid 1, iid 11, Bool), zeroed session keys,
/// broadcast key `[0u8; 32]`, controller id `"test-controller"`, pairing id
/// `"AE:EC:86:C0:BF:D7"`.
///
/// # Panics
///
/// Panics if the mock GATT enumeration or database build fails (should never
/// happen in a correct test setup).
#[allow(clippy::unwrap_used)] // test-support fixture: failures here are test failures
pub async fn ble_accessory_with_db() -> (BleAccessory, Arc<MockGatt>) {
    let gatt = Arc::new(MockGatt::new().with_services(vec![on_service()]));
    gatt.queue_read(ON_CHAR_UUID, sig_resp());
    let session = BleSession::new(SessionKeys {
        read_key: [0; 32],
        write_key: [0; 32],
    });
    let services = gatt.enumerate().await.unwrap();
    let accessories = crate::db::build_db(gatt.as_ref(), &services, 512)
        .await
        .unwrap();
    let ctx = SecureContext {
        session,
        session_generation: 0,
        keypair: hap_crypto::ControllerKeypair::generate("test-controller".into()),
        pairing: hap_crypto::AccessoryPairing {
            pairing_id: "AE:EC:86:C0:BF:D7".into(),
            ltpk: [0; 32],
        },
        verify_char: VERIFY_CHAR_UUID.into(),
        verify_iid: 1,
        pairings_char: PAIRINGS_CHAR_UUID.into(),
        pairings_iid: 2,
        broadcast_key: hap_crypto::BroadcastKey::from_bytes([0u8; 32]),
        initial_gsn: 0,
    };
    let h = BleAccessory::new(gatt.clone(), ctx, 512, &services, accessories);
    (h, gatt)
}

/// A [`SleepyConnector`](crate::sleepy::SleepyConnector) that returns a
/// preloaded accessory — for hardware-free cold-arm tests. Testing seam,
/// semver-exempt.
pub struct MockSleepyConnector {
    inner: tokio::sync::Mutex<Option<BleAccessory>>,
    advert: Arc<MockGatt>,
}

impl MockSleepyConnector {
    /// Wrap `accessory`, first setting its advert source to `advert` — the
    /// same [`MockGatt`] the caller will push adverts through.
    #[must_use]
    pub fn new(mut accessory: BleAccessory, advert: Arc<MockGatt>) -> Self {
        accessory.set_advert_source(advert.clone() as Arc<dyn crate::gatt::AdvertSource>);
        Self {
            inner: tokio::sync::Mutex::new(Some(accessory)),
            advert,
        }
    }

    /// The mock advert channel (inject 0x06/0x11 adverts) for the returned accessory.
    #[must_use]
    pub fn advert_sender(&self) -> tokio::sync::mpsc::Sender<crate::gatt::RawAdvert> {
        self.advert.advert_sender()
    }
}

#[async_trait::async_trait]
impl crate::sleepy::SleepyConnector for MockSleepyConnector {
    async fn connect(
        &self,
        _device_id: [u8; 6],
        _pairing: &hap_crypto::AccessoryPairing,
        _broadcast: Option<crate::broadcast_state::BleBroadcastState>,
    ) -> crate::error::Result<BleAccessory> {
        self.inner
            .lock()
            .await
            .take()
            .ok_or(crate::error::BleError::AccessoryNotFound)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod sleepy_tests {
    use super::*;
    use crate::sleepy::SleepyConnector;

    #[tokio::test]
    async fn mock_connector_returns_ready_accessory_with_source() {
        let (acc, gatt) = ble_accessory_with_db().await;
        let conn = MockSleepyConnector::new(acc, gatt.clone());
        let pairing = hap_crypto::AccessoryPairing {
            pairing_id: "AE:EC:86:C0:BF:D7".into(),
            ltpk: [0u8; 32],
        };
        let mut ble = conn
            .connect([0xAE, 0xEC, 0x86, 0xC0, 0xBF, 0xD7], &pairing, None)
            .await
            .unwrap();
        // The returned accessory self-sources (advert source already set):
        ble.watch_sleepy_events(vec![(1, 11)]).await.unwrap();
    }
}
