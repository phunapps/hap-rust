//! Cold-arm sleepy watch, driven entirely by the mock connector + MockGatt.
#![allow(clippy::unwrap_used)]
use hap_ble::test_support::{ble_accessory_with_db, MockSleepyConnector};
use hap_controller::{HapController, JsonFileStore};
use hap_pairing::{PairingStore as _, StoredAccessory, StoredBroadcast, StoredTransport};
use std::sync::Arc;
use std::time::Duration;
use tokio_stream::StreamExt as _;

#[tokio::test]
async fn cold_arm_emits_and_autopersists() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("p.json");
    let store = JsonFileStore::new(&path);
    // Seed a BLE pairing whose id matches the fixture (AE:EC:86:C0:BF:D7), gsn 0.
    store
        .save_pairing(&StoredAccessory {
            pairing: hap_crypto::AccessoryPairing {
                pairing_id: "AE:EC:86:C0:BF:D7".into(),
                ltpk: [0u8; 32],
            },
            transport: StoredTransport::Ble {
                device_id: [0xAE, 0xEC, 0x86, 0xC0, 0xBF, 0xD7],
                broadcast: Some(StoredBroadcast {
                    key: hap_crypto::BroadcastKey::from_bytes([0u8; 32]),
                    gsn: 0,
                }),
            },
        })
        .await
        .unwrap();

    let (acc, gatt) = ble_accessory_with_db().await;
    // queue the sealed read the poll issues for iid 11 → Bool(true)
    let mut plain = vec![0x02, 0x01, 0x00];
    let vbody = {
        let v = vec![0x01, 0x01, 0x01];
        v
    };
    plain.extend_from_slice(&u16::try_from(vbody.len()).unwrap().to_le_bytes());
    plain.extend_from_slice(&vbody);
    // The cold-arm path performs TWO encrypted GATT reads on this characteristic,
    // over one shared BLE session, before the watch goes live:
    //   1. the config-response read that `enable_broadcasts` issues while
    //      connected (opened at session receive-counter 0), then
    //   2. the catch-up read the 0x06 poll issues (now at receive-counter 1,
    //      because the accessory's disconnect is a mock no-op that — unlike real
    //      hardware — does not invalidate the session and reset the counter).
    // The BLE session nonce is four zero bytes followed by the little-endian
    // counter, so queue the same Bool(true) PDU sealed once per counter value.
    let seal_at = |ctr: u64| {
        let mut nonce = [0u8; 12];
        nonce[4..].copy_from_slice(&ctr.to_le_bytes());
        hap_crypto::aead::chacha20poly1305_seal(&[0u8; 32], &nonce, &[], &plain).unwrap()
    };
    gatt.queue_read("00000025-0000-1000-8000-0026bb765291", seal_at(0));
    gatt.queue_read("00000025-0000-1000-8000-0026bb765291", seal_at(1));
    let connector = Arc::new(MockSleepyConnector::new(acc, gatt.clone()));

    let mut controller = HapController::new(store).await.unwrap();
    controller.set_sleepy_connector_for_tests(connector.clone());
    let watch = controller
        .watch_sleepy("AE:EC:86:C0:BF:D7", vec![(1, 11)])
        .await
        .unwrap();
    let mut events = watch.events();

    // Inject a 0x06 GSN bump; expect an event + auto-persist of the new gsn.
    connector
        .advert_sender()
        .send(hap_ble::RawAdvert {
            manufacturer_data: vec![
                0x06, 0x21, 0x01, 0xAE, 0xEC, 0x86, 0xC0, 0xBF, 0xD7, 0x01, 0x00, 0x09, 0x00, 0x01,
                0x00,
            ],
        })
        .await
        .unwrap();
    let ev = tokio::time::timeout(Duration::from_secs(2), events.next())
        .await
        .unwrap()
        .unwrap();
    assert_eq!((ev.aid, ev.iid), (1, 11));
    assert_eq!(ev.value, hap_model::format::CharValue::Bool(true));

    // Auto-persist should (eventually) write gsn 9 to the store — poll instead
    // of a fixed sleep so this isn't flaky under load.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    let gsn = loop {
        let reloaded = JsonFileStore::new(&path).load_pairings().await.unwrap();
        let gsn = match &reloaded[0].transport {
            StoredTransport::Ble { broadcast, .. } => broadcast.as_ref().unwrap().gsn,
            StoredTransport::Ip { .. } => panic!(),
        };
        if gsn == 9 || tokio::time::Instant::now() >= deadline {
            break gsn;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    };
    assert_eq!(gsn, 9);
}

#[tokio::test]
async fn watch_sleepy_on_ip_or_absent_errors() {
    let dir = tempfile::tempdir().unwrap();
    let store = JsonFileStore::new(dir.path().join("p.json"));
    let controller = HapController::new(store).await.unwrap();
    let err = controller.watch_sleepy("nope", vec![]).await.unwrap_err();
    assert!(matches!(err, hap_controller::HapError::UnknownAccessory(_)));
}

#[tokio::test]
async fn watch_sleepy_on_ip_accessory_errors() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("p.json");
    let store = JsonFileStore::new(&path);
    store
        .save_pairing(&StoredAccessory {
            pairing: hap_crypto::AccessoryPairing {
                pairing_id: "ip-accessory".into(),
                ltpk: [0u8; 32],
            },
            transport: StoredTransport::Ip {
                addr: "192.0.2.1:51826".parse().unwrap(),
            },
        })
        .await
        .unwrap();

    let controller = HapController::new(store).await.unwrap();
    let err = controller
        .watch_sleepy("ip-accessory", vec![])
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        hap_controller::HapError::UnsupportedByTransport(_)
    ));
}
