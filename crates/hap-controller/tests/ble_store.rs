//! Store-level behavior of the BLE controller arms (no radio needed).
#![allow(clippy::unwrap_used)]

use hap_controller::{AccessoryHandle, HapController, HapError};
use hap_pairing::{
    JsonFileStore, PairingStore as _, StoredAccessory, StoredBroadcast, StoredTransport,
};

fn ble_record(id: &str) -> StoredAccessory {
    StoredAccessory {
        pairing: hap_crypto::AccessoryPairing {
            pairing_id: id.into(),
            ltpk: [1u8; 32],
        },
        transport: StoredTransport::Ble {
            device_id: [9, 9, 9, 9, 9, 9],
            broadcast: Some(StoredBroadcast {
                key: hap_crypto::BroadcastKey::from_bytes([3u8; 32]),
                gsn: 5,
            }),
        },
    }
}

#[tokio::test]
async fn admin_ops_on_ble_records_are_unsupported() {
    let dir = tempfile::tempdir().unwrap();
    let store = JsonFileStore::new(dir.path().join("p.json"));
    store.save_pairing(&ble_record("ble-x")).await.unwrap();
    let c = HapController::new(store).await.unwrap();
    assert!(matches!(
        c.list_pairings("ble-x").await.unwrap_err(),
        HapError::UnsupportedByTransport("list_pairings")
    ));
    assert!(matches!(
        c.add_pairing("ble-x", "other", [0u8; 32], false)
            .await
            .unwrap_err(),
        HapError::UnsupportedByTransport("add_pairing")
    ));
}

#[tokio::test]
async fn paired_lists_ble_records_too() {
    let dir = tempfile::tempdir().unwrap();
    let store = JsonFileStore::new(dir.path().join("p.json"));
    store.save_pairing(&ble_record("ble-y")).await.unwrap();
    let c = HapController::new(store).await.unwrap();
    assert_eq!(c.paired(), vec!["ble-y".to_string()]);
}

#[tokio::test]
async fn save_state_persists_latest_gsn() {
    let dir = tempfile::tempdir().unwrap();
    let store = JsonFileStore::new(dir.path().join("p.json"));
    // Seed a BLE record whose pairing_id matches the mock fixture's, with a
    // stale gsn — save_state should overwrite it with the fixture's current
    // broadcast state.
    store
        .save_pairing(&ble_record("AE:EC:86:C0:BF:D7"))
        .await
        .unwrap();
    let controller = HapController::new(store).await.unwrap();

    let (accessory, _gatt) = hap_ble::test_support::ble_accessory_with_db().await;
    let handle = AccessoryHandle::from_ble_for_tests(accessory);

    controller.save_state(&handle).await.unwrap();

    let reread = JsonFileStore::new(dir.path().join("p.json"));
    let stored = reread
        .load_pairings()
        .await
        .unwrap()
        .into_iter()
        .find(|s| s.pairing.pairing_id == "AE:EC:86:C0:BF:D7")
        .unwrap();
    let StoredTransport::Ble { broadcast, .. } = stored.transport else {
        panic!("expected a BLE record");
    };
    assert_eq!(broadcast.unwrap().gsn, 0);
}
