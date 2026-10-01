//! `HapController` lifecycle against the in-memory `MockStore`.

// CLAUDE.md test-code carve-out.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use hap_controller::{HapController, StoredTransport};
use hap_pairing::{JsonFileStore, PairingStore as _};

mod common;

#[tokio::test]
async fn new_creates_and_persists_a_controller_identity() {
    let store = common::MockStore::new();
    let controller = HapController::new(store).await.unwrap();
    // A fresh store has no pairings.
    assert!(controller.paired().is_empty());
}

#[tokio::test]
async fn paired_lists_seeded_accessory_ids() {
    let entry = common::sample_pairing("AA:BB:CC:DD:EE:FF");
    let store = common::MockStore::new().with_pairing(entry);
    let controller = HapController::new(store).await.unwrap();
    assert_eq!(controller.paired(), vec!["AA:BB:CC:DD:EE:FF".to_string()]);
}

#[tokio::test]
async fn remove_pairing_unknown_id_errors() {
    let store = common::MockStore::new();
    let mut controller = HapController::new(store).await.unwrap();
    let err = controller.remove_pairing("nope").await.unwrap_err();
    assert!(matches!(
        err,
        hap_controller::HapError::UnknownAccessory(id) if id == "nope"
    ));
}

/// A [`JsonFileStore`] for the controller plus a second handle on the same
/// file, so a test can observe (or mutate) the store from outside the
/// controller that owns the first handle.
fn file_stores(dir: &tempfile::TempDir) -> (JsonFileStore, JsonFileStore) {
    let path = dir.path().join("p.json");
    (JsonFileStore::new(path.clone()), JsonFileStore::new(path))
}

async fn stored_ids(store: &JsonFileStore) -> Vec<String> {
    let mut ids: Vec<String> = store
        .load_pairings()
        .await
        .unwrap()
        .into_iter()
        .map(|s| s.pairing.pairing_id)
        .collect();
    ids.sort();
    ids
}

#[tokio::test]
async fn forget_pairing_deletes_from_store_and_paired_cache() {
    let dir = tempfile::tempdir().unwrap();
    let (store, observer) = file_stores(&dir);
    // `sample_pairing` points at 127.0.0.1:0, which nothing can answer: a
    // forget that tried to contact the accessory would fail here.
    store
        .save_pairing(&common::sample_pairing("AA:BB:CC:DD:EE:FF"))
        .await
        .unwrap();
    let mut controller = HapController::new(store).await.unwrap();

    controller
        .forget_pairing("AA:BB:CC:DD:EE:FF")
        .await
        .unwrap();

    assert!(controller.paired().is_empty());
    assert!(stored_ids(&observer).await.is_empty());
}

#[tokio::test]
async fn forget_pairing_unknown_id_is_ok() {
    let mut controller = HapController::new(common::MockStore::new()).await.unwrap();
    controller.forget_pairing("nope").await.unwrap();
}

#[tokio::test]
async fn forget_pairing_twice_is_ok() {
    let store = common::MockStore::new().with_pairing(common::sample_pairing("AA:BB:CC:DD:EE:FF"));
    let mut controller = HapController::new(store).await.unwrap();
    controller
        .forget_pairing("AA:BB:CC:DD:EE:FF")
        .await
        .unwrap();
    controller
        .forget_pairing("AA:BB:CC:DD:EE:FF")
        .await
        .unwrap();
    assert!(controller.paired().is_empty());
}

#[tokio::test]
async fn forget_pairing_matches_the_id_case_insensitively() {
    let dir = tempfile::tempdir().unwrap();
    let (store, observer) = file_stores(&dir);
    store
        .save_pairing(&common::sample_pairing("AA:BB:CC:DD:EE:FF"))
        .await
        .unwrap();
    let mut controller = HapController::new(store).await.unwrap();

    controller
        .forget_pairing("aa:bb:cc:dd:ee:ff")
        .await
        .unwrap();

    // The store is keyed by the canonical (uppercase) id; a delete issued
    // with the caller's lowercase form would have left the record behind.
    assert!(controller.paired().is_empty());
    assert!(stored_ids(&observer).await.is_empty());
}

#[tokio::test]
async fn forget_pairing_leaves_other_pairings_untouched() {
    let dir = tempfile::tempdir().unwrap();
    let (store, observer) = file_stores(&dir);
    store
        .save_pairing(&common::sample_pairing("AA:BB:CC:DD:EE:FF"))
        .await
        .unwrap();
    store
        .save_pairing(&common::sample_pairing("11:22:33:44:55:66"))
        .await
        .unwrap();
    let mut controller = HapController::new(store).await.unwrap();

    controller
        .forget_pairing("AA:BB:CC:DD:EE:FF")
        .await
        .unwrap();

    assert_eq!(controller.paired(), vec!["11:22:33:44:55:66".to_string()]);
    assert_eq!(
        stored_ids(&observer).await,
        vec!["11:22:33:44:55:66".to_string()]
    );
}

#[tokio::test]
async fn forget_pairing_drops_a_stale_cache_entry_whose_record_is_gone() {
    let dir = tempfile::tempdir().unwrap();
    let (store, observer) = file_stores(&dir);
    store
        .save_pairing(&common::sample_pairing("AA:BB:CC:DD:EE:FF"))
        .await
        .unwrap();
    let mut controller = HapController::new(store).await.unwrap();
    // Delete behind the controller's back: the store no longer has the
    // record, but the `paired()` snapshot still lists it.
    observer.delete_pairing("AA:BB:CC:DD:EE:FF").await.unwrap();
    assert_eq!(controller.paired(), vec!["AA:BB:CC:DD:EE:FF".to_string()]);

    controller
        .forget_pairing("aa:bb:cc:dd:ee:ff")
        .await
        .unwrap();

    assert!(controller.paired().is_empty());
}

#[tokio::test]
async fn failed_remove_pairing_leaves_local_state_unchanged() {
    let dir = tempfile::tempdir().unwrap();
    let (store, observer) = file_stores(&dir);
    // An "accessory" that accepts the TCP connection and hangs up at once:
    // the dial succeeds (so no mDNS fallback browse), then Pair Verify fails.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((socket, _)) = listener.accept().await {
            drop(socket);
        }
    });
    let mut entry = common::sample_pairing("AA:BB:CC:DD:EE:FF");
    entry.transport = StoredTransport::Ip { addr };
    store.save_pairing(&entry).await.unwrap();
    let mut controller = HapController::new(store).await.unwrap();

    controller
        .remove_pairing("AA:BB:CC:DD:EE:FF")
        .await
        .unwrap_err();

    assert_eq!(controller.paired(), vec!["AA:BB:CC:DD:EE:FF".to_string()]);
    assert_eq!(
        stored_ids(&observer).await,
        vec!["AA:BB:CC:DD:EE:FF".to_string()]
    );
}
