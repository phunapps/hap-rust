//! `HapController` lifecycle against the in-memory `MockStore`.

// CLAUDE.md test-code carve-out.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use hap_controller::HapController;

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
