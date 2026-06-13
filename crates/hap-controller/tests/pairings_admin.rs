//! list_pairings / add_pairing surface PairingsAdmin; here we cover the
//! store-lookup path (UnknownAccessory). Full behavior is tested in hap-pairing.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use hap_controller::HapController;

mod common;

#[tokio::test]
async fn list_pairings_unknown_id_errors() {
    let controller = HapController::new(common::MockStore::new()).await.unwrap();
    let err = controller.list_pairings("nope").await.unwrap_err();
    assert!(matches!(err, hap_controller::HapError::UnknownAccessory(id) if id == "nope"));
}

#[tokio::test]
async fn add_pairing_unknown_id_errors() {
    let controller = HapController::new(common::MockStore::new()).await.unwrap();
    let err = controller
        .add_pairing("nope", "ctrl-2", [0u8; 32], false)
        .await
        .unwrap_err();
    assert!(matches!(err, hap_controller::HapError::UnknownAccessory(id) if id == "nope"));
}
