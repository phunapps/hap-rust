//! End-to-end: the real `hap-thread` controller drives the reference accessory
//! over UDP CoAP (no Thread hardware needed) — identify and Pair Verify.

#![allow(clippy::unwrap_used, clippy::expect_used)] // test code

use std::net::SocketAddr;
use std::sync::Arc;

use hap_crypto::AccessoryPairing;
use hap_thread::ThreadController;
use hap_thread_dut::ReferenceAccessory;
use tokio::sync::oneshot;

/// Spawn the accessory on an ephemeral loopback UDP port and return its address.
async fn spawn(accessory: Arc<ReferenceAccessory>) -> SocketAddr {
    let (tx, rx) = oneshot::channel::<SocketAddr>();
    tokio::spawn(accessory.serve("[::1]:0".parse().unwrap(), move |addr| {
        let _ = tx.send(addr);
    }));
    rx.await.unwrap()
}

#[tokio::test]
async fn controller_identifies_the_reference_accessory() {
    let accessory = Arc::new(ReferenceAccessory::new("11:22:33:44:55:66"));
    let addr = spawn(accessory).await;

    let controller = ThreadController::generate("AA:BB:CC:DD:EE:FF".into());
    controller
        .identify(addr)
        .await
        .expect("identify should succeed against the reference accessory");
}

#[tokio::test]
async fn controller_pair_verifies_with_the_reference_accessory() {
    let accessory = Arc::new(ReferenceAccessory::new("11:22:33:44:55:66"));
    let controller = ThreadController::generate("AA:BB:CC:DD:EE:FF".into());

    // Provision the pairing both ways, as Pair Setup would establish it.
    accessory.provision_controller(controller.keypair().id.clone(), controller.keypair().ltpk());
    let pairing = AccessoryPairing {
        pairing_id: accessory.pairing_id().into(),
        ltpk: accessory.accessory_ltpk(),
    };

    let addr = spawn(accessory).await;

    // A full Pair Verify (M1–M4) over CoAP: the controller verifies the
    // accessory's M2 signature and the accessory verifies the controller's M3
    // signature; a session is established on both sides.
    controller
        .connect(addr, &pairing)
        .await
        .expect("Pair Verify should complete against the reference accessory");
}

#[tokio::test]
async fn controller_reads_and_writes_the_lightbulb() {
    let accessory = Arc::new(ReferenceAccessory::new("11:22:33:44:55:66"));
    let controller = ThreadController::generate("AA:BB:CC:DD:EE:FF".into());
    accessory.provision_controller(controller.keypair().id.clone(), controller.keypair().ltpk());
    let pairing = AccessoryPairing {
        pairing_id: accessory.pairing_id().into(),
        ltpk: accessory.accessory_ltpk(),
    };
    let on_iid = ReferenceAccessory::ON_IID;
    let acc_for_assert = Arc::clone(&accessory);
    let addr = spawn(accessory).await;

    let handle = controller
        .connect(addr, &pairing)
        .await
        .expect("pair verify");

    // Reads back off, over the encrypted session.
    assert_eq!(handle.read_characteristic(on_iid).await.unwrap(), vec![0]);

    // Write On = true, then read it back as true — and the accessory state moved.
    handle.write_characteristic(on_iid, &[1]).await.unwrap();
    assert_eq!(handle.read_characteristic(on_iid).await.unwrap(), vec![1]);
    assert!(acc_for_assert.is_on());

    // Write On = false again.
    handle.write_characteristic(on_iid, &[0]).await.unwrap();
    assert_eq!(handle.read_characteristic(on_iid).await.unwrap(), vec![0]);
    assert!(!acc_for_assert.is_on());
}

#[tokio::test]
async fn controller_pair_setup_then_connect_and_read() {
    // Nothing is pre-provisioned: the controller learns the accessory's LTPK and
    // the accessory learns the controller's, purely by running Pair Setup over
    // CoAP with the shared setup code.
    let accessory =
        Arc::new(ReferenceAccessory::new("11:22:33:44:55:66").with_setup_code("123-45-678"));
    let controller = ThreadController::generate("AA:BB:CC:DD:EE:FF".into());
    let addr = spawn(accessory).await;

    // Full Pair Setup M1–M6 over CoAP, followed (inside `pair`) by a Pair Verify.
    let (_first, pairing) = controller
        .pair(addr, "123-45-678")
        .await
        .expect("Pair Setup should complete against the reference accessory");
    assert_eq!(pairing.pairing_id, "11:22:33:44:55:66");

    // The pairing persists: a fresh Pair Verify with it reconnects and reads.
    let handle = controller
        .connect(addr, &pairing)
        .await
        .expect("Pair Verify with the freshly established pairing should connect");
    assert_eq!(
        handle
            .read_characteristic(ReferenceAccessory::ON_IID)
            .await
            .unwrap(),
        vec![0]
    );
}

#[tokio::test]
async fn pair_setup_rejects_wrong_setup_code() {
    let accessory =
        Arc::new(ReferenceAccessory::new("11:22:33:44:55:66").with_setup_code("123-45-678"));
    let controller = ThreadController::generate("AA:BB:CC:DD:EE:FF".into());
    let addr = spawn(accessory).await;

    assert!(
        controller.pair(addr, "000-00-000").await.is_err(),
        "Pair Setup must fail when the controller uses the wrong setup code"
    );
}

#[tokio::test]
async fn pair_setup_unavailable_without_a_setup_code() {
    // An accessory built without a setup code refuses Pair Setup (the `/1`
    // resource stays a 4.04), so `pair` errors out.
    let accessory = Arc::new(ReferenceAccessory::new("11:22:33:44:55:66"));
    let controller = ThreadController::generate("AA:BB:CC:DD:EE:FF".into());
    let addr = spawn(accessory).await;

    assert!(
        controller.pair(addr, "123-45-678").await.is_err(),
        "Pair Setup must be unavailable when the accessory has no setup code"
    );
}

#[tokio::test]
async fn pair_verify_rejects_an_unknown_controller() {
    let accessory = Arc::new(ReferenceAccessory::new("11:22:33:44:55:66"));
    let controller = ThreadController::generate("AA:BB:CC:DD:EE:FF".into());

    // Provision a DIFFERENT controller identity, so the real controller's M3
    // signature will not verify.
    let stranger = ThreadController::generate("99:99:99:99:99:99".into());
    accessory.provision_controller(stranger.keypair().id.clone(), stranger.keypair().ltpk());
    let pairing = AccessoryPairing {
        pairing_id: accessory.pairing_id().into(),
        ltpk: accessory.accessory_ltpk(),
    };

    let addr = spawn(accessory).await;

    assert!(
        controller.connect(addr, &pairing).await.is_err(),
        "Pair Verify must fail for an unprovisioned controller"
    );
}
