//! End-to-end: the real `hap-thread` controller identifies the reference
//! accessory over a UDP CoAP round-trip (no Thread hardware needed).

#![allow(clippy::unwrap_used)] // test code

use std::net::SocketAddr;
use std::sync::Arc;

use hap_thread::ThreadController;
use hap_thread_dut::ReferenceAccessory;
use tokio::sync::oneshot;

#[tokio::test]
async fn controller_identifies_the_reference_accessory() {
    // Start the accessory on an ephemeral loopback UDP port.
    let accessory = Arc::new(ReferenceAccessory::new("11:22:33:44:55:66"));
    let (tx, rx) = oneshot::channel::<SocketAddr>();
    tokio::spawn(accessory.serve("[::1]:0".parse().unwrap(), move |addr| {
        let _ = tx.send(addr);
    }));
    let addr = rx.await.unwrap();

    // Drive the real controller's identify against it.
    let controller = ThreadController::generate("AA:BB:CC:DD:EE:FF".into());
    controller
        .identify(addr)
        .await
        .expect("identify should succeed against the reference accessory");
}

#[tokio::test]
async fn unknown_resource_is_not_found() {
    // A connect (Pair Verify) against the not-yet-implemented `/2` must surface
    // as a clean error, not a hang — proves the server answers every datagram.
    let accessory = Arc::new(ReferenceAccessory::new("11:22:33:44:55:66"));
    let (tx, rx) = oneshot::channel::<SocketAddr>();
    tokio::spawn(accessory.serve("[::1]:0".parse().unwrap(), move |addr| {
        let _ = tx.send(addr);
    }));
    let addr = rx.await.unwrap();

    let controller = ThreadController::generate("AA:BB:CC:DD:EE:FF".into());
    let pairing = hap_crypto::AccessoryPairing {
        pairing_id: "11:22:33:44:55:66".into(),
        ltpk: controller.keypair().ltpk(),
    };
    // `/2` returns 4.04 → the controller maps it to SessionExpired.
    let err = controller.connect(addr, &pairing).await;
    assert!(
        err.is_err(),
        "connect against an unimplemented /2 must error"
    );
}
