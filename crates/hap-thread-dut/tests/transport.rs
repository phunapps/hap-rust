//! End-to-end transport-hardening tests: the real `hap-thread` controller
//! against a `hap-thread-dut` configured to behave like a *slow* accessory
//! (empty ACK then a separate response, RFC 7252 §5.2.2) or a *block-wise* one
//! (a large response fragmented with Block2, RFC 7959) — the F1/F2 findings from
//! `crates/hap-thread/BRINGUP.md`.

#![allow(clippy::unwrap_used, clippy::expect_used)] // test code

use std::net::SocketAddr;
use std::sync::Arc;

use hap_thread::ThreadController;
use hap_thread_dut::ReferenceAccessory;
use tokio::sync::oneshot;

async fn spawn(accessory: Arc<ReferenceAccessory>) -> SocketAddr {
    let (tx, rx) = oneshot::channel::<SocketAddr>();
    tokio::spawn(accessory.serve("[::1]:0".parse().unwrap(), move |addr| {
        let _ = tx.send(addr);
    }));
    rx.await.unwrap()
}

#[tokio::test]
async fn controller_survives_separate_responses() {
    // F1: the accessory empty-ACKs every request, then answers with a separate
    // CON carrying the same token. The whole pair → verify → read chain must
    // still complete over that.
    let accessory = Arc::new(
        ReferenceAccessory::new("11:22:33:44:55:66")
            .with_setup_code("123-45-678")
            .with_slow_responses(),
    );
    let controller = ThreadController::generate("AA:BB:CC:DD:EE:FF".into());
    let addr = spawn(accessory).await;

    let (_first, pairing) = controller
        .pair(addr, "123-45-678")
        .await
        .expect("Pair Setup must complete despite separate responses");
    let handle = controller
        .connect(addr, &pairing)
        .await
        .expect("Pair Verify must complete despite separate responses");
    assert_eq!(
        handle
            .read_characteristic(ReferenceAccessory::ON_IID)
            .await
            .unwrap(),
        vec![0]
    );
}

#[tokio::test]
async fn controller_reassembles_a_blockwise_database() {
    // F2: the accessory returns its (synthetic) attribute database as Block2
    // fragments; the controller must reassemble them into the whole payload.
    let block_size = 512;
    let accessory = Arc::new(
        ReferenceAccessory::new("11:22:33:44:55:66")
            .with_setup_code("123-45-678")
            .with_blockwise_responses(block_size),
    );
    let controller = ThreadController::generate("AA:BB:CC:DD:EE:FF".into());
    let addr = spawn(accessory).await;

    let (handle, _pairing) = controller.pair(addr, "123-45-678").await.expect("pair");
    let db = handle
        .read_database_raw()
        .await
        .expect("block-wise database read must reassemble");

    let expected = ReferenceAccessory::synthetic_database();
    assert!(
        expected.len() > block_size,
        "the database must exceed one block to exercise Block2"
    );
    assert_eq!(
        db, expected,
        "reassembled database must match byte-for-byte"
    );
}
