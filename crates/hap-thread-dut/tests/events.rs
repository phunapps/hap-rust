//! End-to-end events over UDP CoAP: the real `hap-thread` controller subscribes
//! to the reference accessory, the accessory pushes an encrypted event PUT, and
//! the controller decrypts it — all without Thread hardware. The concurrency
//! test exercises the single-socket connection-actor demux: a read and the event
//! watcher run at once on the same accessory without stealing each other's
//! datagrams.

#![allow(clippy::unwrap_used, clippy::expect_used)] // test code

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use hap_crypto::AccessoryPairing;
use hap_thread::ThreadController;
use hap_thread_dut::ReferenceAccessory;
use tokio::sync::oneshot;
use tokio_stream::StreamExt as _;

/// Spawn the accessory on an ephemeral loopback UDP port and return its address.
async fn spawn(accessory: Arc<ReferenceAccessory>) -> SocketAddr {
    let (tx, rx) = oneshot::channel::<SocketAddr>();
    tokio::spawn(accessory.serve("[::1]:0".parse().unwrap(), move |addr| {
        let _ = tx.send(addr);
    }));
    rx.await.unwrap()
}

/// Provision a pairing both ways and Pair Verify, returning the connected handle
/// and an `Arc` to the accessory for pushing events.
async fn connected() -> (hap_thread::ThreadAccessory, Arc<ReferenceAccessory>) {
    let accessory = Arc::new(ReferenceAccessory::new("11:22:33:44:55:66"));
    let controller = ThreadController::generate("AA:BB:CC:DD:EE:FF".into());
    accessory.provision_controller(controller.keypair().id.clone(), controller.keypair().ltpk());
    let pairing = AccessoryPairing {
        pairing_id: accessory.pairing_id().into(),
        ltpk: accessory.accessory_ltpk(),
    };
    let acc = Arc::clone(&accessory);
    let addr = spawn(accessory).await;
    let handle = controller
        .connect(addr, &pairing)
        .await
        .expect("Pair Verify should complete");
    (handle, acc)
}

#[tokio::test]
async fn controller_receives_a_pushed_event() {
    let (handle, accessory) = connected().await;

    handle
        .subscribe(ReferenceAccessory::ON_IID)
        .await
        .expect("subscribe should be accepted");

    // The accessory pushes an event (as a real sensor would on a state change).
    let delivered = accessory
        .push_event(ReferenceAccessory::ON_IID, &[1])
        .await
        .expect("push should succeed");
    assert!(delivered, "a subscribed controller must receive the event");

    let event = handle.next_event().await.expect("event should decrypt");
    assert_eq!(event, vec![(ReferenceAccessory::ON_IID, vec![1u8])]);
}

#[tokio::test]
async fn push_without_a_subscriber_is_a_no_op() {
    let (_handle, accessory) = connected().await;
    // No subscribe(): the accessory has no one to notify.
    let delivered = accessory
        .push_event(ReferenceAccessory::ON_IID, &[1])
        .await
        .expect("push should not error");
    assert!(!delivered, "with no subscriber there is nothing to deliver");
}

#[tokio::test]
async fn reads_and_event_watching_run_concurrently() {
    let (mut handle, accessory) = connected().await;
    handle
        .subscribe(ReferenceAccessory::ON_IID)
        .await
        .expect("subscribe");

    // Watch events on the SAME accessory the reads go to.
    let stream = handle.watch_events();
    tokio::pin!(stream);

    // Interleave a normal read with an accessory-pushed event on the one socket.
    // The connection actor must route the read's response to the read and the
    // event PUT to the watcher — neither stealing the other's datagram. Under the
    // old (pre-demux) design the watcher and the read both raced `socket.recv`,
    // so a read could hang forever; the timeout turns that into a fast failure.
    let read = handle.read_characteristic(ReferenceAccessory::ON_IID);
    let push = accessory.push_event(ReferenceAccessory::ON_IID, &[1]);
    let (read_res, push_res) =
        tokio::time::timeout(Duration::from_secs(5), async { tokio::join!(read, push) })
            .await
            .expect("read + push must both complete without deadlock");

    assert_eq!(read_res.expect("read completes"), vec![0]);
    assert!(push_res.expect("push completes"), "event was delivered");

    let event = tokio::time::timeout(Duration::from_secs(5), stream.next())
        .await
        .expect("event should arrive on the stream")
        .expect("stream yields the event");
    assert_eq!(event, (ReferenceAccessory::ON_IID, vec![1u8]));

    // And the accessory is still fully usable for another read afterwards.
    let again = tokio::time::timeout(
        Duration::from_secs(5),
        handle.read_characteristic(ReferenceAccessory::ON_IID),
    )
    .await
    .expect("post-event read must not hang")
    .expect("read succeeds");
    assert_eq!(again, vec![0]);
}
