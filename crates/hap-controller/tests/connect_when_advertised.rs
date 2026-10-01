//! `HapController::connect_when_advertised` over BLE, driven by a scripted
//! connector — no radio needed.

// CLAUDE.md test-code carve-out.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use hap_ble::test_support::ble_accessory_with_db;
use hap_ble::{BleAccessory, BleBroadcastState, BleError, SleepyConnector};
use hap_controller::{HapController, HapError, StoredAccessory, StoredTransport};
use hap_pairing::StoredBroadcast;
use tokio::sync::mpsc;

mod common;

const SENSOR_A: [u8; 6] = [0xAE, 0xEC, 0x86, 0xC0, 0xBF, 0xD7];
const SENSOR_B: [u8; 6] = [0x59, 0xFA, 0xBC, 0x61, 0x09, 0xD2];

fn ble_record(id: &str, device_id: [u8; 6], gsn: u16) -> StoredAccessory {
    StoredAccessory {
        pairing: hap_crypto::AccessoryPairing {
            pairing_id: id.into(),
            ltpk: [1u8; 32],
        },
        transport: StoredTransport::Ble {
            device_id,
            broadcast: Some(StoredBroadcast {
                key: hap_crypto::BroadcastKey::from_bytes([3u8; 32]),
                gsn,
            }),
        },
    }
}

type Outcome = hap_ble::Result<BleAccessory>;
/// One device's scripted outcomes; the async mutex lets `connect` hold the
/// receiver across its `recv().await`.
type Script = Arc<tokio::sync::Mutex<mpsc::Receiver<Outcome>>>;

/// What the controller handed the connector on one `connect` call.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Call {
    device_id: [u8; 6],
    pairing_id: String,
    gsn: Option<u16>,
}

/// A [`SleepyConnector`] whose `connect` stays pending — like a real scan for
/// a sleeping device — until the test sends that device's next outcome.
#[derive(Default)]
struct ScriptedConnector {
    outcomes: Mutex<HashMap<[u8; 6], Script>>,
    calls: Mutex<Vec<Call>>,
    /// `connect` futures currently alive (pending on an outcome).
    waiting: Arc<AtomicUsize>,
}

impl ScriptedConnector {
    /// Register `device_id` and return the sender that scripts its outcomes.
    fn script(&self, device_id: [u8; 6]) -> mpsc::Sender<Outcome> {
        let (tx, rx) = mpsc::channel(8);
        self.outcomes
            .lock()
            .unwrap()
            .insert(device_id, Arc::new(tokio::sync::Mutex::new(rx)));
        tx
    }

    fn calls(&self) -> Vec<Call> {
        self.calls.lock().unwrap().clone()
    }

    fn waiting(&self) -> usize {
        self.waiting.load(Ordering::SeqCst)
    }

    /// Yield until `n` `connect` futures are alive.
    async fn until_waiting(&self, n: usize) {
        tokio::time::timeout(Duration::from_secs(5), async {
            while self.waiting() != n {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("connector never reached the expected number of waits");
    }
}

/// Decrements the live-wait count when a `connect` future ends or is dropped.
struct WaitGuard(Arc<AtomicUsize>);

impl Drop for WaitGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

#[async_trait::async_trait]
impl SleepyConnector for ScriptedConnector {
    async fn connect(
        &self,
        device_id: [u8; 6],
        pairing: &hap_crypto::AccessoryPairing,
        broadcast: Option<BleBroadcastState>,
    ) -> Outcome {
        self.calls.lock().unwrap().push(Call {
            device_id,
            pairing_id: pairing.pairing_id.clone(),
            gsn: broadcast.map(|b| b.gsn),
        });
        let rx = self
            .outcomes
            .lock()
            .unwrap()
            .get(&device_id)
            .cloned()
            .expect("connect for a device the test did not script");
        self.waiting.fetch_add(1, Ordering::SeqCst);
        let _guard = WaitGuard(self.waiting.clone());
        let mut rx = rx.lock().await;
        rx.recv().await.expect("outcome sender dropped")
    }
}

/// A controller over `records` whose BLE waits go through the returned
/// scripted connector.
async fn controller_with(records: Vec<StoredAccessory>) -> (HapController, Arc<ScriptedConnector>) {
    let store = records
        .into_iter()
        .fold(common::MockStore::new(), common::MockStore::with_pairing);
    let mut controller = HapController::new(store).await.unwrap();
    let connector = Arc::new(ScriptedConnector::default());
    controller.set_sleepy_connector_for_tests(connector.clone());
    (controller, connector)
}

#[tokio::test]
async fn returns_a_handle_that_serves_the_accessory_database() {
    let (controller, connector) =
        controller_with(vec![ble_record("AE:EC:86:C0:BF:D7", SENSOR_A, 5)]).await;
    let (accessory, _gatt) = ble_accessory_with_db().await;
    connector
        .script(SENSOR_A)
        .send(Ok(accessory))
        .await
        .unwrap();

    let mut handle = controller
        .connect_when_advertised("AE:EC:86:C0:BF:D7")
        .await
        .unwrap();

    // The fixture's database: accessory 1 with the single On characteristic.
    let accessories = handle.accessories().await.unwrap();
    assert_eq!(accessories.len(), 1);
    assert_eq!(accessories[0].aid, 1);
    let iids: Vec<u64> = accessories[0]
        .services
        .iter()
        .flat_map(|s| s.characteristics.iter().map(|c| c.iid))
        .collect();
    assert_eq!(iids, vec![11]);
}

#[tokio::test]
async fn hands_the_connector_the_stored_device_id_pairing_and_gsn() {
    let (controller, connector) =
        controller_with(vec![ble_record("AE:EC:86:C0:BF:D7", SENSOR_A, 5)]).await;
    let (accessory, _gatt) = ble_accessory_with_db().await;
    connector
        .script(SENSOR_A)
        .send(Ok(accessory))
        .await
        .unwrap();

    // Looked up lowercase, as `Discovered::id()` yields from an advert.
    controller
        .connect_when_advertised("ae:ec:86:c0:bf:d7")
        .await
        .unwrap();

    assert_eq!(
        connector.calls(),
        vec![Call {
            device_id: SENSOR_A,
            pairing_id: "AE:EC:86:C0:BF:D7".into(),
            gsn: Some(5),
        }]
    );
}

#[tokio::test]
async fn stays_pending_until_the_accessory_advertises() {
    let (controller, connector) =
        controller_with(vec![ble_record("AE:EC:86:C0:BF:D7", SENSOR_A, 5)]).await;
    let outcomes = connector.script(SENSOR_A);

    let wait = tokio::spawn(controller.connect_when_advertised("AE:EC:86:C0:BF:D7"));
    connector.until_waiting(1).await;
    // Give a wrongly-resolving future every chance to finish.
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(!wait.is_finished());

    let (accessory, _gatt) = ble_accessory_with_db().await;
    outcomes.send(Ok(accessory)).await.unwrap();
    wait.await.unwrap().unwrap();
}

#[tokio::test]
async fn dropping_the_wait_abandons_the_connector_wait() {
    let (controller, connector) =
        controller_with(vec![ble_record("AE:EC:86:C0:BF:D7", SENSOR_A, 5)]).await;
    let _outcomes = connector.script(SENSOR_A);

    let wait = tokio::spawn(controller.connect_when_advertised("AE:EC:86:C0:BF:D7"));
    connector.until_waiting(1).await;

    wait.abort();
    let joined = wait.await.err().expect("the aborted wait still completed");
    assert!(joined.is_cancelled());
    assert_eq!(connector.waiting(), 0);
}

#[tokio::test]
async fn a_second_accessory_connects_while_the_first_is_still_waiting() {
    let (controller, connector) = controller_with(vec![
        ble_record("AE:EC:86:C0:BF:D7", SENSOR_A, 5),
        ble_record("59:FA:BC:61:09:D2", SENSOR_B, 0),
    ])
    .await;
    let _absent = connector.script(SENSOR_A);
    let present = connector.script(SENSOR_B);

    let first = tokio::spawn(controller.connect_when_advertised("AE:EC:86:C0:BF:D7"));
    connector.until_waiting(1).await;

    let (accessory, _gatt) = ble_accessory_with_db().await;
    present.send(Ok(accessory)).await.unwrap();
    tokio::time::timeout(
        Duration::from_secs(5),
        controller.connect_when_advertised("59:FA:BC:61:09:D2"),
    )
    .await
    .expect("the second wait was blocked behind the first")
    .unwrap();

    assert!(!first.is_finished());
    first.abort();
}

#[tokio::test]
async fn the_wait_does_not_keep_the_controller_borrowed() {
    let (controller, connector) =
        controller_with(vec![ble_record("AE:EC:86:C0:BF:D7", SENSOR_A, 5)]).await;
    let outcomes = connector.script(SENSOR_A);
    // The consumer's pattern: every controller call goes through one mutex.
    let controller = Arc::new(tokio::sync::Mutex::new(controller));

    // Create the wait under the mutex, release the mutex, await outside it.
    let wait = {
        let guard = controller.lock().await;
        guard.connect_when_advertised("AE:EC:86:C0:BF:D7")
    };
    let wait = tokio::spawn(wait);
    connector.until_waiting(1).await;

    // While the wait is pending, other callers still get the controller.
    let mut guard = controller.try_lock().expect("the wait holds the mutex");
    guard.forget_pairing("nope").await.unwrap();
    drop(guard);

    let (accessory, _gatt) = ble_accessory_with_db().await;
    outcomes.send(Ok(accessory)).await.unwrap();
    wait.await.unwrap().unwrap();
}

#[tokio::test(start_paused = true)]
async fn keeps_waiting_when_the_accessory_is_lost_before_the_connect_completes() {
    let (controller, connector) =
        controller_with(vec![ble_record("AE:EC:86:C0:BF:D7", SENSOR_A, 5)]).await;
    let outcomes = connector.script(SENSOR_A);
    // Seen in the scan, then gone before the link came up — three ways.
    outcomes
        .send(Err(BleError::AccessoryNotFound))
        .await
        .unwrap();
    outcomes.send(Err(BleError::Disconnected)).await.unwrap();
    outcomes
        .send(Err(BleError::Backend("connect failed".into())))
        .await
        .unwrap();
    let (accessory, _gatt) = ble_accessory_with_db().await;
    outcomes.send(Ok(accessory)).await.unwrap();

    controller
        .connect_when_advertised("AE:EC:86:C0:BF:D7")
        .await
        .unwrap();

    assert_eq!(connector.calls().len(), 4);
}

#[tokio::test(start_paused = true)]
async fn backs_off_between_attempts_after_a_lost_accessory() {
    let (controller, connector) =
        controller_with(vec![ble_record("AE:EC:86:C0:BF:D7", SENSOR_A, 5)]).await;
    let outcomes = connector.script(SENSOR_A);
    outcomes
        .send(Err(BleError::AccessoryNotFound))
        .await
        .unwrap();
    let (accessory, _gatt) = ble_accessory_with_db().await;
    outcomes.send(Ok(accessory)).await.unwrap();

    let started = tokio::time::Instant::now();
    controller
        .connect_when_advertised("AE:EC:86:C0:BF:D7")
        .await
        .unwrap();

    // The mock answers instantly, so any elapsed (virtual) time is the
    // backoff: without one, a connector that fails fast would be spun.
    assert!(started.elapsed() >= Duration::from_secs(1));
}

#[tokio::test(start_paused = true)]
async fn a_rejected_pair_verify_is_returned_without_retrying() {
    let (controller, connector) =
        controller_with(vec![ble_record("AE:EC:86:C0:BF:D7", SENSOR_A, 5)]).await;
    let outcomes = connector.script(SENSOR_A);
    outcomes
        .send(Err(BleError::PairingRejected(2)))
        .await
        .unwrap();

    let err = controller
        .connect_when_advertised("AE:EC:86:C0:BF:D7")
        .await
        .err()
        .expect("a rejected Pair Verify must end the wait");

    assert!(matches!(err, HapError::Ble(BleError::PairingRejected(2))));
    assert_eq!(connector.calls().len(), 1);
}

#[tokio::test]
async fn an_ip_pairing_never_reaches_the_ble_connector() {
    // An "accessory" that accepts the TCP connection and hangs up at once, so
    // the IP connect fails fast (no mDNS fallback browse).
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((socket, _)) = listener.accept().await {
            drop(socket);
        }
    });
    let mut entry = common::sample_pairing("AA:BB:CC:DD:EE:FF");
    entry.transport = StoredTransport::Ip { addr };
    let (controller, connector) = controller_with(vec![entry]).await;

    let waited = controller
        .connect_when_advertised("AA:BB:CC:DD:EE:FF")
        .await
        .err()
        .expect("nothing answers Pair Verify");
    let direct = controller
        .connect("AA:BB:CC:DD:EE:FF")
        .await
        .err()
        .expect("nothing answers Pair Verify");

    // Same failure as `connect()`, and the BLE wait was never involved.
    assert_eq!(
        std::mem::discriminant(&waited),
        std::mem::discriminant(&direct)
    );
    assert!(connector.calls().is_empty());
}
