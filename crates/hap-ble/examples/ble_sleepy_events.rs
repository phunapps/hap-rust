//! Task 11 hardware validation: pair with a sleepy HAP-BLE accessory (enabling
//! encrypted broadcasts), then watch for durable events that arrive WHILE the
//! device is disconnected — encrypted broadcasts (0x11) and disconnected-event
//! polls (0x06 GSN bump). Trigger motion on the Onvis to generate them.
//!
//! Run: `cargo run --release -p hap-ble --example ble_sleepy_events -- <setup-code>`
#![allow(clippy::expect_used, clippy::unwrap_used)] // example binary
use hap_ble::GattConnection;
use std::sync::Arc;
use std::time::Duration;
use tokio_stream::StreamExt as _;

fn parse_device_id(s: &str) -> Option<[u8; 6]> {
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 6 {
        return None;
    }
    let mut out = [0u8; 6];
    for (i, p) in parts.iter().enumerate() {
        out[i] = u8::from_str_radix(p, 16).ok()?;
    }
    Some(out)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Print hap-ble's structured diagnostics (advert path, broadcast-enable,
    // per-characteristic broadcast capability). Override with e.g.
    // `RUST_LOG=hap_ble=trace`.
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "hap_ble=debug".into()),
        )
        .with_target(true)
        .init();

    let setup_code = std::env::args()
        .nth(1)
        .expect("usage: ble_sleepy_events <setup-code>");

    // Scan-retry for an unpaired sleepy accessory (one process / one BT session).
    let mut target = None;
    for _ in 0..10 {
        if let Some(t) = hap_ble::scan(Duration::from_secs(8))
            .await?
            .into_iter()
            .find(|a| !a.paired)
        {
            target = Some(t);
            break;
        }
    }
    let Some(target) = target else {
        println!("No unpaired accessory found.");
        return Ok(());
    };
    let Some(device_id) = parse_device_id(&target.device_id) else {
        println!("Could not parse device id {}", target.device_id);
        return Ok(());
    };
    println!(
        "Pairing with {} (device_id {:02x?}) ...",
        target.device_id, device_id
    );

    let conn = hap_ble::connect_gatt(&target).await?;
    let advert_source: Arc<dyn hap_ble::AdvertSource> = conn.clone();
    let controller = hap_ble::BleController::generate("hap-ble-sleepy".into());
    let controller_id = controller.keypair().id.clone();
    let hap_ble::Paired {
        mut accessory,
        broadcast: _broadcast,
        ..
    } = controller.pair(conn.clone(), &target, &setup_code).await?;
    println!(">>> Paired; broadcast-key generation requested.");

    // Watch MotionDetected two ways: the disconnected-event POLL (on a GSN bump
    // in a 0x06 advert, reconnect and read) AND — if the accessory advertises
    // broadcast-notify support and accepts the enable — encrypted 0x11
    // broadcasts, which arrive without a reconnect and so catch fast transitions
    // the poll misses. Watch the `hap_ble=debug` trace for the broadcast
    // outcome: `supports_broadcast=true`, `generate-broadcast-key accepted`, and
    // `enable_broadcasts: accepted`.
    let poll_iids = if let Ok((aid, iid)) = accessory.find(
        hap_ble::ServiceType::MotionSensor,
        hap_ble::CharacteristicType::MotionDetected,
    ) {
        println!(">>> will watch MotionDetected aid={aid} iid={iid} (poll + broadcast).");
        vec![(aid, iid)]
    } else {
        println!(">>> no MotionDetected char found.");
        vec![]
    };

    // Ask the accessory to broadcast these characteristics while disconnected.
    // Best-effort: an accessory that does not support broadcast for a
    // characteristic simply keeps delivering it via the 0x06 poll.
    let broadcast_iids: Vec<u64> = poll_iids.iter().map(|(_, iid)| *iid).collect();
    accessory.enable_broadcasts(&broadcast_iids).await?;
    println!(">>> enable_broadcasts requested for {broadcast_iids:?}.");

    // Release the GATT link so the accessory advertises (and macOS CoreBluetooth
    // surfaces its adverts to a scan). The poll read reconnects on demand — now
    // bounded by the connect timeout so it can't hang.
    conn.disconnect().await;
    println!(">>> Disconnected — device will now advertise.");
    tokio::time::sleep(Duration::from_secs(3)).await;

    accessory
        .watch_sleepy_events_with_source(advert_source, device_id, poll_iids)
        .await?;
    println!(">>> Watching sleepy events for 180s. TRIGGER MOTION (wave, wait ~30s, repeat).");

    let mut events = accessory.events();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(180);
    let mut count = 0u32;
    loop {
        match tokio::time::timeout(Duration::from_secs(15), events.next()).await {
            Ok(Some(ev)) => {
                count += 1;
                println!(
                    "EVENT #{count}: aid={} iid={} value={:?}",
                    ev.aid, ev.iid, ev.value
                );
            }
            Ok(None) => break,
            Err(_) => {
                println!(
                    "... {}s elapsed, {count} events so far (waiting for motion) ...",
                    180u64.saturating_sub((deadline - tokio::time::Instant::now()).as_secs())
                );
            }
        }
        if tokio::time::Instant::now() >= deadline {
            break;
        }
    }
    println!(">>> done watching. {count} sleepy events total.");

    println!("removing pairing ({controller_id}) ...");
    match accessory.remove_pairing(&controller_id).await {
        Ok(()) => println!("pairing removed."),
        Err(e) => println!("remove_pairing: {e}"),
    }
    Ok(())
}
