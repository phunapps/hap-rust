//! Pair with the first unpaired HAP BLE accessory, list its attribute database,
//! read a value, and stream connected events.
//!
//! Run: `cargo run --release -p hap-ble --example ble_pair_and_read -- <setup-code>`
//! e.g. `cargo run --release -p hap-ble --example ble_pair_and_read -- 123-45-678`
use std::time::Duration;
use tokio_stream::StreamExt as _;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let Some(setup_code) = std::env::args().nth(1) else {
        eprintln!("usage: ble_pair_and_read <setup-code>");
        return Ok(());
    };

    // Sleepy BLE sensors advertise intermittently, so scan in a retry loop
    // (one process / one BT session) until an unpaired accessory appears rather
    // than giving up after a single window.
    let mut target = None;
    for attempt in 1..=8 {
        let found = hap_ble::scan(Duration::from_secs(8)).await?;
        if let Some(t) = found.into_iter().find(|a| !a.paired) {
            target = Some(t);
            break;
        }
        println!("scan {attempt}: no unpaired accessory yet, retrying...");
    }
    let Some(target) = target else {
        println!("No unpaired accessory found.");
        return Ok(());
    };
    let target = &target;
    println!("Pairing with {}...", target.device_id);

    let gatt: std::sync::Arc<dyn hap_ble::GattConnection> = hap_ble::connect_gatt(target).await?;
    let controller = hap_ble::BleController::generate("hap-ble-example".into());
    let controller_id = controller.keypair().id.clone();
    let (mut accessory, _pairing) = controller.pair(gatt, target, &setup_code).await?;

    println!("Paired. Attribute database:");
    for acc in accessory.accessories() {
        for svc in &acc.services {
            for ch in &svc.characteristics {
                println!(
                    "  aid={} iid={} {:?} {:?}",
                    acc.aid, ch.iid, ch.char_type, ch.format
                );
            }
        }
    }

    // Read the first readable characteristic.
    if let Some((aid, iid)) = accessory.accessories().iter().find_map(|a| {
        a.services.iter().find_map(|s| {
            s.characteristics
                .iter()
                .find(|c| c.perms.read)
                .map(|c| (a.aid, c.iid))
        })
    }) {
        match accessory.read(aid, iid).await {
            Ok(v) => println!("read aid={aid} iid={iid} -> {v:?}"),
            Err(e) => println!("read failed: {e}"),
        }
    }

    // Stream MotionDetected events for 45s, if present (trigger motion).
    if let Ok((aid, iid)) = accessory.find(
        hap_ble::ServiceType::MotionSensor,
        hap_ble::CharacteristicType::MotionDetected,
    ) {
        println!("subscribing to MotionDetected (aid={aid} iid={iid}); trigger motion for 45s...");
        accessory.subscribe(aid, iid).await?;
        let mut events = accessory.events();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(45);
        while let Ok(Some(ev)) = tokio::time::timeout_at(deadline, events.next()).await {
            println!("EVENT: aid={} iid={} value={:?}", ev.aid, ev.iid, ev.value);
        }
        println!("done watching events.");
    }

    // Clean up: remove this controller's pairing so the example can be re-run
    // without exhausting the accessory's pairing slots.
    println!("removing this controller's pairing ({controller_id})...");
    match accessory.remove_pairing(&controller_id).await {
        Ok(()) => println!("pairing removed."),
        Err(e) => println!("remove_pairing failed: {e}"),
    }
    Ok(())
}
