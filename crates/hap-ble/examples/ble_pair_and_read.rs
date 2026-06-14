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

    let found = hap_ble::scan(Duration::from_secs(10)).await?;
    let Some(target) = found.iter().find(|a| !a.paired).or_else(|| found.first()) else {
        println!("No accessory found.");
        return Ok(());
    };
    println!("Pairing with {}...", target.device_id);

    let gatt: std::sync::Arc<dyn hap_ble::GattConnection> = hap_ble::connect_gatt(target).await?;
    let controller = hap_ble::BleController::generate("hap-ble-example".into());
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
    Ok(())
}
