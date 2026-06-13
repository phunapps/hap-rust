//! Pair with the first unpaired HAP BLE accessory and list its attribute
//! database.
//!
//! Run: `cargo run -p hap-ble --example ble_pair_and_read -- <setup-code>`
//! e.g. `cargo run -p hap-ble --example ble_pair_and_read -- 123-45-678`
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let Some(setup_code) = std::env::args().nth(1) else {
        eprintln!("usage: ble_pair_and_read <setup-code>");
        return Ok(());
    };

    let found = hap_ble::scan(Duration::from_secs(5)).await?;
    let Some(target) = found.iter().find(|a| !a.paired).or_else(|| found.first()) else {
        println!("No accessory found.");
        return Ok(());
    };
    println!("Pairing with {}...", target.device_id);

    let gatt: std::sync::Arc<dyn hap_ble::GattConnection> =
        hap_ble::connect_gatt(target).await?;
    let controller = hap_ble::BleController::generate("hap-ble-example".into());
    let (accessory, _pairing) = controller.pair(gatt, target, &setup_code).await?;

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
    Ok(())
}
