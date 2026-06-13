//! Scan for HAP accessories over BLE and print what we find.
//!
//! Run: `cargo run -p hap-ble --example ble_scan`
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Scanning for HAP BLE accessories (5s)...");
    let found = hap_ble::scan(Duration::from_secs(5)).await?;
    if found.is_empty() {
        println!("None found. Is Bluetooth on and the accessory awake?");
    }
    for a in &found {
        println!(
            "- device_id={} category={} paired={} c#={} gsn={} ({})",
            a.device_id, a.category, a.paired, a.config_number, a.global_state_number, a.peripheral_id
        );
    }
    Ok(())
}
