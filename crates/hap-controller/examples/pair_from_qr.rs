//! Pair the accessory a scanned HomeKit QR points at.
//! `cargo run -p hap-controller --features ble --example pair_from_qr -- "X-HM://…"`
#![allow(clippy::expect_used, clippy::unwrap_used)] // example binary
use hap_controller::{HapController, JsonFileStore, SetupPayload};
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let uri = std::env::args()
        .nth(1)
        .expect("usage: pair_from_qr <X-HM://...>");
    let payload = SetupPayload::parse(&uri)?;
    println!(
        "scanned: category={} setup_id={:?} flags(ip={},ble={},nfc={})",
        payload.category, payload.setup_id, payload.flags.ip, payload.flags.ble, payload.flags.nfc
    );

    let mut controller = HapController::new(JsonFileStore::new("./homekit-pairings.json")).await?;
    println!("discovering + matching (up to 90s) ...");
    let mut handle = controller
        .pair_with_payload(&payload, Duration::from_secs(90))
        .await?;
    let accessories = handle.accessories().await?;
    println!("paired — {} accessories in database", accessories.len());
    controller.save_state(&handle).await?;
    Ok(())
}
