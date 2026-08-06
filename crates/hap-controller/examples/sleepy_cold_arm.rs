//! Cold-arm a stored sleepy BLE sensor and stream its events.
//! `cargo run -p hap-controller --features ble --example sleepy_cold_arm -- <accessory-id> <iid>`
#![allow(clippy::expect_used, clippy::unwrap_used)] // example binary
use hap_controller::{HapController, JsonFileStore};
use std::time::Duration;
use tokio_stream::StreamExt as _;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let id = std::env::args()
        .nth(1)
        .expect("usage: sleepy_cold_arm <accessory-id> <iid>");
    let iid: u64 = std::env::args().nth(2).expect("iid").parse()?;
    let controller = HapController::new(JsonFileStore::new("./homekit-pairings.json")).await?;
    let watch = controller.watch_sleepy(&id, vec![(1, iid)]).await?;
    println!("armed; waiting for the sensor's next advert (trigger it) ...");
    let mut events = watch.events();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(180);
    while tokio::time::Instant::now() < deadline {
        if let Ok(Some(ev)) = tokio::time::timeout(Duration::from_secs(15), events.next()).await {
            println!("EVENT aid={} iid={} value={:?}", ev.aid, ev.iid, ev.value);
        }
    }
    watch.save_state().await?;
    Ok(())
}
