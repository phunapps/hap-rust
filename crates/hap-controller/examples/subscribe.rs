//! Connect to an already-paired sensor and stream its value changes.
//!
//! Run: `cargo run -p hap-controller --example subscribe -- <accessory-id>`

#![allow(clippy::unwrap_used, clippy::expect_used)] // example binary

use hap_controller::{CharacteristicType, HapController, JsonFileStore, ServiceType};
use tokio_stream::StreamExt;

#[tokio::main]
async fn main() -> hap_controller::Result<()> {
    let accessory_id = std::env::args()
        .nth(1)
        .expect("usage: subscribe <accessory-id> (see the `discover` example)");

    let store = JsonFileStore::new("./homekit-pairings.json");
    let controller = HapController::new(store).await?;

    let mut handle = controller.connect(&accessory_id).await?;
    handle.accessories().await?;

    let (aid, iid) = handle.find(
        ServiceType::TemperatureSensor,
        CharacteristicType::CurrentTemperature,
    )?;
    handle.subscribe(aid, iid).await?;
    println!("Subscribed to temperature on {accessory_id}. Streaming events (Ctrl-C to stop)...");

    let mut events = handle.events();
    while let Some(evt) = events.next().await {
        println!("aid={} iid={} -> {:?}", evt.aid, evt.iid, evt.value);
    }
    Ok(())
}
