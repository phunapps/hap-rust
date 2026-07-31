//! Discover on both transports, pair whatever answers first, read one value,
//! then stream events. Run:
//! `cargo run -p hap-controller --features ble --example unified_pair_and_read -- <setup-code>`
#![allow(clippy::expect_used, clippy::unwrap_used)] // example binary
use hap_controller::{CharacteristicType, Discovered, HapController, JsonFileStore, ServiceType};
use std::time::Duration;
use tokio_stream::StreamExt as _;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let setup_code = std::env::args()
        .nth(1)
        .expect("usage: unified_pair_and_read <setup-code>");
    let mut controller = HapController::new(JsonFileStore::new("./homekit-pairings.json")).await?;

    let found = controller.discover(Duration::from_secs(8)).await?;
    let Some(target) = found.iter().find(|d| !d.paired()) else {
        println!("no unpaired accessory found on either transport");
        return Ok(());
    };
    let transport = match target {
        Discovered::Ip(_) => "ip",
        Discovered::Ble(_) => "ble",
    };
    println!("pairing with {} over {transport} ...", target.name());

    let mut handle = controller.pair(target, &setup_code).await?;
    let accessories = handle.accessories().await?;
    println!("{} accessories in database", accessories.len());

    // Try to read the On characteristic from a LightBulb service
    match handle.find(ServiceType::LightBulb, CharacteristicType::On) {
        Ok((aid, iid)) => match handle.read(aid, iid).await {
            Ok(value) => println!("On = {value:?}"),
            Err(e) => println!("read failed: {e}"),
        },
        Err(_) => println!("no LightBulb/On characteristic found"),
    }

    let mut events = handle.events();
    println!("streaming events for 60s ...");
    let _ = tokio::time::timeout(Duration::from_secs(60), async {
        while let Some(ev) = events.next().await {
            println!("event: aid={} iid={} value={:?}", ev.aid, ev.iid, ev.value);
        }
    })
    .await;
    controller.save_state(&handle).await?;
    Ok(())
}
