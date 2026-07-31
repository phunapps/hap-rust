//! Pair with a plug using its setup code, then toggle its On characteristic.
//!
//! Run: `cargo run -p hap-controller --example pair_and_toggle -- 123-45-678`

#![allow(clippy::unwrap_used, clippy::expect_used)] // example binary

use std::time::Duration;

use hap_controller::{CharValue, CharacteristicType, HapController, JsonFileStore, ServiceType};

#[tokio::main]
async fn main() -> hap_controller::Result<()> {
    let setup_code = std::env::args()
        .nth(1)
        .expect("usage: pair_and_toggle <setup-code, e.g. 123-45-678>");

    let store = JsonFileStore::new("./homekit-pairings.json");
    let mut controller = HapController::new(store).await?;

    let found = controller.discover_ip(Duration::from_secs(5)).await?;
    let target = found.first().expect("no accessory found to pair with");
    println!("Pairing with {} ...", target.name);

    let mut handle = controller.pair(target, &setup_code).await?;
    handle.accessories().await?; // populate the cache so find() works

    // Locate the On characteristic of an Outlet or Switch service.
    let (aid, iid) = handle
        .find(ServiceType::Outlet, CharacteristicType::On)
        .or_else(|_| handle.find(ServiceType::Switch, CharacteristicType::On))?;

    let current = handle.read(aid, iid).await?;
    let next = matches!(current, CharValue::Bool(false));
    println!("On is {current:?}; setting to {next}");
    handle.write(aid, iid, CharValue::Bool(next)).await?;
    println!("Done.");
    Ok(())
}
