//! Discover HomeKit accessories on the local network and print them.
//!
//! Run: `cargo run -p hap-controller --example discover`

#![allow(clippy::unwrap_used, clippy::expect_used)] // example binary

use std::time::Duration;

use hap_controller::{HapController, JsonFileStore};

#[tokio::main]
async fn main() -> hap_controller::Result<()> {
    let store = JsonFileStore::new("./homekit-pairings.json");
    let controller = HapController::new(store).await?;

    println!("Browsing _hap._tcp for 5s...");
    let found = controller.discover(Duration::from_secs(5)).await?;

    if found.is_empty() {
        println!("No accessories found. Is one in pairing mode on this network?");
        return Ok(());
    }
    for acc in &found {
        println!("- {}  ({})  paired={}", acc.name(), acc.id(), acc.paired());
    }
    Ok(())
}
