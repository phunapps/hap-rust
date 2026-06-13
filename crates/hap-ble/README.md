# hap-ble

A Bluetooth LE transport for the [hap-rust](https://github.com/phunapps/hap-rust)
HomeKit controller stack. Discover, pair with, read from, and stream events off
a HomeKit accessory over BLE, reusing the same Pair Setup / Pair Verify crypto
as the IP transport.

> **Status:** Milestone A — a standalone transport. Unifying it with the IP
> `hap-controller` under one API is Milestone B. Characteristic **write**,
> broadcast notifications, and Thread are out of scope for this milestone.

## Example

```rust,no_run
use std::time::Duration;

# async fn run() -> Result<(), Box<dyn std::error::Error>> {
let found = hap_ble::scan(Duration::from_secs(5)).await?;
let Some(target) = found.iter().find(|a| !a.paired) else { return Ok(()) };

let gatt = hap_ble::connect_gatt(target).await?;
let controller = hap_ble::BleController::generate("my-controller".into());
let (accessory, _pairing) = controller.pair(gatt, target, "123-45-678").await?;

for acc in accessory.accessories() {
    println!("accessory with {} services", acc.services.len());
}
# Ok(())
# }
```

## Platform notes

- **macOS:** uses CoreBluetooth; the first run triggers the system Bluetooth
  permission prompt.
- **Linux:** uses BlueZ over D-Bus.

See the workspace `CHANGELOG.md` and the design spec in `docs/superpowers/specs/`.
