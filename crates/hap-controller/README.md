# hap-controller

The high-level [HomeKit Accessory Protocol (HAP)][hap] **controller** API — the
v1.0 face of the [`hap-rust`](https://github.com/phunapps/hap-rust) workspace. It
composes every lower `hap-*` crate (TLV8 codec, SRP/HAP crypto, transport,
pairing, accessory model) behind one ergonomic, fully documented surface so a
downstream application depends only on this crate to **discover, pair, connect,
read, write, and subscribe** to HomeKit accessories.

This is the controller side (what a Home-app / hub does), not the accessory
side. It is the first production-grade pure-Rust HomeKit controller library;
`aiohomekit` (Python, behind Home Assistant) is the closest comparable.

```sh
cargo add hap-controller
```

## Quickstart

```rust,no_run
use std::time::Duration;
use hap_controller::{CharValue, CharacteristicType, HapController, JsonFileStore, ServiceType};

#[tokio::main]
async fn main() -> hap_controller::Result<()> {
    // A JsonFileStore persists the controller identity and every pairing.
    let store = JsonFileStore::new("./homekit-pairings.json");
    let mut controller = HapController::new(store).await?;

    // Discover, then pair a plug with its 8-digit setup code.
    let found = controller.discover(Duration::from_secs(5)).await?;
    let plug = found.first().expect("an accessory in pairing mode");
    let mut handle = controller.pair(plug, "123-45-678").await?;

    // Toggle its On characteristic.
    handle.accessories().await?;
    let (aid, iid) = handle.find(ServiceType::Outlet, CharacteristicType::On)?;
    handle.write(aid, iid, CharValue::Bool(true)).await?;
    Ok(())
}
```

## The two types

- **`HapController`** — owns a `PairingStore` and the controller's long-term
  identity. `new`, `discover`, `pair`, `connect`, `paired`, `remove_pairing`.
- **`AccessoryHandle`** — one live secure session to one accessory.
  `accessories` (cached attribute database), typed `find(ServiceType,
  CharacteristicType)`, `read`, `write`, `subscribe`, and `events()` — an async
  `Stream<Item = CharacteristicEvent>`.

All failures surface as one `HapError`; `hap_controller::Result<T>` is the
public result alias.

## Examples

```sh
cargo run -p hap-controller --example discover
cargo run -p hap-controller --example pair_and_toggle -- 123-45-678
cargo run -p hap-controller --example subscribe -- <accessory-id>
```

## Migrating from aiohomekit

See [`docs/aiohomekit-migration.md`](../../docs/aiohomekit-migration.md) for a
call-by-call map from the `aiohomekit` controller API to `hap-controller`.

## Deferred past v1.0

BLE transport (GATT, HAP-BLE), IP-camera streaming (RTP/SRTP), MFi / hardware
authentication, the resident-controller role, Thread transport / Matter
bridging, `no_std`, the accessory side, and HAP service/characteristic types
beyond the common set. These ship in the 1.x line.

## License

Apache-2.0.

[hap]: https://developers.homebridge.io/
