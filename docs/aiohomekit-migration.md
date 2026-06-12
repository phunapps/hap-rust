# Migrating from aiohomekit to hap-controller

[`aiohomekit`](https://github.com/Jc2k/aiohomekit) is the Python IP-HomeKit
controller behind Home Assistant. `hap-controller` covers the same controller
workflow in Rust. This guide maps the calls you already know onto their
`hap-controller` equivalents.

The shapes are close, but two differences are worth calling out up front:

1. **Events are a `Stream`, not a callback.** aiohomekit dispatches change
   notifications through a callback dispatcher; `hap-controller` exposes them as
   an async `futures`/`tokio-stream` `Stream<Item = CharacteristicEvent>` from
   `handle.events()`. You `await` items in a loop instead of registering a
   listener.
2. **Persistence is a trait, not a dict.** aiohomekit hands you a `pairing_data`
   dict to serialize yourself. `hap-controller` takes a `PairingStore` (use the
   built-in `JsonFileStore`); `pair` and `remove_pairing` persist automatically,
   and the controller identity is loaded or created for you on `new`.

Also note values are a typed `CharValue` enum (`Bool`, `Int`, `Uint`, `Float`,
`Str`, `Bytes`) rather than aiohomekit's loosely-typed dict values.

## Call map

| aiohomekit (Python)                                    | hap-controller (Rust)                                      |
| ------------------------------------------------------ | ---------------------------------------------------------- |
| `Controller(...)` / `await controller.async_start()`   | `HapController::new(store).await?`                         |
| `await controller.async_discover()`                    | `controller.discover(timeout).await?`                      |
| `await controller.async_setup_pairing(...)` + finish   | `controller.pair(&accessory, setup_code).await?`           |
| `controller.pairings` / load from storage              | `controller.paired()` + `controller.connect(id).await?`    |
| `await pairing.list_accessories_and_characteristics()` | `handle.accessories().await?`                              |
| `await pairing.get_characteristics([(aid, iid)])`      | `handle.read(aid, iid).await?`                             |
| `await pairing.put_characteristics([(aid, iid, v)])`   | `handle.write(aid, iid, value).await?`                     |
| `pairing.dispatcher_connect(callback)`                 | `handle.subscribe(aid, iid).await?` + `handle.events()`    |
| `await pairing.remove_pairing(id)`                     | `controller.remove_pairing(id).await?`                     |
| `pairing.pairing_data` (persisted dict)                | `PairingStore` / `JsonFileStore` (persisted automatically) |

## Finding characteristics

aiohomekit returns the accessory database as nested dicts you index by service
and characteristic type strings. `hap-controller` parses it into a typed tree
and offers a helper:

```rust,ignore
handle.accessories().await?;                                 // fetch + cache once
let (aid, iid) = handle.find(ServiceType::Outlet, CharacteristicType::On)?;
```

You can also walk `handle.accessories()` (a `&[Accessory]`) directly — each
`Accessory` has public `aid` and `services`, each `Service` a `service_type` and
`characteristics`, each `Characteristic` an `iid`, `char_type`, `format`,
`value`, and metadata.

## Events

```rust,ignore
use tokio_stream::StreamExt;

handle.subscribe(aid, iid).await?;
let mut events = handle.events();
while let Some(evt) = events.next().await {
    println!("aid={} iid={} -> {:?}", evt.aid, evt.iid, evt.value);
}
```

Each `events()` call returns an independent stream; events that arrive while a
particular stream is lagging are dropped for that stream.
