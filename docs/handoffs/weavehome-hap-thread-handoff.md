# Handoff: integrating HAP-over-Thread (+ BLE commissioning) into WeaveHome

**Date:** 2026-08-07 · **Source repo:** `phunapps/hap-rust` (branch `main`, tag `v3.0.3`)

All crates below are **published to crates.io** and hardware-validated end-to-end
against a real **Onvis SMS2** over Thread. This handoff covers what shipped, the
new public APIs, the integration flow, and the caveats you need to know.

---

## 1. What shipped (crate versions)

| Crate | New version | What's new for you |
|---|---|---|
| `hap-crypto` | **1.4.0** | `HapPairSetupSrpServer` — accessory-side Pair Setup (only needed if you host a DUT/accessory; controllers don't use it). Additive, backward compatible. |
| `hap-ble` | **0.7.0** | `thread_provision` + `ThreadDataset` — commission a HomeKit Thread accessory onto your Thread network over BLE. **Breaking 0.x bump** (0.6→0.7). |
| `hap-controller` | **3.0.3** | Internal `hap-ble` 0.6→0.7 dependency bump. Public API unchanged; drop-in for 3.0.x consumers. |
| `hap-thread` | **0.1.0** *(first release)* | The HAP-over-Thread **controller**: discover, pair, Pair Verify, read/write characteristics, read the `0x09` database, and **subscribe to events** over CoAP/UDP/IPv6. |
| `hap-thread-dut` | **0.1.0** *(first release)* | A reference **accessory** (device-under-test) for exercising Thread controllers without Apple hardware. You probably don't ship this; it's for tests. |

### Cargo.toml changes for WeaveHome
```toml
# bump these:
hap-ble = "0.7"          # was 0.6 — see migration note below
hap-controller = "3.0.3" # if you use the unified controller
hap-crypto = "1.4"

# add this for Thread:
hap-thread = "0.1"
```

**Migration note (hap-ble 0.6 → 0.7):** cargo treats a 0.x minor bump as breaking,
but the change is **purely additive** (new `thread_provision`/`ThreadDataset`). No
existing `hap-ble` API changed — you should only need to bump the version pin.

---

## 2. The one big idea: commissioning is BLE, operation is Thread

A HomeKit Thread accessory (like the SMS2) **cannot** be given Thread credentials
except over BLE. So the lifecycle is:

1. **Discover + Pair Setup over BLE** (existing `hap-ble` flow).
2. **`thread_provision`** over that BLE session — write your Thread operational
   dataset to the accessory. It leaves BLE and joins your Thread mesh.
3. **Pair Verify over Thread** reusing the **same controller identity** — the
   pairing is transport-agnostic (the accessory stored your controller LTPK once),
   so you Pair *Verify* (not Setup) over Thread with the pairing from step 1.
4. **Operate over Thread**: read/write characteristics, subscribe to events.

**Transport selection policy** (WeaveHome should implement): for a Thread-capable
accessory, *if you have a Thread border router*, commission it to Thread and
operate there (routable, always-on, low-power — better for battery sensors);
otherwise stay on BLE. BLE remains the setup path and the fallback. The controller
makes this choice from device capability + network availability — not a user
toggle.

---

## 3. New APIs you'll call

### 3a. Commission over BLE — `hap-ble` 0.7
```rust
use hap_ble::{BleController, ThreadDataset, Paired};

// Pair over BLE (existing flow), keeping ONE controller identity you also use
// for Thread:
let keypair = /* your persisted hap_crypto::ControllerKeypair */;
let ble = BleController::new(keypair.clone());
let Paired { mut accessory, pairing, .. } = ble.pair(gatt, &target, setup_code).await?;

// Your Thread operational dataset (from your border router — OpenThread:
// `ot-ctl networkname/channel/panid/extpanid/networkkey`).
let dataset = ThreadDataset {
    network_name: "MyThreadNet".into(),
    channel: 24,
    pan_id: 0x89d7,
    ext_pan_id: [/* 8 bytes */],
    network_key: [/* 16 bytes — SECRET; ThreadDataset's Debug redacts it */],
};
accessory.thread_provision(&dataset).await?;   // it now joins your mesh
// Persist `keypair` + `pairing` (accessory id + LTPK) — you need both for Thread.
```
`thread_provision` tolerates the expected BLE teardown as the device switches
networks (it returns `Ok`); **confirm success by the device appearing on the mesh**
(SRP `_hap._udp`), not by the call result.

### 3b. Operate over Thread — `hap-thread` 0.1
```rust
use hap_thread::{ThreadController, discover};

// Discover on the mesh (mDNS/SRP `_hap._udp`). NB: SRP keeps *stale* registrations
// for a host until their lease expires — filter/try candidates (see caveats).
let found = discover(std::time::Duration::from_secs(4)).await?;
let addr = /* pick the live candidate's SocketAddr */;

// Pair VERIFY over Thread with the SAME identity + the pairing from BLE:
let controller = ThreadController::new(keypair);      // reuse the BLE keypair
let accessory = controller.connect(addr, &pairing).await?;  // Pair Verify

// Read / write characteristics by instance id:
let value = accessory.read_characteristic(iid).await?;
accessory.write_characteristic(iid, &[0x01]).await?;

// The whole 0x09 attribute database (raw decrypted bytes — see caveat on decode):
let db: Vec<u8> = accessory.read_database_raw().await?;

// Events (accessory-pushed): subscribe, then await pushes:
accessory.subscribe(iid).await?;                      // 0x0B
loop {
    let events: Vec<(u16, Vec<u8>)> = accessory.next_event().await?; // (iid, value)
    for (iid, value) in events { /* dispatch */ }
}
accessory.unsubscribe(iid).await?;                    // 0x0C
```
- First-time (unpaired) Thread pairing: `controller.pair(addr, setup_code)` does
  Pair Setup + Verify (for accessories already on a Thread network you can reach).
- `identify(addr)` is an unauthenticated poke (an already-paired accessory answers
  `4.04` — that's correct, not an error to panic on).

### 3c. `hap-crypto` 1.4 — `HapPairSetupSrpServer`
Only relevant if WeaveHome ever hosts an accessory/DUT. Controllers ignore it.

---

## 4. Caveats & known limitations (read these)

1. **`0x09` → typed tree decode now ships in `hap-thread` 0.2.0.** `ThreadAccessory::read_database()` returns a typed `Vec<hap_model::Accessory>` (services → characteristics with iid, HAP type, format, perms); `hap_thread::decode_database(raw)` decodes a raw body. Cross-verified against aiohomekit on the committed real SMS2 body. (`read_database_raw` still returns the raw bytes if you want them.) NB: bump `hap-thread = "0.2"` to get this.

2. **Events stream (`hap-thread` 0.3.0).** `ThreadAccessory::watch_events()` returns
   a `Stream<Item = (u16, Vec<u8>)>` backed by a background task — feed it straight
   to your event bus (the lower-level `next_event()` loop is still available).
   `subscribe()` the characteristics first; re-subscribe after any Pair Verify
   (session reset). **Caveat:** while a watcher is active it owns the session's
   inbound path, so don't interleave reads/writes with event watching on the *same*
   accessory (a full request/response + event demux on one socket is future work).
   NB: bump `hap-thread = "0.3"`.

3. **Sleepy accessories.** The SMS2 is a Thread SED: high, variable latency
   (ping RTT 0.4–1.5 s) and it re-arms motion slowly (~15 s between triggers). The
   transport retransmits, but budget generous timeouts and expect the first
   Pair-Verify attempt to sometimes need a retry.

4. **Stale SRP discovery.** After re-commissioning, SRP holds the old host
   registration (dead address) until its lease expires. Discovery returns both —
   **try each candidate** and skip the ones that time out (our `onvis_thread`
   example does this; copy that logic).

5. **Large responses arrive as one datagram.** The Onvis returns the whole `0x09`
   (~2.7 KB) as a single IPv6-fragmented datagram, not Block2. `hap-thread`'s
   receive buffer is 16 KiB to handle this; both Block2 (RFC 7959) and separate
   responses (RFC 7252 §5.2.2) are also handled. If you target accessories with
   even larger databases, the buffer may need raising.

6. **macOS BLE is broken on macOS 26.** `bluest`/`objc2-foundation 0.3.2` panics
   (`NSUUID getUUIDBytes:`) on macOS 26.5.x before it can scan. **Run BLE
   (commissioning) on Linux/BlueZ** (we did it on a Raspberry Pi) until `bluest`
   ships a fix. Thread (UDP) is unaffected and runs anywhere on the mesh.

7. **BLE encrypted broadcasts (`0x11`) are unexercised on the SMS2** — the device
   doesn't emit them (confirmed vs aiohomekit). Our broadcast crypto is
   CI-vector-validated but has no live emitter on this sensor; unrelated to Thread.

---

## 5. What's proven on real hardware (confidence)

Against a factory-reset **Onvis SMS2** on an OpenThread border router:
- BLE Pair Setup → `thread_provision` → device SRP-registered on the mesh.
- **Pair Verify over Thread** (cross-transport identity reuse).
- **`0x09` database read** over the radio (2737 bytes; decodes to the full SMS2
  service/characteristic tree).
- **Live MotionDetected events over Thread** — `value=[1]` (detected) and
  `value=[0]` (clear), decrypted on the event channel.

Full narrative + logs: `docs/tested-devices.md` (section "Onvis SMS2 — BLE→Thread
commissioning"). CoAP session/record layer is byte-for-byte cross-verified against
aiohomekit (`test-vectors/thread-coap/`).

---

## 6. Suggested WeaveHome integration order

1. Bump `hap-ble`/`hap-controller`/`hap-crypto`; add `hap-thread`. Build/test.
2. Add a **commissioning flow**: BLE pair → `thread_provision(dataset)` → persist
   `{controller keypair, accessory pairing, transport=Thread}` in your store
   (mirror the transport-tagged pairing record `hap-controller` already uses).
3. Add a **Thread connect+operate path**: discover (try-each) → `connect(addr,
   pairing)` → read/write; run a per-accessory **event task** around
   `subscribe`/`next_event`.
4. **iid mapping:** decode the `0x09` body (out-of-band for now) into your
   characteristic model, or gate Thread accessories to known profiles until the
   Rust tree decoder lands.
5. Implement the **transport-selection policy** (§2): prefer Thread when a border
   router is present.
6. Run BLE commissioning on a Linux host until the macOS `bluest` fix lands.

Questions on any API — the `crates/hap-thread/examples/onvis_thread.rs` example is
the complete, working reference for the whole commission→verify→read→events flow.
