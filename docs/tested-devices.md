# Accessories tested against `hap-rust`

`CLAUDE.md` asks us to record which HomeKit accessories we have paired and
controlled. Fill a row each time you pair a real accessory end-to-end (from M5
onward) or control one (from M6 onward).

## Devices paired with hap-rust

Pair using the `pair_accessory` example; the full procedure (and how to fill a
row here) is in [`runbooks/m5-first-pairing.md`](runbooks/m5-first-pairing.md).

| Accessory (make/model) | Category | Setup | Date | aiohomekit cross-check | Notes |
|---|---|---|---|---|---|
| LIFX Clean (LIFX Z 6DCBC4) | Lightbulb (5) | IP, 8-digit code | 2026-06-12 | PASS — aiohomekit Pair-Verified with the controller identity hap-rust created and `list-pairings` reported it as admin; hap-rust `ListPairings` returns the identical pairing | **First pure-Rust HAP pairing.** Full M5 flow end-to-end: discover (`_hap._tcp`) → Pair Setup (SRP-6a M1–M6) → persist → Pair Verify (M1–M4) → SecureSession → ListPairings → 1 pairing (this controller, admin). Surfaced and fixed a real bug: `/pairings` is POST, not PUT (405 on PUT). |

**Deferred:** any BLE-only accessory — blocked on the BLE transport (post-v1.0).
HAP-IP accessories only for v1.0.

## Devices tested over BLE (`hap-ble`, Milestone A)

| Accessory (make/model) | Category | Date | Result |
|---|---|---|---|
| Onvis Smart Motion Sensor SMS2 | Sensor (10) | 2026-06-14 | **Fully validated** — discover → pair → full 65-char database → encrypted read → connected events. |

**Full success (with the `bluest` backend + reconnect-and-resume supervisor):**
discover → Pair Setup → Pair Verify → the entire ~65-characteristic attribute
database → an encrypted value read (`read(aid=1, iid=3) → "Onvis"`) → **connected
events** (subscribed to MotionDetected; each motion trigger produced
`EVENT iid=3074 value=Bool(true)`). The typed model decoded correctly
(MotionDetected→Bool, CurrentTemperature→Float, CurrentRelativeHumidity→Float,
BatteryLevel→Uint8, …). Run via
`cargo run --release -p hap-ble --example ble_pair_bluest -- <setup-code>`.

HAP-BLE connected events use the GATT notification only as a **trigger**; the new
value is fetched with an encrypted Characteristic-Read in response (not carried in
the notification).

The earlier-recorded findings below were the path to that result.

**What validated on the real Onvis SMS2:**

- **BLE scan + HAP advertisement parsing** — manufacturer-data (company `0x004C`)
  parsed exactly: device id, category 10 (Sensor), GSN, `c#`, unpaired flag. (The
  Onvis rotates its advertised HAP device id between adverts; the CoreBluetooth
  peripheral UUID is stable, so match/connect by that.)
- **GATT connect + discovery** (14 services) and **Instance-ID descriptor
  resolution** for every characteristic (Pair-Setup `…004c`→iid 34, Pair-Verify
  `…004e`→iid 35, plus temp/humidity/motion/battery services).
- **Full Pair Setup (M1→M6) and Pair Verify (M1→M4) on the wire.** Trace: M1→read
  418 (M2 salt+pubkey), M3→read 104 (M4), M5→read 147 (M6); verify M1→read 147,
  M3→read 10 (M4). The SRP-6a + X25519/Ed25519 handshake from `hap-crypto` drives
  correctly over BLE.

**Three real HAP-BLE bugs found & fixed via an aiohomekit/bleak reference capture
of the same device** (`xtask/scripts/capture-pair-setup/ble_pair_capture.py`):

1. **Missing Return-Response param.** A Characteristic-Write over BLE must include
   HAP-Param Return-Response (`0x09`=1) before the Value param, or the accessory
   replies with only a status (the bare `02 01 00` we saw) and never returns the
   body. This single missing TLV param blocked the entire handshake. (Not needed
   over IP, which is why Pair Setup worked there.)
2. **Fragment size.** PDUs must be fragmented to the ATT MTU (the Onvis negotiated
   ~290); our 512 produced an oversized single write that hung at M3. Now 180.
3. **Per-fragment encryption.** The secure session encrypts each fragment
   separately (plaintext fragmented then sealed), not the whole PDU once.

**What finished the job (the database build + read):** the Onvis drops the link
every few operations during the long ~65-characteristic structure sweep. This is
a sleepy-accessory trait, not a protocol gap — aiohomekit (cross-checked on the
same device: it read all 65 characteristics across ~10 disconnects via
`bleak-retry-connector`) handles it by reconnecting through the drops. Four
changes closed it:

4. **Reconnect-and-resume supervisor** (`BluestConnection`): each operation
   reconnects (re-discovering handles by UUID) and retries on a clean disconnect,
   resuming the sweep where it left off.
5. **`bluest` backend instead of `btleplug`** on macOS: btleplug *hung* on these
   disconnects (no timeout, unrecoverable); bluest returns clean errors a
   supervisor can act on. (btleplug's CoreBluetooth backend is its least mature.)
6. **Order:** read only the Pair-Setup iid, Pair Setup, *then* the resilient
   tree walk + signature reads, *then* Pair Verify — so the stateful handshakes
   run before the long sweep and a mid-sweep reconnect can't corrupt them.
7. **Unencrypted structure fetch:** signature reads happen after Pair Setup but
   before Pair Verify (no session yet), matching HAP; only values are encrypted.

Plus a **factory reset** of the device — a successfully-paired accessory rejects a
fresh Pair Setup ("pairing error"); a power-cycle keeps the pairing, a factory
reset returns it to pairable.

**Connected events** were the last piece: a HAP-BLE notification is only a
trigger, so on each one the controller issues an encrypted Characteristic-Read for
the value. With that, MotionDetected events flowed on every motion trigger.

## Feature B spike — macOS scan-while-connected (2026-06-15, Onvis SMS2)

Gate for the sleepy-device-events milestone (Approach 1: each `BleAccessory` runs
its own continuous scan while also connecting on demand for catch-up polls). A
throwaway spike paired the Onvis, then for ~30 s issued encrypted reads **while a
continuous scan ran concurrently**: **6/6 reads OK, 0 errors**, and a clean
`remove_pairing` afterward. Scanning does **not** disturb an active CoreBluetooth
connection on macOS — Approach 1 is safe.

Note: the concurrent scan reported 0 adverts each round, which is expected — a BLE
peripheral stops advertising once connected (and no other HAP-BLE device was in
range). The broadcast / disconnected-event channels operate when the device is
*disconnected* (and therefore advertising), which standard scans already pick up
reliably; the spike's job was only to prove the scanner can't corrupt a live link.

## Feature B durable events — live validation (2026-06-15, Onvis SMS2)

Validated the shipped sleepy-device-events code (`hap-crypto` 1.1.0 broadcast
module + `hap-ble` 0.1.0 `watch_sleepy_events`) against the real Onvis SMS2.

**What validated live:** pair → `Paired{accessory,pairing,broadcast}` →
generate-broadcast-key request **accepted** by the accessory → the advert pipeline
end-to-end (continuous scan → match by **HAP Device ID** in manufacturer data →
GSN-bump detection → poll trigger) → **no reconnect storm over a long idle**
(the original Feature-A reconnect-storm bug, confirmed fixed: best-effort notify
with no auto-reconnect).

**Device limitation — the Onvis SMS2 does NOT emit `0x11` encrypted broadcasts.**
The decisive cross-check: a script
(`xtask/scripts/capture-pair-setup/aio_broadcast_test.py`) drove **aiohomekit**
itself — broadcast key derived, all 10 broadcast-capable characteristics
(including MotionDetected) subscribed, then disconnected — and observed **zero
`0x11` adverts over 90 s of repeated motion**. So this is the accessory's choice,
not a hap-rust bug. Our broadcast crypto is correct and CI-vector-validated
(byte-exact against captured aiohomekit vectors); it simply has no live emitter to
test against on this sensor. A different accessory that broadcasts is needed to
exercise the `0x11` decrypt path on real hardware.

**Poll path live delivery is blocked by a macOS limitation (not a protocol bug).**
The disconnected-event catch-up poll needs to connect *while* the advert scan is
running, but on macOS CoreBluetooth a `connect` cannot complete while a scan is in
progress, so the reconnect-read hangs. The catch-up poll therefore detects the GSN
bump but can't yet fetch the value live on macOS. Scoped follow-up for a future
hap-ble 0.x: pause the advert scan during the reconnect-read, run reads off the
advert task, and re-add `NotFound`→reconnect mapping (currently
`NotFound`→`Disconnected` because it hangs during a scan). The IP path and all
CI-tested logic are unaffected.

**Update (2026-07-27):** the scoped follow-up shipped in `hap-ble` 0.2.0 —
the advert scan pauses during reconnect/disconnect (`ScanGate`), catch-up poll
reads run off the advert task (GSN bumps coalesce through a watch channel),
and bluest `NotFound` maps to a recoverable disconnect again. Live poll-path
delivery on the Onvis SMS2 is pending re-validation (next section when run).

## Feature B poll path — live validation (2026-07-31, Onvis SMS2)

Validated `hap-ble` 0.2.0's scan-pause poll path end-to-end on the real Onvis
SMS2 (`ble_sleepy_events` example, release build): factory-reset → pair →
generate-broadcast-key accepted → disconnect → 180 s watch window, two motion
triggers ~90 s apart.

- **Disconnected-event poll delivered live on macOS.** Both triggers produced
  `MotionDetected` events through the `0x06` GSN-bump poll: bump detected →
  advert scan paused → reconnect-read completed → value decoded → scan
  resumed. The reconnect-read that hung mid-scan before 0.2.0 completed both
  times.
- **Scan resumption proven on hardware.** The second GSN bump was detected and
  polled after the first cycle's reconnect-read had taken and released the
  radio — the advert scan restarts cleanly after each `ScanGate` pause (the
  one liveness property CI structurally cannot see).
- **Sensor re-arm caveat.** Continuous motion keeps the SMS2's motion state
  active and produces no further GSN bumps; a ~60 s still period between
  triggers is needed before it re-triggers. (The earlier "wait ~30 s" guidance
  is marginal — 60 s is reliable.)
- **`remove_pairing` on the slept device succeeded** — the operation's
  reconnect now recovers from the stale-handle `NotFound` and the accessory
  returned to pairable state. No reconnect storm, clean exit.
- Still **no `0x11` encrypted broadcasts** from this accessory (unchanged
  device limitation); the broadcast decrypt path remains CI-vector-validated
  only.
