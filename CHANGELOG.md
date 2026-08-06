# Changelog

All notable changes to crates in the `hap-rust` workspace.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Each crate is versioned independently. Sections below are grouped by crate; the
workspace-wide foundation work is tracked under "Workspace".

## 3.0.2 / hap-ble 0.6.1 — 2026-08-07 — Encrypted broadcast (0x11) motion, end-to-end

Completes HAP-BLE encrypted broadcast notifications: a sleepy sensor's
characteristic change now arrives as an instant encrypted `0x11` broadcast
instead of only the ~2 s reconnect poll. Two fixes, both hardware-validated
against an Onvis SMS2 (motion delivered as `0x11` → decrypted → `MotionDetected =
true`). `hap-ble` bumps to `0.6.1`; `hap-controller` to `3.0.2` (dep bump only,
no API change).

### `hap-ble` 0.6.1
- **Fix:** the generate-broadcast-key request was aborted because the
  Protocol-Information Service-Signature characteristic was dropped from the
  enumerated attribute tree (`enumerate` skipped the Service-Signature char for
  *every* service, so its service could not be found). It is now retained for the
  Protocol-Information service — where its instance id is the request target —
  and skipped from the model elsewhere, mirroring the existing handle-map
  asymmetry. This was a latent bug from 0.5 that 0.6.0 only made visible.
- **Fix:** the generate-broadcast-key Protocol-Configuration PDU now carries the
  Protocol-Information **service's** instance id (aiohomekit's
  `hap_char.service.iid`), read from the service's Service-Instance-ID
  characteristic during discovery and carried on `GattService::iid`. It
  previously sent the Service-Signature *characteristic's* iid, which a real
  accessory rejects with HAP status 4 ("invalid instance id"), leaving no
  broadcast key and therefore no `0x11` broadcasts. With both fixes the accessory
  generates its broadcast key, accepts the per-characteristic enable, and emits
  encrypted broadcasts that decode to characteristic events.

### `hap-controller` 3.0.2
- Depends on `hap-ble` `0.6.1`. No API change.

## 3.0.1 / hap-ble 0.6.0 — 2026-08-07 — Linux sleepy-poll fix + broadcast diagnostics

Unblocks sleepy BLE sensors on Linux/BlueZ (the cold-arm catch-up poll now
reconnects instead of dying on the first read) and makes HAP encrypted-broadcast
(`0x11`) setup observable end-to-end. `hap-ble` bumps to `0.6.0`; `hap-controller`
bumps to `3.0.1` solely to depend on it (no `hap-controller` API change). No
consumer code change is required.

### `hap-ble` 0.6.0
- **Fix (Linux/BlueZ):** a GATT operation against a disconnected device surfaces
  on BlueZ as `org.bluez.Error.Failed` "Not connected", which `bluest` collapses
  to `ErrorKind::Other`. `be()` classified that as a non-recoverable `Backend`
  error, so the reconnect-and-retry supervisor never fired and the sleepy
  cold-arm catch-up poll read on a deliberately-dropped link — every read failed
  with "Not connected". `be()` now recovers this case from the error message and
  classifies it as `Disconnected`, matching how macOS/CoreBluetooth already
  surfaced it (the typed `NotConnected` kind). A genuine unrelated `Other` error
  still maps to `Backend` (no spurious reconnects).
- **Diagnostics:** `tracing` instrumentation across the sleepy advert path
  (advert reception, device-id match, GSN-bump vs suppression, poll firing and
  event emission) and the broadcast-enable path. Enable with a `hap_ble=debug`
  (or `=trace`) subscriber; zero-cost when no subscriber is installed.
- **Diagnostics:** the two writes that arm encrypted broadcasts now log their
  outcome (`hap_ble=debug`) instead of silently dropping it — the
  `GenerateBroadcastEncryptionKey` Protocol-Config write at connect and each
  per-characteristic `enable_broadcasts` write (accepted / rejected-with-status /
  write-failed / characteristic-absent). Each characteristic's raw HAP
  properties word is logged at discovery, including the `0x0200`
  supports-broadcast-notify bit — the definitive check for whether a given
  characteristic can emit `0x11` broadcasts at all. Behavior is unchanged; both
  broadcast-arming paths remain best-effort and non-fatal, and no public API
  changed.

### `hap-controller` 3.0.1
- Depends on `hap-ble` `0.6.0` (for the Linux sleepy-poll fix and broadcast
  diagnostics above). No API change.

## 3.0.0 — 2026-08-06 — Seamless sleepy BLE sensors

Cold-arm a sleepy BLE sensor straight from a stored pairing after a reboot —
no blocking connect, no re-pairing — and durably persist broadcast/GSN state
through concurrent writers. `hap-controller` majors to `3.0.0` for one breaking
signature change (below); `hap-pairing` (`2.1.0`) and `hap-ble` (`0.5.0`) are
additive.

### `hap-controller` 3.0.0
- `HapController::watch_sleepy(accessory_id, poll_iids)` cold-arms an
  advert-driven watch from a stored BLE pairing and returns a `SleepyWatch`
  immediately, without blocking on the connect: a background task waits for
  the device's next advertisement, connects once (serialized by an internal
  radio mutex), enables broadcasts, disconnects so the sleepy device
  advertises again, arms the self-sourcing sleepy watch, and pumps events into
  `SleepyWatch::events`, auto-persisting GSN/broadcast state via
  `PairingStore::save_broadcast_state` after every event. `SleepyWatch::save_state`
  force-flushes the latest state (an `Ok` no-op before the background task has
  connected).
- **Breaking (the reason for the major bump):** the unified
  `AccessoryHandle::watch_sleepy_events` signature changes from the previous,
  unusable 3-argument form to `watch_sleepy_events(poll_iids)` — 1-arg,
  self-sourcing the advert source and device id from the live connection,
  matching `hap-ble`'s new primitive below. The 3-arg form was effectively
  uncallable (the caller could not obtain the `AdvertSource`), but a
  signature change is breaking, so `hap-controller` majors to `3.0.0` per
  strict semver.

### `hap-pairing` 2.1.0
- Store writes are now atomic with respect to concurrent writers: the JSON
  file store serializes and overwrites via a temp-file-then-rename, and the
  new `PairingStore::save_broadcast_state(id, broadcast)` updates only a
  stored accessory's broadcast key/GSN — a targeted, race-safe alternative to
  read-modify-write on the full pairing record for sleepy-watch background
  tasks that persist after every event.

### `hap-ble` 0.5.0
- `GattConnection::disconnect` on the connection seam, so a sleepy watch can
  drop the link after enabling broadcasts and let the device advertise again.
- New self-sourcing `BleAccessory::watch_sleepy_events(poll_iids)`, which
  reuses the accessory's own advert source and device id.
- **Breaking:** the previous explicit-source primitive is renamed
  `watch_sleepy_events_with_source` (unchanged 3-arg signature) to free up
  the `watch_sleepy_events` name for the new self-sourcing method. Direct
  `hap-ble` callers of the old 3-arg `watch_sleepy_events` must switch to
  `watch_sleepy_events_with_source`.
- New `SleepyConnector` trait (and `BluestSleepyConnector`), the seam
  `hap-controller`'s cold-arm orchestration connects through — testable
  without a real radio.

## 2.1.0 — 2026-08-06 — QR setup-payload pairing

Pair the exact accessory a scanned HomeKit QR points at, precisely and
symmetrically over IP and BLE.

### `hap-controller` 2.1.0
- `SetupPayload::match_kind` + `HapController::pair_with_payload(payload, timeout)`:
  discover-with-retry, identify the scanned accessory (precise setup-hash match
  when available, else category), and pair — with new `HapError::NoMatchingAccessory`
  / `AmbiguousMatch` errors and no auto-trying the code against multiple devices.
- **Behavior change:** `SetupFlags.ble` / `.nfc` now decode from the payload
  (previously hardcoded `false`).

### `hap-crypto` 1.2.0
- New `setup_hash(setup_id, device_id)` — the HAP setup hash.

### `hap-transport` 1.2.0
- `DiscoveredAccessory.setup_hash` decoded from the `sh` mDNS TXT.

### `hap-ble` 0.4.0
- **Breaking:** `DiscoveredBleAccessory.setup_hash` from the advertisement; base
  advert floor lowered 17→15 so hashless short adverts still discover.

## 2.0.0 — 2026-08-04 — Milestone B (unified controller)

One controller API across IP and Bluetooth LE. `hap-pairing` bumps to `2.0.0`
(transport-aware store, v1 files migrate transparently), `hap-ble` to `0.3.0`
(public `write`, `test-support` feature), `hap-controller` to `2.0.0`.

### `hap-controller` 2.0.0

- `discover` now returns `Vec<Discovered>` spanning mDNS and (with the new
  `ble` cargo feature) the BLE scan; `discover_ip`/`discover_ble` remain as
  typed escape hatches. `pair` takes a `&Discovered`; `connect` dispatches on
  the stored record's transport.
- `AccessoryHandle` is transport-unified: read/write/subscribe/events work
  identically over both transports; batch reads/writes loop sequentially on
  BLE; IP-only operations (`unsubscribe`, timed writes, write-with-response,
  pairings list/add, identify) return the new
  `HapError::UnsupportedByTransport` on BLE.
- New `save_state` persists BLE broadcast material (key + latest GSN).
- **Migration:** v1 pairing-store files load transparently and are rewritten
  as version 2 on the next save. Code constructing `StoredAccessory` must
  switch from `addr` to `transport: StoredTransport::Ip { addr }`.

### `hap-pairing` 2.0.0

- `StoredAccessory.transport: StoredTransport` (`Ip { addr }` or
  `Ble { device_id, broadcast }` with zeroizing key material); JSON store
  document version 2 with transparent v1 migration; `WrongTransport` error;
  `format_device_id`/`parse_device_id` helpers.

### `hap-ble` 0.3.0

- Public `BleAccessory::write` (typed, format-encoded, session-revived) and
  `pairing_id`; `BleError::RequestRejected`; `test-support` feature exposing
  the GATT mock and accessory fixture (semver-exempt testing seam).

## 1.4.0 — 2026-07-27

Live disconnected-event delivery on macOS. `hap-ble` bumps to `0.2.0`
(behavioral); the other crates are unchanged.

### `hap-ble` 0.2.0

- The advert scan pauses while the supervisor reconnects or disconnects
  (`ScanGate` coordination): on macOS CoreBluetooth a connect cannot complete
  while a scan is running, which left the disconnected-event catch-up poll
  unable to fetch values live. Stop scan → connect → resume scan; the catch-up
  read then runs over the re-established link.
- Catch-up poll reads run on their own task, fed the latest bumped GSN through
  a watch channel — the advert loop never blocks on GATT I/O, and a burst of
  GSN bumps coalesces into one poll of the latest value.
- bluest `NotFound` errors classify as recoverable disconnects, so an
  operation against a slept accessory's stale handle reconnects (and
  re-discovers handles) instead of failing — this also fixes `remove_pairing`
  after the device has slept.

## 1.3.0 — 2026-06-15

BLE transport and durable sleepy-device events. `hap-crypto` bumps to `1.1.0`
(additive) and `hap-ble` makes its first release at `0.1.0`; the other crates
are unchanged.

### `hap-crypto` 1.1.0

- New `broadcast` module for HAP-BLE encrypted broadcast notifications:
  `BroadcastKey` (a zeroizing newtype with a redacted `Debug`), `derive` of the
  broadcast-encryption key via HKDF-SHA512, and `seal`/`open` using
  ChaCha20-Poly1305 with the HAP 4-byte partial Poly1305 tag and a GSN-derived
  nonce. Byte-verified against captured `aiohomekit` vectors.
- `PairVerifyClient::broadcast_key` derives the broadcast key from the Pair
  Verify shared secret and the controller's long-term public key.

### `hap-ble` 0.1.0 — first release

- HAP Bluetooth LE transport: discover, pair (Pair Setup + Pair Verify), build
  the attribute database, encrypted characteristic reads, and connected event
  notifications, over the `bluest` backend (macOS CoreBluetooth).
- Durable events for sleepy accessories that drop their BLE link: encrypted
  broadcast notifications (manufacturer-data type `0x11`, decrypted with the
  persisted broadcast key against the advertised GSN) and a disconnected-event
  catch-up poll (a GSN bump in a `0x06` advertisement triggers a single
  connect→read→disconnect). Both surface through the unchanged `events()` stream,
  deduplicated by `(iid, gsn)`.
- Best-effort connected GATT notify with no auto-reconnect; lazy
  operation-driven re-verify on the read path (`revive_if_stale`).
- Public API: `AdvertSource` trait, `Paired { accessory, pairing, broadcast }`
  from `pair()`, `connect(pairing, Option<BleBroadcastState>)`,
  `BleAccessory::{accessories, find, read, subscribe, events, watch_sleepy_events,
  enable_broadcasts, remove_pairing}`.

## 1.2.0 — 2026-06-13

Controller polish. `hap-model` and `hap-controller` bump to `1.2.0` (additive);
the other four crates are unchanged.

### `hap-model` 1.2.0

- `HapStatus` enum mapping the HAP per-characteristic status codes
  (`from_code`/`code`); `ModelError::hap_status()` interprets a
  `CharacteristicStatus` error (e.g. `-70405` → `ReadFromWriteOnly`).

### `hap-controller` 1.2.0

- `AccessoryHandle::unsubscribe` — turn off event notifications for a
  characteristic (and stop the reconnect supervisor re-issuing it).
- `HapController::list_pairings` / `add_pairing` — inspect and add controllers
  on an accessory (multi-admin); re-exports `PairingInfo`.
- `HapController::identify` — pre-pairing `POST /identify` on an unpaired
  accessory (blink/beep before pairing).
- Configurable **per-request timeout** (default 10s, `set_request_timeout`): a
  foreground read/write on a silently-dropped link fails fast with
  `HapError::ConnectionLost` instead of hanging until TCP's own timeout.
- The reconnector now reads the accessory's config number (`c#`) on reconnect,
  so the cached attribute database refreshes when the configuration changes.
- Re-exports `HapStatus` from `hap-model`.

## 1.1.0 — 2026-06-13

Controller completeness. `hap-model`, `hap-controller`, and `hap-transport` bump
to `1.1.0` (all additive); `hap-tlv8`, `hap-crypto`, and `hap-pairing` stay at
`1.0.0`.

### `hap-transport` 1.1.0

- Adds `error_test_support` (`session_closed()`, `io_disconnected()`) so
  downstream crates can construct the `#[non_exhaustive]` `TransportError`
  variants in their tests, matching the existing `*_test_support` modules.

### `hap-model` 1.1.0

- Full HAP type catalog: 41 services and 127 characteristics (was 14 / 21),
  code-generated from aiohomekit's type tables.
- Value semantics on `CharacteristicType`: `unit()` (+ a new `Unit` enum),
  `valid_values()` (named enum values), alongside the existing `default_format()`.
- New `/characteristics` body builders: `build_prepare_request`,
  `build_timed_write_request`, `build_write_request_with_response`.
- **Fix:** `build_read_request` no longer requests `meta=1`. Some shipping
  HomeKit firmware (e.g. LIFX) returns malformed JSON for `meta=1` reads;
  metadata is now sourced from the well-formed `/accessories` database instead.

### `hap-controller` 1.1.0

- Batch I/O: `AccessoryHandle::read_many` / `write_many`. Read values are typed
  from the cached accessory database.
- Timed writes (`write_timed`, via `/prepare` + `pid`) and `write_with_response`
  (the HAP `r` flag).
- **Transparent auto-reconnect.** A dropped secure session is re-established by a
  background supervisor (indefinite backoff, capped); foreground ops wait a
  bounded window then return the new `HapError::ConnectionLost`. Subscriptions
  are re-issued after every reconnect; the cached DB is refreshed when a
  reconnect reports a changed config number. New
  `AccessoryHandle::connection_state()` exposes a `ConnectionState` stream.
- `SetupPayload::parse` decodes the `X-HM://` setup URI; new
  `HapError::InvalidSetupPayload`.
- Validated end-to-end against real LIFX hardware.

## 1.0.0 — 2026-06-12

First stable release. All six crates ship `1.0.0` together: `hap-tlv8`,
`hap-crypto`, `hap-transport`, `hap-pairing`, `hap-model`, and `hap-controller`.

`hap-rust` is the first production-grade pure-Rust HomeKit (HAP) **controller**
library. The headline crate, **`hap-controller`**, composes the lower crates
behind one ergonomic surface:

- `HapController` — `new`, `discover`, `pair`, `connect`, `paired`,
  `remove_pairing` over a `PairingStore` (`JsonFileStore` for persistence).
- `AccessoryHandle` — `accessories` (cached attribute DB), typed
  `find(ServiceType, CharacteristicType)`, `read`, `write`, `subscribe`, and
  `events()` (an async `Stream<CharacteristicEvent>`). Event values decode with
  the characteristic's declared format.
- `HapError` umbrella with `#[from]` conversions for every lower-crate error.
- Examples (`discover`, `pair_and_toggle`, `subscribe`), a crate README, and an
  `aiohomekit` → `hap-controller` migration guide.

Validated end-to-end against real hardware: discover → pair (SRP-6a Pair Setup +
Pair Verify) → read/write → subscribe/events → remove_pairing.

**Deferred past v1.0:** BLE transport, IP-camera streaming, MFi/hardware auth,
the resident-controller role, Thread/Matter bridging, `no_std`, the accessory
side, and HAP service/characteristic types beyond the common set.

## Workspace

### [Unreleased] — M0 foundation

- Public repository scaffolding: Cargo workspace with six `hap-*` crate
  skeletons (`hap-tlv8`, `hap-crypto`, `hap-transport`, `hap-pairing`,
  `hap-model`, `hap-controller`) plus the unpublished `xtask` automation crate.
- Shared `[workspace.package]` metadata and a deny/forbid lint policy
  (`unsafe_code = forbid`, `unwrap_used`, `expect_used`, `missing_errors_doc`,
  `missing_panics_doc`, `undocumented_unsafe_blocks`) every crate opts into.
- CI: `fmt`, `clippy -D warnings`, `test`, MSRV build, `rustdoc -D warnings`,
  `cargo audit`, `cargo deny`; plus a weekly fuzz workflow stub.
- README with the M0–M7 roadmap, `CONTRIBUTING.md`, `CLAUDE.md`, ADR 0001
  (workspace layout), and doc stubs (`spec-references`, `aiohomekit-comparison`,
  `tested-devices`).
- `test-vectors/` tree (`tlv8/`, `srp/`, `pair-verify/`, `session/`,
  `accessories/`) and the documented first `aiohomekit` TLV8 capture task.

## hap-pairing

### [0.1.0] — M5

First release: Pair Setup + Pair Verify orchestration over the real transport,
pairings management, and persistence. **First pure-Rust HomeKit controller pairs
a real accessory end to end.**

- `pair` — drives **Pair Setup** (SRP-6a, M1–M6) over a `HapConnection`,
  returning the accessory's `AccessoryPairing` (pairing id + LTPK) and a live
  `SecureSession`.
- `connect` — drives **Pair Verify** (X25519 + Ed25519, M1–M4) from a stored
  pairing, returning a fresh `SecureSession`.
- `PairingsAdmin` — `add` / `remove` / `list` over the `/pairings` endpoint of
  an established session (`PairingInfo`: id, LTPK, admin permission).
- `PairingStore` trait + `JsonFileStore` — persist the controller's long-term
  identity and its known accessories (`StoredAccessory`) across restart.
- `PairingError` — the crate's error type over the pairing/transport/crypto
  layers.
- `pair_accessory` example (the operator binary) and the
  `docs/runbooks/m5-first-pairing.md` first-pairing runbook.

### Additive changes in dependencies

- `hap-crypto`: `ControllerKeypair::seed()` plus `Clone` on the keypair, so the
  controller identity can be persisted and reloaded by `JsonFileStore`
  (additive, semver-minor).

## hap-transport

### [Unreleased] — M4

Initial implementation of the HAP IP transport (not yet published; the crate
stays at `0.0.0` until the workspace begins publishing).

- mDNS discovery of `_hap._tcp.local.` accessories with TXT-record parsing
  (`discover`, `DiscoveredAccessory`; `paired` derived from the `sf` flag).
- Minimal HAP HTTP/1.1 request encoder / response parser (`Content-Length` and
  `chunked` bodies; shared with the `EVENT/1.0` parser).
- ChaCha20-Poly1305 secure record layer (2-byte LE length AAD, 4-zero + 64-bit
  LE counter nonce, per-direction counters), cross-verified byte-for-byte
  against record frames captured from aiohomekit 3.2.20.
- `EVENT/1.0` notification demultiplexing onto an mpsc channel.
- `HapConnection` (plaintext, pre-session) and `SecureSession` (record-framed,
  post-Pair-Verify) over Tokio.

## hap-tlv8

_No releases yet. First release targets M1._
