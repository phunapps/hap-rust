# Changelog

All notable changes to crates in the `hap-rust` workspace.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Each crate is versioned independently. Sections below are grouped by crate; the
workspace-wide foundation work is tracked under "Workspace".

## 2.0.0 — Milestone B (unified controller)

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
