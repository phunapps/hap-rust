# hap-rust — HAP-over-Thread roadmap

Remaining work to take the Thread transport (`hap-thread`) and its reference
accessory (`hap-thread-dut`) from "validated over UDP" to "validated over real
Thread against a real accessory, published." Each item below is a **self-contained
session spec** — hand one to a fresh session and it has the context to execute.

Do them **in order** (each builds on the previous). Everything lives on branch
**`thread-support`** (off `main`).

---

## Shared context (read first, every session)

**Crates**
- `crates/hap-thread` — the HAP-over-Thread **controller** (client). Speaks HAP
  PDUs over CoAP/UDP/IPv6. Reviewed twice; see `crates/hap-thread/BRINGUP.md`.
- `crates/hap-thread-dut` — the **reference accessory** (server / device-under-
  test). Lets the controller be driven end-to-end without Apple hardware. To be
  published as a DUT.
- `crates/hap-crypto` — all crypto. Controller-side Pair Setup/Verify clients,
  plus (added for the DUT) `SrpServer`, `PairVerifyClient::event_key`. The SRP
  module (`src/srp.rs`) is `pub(crate)`.

**Reference (the correctness oracle — cross-verify against it, per CLAUDE.md):**
aiohomekit, vendored at
`xtask/scripts/capture-pair-setup/.venv/lib/python3.14/site-packages/aiohomekit/`
— CoAP transport in `controller/coap/{connection,pairing,structs,pdu}.py`; BLE in
`controller/ble/`. Run its pure functions to capture byte-exact vectors.

**Design docs:** `docs/superpowers/specs/2026-08-07-hap-thread-design.md` (the
hap-thread design + open decisions D1–D6), `crates/hap-thread/BRINGUP.md`
(hardware findings F1/F2/F7), `test-vectors/thread-coap/` (session/key vectors +
capture script).

**What already works (over UDP, no hardware):** `hap-thread` ⇄ `hap-thread-dut`
complete **identify, Pair Verify (M1–M4), the encrypted session, and Lightbulb
`On` read/write** — see `crates/hap-thread-dut/tests/identify.rs`. Run
`cargo test -p hap-thread-dut` to confirm the baseline.

**The Pi test rig:** `admin@192.168.1.29` (passwordless sudo). OTBR is already
running (leader of Thread network `OpenThread-89d7`, channel 24; off-mesh prefix
`fdc8:45f:7f98:1::/64`). Thread radio (Nordic RCP) on `/dev/ttyACM0`; ESP32-C6 on
`/dev/ttyACM1`. Rust toolchain installed; repo cloned at `~/hap-rust`. No
espflash/esptool yet.

**House rules (CLAUDE.md):** no `unwrap`/`expect` in library code (tests exempt
with an `#[allow]`); `#![forbid(unsafe_code)]`; rustdoc on public items; clippy
pedantic `-D warnings`; test-vectors captured from aiohomekit before code; strict
semver. No `Co-Authored-By` trailers.

---

## Item 1 — Finish the Pair Setup (SRP) server in the DUT

**Goal:** `hap-thread`'s real `pair_setup` completes a full M1–M6 Pair Setup
against `hap-thread-dut` over CoAP, establishing a pairing (the DUT learns the
controller's LTPK; the controller learns the accessory's LTPK) that a subsequent
Pair Verify then uses — all over UDP, no hardware.

**Already done:** the SRP-6a **primitive** — `hap_crypto::srp::SrpServer`
(verifier, B, premaster, session key, verify-M1→M2), cross-validated against
`SrpClient` (`srp::tests::srp_client_and_server_agree_end_to_end`).

**Task:**
1. Expose the SRP server for the DUT. Recommended: a small **public** HAP-specific
   wrapper in `hap-crypto` (e.g. `pub struct HapPairSetupSrpServer`) hiding the
   generics/group — constructor `new(setup_code) -> (server, salt)`, methods
   `b_pub_bytes()`, `session_key(a_pub_bytes) -> Result<Vec<u8>>`,
   `verify_m1_prove_m2(a_pub_bytes, m1) -> Result<Vec<u8>>`. Keep `srp` module
   `pub(crate)`; only the wrapper is public. (Additive → hap-crypto minor bump.)
2. Implement the **accessory M1–M6 state machine** in `hap-thread-dut`
   (`src/pairing.rs` — add `pair_setup` alongside the existing Pair Verify):
   - **M1→M2:** parse `{State=1, Method=0}`; reply `{State=2, Salt=s, PublicKey=B}`.
   - **M3→M4:** parse `{State=3, PublicKey=A, Proof=M1}`; compute the session key
     from `A`, verify `M1`, reply `{State=4, Proof=M2}` (or `{State=4, Error}`).
   - **M5→M6 (the LTPK exchange):** decrypt M5's `EncryptedData` under
     `HKDF(K, "Pair-Setup-Encrypt-Salt", "Pair-Setup-Encrypt-Info")` with nonce
     `PS-Msg05`; it holds `{Identifier=controllerID, PublicKey=controllerLTPK,
     Signature}`. Verify the controller signature over
     `iOSDeviceX ‖ controllerID ‖ controllerLTPK`, where
     `iOSDeviceX = HKDF(K, "Pair-Setup-Controller-Sign-Salt",
     "Pair-Setup-Controller-Sign-Info")`. **Store `(controllerID, controllerLTPK)`
     as the pairing** (call the existing `provision_controller`). Then build M6:
     sign `AccessoryX ‖ accessoryID ‖ accessoryLTPK`
     (`AccessoryX = HKDF(K, "Pair-Setup-Accessory-Sign-Salt",
     "Pair-Setup-Accessory-Sign-Info")`), encrypt `{Identifier, PublicKey,
     Signature}` with nonce `PS-Msg06`, reply `{State=6, EncryptedData}`.
   - Wire `PATH_PAIR_SETUP` (`"1"`) in `handle()` to this state machine (drop the
     current `4.04` stub). Hold M1/M3 progress in a `Mutex`, like Pair Verify.
3. **Cross-check (the whole point):** in `tests/identify.rs`, add a test that
   drives `hap_thread`'s `ThreadController::pair` (Pair Setup) against the DUT
   with a fixed setup code, asserts it returns an `AccessoryPairing`, and then
   `connect()`s (Pair Verify) with that pairing and reads the Lightbulb — a full
   **pair → verify → read** with nothing pre-provisioned.

**References:** mirror `hap_crypto::pair_setup::PairSetupClient` exactly (M5/M6
salts, info, nonces `PS-Msg05/06`, the `iOSDeviceX`/`AccessoryX` derivations, the
signed-message concatenation order) — it is the client this must interoperate
with. `aiohomekit/controller/coap/pairing.py::do_pair_setup*` shows the CoAP
framing.

**Acceptance:** the new pair→verify→read test passes; `cargo test -p
hap-thread-dut` and `cargo test -p hap-crypto` green; clippy `-D warnings` +
`cargo fmt --check` clean.

---

## Item 2 — Run it over real Thread

**Goal:** the DUT runs on the Thread mesh (via the Pi's OTBR) and `hap-thread`
drives it (identify → pair → verify → read/write `On`) over **actual Thread/IPv6**
— proving the real radio/transport path, not just loopback UDP.

**Prereq:** Item 1 (so full pairing works) — or run with `provision_controller`
if Item 1 isn't done yet. **Item 3's transport fixes are only needed if this
run surfaces them** (the DUT answers immediately with small payloads, so the
basic transport may already suffice for read/write; the `0x09` database — which
would need Block2 — is not implemented in the DUT, so it won't be exercised).

**Task:**
1. **Cross-compile the DUT for the Pi** (`aarch64-unknown-linux-gnu`) or build it
   natively on the Pi (`ssh admin@192.168.1.29`, the toolchain + `~/hap-rust` are
   there): `git fetch && checkout thread-support`, `cargo build --release -p
   hap-thread-dut`.
2. **Bind the DUT to a Thread-reachable address.** With OTBR, the Pi has a Thread
   interface; bind the accessory to the off-mesh-routable address (in
   `fdc8:45f:7f98:1::/64`) or `[::]:5683`. Run:
   `./target/release/hap-thread-dut '[<thread-addr>]:5683' AA:BB:CC:DD:EE:FF`.
   (Optionally add SRP registration so it appears under `_hap._udp`; otherwise
   address the controller at the known IPv6 directly and skip discovery.)
3. **Drive it from `hap-thread`.** Either write a tiny example binary
   (`crates/hap-thread/examples/thread_connect.rs`: discover or take an addr,
   pair/connect, read/write `On`) run on the Pi, or from the Mac if it routes to
   the mesh through the Pi border router. Confirm `On` read/write works over the
   radio.
4. Log results in `docs/tested-devices.md`.

**Acceptance:** identify + pair/verify + `On` read/write succeed against the DUT
over the Thread mesh (not loopback); a captured log shows the CoAP round-trips.
Note anything that broke (feeds Item 3).

---

## Item 3 — Harden `hap-thread`'s CoAP transport for real hardware

**Goal:** `UdpCoapTransport` survives what a real accessory (the Onvis) does that
the DUT doesn't. From the hap-thread final review (F1/F2/F7 in
`crates/hap-thread/BRINGUP.md`).

**Task:**
1. **F1 — CoAP separate responses / empty ACKs + token correlation.** A slow
   accessory sends an *empty ACK* (type=ACK, code `0.00`, same message-id) then a
   *separate CON* carrying the payload (new message-id, **same token**).
   `coap.rs::UdpCoapTransport::post` currently matches by message-id and returns
   the empty ACK → fails. Fix: set + match on the **token**; on an empty ACK keep
   waiting (don't retransmit) for the token's real response, ACK that separate
   CON, use its payload. (This also fixes F7's retransmit correlation.)
2. **F2 — Block2 reassembly (RFC 7959).** A large response (the `0x09` database)
   arrives block-wise; `coap-lite` does message-level only. Reassemble Block2
   blocks before handing the payload up (which then gets decrypted as one AEAD
   message). Raise/relax `RECV_BUF` as needed.
3. **Test both against the DUT.** Extend `hap-thread-dut` to *optionally* exhibit
   these behaviours behind a flag: a "slow" mode that empty-ACKs then sends a
   separate CON, and a "blockwise" mode that chunks a large response. Add
   `hap-thread` transport tests driving those.

**References:** `aiohomekit` gets both for free via `aiocoap`; RFC 7252 §5.2.2
(separate responses), RFC 7959 (Block2). `crates/hap-thread/BRINGUP.md`.

**Acceptance:** new transport tests for empty-ACK/separate-response and Block2
reassembly pass against the DUT's slow/blockwise modes; existing tests still
green; clippy/fmt clean.

---

## Item 4 — ESP32-C6 onboard LED as the physical Lightbulb

**Goal:** writing `On` through the DUT visibly toggles the C6's onboard LED — a
physical demo of the whole chain.

**Already done (Rust side):** `hap_thread_dut::SerialLedActuator` writes `b'1'`/
`b'0'` to a serial device; the bin takes a 3rd arg for the serial-LED path
(`hap-thread-dut '[::]:5683' <id> /dev/ttyACM1`).

**Task:**
1. **Flash a tiny firmware on the C6** (on `/dev/ttyACM1`) that reads one serial
   byte and sets its onboard addressable LED (WS2812 on GPIO8 for
   ESP32-C6-DevKitC): `'1'` → on, `'0'` → off. Options, easiest first:
   - **MicroPython:** flash the prebuilt ESP32-C6 MicroPython `.bin` with
     `esptool` (install in a venv on the Pi — PEP 668 blocks a bare `pip
     install`), then a ~10-line `main.py` (`sys.stdin` read → `neopixel`).
   - **Arduino / ESP-IDF / esp-hal:** a ~10-line sketch; heavier toolchain.
   Set up `esptool` on the Pi: `python3 -m venv ~/esptool-venv &&
   ~/esptool-venv/bin/pip install esptool`. Chip is on `/dev/ttyACM1`
   (USB-serial-JTAG).
2. **Demo:** run the DUT with `/dev/ttyACM1` as the actuator, drive `On` from
   `hap-thread`, watch the LED. (Note: only one process can hold the serial port —
   don't leave a REPL attached.)
3. Commit the C6 firmware/sketch under `crates/hap-thread-dut/firmware/esp32c6/`
   with a README (wiring, flash command).

**Acceptance:** `hap-thread` writing `On=true/false` toggles the physical LED.

---

## Item 5 — Final validation on the Onvis SMS2, then publish

**Goal:** confirm `hap-thread` works against a **real** HAP-over-Thread accessory,
then release.

**Prereq:** Items 1–3 (full pairing + hardened transport). The Onvis must be
**commissioned onto our Thread network** first — this is the real gap
(HomeKit Thread accessories receive their Thread credentials over BLE during
setup; if the Onvis is on Apple Home's Thread network we must re-provision it to
our OTBR). Scope the commissioning approach at the start of this session; it may
need a BLE Thread-credential write added to `hap-ble` (deferred design work).

**Task:**
1. Commission the SMS2 onto `OpenThread-89d7` (BLE credential provisioning or the
   OTBR commissioner).
2. Drive `hap-thread` against it: discover `_hap._udp`, pair, verify, read the
   `0x09` database (needs Item 3's Block2), read sensor characteristics.
3. Backfill the real `0x09` database body as a committed vector under
   `test-vectors/thread-coap/` and implement/verify the `0x09`→`hap-model` tree
   decode in `hap-thread` (deferred in MT-1; see design §11 / BRINGUP).
4. Log in `docs/tested-devices.md`.
5. **Publish** (user-gated, per repo policy): version-bump + CHANGELOG, verify
   full workspace + both clippy matrices + fmt, merge `thread-support` → `main`,
   publish `hap-crypto` (if bumped) → `hap-thread` → `hap-thread-dut`, tag.

**Acceptance:** a real read from the SMS2 over Thread; crates published; roadmap
items checked off.

---

## Status checklist
- [x] Item 1 — Pair Setup server (SRP primitive ✅; M1–M6 orchestration + M5/M6 ✅)
- [x] Item 2 — Run over real Thread (DUT ⇄ controller over the OMR mesh address on the Pi; radio-hop deferred to a separate node in Item 4/5)
- [x] Item 3 — Transport hardening (F1 separate-responses ✅, F2 Block2 ✅; token correlation covers F7)
- [x] Item 4 — ESP32-C6 LED firmware (MicroPython flashed; byte→LED path verified; DUT drives On→serial end-to-end — physical photons pending a visual confirm)
- [ ] Item 5 — Onvis validation + publish. **Hardware-validated on the real SMS2:** commission over BLE (`hap-ble` 0.7.0 `thread_provision`) → Pair Verify over Thread → **`0x09` database read (2737 bytes)** over the radio. Two transport bugs found + fixed: Block2 continuation framing (empty payload + fresh token) and the decisive one — the Onvis returns `0x09` as one ~2.7 KB IPv6-fragmented datagram, so `RECV_BUF` was raised 1500→16 KiB (truncation was the AEAD failure). Real `0x09` body committed as a vector. **Open:** events over Thread (`0x0B` subscribe + inbound CoAP event server — in progress), then `0x09` tree decode, sensor reads, and the **user-gated publish**. BLE runs on the Pi (macOS-26 `objc2` blocker on the Mac).
