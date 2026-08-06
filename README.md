# hap-rust

[![CI](https://github.com/phunapps/hap-rust/actions/workflows/ci.yml/badge.svg)](https://github.com/phunapps/hap-rust/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

A Rust implementation of the **HomeKit Accessory Protocol (HAP)** — controller side.

> Status: **Milestone B.** Core functionality is complete and published.
> See the [Changelog](CHANGELOG.md) and crates.io pages for release notes.

## What this is

`hap-rust` is a workspace of small, focused crates that together let a Rust
application act as a HomeKit **controller** — discovering accessories on the
local network, pairing with them, establishing secure sessions, and reading,
writing, and subscribing to their characteristics. It supports both the **IP
transport** (HTTP over TCP, accessories discovered via mDNS) and **Bluetooth LE**
(with the `ble` feature).

The Rust ecosystem already has [`hap-rs`](https://github.com/ewilken/hap-rs) for
the **accessory (device)** side. The controller side has no production-grade
Rust library today. That is the gap we are filling.

## What this is not

- Not a HAP accessory implementation — see `hap-rs`.
- Not a smart-home platform — this is a protocol library.
- Not a quick MVP. HAP pairing is a security-sensitive cryptographic protocol.
  Wrong code means broken pairings or leaked long-term keys. The project is
  paced for correctness, not speed.

## Workspace layout

```
hap-rust/
├── crates/
│   ├── hap-tlv8/          # M1 — TLV8 encode/decode + 255-byte fragmentation
│   ├── hap-crypto/        # M2, M3 — Pair Setup (SRP-6a), Pair Verify (X25519/Ed25519)
│   ├── hap-transport/     # M4 — mDNS, HAP HTTP/1.1, record layer, events
│   ├── hap-pairing/       # M5 — pairing state machines, pairings mgmt, persistence
│   ├── hap-model/         # M6 — accessory/service/characteristic DB, HAP-defined types
│   └── hap-controller/    # M7 — high-level controller API (v1.0)
├── test-vectors/          # binary + JSON fixtures captured from aiohomekit / HAP spec
├── examples/              # how to use the published crates
├── xtask/                 # codegen, vector capture, release helpers
└── docs/                  # protocol notes, spec references, ADRs
```

Each crate is independently versioned and independently publishable. A consumer
who only wants TLV8 decoding can depend on `hap-tlv8` without pulling in any of
the higher layers. Dependencies flow strictly downward: `hap-tlv8` has no
`hap-*` dependencies; `hap-controller` depends on all of the others.

## Roadmap

The work is sequenced so each milestone validates the previous. Each milestone
ends with a `cargo publish` to crates.io.

| Milestone | Crate                | Goal                                                                | Target  |
| --------- | -------------------- | ------------------------------------------------------------------- | ------- |
| M0        | —                    | Repo, workspace, CI, roadmap, first aiohomekit vector capture       | done    |
| M1        | `hap-tlv8`           | TLV8 reader/writer, 255-byte fragmentation, separators; proptest + fuzz | done    |
| M2        | `hap-crypto` v0.1    | Pair Setup: SRP-6a (3072-bit, SHA-512), HKDF-SHA512, ChaCha20-Poly1305, Ed25519 | done    |
| M3        | `hap-crypto` v0.2    | Pair Verify: X25519 ECDH, Ed25519 verify, session-key derivation    | done    |
| M4        | `hap-transport`      | mDNS `_hap._tcp` discovery, HAP HTTP/1.1, record layer, EVENT notifications | done    |
| M5        | `hap-pairing`        | Pair Setup + Pair Verify state machines, pairings mgmt. **First pairing.** | done    |
| M6        | `hap-model`          | Accessory/service/characteristic DB, read/write, HAP-defined types (codegen) | done    |
| M7        | `hap-controller`     | High-level controller API, subscriptions, examples. **v1.0.**       | done    |
| MB        | `hap-ble` + unified  | Unified IP+BLE controller API. **Milestone B.**                     | done    |

**M5 is the headline announcement milestone** — "first pure-Rust HomeKit
controller pairs a real accessory."

Features deferred past v1.0: MFi / hardware authentication,
IP-camera streaming (RTP / SRTP), resident-controller behaviour, Thread
transport, Matter bridging, `no_std`, the accessory side, and HAP-defined types
beyond the common set. These ship in 1.x.

## How we verify correctness

HAP is well-specified but full of edge cases. We do not trust our own reading of
the spec. For every protocol layer:

1. Capture binary inputs and outputs from
   [`aiohomekit`](https://github.com/Jc2k/aiohomekit) — the Python controller
   behind Home Assistant — running a real operation against a real accessory.
   Save them under `test-vectors/`.
2. Implement the Rust version.
3. Assert byte-for-byte equality with the captured `aiohomekit` output.

We also use:

- the HAP specification's SRP and other test vectors as a second, independent
  reference,
- [`proptest`](https://docs.rs/proptest) for `hap-tlv8` roundtrip properties,
- [`cargo-fuzz`](https://rust-fuzz.github.io/book/) for parsers of untrusted
  input (the TLV8 reader and the `/accessories` JSON parser),
- real HomeKit hardware from Milestone 5 onwards (logged in
  [`docs/tested-devices.md`](docs/tested-devices.md)).

If Rust output diverges from `aiohomekit`, **we are wrong by default**.
Investigate before changing the test.

## Cryptographic posture

- We do not implement cryptographic primitives. AEAD (ChaCha20-Poly1305),
  HKDF-SHA512, SHA-512, Ed25519, and X25519 come from vetted crates; SRP-6a
  big-integer math from a vetted bigint crate. We implement the HAP-defined
  **protocols** on top — SRP-6a Pair Setup, Pair Verify — not the math
  underneath.
- **Unlike its sibling `matter-rust`, this project does *not* gate crypto
  releases on external cryptographic review.** Correctness is established by
  byte-for-byte cross-verification against `aiohomekit` and the HAP spec
  vectors, interoperable pairing against real accessories, and negative-path
  tests. The residual risk (weaker than expert review at catching subtle
  side-channel issues) is an accepted, deliberate trade-off, recorded in
  [`CLAUDE.md`](CLAUDE.md) and the design spec. It can be revisited before a 1.0
  announcement.

## Positioning vs. other HomeKit libraries

| Project                | Language   | Side       | Notes                                                       |
| ---------------------- | ---------- | ---------- | ---------------------------------------------------------- |
| **hap-rust** (this)    | Rust       | Controller | The gap we fill — no production-grade Rust controller today |
| `hap-rs`               | Rust       | Accessory  | Device side; complementary, not competing                  |
| `aiohomekit`           | Python     | Controller | Production controller behind Home Assistant; our reference |
| `homekit_python`       | Python     | Controller | Older Python controller                                     |
| `HAP-python`           | Python     | Accessory  | Device side                                                 |

`aiohomekit` is our primary cross-reference for byte-level correctness; `hap-rs`
is the device-side counterpart we do not duplicate.

## Using the published crates

The high-level API is available in `hap-controller`:

```toml
[dependencies]
hap-controller = { version = "2.0", features = ["ble"] }
```

A complete example (discovering on both transports, pairing, and streaming
events):

```rust,ignore
use hap_controller::{Discovered, HapController, JsonFileStore};
use std::time::Duration;
use tokio_stream::StreamExt as _;

let mut controller = HapController::new(JsonFileStore::new("./homekit-pairings.json")).await?;
let found = controller.discover(Duration::from_secs(8)).await?;
let target = &found[0];  // IP or BLE
let mut handle = controller.pair(target, "123-45-678").await?;

let mut events = handle.events();
while let Some(ev) = events.next().await {
    println!("event: aid={} iid={} value={:?}", ev.aid, ev.iid, ev.value);
}
```

See [`crates/hap-controller/examples/unified_pair_and_read.rs`](crates/hap-controller/examples/unified_pair_and_read.rs)
for the full example.

To pair the exact accessory a scanned HomeKit setup QR points at, parse the
`X-HM://` URI with `SetupPayload::parse` and call
`HapController::pair_with_payload` — see
[`crates/hap-controller/examples/pair_from_qr.rs`](crates/hap-controller/examples/pair_from_qr.rs).

For a sleepy BLE sensor with only a stored pairing (no live connection, e.g.
after a reboot), `HapController::watch_sleepy` cold-arms it without a blocking
connect — see
[`crates/hap-controller/examples/sleepy_cold_arm.rs`](crates/hap-controller/examples/sleepy_cold_arm.rs).

## Pairing a real accessory

As of **M5**, the first pure-Rust HomeKit controller pairs a real accessory end
to end. The `pair_accessory` example discovers an accessory, runs Pair Setup
(SRP-6a M1–M6) and Pair Verify (M1–M4), persists the pairing, and proves the
secure session by listing the accessory's pairings:

```bash
cargo run -p hap-pairing --example pair_accessory -- --code XXX-XX-XXX --name "Living Room Plug"
```

The accessory must be unpaired (removed from Apple Home first). The full
end-to-end procedure — preparing the accessory, the variants (`--addr`,
`--store`), expected output, the `aiohomekit` cross-check, and troubleshooting —
is in [`docs/runbooks/m5-first-pairing.md`](docs/runbooks/m5-first-pairing.md).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). The short version:

- Any PR that changes protocol behaviour must include `aiohomekit` test vectors.
- No `unwrap()` or `expect()` in library code. Test code is fine with a comment
  justifying the assumption.
- `#![forbid(unsafe_code)]` at every crate root — this is a hard rule.

## License

[Apache 2.0](LICENSE).

## Was this written with AI help?

Yes. The maintainer used AI assistance throughout. Every design decision was
made by a human; every line was reviewed; correctness is verified against
`aiohomekit` and (where applicable) HAP spec test vectors. The code stands on
its own merits — read it.
