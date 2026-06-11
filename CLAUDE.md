# CLAUDE.md — hap-rust

> Read this entire file before writing a single line of code.
> Every decision here was made deliberately. Do not override without asking first.

---

## Project Identity

- **Name:** hap-rust
- **What it is:** A Rust implementation of the HomeKit Accessory Protocol (HAP),
  controller side.
- **License:** Apache 2.0 (permissive — this is a protocol library, not a product).
- **Goal:** Become the production-grade Rust library for building HomeKit
  controllers.
- **Repo:** Public on GitHub from day one.
- **Crates.io prefix:** `hap-*`.
- **Sibling project:** `matter-rust` — this project deliberately mirrors its
  structure, discipline, and milestone-per-publishable-crate model.

## What This Project Is Not

- Not a HAP accessory implementation — that's `hap-rs`. We are controller-side,
  which has no production-grade Rust library today. This is the gap we fill.
- Not a smart-home platform — that's WeaveHome, a separate project that will
  consume this library.
- Not a quick MVP. HAP pairing is a security-sensitive cryptographic protocol.
  Wrong code means broken pairings or leaked long-term keys.
- Not BLE. The Bluetooth LE transport is deferred past v1.0.

---

## Non-Negotiable Rules

- **Never implement cryptographic primitives.** AEAD (ChaCha20-Poly1305),
  HKDF-SHA512, SHA-512, Ed25519, and X25519 come from vetted crates; SRP-6a
  big-integer math from a vetted bigint crate. We implement *protocols*
  (SRP-6a Pair Setup, Pair Verify) on top. We do not implement the math.
- **Test vectors before code.** For every protocol piece, capture the expected
  inputs and outputs from `aiohomekit` (or the HAP spec) FIRST, save under
  `test-vectors/`, then write code that produces matching output,
  cross-verified byte-for-byte.
- **No `unwrap()` or `expect()` in library code.** Test code is fine with a
  documented justification.
- **`#![forbid(unsafe_code)]`** at every crate root (and `unsafe_code = forbid`
  in the workspace lint policy).
- **Every public type and function gets rustdoc.**
- **Semver discipline from day one.** Breaking → major, additive → minor, fix →
  patch. No exceptions.
- **Do not skip ahead in the milestone plan.** Each milestone validates the
  previous.

## Crypto verification — NO external review gate (divergence from matter-rust)

**This is the one place we deliberately diverge from `matter-rust`'s
discipline.** `matter-rust` gates every crypto-protocol release on external
cryptographic review. **`hap-rust` does not.** We develop and test the Pair
Setup / Pair Verify implementations ourselves. Correctness is established by:

1. Byte-for-byte cross-verification of every SRP-6a intermediate value
   (`k`, `x`, `A`, `B`, `S`, `M1`, `M2`) and every Pair Setup / Pair Verify
   message against captured `aiohomekit` traces and the HAP spec's SRP vectors.
2. Successful interoperable pairing and session establishment against multiple
   real accessories and against `aiohomekit` as the peer, in both directions.
3. Negative-path tests: wrong setup code, tampered signatures, replayed/altered
   records, and out-of-order pairing states must all be rejected.

**Residual risk, recorded explicitly:** self-review plus interop testing catches
functional and most protocol errors, but is weaker than expert cryptographic
review at catching subtle side-channel or constant-time issues. This is an
accepted, deliberate trade-off. It may be revisited before a 1.0 announcement.

---

## Language & Runtime

- Language: **Rust** (stable channel).
- MSRV: **1.85**. Revise upwards only when a dependency requires it; document the
  bump in a new ADR.
- Async: **Tokio** for the transport and controller layers; plain Rust below.
- Clippy lints enforced in CI (`-D warnings`):
  `unwrap_used`, `expect_used`, `missing_errors_doc`, `missing_panics_doc`,
  `undocumented_unsafe_blocks`, plus `clippy::pedantic`.
- `cargo audit` and `cargo deny` on every PR. `cargo-fuzz` weekly.

---

## Dependency Strategy

```
Crypto primitives (NEVER reimplement; provider chosen in M2):
  ring and/or RustCrypto      → ChaCha20-Poly1305, HKDF-SHA512, SHA-512,
                                Ed25519 (ed25519-dalek), X25519 (x25519-dalek)
  crypto-bigint / num-bigint  → SRP-6a modular exponentiation
Networking:
  tokio                       → async runtime (transport + controller layers)
  mdns-sd                     → _hap._tcp discovery
Encoding:
  thiserror                   → error types
  serde + serde_json          → /accessories and /characteristics JSON (hap-model)
  bitflags                    → HAP feature/permission flag sets
Testing:
  proptest                    → property tests (hap-tlv8)
  cargo-fuzz                  → fuzzing parsers
```

Pick one AEAD/hash provider and stick with it (start with `ring`, fall back to
RustCrypto for any primitive `ring` lacks). The wire format for pairing is TLV8,
not JSON — `serde_json` is only for the accessory data model. **Ask before
adding anything not on this list, especially crypto.** Crypto-primitive crates
are added to `[workspace.dependencies]` when `hap-crypto` (M2) lands.

---

## Architecture Principles

### Workspace structure

A single Cargo workspace at the repository root. Six `hap-*` member crates under
`crates/` plus `xtask/` (automation, unpublished). See ADR 0001
(`docs/decisions/0001-workspace-layout.md`).

```
crates/
  hap-tlv8/         M1 — TLV8 encode/decode + fragmentation
  hap-crypto/       M2, M3 — Pair Setup (SRP-6a), Pair Verify (X25519/Ed25519)
  hap-transport/    M4 — mDNS, HAP HTTP/1.1, record layer, events
  hap-pairing/      M5 — pairing state machines, pairings mgmt, persistence
  hap-model/        M6 — accessory/service/characteristic DB, HAP-defined types
  hap-controller/   M7 — high-level controller API (v1.0)
xtask/              codegen, vector capture, release helpers
```

### Crate independence

Each crate is usable on its own; dependencies flow strictly downward.

- `hap-tlv8` — zero `hap-*` dependencies.
- `hap-crypto` — depends on `hap-tlv8`.
- `hap-transport` — depends on `hap-crypto`, `hap-tlv8`.
- `hap-pairing` — depends on `hap-tlv8`, `hap-crypto`, `hap-transport`.
- `hap-model` — depends on `hap-tlv8` plus a JSON layer; otherwise standalone.
- `hap-controller` — depends on all of the above.

### No premature abstractions

Ship concrete types first. Trait abstractions emerge when a second
implementation appears, not before.

---

## How We Verify Correctness

`aiohomekit` (the Python controller behind Home Assistant) is the primary
cross-reference. For every protocol layer: capture binary inputs/outputs from
`aiohomekit` during a real operation, save under `test-vectors/`, implement the
Rust version, assert byte-for-byte equality. The HAP spec's SRP vectors are a
second, independent reference. `proptest` for `hap-tlv8` roundtrips; `cargo-fuzz`
for parsers of untrusted input; real-accessory testing from M5 onward, logged in
`docs/tested-devices.md`. **If Rust output diverges from `aiohomekit`, we are
wrong by default** — investigate before changing the test.

---

## Milestone Plan

Each milestone (from M1) produces a publishable crate and ends with
`cargo publish`. Even if work stops early, the ecosystem gains useful crates.

| M  | Crate            | Goal                                                                        |
| -- | ---------------- | --------------------------------------------------------------------------- |
| M0 | —                | Repo, workspace, CI, roadmap, first aiohomekit vector capture               |
| M1 | `hap-tlv8`       | TLV8 reader/writer, 255-byte fragmentation, separators; proptest + fuzz     |
| M2 | `hap-crypto` 0.1 | Pair Setup: SRP-6a (3072-bit, SHA-512), HKDF-SHA512, ChaCha20-Poly1305, Ed25519 |
| M3 | `hap-crypto` 0.2 | Pair Verify: X25519 ECDH, Ed25519 verify, session-key derivation            |
| M4 | `hap-transport`  | mDNS `_hap._tcp` discovery, HAP HTTP/1.1, record layer, EVENT notifications |
| M5 | `hap-pairing`    | Pair Setup + Pair Verify state machines, pairings mgmt. **First pairing.**  |
| M6 | `hap-model`      | Accessory/service/characteristic DB, read/write, HAP-defined types (codegen)|
| M7 | `hap-controller` | High-level controller API, subscriptions, examples. **v1.0.**               |

**M5 is the headline announcement milestone** — "first pure-Rust HomeKit
controller pairs a real accessory."

### How hap-rust differs from matter-rust

- **No certificate milestone.** HomeKit pairing exchanges raw Ed25519 public
  keys; there is no PKI / cert chain. `matter-rust`'s `matter-cert` milestone
  has no equivalent here.
- **No external crypto review gate** (see "Crypto verification" above).
- **Simpler data model.** The accessory DB is JSON over HTTP, not a TLV cluster
  tree, so `hap-model` is lighter than `matter-clusters`.
- Net: 8 milestones (M0–M7) vs. matter-rust's 9.

---

## What's Deferred Post-v1.0

BLE transport (GATT, HAP-BLE PDU fragmentation, BLE pairing); MFi / hardware
authentication; IP-camera streaming (RTP / SRTP); resident-controller behaviour;
Thread transport and Matter bridging; `no_std`; the accessory side; HAP-defined
service/characteristic types beyond the common set. These ship in 1.x.

---

## Commit & Communication

- Commit subject lines: lowercase, imperative, ≤ 72 chars. Body explains *why*.
- **Do not add `Co-Authored-By` trailers** — the repo git config records the
  author.
- README, CHANGELOG, and per-crate docs are kept current with every release.
- When asked "is this AI-generated": be honest — developed with significant AI
  assistance, every design decision made by a human, every line reviewed,
  conformance verified against `aiohomekit`. The code stands on its own merits.
