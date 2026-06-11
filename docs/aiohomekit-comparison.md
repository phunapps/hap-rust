# aiohomekit comparison notes

[`aiohomekit`](https://github.com/Jc2k/aiohomekit) is the production-grade
HomeKit controller behind Home Assistant. It is our primary cross-reference for
byte-level correctness. This document records how `hap-rust`'s shape differs
from `aiohomekit`, so that contributors moving between the two understand why.

## High-level shape

| Aspect              | aiohomekit                             | hap-rust                                                 |
| ------------------- | -------------------------------------- | ------------------------------------------------------- |
| Language            | Python                                 | Rust                                                    |
| Runtime             | asyncio                                | Tokio (transport + controller layers); plain Rust below |
| Crypto primitives   | `cryptography`, `pyflakes`-checked SRP | vetted Rust crates (selected in M2)                     |
| Distribution        | Single PyPI package (`aiohomekit`)     | Many small crates, independently versioned             |
| Wire format         | TLV8 (pairing) + JSON (model)          | TLV8 (`hap-tlv8`) + JSON (`hap-model`)                  |
| Type tables         | Python dicts / generated metadata      | Generated at build time by `xtask` codegen             |
| Async style         | coroutines, callbacks                  | `async fn`, `Stream`, `tokio::sync` channels           |

## How we cross-verify

For every protocol piece, the workflow is:

1. Instrument `aiohomekit` during a real operation against a real accessory
   (or against `aiohomekit` acting as the peer in both directions).
2. Capture the binary messages at the boundary — TLV8 payloads, SRP-6a
   intermediate values, Pair Verify keys, framed records, `/accessories` JSON.
3. Save them under `test-vectors/` with a manifest describing each.
4. Implement the Rust version and assert byte-for-byte equality.

If `hap-rust` produces different bytes than `aiohomekit` for the same input,
**`hap-rust` is wrong by default** and we investigate. Add the divergence as a
test vector, then fix the Rust side. The exception is a genuine `aiohomekit`
bug — in that case we cite the HAP spec, record the finding here, and report it
upstream.

## Where we will diverge on ergonomics

- Error types are typed enums (`thiserror`), not Python exceptions.
- Streams of characteristic events are `impl Stream`, not callbacks.
- Subscriptions are explicit handles with `Drop` cancelling the subscription.

These are language-idiomatic differences. They do not affect interop.

## Crypto review divergence (vs. matter-rust)

`hap-rust`'s sibling project `matter-rust` gates every crypto-protocol release
on external cryptographic review. **`hap-rust` does not.** Correctness for Pair
Setup / Pair Verify rests on byte-for-byte cross-verification against
`aiohomekit` and the HAP spec's SRP vectors, interop pairing against real
accessories, and negative-path tests. This is a deliberate, recorded trade-off
(see `CLAUDE.md`). It raises the bar on how thorough the `aiohomekit`
cross-verification has to be — hence this document.
