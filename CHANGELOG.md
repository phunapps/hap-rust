# Changelog

All notable changes to crates in the `hap-rust` workspace.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Each crate is versioned independently. Sections below are grouped by crate; the
workspace-wide foundation work is tracked under "Workspace".

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
