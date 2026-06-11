# ADR 0001: Cargo workspace layout

- **Status:** accepted
- **Date:** 2026-06-12
- **Milestone:** 0

## Context

`hap-rust` is a Rust controller-side implementation of the HomeKit Accessory
Protocol (HAP). The project is sequenced into eight milestones (M0–M7), each
(from M1 on) producing one publishable crate. We needed to choose how to lay the
workspace out before any code was written. The project deliberately mirrors its
sibling `matter-rust`'s structure and discipline (see that project's ADR 0001).

## Decision

A single Cargo workspace at the repository root, with each milestone's
deliverable as an independent member crate under `crates/`. Each crate is
independently versioned and independently publishable to crates.io.

```
crates/
  hap-tlv8/         Milestone 1
  hap-crypto/       Milestones 2, 3
  hap-transport/    Milestone 4
  hap-pairing/      Milestone 5
  hap-model/        Milestone 6
  hap-controller/   Milestone 7
xtask/              workspace automation (not published)
```

Supporting top-level directories:

```
test-vectors/   binary + JSON fixtures captured from aiohomekit / HAP spec
examples/       how to use the published crates
docs/           protocol notes, spec references, ADRs
.github/        CI workflows and PR template
```

Shared metadata (edition, MSRV, license, repository, lints) lives in
`[workspace.package]` and `[workspace.lints]` in the root `Cargo.toml`. Each
member crate inherits these via `field.workspace = true` and opts into the lint
policy with `[lints] workspace = true`.

## Alternatives considered

### One large crate with feature flags

Pattern: `hap` crate, `[features]` for `tlv8`, `crypto`, `transport`,
`controller`.

Rejected: feature flags would couple the release cadence of all layers, and
crypto changes would force version bumps on TLV8 consumers. We want the opposite
— small, sharply versioned crates. A consumer who only wants TLV8 should depend
on `hap-tlv8` alone.

### Separate repositories per crate

Pattern: `hap-rust/hap-tlv8`, `hap-rust/hap-crypto`, …

Rejected: cross-crate refactors (which we expect to do often pre-1.0) become
much harder with separate repos. Single workspace, multiple crates, gets us the
publishing independence without the workflow tax.

### Controller and accessory side in one workspace alongside `hap-rs`

Rejected: `hap-rs` is a separate project covering the accessory (device) side.
We are controller-only and do not fork it.

## Consequences

- Contributors run `cargo build` / `cargo test` at the workspace root, not per
  crate.
- Each crate gains its own `CHANGELOG.md` section once it ships its first
  release; the workspace `CHANGELOG.md` groups by crate.
- Internal cross-crate dependencies use `path` plus `version` so the same
  manifests work both in-tree and after publishing.
- Codegen for `hap-model`'s HAP-defined type tables and `aiohomekit` vector
  capture both live in `xtask`.

## Edition and MSRV

- Edition: `2021`.
- MSRV: `1.85`. Chosen as a recent-but-not-bleeding-edge stable floor. Revise
  upwards only when a concrete dependency need arises; document the bump and the
  reason in a new ADR.

## Divergence from matter-rust

`matter-rust` has an M2 `matter-cert` certificate milestone and gates crypto
releases on external review. `hap-rust` has **no certificate milestone** (HAP
exchanges raw Ed25519 public keys; there is no PKI) and **no external crypto
review gate** (see `CLAUDE.md` / the design spec). The workspace layout is
otherwise the same model.

## References

- `CLAUDE.md` "Workspace layout" section.
- `docs/superpowers/specs/2026-06-12-hap-rust-design.md`.
- `matter-rust` ADR 0001 (the model this mirrors).
- Cargo book, [Workspaces](https://doc.rust-lang.org/cargo/reference/workspaces.html).
