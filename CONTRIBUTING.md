# Contributing to hap-rust

Thank you for considering a contribution. This is a security-sensitive protocol
library — please read this whole document before opening a PR that touches code.

## Code of Conduct

This project follows the [Rust Code of Conduct](https://www.rust-lang.org/policies/code-of-conduct).
Be kind, be patient, assume good faith.

## Ground rules

1. **Correctness over speed.** HAP is a security protocol. A subtly wrong
   pairing implementation can break a pairing or leak a long-term key. We move
   slowly on purpose.
2. **No cryptographic primitives.** AEAD, HKDF, SHA-512, Ed25519, and X25519
   come from vetted crates; SRP-6a big-integer math from a vetted bigint crate.
   We implement protocols on top of those primitives, not the math underneath.
   If you find yourself implementing modular exponentiation by hand, stop.
3. **No `unwrap()` / `expect()` in library code.** Return `Result`. Test code
   may use them, but add a one-line comment explaining the invariant.
4. **`#![forbid(unsafe_code)]` at every crate root.** This is enforced by the
   workspace lint policy and is not negotiable.
5. **Test vectors before code.** For any protocol behaviour, capture the
   expected input/output from `aiohomekit` (or the HAP spec) first, save it
   under `test-vectors/`, then write Rust that produces matching output.
6. **Every public item gets rustdoc.** This is a library others will depend on.
7. **Semver from day one.** Breaking changes bump major. Additive changes bump
   minor. Bug fixes bump patch. No exceptions.

## What kinds of contributions are welcome

- Implementing planned milestone work (check the milestone tracking issue).
- Capturing `aiohomekit` test vectors for upcoming protocol pieces.
- Documentation: rustdoc gaps, `docs/spec-references.md`, ADRs.
- Bug fixes with a regression test.
- Reproducing and reporting interop issues with real HomeKit accessories.

Please **open an issue first** before starting work on:

- A new milestone or feature outside the published roadmap.
- An API change to an already-published crate.
- Any change to `hap-crypto` (Pair Setup / Pair Verify). Crypto changes need a
  matching `aiohomekit` / spec vector and careful sequencing with releases.

## Workflow

1. Open or comment on an issue describing the work.
2. Fork, branch, write code, write tests.
3. Run the full local check:
   ```
   cargo xtask check
   ```
   This runs every gate CI runs: `rustfmt --check`, `clippy -D warnings`,
   `cargo test`, and `cargo doc -D warnings`. See **Local toolchain** below for
   the optional `cargo-audit` / `cargo-deny` gates CI also runs.
4. Open a PR. Fill in the template completely.
5. Address review feedback. Expect at least one full reviewer pass on anything
   that touches protocol code.

## Local toolchain

`cargo xtask check` covers fmt, clippy, test, and doc. CI also runs
`cargo audit` and `cargo deny`. To run those two locally, install them once:

```
cargo install cargo-audit --locked
cargo install cargo-deny --locked
```

`rustfmt` and `clippy` ship with `rustup` and don't need separate installation.

## Crypto-touching changes

Any PR that modifies code inside `crates/hap-crypto/` — or anything that affects
the bytes on the wire during Pair Setup or Pair Verify — is subject to extra
rules:

- Label the PR `crypto`.
- Include the `aiohomekit` (and, where it exists, HAP spec) test vectors that
  prove the change is correct, cross-verified byte-for-byte.
- Add negative-path tests (wrong setup code, tampered signatures, replayed or
  altered records, out-of-order pairing states) where applicable.
- Do not change cryptographic primitives or their parameters without a written
  justification in the PR description.

> Note: unlike `matter-rust`, this project does **not** gate crypto releases on
> external cryptographic review. Correctness rests on cross-verification and
> interop testing. The trade-off is recorded in `CLAUDE.md`.

## Commit style

- One logical change per commit where practical.
- Subject line ≤ 72 chars, imperative mood, lowercase: `add tlv8 reader`.
- Body explains *why* the change is correct, not *what* it does (the diff
  already shows the what).
- Do **not** add `Co-Authored-By` trailers; the repository git config already
  records the author.

## Releasing

Releases are cut by the maintainer at the end of each milestone. The flow is:

1. Update `CHANGELOG.md` for the crate(s) being released.
2. Bump versions in the relevant `crates/*/Cargo.toml`.
3. Tag `<crate>-vX.Y.Z`.
4. `cargo publish` from a clean checkout of the tag.

### Release checklist

Inter-crate path dependencies are pinned `version = "0.0.0"` (a caret `^0.0.0`
requirement that matches only `0.0.0`). Before `cargo publish` of any crate:

- Bump BOTH the crate's own `version` AND the `version = ` field of every other
  crate that path-depends on it, in lockstep, so the published-version
  requirements resolve. (A crate published at, say, `0.1.0` cannot be depended
  on by an `= "0.0.0"` requirement.)
- Ensure each crate being published has a `README.md` in its crate directory —
  the `readme = "README.md"` manifest key requires the file to exist.

## Questions

Open a [Discussion](https://github.com/phunapps/hap-rust/discussions) for design
questions, an [Issue](https://github.com/phunapps/hap-rust/issues) for bugs and
tracked work.
