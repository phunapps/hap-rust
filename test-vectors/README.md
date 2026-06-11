# Test vectors

Binary and JSON fixtures captured from `aiohomekit` (and, where they exist, the
HAP specification) that `hap-rust` crates verify themselves against
byte-for-byte. See `docs/aiohomekit-comparison.md` for the cross-verification
philosophy.

## Layout

```
tlv8/         M1 — TLV8 encode/decode cases (type byte, value, fragmentation)
srp/          M2 — SRP-6a intermediate values + Pair Setup M1–M6 messages
pair-verify/  M3 — X25519 / Ed25519 / session-key derivation
session/      M4 — ChaCha20-Poly1305 framed records
accessories/  M6 — sample /accessories and /characteristics JSON payloads
```

Each populated subdirectory carries a `manifest.toml` indexing its vectors. The
`.gitkeep` files keep empty subdirectories in the tree until their milestone
populates them.

## Capturing

Capture tooling lives under `xtask/scripts/<capture-name>/` and is driven by
`cargo xtask capture-<name>`. The first one — `capture-tlv8` — is documented in
`xtask/scripts/capture-tlv8/README.md` and ships its mechanics in M0; the wired
`cargo xtask capture-tlv8` subcommand and the captured bytes land in M1.
