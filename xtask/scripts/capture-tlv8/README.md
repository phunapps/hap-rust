# Capturing TLV8 pairing vectors from aiohomekit (M1)

Goal: produce `test-vectors/tlv8/*.bin` plus a `manifest.toml` describing each
one, captured from `aiohomekit`'s TLV8 codec, so that the M1 `hap-tlv8` crate
can be verified byte-for-byte. Two sources of vectors:

- **Tier 1 — HAP spec §14.1 transcriptions.** Bytes are pre-declared from the
  spec; the script cross-checks each against `aiohomekit`'s codec output and
  aborts on any disagreement.
- **Tier 2 — real pairing payloads.** TLV8 buffers lifted from a real
  Pair Setup / Pair Verify exchange (`aiohomekit` instrumented during a pairing
  against a real accessory). These exercise multi-item structures and the
  255-byte **fragmentation** case that a synthetic transcription would not.

The Rust test harness that consumes `manifest.toml` ships with `hap-tlv8` in the
M1 implementation plan — it is out of scope here.

## Prerequisites

```bash
python3 -m venv xtask/scripts/capture-tlv8/.venv
xtask/scripts/capture-tlv8/.venv/bin/pip install 'aiohomekit==3.*'
```

Pin the exact `aiohomekit` version actually installed into this README and the
commit message, so two contributors regenerating produce identical bytes. The
`.venv/` directory is git-ignored (see `.gitignore`).

## Tier 1 — spec transcription cross-check (no hardware)

`capture_tlv8.py` carries a list of Tier-1 cases. Each declares a TLV8 item
list (type byte + value) and the expected encoded bytes from HAP spec §14.1. The
script encodes the same items through `aiohomekit.protocol.tlv.TLV` and asserts
equality before writing the `.bin`.

```bash
xtask/scripts/capture-tlv8/.venv/bin/python \
  xtask/scripts/capture-tlv8/capture_tlv8.py --tier1
```

Expected: writes the Tier-1 `.bin` files and a `manifest.toml`, printing
`tier-1: N vectors OK`. If `aiohomekit` disagrees with a spec-declared byte
string, the script exits non-zero and prints both — **do not** edit the expected
bytes to match `aiohomekit`; investigate (spec transcription typo vs. an
`aiohomekit` bug) and record the resolution.

## Tier 2 — real pairing capture (one accessory)

To capture fragmentation and real multi-item structures, instrument `aiohomekit`
during a real pairing. The hook point is `aiohomekit.protocol.tlv.TLV.decode`
(inbound) and `.encode` (outbound): wrap them so every TLV8 buffer crossing the
boundary is written to disk with a label.

```bash
# Put the accessory in pairing mode, then:
xtask/scripts/capture-tlv8/.venv/bin/python \
  xtask/scripts/capture-tlv8/capture_tlv8.py \
  --tier2 --device <accessory-id> --setup-code <8-digit-code>
```

The script monkey-patches the codec, performs Pair Setup + Pair Verify, and for
each TLV8 buffer writes a `.bin` and appends a manifest entry. The headline
target is a **fragmented** value: a `kTLVType_Certificate`/signature-style item
whose value exceeds 255 bytes, which HAP splits across consecutive items of the
same type. Capture at least one such buffer; it is the reason a real pairing is
required rather than synthetic data.

> Secrets hygiene: never commit a vector containing the setup code, the SRP
> password verifier, or a long-term secret key. Tier-2 vectors are post-encode
> TLV8 *structure* bytes (e.g. the public-key and proof items), not the raw
> secrets. Review each `.bin` before adding it.

## Manifest schema

`test-vectors/tlv8/manifest.toml` is an array of `[[vector]]` tables:

```toml
[[vector]]
id          = "0001-single-item-uint8"   # zero-padded sequence + slug
description = "Single TLV8 item: type 0x06 (State), value 0x01"
source      = "HAP spec R2 §14.1 (example)" # or "aiohomekit pair-setup M2 capture"
tier        = 1                            # 1 = spec transcription, 2 = aiohomekit capture
file        = "0001-single-item-uint8.bin" # bytes live alongside the manifest

# One [[vector.item]] per logical TLV8 item BEFORE fragmentation. The reader
# must reconstruct exactly these after de-fragmenting; the writer must produce
# `file`'s bytes from exactly these.
[[vector.item]]
type  = 0x06              # the 1-byte TLV8 type
value = "01"             # lowercase hex of the value bytes (post-defragmentation)

# Fragmentation cases set `fragmented = true` and carry a value > 255 bytes; the
# `.bin` then contains multiple wire items of the same `type`, but this manifest
# still lists the single logical item with its full concatenated value.
[[vector]]
id          = "0007-fragmented-300-bytes"
description = "Single item, type 0x09, 300-byte value (fragmented across 2 wire items)"
source      = "aiohomekit pair-setup M4 capture"
tier        = 2
file        = "0007-fragmented-300-bytes.bin"
fragmented  = true

[[vector.item]]
type  = 0x09
value = "00010203..."   # full 300-byte value as hex (the de-fragmented logical value)
```

The schema mirrors what the M1 Rust harness will deserialize: for each vector it
rebuilds the `item` list, encodes via `Tlv8Writer`, asserts the bytes equal
`file`, then decodes `file` via `Tlv8Reader` and asserts the de-fragmented items
equal the `item` list. The `fragmented` flag documents intent; the writer must
fragment automatically and the reader must concatenate automatically, so the
round-trip proves both directions.

## Wiring `cargo xtask capture-tlv8` (M1)

In M0 the `capture-tlv8` xtask subcommand is a stub that errors with a pointer to
this README. In M1 it is wired to shell out to this script (mirroring how
matter-rust's `cargo xtask capture-tlv` drives its Node capture script), and the
captured `.bin` files + `manifest.toml` are committed.
