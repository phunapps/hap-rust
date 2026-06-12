# Capturing a Pair Setup (SRP-6a) trace from aiohomekit (M2)

Goal: produce a real HAP **Pair Setup** trace — the M1..M6 TLV8 wire messages
plus the SRP-6a intermediate values — captured from `aiohomekit` pairing a real,
unpaired accessory, so the M2 `hap-crypto` crate can be cross-verified
byte-for-byte. Outputs land in:

- `test-vectors/pair-setup/` — the M1..M6 wire messages + `manifest.toml`
- `test-vectors/srp/` — the SRP intermediates + `manifest.toml`

The operator-facing, step-by-step guide (against a LIFX bulb) is
`docs/runbooks/m2-capture-pair-setup-lifx.md`. This file is the developer-facing
reference for the script itself.

## Prerequisites

```bash
python3 -m venv xtask/scripts/capture-pair-setup/.venv
xtask/scripts/capture-pair-setup/.venv/bin/pip install 'aiohomekit'
```

Pin the exact `aiohomekit` version actually installed into the runbook and the
commit message, so two contributors regenerating produce the same bytes. The
`.venv/` directory is git-ignored.

## Running

```bash
# Code is a SECRET: prefer the env var so it never lands in shell history.
export HAP_SETUP_CODE=XXX-XX-XXX
xtask/scripts/capture-pair-setup/.venv/bin/python \
  xtask/scripts/capture-pair-setup/capture_pair_setup.py \
  --device <hap-device-id>
```

`--dry-run` validates args and installs the instrumentation without pairing
(useful with no hardware to confirm the script + aiohomekit import cleanly).

## What it captures

- **Wire messages M1..M6 (must-have).** Captured at the TLV8 codec boundary
  (`aiohomekit.protocol.tlv.TLV.encode`/`.decode`), labelled by their
  `kTLVType_State` byte. Authoritative; independent of aiohomekit internals.
- **SRP intermediates (best-effort).** Extracted from `aiohomekit.crypto.srp`'s
  `SrpClient` via a monkeypatch on `get_session_key`. Attribute names have varied
  across aiohomekit versions; the script probes a list of likely names per value
  and records `unavailable` (omitting the file) when none match. To reach a value
  the probe misses, read the installed `aiohomekit/crypto/srp.py`, add the
  attribute name to the relevant tuple in `_install_srp_probe`, and note it.

## Secrets hygiene

- The **setup code** is never written to any output and is redacted from logs.
- `m5.bin`/`m6.bin` carry the encrypted LTPK exchange; `srp/{S,K,proof_*}.bin`
  are session/identity material. The script prints a "safe to commit vs.
  sensitive" table at the end of every run — review each `.bin` before committing.
- `test-vectors/srp/` and `test-vectors/pair-setup/` ship with only a `.gitkeep`
  until a reviewed capture populates them.

## Manifest schema

`test-vectors/pair-setup/manifest.toml` carries a `[messages]` table mapping
`m1`..`m6` to files plus one `[[message]]` per message with `id`, `file`, `role`.
`test-vectors/srp/manifest.toml` carries `group`/`hash`/`username` headers plus
one `[[vector]]` per intermediate (`srp-salt`, `srp-k`, `srp-x`, `srp-A`,
`srp-B`, `srp-u`, `srp-S`, `srp-K`, `srp-proof_m1`, `srp-proof_m2`) with `id`,
`intermediate`, `notes` (the derivation formula, text only), and `file`
(empty when unavailable). These mirror the conventions in
`test-vectors/tlv8/manifest.toml`.

## Wiring `cargo xtask capture-pair-setup`

`cargo xtask capture-pair-setup` prints a pointer to this README and the runbook
(it does not run the capture itself, which needs hardware on the operator's LAN),
mirroring how M0 stubbed `capture-tlv8`.
