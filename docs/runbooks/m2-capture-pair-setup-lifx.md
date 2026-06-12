# Runbook: capture a Pair Setup (SRP-6a) trace from a LIFX bulb

**Milestone:** M2 (`hap-crypto` 0.1 — Pair Setup).
**Goal:** capture a real HAP Pair Setup trace (the M1..M6 TLV8 wire messages and
the SRP-6a intermediates) from `aiohomekit` pairing a LIFX bulb, so `hap-crypto`
can be cross-verified byte-for-byte.

You (the operator, on your LAN) run this. It needs real hardware. Read the whole
runbook once before starting. The capture script and its developer reference live
at `xtask/scripts/capture-pair-setup/`.

---

## What you need

- A Mac/Linux machine on the **same LAN / Wi-Fi** as the bulb, with Python 3.11+.
- A **LIFX bulb that is UNPAIRED / in HomeKit pairing mode** (see "Prepare the
  bulb" — a bulb already in Apple Home will reject pairing with a max-pairings
  error and must be removed first).
- The bulb's **8-digit HomeKit setup code**, formatted `XXX-XX-XXX`. Find it on
  the device itself, on the box/manual, or in the LIFX app under the device's
  HomeKit/"Add to Apple Home" screen. **This code is a secret — never commit it
  or paste it into a file.**

---

## Prepare the bulb (must be unpaired)

HomeKit accessories accept exactly one controller pairing (plus admin-added
ones). If the bulb is already in Apple Home, Pair Setup will fail with a
max-pairings / "already paired" error. Get it to a clean state:

1. **If it is in Apple Home:** open the Home app → long-press the bulb → Settings
   (gear) → scroll down → **Remove Accessory**. This frees the HomeKit pairing.
2. **If you cannot remove it cleanly (or are unsure):** factory reset the bulb.
   For most LIFX bulbs: toggle power off/on 5 times in a row (roughly 2s on, 2s
   off), and the bulb cycles colours to confirm the reset. Confirm the exact
   sequence for your model in the LIFX app or manual.
3. After removal/reset the bulb advertises itself again on `_hap._tcp` as
   unpaired (status flag "not paired"). Keep it powered on and on your network.

---

## Step 1 — Set up the Python venv

```bash
cd /Users/hemanshubhojak/code/hap-rust
python3 -m venv xtask/scripts/capture-pair-setup/.venv
xtask/scripts/capture-pair-setup/.venv/bin/pip install --upgrade pip
xtask/scripts/capture-pair-setup/.venv/bin/pip install 'aiohomekit'
```

Record the installed version (so a re-capture is reproducible):

```bash
xtask/scripts/capture-pair-setup/.venv/bin/pip show aiohomekit | grep -i version
```

Note that version in your commit message. The `.venv/` directory is git-ignored.

---

## Step 2 — Discover the bulb on `_hap._tcp`

Confirm the bulb is visible and grab its HAP device id:

```bash
# Browse the HomeKit service type. Either tool works:
dns-sd -B _hap._tcp           # macOS
# or:
avahi-browse -rt _hap._tcp    # Linux
```

Look for the LIFX bulb in the results. The device id you want is the accessory's
HAP id (the `id=` TXT field, an `XX:XX:XX:XX:XX:XX`-style string). The status
flag in the TXT record should indicate the accessory is **not yet paired**
(`sf=1`); `sf=0` means it is already paired — go back to "Prepare the bulb".

You can also let aiohomekit discover it for you; `--device <id>` is the reliable
selector.

---

## Step 3 — Run the capture

The setup code is a secret. Pass it via the env var so it stays out of shell
history and process listings:

```bash
cd /Users/hemanshubhojak/code/hap-rust
export HAP_SETUP_CODE=XXX-XX-XXX          # the bulb's real code; never commit it
xtask/scripts/capture-pair-setup/.venv/bin/python \
  xtask/scripts/capture-pair-setup/capture_pair_setup.py \
  --device <hap-device-id-from-step-2>
unset HAP_SETUP_CODE                       # clear it from the environment
```

The script:

1. Installs instrumentation (a TLV8-codec tee for the wire messages, and a
   best-effort SRP probe on aiohomekit's `SrpClient`).
2. Drives a full Pair Setup against the bulb.
3. Writes the outputs (Step 4) and prints a **"safe to commit vs. sensitive"**
   summary plus any warnings.

A clean run ends with "No warnings: all wire messages and SRP intermediates
captured." Missing any of M1..M6 is a hard failure (exit non-zero) — those are
the must-have fixtures; re-run against an unpaired bulb.

---

## Step 4 — Where the outputs land

```
test-vectors/pair-setup/
  m1.bin .. m6.bin        # the six TLV8 wire messages
  manifest.toml           # indexes each message by id + role
test-vectors/srp/
  salt.bin k.bin x.bin A.bin B.bin u.bin S.bin K.bin proof_m1.bin proof_m2.bin
  manifest.toml           # one [[vector]] per SRP intermediate (files omitted if unavailable)
```

SRP intermediates are best-effort: any value the probe could not extract from the
installed aiohomekit is recorded in `srp/manifest.toml` with an empty `file` and
an "unavailable" note. The M1..M6 wire messages are not best-effort — they must
all be present.

---

## Step 5 — Sanity-check the capture

```bash
# Six wire messages, each non-empty:
ls -l test-vectors/pair-setup/m?.bin

# Each message should carry its State byte (0x06 = kTLVType_State):
#   m1 -> ...06 01 01..., m2 -> ...06 01 02..., ... m6 -> ...06 01 06...
xxd test-vectors/pair-setup/m1.bin | head
xxd test-vectors/pair-setup/m2.bin | head   # also carries Salt + PublicKey(B)

# SRP salt should be 16 bytes; A and B should be 384 bytes (3072-bit group):
wc -c test-vectors/srp/salt.bin test-vectors/srp/A.bin test-vectors/srp/B.bin

# Manifests parse and reference real files:
cat test-vectors/pair-setup/manifest.toml
cat test-vectors/srp/manifest.toml
```

Spot-check that no file accidentally contains the setup code (it should not — the
script never writes it).

---

## Step 6 — What to commit vs. keep local/secret

The script prints this table; it is repeated here so you can decide before
`git add`:

**Safe to commit** (wire structure / public or derivable protocol bytes):

- `test-vectors/pair-setup/m1.bin .. m6.bin` and its `manifest.toml`
- `test-vectors/srp/{salt,k,x,A,B,u}.bin` and its `manifest.toml`

**Sensitive — review carefully before committing** (session/identity material):

- `test-vectors/srp/{S,K}.bin` (premaster secret, session key)
- `test-vectors/srp/{proof_m1,proof_m2}.bin` (SRP proofs)
- `m5.bin`/`m6.bin` carry the encrypted LTPK exchange

These come from a throwaway test bulb pairing, so committing them is acceptable
for cross-verification, but **review each `.bin` first** and never include
material from an accessory you care about.

**Never commit:**

- the 8-digit setup code (the script never writes it; do not add it by hand),
- any controller long-term private key.

If you choose to keep the sensitive files local only, leave the `.gitkeep` in
place and commit just the safe set; update the manifests accordingly.

Suggested commit (author is set by repo git config; **no `Co-Authored-By`
trailer**):

```bash
git add test-vectors/pair-setup test-vectors/srp
git commit -m "capture pair setup m1-m6 and srp intermediates from aiohomekit"
```

---

## What this validates

Once these fixtures exist, the M2 `hap-crypto` tests are wired to them:

- The `#[ignore]`d test **`hap_params_match_captured_trace`** cross-verifies the
  SHA-512 / 3072-bit SRP-6a intermediates (`k`, `x`, `A`, `B`, `u`, `S`, `K`, and
  the two proofs) against `test-vectors/srp/`.
- The later Pair Setup integration test (**`replays_captured_trace_end_to_end`**)
  replays the client and asserts the M1..M6 messages it produces equal
  `test-vectors/pair-setup/m1.bin .. m6.bin` byte-for-byte, down to the final
  accessory LTPK.

Per `CLAUDE.md`: if Rust output diverges from a fixture, the Rust code is wrong
by default — investigate the code, not the fixture.

---

## Troubleshooting

- **Bulb not discoverable (`_hap._tcp` empty / bulb absent).** Confirm the bulb
  and the machine are on the same subnet/VLAN (mDNS does not cross subnets).
  Power-cycle the bulb. Disable any Wi-Fi client isolation on the router.
  Re-run `dns-sd -B _hap._tcp`.
- **"already paired" / max-pairings / `sf=0`.** The bulb still holds a HomeKit
  pairing. Remove it from Apple Home, or factory reset it (see "Prepare the
  bulb"), then re-check the status flag is "not paired" (`sf=1`).
- **Wrong code / pairing rejected with an authentication error.** Re-read the
  8-digit code; it is `XXX-XX-XXX`. The script accepts it with or without dashes
  but must be exactly 8 digits. A repeatedly wrong code can make the accessory
  rate-limit or lock pairing for a while — wait, or power-cycle the bulb.
- **Script exits "missing wire messages".** Pair Setup did not complete (e.g.
  the bulb dropped off Wi-Fi, or it was already paired). Fix the bulb state and
  re-run; partial outputs from a failed run should be deleted before retrying.
- **SRP intermediates all "unavailable".** The installed aiohomekit uses
  attribute names the probe does not know. The wire messages are still valid.
  Read the installed `aiohomekit/crypto/srp.py`, add the right attribute names to
  the probe tuples in `capture_pair_setup.py` (`_install_srp_probe`), and re-run.
- **Import error for `aiohomekit.*`.** The aiohomekit API moved. The script's
  import guards name the exact module that failed; update that import and record
  the change.
