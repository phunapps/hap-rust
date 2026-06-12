# Runbook: pair a real accessory end to end with `hap-rust` (M5)

**Milestone:** M5 (`hap-pairing` 0.1 — Pair Setup + Pair Verify orchestration,
pairings management, persistence).
**Goal:** drive a full, real HomeKit pairing from pure Rust — discover an
accessory, run Pair Setup (SRP-6a M1–M6) and Pair Verify (M1–M4), persist the
pairing, and prove the resulting secure session by listing the accessory's
pairings. This is the headline M5 milestone: *first pure-Rust HomeKit controller
pairs a real accessory.*

You (the operator, on your LAN) run this. It needs real hardware. Read the whole
runbook once before starting. The operator binary is the `pair_accessory`
example at `crates/hap-pairing/examples/pair_accessory.rs`.

---

## What you need

- A Mac/Linux machine on the **same LAN / Wi-Fi (same L2 segment)** as the
  accessory — mDNS does not cross subnets/VLANs.
- An **UNPAIRED HomeKit IP accessory** (see "Prepare the accessory"). HAP grants
  exactly one *admin* pairing; an accessory already in Apple Home will reject a
  new Pair Setup, so it must be removed from Apple Home first. Good first
  targets from `docs/tested-devices.md`: a LIFX bulb (preferred), an Eve Energy
  plug.
- The accessory's **8-digit HomeKit setup code**, formatted `XXX-XX-XXX`. Find
  it on the device itself, on its HomeKit setup label/sticker, on the box, or in
  the vendor app's "Add to Apple Home" screen. **This code is a secret — never
  commit it or paste it into a tracked file.**

---

## Prepare the accessory (must be unpaired)

HomeKit accessories accept exactly one admin controller pairing. If the
accessory is already in Apple Home, Pair Setup fails with a Busy /
already-paired error (`kTLVError_Busy`, `0x07`). Get it to a clean state:

1. **If it is in Apple Home:** open the Home app → long-press the accessory →
   Settings (gear) → scroll down → **Remove Accessory**. This frees the HomeKit
   pairing.
2. **If you cannot remove it cleanly (or are unsure):** factory reset the
   accessory per its manual (e.g. most LIFX bulbs: toggle power off/on 5 times).
3. After removal/reset the accessory re-advertises on `_hap._tcp` as unpaired
   (status flag `sf=1`). Keep it powered on and on your network.

---

## Run

The setup code is a secret; it is passed on the command line here for brevity,
so prefer a private shell and clear your history afterward (or wrap it so it is
not logged). From the repo root:

```bash
cd /Users/hemanshubhojak/code/hap-rust

# discover + pick by name (case-insensitive substring of the advertised name):
cargo run -p hap-pairing --example pair_accessory -- \
  --code XXX-XX-XXX --name "Living Room Plug"
```

With no `--name`, the example pairs the **first unpaired** accessory it
discovers. Useful variants:

```bash
# skip discovery and connect to a known address (host:port):
cargo run -p hap-pairing --example pair_accessory -- \
  --code XXX-XX-XXX --addr 192.0.2.10:51826

# choose where the controller identity + pairings are stored, and the
# controller's own pairing id (defaults: controller.json, hap-rust-controller):
cargo run -p hap-pairing --example pair_accessory -- \
  --code XXX-XX-XXX --name "Eve Energy" \
  --store my-controller.json --controller-id my-mac
```

`cargo run -p hap-pairing --example pair_accessory -- --help` prints the full
flag list and exits — no device needed.

---

## What happens

1. **Controller identity.** The example opens the `--store` JSON file
   (`controller.json` by default). If it holds a controller, that long-term
   [`ControllerKeypair`] is loaded; otherwise a fresh one is generated (Ed25519
   seed + pairing id) and saved immediately.
2. **Discovery.** Unless `--addr` is given, it browses `_hap._tcp` for 5s and
   selects the accessory matching `--name`, or the first unpaired one.
3. **Connect.** It opens a plaintext (pre-session) `HapConnection` to the
   accessory's address.
4. **Pair Setup — SRP-6a, M1–M6** over `/pair-setup`: start request,
   SRP key exchange (3072-bit, SHA-512), proof verification, then the encrypted
   exchange of long-term keys. Yields the accessory's `AccessoryPairing`
   (its pairing id + Ed25519 LTPK).
5. **Persist.** The `StoredAccessory` (pairing + address) is written to the
   store, alongside the controller record.
6. **Pair Verify — M1–M4** over `/pair-verify`: X25519 ECDH + Ed25519 verify,
   deriving the session keys. Yields a live `SecureSession` (the
   ChaCha20-Poly1305 record layer).
7. **Prove the session.** `PairingsAdmin::list()` sends `ListPairings` over the
   secure session and prints what the accessory reports — which now includes
   this controller, with admin permission.

---

## Expected output

A successful run prints, in order: the controller identity that was loaded or
created; the selected accessory (name / id / addr); a connect line; the paired
accessory's pairing id + LTPK; a "saved pairing" line; and finally the
accessory's pairing list, e.g.:

```text
created new controller identity "hap-rust-controller" and saved to controller.json
selected accessory name="Living Room Plug" id="AE:EC:86:C0:BF:D7" addr=192.0.2.10:51826 paired=false
connected to 192.0.2.10:51826
paired: accessory pairing id "AE:EC:86:C0:BF:D7" (LTPK 3b4f...)
saved pairing for "AE:EC:86:C0:BF:D7" to controller.json
accessory reports 1 pairing(s):
  - id="hap-rust-controller" admin=true ltpk=...
done. first pure-Rust HomeKit pairing established end to end.
```

On disk, `controller.json` now holds **one controller record** (its pairing id +
seed) and **one accessory record** (the accessory's pairing id + LTPK + last
address). Re-running with the same store reuses the controller identity. Note
that re-pairing the *same* accessory again will fail unless it is unpaired
first — the accessory already holds this controller as an admin pairing.

---

## Cross-verification with `aiohomekit`

The byte-level crypto is already gated by the M2–M4 cross-checks against
captured `aiohomekit` traces, so this step confirms **orchestration +
persistence**, not the primitives:

1. Unpair the accessory from `hap-rust` (remove its admin pairing) and reset it
   to unpaired (see "Prepare the accessory").
2. Pair the same accessory with `aiohomekit` (the Python controller behind Home
   Assistant) and run its `list_pairings` / discovery.
3. Confirm `aiohomekit` reports an equivalent pairing (an admin controller
   pairing with a 32-byte LTPK) and the same accessory pairing id / category as
   `hap-rust` saw. Any divergence in the orchestration is a `hap-rust` bug by
   default (per `CLAUDE.md`).

---

## Troubleshooting

- **`Accessory(0x02)` (Authentication).** Wrong setup code. Re-read the 8-digit
  code; it is `XXX-XX-XXX`. The accessory may rate-limit after repeated wrong
  codes.
- **`Accessory(0x06)` (MaxTries).** Too many failed attempts — the accessory has
  locked Pair Setup. Power-cycle the accessory and retry with the correct code.
- **`Accessory(0x07)` (Busy / already paired).** The accessory already holds an
  admin pairing. Remove the existing pairing first (Apple Home → Remove
  Accessory, or factory reset), then re-check it advertises `sf=1`.
- **Discovery failures (no accessory found).** Confirm the machine and accessory
  are on the same subnet/VLAN (mDNS does not cross subnets); disable Wi-Fi
  client isolation / AP isolation; ensure any mDNS reflector is forwarding
  `_hap._tcp`. Use `--addr host:port` to bypass discovery entirely.
- **`Crypto` error on verify.** A stale or revoked pairing in the store — the
  accessory no longer recognizes the persisted pairing (it was removed/reset on
  the accessory side). Delete the accessory record from the store (or use a
  fresh `--store`) and run a clean Pair Setup again.

---

## Recording the result

Fill a row in [`docs/tested-devices.md`](../tested-devices.md): the accessory
make/model, its HAP category, the setup-code source, the date, whether the
`aiohomekit` cross-check passed, and any notes (firmware, quirks). Do not record
the setup code itself.
