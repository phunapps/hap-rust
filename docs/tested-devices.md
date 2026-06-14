# Accessories tested against `hap-rust`

`CLAUDE.md` asks us to record which HomeKit accessories we have paired and
controlled. Fill a row each time you pair a real accessory end-to-end (from M5
onward) or control one (from M6 onward).

## Devices paired with hap-rust

Pair using the `pair_accessory` example; the full procedure (and how to fill a
row here) is in [`runbooks/m5-first-pairing.md`](runbooks/m5-first-pairing.md).

| Accessory (make/model) | Category | Setup | Date | aiohomekit cross-check | Notes |
|---|---|---|---|---|---|
| LIFX Clean (LIFX Z 6DCBC4) | Lightbulb (5) | IP, 8-digit code | 2026-06-12 | PASS — aiohomekit Pair-Verified with the controller identity hap-rust created and `list-pairings` reported it as admin; hap-rust `ListPairings` returns the identical pairing | **First pure-Rust HAP pairing.** Full M5 flow end-to-end: discover (`_hap._tcp`) → Pair Setup (SRP-6a M1–M6) → persist → Pair Verify (M1–M4) → SecureSession → ListPairings → 1 pairing (this controller, admin). Surfaced and fixed a real bug: `/pairings` is POST, not PUT (405 on PUT). |

**Deferred:** any BLE-only accessory — blocked on the BLE transport (post-v1.0).
HAP-IP accessories only for v1.0.

## Devices tested over BLE (`hap-ble`, Milestone A)

| Accessory (make/model) | Category | Date | Result |
|---|---|---|---|
| Onvis Smart Motion Sensor SMS2 | Sensor (10) | 2026-06-14 | **Pairing validated** — full Pair Setup + Pair Verify complete on the wire; post-pairing DB build not yet confirmed (device stability) |

**What validated on the real Onvis SMS2:**

- **BLE scan + HAP advertisement parsing** — manufacturer-data (company `0x004C`)
  parsed exactly: device id, category 10 (Sensor), GSN, `c#`, unpaired flag. (The
  Onvis rotates its advertised HAP device id between adverts; the CoreBluetooth
  peripheral UUID is stable, so match/connect by that.)
- **GATT connect + discovery** (14 services) and **Instance-ID descriptor
  resolution** for every characteristic (Pair-Setup `…004c`→iid 34, Pair-Verify
  `…004e`→iid 35, plus temp/humidity/motion/battery services).
- **Full Pair Setup (M1→M6) and Pair Verify (M1→M4) on the wire.** Trace: M1→read
  418 (M2 salt+pubkey), M3→read 104 (M4), M5→read 147 (M6); verify M1→read 147,
  M3→read 10 (M4). The SRP-6a + X25519/Ed25519 handshake from `hap-crypto` drives
  correctly over BLE.

**Three real HAP-BLE bugs found & fixed via an aiohomekit/bleak reference capture
of the same device** (`xtask/scripts/capture-pair-setup/ble_pair_capture.py`):

1. **Missing Return-Response param.** A Characteristic-Write over BLE must include
   HAP-Param Return-Response (`0x09`=1) before the Value param, or the accessory
   replies with only a status (the bare `02 01 00` we saw) and never returns the
   body. This single missing TLV param blocked the entire handshake. (Not needed
   over IP, which is why Pair Setup worked there.)
2. **Fragment size.** PDUs must be fragmented to the ATT MTU (the Onvis negotiated
   ~290); our 512 produced an oversized single write that hung at M3. Now 180.
3. **Per-fragment encryption.** The secure session encrypts each fragment
   separately (plaintext fragmented then sealed), not the whole PDU once.

**Not yet confirmed end-to-end:** the post-pairing attribute-database build
(enumerate + encrypted signature reads). The Onvis drops the link during the
~40-read instance-ID descriptor sweep — a device connection-stability issue (it
advertises in brief bursts and is aggressive about dropping), not a protocol gap.
Needs a steadier BLE accessory or a reconnect/retry strategy to finish read +
events validation.
