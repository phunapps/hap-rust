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
| Onvis Smart Motion Sensor SMS2 | Sensor (10) | 2026-06-14 | **Partial** — discovery + GATT + Pair Setup M1 validated on the wire; M2 retrieval blocked (see below) |

**What validated on the real Onvis SMS2** (device id `a3:ca:fb:f0:db:7e`):

- **BLE scan + HAP advertisement parsing.** Raw manufacturer-data (company
  `0x004C`) `063101a3cafbf0db7e0a00010001029568b90d` parsed exactly: device id,
  category 10 (Sensor), GSN, config number `c#=1`, and the unpaired flag
  (status bit0 set). `parse_hap_advert` matches the device byte-for-byte.
- **GATT connect + service/characteristic discovery** (14 services).
- **HAP Instance-ID descriptor resolution.** Reading each characteristic's
  Instance-ID descriptor (`DC46F0FE-…`) returns real iids — e.g. Pair-Setup
  (`…004c`) → iid 34, Pair-Verify (`…004e`) → iid 35, plus the sensor services
  (temperature/humidity/motion/battery). `BtleplugConnection::{instance_id,
  enumerate}` work end-to-end.
- **Pair Setup M1 on the wire.** The framed write PDU
  `00 02 01 22 00 08 00 | 01 06 06 01 01 00 01 00` (CharWrite, tid 1, iid 34,
  value-param-wrapped `State=M1, Method=PairSetup`) is accepted — the accessory
  responds with a HAP response PDU, status `0x00` (success).

**Blocked: Pair Setup M2 retrieval.** The accessory's response to M1 is a bare
3-byte `02 01 00` (response, tid 1, status success) with **no body**, where M2
must carry the SRP salt + public key. A second read of the pairing
characteristic consistently triggers an immediate `Device disconnected`. This
Onvis also advertises only in brief bursts and drops the link within ~1 read,
making iteration slow. Root cause unresolved — needs a reference HAP-BLE
pairing capture (e.g. aiohomekit/bleak against the same device) to reconcile
the read-response semantics, and/or a less aggressively-sleepy BLE accessory.
The pairing crypto/PDU logic itself is CI-validated and reaches the wire
correctly; this is a transport-reconciliation gap, not a crypto gap.
