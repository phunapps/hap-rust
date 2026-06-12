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
