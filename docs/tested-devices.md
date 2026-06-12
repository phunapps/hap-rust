# Accessories tested against `hap-rust`

`CLAUDE.md` asks us to record which HomeKit accessories we have paired and
controlled. Fill a row each time you pair a real accessory end-to-end (from M5
onward) or control one (from M6 onward).

## Devices paired with hap-rust

Pair using the `pair_accessory` example; the full procedure (and how to fill a
row here) is in [`runbooks/m5-first-pairing.md`](runbooks/m5-first-pairing.md).

| Accessory (make/model) | Category | Setup | Date | aiohomekit cross-check | Notes |
|---|---|---|---|---|---|
| _pending first run_ | — | — | — | — | To be filled when hardware is run. M5 flow: discover (`_hap._tcp`) → Pair Setup (SRP-6a M1–M6) → persist `controller.json` → Pair Verify (M1–M4) → SecureSession → ListPairings. |

**Deferred:** any BLE-only accessory — blocked on the BLE transport (post-v1.0).
HAP-IP accessories only for v1.0.
