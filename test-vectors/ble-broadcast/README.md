# HAP-BLE broadcast-notification test vectors

Cross-verification vectors for the `hap-crypto` `BroadcastKey` (HAP-BLE encrypted
broadcast notifications). Captured/derived from **aiohomekit** — the project's
correctness reference — on 2026-06-15 against a real Onvis SMS2.

## Files

- **`derive.json`** — `HKDF-SHA512(ikm, salt, info="Broadcast-Encryption-Key")`.
  Synthetic non-secret `ikm`/`salt` run through aiohomekit's `hkdf_derive`, so it
  is safe to commit. Verifies `BroadcastKey::derive` produces the same key bytes.
  On a real device the inputs are `ikm` = the Pair-Verify X25519 shared secret,
  `salt` = the controller LTPK (confirmed live; see "live evidence" below).
- **`open.json`** — a ChaCha20-Poly1305 **partial-tag (4-byte)** decryption vector.
  Built with aiohomekit's `ChaCha20Poly1305Encryptor` (full encrypt) truncated to
  the 4-byte broadcast tag, then round-tripped through aiohomekit's
  `ChaCha20Poly1305PartialTag.open`. `nonce = PACK_NONCE(gsn) = [0,0,0,0] ++
  gsn_u64_le`; AAD = the 6-byte advertising id; `combined_text = ciphertext ||
  tag[:4]`. Verifies `BroadcastKey::open`.
- **`generate-key-pdu.json`** — the real generate-broadcast-key request PDU
  (`OpCode::PROTOCOL_CONFIG = 0x08`, body `[0x01,0x00]` = GenerateBroadcastEncryptionKey,
  to the Service-Signature characteristic). No secrets.

## Live evidence (not committed)

`broadcast_capture.py` paired a real Onvis SMS2, ran the generate-broadcast-key
exchange, and derived the device's actual broadcast key — confirming the
algorithm (info string, ikm/salt ordering) end-to-end. That real key + LTPK are
kept locally in `derive.live.local.json` (gitignored via `*.local.json`) and are
**not** committed, since the repo is public. The live encrypted-broadcast (`0x11`)
advert is captured during hardware validation (the device only broadcasts while
disconnected); the `open.json` partial-tag math is validated here in CI.

## Regenerating

```bash
xtask/scripts/capture-pair-setup/.venv/bin/python \
  xtask/scripts/capture-pair-setup/gen_broadcast_vectors.py        # derive.json + open.json
# Live capture (hardware): broadcast_capture.py <setup-code> Onvis  # generate-key-pdu.json + live evidence
```
