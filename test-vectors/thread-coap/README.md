# HAP-over-Thread (CoAP) test vectors

Cross-verification vectors for the `hap-thread` CoAP session record layer and the
CoAP event key, derived from **aiohomekit** (the project's correctness reference)
over a synthetic, non-secret X25519 shared secret `00..1f`. All values are
deterministic and safe to commit.

## Provenance
`gen_thread_vectors.py` runs aiohomekit's `hkdf_derive` (HKDF-SHA512) and the
`cryptography` `ChaCha20Poly1305` primitive with the CoAP nonce
`struct.pack("=4xQ", counter)` (4 zero bytes + u64 LE) and empty AAD — exactly
what `aiohomekit/controller/coap/connection.py` uses. Regenerate:

```bash
xtask/scripts/capture-pair-setup/.venv/bin/python \
    test-vectors/thread-coap/gen_thread_vectors.py
```

## Where they are asserted
- `crates/hap-crypto/src/pair_verify.rs::coap_session_keys_match_aiohomekit`
  — the three HKDF keys (control read/write + the Thread-only event key).
- `crates/hap-thread/src/session.rs`
  — `seal_request_matches_aiohomekit_and_advances_counter` (write key, empty AAD,
    counter nonce, counter advance), `open_response_decrypts_aiohomekit_ciphertext`
    (read key), `open_event_decrypts_aiohomekit_ciphertext` (event key).

## Captured from real hardware (2026-08-07)
`onvis-sms2-0x09.bin` — the **real `0x09` attribute-database body** (2737 bytes)
read from a commissioned Onvis SMS2 over Thread (the decrypted `ReadDatabase`
response body, PDU header stripped). The device returns the whole database as one
~2.7 KB IPv6-fragmented datagram, not Block2. This is the vector for the pending
`0x09`→`hap-model` tree decode; it is the accessory's public attribute structure
(services/characteristics), no secrets.

## Not yet captured (needs hardware)
A live event PUT (the accessory's encrypted `0x0B`-subscribed notification) — the
event server is being added; capture a real event body here when it lands.
