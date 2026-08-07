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

## Not yet captured (needs hardware)
A real `0x09` accessory-database body and a live event PUT can only be captured
from a commissioned device; the `0x09`→tree decode and the event server are
deferred until then (see the design doc and BRINGUP notes).
