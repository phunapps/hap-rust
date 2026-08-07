#!/usr/bin/env python3
"""Generate HAP-over-Thread (CoAP) cross-verification vectors from aiohomekit.

These pin the CoAP session record layer and event key of `hap-thread` (and
`hap_crypto::PairVerifyClient::event_key`) byte-for-byte against aiohomekit —
the project's correctness reference. Every value is deterministic given a
synthetic, non-secret X25519 shared secret (00..1f), so this is safe to commit.

Run with the capture venv that has aiohomekit + cryptography installed:

    xtask/scripts/capture-pair-setup/.venv/bin/python \
        test-vectors/thread-coap/gen_thread_vectors.py

It prints (and this file's sibling vectors.json records) the exact bytes the
Rust tests assert:
  - hap-crypto  pair_verify.rs::coap_session_keys_match_aiohomekit  (the 3 keys)
  - hap-thread  session.rs::seal_request_matches_aiohomekit_and_advances_counter
  - hap-thread  session.rs::open_response_decrypts_aiohomekit_ciphertext
  - hap-thread  session.rs::open_event_decrypts_aiohomekit_ciphertext
"""

import struct

from aiohomekit.crypto.hkdf import hkdf_derive
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

# Synthetic, non-secret X25519 shared secret.
SHARED = bytes(range(32))  # 00 01 02 .. 1f


def nonce(counter: int) -> bytes:
    # CoAP session nonce: 4 zero bytes then the 64-bit LE counter.
    return struct.pack("=4xQ", counter)


def main() -> None:
    read_key = hkdf_derive(SHARED, b"Control-Salt", b"Control-Read-Encryption-Key", 32)
    write_key = hkdf_derive(SHARED, b"Control-Salt", b"Control-Write-Encryption-Key", 32)
    event_key = hkdf_derive(SHARED, b"Event-Salt", b"Event-Read-Encryption-Key", 32)

    # Controller->accessory request (write key), a CharRead PDU, counters 0 and 1.
    req_pt = bytes([0x00, 0x03, 0x00, 0x01, 0x00, 0x00, 0x00])
    write_ct0 = ChaCha20Poly1305(write_key).encrypt(nonce(0), req_pt, b"")
    write_ct1 = ChaCha20Poly1305(write_key).encrypt(nonce(1), req_pt, b"")

    # Accessory->controller response (read key), a response PDU, counter 0.
    resp_pt = bytes([0x02, 0x00, 0x00, 0x01, 0x00, 0x2A])
    read_ct0 = ChaCha20Poly1305(read_key).encrypt(nonce(0), resp_pt, b"")

    # Accessory->controller event (event key): one record
    # [reserved=0][iid=0x000A LE][len=1 LE][body=0x01], counter 0.
    event_pt = bytes([0x00, 0x0A, 0x00, 0x01, 0x00, 0x01])
    event_ct0 = ChaCha20Poly1305(event_key).encrypt(nonce(0), event_pt, b"")

    for name, val in [
        ("shared_secret", SHARED),
        ("read_key", read_key),
        ("write_key", write_key),
        ("event_key", event_key),
        ("write_ct0", write_ct0),
        ("write_ct1", write_ct1),
        ("read_ct0", read_ct0),
        ("event_ct0", event_ct0),
    ]:
        print(f"{name} = {val.hex()}")


if __name__ == "__main__":
    main()
