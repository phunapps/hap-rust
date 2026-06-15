"""Generate secret-free, reference-accurate HAP broadcast test vectors using
aiohomekit's OWN crypto primitives (no hardware). These cross-verify the Rust
`hap-crypto` BroadcastKey against aiohomekit byte-for-byte.

- derive.json: HKDF-SHA512(ikm, salt, "Broadcast-Encryption-Key") via aiohomekit
  `hkdf_derive` — confirms our derive matches (info string + arg order). The
  live capture (broadcast_capture.py) confirmed, against a real Onvis, that the
  device's broadcast key derives as hkdf(ikm=pair-verify-shared-secret,
  salt=controller-LTPK, info="Broadcast-Encryption-Key"); this vector uses
  synthetic (non-secret) ikm/salt so it is safe to commit to a public repo.
- open.json: a ChaCha20-Poly1305 *partial-tag* (4-byte) decryption vector built
  with aiohomekit's `ChaCha20Poly1305Encryptor` (full encrypt) then truncated to
  the 4-byte broadcast tag and round-tripped through aiohomekit's
  `ChaCha20Poly1305PartialTag.open` to prove validity. nonce = PACK_NONCE(gsn).
"""
import json
import os

from aiohomekit.crypto.hkdf import hkdf_derive
from aiohomekit.crypto.chacha20poly1305 import (
    PACK_NONCE,
    ChaCha20Poly1305Encryptor,
    ChaCha20Poly1305PartialTag,
)

OUT = os.path.join(
    os.path.dirname(__file__), "..", "..", "..", "test-vectors", "ble-broadcast"
)
OUT = os.path.abspath(OUT)
os.makedirs(OUT, exist_ok=True)

BROADCAST_INFO = b"Broadcast-Encryption-Key"


def write(name, obj):
    path = os.path.join(OUT, name)
    with open(path, "w") as f:
        json.dump(obj, f, indent=2)
        f.write("\n")
    print(f"[WRITE] {path}")


def gen_derive():
    ikm = bytes([0x11] * 32)
    salt = bytes([0x22] * 32)
    key = hkdf_derive(ikm, salt, BROADCAST_INFO, length=32)
    write(
        "derive.json",
        {
            "_note": "synthetic non-secret inputs; verifies HKDF-SHA512 matches aiohomekit "
            "with info 'Broadcast-Encryption-Key'. Live Onvis derivation confirmed "
            "separately (broadcast_capture.py); real key kept local, not committed.",
            "ikm_hex": ikm.hex(),
            "salt_hex": salt.hex(),
            "info": BROADCAST_INFO.decode(),
            "key_hex": key.hex(),
        },
    )


def gen_open():
    key = bytes([0x33] * 32)
    gsn = 5
    aid = bytes([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF])
    # A plausible HAP broadcast plaintext (iid LE + value); any bytes round-trip.
    plaintext = bytes([0x02, 0x0C, 0x00, 0x01])
    nonce = PACK_NONCE(gsn)
    # Full ChaCha20-Poly1305 (16-byte tag), then truncate the tag to 4 bytes —
    # exactly what a HAP broadcast carries (ciphertext || tag[:4]).
    full = ChaCha20Poly1305Encryptor(key).encrypt(aid, nonce, plaintext)
    ciphertext, full_tag = full[:-16], full[-16:]
    combined = ciphertext + full_tag[:4]
    # Round-trip through aiohomekit's partial-tag open to guarantee validity.
    back = ChaCha20Poly1305PartialTag(key).open(nonce, combined, aid)
    assert back == plaintext, f"reference partial-tag round-trip failed: {back!r}"
    write(
        "open.json",
        {
            "_note": "synthetic non-secret vector built with aiohomekit's ChaCha20Poly1305 "
            "(full encrypt, 4-byte truncated tag) and verified via its "
            "ChaCha20Poly1305PartialTag.open. nonce=PACK_NONCE(gsn)=[0,0,0,0]+gsn_u64_le; "
            "AAD=advertising_id; combined_text=ciphertext||tag[:4].",
            "key_hex": key.hex(),
            "gsn": gsn,
            "advertising_id_hex": aid.hex(),
            "combined_text_hex": combined.hex(),
            "plaintext_hex": plaintext.hex(),
        },
    )


if __name__ == "__main__":
    gen_derive()
    gen_open()
    print("done.")
