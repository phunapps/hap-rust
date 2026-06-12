#!/usr/bin/env python3
"""Capture HAP secure-session record-layer frames from aiohomekit.

This emits the byte-exact ChaCha20-Poly1305 record frames that aiohomekit's IP
transport puts on the wire after Pair Verify, so `hap-transport`'s record layer
(M4) can be cross-verified byte-for-byte against an independent implementation.

It does NOT need a real accessory or a live pairing. The record layer is a pure
function of (directional key, per-direction counter, plaintext block); we drive
aiohomekit's *own* framing primitives directly:

  - `aiohomekit.crypto.chacha20poly1305.ChaCha20Poly1305Encryptor` / `Decryptor`
  - `PACK_NONCE = partial(Struct("<LQ").pack, 0)`  (4 zero bytes + 64-bit LE counter)
  - the 2-byte little-endian length prefix that aiohomekit uses as the AEAD AAD,
    reproduced exactly as `SecureHomeKitProtocol.send_bytes` does it:
        len_bytes = struct.pack("<H", len(block))
        frame     = len_bytes + encryptor.encrypt(len_bytes, PACK_NONCE(counter), block)

The keys here are SYNTHETIC test keys (00..1f, 20..3f, ...), not real session
keys, so the fixtures expose no secret whatsoever. Their only job is to pin the
framing/nonce/AAD construction. aiohomekit is the source of truth for the
ciphertext — this script never writes ciphertext by hand.

Run (from the repo root):
    xtask/scripts/capture-pair-setup/.venv/bin/python \
        xtask/scripts/capture-session/capture_session.py

Writes test-vectors/session/{manifest.json, *.plain.bin, *.frame.bin}.
"""

from __future__ import annotations

import json
import struct
from importlib.metadata import version
from pathlib import Path

from aiohomekit.crypto.chacha20poly1305 import (
    PACK_NONCE,
    ChaCha20Poly1305Decryptor,
    ChaCha20Poly1305Encryptor,
)

PACK_U16LE = struct.Struct("<H").pack
MAX_BLOCK = 1024

# Synthetic directional keys. write == controller->accessory (c2a),
# read == accessory->controller (a2c). Distinct, obviously-fake patterns.
WRITE_KEY = bytes(range(0x00, 0x20))          # 00 01 .. 1f
READ_KEY = bytes(range(0x20, 0x40))           # 20 21 .. 3f
STREAM_KEY = bytes((0xA5,)) * 32              # a5 a5 .. (for the multi-block message)

# Representative HAP plaintext payloads (knowable HTTP/EVENT bytes).
GET_ACCESSORIES = (
    b"GET /accessories HTTP/1.1\r\n"
    b"Content-Type: application/hap+json\r\n"
    b"Content-Length: 0\r\n\r\n"
)
PUT_CHARACTERISTICS = (
    b"PUT /characteristics HTTP/1.1\r\n"
    b"Content-Type: application/hap+json\r\n"
    b"Content-Length: 49\r\n\r\n"
    b'{"characteristics":[{"aid":1,"iid":9,"value":true}]}'[:49]
)
ACCESSORIES_200 = (
    b"HTTP/1.1 200 OK\r\n"
    b"Content-Type: application/hap+json\r\n"
    b"Content-Length: 22\r\n\r\n"
    b'{"accessories":[{"x":1}]}'[:22]
)
NO_CONTENT_204 = b"HTTP/1.1 204 No Content\r\n\r\n"
EVENT_PUSH = (
    b"EVENT/1.0 200 OK\r\n"
    b"Content-Type: application/hap+json\r\n"
    b"Content-Length: 30\r\n\r\n"
    b'{"characteristics":[{"value":1}]}'[:30]
)


def encrypt_frame(key: bytes, counter: int, block: bytes) -> bytes:
    """Reproduce aiohomekit `send_bytes`' per-block framing for one block."""
    assert len(block) <= MAX_BLOCK
    len_bytes = PACK_U16LE(len(block))
    enc = ChaCha20Poly1305Encryptor(key)
    return len_bytes + enc.encrypt(len_bytes, PACK_NONCE(counter), block)


def decrypt_frame(key: bytes, counter: int, frame: bytes) -> bytes:
    """Inverse, mirroring aiohomekit `data_received`, for a self-check."""
    block_len = struct.unpack("<H", frame[:2])[0]
    block_and_tag = frame[2 : 2 + block_len + 16]
    dec = ChaCha20Poly1305Decryptor(key)
    return dec.decrypt(frame[:2], PACK_NONCE(counter), bytes(block_and_tag))


def main() -> None:
    repo_root = Path(__file__).resolve().parents[3]
    out_dir = repo_root / "test-vectors" / "session"
    out_dir.mkdir(parents=True, exist_ok=True)

    # Build a >1024-byte payload to exercise the block split + counter increment.
    large = bytes((i * 37 + 11) & 0xFF for i in range(1500))
    large_block0 = large[:MAX_BLOCK]      # exactly 1024 -> counter 0
    large_block1 = large[MAX_BLOCK:]      # remaining 476 -> counter 1

    # (id, direction, key, counter, plaintext)
    specs = [
        ("c2a-getaccessories-req-0", "controller_to_accessory", WRITE_KEY, 0, GET_ACCESSORIES),
        ("c2a-putcharacteristics-req-1", "controller_to_accessory", WRITE_KEY, 1, PUT_CHARACTERISTICS),
        ("a2c-accessories-resp-0", "accessory_to_controller", READ_KEY, 0, ACCESSORIES_200),
        ("a2c-nocontent-resp-1", "accessory_to_controller", READ_KEY, 1, NO_CONTENT_204),
        ("a2c-event-0", "accessory_to_controller", READ_KEY, 5, EVENT_PUSH),
        ("c2a-largemsg-block-0", "controller_to_accessory", STREAM_KEY, 0, large_block0),
        ("c2a-largemsg-block-1", "controller_to_accessory", STREAM_KEY, 1, large_block1),
        ("c2a-empty-0", "controller_to_accessory", WRITE_KEY, 7, b""),
    ]

    frames = []
    for fid, direction, key, counter, plaintext in specs:
        frame = encrypt_frame(key, counter, plaintext)
        # Self-check: aiohomekit must decrypt its own frame back to the plaintext.
        assert decrypt_frame(key, counter, frame) == plaintext, fid

        plain_file = f"{fid}.plain.bin"
        frame_file = f"{fid}.frame.bin"
        (out_dir / plain_file).write_bytes(plaintext)
        (out_dir / frame_file).write_bytes(frame)
        frames.append(
            {
                "id": fid,
                "direction": direction,
                "key_hex": key.hex(),
                "counter": counter,
                "plaintext_len": len(plaintext),
                "frame_len": len(frame),
                "plaintext_file": plain_file,
                "frame_file": frame_file,
            }
        )

    manifest = {
        "source": (
            f"aiohomekit {version('aiohomekit')} "
            "(cryptography " f"{version('cryptography')}) — framing primitives "
            "ChaCha20Poly1305Encryptor + PACK_NONCE from "
            "aiohomekit.crypto.chacha20poly1305, reproducing "
            "SecureHomeKitProtocol.send_bytes (controller/ip/connection.py)"
        ),
        "captured": "2026-06-12",
        "note": (
            "Synthetic test keys (not real session keys); the keys only pin the "
            "framing. Each frame is one record block: 2-byte LE length (also the "
            "AEAD AAD) + ChaCha20-Poly1305 ciphertext + 16-byte tag. Nonce is "
            "PACK_NONCE(counter) = 4 zero bytes + 64-bit LE counter."
        ),
        "frames": frames,
    }
    (out_dir / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(f"wrote {len(frames)} frames + manifest.json to {out_dir}")
    for f in frames:
        print(f"  {f['id']:32} dir={f['direction']:24} ctr={f['counter']} "
              f"plain={f['plaintext_len']:>4} frame={f['frame_len']:>4}")


if __name__ == "__main__":
    main()
