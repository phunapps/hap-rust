# Session record-layer vectors

Byte-exact HAP secure-session **record frames**, used to cross-verify
`hap-transport`'s record layer (M4) against an independent implementation.

## What these are

After Pair Verify, every HTTP byte of a HAP IP session is carried inside record
frames. One plaintext block (≤ 1024 bytes) becomes:

```text
[ 2-byte LE length ][ ChaCha20-Poly1305 ciphertext ][ 16-byte Poly1305 tag ]
```

- The **2-byte little-endian length** prefix is also the AEAD **AAD**.
- The **nonce** is `PACK_NONCE(counter)` = 4 zero bytes followed by the 64-bit
  little-endian frame counter; counters are per-direction and increment by one
  per frame.
- `write`/`c2a` key encrypts controller→accessory; `read`/`a2c` key decrypts
  accessory→controller.

## Provenance — generated, not hand-written

Produced by [`xtask/scripts/capture-session/capture_session.py`](../../xtask/scripts/capture-session/capture_session.py)
using **aiohomekit 3.2.20** (cryptography 48.0.1) as the oracle. The script
drives aiohomekit's own framing primitives directly:

- `aiohomekit.crypto.chacha20poly1305.ChaCha20Poly1305Encryptor` / `Decryptor`
- `PACK_NONCE = partial(Struct("<LQ").pack, 0)`
- the 2-byte LE length prefix used as AAD,

reproducing `SecureHomeKitProtocol.send_bytes` in
`aiohomekit/controller/ip/connection.py` exactly. **No ciphertext in this
directory was written by hand** — it all comes from aiohomekit.

## No real secrets

The keys are **synthetic test keys** (`00..1f`, `20..3f`, `a5..`), not real
session keys. They exist only to pin the framing / nonce / AAD construction, so
there is no secret to leak and no live pairing is required. This is a
cross-implementation framing check, complementing the RFC 8439 AEAD vectors that
already prove the underlying cipher in `hap-crypto`.

To regenerate:

```bash
xtask/scripts/capture-pair-setup/.venv/bin/python \
    xtask/scripts/capture-session/capture_session.py
```

## Manifest

`manifest.json` lists every frame: `id`, `direction`, `key_hex`, `counter`,
`plaintext_file`, `frame_file`, and the plaintext/frame byte lengths.

| id | dir | counter | covers |
| -- | --- | ------- | ------ |
| `c2a-getaccessories-req-0` | c→a | 0 | a `GET /accessories` request block |
| `c2a-putcharacteristics-req-1` | c→a | 1 | counter increment, same direction |
| `a2c-accessories-resp-0` | a→c | 0 | a `200` JSON response block |
| `a2c-nocontent-resp-1` | a→c | 1 | a `204` response, a→c counter 1 |
| `a2c-event-0` | a→c | 5 | an `EVENT/1.0` push (for the M4 demux test) |
| `c2a-largemsg-block-0` | c→a | 0 | a full 1024-byte block (split boundary) |
| `c2a-largemsg-block-1` | c→a | 1 | the 476-byte continuation block |
| `c2a-empty-0` | c→a | 7 | a zero-length block (18-byte frame) |

See also [`docs/aiohomekit-comparison.md`](../../docs/aiohomekit-comparison.md).
