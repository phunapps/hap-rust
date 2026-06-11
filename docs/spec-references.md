# HAP specification references

This document collects the specific specification sections and `aiohomekit`
modules we rely on, so we never have to hunt for "where is the source of truth
for X?".

The normative reference is the **HomeKit Accessory Protocol Specification
(Non-Commercial Version, Release R2)**, published by Apple and publicly
available. Citations below refer to that document unless noted otherwise; bump
the column when we adopt a later release.

| Topic                              | HAP spec §                | aiohomekit path                                       |
| ---------------------------------- | ------------------------- | ----------------------------------------------------- |
| TLV8 encoding                      | 14.1 (TLV8)               | `aiohomekit/protocol/tlv.py`                           |
| Pair Setup (SRP-6a)                | 5.6 (Pair Setup)          | `aiohomekit/protocol/__init__.py` (`perform_pair_setup`) |
| SRP-6a primitive (3072-bit, SHA-512)| 5.6 / RFC 5054           | `aiohomekit/crypto/srp.py`                             |
| Pair Verify (X25519 / Ed25519)     | 5.7 (Pair Verify)         | `aiohomekit/protocol/__init__.py` (`perform_pair_verify`) |
| Session security / record framing  | 6.5 (Session Security)    | `aiohomekit/controller/ip/connection.py`              |
| ChaCha20-Poly1305 record layer     | 6.5.2                     | `aiohomekit/crypto/chacha20poly1305.py`               |
| HAP HTTP / content types           | 6.3, 6.7                  | `aiohomekit/controller/ip/connection.py`              |
| EVENT notifications                 | 6.8 (Notifications)       | `aiohomekit/controller/ip/connection.py`              |
| mDNS `_hap._tcp` discovery + TXT    | 6.4 (Discovery)           | `aiohomekit/zeroconf.py`                               |
| Pairings management (`/pairings`)   | 5.10–5.12                 | `aiohomekit/protocol/__init__.py`                     |
| Accessory attribute database        | 6.6, 7 (Accessory Objects)| `aiohomekit/model/__init__.py`                        |
| Characteristic types / formats      | 9 (Characteristics)       | `aiohomekit/model/characteristics/`                   |
| Service types                       | 8 (Services)              | `aiohomekit/model/services/`                           |

## Conventions

- When a paragraph below uses "shall" / "may" / "should", it is quoting the HAP
  specification directly. Treat them with RFC 2119 semantics.
- `aiohomekit` is our primary cross-reference for protocol bytes. When our
  reading of the spec and `aiohomekit`'s behaviour disagree, capture both, file
  the divergence, and resolve it before writing code — see
  `docs/aiohomekit-comparison.md`.
- Open questions about spec interpretation belong in `docs/decisions/` as an
  ADR, not as inline comments.
