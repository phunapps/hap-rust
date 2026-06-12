HomeKit Accessory Protocol (HAP) pairing cryptography: Pair Setup (SRP-6a with SHA-512, HKDF-SHA512, ChaCha20-Poly1305, Ed25519) and Pair Verify (X25519 ECDH, Ed25519, session-key derivation).

Part of the [`hap-rust`](https://github.com/phunapps/hap-rust) workspace. Cryptographic primitives come from vetted crates; this crate implements the HAP *protocols* on top, cross-verified byte-for-byte against `aiohomekit` traces and the HAP spec's SRP vectors.
