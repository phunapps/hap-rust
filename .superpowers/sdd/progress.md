# hap-thread build progress ledger

Branch: thread-support (off main). Design: docs/superpowers/specs/2026-08-07-hap-thread-design.md
(gitignored — copy in session scratchpad). Reference: aiohomekit controller/coap.

Clippy -D warnings is gated at end-of-crate wiring (bottom-up build leaves
pub(crate) helpers transiently dead_code until consumed). Tests pass per module.

- [x] Task 1: crate scaffold (Cargo.toml, lib.rs, error.rs) + workspace wiring + coap-lite dep
- [x] Task 2: pdu.rs — encode_request/encode_all/decode_response/decode_all + 9 tests
- [ ] Task 3: coap.rs — CoapTransport trait + MockCoapTransport + UdpCoapTransport
- [ ] Task 4: session.rs — three-key record layer (ChaCha/HKDF vectors)
- [ ] Task 5: discovery.rs — _hap._udp
- [ ] Task 6: pairing.rs — pair setup + verify over CoAP
- [ ] Task 7: db.rs — 0x09 database decode
- [ ] Task 8: accessory.rs/controller.rs — connect, read/write, persistence
- [ ] Task 9 (stretch): subscribe + event record parser
- [ ] Task 10: README, rustdoc, example, final clippy/fmt gate
