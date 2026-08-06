# hap-thread build progress ledger

Branch: thread-support (off main). Design: docs/superpowers/specs/2026-08-07-hap-thread-design.md
(gitignored — copy in session scratchpad). Reference: aiohomekit controller/coap.

Clippy -D warnings is gated at end-of-crate wiring (bottom-up build leaves
pub(crate) helpers transiently dead_code until consumed). Tests pass per module.

- [x] Task 1: crate scaffold (Cargo.toml, lib.rs, error.rs) + workspace wiring + coap-lite dep
- [x] Task 2: pdu.rs — encode_request/encode_all/decode_response/decode_all + 9 tests
- [x] Task 3: coap.rs — CoapTransport trait + UDP + mock (2 tests)
- [x] Task 4: session.rs — three-key record layer, aiohomekit vectors (5 tests)
- [x] Task 5: discovery.rs — _hap._udp browse + TXT parse (4 tests)
- [x] Task 6: pairing.rs — pair setup + verify over CoAP + _with_client seam (2 tests)
- [ ] Task 7: db.rs — 0x09 database decode
- [ ] Task 8: accessory.rs/controller.rs — connect, read/write, persistence
- [ ] Task 9 (stretch): subscribe + event record parser
- [ ] Task 10: README, rustdoc, example, final clippy/fmt gate

## Spec review outcomes (SOUND-WITH-CHANGES) applied to build
- Finding 1 (pdu must follow aiohomekit not hap-ble): ALREADY correct in pdu.rs
  (always-length, fixed 5-byte response, value-only write body). Verified by tests.
- Finding 4: CoapTransport::post returns CoapResponse{ code:(u8,u8), payload } so
  4.04 -> SessionExpired is expressible. (applied in coap.rs)
- Finding 2/D3: add PairVerifyClient::event_key() to hap-crypto (HKDF over private
  shared_secret, "Event-Salt"/"Event-Read-Encryption-Key"); minor bump 1.3.0.
- Finding 3: StoredTransport::Thread is BREAKING hap-pairing -> DEFER persistence
  out of MT-1; note #[non_exhaustive] fix as a separate hap-pairing task.
- Finding 5: db.rs must use ordered Tlv8Reader (NOT Tlv8Map which dedups repeats);
  0x09 DB vector is synthetic until device bring-up.
- Finding 7: nonce counter u64 (12-byte nonce); direction send=write_key/send_ctr,
  recv=read_key/recv_ctr; char type=0x04, char iid=0x05 in DB.
- Finding 6: coap-lite has no Block2 reassembly / no CON retransmit beyond basic;
  real UdpCoapTransport needs both at device bring-up (documented risk).
