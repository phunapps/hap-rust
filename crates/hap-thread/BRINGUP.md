# hap-thread — hardware bring-up notes

The MT-1 protocol core is unit-tested against aiohomekit but has never run against
a real accessory. Before/while testing against a commissioned SMS2 over Thread,
address these — ordered by how soon they bite. (From the final MT-1 review.)

## Blockers to fix before the first hardware attempt

1. **CoAP separate responses / empty ACKs (review F1). ✅ RESOLVED (roadmap Item 3).**
   `coap.rs::UdpCoapTransport::post` matched responses by message-id and returned
   the first datagram. A HAP accessory that can't answer within the ACK window
   sends an *empty ACK* (code 0.00, same message-id) then a *separate CON* with
   the real payload (new message-id, **same token**).
   Now `post` correlates strictly by **token** via an `exchange()` helper: an
   empty ACK stops retransmission and it waits `SEPARATE_RESPONSE_TIMEOUT` for the
   token's real response, ACKs that separate CON, and uses its payload. Covered by
   `coap::tests::post_handles_empty_ack_then_separate_response` and end-to-end by
   `hap-thread-dut`'s `with_slow_responses` mode
   (`hap-thread-dut/tests/transport.rs::controller_survives_separate_responses`).

2. **CoAP Block2 reassembly (review F2). ✅ RESOLVED (roadmap Item 3).**
   The `0x09` database (and large batched reads) arrive block-wise over Thread's
   small MTU; `read_database_raw` used to return only the first block.
   `post` now reassembles Block2 fragments (RFC 7959): it re-POSTs the request with
   a Block2 option (sharing one token) until the more-bit clears, concatenating the
   payloads (capped at `MAX_BLOCKS`), which the session then decrypts as one AEAD
   message. Covered by `coap::tests::post_reassembles_block2_response` and
   end-to-end by `hap-thread-dut`'s `with_blockwise_responses` mode
   (`…/transport.rs::controller_reassembles_a_blockwise_database`). `RECV_BUF`
   stays 1500 — sized for one block plus framing, which is all a datagram carries.

## Watch list (verify empirically on the SMS2)

3. **Batched tid ordering + aid=1.** `decode_all` now requires `tid == index`
   (review F5). Confirm the accessory echoes tids in order for batched
   reads/writes. The single-accessory `aid = 1` assumption holds for the SMS2 but
   breaks for a bridge — revisit when the `0x09` tree decode lands (it carries the
   real accessory instance-id).

4. **CoAP retransmission (review F7).** Fixed 2 s timeout, no backoff/jitter, no
   token correlation, shared socket not concurrency-safe (safe today because
   `post_secure` serializes). **Token correlation is now done** (F1 above): a
   stray/duplicate response from an earlier exchange is discarded because it
   carries a different token. Backoff/jitter and concurrent use of one socket
   remain future hardening (not needed while `post_secure` serializes).

## Then, in order
- Capture a real `0x09` body + a live event PUT → commit as vectors, implement the
  `0x09` → `hap-model` tree decode (add the `hap-model` dep back) and the event
  server (MT-2).
- Add `StoredTransport::Thread` to `hap-pairing` (a deliberate breaking change;
  mark the enum `#[non_exhaustive]`) and wire persistence (add `hap-pairing` back).
