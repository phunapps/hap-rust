# hap-thread — hardware bring-up notes

The MT-1 protocol core is unit-tested against aiohomekit but has never run against
a real accessory. Before/while testing against a commissioned SMS2 over Thread,
address these — ordered by how soon they bite. (From the final MT-1 review.)

## Blockers to fix before the first hardware attempt

1. **CoAP separate responses / empty ACKs (review F1).**
   `coap.rs::UdpCoapTransport::post` matches responses by message-id and returns
   the first datagram. A HAP accessory that can't answer within the ACK window
   sends an *empty ACK* (code 0.00, same message-id) then a *separate CON* with
   the real payload (new message-id, **same token**). Current code returns the
   empty ACK → `changed_payload()` fails with `CoapCode("0.00")`. Fix: on an
   empty ACK, keep waiting (don't retransmit) for a datagram whose **token**
   matches, ACK that separate response, use its payload. Slow ops (DB read, first
   write) are exactly where this happens.

2. **CoAP Block2 reassembly (review F2).**
   The `0x09` database (and large batched reads) arrive block-wise over Thread's
   small MTU. `accessory.rs::read_database_raw` returns only the first block
   today; it is effectively non-functional against real hardware until RFC 7959
   Block2 reassembly is added (coap-lite does not do this). Also raise/relax
   `RECV_BUF` (1500) for datagram sizing.

## Watch list (verify empirically on the SMS2)

3. **Batched tid ordering + aid=1.** `decode_all` now requires `tid == index`
   (review F5). Confirm the accessory echoes tids in order for batched
   reads/writes. The single-accessory `aid = 1` assumption holds for the SMS2 but
   breaks for a bridge — revisit when the `0x09` tree decode lands (it carries the
   real accessory instance-id).

4. **CoAP retransmission (review F7).** Fixed 2 s timeout, no backoff/jitter, no
   token correlation, shared socket not concurrency-safe (safe today because
   `post_secure` serializes). Harden alongside F1.

## Then, in order
- Capture a real `0x09` body + a live event PUT → commit as vectors, implement the
  `0x09` → `hap-model` tree decode (add the `hap-model` dep back) and the event
  server (MT-2).
- Add `StoredTransport::Thread` to `hap-pairing` (a deliberate breaking change;
  mark the enum `#[non_exhaustive]`) and wire persistence (add `hap-pairing` back).
