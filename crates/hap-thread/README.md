# hap-thread

HomeKit Accessory Protocol (HAP) **Thread transport**, controller side — part of
the [`hap-rust`](https://github.com/phunapps/hap-rust) workspace.

HAP-over-Thread is not a separate application protocol: a Thread accessory speaks
the same HAP PDUs as HAP-BLE, carried in **CoAP messages over UDP/IPv6**. This
crate is the CoAP application layer a controller uses once an accessory is
reachable on a Thread network.

## Status: milestone MT-1 (protocol core, pre-hardware)

Implemented and **cross-verified against aiohomekit** (the project's correctness
reference) with unit tests — no device required:

- **PDU codec** (`pdu`) — HAP request/response PDUs and the batched form CoAP
  uses (`encode_all` / `decode_all`), matching aiohomekit's `pdu.py` (the length
  field is always present; there is no BLE-style return-response param or
  fragmentation).
- **CoAP transport** (`coap`) — a `CoapTransport` seam returning the response
  *code* alongside the payload (`2.04 Changed` vs `4.04 Not Found` → re-verify),
  with a real `UdpCoapTransport` (IPv6) and a `MockCoapTransport` for tests.
- **Secure session** (`session`) — the post-verify ChaCha20-Poly1305 record
  layer: three directional keys (control read/write + a CoAP-only event key),
  empty AAD, whole-payload framing, `[0;4]‖counter` nonce. Seal/open are
  byte-for-byte cross-verified against aiohomekit.
- **Pair Setup + Pair Verify** (`pairing`) — driving `hap-crypto`'s
  transport-agnostic state machines over CoAP `/1` and `/2`, and deriving the
  CoAP event key.
- **Discovery** (`discovery`) — `_hap._udp` mDNS browse + TXT parse.
- **Connected accessory** (`accessory`, `controller`) — `ThreadController`
  (identify / pair / connect) and `ThreadAccessory` (characteristic
  read/write, batched reads, raw `0x09` database read) over the secure session.

## Deferred (need hardware or a captured trace)

- **`0x09` database → typed tree.** `read_database_raw` returns the decrypted
  bytes; decoding the nested container TLV into a `hap-model` tree is left until
  a real accessory body can be captured to cross-verify against (a self-built
  vector would only prove internal consistency).
- **Event notifications.** The subscribe opcodes and the event-record decrypt
  path are present; the inbound CoAP **server** that receives event PUTs is
  MT-2.
- **CoAP block-wise transfer (Block2).** A large `0x09` response delivered in
  blocks needs reassembly before decryption — added at bring-up.
- **Persistence.** Storing a Thread pairing needs a `StoredTransport::Thread`
  variant in `hap-pairing` (a deliberate breaking change, tracked separately);
  `pair` returns the `AccessoryPairing` for the caller to persist meanwhile.
- **Commissioning.** Getting an accessory onto a Thread network (Border Router +
  BLE credential provisioning) is out of scope; this crate assumes the accessory
  is already reachable and advertises `_hap._udp`.

See `docs/superpowers/specs/2026-08-07-hap-thread-design.md` for the full design.

## Usage sketch

```rust,ignore
use hap_thread::{discover, ThreadController};
use std::time::Duration;

let accessories = discover(Duration::from_secs(4)).await?;
let target = accessories.into_iter().find(|a| !a.paired).unwrap();

let controller = ThreadController::generate("AA:BB:CC:DD:EE:FF".into());
let (accessory, pairing) = controller.pair(target.addr, "123-45-678").await?;
// persist `pairing` yourself for now; later: controller.connect(addr, &pairing)

let value = accessory.read_characteristic(iid).await?;
accessory.write_characteristic(iid, &[0x01]).await?;
```

## License

Apache-2.0.
