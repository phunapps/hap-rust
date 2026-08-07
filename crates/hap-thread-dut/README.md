# hap-thread-dut

A HomeKit-over-Thread (CoAP) **reference accessory / device-under-test** for the
`hap-rust` workspace. It is the *accessory* side of HAP-over-Thread — a CoAP
server answering the four HAP resources (`/0` identify, `/1` Pair Setup, `/2`
Pair Verify, `/` encrypted traffic) — so a HAP-over-Thread *controller* (such as
`hap-thread`) can be driven end-to-end without Apple hardware. A test/reference
tool, not a product.

## Run
```bash
cargo run -p hap-thread-dut -- '[::]:5683' AA:BB:CC:DD:EE:FF
```
Bind to a Thread mesh-local/off-mesh address to serve over real Thread (via an
OpenThread Border Router), or to loopback/LAN for wired testing.

## Status (incremental)
- ✅ CoAP server transport + `identify`
- ⏳ Pair Setup (accessory/SRP), Pair Verify, secure session, characteristic
  database, event push — in progress; unimplemented resources return `4.04`.
