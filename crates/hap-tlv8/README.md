# hap-tlv8

HomeKit Accessory Protocol (HAP) TLV8 encoder and decoder, with automatic
255-byte fragmentation and separator handling. Milestone 1 of
[`hap-rust`](https://github.com/hemanshubhojak/hap-rust).

## Format

A TLV8 stream is a sequence of `(type: u8, length: u8, value)` items. Values
longer than 255 bytes fragment across consecutive same-type items; a
zero-length item of type `0xFF` separates repeated structures.

## Example

```rust
use hap_tlv8::{Tlv8Writer, Tlv8Reader};

let mut bytes = Vec::new();
let mut w = Tlv8Writer::new(&mut bytes);
w.push_u8(0x06, 1);      // State = 1
w.push_u8(0x00, 0);      // Method = Pair Setup
let items = Tlv8Reader::parse(&bytes).unwrap();
assert_eq!(items, vec![(0x06, vec![1]), (0x00, vec![0])]);
```

## License

Apache-2.0.
