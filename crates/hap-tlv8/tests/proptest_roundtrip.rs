//! Property-based round-trip tests for `hap-tlv8`.
//!
//! Encoding a sequence of logical items with [`Tlv8Writer::push`] then parsing
//! with [`Tlv8Reader::parse`] must return the same items, provided adjacent
//! items have distinct types (otherwise reassembly legitimately merges them,
//! which is the documented behaviour, not a round-trip).

// CLAUDE.md test-code carve-out: unwrap/expect allowed with documented reason.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use hap_tlv8::{Tlv8Reader, Tlv8Writer, SEPARATOR};
use proptest::prelude::*;

/// Strategy for a single item: a non-separator type and a value of up to
/// 600 bytes (exercising multi-fragment values).
fn item_strategy() -> impl Strategy<Value = (u8, Vec<u8>)> {
    (
        (0u8..=0xFE).prop_filter("not separator", |t| *t != SEPARATOR),
        prop::collection::vec(any::<u8>(), 0..600),
    )
}

/// Collapse adjacent same-type items so each logical item has a distinct type
/// from its predecessor — the only inputs that round-trip exactly.
fn normalize(items: Vec<(u8, Vec<u8>)>) -> Vec<(u8, Vec<u8>)> {
    let mut out: Vec<(u8, Vec<u8>)> = Vec::new();
    for (ty, value) in items {
        match out.last_mut() {
            Some(last) if last.0 == ty => last.1.extend(value),
            _ => out.push((ty, value)),
        }
    }
    out
}

proptest! {
    #[test]
    fn parse_after_write_recovers_normalized_items(
        items in prop::collection::vec(item_strategy(), 0..16)
    ) {
        let normalized = normalize(items);

        let mut buf = Vec::new();
        {
            let mut w = Tlv8Writer::new(&mut buf);
            for (ty, value) in &normalized {
                w.push(*ty, value);
            }
        }

        let parsed = Tlv8Reader::parse(&buf).unwrap();
        prop_assert_eq!(parsed, normalized);
    }

    #[test]
    fn parse_never_panics_on_arbitrary_bytes(bytes in prop::collection::vec(any::<u8>(), 0..1024)) {
        // The reader must return Ok or Err, never panic, on any input.
        let _ = Tlv8Reader::parse(&bytes);
    }
}
