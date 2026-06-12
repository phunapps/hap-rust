#![no_main]

use libfuzzer_sys::fuzz_target;

// The fuzzer feeds arbitrary bytes to the reader. The PRIMARY invariant is that
// parsing untrusted input never panics, hangs, or over-allocates; a returned
// `Err` is a perfectly good outcome.
//
// As a SECONDARY check we verify re-encode stability, but only where the writer
// can faithfully represent the parsed items. The reader preserves a separator
// (`0xFF`) item verbatim, including any non-empty value, whereas the writer can
// only emit a zero-length `0xFF` (`push_separator`) and would fragment a
// non-empty one. That asymmetry is fine for real HAP (separators are always
// zero-length), so we skip the stability assertion when any non-empty `0xFF`
// item is present rather than flag a false round-trip failure.
fuzz_target!(|data: &[u8]| {
    // Primary invariant: parsing must not panic. Err is acceptable.
    let Ok(items) = hap_tlv8::Tlv8Reader::parse(data) else {
        return;
    };

    // The writer cannot represent a non-empty separator item; skip the
    // stability check for inputs that contain one.
    let writer_representable = items
        .iter()
        .all(|(ty, value)| *ty != hap_tlv8::SEPARATOR || value.is_empty());
    if !writer_representable {
        return;
    }

    let mut buf = Vec::new();
    {
        let mut w = hap_tlv8::Tlv8Writer::new(&mut buf);
        for (ty, value) in &items {
            if *ty == hap_tlv8::SEPARATOR {
                w.push_separator();
            } else {
                w.push(*ty, value);
            }
        }
    }
    let reparsed = hap_tlv8::Tlv8Reader::parse(&buf)
        .expect("re-encoding of accepted items must re-parse");
    assert_eq!(reparsed, items, "round-trip instability on accepted input");
});
