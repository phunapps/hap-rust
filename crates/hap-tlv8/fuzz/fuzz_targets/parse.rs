#![no_main]

use libfuzzer_sys::fuzz_target;

// The fuzzer feeds arbitrary bytes to the reader. It must never panic; it may
// return Ok or Err. When it returns Ok, the reassembled items must survive a
// re-parse of their re-encoding (round-trip stability on accepted inputs).
fuzz_target!(|data: &[u8]| {
    if let Ok(items) = hap_tlv8::Tlv8Reader::parse(data) {
        let mut buf = Vec::new();
        {
            let mut w = hap_tlv8::Tlv8Writer::new(&mut buf);
            for (ty, value) in &items {
                if *ty == hap_tlv8::SEPARATOR && value.is_empty() {
                    w.push_separator();
                } else {
                    w.push(*ty, value);
                }
            }
        }
        let reparsed = hap_tlv8::Tlv8Reader::parse(&buf)
            .expect("re-encoding of accepted items must re-parse");
        assert_eq!(reparsed, items, "round-trip instability on accepted input");
    }
});
