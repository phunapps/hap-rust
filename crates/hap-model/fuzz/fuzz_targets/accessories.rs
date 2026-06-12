#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // The parser must never panic on arbitrary input; errors are fine.
    let _ = hap_model::parse_accessories(data);
});
