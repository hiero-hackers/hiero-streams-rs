#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = hiero_streams::detect_format(data);
    let _ = hiero_streams::parse_record_file(data);
});
