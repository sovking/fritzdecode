#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let key = [0u8; 32];
        let _ = fritzdecode::crypto::decode_secret(s, key, fritzdecode::crypto::IsStringValue::Yes);
        let _ = fritzdecode::crypto::decode_secret(s, key, fritzdecode::crypto::IsStringValue::No);
    }
});
