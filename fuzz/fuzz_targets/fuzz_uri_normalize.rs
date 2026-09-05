#![no_main]
use cat_token::uri::{decompose_uri, normalize_uri};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = normalize_uri(s);
        let _ = decompose_uri(s);
    }
});
