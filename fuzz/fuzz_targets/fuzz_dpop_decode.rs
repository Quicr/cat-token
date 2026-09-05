#![no_main]
use cat_token::dpop::DpopProof;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = DpopProof::decode(s);
    }
});
