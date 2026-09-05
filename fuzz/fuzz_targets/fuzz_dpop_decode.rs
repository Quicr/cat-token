#![no_main]
use cat_token::dpop::DpopProof;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = DpopProof::decode(data);
});
