#![no_main]
use cat_token::*;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let key = HmacSha256Algorithm::generate_key().unwrap();
    let alg = HmacSha256Algorithm::from_secret_key(&key);
    let limits = CwtLimits::default();
    let _ = decode_token_with_limits(data, &alg, &limits);
});
