#![no_main]
use cat_token::*;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let limits = CwtLimits::default();
    let _ = Cwt::decode_payload_with_limits(data, &limits);
});
