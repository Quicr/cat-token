#![no_main]
use cat_token::x509::extract_spki_from_cert;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = extract_spki_from_cert(data);
});
