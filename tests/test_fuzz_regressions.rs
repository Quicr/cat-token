//! Regression tests derived from libFuzzer `slow-unit-*` artifacts. Each
//! input previously drove the CBOR decoder into pathological behaviour
//! (nested map recursion, byte-string length parsing). The clamped
//! recursion limit (see `CBOR_MAX_RECURSION_DEPTH`) and the CwtLimits
//! enforcement now ensure the decoder either accepts the input quickly or
//! returns an error — either outcome is fine, we just refuse to hang.
//!
//! Each test wraps the decode in a bounded thread so a real regression
//! (an unbounded loop reintroduced) fails the test rather than blocking
//! CI. The bound is generous (2 s) — normal decoding of these payloads
//! completes in microseconds.

use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use cat_token::{Cwt, CwtLimits};

fn assert_decodes_within(bytes: Vec<u8>, budget: Duration, name: &str) {
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let limits = CwtLimits::default();
        let _ = Cwt::decode_payload_with_limits(&bytes, &limits);
        let _ = tx.send(());
    });
    match rx.recv_timeout(budget) {
        Ok(()) => {}
        Err(_) => panic!("fuzz regression {name}: decode did not complete within {budget:?}"),
    }
}

/// `slow-unit-407e...`: 64 bytes of 0xA3 (CBOR map(3) headers)
/// followed by 0x08. Prior versions unbounded-recursed through the
/// nested maps; the clamped recursion limit now bails out fast.
#[test]
fn fuzz_regression_deeply_nested_map_headers() {
    let bytes = vec![
        0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3,
        0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3,
        0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3,
        0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3, 0xa3,
        0xa3, 0xa3, 0xa3, 0x08,
    ];
    assert_decodes_within(
        bytes,
        Duration::from_secs(2),
        "deeply_nested_map_headers",
    );
}

/// `slow-unit-5cc1...`: byte-string length header (0xB7 = map(23))
/// followed by a mix of `0xB7` map headers and a trailing 0x4A (byte
/// string length 10) with no payload. The decoder should reject on the
/// truncated tail, not spin.
#[test]
fn fuzz_regression_truncated_map_with_byte_string_header() {
    let bytes = vec![
        0xb7, 0xd0, 0xb7, 0xb7, 0xb7, 0xb7, 0xb7, 0xb7, 0xb7, 0xb7, 0xb7, 0xb7, 0x4a,
    ];
    assert_decodes_within(
        bytes,
        Duration::from_secs(2),
        "truncated_map_with_byte_string_header",
    );
}

/// `slow-unit-df58...`: a single unsigned-int major byte (0x2a).
/// Trivially decodes; kept as a corpus canary — if this ever takes
/// longer than a millisecond, we've regressed in a way worth catching.
#[test]
fn fuzz_regression_single_unsigned_integer() {
    let bytes = vec![0x2a];
    assert_decodes_within(bytes, Duration::from_millis(500), "single_unsigned_integer");
}
