// SPDX-FileCopyrightText: Copyright (c) 2022 Quicr
// SPDX-License-Identifier: BSD-2-Clause

use cat_token::moqt::{MoqtScopeBuilder, MoqtValidator, RelayRequestContext};
use cat_token::*;
use chrono::{Duration, Utc};
use criterion::{BenchmarkId, Criterion, black_box, criterion_group, criterion_main};

fn make_validated(token: &CatToken) -> ValidatedToken {
    let key = HmacSha256Algorithm::new(b"test-key-for-roundtrip-000000000");
    let encoded = encode_token(token, &key).unwrap();
    let validator = CatTokenValidator::new().dangerously_allow_unencrypted_privacy_claims();
    Decoder::with_algorithm(&key)
        .decode(&encoded)
        .unwrap()
        .validate(&validator)
        .unwrap()
}

fn create_simple_token() -> CatToken {
    let now = Utc::now();
    let exp = now + Duration::hours(1);

    CatToken::new()
        .with_issuer("https://auth.example.com")
        .with_audience(vec!["client1".to_string(), "client2".to_string()])
        .with_expiration(exp)
        .with_not_before(now)
        .with_cwt_id_str("token-12345")
        .with_version(1)
        .with_subject("user@example.com")
        .with_issued_at(now)
}

fn create_complex_token() -> CatToken {
    let now = Utc::now();
    let exp = now + Duration::hours(1);
    let iat = now - Duration::minutes(1);

    CatToken::new()
        .with_issuer("https://auth.example.com")
        .with_audience(vec![
            "client1".to_string(),
            "client2".to_string(),
            "mobile-app".to_string(),
        ])
        .with_expiration(exp)
        .with_not_before(now)
        .with_cwt_id_str("token-12345")
        .with_version(1)
        .with_replay_protection(claims::ReplayProtection::Prohibited)
        .with_geo_coordinate(40.7128, -74.0060, 100)
        .with_geohash("dr5regw")
        .with_subject("user@example.com")
        .with_issued_at(iat)
        .with_interface_data("mobile-interface-v2")
        .with_confirmation(b"jwk-thumbprint-xyz-padded-to-32b".to_vec())
        .with_dpop_settings(cat_token::CatDpopSettings::new().with_window(300).unwrap())
        .with_ip_address("192.168.1.100")
        .unwrap()
        .with_ip_range("10.0.0.0/8")
        .unwrap()
        .with_asn(64512)
        .with_asn_range(64512, 65535)
}

fn bench_token_creation(c: &mut Criterion) {
    let mut group = c.benchmark_group("token_creation");

    group.bench_function("simple_token", |b| {
        b.iter(|| black_box(create_simple_token()))
    });

    group.bench_function("complex_token", |b| {
        b.iter(|| black_box(create_complex_token()))
    });

    group.finish();
}

fn bench_token_validation(c: &mut Criterion) {
    let mut group = c.benchmark_group("token_validation");

    let simple_token = create_simple_token();
    let complex_token = create_complex_token();

    let validator = CatTokenValidator::new()
        .with_expected_issuers(vec!["https://auth.example.com".to_string()])
        .with_expected_audiences(vec!["client1".to_string(), "client2".to_string()])
        .with_clock_skew_tolerance(60)
        .unwrap();

    group.bench_function("simple_token_validation", |b| {
        b.iter(|| black_box(validator.validate(&simple_token)).ok())
    });

    group.bench_function("complex_token_validation", |b| {
        b.iter(|| black_box(validator.validate(&complex_token)).ok())
    });

    group.finish();
}

fn bench_token_cloning(c: &mut Criterion) {
    let mut group = c.benchmark_group("token_cloning");

    let simple_token = create_simple_token();
    let complex_token = create_complex_token();

    group.bench_function("simple_token_clone", |b| {
        b.iter(|| black_box(simple_token.clone()))
    });

    group.bench_function("complex_token_clone", |b| {
        b.iter(|| black_box(complex_token.clone()))
    });

    group.finish();
}

fn bench_moqt_authorization(c: &mut Criterion) {
    let mut group = c.benchmark_group("moqt_authorization");

    // Single scope token
    let single_scope = MoqtScopeBuilder::new()
        .full_access()
        .namespace_prefix(b"cdn.")
        .track_prefix(b"/stream/")
        .build();

    let single_scope_token = CatTokenBuilder::new()
        .issuer("https://auth.example.com")
        .moqt_scope(single_scope)
        .build()
        .unwrap();

    // Multi-scope token (10 scopes)
    let multi_scopes: Vec<_> = (0..10)
        .map(|i| {
            MoqtScopeBuilder::new()
                .action(MoqtAction::Publish)
                .action(MoqtAction::Subscribe)
                .namespace_exact(format!("namespace-{}", i).as_bytes())
                .track_prefix(b"/")
                .build()
        })
        .collect();

    let multi_scope_token = CatTokenBuilder::new()
        .issuer("https://auth.example.com")
        .moqt_scopes(multi_scopes)
        .build()
        .unwrap();

    let validator = MoqtValidator::new().dangerously_allow_missing_audience();

    let single_validated = make_validated(&single_scope_token);
    let multi_validated = make_validated(&multi_scope_token);

    // Matching request (single scope)
    let matching_request = RelayRequestContext::new(
        "relay",
        MoqtAction::Publish,
        vec![b"cdn.example.com".to_vec()],
        b"/stream/live".to_vec(),
    );

    group.bench_function("single_scope_match", |b| {
        b.iter(|| {
            black_box(
                validator
                    .authorize(&single_validated, &matching_request)
                    .unwrap(),
            )
        })
    });

    // Non-matching request (must check all scopes)
    let non_matching_request = RelayRequestContext::new(
        "relay",
        MoqtAction::Publish,
        vec![b"other.com".to_vec()],
        b"/stream/live".to_vec(),
    );

    group.bench_function("single_scope_no_match", |b| {
        b.iter(|| {
            black_box(
                validator
                    .authorize(&single_validated, &non_matching_request)
                    .is_err(),
            )
        })
    });

    // Multi-scope - first scope matches
    let first_match_request = RelayRequestContext::new(
        "relay",
        MoqtAction::Publish,
        vec![b"namespace-0".to_vec()],
        b"/track".to_vec(),
    );

    group.bench_function("multi_scope_first_match", |b| {
        b.iter(|| {
            black_box(
                validator
                    .authorize(&multi_validated, &first_match_request)
                    .unwrap(),
            )
        })
    });

    // Multi-scope - last scope matches
    let last_match_request = RelayRequestContext::new(
        "relay",
        MoqtAction::Publish,
        vec![b"namespace-9".to_vec()],
        b"/track".to_vec(),
    );

    group.bench_function("multi_scope_last_match", |b| {
        b.iter(|| {
            black_box(
                validator
                    .authorize(&multi_validated, &last_match_request)
                    .unwrap(),
            )
        })
    });

    // Multi-scope - no match
    let no_match_request = RelayRequestContext::new(
        "relay",
        MoqtAction::Publish,
        vec![b"namespace-99".to_vec()],
        b"/track".to_vec(),
    );

    group.bench_function("multi_scope_no_match", |b| {
        b.iter(|| {
            black_box(
                validator
                    .authorize(&multi_validated, &no_match_request)
                    .is_err(),
            )
        })
    });

    group.finish();
}

fn bench_moqt_throughput(c: &mut Criterion) {
    let mut group = c.benchmark_group("moqt_throughput");

    let scope = MoqtScopeBuilder::new()
        .full_access()
        .namespace_prefix(b"cdn.")
        .build();

    let token = CatTokenBuilder::new()
        .issuer("https://auth.example.com")
        .moqt_scope(scope)
        .build()
        .unwrap();

    let validator = MoqtValidator::new().dangerously_allow_missing_audience();
    let validated = make_validated(&token);

    // Simulate batch authorization (100K ops target)
    for batch_size in [1000, 10000, 100000].iter() {
        group.bench_with_input(
            BenchmarkId::new("batch_authorize", batch_size),
            batch_size,
            |b, &size| {
                let requests: Vec<_> = (0..size)
                    .map(|i| {
                        RelayRequestContext::new(
                            "relay",
                            MoqtAction::Publish,
                            vec![b"cdn.example.com".to_vec()],
                            format!("/stream/{}", i).into_bytes(),
                        )
                    })
                    .collect();

                b.iter(|| {
                    let mut authorized = 0;
                    for req in &requests {
                        if validator.authorize(&validated, req).is_ok() {
                            authorized += 1;
                        }
                    }
                    black_box(authorized)
                })
            },
        );
    }

    group.finish();
}

/// Concurrent authorize throughput. Fans a batch of pre-built requests
/// across N worker threads sharing one `MoqtValidator` + `ValidatedToken`.
/// The lack of storage state on the validator means near-linear scaling is
/// the expected outcome; any degradation as `threads` grows is a red flag
/// for accidental locking on the sync authorize path. Runs against tokens
/// without DPoP or catreplay — those have deliberate serialization points
/// (JTI store, `cti` store) benched separately as their own workloads.
fn bench_moqt_concurrent_authorize(c: &mut Criterion) {
    use std::sync::Arc;
    use std::thread;

    let mut group = c.benchmark_group("moqt_concurrent_authorize");

    let scope = MoqtScopeBuilder::new()
        .full_access()
        .namespace_prefix(b"cdn.")
        .build();
    let token = CatTokenBuilder::new()
        .issuer("https://auth.example.com")
        .moqt_scope(scope)
        .build()
        .unwrap();
    let validator = Arc::new(MoqtValidator::new().dangerously_allow_missing_audience());
    let validated = Arc::new(make_validated(&token));

    // Fixed per-thread batch. Total ops = threads * batch, so throughput
    // per second scales cleanly when contention is absent.
    const BATCH_PER_THREAD: usize = 5_000;

    for &threads in [1usize, 2, 4, 8].iter() {
        group.throughput(criterion::Throughput::Elements(
            (threads * BATCH_PER_THREAD) as u64,
        ));
        group.bench_with_input(
            BenchmarkId::new("threads", threads),
            &threads,
            |b, &threads| {
                // Pre-build requests once per configuration so the timer
                // measures authorization work only.
                let requests: Arc<Vec<RelayRequestContext>> = Arc::new(
                    (0..BATCH_PER_THREAD)
                        .map(|i| {
                            RelayRequestContext::new(
                                "relay",
                                MoqtAction::Publish,
                                vec![b"cdn.example.com".to_vec()],
                                format!("/stream/{i}").into_bytes(),
                            )
                        })
                        .collect(),
                );

                b.iter(|| {
                    let handles: Vec<_> = (0..threads)
                        .map(|_| {
                            let validator = Arc::clone(&validator);
                            let validated = Arc::clone(&validated);
                            let requests = Arc::clone(&requests);
                            thread::spawn(move || {
                                let mut authorized = 0usize;
                                for req in requests.iter() {
                                    if validator.authorize(&validated, req).is_ok() {
                                        authorized += 1;
                                    }
                                }
                                authorized
                            })
                        })
                        .collect();
                    let total: usize = handles.into_iter().map(|h| h.join().unwrap()).sum();
                    black_box(total)
                })
            },
        );
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_token_creation,
    bench_token_validation,
    bench_token_cloning,
    bench_moqt_authorization,
    bench_moqt_throughput,
    bench_moqt_concurrent_authorize
);
criterion_main!(benches);
