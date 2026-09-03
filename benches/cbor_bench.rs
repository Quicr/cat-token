// SPDX-FileCopyrightText: Copyright (c) 2022 Quicr
// SPDX-License-Identifier: BSD-2-Clause

use cat_token::*;
use chrono::{Duration, Utc};
use criterion::{BenchmarkId, Criterion, black_box, criterion_group, criterion_main};

fn create_simple_token() -> CatToken {
    let now = Utc::now();
    let exp = now + Duration::hours(1);

    CatToken::new()
        .with_issuer("https://auth.example.com")
        .with_audience(vec!["client1".to_string()])
        .with_expiration(exp)
        .with_cwt_id("token-123")
        .with_subject("user@example.com")
}

fn create_medium_token() -> CatToken {
    let now = Utc::now();
    let exp = now + Duration::hours(1);

    CatToken::new()
        .with_issuer("https://auth.example.com")
        .with_audience(vec!["client1".to_string(), "client2".to_string()])
        .with_expiration(exp)
        .with_not_before(now)
        .with_cwt_id_str("token-12345")
        .with_version(1)
        .with_replay_protection(claims::ReplayProtection::Prohibited)
        .with_subject("user@example.com")
        .with_issued_at(now)
        .with_interface_data("web-interface")
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
            "web-app".to_string(),
            "api-service".to_string(),
        ])
        .with_expiration(exp)
        .with_not_before(now)
        .with_cwt_id_str("token-12345-complex")
        .with_version(1)
        .with_replay_protection(claims::ReplayProtection::Prohibited)
        .with_geo_coordinate(40.7128, -74.0060, Some(100))
        .with_geohash("dr5regw")
        .with_subject("user@example.com")
        .with_issued_at(iat)
        .with_interface_data("mobile-interface-v2")
        .with_confirmation(b"jwk-thumbprint-xyz-padded-to-32b".to_vec())
        .with_dpop_settings(cat_token::CatDpopSettings::new().with_window(300))
        .with_ip_address("192.168.1.100")
        .with_ip_range("10.0.0.0/8")
        .with_asn(64512)
        .with_asn_range(64512, 65535)
}

fn bench_cbor_encoding(c: &mut Criterion) {
    let mut group = c.benchmark_group("cbor_encoding");

    let simple_token = create_simple_token();
    let medium_token = create_medium_token();
    let complex_token = create_complex_token();

    let simple_cwt = Cwt::new(ALG_HMAC256_256, simple_token);
    let medium_cwt = Cwt::new(ALG_ES256, medium_token);
    let complex_cwt = Cwt::new(ALG_PS256, complex_token);

    group.bench_function("simple_token", |b| {
        b.iter(|| black_box(simple_cwt.encode_payload().unwrap()))
    });

    group.bench_function("medium_token", |b| {
        b.iter(|| black_box(medium_cwt.encode_payload().unwrap()))
    });

    group.bench_function("complex_token", |b| {
        b.iter(|| black_box(complex_cwt.encode_payload().unwrap()))
    });

    group.finish();
}

fn bench_cbor_decoding(c: &mut Criterion) {
    let mut group = c.benchmark_group("cbor_decoding");

    let simple_token = create_simple_token();
    let medium_token = create_medium_token();
    let complex_token = create_complex_token();

    let simple_cwt = Cwt::new(ALG_HMAC256_256, simple_token);
    let medium_cwt = Cwt::new(ALG_ES256, medium_token);
    let complex_cwt = Cwt::new(ALG_PS256, complex_token);

    let simple_cbor = simple_cwt.encode_payload().unwrap();
    let medium_cbor = medium_cwt.encode_payload().unwrap();
    let complex_cbor = complex_cwt.encode_payload().unwrap();

    group.bench_function("simple_token", |b| {
        b.iter(|| black_box(Cwt::decode_payload(&simple_cbor).unwrap()))
    });

    group.bench_function("medium_token", |b| {
        b.iter(|| black_box(Cwt::decode_payload(&medium_cbor).unwrap()))
    });

    group.bench_function("complex_token", |b| {
        b.iter(|| black_box(Cwt::decode_payload(&complex_cbor).unwrap()))
    });

    group.finish();
}

fn bench_roundtrip_encoding(c: &mut Criterion) {
    let mut group = c.benchmark_group("cbor_roundtrip");

    let simple_token = create_simple_token();
    let medium_token = create_medium_token();
    let complex_token = create_complex_token();

    let simple_cwt = Cwt::new(ALG_HMAC256_256, simple_token);
    let medium_cwt = Cwt::new(ALG_ES256, medium_token);
    let complex_cwt = Cwt::new(ALG_PS256, complex_token);

    group.bench_function("simple_token", |b| {
        b.iter(|| {
            let encoded = simple_cwt.encode_payload().unwrap();
            black_box(Cwt::decode_payload(&encoded).unwrap())
        })
    });

    group.bench_function("medium_token", |b| {
        b.iter(|| {
            let encoded = medium_cwt.encode_payload().unwrap();
            black_box(Cwt::decode_payload(&encoded).unwrap())
        })
    });

    group.bench_function("complex_token", |b| {
        b.iter(|| {
            let encoded = complex_cwt.encode_payload().unwrap();
            black_box(Cwt::decode_payload(&encoded).unwrap())
        })
    });

    group.finish();
}

fn bench_cbor_size_analysis(c: &mut Criterion) {
    let mut group = c.benchmark_group("cbor_size_analysis");

    let simple_token = create_simple_token();
    let medium_token = create_medium_token();
    let complex_token = create_complex_token();

    let simple_cwt = Cwt::new(ALG_HMAC256_256, simple_token);
    let medium_cwt = Cwt::new(ALG_ES256, medium_token);
    let complex_cwt = Cwt::new(ALG_PS256, complex_token);

    let simple_size = simple_cwt.encode_payload().unwrap().len();
    let medium_size = medium_cwt.encode_payload().unwrap().len();
    let complex_size = complex_cwt.encode_payload().unwrap().len();

    println!("CBOR Size Analysis:");
    println!("Simple token: {} bytes", simple_size);
    println!("Medium token: {} bytes", medium_size);
    println!("Complex token: {} bytes", complex_size);

    // Benchmark encoding with size awareness
    for (name, (cwt, expected_size)) in [
        ("simple", (&simple_cwt, simple_size)),
        ("medium", (&medium_cwt, medium_size)),
        ("complex", (&complex_cwt, complex_size)),
    ] {
        group.bench_with_input(
            BenchmarkId::new(
                "encode_with_size",
                format!("{}_{}_bytes", name, expected_size),
            ),
            &(cwt, expected_size),
            |b, (cwt, _expected_size)| {
                b.iter(|| {
                    let encoded = cwt.encode_payload().unwrap();
                    black_box(encoded.len());
                })
            },
        );
    }

    group.finish();
}

fn bench_different_algorithms(c: &mut Criterion) {
    let mut group = c.benchmark_group("cbor_by_algorithm");

    let token = create_medium_token();

    let hmac_cwt = Cwt::new(ALG_HMAC256_256, token.clone());
    let es256_cwt = Cwt::new(ALG_ES256, token.clone());
    let ps256_cwt = Cwt::new(ALG_PS256, token);

    group.bench_function("hmac256_encode", |b| {
        b.iter(|| black_box(hmac_cwt.encode_payload().unwrap()))
    });

    group.bench_function("es256_encode", |b| {
        b.iter(|| black_box(es256_cwt.encode_payload().unwrap()))
    });

    group.bench_function("ps256_encode", |b| {
        b.iter(|| black_box(ps256_cwt.encode_payload().unwrap()))
    });

    let hmac_cbor = hmac_cwt.encode_payload().unwrap();
    let es256_cbor = es256_cwt.encode_payload().unwrap();
    let ps256_cbor = ps256_cwt.encode_payload().unwrap();

    group.bench_function("hmac256_decode", |b| {
        b.iter(|| black_box(Cwt::decode_payload(&hmac_cbor).unwrap()))
    });

    group.bench_function("es256_decode", |b| {
        b.iter(|| black_box(Cwt::decode_payload(&es256_cbor).unwrap()))
    });

    group.bench_function("ps256_decode", |b| {
        b.iter(|| black_box(Cwt::decode_payload(&ps256_cbor).unwrap()))
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_cbor_encoding,
    bench_cbor_decoding,
    bench_roundtrip_encoding,
    bench_cbor_size_analysis,
    bench_different_algorithms
);
criterion_main!(benches);
