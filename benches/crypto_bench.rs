// SPDX-FileCopyrightText: Copyright (c) 2022 Quicr
// SPDX-License-Identifier: BSD-2-Clause

use cat_token::*;
use criterion::{BenchmarkId, Criterion, black_box, criterion_group, criterion_main};

const SMALL_DATA: &[u8] = b"Hello, World!";
const MEDIUM_DATA: &[u8] = b"Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat.";
const LARGE_DATA: &[u8] = &[0u8; 1024];

fn setup_hmac() -> HmacSha256Algorithm {
    let key = HmacSha256Algorithm::generate_key().unwrap();
    HmacSha256Algorithm::from_secret_key(&key)
}

fn setup_es256() -> Es256Algorithm {
    Es256Algorithm::new_with_key_pair().unwrap()
}

fn setup_ps256() -> Ps256Algorithm {
    Ps256Algorithm::new_with_key_pair().unwrap()
}

fn bench_hmac_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("hmac_operations");
    let hmac = setup_hmac();

    // Benchmark key generation
    group.bench_function("key_generation", |b| {
        b.iter(|| black_box(HmacSha256Algorithm::generate_key()))
    });

    // Benchmark signing with different data sizes
    for (name, data) in [
        ("small", SMALL_DATA),
        ("medium", MEDIUM_DATA),
        ("large", LARGE_DATA),
    ] {
        group.bench_with_input(BenchmarkId::new("sign", name), data, |b, data| {
            b.iter(|| black_box(hmac.sign(data).unwrap()))
        });
    }

    // Benchmark verification
    let signatures: Vec<_> = [SMALL_DATA, MEDIUM_DATA, LARGE_DATA]
        .iter()
        .map(|data| hmac.sign(data).unwrap())
        .collect();

    for (name, (data, sig)) in [
        ("small", (SMALL_DATA, &signatures[0])),
        ("medium", (MEDIUM_DATA, &signatures[1])),
        ("large", (LARGE_DATA, &signatures[2])),
    ] {
        group.bench_with_input(
            BenchmarkId::new("verify", name),
            &(data, sig),
            |b, (data, sig)| b.iter(|| hmac.verify(black_box(data), black_box(sig)).unwrap()),
        );
    }

    group.finish();
}

fn bench_es256_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("es256_operations");
    let es256 = setup_es256();

    // Benchmark key generation
    group.bench_function("key_generation", |b| {
        b.iter(|| black_box(Es256Algorithm::new_with_key_pair().unwrap()))
    });

    // Benchmark signing with different data sizes
    for (name, data) in [
        ("small", SMALL_DATA),
        ("medium", MEDIUM_DATA),
        ("large", LARGE_DATA),
    ] {
        group.bench_with_input(BenchmarkId::new("sign", name), data, |b, data| {
            b.iter(|| black_box(es256.sign(data).unwrap()))
        });
    }

    // Benchmark verification
    let signatures: Vec<_> = [SMALL_DATA, MEDIUM_DATA, LARGE_DATA]
        .iter()
        .map(|data| es256.sign(data).unwrap())
        .collect();

    for (name, (data, sig)) in [
        ("small", (SMALL_DATA, &signatures[0])),
        ("medium", (MEDIUM_DATA, &signatures[1])),
        ("large", (LARGE_DATA, &signatures[2])),
    ] {
        group.bench_with_input(
            BenchmarkId::new("verify", name),
            &(data, sig),
            |b, (data, sig)| b.iter(|| es256.verify(black_box(data), black_box(sig)).unwrap()),
        );
    }

    group.finish();
}

fn bench_ps256_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("ps256_operations");
    let ps256 = setup_ps256();

    // Benchmark key generation
    group.bench_function("key_generation", |b| {
        b.iter(|| black_box(Ps256Algorithm::new_with_key_pair().unwrap()))
    });

    // Benchmark signing with different data sizes
    for (name, data) in [
        ("small", SMALL_DATA),
        ("medium", MEDIUM_DATA),
        ("large", LARGE_DATA),
    ] {
        group.bench_with_input(BenchmarkId::new("sign", name), data, |b, data| {
            b.iter(|| black_box(ps256.sign(data).unwrap()))
        });
    }

    // Benchmark verification
    let signatures: Vec<_> = [SMALL_DATA, MEDIUM_DATA, LARGE_DATA]
        .iter()
        .map(|data| ps256.sign(data).unwrap())
        .collect();

    for (name, (data, sig)) in [
        ("small", (SMALL_DATA, &signatures[0])),
        ("medium", (MEDIUM_DATA, &signatures[1])),
        ("large", (LARGE_DATA, &signatures[2])),
    ] {
        group.bench_with_input(
            BenchmarkId::new("verify", name),
            &(data, sig),
            |b, (data, sig)| b.iter(|| ps256.verify(black_box(data), black_box(sig)).unwrap()),
        );
    }

    group.finish();
}

fn bench_crypto_comparison(c: &mut Criterion) {
    let mut group = c.benchmark_group("crypto_comparison");

    let hmac = setup_hmac();
    let es256 = setup_es256();
    let ps256 = setup_ps256();

    let test_data = MEDIUM_DATA;

    group.bench_function("hmac_sign", |b| {
        b.iter(|| black_box(hmac.sign(test_data).unwrap()))
    });

    group.bench_function("es256_sign", |b| {
        b.iter(|| black_box(es256.sign(test_data).unwrap()))
    });

    group.bench_function("ps256_sign", |b| {
        b.iter(|| black_box(ps256.sign(test_data).unwrap()))
    });

    // Verification comparison
    let hmac_sig = hmac.sign(test_data).unwrap();
    let es256_sig = es256.sign(test_data).unwrap();
    let ps256_sig = ps256.sign(test_data).unwrap();

    group.bench_function("hmac_verify", |b| {
        b.iter(|| {
            hmac.verify(black_box(test_data), black_box(&hmac_sig))
                .unwrap()
        })
    });

    group.bench_function("es256_verify", |b| {
        b.iter(|| {
            es256
                .verify(black_box(test_data), black_box(&es256_sig))
                .unwrap()
        })
    });

    group.bench_function("ps256_verify", |b| {
        b.iter(|| {
            ps256
                .verify(black_box(test_data), black_box(&ps256_sig))
                .unwrap()
        })
    });

    group.finish();
}

fn bench_utility_functions(c: &mut Criterion) {
    let mut group = c.benchmark_group("utility_functions");

    let header = b"header_data";
    let payload = b"payload_data";

    group.bench_function("create_signing_input", |b| {
        b.iter(|| black_box(create_signing_input(header, payload, ALG_ES256).unwrap()))
    });

    group.bench_function("hash_sha256", |b| {
        b.iter(|| black_box(hash_sha256(MEDIUM_DATA)))
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_hmac_operations,
    bench_es256_operations,
    bench_ps256_operations,
    bench_crypto_comparison,
    bench_utility_functions
);
criterion_main!(benches);
