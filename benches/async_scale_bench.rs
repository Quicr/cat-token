// SPDX-FileCopyrightText: Copyright (c) 2022 Quicr
// SPDX-License-Identifier: BSD-2-Clause

//! Scale bench for `AsyncMoqtValidator::authorize`.
//!
//! The realistic CDN failure mode is not sync-path CPU — the P0-1 audit
//! path already benches that. It's async-path tail latency when the
//! DPoP JTI store is a remote service adding p50/p99 delay to every
//! request. This bench pins the async pipeline against a
//! latency-injecting store so a regression in the pre-commit/commit
//! split shows up as tail-latency growth, not just throughput drop.
//!
//! Every request carries a fresh, signed DPoP proof and the underlying
//! token has a `cnf` binding, so `AsyncJtiStore::check_and_insert` is
//! called on the authorization path exactly once per request. If the
//! bench numbers are ever unchanged by increasing `latency`, the store
//! wiring is broken — see `sanity_store_was_called` at the end of the
//! bench group.
//!
//! Run with:
//!   cargo bench --bench async_scale_bench --features async
//!
//! This bench proves the CI-runnable half of finding (3). A real 100k-
//! flow soak requires actual infrastructure — the bench catches
//! regressions between soaks; the soak proves the deployment.

use cat_token::r#async::{AsyncInMemoryStrictJtiStore, AsyncJtiStore, AsyncMoqtValidator};
use cat_token::dpop::{DpopProof, compute_access_token_hash, generate_jti};
use cat_token::jwk::Jwk;
use cat_token::moqt::{MoqtValidator, RelayRequestContext};
use cat_token::*;
use criterion::{BenchmarkId, Criterion, black_box, criterion_group, criterion_main};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tokio::runtime::Runtime;

/// A store that adds a fixed async delay before delegating to an inner
/// strict store, and counts every call. Simulates the round-trip cost
/// of a Redis/DynamoDB call without pulling in a network dependency.
/// The call counter is the sanity check that the bench actually routes
/// through the JTI store.
struct LatencyStore {
    inner: AsyncInMemoryStrictJtiStore,
    latency: Duration,
    calls: AtomicU64,
}

impl LatencyStore {
    fn new(latency: Duration) -> Self {
        Self {
            inner: AsyncInMemoryStrictJtiStore::new(1024),
            latency,
            calls: AtomicU64::new(0),
        }
    }

    fn calls(&self) -> u64 {
        self.calls.load(Ordering::Relaxed)
    }
}

#[async_trait::async_trait]
impl AsyncJtiStore for LatencyStore {
    async fn check_and_insert(&self, key: String, iat: i64) -> Result<(), CatError> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        if !self.latency.is_zero() {
            tokio::time::sleep(self.latency).await;
        }
        self.inner.check_and_insert(key, iat).await
    }
    fn is_strict(&self) -> bool {
        // Simulated backend advertises strict; the harness proves the
        // async pipeline actually respects that at construction time.
        true
    }
}

/// Build a `cnf`-bound token and its `ValidatedToken`, plus the
/// signing key material needed to mint DPoP proofs against it. The
/// `Es256Algorithm` here is the *DPoP holder key*, not the token
/// signer — the token is HMAC-signed with a distinct key inside
/// `make_validated`.
fn make_bench_context() -> (ValidatedToken, Es256Algorithm, Jwk) {
    let alg = Es256Algorithm::new_with_key_pair().unwrap();
    let jwk = Jwk::from_es256_verifying_key(alg.verifying_key()).unwrap();
    let thumbprint = jwk.thumbprint().unwrap();

    let scope = MoqtScopeBuilder::new()
        .full_access()
        .namespace_prefix(b"cdn.")
        .build();
    let token = CatTokenBuilder::new()
        .issuer("https://auth.example.com")
        .moqt_scope(scope)
        .confirmation(thumbprint)
        .build()
        .unwrap();

    let key = HmacSha256Algorithm::new(b"bench-key-for-async-scale-0000000");
    let encoded = encode_token(&token, &key).unwrap();
    let cat_validator =
        CatTokenValidator::dangerously_any_issuer().dangerously_allow_unencrypted_privacy_claims();
    let validated = Decoder::with_algorithm(&key)
        .decode(&encoded)
        .unwrap()
        .validate(&cat_validator)
        .unwrap();

    (validated, alg, jwk)
}

fn build_proof(
    alg: &Es256Algorithm,
    jwk: Jwk,
    validated: &ValidatedToken,
    index: usize,
) -> DpopProof {
    let mut proof = DpopProof::create_for_moqt(
        MoqtAction::Publish,
        vec![b"cdn.example.com".to_vec()],
        format!("/stream/{index}").as_bytes(),
        ALG_ES256,
        jwk,
    )
    .with_replay_id(generate_jti())
    .with_access_token_hash(compute_access_token_hash(validated.serialized()));
    proof.sign(alg).unwrap();
    proof
}

fn bench_async_authorize_scale(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let mut group = c.benchmark_group("async_authorize_scale");

    let (validated, alg, jwk) = make_bench_context();
    let validated = Arc::new(validated);

    let dpop_settings = CatDpopSettings::new()
        .with_window(300)
        .unwrap()
        .with_jti_processing(true);

    // Sweep across simulated backend latencies. 0 μs = local memory,
    // 100 μs = same-DC Redis, 1 ms = cross-DC or a slow shard.
    for &latency_us in [0u64, 100, 1_000].iter() {
        let latency = Duration::from_micros(latency_us);
        // 512 concurrent tasks per iteration — enough to expose lock
        // contention if the pre-commit path accidentally serialises on
        // shared state.
        const CONCURRENCY: usize = 512;

        // Pre-mint proofs so the timer measures the authorization +
        // JTI-commit path, not ES256 signing. Each request gets a
        // distinct JTI so the store admits it (no replay collision).
        let proofs: Vec<DpopProof> = (0..CONCURRENCY)
            .map(|i| build_proof(&alg, jwk.clone(), &validated, i))
            .collect();
        let proofs = Arc::new(proofs);

        group.throughput(criterion::Throughput::Elements(CONCURRENCY as u64));
        group.bench_with_input(
            BenchmarkId::new("latency_us", latency_us),
            &latency,
            |b, &latency| {
                b.iter(|| {
                    rt.block_on(async {
                        let store = Arc::new(LatencyStore::new(latency));
                        let store_dyn: Arc<dyn AsyncJtiStore> = store.clone();
                        let validator = AsyncMoqtValidator::strict(
                            MoqtValidator::new()
                                .dangerously_allow_missing_audience()
                                .dpop_best_effort(dpop_settings.clone()),
                            store_dyn,
                        )
                        .expect("strict store construction");

                        let mut tasks = Vec::with_capacity(CONCURRENCY);
                        for i in 0..CONCURRENCY {
                            let validated = Arc::clone(&validated);
                            let validator = validator.clone();
                            let proof = proofs[i].clone();
                            tasks.push(tokio::spawn(async move {
                                let request = RelayRequestContext::new(
                                    "relay",
                                    MoqtAction::Publish,
                                    vec![b"cdn.example.com".to_vec()],
                                    format!("/stream/{i}").into_bytes(),
                                )
                                .with_dpop_proof(proof);
                                validator.authorize(&validated, &request).await.is_ok()
                            }));
                        }
                        let mut ok = 0usize;
                        for t in tasks {
                            if t.await.unwrap() {
                                ok += 1;
                            }
                        }
                        // Store must have been called once per request; if
                        // this assertion ever regresses the bench is
                        // measuring the wrong thing (see finding P1).
                        assert_eq!(
                            store.calls(),
                            CONCURRENCY as u64,
                            "LatencyStore must be invoked once per authorize call"
                        );
                        assert_eq!(ok, CONCURRENCY, "every DPoP-bound request should authorize");
                        black_box(ok)
                    })
                })
            },
        );
    }

    group.finish();
}

criterion_group!(benches, bench_async_authorize_scale);
criterion_main!(benches);
