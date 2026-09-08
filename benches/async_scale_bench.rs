// SPDX-FileCopyrightText: Copyright (c) 2022 Quicr
// SPDX-License-Identifier: BSD-2-Clause

//! Scale bench for `AsyncMoqtValidator::authorize_async`.
//!
//! The realistic CDN failure mode is not sync-path CPU — the P0-1 audit
//! path already benches that. It's async-path tail latency when the
//! DPoP JTI store is a remote service adding p50/p99 delay to every
//! request. This bench pins the async pipeline against a
//! latency-injecting store so a regression in the pre-commit/commit
//! split shows up as tail-latency growth, not just throughput drop.
//!
//! Run with:
//!   cargo bench --bench async_scale_bench --features async
//!
//! This bench proves the CI-runnable half of finding (3). A real 100k-
//! flow soak requires actual infrastructure — the bench catches
//! regressions between soaks; the soak proves the deployment.

use cat_token::r#async::{AsyncInMemoryStrictJtiStore, AsyncJtiStore, AsyncMoqtValidator};
use cat_token::prelude::*;
use cat_token::{CatError, HmacSha256Algorithm};
use criterion::{BenchmarkId, Criterion, black_box, criterion_group, criterion_main};
use std::sync::Arc;
use std::time::Duration;
use tokio::runtime::Runtime;

/// A store that adds a fixed async delay before delegating to an inner
/// strict store. Simulates the round-trip cost of a Redis/DynamoDB call
/// without pulling in a network dependency. Real backends have p50/p99
/// distributions rather than a fixed floor; a follow-up bench can inject
/// a histogram, but the fixed floor is enough to catch pipeline
/// regressions that change per-call work.
struct LatencyStore {
    inner: AsyncInMemoryStrictJtiStore,
    latency: Duration,
}

impl LatencyStore {
    fn new(latency: Duration) -> Self {
        Self {
            inner: AsyncInMemoryStrictJtiStore::new(),
            latency,
        }
    }
}

#[async_trait::async_trait]
impl AsyncJtiStore for LatencyStore {
    async fn check_and_insert(&self, key: String, iat: i64) -> Result<(), CatError> {
        tokio::time::sleep(self.latency).await;
        self.inner.check_and_insert(key, iat).await
    }
    fn is_strict(&self) -> bool {
        // Simulated backend advertises strict; the harness proves the
        // async pipeline actually respects that at construction time.
        true
    }
}

fn make_validated(token: &CatToken) -> ValidatedToken {
    let key = HmacSha256Algorithm::new(b"bench-key-for-async-scale-0000000");
    let encoded = encode_token(token, &key).unwrap();
    let validator = CatTokenValidator::new().allow_unencrypted_privacy_claims();
    decode_token(&encoded, &key)
        .unwrap()
        .validate(&validator)
        .unwrap()
}

fn bench_async_authorize_scale(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let mut group = c.benchmark_group("async_authorize_scale");

    // Build one token/validator; iterate distinct requests (different
    // tracks) so the pipeline exercises the JTI commit each iteration.
    let scope = MoqtScopeBuilder::new()
        .full_access()
        .namespace_prefix(b"cdn.")
        .build();
    let token = CatTokenBuilder::new()
        .issuer("https://auth.example.com")
        .moqt_scope(scope)
        .build()
        .unwrap();
    let validated = Arc::new(make_validated(&token));

    // Sweep across simulated backend latencies. 0 μs = local memory,
    // 100 μs = same-DC Redis, 1 ms = cross-DC or a slow shard.
    for &latency_us in [0u64, 100, 1_000].iter() {
        let latency = Duration::from_micros(latency_us);
        // 512 concurrent tasks per iteration — enough to expose lock
        // contention if the pre-commit path accidentally serialises on
        // shared state.
        const CONCURRENCY: usize = 512;

        group.throughput(criterion::Throughput::Elements(CONCURRENCY as u64));
        group.bench_with_input(
            BenchmarkId::new("latency_us", latency_us),
            &latency,
            |b, &latency| {
                b.iter(|| {
                    rt.block_on(async {
                        let store: Arc<dyn AsyncJtiStore> = Arc::new(LatencyStore::new(latency));
                        let validator = AsyncMoqtValidator::try_from_sync_strict(
                            MoqtValidator::new().allow_missing_audience(),
                            store,
                        )
                        .expect("strict store construction");

                        let mut tasks = Vec::with_capacity(CONCURRENCY);
                        for i in 0..CONCURRENCY {
                            let validated = Arc::clone(&validated);
                            let validator = validator.clone();
                            tasks.push(tokio::spawn(async move {
                                let request = RelayRequestContext::new(
                                    "relay",
                                    MoqtAction::Publish,
                                    vec![b"cdn.example.com".to_vec()],
                                    format!("/stream/{i}").into_bytes(),
                                );
                                validator
                                    .authorize_async(&validated, &request, None, None)
                                    .await
                                    .is_ok()
                            }));
                        }
                        let mut ok = 0usize;
                        for t in tasks {
                            if t.await.unwrap() {
                                ok += 1;
                            }
                        }
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
