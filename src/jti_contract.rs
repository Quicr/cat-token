// SPDX-FileCopyrightText: Copyright (c) 2022 Quicr
// SPDX-License-Identifier: BSD-2-Clause

//! Contract-test harness for [`JtiStore`] and [`AsyncJtiStore`] backends.
//!
//! A distributed replay store (Redis, DynamoDB with strong consistency,
//! Cassandra LWT, etc.) cannot be proven correct just by reading its
//! rustdoc: real CDN scale exposes atomicity races, TTL misconfiguration,
//! and outage-behavior bugs that only appear under contention. This
//! module ships the property tests every strict-store implementation
//! must pass before it is deployed at CDN scale.
//!
//! # What this proves
//!
//! Each check corresponds to one clause of the strict-store contract
//! documented on [`JtiStore::is_strict`]. Passing the full battery is
//! NECESSARY but not SUFFICIENT: it demonstrates the store behaves
//! correctly under contention this harness produced, not that the
//! deployed backend has TTL configured correctly or fails closed on the
//! particular network partition your relay sees. Wire this into your
//! integration CI *and* run a soak on production-shaped traffic.
//!
//! - [`assert_no_dropped_insert_within_ttl`] — a JTI accepted by
//!   `check_and_insert` must remain observable (subsequent duplicates
//!   rejected) for at least the freshness window. Fails a store that
//!   silently sheds under memory pressure.
//! - [`assert_distinct_keys_never_collide`] — inserting N distinct JTIs
//!   from concurrent threads/tasks must not report any of them as
//!   replay. Fails a store whose hash-partition or LRU shard behavior
//!   introduces false positives.
//! - [`assert_atomic_insert_if_absent`] — N concurrent inserts of the
//!   same JTI must succeed exactly once and be rejected as replay for
//!   the other N-1. Fails a check-then-set implementation that races.
//! - [`assert_fail_closed_on_backend_outage`] — an unavailable backend
//!   must surface [`CatError::CryptoError`], not silently accept the
//!   insert. Fails a client that retries into swallowed errors.
//!
//! # How to use
//!
//! In your backend crate, add a test file that constructs the store and
//! calls each assertion. Because these are ordinary functions (not
//! `#[test]`), you can compose them into your own tokio/async-std/smol
//! test runner:
//!
//! ```ignore
//! use cat_token::jti_contract;
//!
//! #[test]
//! fn my_redis_store_meets_strict_contract() {
//!     let store = MyRedisJtiStore::new(/* ... */);
//!     jti_contract::assert_no_dropped_insert_within_ttl(&store, 300);
//!     jti_contract::assert_distinct_keys_never_collide(&store, 1000);
//!     jti_contract::assert_atomic_insert_if_absent(&store, 64);
//! }
//! ```
//!
//! Async equivalents live under [`self::asynchronous`] when the crate is
//! built with `--features async`.

use crate::JtiStore;
use crate::error::CatError;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;

/// Smoke test: an accepted JTI must be rejected on immediate re-insert.
/// Named `_within_ttl` because it is the minimum a strict store must
/// satisfy inside its freshness window, but this harness does not
/// exercise time passage, memory pressure, or cross-node retention —
/// those need a soak against production-shaped traffic. A store that
/// passes this and then drops entries under load will still fail at
/// scale; treat this as a canary, not a TTL proof.
pub fn assert_no_dropped_insert_within_ttl(store: &dyn JtiStore, iat: i64) {
    let key = "contract-test-jti-single".to_string();
    store
        .check_and_insert(key.clone(), iat)
        .expect("first insert must succeed");
    match store.check_and_insert(key, iat) {
        Err(CatError::ReplayAttackDetected) => {}
        Ok(()) => panic!(
            "strict store dropped a JTI inside its freshness window; \
             duplicate insert unexpectedly succeeded"
        ),
        Err(other) => panic!("strict store surfaced unexpected error on duplicate: {other:?}"),
    }
}

/// Assert that inserting `n` *distinct* JTIs concurrently never reports
/// any of them as replay. Fails a store whose sharding or hashing
/// produces false collisions.
///
/// Uses `std::thread`; safe to call from a synchronous test runner.
pub fn assert_distinct_keys_never_collide(store: &(dyn JtiStore + Sync), n: usize) {
    // Requires interior sharing; wrap in Arc under the hood.
    let store_arc: Arc<&(dyn JtiStore + Sync)> = Arc::new(store);
    let false_replays = Arc::new(AtomicUsize::new(0));

    thread::scope(|scope| {
        for i in 0..n {
            let store = Arc::clone(&store_arc);
            let counter = Arc::clone(&false_replays);
            scope.spawn(move || {
                let key = format!("contract-distinct-{i}");
                match store.check_and_insert(key, 1) {
                    Ok(()) => {}
                    Err(CatError::ReplayAttackDetected) => {
                        counter.fetch_add(1, Ordering::Relaxed);
                    }
                    Err(other) => panic!("unexpected backend error: {other:?}"),
                }
            });
        }
    });

    let false_replays = false_replays.load(Ordering::Relaxed);
    assert_eq!(
        false_replays, 0,
        "store reported {false_replays} false collisions among {n} distinct JTIs"
    );
}

/// Assert insert-if-absent atomicity: `n` concurrent inserts of the
/// *same* JTI must succeed exactly once. If the store implements the
/// operation as check-then-set instead of an atomic upsert, some inserts
/// will both see "not present" and both succeed — this harness catches
/// that.
pub fn assert_atomic_insert_if_absent(store: &(dyn JtiStore + Sync), n: usize) {
    let key = "contract-atomic-shared".to_string();
    let successes = Arc::new(AtomicUsize::new(0));
    let replay_rejections = Arc::new(AtomicUsize::new(0));
    let store_arc: Arc<&(dyn JtiStore + Sync)> = Arc::new(store);

    thread::scope(|scope| {
        for _ in 0..n {
            let store = Arc::clone(&store_arc);
            let key = key.clone();
            let successes = Arc::clone(&successes);
            let replay_rejections = Arc::clone(&replay_rejections);
            scope.spawn(move || match store.check_and_insert(key, 1) {
                Ok(()) => {
                    successes.fetch_add(1, Ordering::Relaxed);
                }
                Err(CatError::ReplayAttackDetected) => {
                    replay_rejections.fetch_add(1, Ordering::Relaxed);
                }
                Err(other) => panic!("unexpected backend error: {other:?}"),
            });
        }
    });

    let successes = successes.load(Ordering::Relaxed);
    let rejections = replay_rejections.load(Ordering::Relaxed);
    assert_eq!(
        successes, 1,
        "atomic insert-if-absent violated: {successes} successful inserts of the same JTI \
         (expected exactly 1)"
    );
    assert_eq!(
        rejections,
        n - 1,
        "expected {} replay rejections, got {}",
        n - 1,
        rejections
    );
}

/// Assert that a store which cannot reach its backend surfaces
/// [`CatError::CryptoError`] on `check_and_insert`. Silent success on
/// outage is the highest-severity failure mode — it authorizes a request
/// whose replay defense has been bypassed. Integrators pass an
/// implementation of [`JtiStore`] that simulates their outage path (a
/// broken Redis client, a null-route DynamoDB, etc.); the harness
/// asserts the correct error surface.
pub fn assert_fail_closed_on_backend_outage(outage_store: &dyn JtiStore) {
    match outage_store.check_and_insert("outage-probe".to_string(), 1) {
        Err(CatError::CryptoError(_)) => {}
        Ok(()) => panic!(
            "store silently accepted an insert while the backend was \
             unreachable — replay defense is bypassed"
        ),
        Err(other) => panic!("outage must surface CatError::CryptoError; got {other:?}"),
    }
}

#[cfg(feature = "async")]
pub mod asynchronous {
    //! Async siblings of the contract assertions. Same semantics; each
    //! function awaits on the store instead of blocking.

    use crate::r#async::AsyncJtiStore;
    use crate::error::CatError;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Async sibling of [`super::assert_no_dropped_insert_within_ttl`].
    /// Smoke test only: catches a store that drops entries between
    /// consecutive calls; does not exercise time passage or contention.
    pub async fn assert_no_dropped_insert_within_ttl(store: &dyn AsyncJtiStore, iat: i64) {
        let key = "contract-async-single".to_string();
        store
            .check_and_insert(key.clone(), iat)
            .await
            .expect("first insert must succeed");
        match store.check_and_insert(key, iat).await {
            Err(CatError::ReplayAttackDetected) => {}
            Ok(()) => panic!("async strict store dropped a JTI inside its freshness window"),
            Err(other) => {
                panic!("async strict store surfaced unexpected error on duplicate: {other:?}")
            }
        }
    }

    /// Async sibling of [`super::assert_atomic_insert_if_absent`]. Drives
    /// N inserts of the same JTI concurrently via [`futures::future::join_all`],
    /// so a check-then-set implementation admits more than one success
    /// and fails the assertion. `join_all` runs the futures on the
    /// caller's task and polls them cooperatively — it does not pick a
    /// runtime (tokio/async-std/smol are all supported) but it does
    /// interleave the futures at every await point, which is what races
    /// a non-atomic read-modify-write inside the store.
    ///
    /// If the store's `check_and_insert` awaits on I/O, a caller who
    /// wants worker-thread parallelism on top of interleaving can wrap
    /// each call in `tokio::spawn` outside the harness.
    pub async fn assert_atomic_insert_if_absent(store: Arc<dyn AsyncJtiStore>, n: usize) {
        let key = "contract-async-atomic".to_string();
        let successes = Arc::new(AtomicUsize::new(0));
        let rejections = Arc::new(AtomicUsize::new(0));

        let mut futures = Vec::with_capacity(n);
        for _ in 0..n {
            let store = Arc::clone(&store);
            let key = key.clone();
            let successes = Arc::clone(&successes);
            let rejections = Arc::clone(&rejections);
            futures.push(async move {
                match store.check_and_insert(key, 1).await {
                    Ok(()) => {
                        successes.fetch_add(1, Ordering::Relaxed);
                    }
                    Err(CatError::ReplayAttackDetected) => {
                        rejections.fetch_add(1, Ordering::Relaxed);
                    }
                    Err(other) => panic!("unexpected backend error: {other:?}"),
                }
            });
        }
        ::futures::future::join_all(futures).await;

        let successes = successes.load(Ordering::Relaxed);
        let rejections = rejections.load(Ordering::Relaxed);
        assert_eq!(
            successes, 1,
            "async atomic insert-if-absent violated: {successes} successful inserts \
             (expected exactly 1)"
        );
        assert_eq!(
            rejections,
            n - 1,
            "expected {} replay rejections, got {}",
            n - 1,
            rejections
        );
    }

    pub async fn assert_fail_closed_on_backend_outage(outage_store: &dyn AsyncJtiStore) {
        match outage_store
            .check_and_insert("outage-probe".to_string(), 1)
            .await
        {
            Err(CatError::CryptoError(_)) => {}
            Ok(()) => panic!(
                "async store silently accepted an insert while the backend was \
                 unreachable — replay defense is bypassed"
            ),
            Err(other) => panic!("outage must surface CatError::CryptoError; got {other:?}"),
        }
    }
}
