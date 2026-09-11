// SPDX-FileCopyrightText: Copyright (c) 2022 Quicr
// SPDX-License-Identifier: BSD-2-Clause

#![cfg(feature = "moqt")]

//! Runs `cat_token::jti_contract` against the two strict stores shipped
//! by the crate. The harness itself is the CDN-integration proof gate;
//! passing it here demonstrates the contract is *satisfiable*, not that
//! any distributed backend has been validated. Backend implementers
//! fork this file, swap the store type, and run the same suite against
//! their Redis/DynamoDB/Cassandra impl.

use cat_token::CatError;
use cat_token::InMemoryStrictJtiStore;
use cat_token::JtiStore;
use cat_token::jti_contract;
use std::sync::Arc;

#[test]
fn strict_in_memory_store_meets_contract() {
    let store = InMemoryStrictJtiStore::new(300, 1024);
    jti_contract::assert_no_dropped_insert_within_ttl(&store, 1);
    // Distinct-key + atomicity assertions need Sync — InMemoryStrictJtiStore
    // holds a Mutex so it satisfies that.
    let store = InMemoryStrictJtiStore::new(300, 1024);
    jti_contract::assert_distinct_keys_never_collide(&store, 256);
    let store = InMemoryStrictJtiStore::new(300, 1024);
    jti_contract::assert_atomic_insert_if_absent(&store, 32);
}

/// A store whose `check_and_insert` always errors, simulating a backend
/// outage. Used to prove the harness catches silent-success bugs.
struct OutageStore;
impl JtiStore for OutageStore {
    fn check_and_insert(&self, _key: String, _iat: i64) -> Result<(), CatError> {
        Err(CatError::BackendUnavailable("simulated outage".to_string()))
    }
    fn len(&self) -> usize {
        0
    }
    fn is_strict(&self) -> bool {
        true
    }
}

#[test]
fn outage_probe_surfaces_crypto_error() {
    jti_contract::assert_fail_closed_on_backend_outage(&OutageStore);
}

#[cfg(feature = "async")]
mod async_contract {
    use super::*;
    use async_trait::async_trait;
    use cat_token::AsyncInMemoryStrictJtiStore;
    use cat_token::r#async::AsyncJtiStore;
    use cat_token::jti_contract::asynchronous;

    #[tokio::test]
    async fn async_strict_in_memory_store_meets_contract() {
        let store = AsyncInMemoryStrictJtiStore::new(1024);
        asynchronous::assert_no_dropped_insert_within_ttl(&store, 1).await;

        let store: Arc<dyn AsyncJtiStore> = Arc::new(AsyncInMemoryStrictJtiStore::new(1024));
        asynchronous::assert_atomic_insert_if_absent(store, 32).await;
    }

    struct AsyncOutageStore;
    #[async_trait]
    impl AsyncJtiStore for AsyncOutageStore {
        async fn check_and_insert(&self, _key: String, _iat: i64) -> Result<(), CatError> {
            Err(CatError::BackendUnavailable("simulated outage".to_string()))
        }
        fn is_strict(&self) -> bool {
            true
        }
    }

    #[tokio::test]
    async fn async_outage_probe_surfaces_crypto_error() {
        asynchronous::assert_fail_closed_on_backend_outage(&AsyncOutageStore).await;
    }
}
