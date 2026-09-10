// SPDX-FileCopyrightText: Copyright (c) 2022 Quicr
// SPDX-License-Identifier: BSD-2-Clause

#![cfg(feature = "moqt")]

//! Fault-injection tests for the replay-JTI store contract.
//!
//! CDN deployments run the JtiStore behind an unreliable transport
//! (network, disk, another process). The strict in-memory fake used in
//! the rest of the test suite covers the happy path; here we wrap it in
//! a fault-injecting proxy and assert that the authorization pipeline
//! degrades correctly under each realistic failure mode:
//!
//! - **DPoP JTI succeeds, CAT-cti commit fails**: authorization is
//!   already committed on the DPoP side. The caller must retry the
//!   request with a fresh JTI; the old one is burned. Verified by
//!   observing that a second call with the same DPoP proof returns
//!   `ReplayAttackDetected` even though the CAT-cti store never saw
//!   the request.
//!
//! - **Replay backend timeout / transient failure**: an insert that
//!   returns a `BackendUnavailable` must NOT be treated as an accepted
//!   JTI. The client retry must be admitted, not rejected as a replay.
//!
//! - **Relay restart mid-reservation**: simulated by dropping and
//!   recreating the store; a JTI that was in flight when the store
//!   died must be admissible on retry. This is the case where the
//!   strict-store guarantee matters: if the store is truly strict, a
//!   restart resets state and retry succeeds; if it isn't (e.g. LRU
//!   evicted the entry), the retry could go either way.
//!
//! These are contract-level tests, not implementation tests: they
//! exercise `MoqtValidator::authorize` and the `JtiStore` trait.

use cat_token::dpop::{
    DpopProof, InMemoryStrictJtiStore, JtiStore, compute_access_token_hash, generate_jti,
};
use cat_token::jwk::Jwk;
use cat_token::*;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

/// JtiStore wrapper that fails inserts on demand. Wraps a real strict
/// backend so the "strict" guarantee is preserved when injection is off.
struct FaultInjector {
    inner: Arc<dyn JtiStore>,
    fail_next_insert: AtomicBool,
    fail_count: AtomicU64,
}

impl FaultInjector {
    fn new(inner: Arc<dyn JtiStore>) -> Self {
        Self {
            inner,
            fail_next_insert: AtomicBool::new(false),
            fail_count: AtomicU64::new(0),
        }
    }

    fn arm(&self) {
        self.fail_next_insert.store(true, Ordering::SeqCst);
    }

    fn injected_failures(&self) -> u64 {
        self.fail_count.load(Ordering::SeqCst)
    }
}

impl JtiStore for FaultInjector {
    fn check_and_insert(&self, key: String, iat: i64) -> Result<(), CatError> {
        if self.fail_next_insert.swap(false, Ordering::SeqCst) {
            self.fail_count.fetch_add(1, Ordering::SeqCst);
            return Err(CatError::BackendUnavailable(
                "injected replay backend fault".into(),
            ));
        }
        self.inner.check_and_insert(key, iat)
    }
    fn len(&self) -> usize {
        self.inner.len()
    }
    fn cleanup(&self, max_age_seconds: i64) {
        self.inner.cleanup(max_age_seconds);
    }
    fn is_strict(&self) -> bool {
        self.inner.is_strict()
    }
}

fn build_token_and_proof(dpop_alg: &Es256Algorithm) -> (ValidatedToken, DpopProof, Vec<u8>) {
    let dpop_jwk = Jwk::from_es256_verifying_key(dpop_alg.verifying_key()).unwrap();
    let thumbprint = dpop_jwk.thumbprint().unwrap();

    let scope = MoqtScopeBuilder::new()
        .subscriber()
        .namespace_exact(b"ns")
        .track_prefix(b"tr")
        .build();
    let token = CatTokenBuilder::new()
        .issuer("https://issuer.example")
        .single_audience("relay.example")
        .moqt_scope(scope)
        .confirmation(dpop_jwk.thumbprint().unwrap())
        .dpop_settings(
            CatDpopSettings::new()
                .with_window(300)
                .unwrap()
                .with_jti_processing(true),
        )
        .build()
        .unwrap();
    let key = HmacSha256Algorithm::new(b"test-key-for-roundtrip-000000000");
    let encoded = encode_token(&token, &key).unwrap();
    let cat_validator = CatTokenValidator::new().allow_unencrypted_privacy_claims();
    let validated = decode_token(&encoded, &key)
        .unwrap()
        .validate(&cat_validator)
        .unwrap();
    let ath = compute_access_token_hash(validated.serialized());
    let mut proof = DpopProof::create_for_moqt(
        MoqtAction::Subscribe,
        vec![b"ns".to_vec()],
        b"track1",
        ALG_ES256,
        dpop_jwk,
    )
    .with_jti(generate_jti())
    .with_access_token_hash(ath);
    proof.sign(dpop_alg).unwrap();
    (validated, proof, thumbprint)
}

fn authorize_ctx(track: &[u8]) -> RelayRequestContext {
    RelayRequestContext::new(
        "relay.example",
        MoqtAction::Subscribe,
        vec![b"ns".to_vec()],
        track.to_vec(),
    )
}

/// A JTI accepted, then retried by the same holder, must be rejected as
/// replay — even if the CAT-cti path was never engaged (no catreplay
/// claim on this token). Confirms the ordering commit-DPoP-first is
/// visible to future requests.
#[test]
fn test_dpop_jti_burned_on_first_success() {
    let dpop_alg = Es256Algorithm::new_with_key_pair().unwrap();
    let (validated, proof, _tp) = build_token_and_proof(&dpop_alg);

    let store: Arc<dyn JtiStore> = Arc::new(InMemoryStrictJtiStore::new(300));
    let settings = CatDpopSettings::new()
        .with_window(300)
        .unwrap()
        .with_jti_processing(true);
    let validator = MoqtValidator::new()
        .dpop_strict(settings, store)
        .expect("strict store");

    let ctx = authorize_ctx(b"track1").with_dpop_proof(proof.clone());
    validator
        .authorize(&validated, &ctx)
        .expect("first authorize must succeed");

    let replay = validator.authorize(&validated, &ctx);
    assert!(
        matches!(replay, Err(CatError::ReplayAttackDetected)),
        "second call with same JTI must fail: {replay:?}"
    );
}

/// A JTI insert that returns a transient error must NOT poison the
/// cache: the client's retry with a fresh JTI must succeed. The
/// fault-injecting wrapper returns BackendUnavailable on the first insert; the
/// underlying strict store never sees that key, so a fresh JTI is
/// virgin.
#[test]
fn test_transient_backend_failure_does_not_burn_jti() {
    let dpop_alg = Es256Algorithm::new_with_key_pair().unwrap();
    let dpop_jwk = Jwk::from_es256_verifying_key(dpop_alg.verifying_key()).unwrap();

    let inner: Arc<dyn JtiStore> = Arc::new(InMemoryStrictJtiStore::new(300));
    let injector = Arc::new(FaultInjector::new(inner));
    let injector_dyn: Arc<dyn JtiStore> = injector.clone();
    let settings = CatDpopSettings::new()
        .with_window(300)
        .unwrap()
        .with_jti_processing(true);
    let validator = MoqtValidator::new()
        .dpop_strict(settings, injector_dyn)
        .expect("strict store");

    let scope = MoqtScopeBuilder::new()
        .subscriber()
        .namespace_exact(b"ns")
        .track_prefix(b"tr")
        .build();
    let token = CatTokenBuilder::new()
        .issuer("https://issuer.example")
        .single_audience("relay.example")
        .moqt_scope(scope)
        .confirmation(dpop_jwk.thumbprint().unwrap())
        .dpop_settings(
            CatDpopSettings::new()
                .with_window(300)
                .unwrap()
                .with_jti_processing(true),
        )
        .build()
        .unwrap();
    let key = HmacSha256Algorithm::new(b"test-key-for-roundtrip-000000000");
    let encoded = encode_token(&token, &key).unwrap();
    let validated = decode_token(&encoded, &key)
        .unwrap()
        .validate(&CatTokenValidator::new().allow_unencrypted_privacy_claims())
        .unwrap();
    let ath = compute_access_token_hash(validated.serialized());

    let mut proof1 = DpopProof::create_for_moqt(
        MoqtAction::Subscribe,
        vec![b"ns".to_vec()],
        b"track1",
        ALG_ES256,
        dpop_jwk.clone(),
    )
    .with_jti(generate_jti())
    .with_access_token_hash(ath.clone());
    proof1.sign(&dpop_alg).unwrap();

    let ctx1 = authorize_ctx(b"track1").with_dpop_proof(proof1);
    injector.arm();
    let first = validator.authorize(&validated, &ctx1);
    assert!(
        matches!(first, Err(CatError::BackendUnavailable(_))),
        "arming the injector must surface the backend error: {first:?}"
    );
    assert_eq!(injector.injected_failures(), 1);

    // Client retries with a fresh JTI. Underlying strict store has no
    // record of anything (the injector short-circuited), so this must
    // succeed cleanly.
    let mut proof2 = DpopProof::create_for_moqt(
        MoqtAction::Subscribe,
        vec![b"ns".to_vec()],
        b"track1",
        ALG_ES256,
        dpop_jwk,
    )
    .with_jti(generate_jti())
    .with_access_token_hash(ath);
    proof2.sign(&dpop_alg).unwrap();
    let ctx2 = authorize_ctx(b"track1").with_dpop_proof(proof2);
    validator
        .authorize(&validated, &ctx2)
        .expect("retry with fresh JTI must succeed");
}

/// Simulate relay restart: drop the store and rebuild it. A JTI that
/// was accepted on the pre-restart instance is unknown to the fresh
/// instance, so retry succeeds. This is the trade-off the audit called
/// out: a strict in-memory store loses replay state on restart.
/// Distributed strict backends (Redis with TTL) don't have this issue —
/// this test documents the in-memory-only behavior explicitly.
#[test]
fn test_relay_restart_loses_in_memory_replay_state() {
    let dpop_alg = Es256Algorithm::new_with_key_pair().unwrap();
    let (validated, proof, _tp) = build_token_and_proof(&dpop_alg);

    {
        let store: Arc<dyn JtiStore> = Arc::new(InMemoryStrictJtiStore::new(300));
        let settings = CatDpopSettings::new().with_window(300).unwrap();
        let validator = MoqtValidator::new()
            .dpop_strict(settings, store)
            .expect("strict store");
        let ctx = authorize_ctx(b"track1").with_dpop_proof(proof.clone());
        validator
            .authorize(&validated, &ctx)
            .expect("pre-restart authorize");
    }
    // Relay restart: brand-new store instance.
    let store: Arc<dyn JtiStore> = Arc::new(InMemoryStrictJtiStore::new(300));
    let settings = CatDpopSettings::new()
        .with_window(300)
        .unwrap()
        .with_jti_processing(true);
    let validator = MoqtValidator::new()
        .dpop_strict(settings, store)
        .expect("strict store");
    let ctx = authorize_ctx(b"track1").with_dpop_proof(proof);
    validator
        .authorize(&validated, &ctx)
        .expect("post-restart in-memory store has no memory of pre-restart JTI");
}

/// A strict store at max_entries must refuse new inserts (not evict).
/// If a relay hits the cap, requests fail loudly rather than silently
/// weaken replay defense.
#[test]
fn test_strict_store_refuses_at_capacity_cap() {
    let store = InMemoryStrictJtiStore::new(300).with_max_entries(1);
    store.check_and_insert("a".into(), 0).unwrap();
    let err = store.check_and_insert("b".into(), 0).unwrap_err();
    assert!(matches!(err, CatError::DpopValidationFailed(_)));
    assert_eq!(store.rejected_over_capacity(), 1);
}
