// SPDX-FileCopyrightText: Copyright (c) 2022 Quicr
// SPDX-License-Identifier: BSD-2-Clause

#![cfg(all(feature = "moqt", feature = "async"))]

//! Exercises the async authorize pipeline end-to-end. The point of these
//! tests is not to duplicate the sync suite — the pre-commit checks share
//! the same implementation — but to prove that the two commit points
//! (DPoP JTI and catreplay cti) go through the async trait surface and
//! that fail-closed behaviour is preserved when a store returns an error.

use async_trait::async_trait;
use cat_token::r#async::{
    AsyncInMemoryStrictJtiStore, AsyncJtiStore, AsyncMoqtValidator, AsyncReplayGuard,
};
use cat_token::dpop::{DpopProof, compute_access_token_hash, generate_jti};
use cat_token::jwk::Jwk;
use cat_token::*;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

fn make_validated(token: &CatToken) -> ValidatedToken {
    let key = HmacSha256Algorithm::new(b"test-key-for-roundtrip-000000000");
    let encoded = encode_token(token, &key).unwrap();
    let validator = CatTokenValidator::new().allow_unencrypted_privacy_claims();
    decode_token(&encoded, &key)
        .unwrap()
        .validate(&validator)
        .unwrap()
}

fn moqt_scope() -> cat_token::MoqtScope {
    cat_token::moqt::MoqtScopeBuilder::new()
        .action(MoqtAction::Publish)
        .namespace_exact(b"ns")
        .build()
}

fn build_dpop_proof(alg: &Es256Algorithm, jwk: Jwk, validated: &ValidatedToken) -> DpopProof {
    let mut proof = DpopProof::create_for_moqt(
        MoqtAction::Publish,
        vec![b"ns".to_vec()],
        b"track",
        ALG_ES256,
        jwk,
    )
    .with_jti(generate_jti())
    .with_access_token_hash(compute_access_token_hash(validated.serialized()));
    proof.sign(alg).unwrap();
    proof
}

#[tokio::test]
async fn async_authorize_happy_path_commits_jti() {
    let alg = Es256Algorithm::new_with_key_pair().unwrap();
    let jwk = Jwk::from_es256_verifying_key(alg.verifying_key()).unwrap();
    let thumbprint = jwk.thumbprint().unwrap();

    let token = CatTokenBuilder::new()
        .issuer("https://test.com")
        .single_audience("relay")
        .moqt_scope(moqt_scope())
        .confirmation(thumbprint)
        .build()
        .unwrap();
    let validated = make_validated(&token);

    let proof = build_dpop_proof(&alg, jwk, &validated);

    let settings = CatDpopSettings::new()
        .with_window(300)
        .unwrap()
        .with_jti_processing(true);
    let sync = cat_token::moqt::MoqtValidator::new().with_dpop_validation(settings);
    let store = Arc::new(AsyncInMemoryStrictJtiStore::new());
    let validator = AsyncMoqtValidator::try_from_sync_strict(sync, store.clone())
        .expect("strict store construction");

    let request = cat_token::moqt::RelayRequestContext::new(
        "relay",
        MoqtAction::Publish,
        vec![b"ns".to_vec()],
        b"track".to_vec(),
    )
    .with_dpop_proof(proof);

    validator
        .authorize_async(&validated, &request, None, None)
        .await
        .expect("async authorize should succeed");

    assert_eq!(store.len(), 1, "async pipeline must commit the JTI");
}

#[tokio::test]
async fn async_authorize_rejects_replayed_jti() {
    let alg = Es256Algorithm::new_with_key_pair().unwrap();
    let jwk = Jwk::from_es256_verifying_key(alg.verifying_key()).unwrap();
    let thumbprint = jwk.thumbprint().unwrap();

    let token = CatTokenBuilder::new()
        .issuer("https://test.com")
        .single_audience("relay")
        .moqt_scope(moqt_scope())
        .confirmation(thumbprint)
        .build()
        .unwrap();
    let validated = make_validated(&token);

    // Same proof (same JTI) used twice — the second must fail replay.
    let proof = build_dpop_proof(&alg, jwk, &validated);

    let settings = CatDpopSettings::new()
        .with_window(300)
        .unwrap()
        .with_jti_processing(true);
    let sync = cat_token::moqt::MoqtValidator::new().with_dpop_validation(settings);
    let store: Arc<dyn AsyncJtiStore> = Arc::new(AsyncInMemoryStrictJtiStore::new());
    let validator =
        AsyncMoqtValidator::try_from_sync_strict(sync, store).expect("strict store construction");

    let request = cat_token::moqt::RelayRequestContext::new(
        "relay",
        MoqtAction::Publish,
        vec![b"ns".to_vec()],
        b"track".to_vec(),
    )
    .with_dpop_proof(proof);

    validator
        .authorize_async(&validated, &request, None, None)
        .await
        .expect("first authorize succeeds");

    let err = validator
        .authorize_async(&validated, &request, None, None)
        .await
        .expect_err("replay must fail");
    assert!(
        matches!(err, CatError::ReplayAttackDetected),
        "expected ReplayAttackDetected, got {err:?}"
    );
}

/// A backend that always errors — used to prove the async pipeline fails
/// closed rather than silently authorizing when the store is
/// unavailable.
struct FaultyJtiStore;

#[async_trait]
impl AsyncJtiStore for FaultyJtiStore {
    async fn check_and_insert(&self, _key: String, _iat: i64) -> Result<(), CatError> {
        Err(CatError::CryptoError("simulated outage".to_string()))
    }
    fn is_strict(&self) -> bool {
        // We're asserting the fail-closed contract, not the strictness
        // one, but returning true here mirrors what a real distributed
        // strict store would advertise before it goes down.
        true
    }
}

#[tokio::test]
async fn async_authorize_fails_closed_on_store_outage() {
    let alg = Es256Algorithm::new_with_key_pair().unwrap();
    let jwk = Jwk::from_es256_verifying_key(alg.verifying_key()).unwrap();
    let thumbprint = jwk.thumbprint().unwrap();

    let token = CatTokenBuilder::new()
        .issuer("https://test.com")
        .single_audience("relay")
        .moqt_scope(moqt_scope())
        .confirmation(thumbprint)
        .build()
        .unwrap();
    let validated = make_validated(&token);
    let proof = build_dpop_proof(&alg, jwk, &validated);

    let settings = CatDpopSettings::new()
        .with_window(300)
        .unwrap()
        .with_jti_processing(true);
    let sync = cat_token::moqt::MoqtValidator::new().with_dpop_validation(settings);
    let validator = AsyncMoqtValidator::try_from_sync_strict(sync, Arc::new(FaultyJtiStore))
        .expect("FaultyJtiStore advertises is_strict = true");

    let request = cat_token::moqt::RelayRequestContext::new(
        "relay",
        MoqtAction::Publish,
        vec![b"ns".to_vec()],
        b"track".to_vec(),
    )
    .with_dpop_proof(proof);

    let err = validator
        .authorize_async(&validated, &request, None, None)
        .await
        .expect_err("store outage must fail authorization closed");
    assert!(
        matches!(err, CatError::CryptoError(_)),
        "expected CryptoError, got {err:?}"
    );
}

/// A store that advertises non-strict behaviour. Passing this to
/// `try_from_sync_strict` MUST fail — the CDN construction contract
/// refuses backends that could evict a retained JTI inside the freshness
/// window.
struct NonStrictJtiStore;

#[async_trait]
impl AsyncJtiStore for NonStrictJtiStore {
    async fn check_and_insert(&self, _key: String, _iat: i64) -> Result<(), CatError> {
        Ok(())
    }
    fn is_strict(&self) -> bool {
        false
    }
}

#[test]
fn async_validator_refuses_non_strict_store() {
    let settings = CatDpopSettings::new()
        .with_window(300)
        .unwrap()
        .with_jti_processing(true);
    let sync = cat_token::moqt::MoqtValidator::new().with_dpop_validation(settings);
    match AsyncMoqtValidator::try_from_sync_strict(sync, Arc::new(NonStrictJtiStore)) {
        Ok(_) => panic!("non-strict store must be refused"),
        Err(CatError::CryptoError(msg)) => {
            assert!(msg.contains("is_strict"), "unexpected message: {msg}");
        }
        Err(other) => panic!("expected strictness CryptoError, got {other:?}"),
    }
}

/// AsyncReplayGuard commits `cti` on `Prohibited`; a duplicate must fail
/// hard even though the JTI store is well behaved.
struct RecordingReplayGuard {
    calls: AtomicUsize,
    inner: tokio::sync::Mutex<std::collections::HashSet<Vec<u8>>>,
}

impl RecordingReplayGuard {
    fn new() -> Self {
        Self {
            calls: AtomicUsize::new(0),
            inner: tokio::sync::Mutex::new(std::collections::HashSet::new()),
        }
    }
    fn calls(&self) -> usize {
        self.calls.load(Ordering::Relaxed)
    }
}

#[async_trait]
impl AsyncReplayGuard for RecordingReplayGuard {
    async fn check_and_record(&self, cti: &[u8]) -> Result<bool, CatError> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        let mut set = self.inner.lock().await;
        Ok(!set.insert(cti.to_vec()))
    }
}

#[tokio::test]
async fn async_authorize_commits_catreplay_via_guard() {
    let alg = Es256Algorithm::new_with_key_pair().unwrap();
    let jwk = Jwk::from_es256_verifying_key(alg.verifying_key()).unwrap();
    let thumbprint = jwk.thumbprint().unwrap();

    // Build a token that mandates Prohibited catreplay.
    let token = CatTokenBuilder::new()
        .issuer("https://test.com")
        .single_audience("relay")
        .moqt_scope(moqt_scope())
        .confirmation(thumbprint)
        .cwt_id(b"unique-cti".to_vec())
        .replay_protection(cat_token::claims::ReplayProtection::Prohibited)
        .build()
        .unwrap();
    let validated = make_validated(&token);

    let make_proof = || build_dpop_proof(&alg, jwk.clone(), &validated);

    let settings = CatDpopSettings::new()
        .with_window(300)
        .unwrap()
        .with_jti_processing(true);
    let sync = cat_token::moqt::MoqtValidator::new().with_dpop_validation(settings);
    let jti_store = Arc::new(AsyncInMemoryStrictJtiStore::new());
    let validator = AsyncMoqtValidator::try_from_sync_strict(sync, jti_store)
        .expect("strict store construction");
    let guard = RecordingReplayGuard::new();

    let request1 = cat_token::moqt::RelayRequestContext::new(
        "relay",
        MoqtAction::Publish,
        vec![b"ns".to_vec()],
        b"track".to_vec(),
    )
    .with_dpop_proof(make_proof());

    validator
        .authorize_async(&validated, &request1, Some(&guard), None)
        .await
        .expect("first replay-guarded authorize succeeds");

    let request2 = cat_token::moqt::RelayRequestContext::new(
        "relay",
        MoqtAction::Publish,
        vec![b"ns".to_vec()],
        b"track".to_vec(),
    )
    .with_dpop_proof(make_proof());

    let err = validator
        .authorize_async(&validated, &request2, Some(&guard), None)
        .await
        .expect_err("duplicate cti must fail with Prohibited replay mode");
    assert!(
        matches!(err, CatError::ReplayAttackDetected),
        "expected ReplayAttackDetected, got {err:?}"
    );
    assert_eq!(
        guard.calls(),
        2,
        "async replay guard should have been consulted for each authorize"
    );
}

/// Non-strict guard used to prove `require_strict_replay_guard` refuses it.
struct BestEffortGuard;
#[async_trait]
impl AsyncReplayGuard for BestEffortGuard {
    async fn check_and_record(&self, _cti: &[u8]) -> Result<bool, CatError> {
        Ok(false)
    }
    // Deliberately inherits the default `is_strict() == false`.
}

struct StrictGuard {
    inner: tokio::sync::Mutex<std::collections::HashSet<Vec<u8>>>,
}
#[async_trait]
impl AsyncReplayGuard for StrictGuard {
    async fn check_and_record(&self, cti: &[u8]) -> Result<bool, CatError> {
        let mut set = self.inner.lock().await;
        Ok(!set.insert(cti.to_vec()))
    }
    fn is_strict(&self) -> bool {
        true
    }
}

/// `require_strict_replay_guard()` rejects a best-effort guard when the
/// token asserts catreplay. Mirrors the JTI-store `try_from_sync_strict`
/// contract at the second commit surface — without this, a CDN deployment
/// could pin JTI strictness but silently accept a leaky `cti` backend.
#[tokio::test]
async fn strict_validator_refuses_best_effort_replay_guard() {
    let alg = Es256Algorithm::new_with_key_pair().unwrap();
    let jwk = Jwk::from_es256_verifying_key(alg.verifying_key()).unwrap();
    let thumbprint = jwk.thumbprint().unwrap();

    let token = CatTokenBuilder::new()
        .issuer("https://test.com")
        .single_audience("relay")
        .moqt_scope(moqt_scope())
        .confirmation(thumbprint)
        .cwt_id(b"strict-cti".to_vec())
        .replay_protection(cat_token::claims::ReplayProtection::Prohibited)
        .build()
        .unwrap();
    let validated = make_validated(&token);

    let settings = CatDpopSettings::new()
        .with_window(300)
        .unwrap()
        .with_jti_processing(true);
    let sync = cat_token::moqt::MoqtValidator::new().with_dpop_validation(settings);
    let jti_store = Arc::new(AsyncInMemoryStrictJtiStore::new());
    let validator = AsyncMoqtValidator::try_from_sync_strict(sync, jti_store)
        .expect("strict store construction")
        .require_strict_replay_guard();

    let request = cat_token::moqt::RelayRequestContext::new(
        "relay",
        MoqtAction::Publish,
        vec![b"ns".to_vec()],
        b"track".to_vec(),
    )
    .with_dpop_proof(build_dpop_proof(&alg, jwk, &validated));

    let err = validator
        .authorize_async(&validated, &request, Some(&BestEffortGuard), None)
        .await
        .expect_err("best-effort guard must be refused under require_strict_replay_guard");
    assert!(
        matches!(&err, CatError::CryptoError(msg) if msg.contains("is_strict")),
        "expected CryptoError referencing is_strict, got {err:?}"
    );
}

/// A strict-attesting guard passes the same gate — the check keys off the
/// guard's `is_strict()` bit, not on the trait object type.
#[tokio::test]
async fn strict_validator_accepts_strict_replay_guard() {
    let alg = Es256Algorithm::new_with_key_pair().unwrap();
    let jwk = Jwk::from_es256_verifying_key(alg.verifying_key()).unwrap();
    let thumbprint = jwk.thumbprint().unwrap();

    let token = CatTokenBuilder::new()
        .issuer("https://test.com")
        .single_audience("relay")
        .moqt_scope(moqt_scope())
        .confirmation(thumbprint)
        .cwt_id(b"strict-ok-cti".to_vec())
        .replay_protection(cat_token::claims::ReplayProtection::Prohibited)
        .build()
        .unwrap();
    let validated = make_validated(&token);

    let settings = CatDpopSettings::new()
        .with_window(300)
        .unwrap()
        .with_jti_processing(true);
    let sync = cat_token::moqt::MoqtValidator::new().with_dpop_validation(settings);
    let jti_store = Arc::new(AsyncInMemoryStrictJtiStore::new());
    let validator = AsyncMoqtValidator::try_from_sync_strict(sync, jti_store)
        .expect("strict store construction")
        .require_strict_replay_guard();

    let guard = StrictGuard {
        inner: tokio::sync::Mutex::new(std::collections::HashSet::new()),
    };
    let request = cat_token::moqt::RelayRequestContext::new(
        "relay",
        MoqtAction::Publish,
        vec![b"ns".to_vec()],
        b"track".to_vec(),
    )
    .with_dpop_proof(build_dpop_proof(&alg, jwk, &validated));

    validator
        .authorize_async(&validated, &request, Some(&guard), None)
        .await
        .expect("strict guard should be accepted under require_strict_replay_guard");
}

/// `require_strict_replay_guard()` is a no-op for tokens that don't assert
/// catreplay — the guard slot is never consulted, so the strictness check
/// never fires. Prevents accidentally regressing on the guard-optional
/// happy path.
#[tokio::test]
async fn strict_validator_no_guard_no_catreplay_still_authorizes() {
    let alg = Es256Algorithm::new_with_key_pair().unwrap();
    let jwk = Jwk::from_es256_verifying_key(alg.verifying_key()).unwrap();
    let thumbprint = jwk.thumbprint().unwrap();

    let token = CatTokenBuilder::new()
        .issuer("https://test.com")
        .single_audience("relay")
        .moqt_scope(moqt_scope())
        .confirmation(thumbprint)
        .build()
        .unwrap();
    let validated = make_validated(&token);

    let settings = CatDpopSettings::new()
        .with_window(300)
        .unwrap()
        .with_jti_processing(true);
    let sync = cat_token::moqt::MoqtValidator::new().with_dpop_validation(settings);
    let jti_store = Arc::new(AsyncInMemoryStrictJtiStore::new());
    let validator = AsyncMoqtValidator::try_from_sync_strict(sync, jti_store)
        .expect("strict store construction")
        .require_strict_replay_guard();

    let request = cat_token::moqt::RelayRequestContext::new(
        "relay",
        MoqtAction::Publish,
        vec![b"ns".to_vec()],
        b"track".to_vec(),
    )
    .with_dpop_proof(build_dpop_proof(&alg, jwk, &validated));

    validator
        .authorize_async(&validated, &request, None, None)
        .await
        .expect("guard-less authorize should succeed when the token has no catreplay");
}
