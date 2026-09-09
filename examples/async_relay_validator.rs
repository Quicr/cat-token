// SPDX-FileCopyrightText: Copyright (c) 2022 Quicr
// SPDX-License-Identifier: BSD-2-Clause

//! Example: MOQT Relay - Async Token Validation with a Custom JTI Store
//!
//! This example is the async sibling of `relay_validator.rs`. It shows:
//!
//! 1. How to bring in the async traits (`AsyncJtiStore`, `AsyncReplayGuard`,
//!    `AsyncMoqtValidator`) from the `async` feature.
//! 2. How to implement `AsyncJtiStore` on your own storage backend — here a
//!    Mutex-guarded HashMap, but the same shape works for Redis, DynamoDB,
//!    or any distributed KV store. Production relays swap this out for
//!    their real backend.
//! 3. How to implement `AsyncReplayGuard` for the `catreplay` cti check.
//! 4. How the pre-commit / commit split lets `authorize` reuse every
//!    non-storage check from the sync pipeline.
//! 5. How `AsyncMoqtValidator::strict` enforces the strict
//!    JTI-store contract at construction time — a non-strict backend is
//!    refused up front rather than being allowed to shed retained JTIs
//!    at runtime.
//!
//! Run with: `cargo run --example async_relay_validator --features async`

use async_trait::async_trait;
use cat_token::ALG_ES256;
use cat_token::r#async::{AsyncJtiStore, AsyncMoqtValidator, AsyncReplayGuard};
use cat_token::prelude::*;
use chrono::{Duration, Utc};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::Mutex;

/// Reference `AsyncJtiStore` backed by a Mutex + HashMap. Swap for Redis
/// (SETNX with TTL) in production. `is_strict()` returns `true` because
/// this backend never evicts inside the freshness window; a real
/// distributed store must guarantee the same across all shards before
/// advertising `true` — see the `JtiStore` rustdoc for the full contract.
struct MyAsyncJtiStore {
    entries: Mutex<HashMap<String, i64>>,
}

impl MyAsyncJtiStore {
    fn new() -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
        }
    }
}

#[async_trait]
impl AsyncJtiStore for MyAsyncJtiStore {
    async fn check_and_insert(&self, key: String, iat: i64) -> Result<(), CatError> {
        // Insert-if-absent. In Redis this maps to `SET key iat NX EX <ttl>`
        // whose reply distinguishes "newly stored" from "already exists".
        let mut guard = self.entries.lock().await;
        if guard.contains_key(&key) {
            return Err(CatError::ReplayAttackDetected);
        }
        guard.insert(key, iat);
        Ok(())
    }

    fn is_strict(&self) -> bool {
        // This example runs in-process with no eviction. A distributed
        // backend must additionally guarantee: atomic insert-if-absent
        // across nodes, TTL >= freshness window, no silent eviction, and
        // fail-closed on outage before returning true here.
        true
    }
}

/// Reference `AsyncReplayGuard` for the CAT `catreplay` cti check. Swap
/// for whatever backend records observed `cti` values across the fleet.
struct MyAsyncReplayGuard {
    seen: Mutex<HashSet<Vec<u8>>>,
}

impl MyAsyncReplayGuard {
    fn new() -> Self {
        Self {
            seen: Mutex::new(HashSet::new()),
        }
    }
}

#[async_trait]
impl AsyncReplayGuard for MyAsyncReplayGuard {
    async fn check_and_record(&self, cti: &[u8]) -> Result<bool, CatError> {
        // Returns true iff the cti was already present. Atomic
        // insert-if-absent semantics are required — see the sync
        // `ReplayGuard` rustdoc for the contract.
        let mut guard = self.seen.lock().await;
        Ok(!guard.insert(cti.to_vec()))
    }
}

#[tokio::main]
async fn main() {
    println!("=== MOQT Relay Async Token Validation Example ===\n");

    let signing_key = Es256Algorithm::new_with_key_pair().unwrap();

    // --- Sync validator holds the policy. AsyncMoqtValidator wraps it. ---
    let token_validator = CatTokenValidator::new()
        .with_expected_issuers(vec!["https://auth.example.com".to_string()])
        .with_expected_audiences(vec!["moqt-relay.example.com".to_string()])
        .with_clock_skew_tolerance(60)
        .unwrap()
        .allow_unencrypted_privacy_claims();

    // DPoP validation enabled so the async pipeline exercises its JTI
    // commit branch. `with_jti_processing(true)` tells the validator to
    // insert the proof's `cti` into the JTI store.
    let dpop_settings = CatDpopSettings::new()
        .with_window(300)
        .unwrap()
        .with_jti_processing(true);
    let moqt_validator = MoqtValidator::new()
        .with_min_revalidation_interval(60.0)
        .dpop_best_effort(dpop_settings);

    let jti_store: Arc<dyn AsyncJtiStore> = Arc::new(MyAsyncJtiStore::new());
    let replay_guard = MyAsyncReplayGuard::new();
    // Custom store advertises is_strict() = true, so we take the CDN path.
    // Non-strict stores would be rejected here — the example intentionally
    // uses the strict constructor to show the production wiring.
    let async_validator = AsyncMoqtValidator::strict(moqt_validator, jti_store)
        .expect("MyAsyncJtiStore advertises is_strict() = true");

    // --- Build a DPoP-bound token issued to the demo holder key. ---
    let holder_alg = Es256Algorithm::new_with_key_pair().unwrap();
    let holder_jwk = Jwk::from_es256_verifying_key(holder_alg.verifying_key()).unwrap();
    let holder_thumbprint = holder_jwk.thumbprint().unwrap();

    let token_bytes = create_dpop_token(&signing_key, holder_thumbprint.clone());

    println!("--- Scenario 1: Valid DPoP-bound authorize ---");
    match validate_and_authorize_async(
        &token_bytes,
        &signing_key,
        &token_validator,
        &async_validator,
        &replay_guard,
        &holder_alg,
        holder_jwk.clone(),
    )
    .await
    {
        Ok(result) => println!("ALLOWED (scope {})\n", result.matched_scope_index()),
        Err(e) => println!("DENIED - {}\n", e),
    }

    println!("--- Scenario 2: Same JTI replayed ---");
    // Rebuild the proof with the same JTI to trigger the replay defense.
    // In a real deployment the client would sign a fresh proof every time
    // (RFC 9449 §5.1); we deliberately reuse to prove the JTI commit works.
    match replay_same_proof_async(
        &token_bytes,
        &signing_key,
        &token_validator,
        &async_validator,
        &replay_guard,
        &holder_alg,
        holder_jwk,
    )
    .await
    {
        Ok(_) => println!("ALLOWED (unexpected — JTI store should have rejected)\n"),
        Err(e) => println!("DENIED - {}\n", e),
    }

    println!("=== Done ===");
}

async fn validate_and_authorize_async(
    token_bytes: &[u8],
    signing_key: &Es256Algorithm,
    token_validator: &CatTokenValidator,
    async_validator: &AsyncMoqtValidator,
    replay_guard: &MyAsyncReplayGuard,
    holder_alg: &Es256Algorithm,
    holder_jwk: Jwk,
) -> Result<AuthorizedRequest, String> {
    let verified = decode_token(token_bytes, signing_key).map_err(|e| e.to_string())?;
    let validated = verified
        .validate(token_validator)
        .map_err(|e| e.to_string())?;

    let proof = build_dpop_proof(holder_alg, holder_jwk, &validated);

    let request = RelayRequestContext::new(
        "moqt-relay.example.com",
        MoqtAction::Publish,
        vec![b"live.sports.example.com".to_vec()],
        b"/football/match123".to_vec(),
    )
    .with_dpop_proof(proof);

    async_validator
        .authorize_with_replay(&validated, &request, replay_guard, None)
        .await
        .map_err(|e| e.to_string())
}

async fn replay_same_proof_async(
    token_bytes: &[u8],
    signing_key: &Es256Algorithm,
    token_validator: &CatTokenValidator,
    async_validator: &AsyncMoqtValidator,
    replay_guard: &MyAsyncReplayGuard,
    holder_alg: &Es256Algorithm,
    holder_jwk: Jwk,
) -> Result<AuthorizedRequest, String> {
    // Reuse Scenario 1's flow: signing a fresh proof would land a fresh
    // JTI in the store and succeed. To demonstrate the replay defense
    // we sign a proof with a *fixed* JTI that collides with Scenario 1's.
    let verified = decode_token(token_bytes, signing_key).map_err(|e| e.to_string())?;
    let validated = verified
        .validate(token_validator)
        .map_err(|e| e.to_string())?;

    let mut proof = DpopProof::create_for_moqt(
        MoqtAction::Publish,
        vec![b"live.sports.example.com".to_vec()],
        b"/football/match123",
        ALG_ES256,
        holder_jwk,
    )
    .with_jti("replay-me".to_string())
    .with_access_token_hash(compute_access_token_hash(validated.serialized()));
    proof.sign(holder_alg).unwrap();

    let request = RelayRequestContext::new(
        "moqt-relay.example.com",
        MoqtAction::Publish,
        vec![b"live.sports.example.com".to_vec()],
        b"/football/match123".to_vec(),
    )
    .with_dpop_proof(proof);

    // First attempt seeds the JTI; second attempt collides.
    let _ = async_validator
        .authorize_with_replay(&validated, &request, replay_guard, None)
        .await;

    async_validator
        .authorize_with_replay(&validated, &request, replay_guard, None)
        .await
        .map_err(|e| e.to_string())
}

fn build_dpop_proof(
    holder_alg: &Es256Algorithm,
    holder_jwk: Jwk,
    validated: &ValidatedToken,
) -> DpopProof {
    let mut proof = DpopProof::create_for_moqt(
        MoqtAction::Publish,
        vec![b"live.sports.example.com".to_vec()],
        b"/football/match123",
        ALG_ES256,
        holder_jwk,
    )
    .with_jti(generate_jti())
    .with_access_token_hash(compute_access_token_hash(validated.serialized()));
    proof.sign(holder_alg).unwrap();
    proof
}

fn create_dpop_token(signing_key: &Es256Algorithm, holder_thumbprint: Vec<u8>) -> Vec<u8> {
    let now = Utc::now();

    let scope = MoqtScopeBuilder::new()
        .publisher()
        .namespace_exact(b"live.sports.example.com")
        .track_prefix(b"/")
        .build();

    let token = CatTokenBuilder::new()
        .issuer("https://auth.example.com")
        .audience(vec!["moqt-relay.example.com".to_string()])
        .subject("broadcaster123")
        .issued_at(now)
        .expires_at(now + Duration::hours(2))
        .moqt_scope(scope)
        .moqt_reval(300.0)
        .confirmation(holder_thumbprint)
        .build()
        .unwrap();

    encode_token(&token, signing_key).expect("Failed to encode token")
}
