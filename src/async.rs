// SPDX-FileCopyrightText: Copyright (c) 2022 Quicr
// SPDX-License-Identifier: BSD-2-Clause

//! Async integration surface for production relays.
//!
//! The sync [`crate::moqt::MoqtValidator::authorize`] pipeline commits to
//! two independent replay stores — the DPoP `JtiStore` and the CAT
//! `ReplayGuard` — via blocking trait calls. A single-node deployment
//! backed by an in-process HashMap is fine that way, but any CDN-scale
//! deployment backs at least one of those stores with a network
//! service (Redis, DynamoDB, etc.), and a blocking call from an async
//! runtime is a deployment hazard: it either burns a `spawn_blocking`
//! thread pool slot per authorize or, if the caller forgets, silently
//! stalls the whole executor.
//!
//! This module exposes the same authorize pipeline with async commit
//! traits so relays can drive it from a tokio/async-std/smol runtime
//! without going through `spawn_blocking`. Every non-storage check
//! (audience, catu, catm, cath, catnip, catpor, MOQT scope matching,
//! DPoP signature + shape verification) runs on the sync
//! [`crate::moqt::MoqtValidator::authorize_precommit`] path — the only
//! points where the async pipeline diverges are:
//!
//! - DPoP JTI commit → [`AsyncJtiStore::check_and_insert`]
//! - `catreplay` cti commit → [`AsyncReplayGuard::check_and_record`]
//!
//! The commit ordering (JTI first, cti second) and the fail-closed
//! contract on backend outage are identical to the sync pipeline; see
//! [`crate::moqt::MoqtValidator::authorize`] for the rationale.
//!
//! The traits use the [`async_trait`] crate for dyn compatibility.
//! Enabling the `async` feature adds a single dependency
//! (`async-trait`); no runtime is pulled in — callers pick their own.

use crate::moqt::{CatReplayObligation, PreCommit};
use crate::{
    AuthorizedRequest, CatError, CatPorBlockList, MoqtValidator, RelayRequestContext,
    ValidatedToken,
};
use async_trait::async_trait;
use std::sync::{Arc, Mutex};

/// Async equivalent of [`crate::dpop::JtiStore::check_and_insert`]. All
/// obligations from the sync trait carry over verbatim:
///
/// - Insert-if-absent must be atomic across every relay that shares the
///   backend; check-then-set is not sufficient.
/// - A duplicate JTI must surface as [`CatError::ReplayAttackDetected`],
///   not silently succeed.
/// - Backend errors must surface as [`CatError::BackendUnavailable`]
///   so the authorization path fails closed on outage.
/// - Entries must be retained for at least the DPoP freshness window.
///
/// The sync `JtiStore` trait is only supplemented here — not replaced —
/// because non-async in-process stores like
/// [`crate::dpop::InMemoryStrictJtiStore`] compose cleanly with async
/// callers by wrapping in [`AsyncJtiStoreAdapter`]. Distributed backends
/// should implement `AsyncJtiStore` natively.
#[async_trait]
pub trait AsyncJtiStore: Send + Sync {
    async fn check_and_insert(&self, key: String, iat: i64) -> Result<(), CatError>;

    /// Self-attestation mirror of [`crate::dpop::JtiStore::is_strict`]. See
    /// that trait's rustdoc for the strict-store contract.
    fn is_strict(&self) -> bool {
        false
    }
}

/// Async equivalent of [`crate::token::ReplayGuard::check_and_record`]. The
/// sync trait's contract carries over: returns `Ok(true)` when the `cti`
/// has been observed before (atomically recording the current observation
/// for future calls), `Ok(false)` on first observation, and an error only
/// on backend failure (which propagates as a hard authorization failure).
///
/// [`is_strict`](AsyncReplayGuard::is_strict) mirrors the JTI-store contract:
/// a strict guard is self-attesting that it retains every observed `cti`
/// for at least the token's `exp - iat` window, insert-if-absent is atomic
/// across every node that shares the backend, and backend outage surfaces
/// as [`CatError::BackendUnavailable`] rather than `Ok(false)`. Distributed CDN
/// deployments MUST use a strict guard behind
/// [`AsyncMoqtValidator::require_strict_replay_guard`]; a best-effort LRU
/// is a replay-defense bypass under memory pressure or restart.
#[async_trait]
pub trait AsyncReplayGuard: Send + Sync {
    async fn check_and_record(&self, cti: &[u8]) -> Result<bool, CatError>;

    /// Self-attestation. See the trait rustdoc for the strict-guard
    /// contract. The crate cannot verify a distributed backend meets it;
    /// the integrator asserts it and audits against the same list as the
    /// JTI store (atomic insert-if-absent, TTL ≥ token lifetime, no
    /// eviction inside TTL, fail-closed on outage).
    fn is_strict(&self) -> bool {
        false
    }
}

/// Wrap a sync [`crate::JtiStore`] as an [`AsyncJtiStore`]. For in-process
/// stores (LRU, strict HashMap) the wrapper adds a Mutex-free direct call —
/// the underlying store is already `Send + Sync` and non-blocking, so no
/// executor hazard exists. Distributed backends should implement
/// `AsyncJtiStore` natively rather than wrapping their blocking client.
pub struct AsyncJtiStoreAdapter {
    inner: Arc<dyn crate::JtiStore>,
}

impl AsyncJtiStoreAdapter {
    pub fn new(inner: Arc<dyn crate::JtiStore>) -> Self {
        Self { inner }
    }
}

#[async_trait]
impl AsyncJtiStore for AsyncJtiStoreAdapter {
    async fn check_and_insert(&self, key: String, iat: i64) -> Result<(), CatError> {
        self.inner.check_and_insert(key, iat)
    }
    fn is_strict(&self) -> bool {
        self.inner.is_strict()
    }
}

/// Async validator that shares its policy config with a sync
/// [`MoqtValidator`] but commits through async traits.
///
/// Construct via [`AsyncMoqtValidator::strict`] (rejects
/// non-strict stores) for CDN/multi-relay deployments, or
/// [`AsyncMoqtValidator::best_effort`] for development and
/// single-tenant tests where eviction under load is acceptable. Sync and
/// async paths must share the same store instance if the deployment ever
/// mixes them — otherwise a JTI accepted on one path can be replayed on
/// the other.
///
/// # CPU offload shape (relay obligation)
///
/// Only the two commits inside [`AsyncMoqtValidator::commit_async`] are
/// actually awaitable — token decode, CAT claim evaluation, MOQT scope
/// matching, and DPoP ES256/PS256 verification all run synchronously
/// inside [`MoqtValidator::authorize_precommit`]. At CDN scale that
/// synchronous half must be lifted off the I/O runtime or a burst of
/// ES256 verifications will inflate p99/p999 tail latency for every
/// unrelated request on the reactor. The precommit / commit split
/// exists to make the offload straightforward:
///
/// ```ignore
/// // Runs on a bounded blocking pool (spawn_blocking, rayon, etc.),
/// // NOT on the reactor. Cap the pool with a semaphore per connection
/// // so a DPoP surge cannot exhaust it.
/// let pre = tokio::task::spawn_blocking({
///     let sync = sync_validator.clone();
///     let token = token.clone();
///     let ctx = ctx.clone();
///     move || sync.authorize_precommit(&token, &ctx, true, None)
/// })
/// .await
/// .expect("blocking pool")??;
///
/// // Back on the reactor: the two replay commits are the only awaits.
/// let authorized = async_validator
///     .commit_async(pre, Some(replay_guard))
///     .await?;
/// ```
///
/// The alternative — wrapping the whole `authorize` call in
/// `spawn_blocking` — works and is simpler, at the cost of tying up a
/// blocking-pool slot for the JTI/cti network round-trips. See
/// `docs/RELAY-OBLIGATIONS.md` §3 for the full checklist.
#[derive(Clone)]
pub struct AsyncMoqtValidator {
    sync: MoqtValidator,
    jti_store: Arc<dyn AsyncJtiStore>,
    require_strict_replay_guard: bool,
}

impl AsyncMoqtValidator {
    /// Build the async validator with a strict JTI store — the CDN
    /// deployment path. The store MUST return `true` from
    /// [`AsyncJtiStore::is_strict`]; otherwise this returns
    /// [`CatError::ConfigurationRefused`] rather than silently accept a
    /// backend that could shed retained JTIs.
    ///
    /// Sync counterpart: [`MoqtValidator::dpop_strict`] applies the same
    /// contract to a synchronous [`crate::JtiStore`]. A deployment
    /// mixing sync and async authorize paths MUST share the same
    /// underlying store instance, otherwise a JTI accepted on one path
    /// can be replayed on the other.
    ///
    /// The `is_strict()` bit is *self-attestation*, matching the sync
    /// contract on [`MoqtValidator::dpop_strict`]. A
    /// distributed backend must additionally guarantee atomic
    /// insert-if-absent across nodes, TTL ≥ freshness window + skew, no
    /// silent eviction inside that TTL, and fail-closed on outage
    /// (surfaced as [`CatError::BackendUnavailable`] from
    /// `check_and_insert`). The reference
    /// [`AsyncInMemoryStrictJtiStore`] satisfies these for a single-
    /// relay deployment; distributed backends must be audited against
    /// the same list before deployment.
    pub fn strict(
        sync: MoqtValidator,
        jti_store: Arc<dyn AsyncJtiStore>,
    ) -> Result<Self, CatError> {
        if !jti_store.is_strict() {
            return Err(CatError::ConfigurationRefused(
                "AsyncJtiStore::is_strict() returned false; strict CDN \
                 deployments require a store that retains every accepted \
                 JTI for the DPoP freshness window. Use \
                 AsyncMoqtValidator::best_effort for local \
                 development."
                    .to_string(),
            ));
        }
        Ok(Self {
            sync,
            jti_store,
            require_strict_replay_guard: false,
        })
    }

    /// Build the async validator without checking store strictness. Use
    /// only for local development, single-tenant tests, or intentionally
    /// best-effort replay defense — a store that evicts under memory
    /// pressure will let a previously-accepted JTI replay. Multi-relay
    /// production deployments MUST use
    /// [`AsyncMoqtValidator::strict`] instead.
    pub fn best_effort(sync: MoqtValidator, jti_store: Arc<dyn AsyncJtiStore>) -> Self {
        Self {
            sync,
            jti_store,
            require_strict_replay_guard: false,
        }
    }

    /// Refuse `authorize` calls whose supplied
    /// [`AsyncReplayGuard`] reports `is_strict() == false`. Set this on
    /// the CDN deployment path so a caller cannot silently degrade the
    /// `catreplay` commit surface to a best-effort backend after the
    /// JTI-store strictness gate has already been enforced at
    /// construction time. Guardless requests (tokens without a
    /// `catreplay` obligation) are unaffected.
    ///
    /// Like [`AsyncJtiStore::is_strict`] this is *self-attestation*:
    /// the crate cannot verify the backend, only that the integrator
    /// has opted into the contract described on [`AsyncReplayGuard`].
    #[must_use]
    pub fn require_strict_replay_guard(mut self) -> Self {
        self.require_strict_replay_guard = true;
        self
    }

    /// Async equivalent of [`MoqtValidator::authorize`]. Runs the sync
    /// pre-commit pipeline (audience, catu/catm/cath/catnip/catpor,
    /// DPoP signature + shape) then awaits the two commit points. Fail-
    /// closed on any error from either store.
    pub async fn authorize(
        &self,
        token: &ValidatedToken,
        ctx: &RelayRequestContext,
    ) -> Result<AuthorizedRequest, CatError> {
        let pre = self.sync.authorize_precommit(token, ctx, false, None)?;
        self.commit_async(pre, None).await
    }

    /// Async equivalent of [`MoqtValidator::authorize_with_replay`].
    pub async fn authorize_with_replay(
        &self,
        token: &ValidatedToken,
        ctx: &RelayRequestContext,
        replay_guard: &dyn AsyncReplayGuard,
        catpor_block_list: Option<&CatPorBlockList>,
    ) -> Result<AuthorizedRequest, CatError> {
        let pre = self
            .sync
            .authorize_precommit(token, ctx, true, catpor_block_list)?;
        self.commit_async(pre, Some(replay_guard)).await
    }

    /// Perform the async commit half of the pipeline. JTI first, then
    /// cti — matches the sync ordering documented on
    /// [`MoqtValidator::authorize`]. Split out from `authorize` so
    /// advanced callers can interleave metrics or tracing between the
    /// pre-commit decision and the storage effects.
    pub async fn commit_async(
        &self,
        pre: PreCommit,
        replay_guard: Option<&dyn AsyncReplayGuard>,
    ) -> Result<AuthorizedRequest, CatError> {
        if let Some((key, iat)) = pre.dpop_jti_key() {
            self.jti_store
                .check_and_insert(key.to_string(), iat)
                .await?;
        }

        let reuse_detected = match pre.replay_obligation().cloned() {
            Some(CatReplayObligation::Prohibited(cti)) => {
                let guard = self.resolve_replay_guard(replay_guard)?;
                if guard.check_and_record(&cti).await? {
                    return Err(CatError::ReplayAttackDetected);
                }
                false
            }
            Some(CatReplayObligation::ReuseDetection(cti)) => {
                let guard = self.resolve_replay_guard(replay_guard)?;
                guard.check_and_record(&cti).await?
            }
            None => false,
        };

        Ok(pre.finalize(reuse_detected))
    }

    fn resolve_replay_guard<'g>(
        &self,
        guard: Option<&'g dyn AsyncReplayGuard>,
    ) -> Result<&'g dyn AsyncReplayGuard, CatError> {
        let guard = guard.ok_or_else(|| {
            CatError::InvalidClaimValue(
                "token asserts catreplay but no replay guard configured".to_string(),
            )
        })?;
        if self.require_strict_replay_guard && !guard.is_strict() {
            return Err(CatError::ConfigurationRefused(
                "AsyncReplayGuard::is_strict() returned false but validator \
                 was constructed with require_strict_replay_guard(); refusing \
                 to commit catreplay through a best-effort backend"
                    .to_string(),
            ));
        }
        Ok(guard)
    }
}

/// Reference [`AsyncJtiStore`] backend for tests and single-node
/// deployments. Wraps an inner Mutex-guarded HashMap (same shape as
/// [`crate::dpop::InMemoryStrictJtiStore`]); returns `is_strict() == true`.
/// Not suitable for multi-node deployments — a Redis-backed
/// implementation of [`AsyncJtiStore`] should replace this at CDN scale.
pub struct AsyncInMemoryStrictJtiStore {
    entries: Mutex<std::collections::HashMap<String, i64>>,
    max_entries: Option<usize>,
    rejected_over_capacity: std::sync::atomic::AtomicU64,
}

impl AsyncInMemoryStrictJtiStore {
    pub fn new() -> Self {
        Self {
            entries: Mutex::new(std::collections::HashMap::new()),
            max_entries: None,
            rejected_over_capacity: std::sync::atomic::AtomicU64::new(0),
        }
    }

    pub fn with_max_entries(mut self, max: usize) -> Self {
        self.max_entries = Some(max);
        self
    }

    pub fn len(&self) -> usize {
        self.entries.lock().map(|e| e.len()).unwrap_or(0)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn rejected_over_capacity(&self) -> u64 {
        self.rejected_over_capacity
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    pub fn cleanup(&self, max_age_seconds: i64) {
        use std::time::{SystemTime, UNIX_EPOCH};
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        if let Ok(mut entries) = self.entries.lock() {
            entries.retain(|_, iat| now.saturating_sub(*iat) < max_age_seconds);
        }
    }
}

impl Default for AsyncInMemoryStrictJtiStore {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl AsyncJtiStore for AsyncInMemoryStrictJtiStore {
    async fn check_and_insert(&self, key: String, iat: i64) -> Result<(), CatError> {
        if key.len() > crate::dpop::MAX_JTI_LENGTH_BYTES {
            return Err(CatError::DpopValidationFailed(format!(
                "JTI exceeds {} byte cap",
                crate::dpop::MAX_JTI_LENGTH_BYTES
            )));
        }
        let mut entries = self
            .entries
            .lock()
            .map_err(|_| CatError::BackendUnavailable("Lock poisoned".to_string()))?;
        if entries.contains_key(&key) {
            return Err(CatError::ReplayAttackDetected);
        }
        if let Some(max) = self.max_entries
            && entries.len() >= max
        {
            self.rejected_over_capacity
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            return Err(CatError::DpopValidationFailed(format!(
                "async strict JTI store at max_entries={max}; increase capacity or cleanup cadence"
            )));
        }
        entries.insert(key, iat);
        Ok(())
    }

    fn is_strict(&self) -> bool {
        true
    }
}
