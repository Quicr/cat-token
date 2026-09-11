// SPDX-FileCopyrightText: Copyright (c) 2022 Quicr
// SPDX-License-Identifier: BSD-2-Clause

use crate::claims::{CatIfAction, CatRenewal};
use crate::token::{
    enforce_catnip, enforce_catpor, enforce_catu, validate_all_headers, validate_method,
};
use crate::{
    BinaryMatch, CatDpopSettings, CatError, CatPorBlockList, CatToken, DpopProof, DpopValidator,
    MoqtAction, MoqtScope, NamespaceMatch, ReplayGuard, ValidatedToken,
};

/// Replay-commit obligation carried out of the sync pre-commit pipeline. Two
/// variants because [`crate::ReplayProtection::Prohibited`] converts a
/// duplicate `cti` into a hard error while `ReuseDetection` records
/// duplicate observations without failing the request.
///
/// Consumed by [`MoqtValidator::commit`] and the async equivalent so both
/// paths honour the same JTI-then-`cti` ordering (see [`MoqtValidator::authorize`]).
///
/// This type is part of the precommit/commit split used by async
/// integrations. Ordinary sync callers of
/// [`MoqtValidator::authorize`] / [`MoqtValidator::authorize_with_replay`]
/// never observe it and should not use it directly.
#[doc(hidden)]
#[derive(Debug, Clone)]
pub enum CatReplayObligation {
    /// Duplicate `cti` MUST fail the request with
    /// [`CatError::ReplayAttackDetected`].
    Prohibited(Vec<u8>),
    /// Duplicate `cti` sets `reuse_detected = true` on the authorization
    /// result but does not fail. Caller decides whether to log/audit.
    ReuseDetection(Vec<u8>),
}

/// Everything the sync pipeline decided before touching a replay store.
///
/// Produced by [`MoqtValidator::authorize_precommit`]; consumed by
/// [`MoqtValidator::commit`] (sync) or
/// [`crate::r#async::AsyncMoqtValidator::commit_async`] (async). Splitting
/// the pipeline this way lets async integrations reuse every non-storage
/// check without duplicating ~250 lines of policy logic.
///
/// Ordinary sync callers of [`MoqtValidator::authorize`] never observe
/// this type; it is only public for the async integration path.
#[doc(hidden)]
#[derive(Debug, Clone)]
pub struct PreCommit {
    scope_index: usize,
    renewal: Option<CatRenewal>,
    revalidation: Option<f64>,
    /// Composite JTI-store key + `iat`, when the DPoP profile requires a
    /// commit. `None` when the token carries no `cnf`, when JTI honouring is
    /// off, or when the proof carries no `cti`.
    jti_commit: Option<(String, i64)>,
    replay: Option<CatReplayObligation>,
}

impl PreCommit {
    pub fn matched_scope_index(&self) -> usize {
        self.scope_index
    }

    pub fn dpop_jti_key(&self) -> Option<(&str, i64)> {
        self.jti_commit.as_ref().map(|(k, iat)| (k.as_str(), *iat))
    }

    pub fn replay_obligation(&self) -> Option<&CatReplayObligation> {
        self.replay.as_ref()
    }

    /// Turn the pre-commit outcome into the final [`AuthorizedRequest`]
    /// after both replay commits have succeeded. Exposed so async callers
    /// ([`crate::r#async::AsyncMoqtValidator::commit_async`]) can produce
    /// the same response shape without touching the sync commit helpers.
    pub fn finalize(self, reuse_detected: bool) -> AuthorizedRequest {
        let mut authorized = AuthorizedRequest::allowed(self.scope_index);
        authorized.reuse_detected = reuse_detected;
        authorized.renewal = self.renewal;
        if let Some(interval) = self.revalidation
            && interval > 0.0
        {
            authorized.requires_revalidation = true;
            authorized.revalidation_interval = Some(interval);
        }
        authorized
    }
}
/// IANA-registered token type for C4M (CAT for MoQ) AUTHORIZATION TOKEN parameter.
pub const C4M_TOKEN_TYPE: u64 = 0x01;

/// Authorization outcome for a single request. Produced only when every
/// signed CAT claim on the token was satisfied by the request context.
/// Carries derived data the caller needs to construct the response:
/// revalidation policy, the token's `catr` renewal instructions (if any),
/// and whether the token's `catreplay` mode observed a duplicate cti
/// (`Prohibited` fails hard; `ReuseDetection` sets this flag for the caller
/// to log/audit).
///
/// Accessors are getters rather than `pub` fields so the struct can grow
/// without breaking downstream matches; construction happens exclusively
/// through the authorization pipeline.
#[derive(Debug, Clone)]
pub struct AuthorizedRequest {
    matched_scope_index: usize,
    requires_revalidation: bool,
    revalidation_interval: Option<f64>,
    renewal: Option<CatRenewal>,
    reuse_detected: bool,
}

impl AuthorizedRequest {
    fn allowed(scope_index: usize) -> Self {
        Self {
            matched_scope_index: scope_index,
            requires_revalidation: false,
            revalidation_interval: None,
            renewal: None,
            reuse_detected: false,
        }
    }

    /// Zero-based index of the MOQT scope on the token that authorized this
    /// request. Callers use this to attribute observed traffic back to a
    /// specific scope (audit / metrics).
    pub fn matched_scope_index(&self) -> usize {
        self.matched_scope_index
    }

    /// Whether the token carries a positive `moqt-reval` interval — i.e.,
    /// the relay must re-check the token before
    /// [`revalidation_interval`](AuthorizedRequest::revalidation_interval)
    /// seconds elapse.
    pub fn requires_revalidation(&self) -> bool {
        self.requires_revalidation
    }

    /// Seconds until revalidation is due, when
    /// [`requires_revalidation`](AuthorizedRequest::requires_revalidation)
    /// is `true`. `None` when the token has no `moqt-reval` claim.
    pub fn revalidation_interval(&self) -> Option<f64> {
        self.revalidation_interval
    }

    /// Renewal directive the response builder must honour (cookie/header/
    /// redirect/automatic) when the token carries `catr`. `None` when the
    /// token asks for no renewal signalling.
    pub fn renewal(&self) -> Option<&CatRenewal> {
        self.renewal.as_ref()
    }

    /// `true` when `catreplay == ReuseDetection` observed a duplicate cti
    /// on this request. The request is still authorized; the flag is for
    /// audit/logging only. `catreplay == Prohibited` fails the request
    /// before this outcome is produced.
    pub fn reuse_detected(&self) -> bool {
        self.reuse_detected
    }
}

/// Context for a relay authorization request, used with
/// [`MoqtValidator::authorize`] and
/// [`MoqtValidator::authorize_with_replay`].
///
/// This is the only supported entry point for authorization. All fields
/// describe the full request context — a missing field represents an
/// unknown value, not a wildcard, and will cause authorization to fail
/// closed when a token claim requires that context (e.g. `catalpn`
/// requires a peer TLS ALPN).
///
/// Construction is fluent: pass the mandatory fields to [`Self::new`],
/// then chain the `with_*` setters for whatever the request carries.
///
/// ```ignore
/// let ctx = RelayRequestContext::new("relay.example.com", MoqtAction::Publish, ns, track)
///     .with_peer_ip(peer_ip)
///     .with_peer_asn(peer_asn)
///     .with_peer_tls_alpn(alpn)
///     .with_request_uri(req.uri.to_string())
///     .with_request_method(req.method.as_str())
///     .add_request_header("x-forwarded-for", peer_ip.to_string())?
///     .with_dpop_proof(proof);
/// ```
///
/// Fields are private; access them through the getter methods. This keeps
/// the struct growable without breaking downstream matches.
#[derive(Debug, Clone)]
pub struct RelayRequestContext {
    pub(crate) relay_endpoint: String,
    pub(crate) action: MoqtAction,
    pub(crate) namespace: Vec<Vec<u8>>,
    pub(crate) track: Vec<u8>,
    pub(crate) peer_tls_alpn: Option<Vec<u8>>,
    pub(crate) peer_ip: Option<std::net::IpAddr>,
    pub(crate) peer_asn: Option<u32>,
    pub(crate) request_uri: Option<String>,
    pub(crate) request_method: Option<String>,
    pub(crate) request_headers: Vec<(String, String)>,
    pub(crate) tenant_id: Option<String>,
    pub(crate) dpop_proof: Option<DpopProof>,
    pub(crate) expected_dpop_nonce: Option<String>,
}

impl RelayRequestContext {
    pub fn new(
        relay_endpoint: impl Into<String>,
        action: MoqtAction,
        namespace: Vec<Vec<u8>>,
        track: Vec<u8>,
    ) -> Self {
        Self {
            relay_endpoint: relay_endpoint.into(),
            action,
            namespace,
            track,
            peer_tls_alpn: None,
            peer_ip: None,
            peer_asn: None,
            request_uri: None,
            request_method: None,
            request_headers: Vec::new(),
            tenant_id: None,
            dpop_proof: None,
            expected_dpop_nonce: None,
        }
    }

    pub fn with_peer_tls_alpn(mut self, alpn: Vec<u8>) -> Self {
        self.peer_tls_alpn = Some(alpn);
        self
    }

    pub fn with_peer_ip(mut self, ip: std::net::IpAddr) -> Self {
        self.peer_ip = Some(ip);
        self
    }

    pub fn with_peer_asn(mut self, asn: u32) -> Self {
        self.peer_asn = Some(asn);
        self
    }

    pub fn with_request_uri(mut self, uri: impl Into<String>) -> Self {
        self.request_uri = Some(uri.into());
        self
    }

    pub fn with_request_method(mut self, method: impl Into<String>) -> Self {
        self.request_method = Some(method.into());
        self
    }

    /// Replace all request headers, validating each `(name, value)`
    /// pair.
    ///
    /// A header name or value that carries CR (0x0D), LF (0x0A), or
    /// NUL (0x00) is rejected outright: those bytes are how upstream
    /// header parsers frame records, so smuggling one through would
    /// let an attacker inject a synthetic header the authorization
    /// stage would then honor. Names are additionally required to be
    /// ASCII per RFC 9110 §5.1; values may carry any non-control ASCII
    /// or valid UTF-8 for permissive HTTP/2/3 parsers, but never a
    /// framing byte.
    ///
    /// Returns [`CatError::InvalidClaimValue`] on the first offending
    /// pair; earlier pairs are still discarded (the mutation is
    /// atomic on success only).
    pub fn with_request_headers(
        mut self,
        headers: Vec<(String, String)>,
    ) -> Result<Self, CatError> {
        for (n, v) in &headers {
            validate_header_pair(n, v)?;
        }
        self.request_headers = headers;
        Ok(self)
    }

    /// Append a single validated header. Same rules as
    /// [`Self::with_request_headers`]; returns
    /// [`CatError::InvalidClaimValue`] if the pair carries a framing
    /// byte or non-ASCII name.
    pub fn add_request_header(
        mut self,
        name: impl Into<String>,
        value: impl Into<String>,
    ) -> Result<Self, CatError> {
        let name = name.into();
        let value = value.into();
        validate_header_pair(&name, &value)?;
        self.request_headers.push((name, value));
        Ok(self)
    }

    pub fn with_tenant_id(mut self, tenant: impl Into<String>) -> Self {
        self.tenant_id = Some(tenant.into());
        self
    }

    pub fn with_dpop_proof(mut self, proof: DpopProof) -> Self {
        self.dpop_proof = Some(proof);
        self
    }

    /// Require the DPoP proof to echo the supplied server nonce (RFC 9449
    /// §8). Call this after the relay has generated (or rotated) a per-
    /// request challenge and included it in the `DPoP-Nonce` response
    /// header that induced this proof. When set, a proof lacking a nonce
    /// or carrying a mismatched nonce is rejected with
    /// [`CatError::DpopValidationFailed`].
    pub fn with_expected_dpop_nonce(mut self, nonce: impl Into<String>) -> Self {
        self.expected_dpop_nonce = Some(nonce.into());
        self
    }

    /// Canonical relay endpoint the client connected to. Matched against
    /// the token's `aud` claim (if present).
    pub fn relay_endpoint(&self) -> &str {
        &self.relay_endpoint
    }

    /// The MOQT action being requested.
    pub fn action(&self) -> MoqtAction {
        self.action
    }

    /// The full track-namespace tuple (segments in order).
    pub fn namespace(&self) -> &[Vec<u8>] {
        &self.namespace
    }

    /// The track name.
    pub fn track(&self) -> &[u8] {
        &self.track
    }

    /// ALPN negotiated on the peer's TLS connection. `None` when the caller
    /// did not populate it; claims that require ALPN pinning fail closed.
    pub fn peer_tls_alpn(&self) -> Option<&[u8]> {
        self.peer_tls_alpn.as_deref()
    }

    /// Peer IP as observed by the relay. `None` when unpopulated; claims that
    /// require IP or ASN scoping fail closed.
    pub fn peer_ip(&self) -> Option<std::net::IpAddr> {
        self.peer_ip
    }

    /// Peer ASN as resolved by the caller's routing table. `None` when
    /// unpopulated; ASN-scoped claims fail closed.
    pub fn peer_asn(&self) -> Option<u32> {
        self.peer_asn
    }

    /// Request URI supplied by the caller, used for URI-shape claims. `None`
    /// when not applicable to the transport.
    pub fn request_uri(&self) -> Option<&str> {
        self.request_uri.as_deref()
    }

    /// Request method (`GET`, `POST`, MOQT verb, ...). `None` when not
    /// applicable to the transport.
    pub fn request_method(&self) -> Option<&str> {
        self.request_method.as_deref()
    }

    /// Request headers observed by the relay, in `(name, value)` order. Empty
    /// when the caller did not populate any; header-shape claims fail closed
    /// against an empty set.
    pub fn request_headers(&self) -> &[(String, String)] {
        &self.request_headers
    }

    /// Optional tenant/connection identity carried from a trusted upstream.
    /// Not enforced by the library — passed through to metrics/audit hooks
    /// by the caller. Present for callers that partition replay state by
    /// tenant.
    pub fn tenant_id(&self) -> Option<&str> {
        self.tenant_id.as_deref()
    }

    /// DPoP proof presented on this request. `None` when the caller did not
    /// attach one; tokens carrying a `cnf` binding fail closed here.
    pub fn dpop_proof(&self) -> Option<&DpopProof> {
        self.dpop_proof.as_ref()
    }

    /// DPoP nonce this relay issued for the challenge that produced the
    /// proof. `None` when no server-issued nonce is required; if set, the
    /// proof must carry a matching `nonce`.
    pub fn expected_dpop_nonce(&self) -> Option<&str> {
        self.expected_dpop_nonce.as_deref()
    }
}

fn validate_header_pair(name: &str, value: &str) -> Result<(), CatError> {
    if name.is_empty() {
        return Err(CatError::InvalidClaimValue(
            "request header name must be non-empty".to_string(),
        ));
    }
    if !name.is_ascii() {
        return Err(CatError::InvalidClaimValue(format!(
            "request header name {name:?} is not ASCII (RFC 9110 §5.1)"
        )));
    }
    for &b in name.as_bytes() {
        // Reject framing bytes (CR/LF/NUL) and non-tchar bytes: ASCII
        // controls and separators forbidden by RFC 9110 §5.1 token
        // grammar.
        if matches!(b, 0x00 | b'\r' | b'\n' | b' ' | b'\t' | b':') {
            return Err(CatError::InvalidClaimValue(format!(
                "request header name {name:?} contains disallowed byte 0x{b:02x}"
            )));
        }
    }
    for &b in value.as_bytes() {
        // Values may carry UTF-8 for permissive HTTP/2/3 parsers but
        // never a framing byte.
        if matches!(b, 0x00 | b'\r' | b'\n') {
            return Err(CatError::InvalidClaimValue(format!(
                "request header {name:?} value contains framing byte 0x{b:02x}"
            )));
        }
    }
    Ok(())
}

/// MOQT-specific token validator
#[derive(Clone)]
#[must_use = "MoqtValidator holds no request state; discarding it means no request can be authorized"]
pub struct MoqtValidator {
    /// Minimum revalidation interval this relay can support (in seconds)
    min_revalidation_interval: Option<f64>,
    /// Whether this relay supports revalidation at all
    supports_revalidation: bool,
    /// DPoP validator for proof-of-possession
    dpop_validator: Option<DpopValidator>,
    /// Expected resource URI for DPoP binding (e.g. "moqt://relay.example.com")
    expected_resource: Option<String>,
    /// Whether to require the relay endpoint to appear in the token's `aud` claim.
    /// Defaults to true — the audit's fail-closed posture demands this.
    require_audience_binding: bool,
    /// Refuse tokens whose `cnf` claim is absent — every request must carry a
    /// verified DPoP proof of possession. Off by default; opting in
    /// promotes the crate from "DPoP is honored when the token asks for it"
    /// to "DPoP is mandatory for every request".
    require_dpop: bool,
    /// Refuse tokens whose `cattpk` (peer-certificate pinning) claim is absent.
    /// Off by default; opting in makes X.509 pinning mandatory for every request.
    require_cattpk: bool,
    /// Commit DPoP JTIs even when the token clears `honor_jti`. A hostile
    /// issuer can otherwise downgrade replay defense per-token by
    /// omitting or clearing the bit; this flag turns that decision into
    /// operator policy.
    require_dpop_replay_tracking: bool,
}

impl Default for MoqtValidator {
    fn default() -> Self {
        Self::new()
    }
}

impl MoqtValidator {
    pub fn new() -> Self {
        Self {
            min_revalidation_interval: None,
            supports_revalidation: true,
            dpop_validator: None,
            expected_resource: None,
            require_audience_binding: true,
            require_dpop: false,
            require_cattpk: false,
            require_dpop_replay_tracking: false,
        }
    }

    /// Set minimum revalidation interval this relay can support
    pub fn with_min_revalidation_interval(mut self, seconds: f64) -> Self {
        self.min_revalidation_interval = Some(seconds);
        self
    }

    /// Disable revalidation support
    pub fn disable_revalidation_support(mut self) -> Self {
        self.supports_revalidation = false;
        self
    }

    /// Enable DPoP validation with a **best-effort** LRU-backed JTI store.
    ///
    /// **Not strict.** RFC 9449 §11.1 requires every accepted JTI be
    /// retained for at least the freshness window; the LRU-backed store
    /// evicts under pressure. CDN-scale deployments MUST call
    /// [`MoqtValidator::dpop_strict`] instead, passing a store that
    /// returns `true` from [`crate::JtiStore::is_strict`]. Use this
    /// constructor only for local development, single-tenant tests, or
    /// intentionally best-effort replay defense.
    pub fn dpop_best_effort(mut self, settings: CatDpopSettings) -> Self {
        self.dpop_validator = Some(DpopValidator::new(settings));
        self
    }

    /// Enable DPoP validation with a caller-supplied **strict**
    /// [`JtiStore`]. The store MUST return `true` from
    /// [`crate::JtiStore::is_strict`]; otherwise this returns
    /// [`CatError::ConfigurationRefused`] rather than silently accept a
    /// store that could shed retained JTIs.
    ///
    /// Async counterpart: [`crate::AsyncMoqtValidator::strict`] applies
    /// the same is_strict() gate to an [`crate::AsyncJtiStore`]. The two
    /// share the same contract; a deployment mixing sync and async
    /// authorize paths MUST share the same underlying store instance
    /// (typically by implementing both traits on one type and passing
    /// the same `Arc`), otherwise a JTI accepted on one path can be
    /// replayed on the other.
    ///
    /// Use this constructor for any deployment that shares replay state
    /// across relays or that must survive a single-relay restart without
    /// losing replay defense. The strict-mode contract is a hard
    /// prerequisite for that guarantee.
    ///
    /// # Caller obligations
    ///
    /// The `is_strict()` bit is *self-attestation*: the store promises it
    /// will never evict a retained JTI within the freshness window. This
    /// crate cannot verify durability, atomic insert-if-absent semantics,
    /// or correct TTL configuration on your behalf. A production CDN
    /// deployment behind a distributed store must additionally guarantee:
    ///
    /// - Atomic insert-if-absent across all relay nodes that share the
    ///   store (a `SETNX`-equivalent with TTL, not `GET` then `SET`).
    /// - `check_and_insert` returns [`CatError::BackendUnavailable`] on backend
    ///   unavailability so authorization fails closed (see
    ///   [`crate::dpop::JtiStore::check_and_insert`]).
    /// - Store TTL ≥ DPoP acceptance window + tolerated clock skew.
    /// - No silent eviction inside that TTL under any load condition.
    ///
    /// The [`crate::dpop::InMemoryStrictJtiStore`] reference backend
    /// satisfies all four for a single-relay deployment; distributed
    /// backends (Redis, DynamoDB with strong consistency, etc.) must be
    /// audited against this list before deployment.
    pub fn dpop_strict(
        mut self,
        settings: CatDpopSettings,
        store: std::sync::Arc<dyn crate::JtiStore>,
    ) -> Result<Self, CatError> {
        self.dpop_validator = Some(DpopValidator::with_jti_store_strict(settings, store)?);
        Ok(self)
    }

    /// Set the expected resource URI for DPoP binding validation
    pub fn with_expected_resource(mut self, resource: impl Into<String>) -> Self {
        self.expected_resource = Some(resource.into());
        self
    }

    /// Accept tokens that omit the `aud` claim. Tokens that DO carry
    /// `aud` are still checked against the relay endpoint. Use only if
    /// the deployment intentionally issues audience-less tokens; the
    /// default (audience required) is the fail-closed posture.
    ///
    /// # Danger
    ///
    /// Audience binding is the primary defense against a token stolen
    /// from one relay being replayed against another. Turning it off
    /// makes any accepted token valid at every relay that shares an
    /// issuer, which is almost never what a CDN deployment wants.
    /// The name deliberately shouts so that grep, code review, and IDE
    /// autocomplete all flag the call.
    pub fn dangerously_allow_missing_audience(mut self) -> Self {
        self.require_audience_binding = false;
        self
    }

    /// Refuse to authorize any token that does not bind a DPoP holder key
    /// via the `cnf` claim. Combined with a `dpop_strict` JTI store this
    /// upgrades the deployment from "DPoP is honored when the issuer asks
    /// for it" to "every request must carry a verified proof of
    /// possession". A token without `cnf` is rejected with
    /// [`CatError::MissingRequiredClaim`] before scope matching runs.
    ///
    /// Requires DPoP validation to be configured — call
    /// [`dpop_strict`] (or [`dpop_best_effort`] for tests) as well;
    /// authorization fails closed otherwise.
    ///
    /// [`dpop_strict`]: MoqtValidator::dpop_strict
    /// [`dpop_best_effort`]: MoqtValidator::dpop_best_effort
    pub fn require_dpop(mut self) -> Self {
        self.require_dpop = true;
        self
    }

    /// Refuse to authorize any token that does not pin a peer certificate
    /// via the `cattpk` claim. The pin is still enforced when
    /// `catcert` / peer-cert context is provided by the integrator; this
    /// setter simply escalates a missing pin from "advisory" to
    /// "required".
    pub fn require_cattpk(mut self) -> Self {
        self.require_cattpk = true;
        self
    }

    /// Commit every DPoP JTI to the store, even when the token's
    /// `catdpop.honor_jti` bit is `false`. Without this override a
    /// hostile issuer can silently opt out of replay tracking on a
    /// per-token basis. Requires DPoP validation to be configured; a
    /// token without `cnf` still passes through the normal path (no
    /// proof, no JTI to commit) — pair with [`require_dpop`] for full
    /// coverage.
    ///
    /// [`require_dpop`]: MoqtValidator::require_dpop
    pub fn require_dpop_replay_tracking(mut self) -> Self {
        self.require_dpop_replay_tracking = true;
        self
    }

    /// Validate MOQT-specific claims in the token. Exposed for
    /// integration tests that exercise the `moqt-reval` policy gates
    /// in isolation. Production code should call
    /// [`MoqtValidator::authorize`] instead — this entry point does not
    /// commit replay state or evaluate transport-scoped claims.
    #[doc(hidden)]
    pub fn validate_moqt_claims(&self, token: &CatToken) -> Result<(), CatError> {
        // Check moqt-reval claim constraints per spec
        if let Some(reval) = token.moqt.moqt_reval {
            // "If a recipient is unable to revalidate tokens, it MUST reject all tokens with a 'moqt-reval' claim"
            if !self.supports_revalidation {
                return Err(CatError::RevalidationRequired);
            }

            // "If the revalidation interval is smaller than the recipient is prepared or able to revalidate,
            //  the recipient MUST reject the token"
            if let Some(min_interval) = self.min_revalidation_interval
                && reval > 0.0
                && reval < min_interval
            {
                return Err(CatError::RevalidationIntervalTooShort);
            }

            // "When the value of this claim is zero, the token MUST NOT be revalidated"
            // This is informational - we just note it
        }

        // Validate that MOQT scopes have valid actions
        if let Some(ref scopes) = token.moqt.moqt {
            for scope in scopes {
                for action in &scope.actions {
                    if !MoqtAction::is_valid(*action as i32) {
                        return Err(CatError::InvalidClaimValue(format!(
                            "Invalid MOQT action: {:?}",
                            action
                        )));
                    }
                }
            }
        }

        Ok(())
    }

    /// Full fail-closed authorization: enforces every signed CAT claim on the
    /// token against the supplied `RelayRequestContext`, threading through the
    /// optional caller-supplied `catpor` block list and `catreplay` guard.
    ///
    /// A missing piece of request context that a token claim requires (e.g.
    /// `catu` with no request_uri) is a hard failure — the authorization path
    /// does not silently allow.
    ///
    /// On success, returns an `AuthorizedRequest` carrying:
    /// - the matched MOQT scope index,
    /// - the token's revalidation policy (if any),
    /// - the token's `catr` renewal instructions for the response builder,
    /// - a `reuse_detected` flag when `catreplay == ReuseDetection` observed
    ///   a duplicate cti (the request is still authorized in that mode).
    ///
    /// Callers who want to surface `catif` action mappings on failure should
    /// consult `token.claims().request.catif` after mapping the returned
    /// error to a claim key.
    ///
    /// # Replay-commit atomicity (caller contract)
    ///
    /// If both DPoP JTI validation and `catreplay` are enabled, the two
    /// commits go to independent stores (`JtiStore` and `ReplayGuard`) in
    /// sequence — JTI first, `cti` second. **This is not atomic.** If the
    /// `cti` commit fails after the JTI commit succeeds, the JTI is burned
    /// but the `cti` is not; the client must retry with a *fresh* JTI (RFC
    /// 9449 requires a new proof on every attempt anyway). See the inline
    /// commentary at the commit site for why JTI-first ordering is the
    /// safer of the two non-atomic orderings.
    ///
    /// Deployments that need strict atomicity between the two stores MUST
    /// back both `JtiStore::check_and_insert` and
    /// `ReplayGuard::check_and_record` with the same transactional
    /// backend (or bind `ReplayGuard::check_and_record` to a store that
    /// records both keys inside a single transaction). This crate does
    /// not distribute a transaction across two independent stores.
    pub fn authorize(
        &self,
        token: &ValidatedToken,
        ctx: &RelayRequestContext,
    ) -> Result<AuthorizedRequest, CatError> {
        let pre = self.authorize_precommit(token, ctx, false, None)?;
        self.commit(token.claims(), pre, None::<&dyn ReplayGuard>)
    }

    /// Full fail-closed authorization with a caller-supplied replay guard
    /// and optional `catpor` block list. Use this when the token may carry
    /// `catreplay` (Prohibited / ReuseDetection) — a token that demands a
    /// guard reaches this crate through [`Self::authorize`] and is
    /// rejected because no guard is supplied.
    ///
    /// See [`Self::authorize`] rustdoc for the atomicity contract between
    /// the two replay commits.
    pub fn authorize_with_replay<G: ReplayGuard + ?Sized>(
        &self,
        token: &ValidatedToken,
        ctx: &RelayRequestContext,
        replay_guard: &G,
        catpor_block_list: Option<&CatPorBlockList>,
    ) -> Result<AuthorizedRequest, CatError> {
        let pre = self.authorize_precommit(token, ctx, true, catpor_block_list)?;
        self.commit(token.claims(), pre, Some(replay_guard))
    }

    /// Run every non-storage authorization check and return the commit
    /// obligations. Split out so async integrations can await the two
    /// storage commits (DPoP JTI, catreplay cti) via
    /// [`crate::r#async::AsyncMoqtValidator::commit_async`] without
    /// duplicating the policy pipeline. Sync callers should use
    /// [`MoqtValidator::authorize`] directly.
    ///
    /// `replay_guard_configured` mirrors whether a [`ReplayGuard`] will be
    /// supplied at commit — required so the pre-commit phase can fail
    /// closed on a token that mandates one when none is configured.
    pub fn authorize_precommit(
        &self,
        token: &ValidatedToken,
        ctx: &RelayRequestContext,
        replay_guard_configured: bool,
        catpor_block_list: Option<&CatPorBlockList>,
    ) -> Result<PreCommit, CatError> {
        let claims = token.claims();

        // 1. Structural MOQT validation (scope actions, moqt-reval policy).
        self.validate_moqt_claims(claims)?;

        // 2. catv version acceptance: unknown non-zero versions must be
        //    rejected rather than silently accepted.
        if let Some(v) = claims.cat.catv
            && v > 1
        {
            return Err(CatError::InvalidClaimValue(format!(
                "catv: unsupported token version {v}"
            )));
        }

        // 3. Audience binding.
        match &claims.core.aud {
            Some(audiences) => {
                if !audiences.contains(&ctx.relay_endpoint) {
                    return Err(CatError::InvalidAudience);
                }
            }
            None => {
                if self.require_audience_binding {
                    return Err(CatError::MissingRequiredClaim("aud".to_string()));
                }
            }
        }

        // 3b. Fail-closed policy gates: escalate optional claims to
        //     mandatory when the operator has opted in. These run before
        //     the expensive DPoP / scope-match work so a token that lacks
        //     the required binding is rejected as cheaply as possible.
        if self.require_dpop && claims.dpop.cnf.is_none() {
            return Err(CatError::MissingRequiredClaim("cnf".to_string()));
        }
        if self.require_cattpk && claims.cat.cattpk.is_none() {
            return Err(CatError::MissingRequiredClaim("cattpk".to_string()));
        }

        // 4. ALPN.
        if let Some(ref token_alpns) = claims.cat.catalpn {
            let peer_alpn = ctx
                .peer_tls_alpn
                .as_ref()
                .ok_or(CatError::MissingRelayContext {
                    claim: "catalpn",
                    field: "peer_tls_alpn",
                })?;
            if !token_alpns.iter().any(|a| a == peer_alpn) {
                return Err(CatError::InvalidClaimValue(
                    "peer TLS ALPN does not match token catalpn".to_string(),
                ));
            }
        }

        // 5. catu — URI-component restrictions.
        if claims.cat.catu.is_some() {
            let uri = ctx
                .request_uri
                .as_deref()
                .ok_or(CatError::MissingRelayContext {
                    claim: "catu",
                    field: "request_uri",
                })?;
            enforce_catu(claims, uri)?;
        }

        // 6. catm — HTTP method restrictions.
        if claims.cat.catm.is_some() {
            let method = ctx
                .request_method
                .as_deref()
                .ok_or(CatError::MissingRelayContext {
                    claim: "catm",
                    field: "request_method",
                })?;
            validate_method(claims, method)?;
        }

        // 7. cath — header restrictions.
        if claims.cat.cath.is_some() {
            let headers: Vec<(&str, &str)> = ctx
                .request_headers
                .iter()
                .map(|(k, v)| (k.as_str(), v.as_str()))
                .collect();
            validate_all_headers(claims, &headers)?;
        }

        // 8. catnip — peer network identity restrictions.
        enforce_catnip(claims, ctx.peer_ip, ctx.peer_asn)?;

        // 9. catpor — probability of rejection. Fail-closed: if the token
        //    carries catpor and no block list is provided, the caller has
        //    misconfigured the relay; refuse rather than skip.
        if claims.cat.catpor.is_some() {
            let block_list = catpor_block_list.ok_or(CatError::MissingRelayContext {
                claim: "catpor",
                field: "catpor_block_list",
            })?;
            enforce_catpor(claims, block_list)?;
        }

        // 10. catreplay — verify a guard has been configured when the token
        //     demands one. The commit itself is deferred to [`Self::commit`]
        //     so that a request that fails downstream checks does not
        //     consume the token's cti. Callers who take the async pipeline
        //     signal the same guard/no-guard decision via
        //     `replay_guard_configured`.
        let replay_mode = claims.cat.catreplay;
        let replay_obligation = match replay_mode {
            Some(crate::ReplayProtection::Prohibited) => {
                if !replay_guard_configured {
                    return Err(CatError::MissingRelayContext {
                        claim: "catreplay",
                        field: "replay_guard",
                    });
                }
                let cti = claims.core.cti.as_ref().ok_or_else(|| {
                    CatError::MissingRequiredClaim(
                        "cti required when catreplay=Prohibited".to_string(),
                    )
                })?;
                Some(CatReplayObligation::Prohibited(cti.clone()))
            }
            Some(crate::ReplayProtection::ReuseDetection) => {
                if !replay_guard_configured {
                    return Err(CatError::MissingRelayContext {
                        claim: "catreplay",
                        field: "replay_guard",
                    });
                }
                let cti = claims.core.cti.as_ref().ok_or_else(|| {
                    CatError::MissingRequiredClaim(
                        "cti required when catreplay=ReuseDetection".to_string(),
                    )
                })?;
                Some(CatReplayObligation::ReuseDetection(cti.clone()))
            }
            _ => None,
        };

        // 11. MOQT scope match.
        let scope_index = self.match_scope_index(claims, ctx).ok_or_else(|| {
            CatError::MoqtActionNotAuthorized(format!(
                "no MOQT scope matches action {:?}",
                ctx.action
            ))
        })?;

        // 12. DPoP proof of possession — verify only; jti commit is deferred
        //     until after all authorization checks succeed.
        let dpop_commit = if let Some(ref cnf) = claims.dpop.cnf {
            let proof = ctx.dpop_proof.as_ref().ok_or_else(|| {
                CatError::DpopValidationFailed(
                    "Token requires DPoP proof but none provided".to_string(),
                )
            })?;

            let validator = self.dpop_validator.as_ref().ok_or_else(|| {
                CatError::DpopValidationFailed("DPoP validation not configured".to_string())
            })?;

            // Reuse the proof's cached JWK thumbprint on the hot path;
            // the first-touch computes SHA-256 once, subsequent authorize
            // calls skip the hash.
            let proof_jkt = proof.jwk_thumbprint()?;
            if !crate::dpop::confirmation_matches_thumbprint(cnf, proof_jkt) {
                return Err(CatError::InvalidDpopBinding);
            }

            let issuer = claims.core.iss.as_deref();
            // Bind the DPoP proof to *this specific token instance* via the
            // access-token-hash claim. Without this binding a valid proof for
            // one token could be reused against a different token sharing the
            // same holder key (e.g. two tokens minted for the same subject with
            // different scopes). The hash covers the wire bytes exactly as
            // received — see [`crate::VerifiedToken::serialized`] for why we
            // do not re-encode.
            let ath_expected = crate::dpop::compute_access_token_hash(token.serialized());
            validator.validate_without_jti_commit(
                proof,
                ctx.action,
                &cnf.jkt,
                issuer,
                Some(&ath_expected),
            )?;

            // Setup actions are endpoint-only: tns/tn are meaningless and
            // must be empty on both sides (enforced by enforce_actx_shape
            // below). Skipping the equality checks here lets a well-formed
            // setup proof authorize without a fake matching namespace.
            match ctx.action.resource_shape() {
                crate::claims::MoqtResourceShape::Endpoint => {}
                _ => {
                    if proof.payload.actx.tns != ctx.namespace {
                        return Err(CatError::DpopValidationFailed(
                            "DPoP proof namespace does not match request".to_string(),
                        ));
                    }
                    if proof.payload.actx.tn != ctx.track {
                        return Err(CatError::DpopValidationFailed(
                            "DPoP proof track does not match request".to_string(),
                        ));
                    }
                }
            }

            if let Some(ref expected) = self.expected_resource {
                match &proof.payload.actx.resource {
                    Some(resource) if resource != expected => {
                        return Err(CatError::DpopValidationFailed(format!(
                            "DPoP proof resource '{}' does not match expected '{}'",
                            resource, expected
                        )));
                    }
                    None => {
                        return Err(CatError::DpopValidationFailed(
                            "DPoP proof missing required resource binding".to_string(),
                        ));
                    }
                    _ => {}
                }
            }

            // CAT-4-MOQT requires the resource URI, if present, to be
            // consistent with the tns/tn fields of the same proof AND with
            // the relay endpoint handling this request. A proof carrying a
            // resource for another relay endpoint must not authorize this
            // one, even when tns/tn happen to match — otherwise a hostile
            // holder could take a proof it obtained against relay A and
            // replay it at relay B by presenting a token whose audience
            // permits both.
            if let Some(resource) = proof.payload.actx.resource.as_deref() {
                let parsed = parse_moqt_resource_uri(resource)?;
                if parsed.endpoint != ctx.relay_endpoint {
                    return Err(CatError::DpopValidationFailed(format!(
                        "DPoP proof resource endpoint '{}' does not match relay '{}'",
                        parsed.endpoint, ctx.relay_endpoint
                    )));
                }
                if let Some(ref ns) = parsed.namespace
                    && proof.payload.actx.tns != *ns
                {
                    return Err(CatError::DpopValidationFailed(
                        "DPoP proof resource namespace tuple disagrees with actx.tns".to_string(),
                    ));
                }
                if let Some(ref tn) = parsed.track
                    && &proof.payload.actx.tn != tn
                {
                    return Err(CatError::DpopValidationFailed(
                        "DPoP proof resource track disagrees with actx.tn".to_string(),
                    ));
                }
                enforce_resource_shape(ctx.action, &parsed)?;
            }

            // Whether or not the proof carries a resource URI, the fields
            // that DO appear in it (or in actx.tns/actx.tn) must be
            // action-appropriate. A setup action carrying a namespace or
            // track is malformed; a track action missing a track name is
            // ambiguous. This guard runs even when the proof omits the
            // resource URI, using actx directly.
            enforce_actx_shape(ctx.action, &proof.payload.actx)?;

            // RFC 9449 §8 nonce challenge. When the relay has pinned an
            // expected nonce for this request the proof MUST carry it
            // verbatim. Missing nonce or mismatch is treated the same —
            // both indicate the client did not obey the server's
            // rotation, and continuing would trust an unrotated proof.
            if let Some(expected) = ctx.expected_dpop_nonce.as_deref() {
                match proof.payload.nonce.as_deref() {
                    Some(actual) if actual == expected => {}
                    Some(_) => {
                        return Err(CatError::DpopValidationFailed(
                            "DPoP proof nonce does not match server challenge".to_string(),
                        ));
                    }
                    None => {
                        return Err(CatError::DpopValidationFailed(
                            "DPoP proof missing required server nonce".to_string(),
                        ));
                    }
                }
            }

            if self.require_dpop_replay_tracking {
                validator.dpop_commit_key_forced(proof, &cnf.jkt, issuer)
            } else {
                validator.dpop_commit_key(proof, &cnf.jkt, issuer)
            }
        } else {
            None
        };

        Ok(PreCommit {
            scope_index,
            renewal: claims.request.catr.clone(),
            revalidation: claims.moqt.moqt_reval,
            jti_commit: dpop_commit,
            replay: replay_obligation,
        })
    }

    /// Sync commit phase. All authorization checks in
    /// [`Self::authorize_precommit`] have passed by the time this runs;
    /// this method touches the two replay stores in the JTI-then-`cti`
    /// order documented on [`Self::authorize`]. The async equivalent is
    /// [`crate::r#async::AsyncMoqtValidator::commit_async`].
    ///
    /// Commit the in-memory DPoP JTI first, then the CAT cti. The two
    /// stores are independent; without a two-phase transaction the crate
    /// must pick an ordering. JTI first is safer because:
    ///   - The default JTI store is in-process and rarely fails
    ///     transiently (lock poisoning is the only real failure surface).
    ///   - The `cti` store is often a distributed backend behind the
    ///     `ReplayGuard` trait and its failures can be transient.
    ///   - If the cti commit fails after JTI commit, the client retries
    ///     with a fresh JTI (required per RFC 9449) so no state is
    ///     leaked: the second attempt sees a virgin cti store and
    ///     succeeds. The reverse ordering (cti first) would leave the
    ///     cti consumed on a JTI failure and turn every transient JTI
    ///     hiccup into a permanent replay error on the caller's retry.
    ///   - If a caller needs strict atomicity between the two stores,
    ///     they can bind both to the same backend behind `ReplayGuard`
    ///     and issue a single transactional commit inside
    ///     `check_and_record`.
    pub fn commit<G: ReplayGuard + ?Sized>(
        &self,
        _claims: &CatToken,
        pre: PreCommit,
        replay_guard: Option<&G>,
    ) -> Result<AuthorizedRequest, CatError> {
        if let Some((key, iat)) = pre.jti_commit.clone() {
            let validator = self.dpop_validator.as_ref().ok_or_else(|| {
                CatError::DpopValidationFailed(
                    "DPoP JTI commit requested but validator not configured".to_string(),
                )
            })?;
            validator.jti_store().check_and_insert(key, iat)?;
        }

        let reuse_detected = match pre.replay.clone() {
            Some(CatReplayObligation::Prohibited(cti)) => {
                let guard = replay_guard.ok_or(CatError::MissingRelayContext {
                    claim: "catreplay",
                    field: "replay_guard",
                })?;
                if guard.check_and_record(&cti)? {
                    return Err(CatError::ReplayAttackDetected);
                }
                false
            }
            Some(CatReplayObligation::ReuseDetection(cti)) => {
                let guard = replay_guard.ok_or(CatError::MissingRelayContext {
                    claim: "catreplay",
                    field: "replay_guard",
                })?;
                guard.check_and_record(&cti)?
            }
            None => false,
        };

        Ok(pre.finalize(reuse_detected))
    }

    /// Look up the `catif` action associated with a given claim key. Callers
    /// can consult this on error to construct a client response consistent
    /// with the token's `catif` directives.
    pub fn catif_action_for(token: &CatToken, claim_key: i64) -> Option<&CatIfAction> {
        token.request.catif.as_ref().and_then(|actions| {
            actions
                .iter()
                .find(|(k, _)| *k == claim_key)
                .map(|(_, a)| a)
        })
    }

    fn match_scope_index(&self, token: &CatToken, ctx: &RelayRequestContext) -> Option<usize> {
        let scopes = token.moqt.moqt.as_ref()?;
        scopes
            .iter()
            .position(|scope| self.scope_matches(scope, ctx))
    }

    fn scope_matches(&self, scope: &MoqtScope, ctx: &RelayRequestContext) -> bool {
        if !scope.allows_action(&ctx.action) {
            return false;
        }

        // "Matches are performed bytewise against the corresponding field of the Full Track Name"
        if !scope.namespace_matches.is_empty() {
            for (i, ns_match) in scope.namespace_matches.iter().enumerate() {
                let tuple_elem = ctx.namespace.get(i).map(|v| v.as_slice());
                if !ns_match.matches(tuple_elem) {
                    return false;
                }
            }
        }

        if let Some(ref track_match) = scope.track_match
            && !track_match.matches(&ctx.track)
        {
            return false;
        }

        true
    }
}

/// Builder for creating MOQT scopes with fluent API
pub struct MoqtScopeBuilder {
    actions: Vec<MoqtAction>,
    namespace_matches: Vec<NamespaceMatch>,
    track_match: Option<BinaryMatch>,
}

impl MoqtScopeBuilder {
    pub fn new() -> Self {
        Self {
            actions: Vec::new(),
            namespace_matches: Vec::new(),
            track_match: None,
        }
    }

    /// Add a single action
    pub fn action(mut self, action: MoqtAction) -> Self {
        self.actions.push(action);
        self
    }

    /// Add multiple actions
    pub fn actions(mut self, actions: &[MoqtAction]) -> Self {
        self.actions.extend_from_slice(actions);
        self
    }

    /// Add publisher actions (PublishNamespace, Publish)
    pub fn publisher(self) -> Self {
        self.actions(&[MoqtAction::PublishNamespace, MoqtAction::Publish])
    }

    /// Add subscriber actions (SubscribeNamespace, Subscribe, Fetch)
    pub fn subscriber(self) -> Self {
        self.actions(&[
            MoqtAction::SubscribeNamespace,
            MoqtAction::Subscribe,
            MoqtAction::Fetch,
        ])
    }

    /// Add all actions
    pub fn full_access(self) -> Self {
        self.actions(&[
            MoqtAction::ClientSetup,
            MoqtAction::ServerSetup,
            MoqtAction::PublishNamespace,
            MoqtAction::SubscribeNamespace,
            MoqtAction::Subscribe,
            MoqtAction::RequestUpdate,
            MoqtAction::Publish,
            MoqtAction::Fetch,
            MoqtAction::TrackStatus,
        ])
    }

    /// Add exact namespace match
    pub fn namespace_exact(mut self, ns: &[u8]) -> Self {
        self.namespace_matches
            .push(NamespaceMatch::exact(ns.to_vec()));
        self
    }

    /// Add prefix namespace match
    pub fn namespace_prefix(mut self, prefix: &[u8]) -> Self {
        self.namespace_matches
            .push(NamespaceMatch::prefix(prefix.to_vec()));
        self
    }

    /// Add suffix namespace match
    pub fn namespace_suffix(mut self, suffix: &[u8]) -> Self {
        self.namespace_matches
            .push(NamespaceMatch::suffix(suffix.to_vec()));
        self
    }

    /// Add exact matches for each segment of a `/`-separated namespace path.
    /// Each segment becomes a separate exact-match tuple element.
    /// Unmatched trailing tuple elements in the request are allowed (tuple-prefix semantics).
    ///
    /// `namespace_path(b"sports/football")` matches any namespace starting with
    /// `["sports", "football", ...]` — e.g. `["sports", "football", "spain"]`.
    pub fn namespace_path(mut self, path: &[u8]) -> Self {
        for segment in path.split(|&b| b == b'/') {
            if !segment.is_empty() {
                self.namespace_matches
                    .push(NamespaceMatch::exact(segment.to_vec()));
            }
        }
        self
    }

    /// Add nil namespace match (end of namespace list)
    pub fn namespace_nil(mut self) -> Self {
        self.namespace_matches.push(NamespaceMatch::nil());
        self
    }

    /// Set exact track match
    pub fn track_exact(mut self, track: &[u8]) -> Self {
        self.track_match = Some(BinaryMatch::exact(track.to_vec()));
        self
    }

    /// Set prefix track match
    pub fn track_prefix(mut self, prefix: &[u8]) -> Self {
        self.track_match = Some(BinaryMatch::prefix(prefix.to_vec()));
        self
    }

    /// Set suffix track match
    pub fn track_suffix(mut self, suffix: &[u8]) -> Self {
        self.track_match = Some(BinaryMatch::suffix(suffix.to_vec()));
        self
    }

    /// Build the MoqtScope
    pub fn build(self) -> MoqtScope {
        MoqtScope {
            actions: self.actions,
            namespace_matches: self.namespace_matches,
            track_match: self.track_match,
        }
    }
}

impl Default for MoqtScopeBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Predefined role-based scope configurations
pub mod roles {
    use super::*;

    /// Create a publisher scope for a specific namespace/track pattern
    pub fn publisher(namespace: &[u8], track_prefix: &[u8]) -> MoqtScope {
        MoqtScopeBuilder::new()
            .publisher()
            .namespace_exact(namespace)
            .track_prefix(track_prefix)
            .build()
    }

    /// Create a subscriber scope for a specific namespace/track pattern
    pub fn subscriber(namespace: &[u8], track_prefix: &[u8]) -> MoqtScope {
        MoqtScopeBuilder::new()
            .subscriber()
            .namespace_exact(namespace)
            .track_prefix(track_prefix)
            .build()
    }

    /// Create a full access scope for a namespace
    pub fn admin(namespace: &[u8]) -> MoqtScope {
        MoqtScopeBuilder::new()
            .full_access()
            .namespace_exact(namespace)
            .build()
    }

    /// Create a read-only scope (subscribe and fetch only)
    pub fn read_only(namespace: &[u8], track_prefix: &[u8]) -> MoqtScope {
        MoqtScopeBuilder::new()
            .actions(&[MoqtAction::Subscribe, MoqtAction::Fetch])
            .namespace_exact(namespace)
            .track_prefix(track_prefix)
            .build()
    }
}

/// Parsed components of a `moqt://<endpoint>[?tns=<b64seg1>,<b64seg2>...[&tn=<b64>]]`
/// resource URI as produced by [`crate::dpop::construct_moqt_uri`]. Used to
/// cross-validate a DPoP proof's `actx.resource` against its own
/// `actx.tns`/`actx.tn`.
///
/// The parser accepts only the strict shape emitted by the constructor. A
/// resource URI with additional query parameters, path components, fragments,
/// or a scheme other than `moqt://` is rejected as invalid form rather than
/// silently ignored, so a hostile proof cannot smuggle a mismatched target
/// through fields the crate does not inspect.
struct MoqtResourceUri {
    endpoint: String,
    /// The namespace tuple, one `Vec<u8>` per tuple segment. `None` means the
    /// resource URI did not carry a namespace at all.
    namespace: Option<Vec<Vec<u8>>>,
    track: Option<Vec<u8>>,
}

fn parse_moqt_resource_uri(uri: &str) -> Result<MoqtResourceUri, CatError> {
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;

    let rest = uri.strip_prefix("moqt://").ok_or_else(|| {
        CatError::DpopValidationFailed(format!(
            "DPoP proof resource must start with moqt://; got '{uri}'"
        ))
    })?;
    if rest.contains('#') || rest.contains('/') {
        return Err(CatError::DpopValidationFailed(
            "DPoP proof resource must not contain '#' or '/'".to_string(),
        ));
    }
    let (endpoint, query) = match rest.split_once('?') {
        Some((ep, q)) => (ep.to_string(), Some(q)),
        None => (rest.to_string(), None),
    };
    if endpoint.is_empty() {
        return Err(CatError::DpopValidationFailed(
            "DPoP proof resource endpoint is empty".to_string(),
        ));
    }
    let mut namespace: Option<Vec<Vec<u8>>> = None;
    let mut track: Option<Vec<u8>> = None;
    if let Some(q) = query {
        for pair in q.split('&') {
            let (k, v) = pair.split_once('=').ok_or_else(|| {
                CatError::DpopValidationFailed(
                    "DPoP proof resource query segment has no '='".to_string(),
                )
            })?;
            match k {
                "tns" if namespace.is_none() => {
                    if v.is_empty() {
                        return Err(CatError::DpopValidationFailed(
                            "DPoP proof resource tns value is empty".to_string(),
                        ));
                    }
                    let mut segments: Vec<Vec<u8>> = Vec::new();
                    for seg in v.split(',') {
                        let decoded = URL_SAFE_NO_PAD.decode(seg).map_err(|e| {
                            CatError::DpopValidationFailed(format!(
                                "DPoP proof resource tns segment base64 decode: {e}"
                            ))
                        })?;
                        segments.push(decoded);
                    }
                    namespace = Some(segments);
                }
                "tn" if track.is_none() => {
                    let decoded = URL_SAFE_NO_PAD.decode(v).map_err(|e| {
                        CatError::DpopValidationFailed(format!(
                            "DPoP proof resource tn base64 decode: {e}"
                        ))
                    })?;
                    track = Some(decoded);
                }
                _ => {
                    return Err(CatError::DpopValidationFailed(format!(
                        "DPoP proof resource has unexpected or repeated query key '{k}'"
                    )));
                }
            }
        }
    }
    if track.is_some() && namespace.is_none() {
        return Err(CatError::DpopValidationFailed(
            "DPoP proof resource carries tn without tns".to_string(),
        ));
    }
    Ok(MoqtResourceUri {
        endpoint,
        namespace,
        track,
    })
}

/// Reject resource URIs whose shape doesn't match the requested action.
/// Setup actions must not name a namespace or track; namespace actions must
/// name a namespace but no track; track actions must name both.
fn enforce_resource_shape(action: MoqtAction, parsed: &MoqtResourceUri) -> Result<(), CatError> {
    use crate::claims::MoqtResourceShape::*;
    match action.resource_shape() {
        Endpoint => {
            if parsed.namespace.is_some() || parsed.track.is_some() {
                return Err(CatError::DpopValidationFailed(format!(
                    "DPoP proof resource carries namespace/track for setup action {:?}",
                    action
                )));
            }
        }
        Namespace => {
            if parsed.namespace.is_none() {
                return Err(CatError::DpopValidationFailed(format!(
                    "DPoP proof resource missing namespace for {:?}",
                    action
                )));
            }
            if parsed.track.is_some() {
                return Err(CatError::DpopValidationFailed(format!(
                    "DPoP proof resource carries track for namespace action {:?}",
                    action
                )));
            }
        }
        Track => {
            if parsed.namespace.is_none() || parsed.track.is_none() {
                return Err(CatError::DpopValidationFailed(format!(
                    "DPoP proof resource missing namespace or track for track action {:?}",
                    action
                )));
            }
        }
    }
    Ok(())
}

/// Reject `actx` maps whose shape doesn't match the requested action. Runs
/// unconditionally so a proof that omits the optional `resource` URI still
/// cannot smuggle e.g. a track name into a setup action.
fn enforce_actx_shape(
    action: MoqtAction,
    actx: &crate::dpop::AuthorizationContext,
) -> Result<(), CatError> {
    use crate::claims::MoqtResourceShape::*;
    match action.resource_shape() {
        Endpoint => {
            if !actx.tns.is_empty() {
                return Err(CatError::DpopValidationFailed(format!(
                    "DPoP actx carries namespace for setup action {:?}",
                    action
                )));
            }
            if !actx.tn.is_empty() {
                return Err(CatError::DpopValidationFailed(format!(
                    "DPoP actx carries track for setup action {:?}",
                    action
                )));
            }
        }
        Namespace => {
            if actx.tns.is_empty() {
                return Err(CatError::DpopValidationFailed(format!(
                    "DPoP actx missing namespace for {:?}",
                    action
                )));
            }
            if !actx.tn.is_empty() {
                return Err(CatError::DpopValidationFailed(format!(
                    "DPoP actx carries track for namespace action {:?}",
                    action
                )));
            }
        }
        Track => {
            if actx.tns.is_empty() || actx.tn.is_empty() {
                return Err(CatError::DpopValidationFailed(format!(
                    "DPoP actx missing namespace or track for track action {:?}",
                    action
                )));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CatTokenBuilder, ValidatedToken};

    fn ctx(action: MoqtAction, ns: Vec<Vec<u8>>, track: Vec<u8>) -> RelayRequestContext {
        RelayRequestContext::new("relay", action, ns, track)
    }

    #[test]
    fn test_relay_request_context() {
        let request = ctx(
            MoqtAction::Publish,
            vec![b"example.com".to_vec()],
            b"/stream/video".to_vec(),
        );
        assert_eq!(request.action, MoqtAction::Publish);
        assert_eq!(request.namespace, vec![b"example.com".to_vec()]);
        assert_eq!(request.track, b"/stream/video".to_vec());
    }

    fn authorize_no_guard(
        validator: &MoqtValidator,
        token: &CatToken,
        request: &RelayRequestContext,
    ) -> Result<AuthorizedRequest, CatError> {
        validator.authorize(&ValidatedToken::from_unchecked(token.clone()), request)
    }

    #[test]
    fn test_moqt_validator_basic() {
        let scope = MoqtScopeBuilder::new()
            .publisher()
            .namespace_exact(b"example.com")
            .track_prefix(b"/stream/")
            .build();

        let token = CatTokenBuilder::new()
            .issuer("https://test.com")
            .single_audience("relay")
            .moqt_scope(scope)
            .build()
            .unwrap();

        let validator = MoqtValidator::new();

        let request = ctx(
            MoqtAction::Publish,
            vec![b"example.com".to_vec()],
            b"/stream/video".to_vec(),
        );
        assert!(authorize_no_guard(&validator, &token, &request).is_ok());

        let request = ctx(
            MoqtAction::Fetch,
            vec![b"example.com".to_vec()],
            b"/stream/video".to_vec(),
        );
        assert!(matches!(
            authorize_no_guard(&validator, &token, &request),
            Err(CatError::MoqtActionNotAuthorized(_))
        ));

        let request = ctx(
            MoqtAction::Publish,
            vec![b"other.com".to_vec()],
            b"/stream/video".to_vec(),
        );
        assert!(matches!(
            authorize_no_guard(&validator, &token, &request),
            Err(CatError::MoqtActionNotAuthorized(_))
        ));

        let request = ctx(
            MoqtAction::Publish,
            vec![b"example.com".to_vec()],
            b"/other/video".to_vec(),
        );
        assert!(matches!(
            authorize_no_guard(&validator, &token, &request),
            Err(CatError::MoqtActionNotAuthorized(_))
        ));
    }

    #[test]
    fn test_moqt_validator_revalidation() {
        let scope = MoqtScopeBuilder::new()
            .publisher()
            .namespace_exact(b"example.com")
            .build();

        let token = CatTokenBuilder::new()
            .issuer("https://test.com")
            .single_audience("relay")
            .moqt_scope(scope)
            .moqt_reval(300.0)
            .build()
            .unwrap();

        let validator = MoqtValidator::new();

        let request = ctx(
            MoqtAction::Publish,
            vec![b"example.com".to_vec()],
            b"/stream".to_vec(),
        );
        let result = authorize_no_guard(&validator, &token, &request).unwrap();

        assert!(result.requires_revalidation());
        assert_eq!(result.revalidation_interval(), Some(300.0));
    }

    #[test]
    fn test_moqt_validator_revalidation_disabled() {
        let scope = MoqtScopeBuilder::new()
            .publisher()
            .namespace_exact(b"example.com")
            .build();

        let token = CatTokenBuilder::new()
            .issuer("https://test.com")
            .moqt_scope(scope)
            .moqt_reval(300.0)
            .build()
            .unwrap();

        let validator = MoqtValidator::new().disable_revalidation_support();

        let result = validator.validate_moqt_claims(&token);
        assert!(matches!(result, Err(CatError::RevalidationRequired)));
    }

    #[test]
    fn test_moqt_validator_min_revalidation_interval() {
        let scope = MoqtScopeBuilder::new()
            .publisher()
            .namespace_exact(b"example.com")
            .build();

        let token = CatTokenBuilder::new()
            .issuer("https://test.com")
            .moqt_scope(scope)
            .moqt_reval(60.0) // 1 minute
            .build()
            .unwrap();

        let validator = MoqtValidator::new().with_min_revalidation_interval(300.0); // 5 minutes minimum

        let result = validator.validate_moqt_claims(&token);
        assert!(matches!(
            result,
            Err(CatError::RevalidationIntervalTooShort)
        ));
    }

    #[test]
    fn test_missing_audience_rejected_by_default() {
        let scope = MoqtScopeBuilder::new()
            .publisher()
            .namespace_exact(b"example.com")
            .build();

        let token = CatTokenBuilder::new()
            .issuer("https://test.com")
            .moqt_scope(scope)
            .build()
            .unwrap();

        let validator = MoqtValidator::new();
        let request = ctx(
            MoqtAction::Publish,
            vec![b"example.com".to_vec()],
            b"/stream".to_vec(),
        );
        let result = authorize_no_guard(&validator, &token, &request);
        assert!(matches!(
            result,
            Err(CatError::MissingRequiredClaim(ref c)) if c == "aud"
        ));
    }

    #[test]
    fn test_scope_builder_roles() {
        let pub_scope = roles::publisher(b"cdn.example.com", b"/live/");
        assert!(pub_scope.allows_action(&MoqtAction::Publish));
        assert!(pub_scope.allows_action(&MoqtAction::PublishNamespace));
        assert!(!pub_scope.allows_action(&MoqtAction::Subscribe));

        let sub_scope = roles::subscriber(b"cdn.example.com", b"/live/");
        assert!(sub_scope.allows_action(&MoqtAction::Subscribe));
        assert!(sub_scope.allows_action(&MoqtAction::Fetch));
        assert!(!sub_scope.allows_action(&MoqtAction::Publish));

        let admin_scope = roles::admin(b"cdn.example.com");
        assert!(admin_scope.allows_action(&MoqtAction::Publish));
        assert!(admin_scope.allows_action(&MoqtAction::Subscribe));
        assert!(admin_scope.allows_action(&MoqtAction::TrackStatus));
    }

    #[test]
    fn test_first_match_wins() {
        let scope1 = MoqtScopeBuilder::new()
            .action(MoqtAction::Publish)
            .namespace_exact(b"example.com")
            .track_prefix(b"/stream/")
            .build();

        let scope2 = MoqtScopeBuilder::new()
            .action(MoqtAction::Fetch)
            .namespace_exact(b"example.com")
            .track_prefix(b"/stream/")
            .build();

        let token = CatTokenBuilder::new()
            .issuer("https://test.com")
            .single_audience("relay")
            .moqt_scopes(vec![scope1, scope2])
            .build()
            .unwrap();

        let validator = MoqtValidator::new();

        let request = ctx(
            MoqtAction::Publish,
            vec![b"example.com".to_vec()],
            b"/stream/1".to_vec(),
        );
        let result = authorize_no_guard(&validator, &token, &request).unwrap();
        assert_eq!(result.matched_scope_index(), 0);

        let request = ctx(
            MoqtAction::Fetch,
            vec![b"example.com".to_vec()],
            b"/stream/1".to_vec(),
        );
        let result = authorize_no_guard(&validator, &token, &request).unwrap();
        assert_eq!(result.matched_scope_index(), 1);
    }
}
