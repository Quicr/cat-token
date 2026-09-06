// SPDX-FileCopyrightText: Copyright (c) 2022 Quicr
// SPDX-License-Identifier: BSD-2-Clause

use crate::{
    BinaryMatch, CatDpopSettings, CatError, CatIfAction, CatPorBlockList, CatRenewal, CatToken,
    DpopProof, DpopValidator, MoqtAction, MoqtScope, NamespaceMatch, ReplayGuard, ValidatedToken,
    confirmation_matches_jwk, enforce_catnip, enforce_catpor, enforce_catreplay, enforce_catu,
    validate_all_headers, validate_method,
};
/// IANA-registered token type for C4M (CAT for MoQ) AUTHORIZATION TOKEN parameter.
pub const C4M_TOKEN_TYPE: u64 = 0x01;

/// Authorization outcome for a single request. Produced only when every
/// signed CAT claim on the token was satisfied by the request context.
/// Carries derived data the caller needs to construct the response:
/// revalidation policy, the token's `catr` renewal instructions (if any),
/// and whether the token's `catreplay` mode observed a duplicate cti
/// (`Prohibited` fails hard; `ReuseDetection` sets this flag for the caller
/// to log/audit).
#[derive(Debug, Clone)]
pub struct AuthorizedRequest {
    pub matched_scope_index: usize,
    pub requires_revalidation: bool,
    pub revalidation_interval: Option<f64>,
    pub renewal: Option<CatRenewal>,
    pub reuse_detected: bool,
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
}

/// Context for a relay authorization request, used with
/// [`MoqtValidator::authorize`].
///
/// This is the only supported entry point for authorization. Fields describe the
/// full request context — a missing field represents an unknown value, not a
/// wildcard, and will cause authorization to fail closed when a token claim
/// requires that context (e.g. `catalpn` requires `peer_tls_alpn`).
#[derive(Debug, Clone)]
pub struct RelayRequestContext {
    /// Canonical relay endpoint the client connected to. Matched against the
    /// token's `aud` claim (if present).
    pub relay_endpoint: String,
    /// The MOQT action being requested.
    pub action: MoqtAction,
    /// The full track name namespace tuple.
    pub namespace: Vec<Vec<u8>>,
    /// The track name.
    pub track: Vec<u8>,
    /// TLS ALPN identifier negotiated with the peer. Required if the token has
    /// a `catalpn` claim.
    pub peer_tls_alpn: Option<Vec<u8>>,
    /// Optional tenant/connection identity carried from a trusted upstream.
    /// Not enforced by the library — passed through to metrics/audit hooks by
    /// the caller. Present for callers that partition replay state by tenant.
    pub tenant_id: Option<String>,
    /// DPoP proof of possession. Required if the token has a `cnf` claim.
    pub dpop_proof: Option<DpopProof>,
    /// Fully-qualified request URI. Required if the token has a `catu` claim.
    pub request_uri: Option<String>,
    /// HTTP method (or equivalent transport verb). Required if the token has
    /// a `catm` claim.
    pub request_method: Option<String>,
    /// Complete request header set (name, value pairs). Every rule in the
    /// token's `cath` claim must be satisfied by some header in this list.
    /// Case-insensitive on name per RFC 9110 §5.1.
    pub request_headers: Vec<(String, String)>,
    /// Peer IP address. Required if the token's `catnip` claim contains any
    /// IP-typed identifier.
    pub peer_ip: Option<std::net::IpAddr>,
    /// Peer autonomous system number. Required if the token's `catnip`
    /// contains any ASN-typed identifier.
    pub peer_asn: Option<u32>,
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
            tenant_id: None,
            dpop_proof: None,
            request_uri: None,
            request_method: None,
            request_headers: Vec::new(),
            peer_ip: None,
            peer_asn: None,
        }
    }

    pub fn with_peer_tls_alpn(mut self, alpn: Vec<u8>) -> Self {
        self.peer_tls_alpn = Some(alpn);
        self
    }

    pub fn with_tenant_id(mut self, tenant: impl Into<String>) -> Self {
        self.tenant_id = Some(tenant.into());
        self
    }

    pub fn with_dpop_proof(mut self, proof: DpopProof) -> Self {
        self.dpop_proof = Some(proof);
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

    pub fn with_request_headers(mut self, headers: Vec<(String, String)>) -> Self {
        self.request_headers = headers;
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
}

/// MOQT-specific token validator
#[derive(Clone)]
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
        }
    }

    /// Set minimum revalidation interval this relay can support
    pub fn with_min_revalidation_interval(mut self, seconds: f64) -> Self {
        self.min_revalidation_interval = Some(seconds);
        self
    }

    /// Disable revalidation support
    pub fn without_revalidation_support(mut self) -> Self {
        self.supports_revalidation = false;
        self
    }

    /// Enable DPoP validation backed by the in-process eviction-based
    /// [`crate::LruJtiStore`].
    ///
    /// **Not strict.** RFC 9449 §11.1 requires every accepted JTI be
    /// retained for at least the freshness window; the LRU-backed default
    /// evicts under pressure. CDN-scale deployments MUST call
    /// [`MoqtValidator::try_with_strict_dpop_validation`] or
    /// [`MoqtValidator::with_dpop_validator`] instead, passing a store that
    /// returns `true` from [`crate::JtiStore::is_strict`].
    pub fn with_dpop_validation(mut self, settings: CatDpopSettings) -> Self {
        self.dpop_validator = Some(DpopValidator::new(settings));
        self
    }

    /// Enable DPoP validation with a caller-supplied strict [`JtiStore`].
    /// The store MUST return `true` from [`crate::JtiStore::is_strict`];
    /// otherwise this returns [`CatError::CryptoError`] rather than
    /// silently accept a store that could shed retained JTIs.
    ///
    /// Use this constructor for any deployment that shares replay state
    /// across relays or that must survive a single-relay restart without
    /// losing replay defense. The strict-mode contract is a hard
    /// prerequisite for that guarantee.
    pub fn try_with_strict_dpop_validation(
        mut self,
        settings: CatDpopSettings,
        store: std::sync::Arc<dyn crate::JtiStore>,
    ) -> Result<Self, CatError> {
        self.dpop_validator = Some(DpopValidator::with_jti_store_strict(settings, store)?);
        Ok(self)
    }

    /// Plug in a pre-constructed [`DpopValidator`]. The caller is
    /// responsible for choosing the underlying [`JtiStore`] and for the
    /// strictness guarantee — use this when the surrounding application
    /// already owns a `DpopValidator` (e.g. shared across multiple
    /// authorization pipelines).
    pub fn with_dpop_validator(mut self, validator: DpopValidator) -> Self {
        self.dpop_validator = Some(validator);
        self
    }

    /// Set the expected resource URI for DPoP binding validation
    pub fn with_expected_resource(mut self, resource: impl Into<String>) -> Self {
        self.expected_resource = Some(resource.into());
        self
    }

    /// Allow tokens without an `aud` claim. Tokens that DO carry `aud` are still
    /// checked against the relay endpoint. Use only if the deployment intentionally
    /// issues audience-less tokens; the default (audience required) is fail-closed.
    pub fn allow_missing_audience(mut self) -> Self {
        self.require_audience_binding = false;
        self
    }

    /// Validate MOQT-specific claims in the token
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
    pub fn authorize<G: ReplayGuard + ?Sized>(
        &self,
        token: &ValidatedToken,
        ctx: &RelayRequestContext,
        replay_guard: Option<&G>,
        catpor_block_list: Option<&CatPorBlockList>,
    ) -> Result<AuthorizedRequest, CatError> {
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

        // 4. ALPN.
        if let Some(ref token_alpns) = claims.cat.catalpn {
            let peer_alpn = ctx.peer_tls_alpn.as_ref().ok_or_else(|| {
                CatError::InvalidClaimValue(
                    "token requires ALPN binding but no peer ALPN provided".to_string(),
                )
            })?;
            if !token_alpns.iter().any(|a| a == peer_alpn) {
                return Err(CatError::InvalidClaimValue(
                    "peer TLS ALPN does not match token catalpn".to_string(),
                ));
            }
        }

        // 5. catu — URI-component restrictions.
        if claims.cat.catu.is_some() {
            let uri = ctx.request_uri.as_deref().ok_or_else(|| {
                CatError::InvalidClaimValue(
                    "token asserts catu but request context has no request_uri".to_string(),
                )
            })?;
            enforce_catu(claims, uri)?;
        }

        // 6. catm — HTTP method restrictions.
        if claims.cat.catm.is_some() {
            let method = ctx.request_method.as_deref().ok_or_else(|| {
                CatError::InvalidClaimValue(
                    "token asserts catm but request context has no request_method".to_string(),
                )
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
            let block_list = catpor_block_list.ok_or_else(|| {
                CatError::InvalidClaimValue(
                    "token asserts catpor but no block list configured on relay".to_string(),
                )
            })?;
            enforce_catpor(claims, block_list)?;
        }

        // 10. catreplay — verify the guard is configured when the token
        //     demands one. The commit is deferred to the end of the pipeline
        //     so that a request that fails downstream checks does not consume
        //     the token's cti.
        let replay_mode = claims.cat.catreplay;
        let replay_guard_for_commit = match replay_mode {
            Some(crate::ReplayProtection::Prohibited)
            | Some(crate::ReplayProtection::ReuseDetection) => {
                Some(replay_guard.ok_or_else(|| {
                    CatError::InvalidClaimValue(
                        "token asserts catreplay but no replay guard configured".to_string(),
                    )
                })?)
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

            if !confirmation_matches_jwk(cnf, &proof.header.jwk)? {
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

            Some((validator, proof, cnf, issuer))
        } else {
            None
        };

        // 13. Commit phase. All authorization checks above have passed; only
        //     now do we consume replay-state resources so an unauthorized
        //     request cannot burn a legitimate token's cti.
        //
        // Commit the in-memory DPoP JTI first, then the CAT cti. The two
        // stores are independent; without a two-phase transaction the crate
        // must pick an ordering. JTI first is safer because:
        //   - The default JTI store is in-process and rarely fails
        //     transiently (lock poisoning is the only real failure surface).
        //   - The `cti` store is often a distributed backend behind the
        //     `ReplayGuard` trait and its failures can be transient.
        //   - If the cti commit fails after JTI commit, the client retries
        //     with a fresh JTI (required per RFC 9449) so no state is
        //     leaked: the second attempt sees a virgin cti store and
        //     succeeds. The reverse ordering (cti first) would leave the
        //     cti consumed on a JTI failure and turn every transient JTI
        //     hiccup into a permanent replay error on the caller's retry.
        //   - If a caller needs strict atomicity between the two stores,
        //     they can bind both to the same backend behind `ReplayGuard`
        //     and issue a single transactional commit inside
        //     `check_and_record`.
        if let Some((validator, proof, cnf, issuer)) = dpop_commit {
            validator.commit_jti(proof, &cnf.jkt, issuer)?;
        }

        let reuse_detected = if let Some(guard) = replay_guard_for_commit {
            enforce_catreplay(claims, guard)?
        } else {
            false
        };

        let mut authorized = AuthorizedRequest::allowed(scope_index);
        authorized.reuse_detected = reuse_detected;
        authorized.renewal = claims.request.catr.clone();
        if let Some(reval) = claims.moqt.moqt_reval
            && reval > 0.0
        {
            authorized.requires_revalidation = true;
            authorized.revalidation_interval = Some(reval);
        }
        Ok(authorized)
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
    use crate::MoqtResourceShape::*;
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
    use crate::MoqtResourceShape::*;
    match action.resource_shape() {
        Endpoint => {
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
        validator.authorize::<dyn ReplayGuard>(
            &ValidatedToken::from_unchecked(token.clone()),
            request,
            None,
            None,
        )
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

        assert!(result.requires_revalidation);
        assert_eq!(result.revalidation_interval, Some(300.0));
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

        let validator = MoqtValidator::new().without_revalidation_support();

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
        assert_eq!(result.matched_scope_index, 0);

        let request = ctx(
            MoqtAction::Fetch,
            vec![b"example.com".to_vec()],
            b"/stream/1".to_vec(),
        );
        let result = authorize_no_guard(&validator, &token, &request).unwrap();
        assert_eq!(result.matched_scope_index, 1);
    }
}
