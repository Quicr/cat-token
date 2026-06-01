// SPDX-FileCopyrightText: Copyright (c) 2022 Quicr
// SPDX-License-Identifier: BSD-2-Clause

use crate::{
    BinaryMatch, CatDpopSettings, CatError, CatToken, CryptographicAlgorithm, DpopProof,
    DpopValidator, MoqtAction, MoqtScope, NamespaceMatch, confirmation_matches_jwk,
};

/// IANA-registered token type for C4M (CAT for MoQ) AUTHORIZATION TOKEN parameter.
/// Value: "c4m" encoded as 24-bit big-endian integer (0x63 = 'c', 0x34 = '4', 0x6d = 'm').
pub const C4M_TOKEN_TYPE: u64 = 0x63346d;

/// MOQT authorization request
#[derive(Debug, Clone)]
pub struct MoqtAuthRequest {
    pub action: MoqtAction,
    pub namespace: Vec<Vec<u8>>, // Namespace tuple elements
    pub track: Vec<u8>,
    pub dpop_proof: Option<DpopProof>,
}

impl MoqtAuthRequest {
    pub fn new(action: MoqtAction, namespace: Vec<Vec<u8>>, track: Vec<u8>) -> Self {
        Self {
            action,
            namespace,
            track,
            dpop_proof: None,
        }
    }

    pub fn with_dpop_proof(mut self, proof: DpopProof) -> Self {
        self.dpop_proof = Some(proof);
        self
    }
}

/// Result of MOQT authorization check
#[derive(Debug, Clone)]
pub struct MoqtAuthResult {
    pub authorized: bool,
    pub matched_scope_index: Option<usize>,
    pub requires_revalidation: bool,
    pub revalidation_interval: Option<f64>,
}

impl MoqtAuthResult {
    pub fn denied() -> Self {
        Self {
            authorized: false,
            matched_scope_index: None,
            requires_revalidation: false,
            revalidation_interval: None,
        }
    }

    pub fn allowed(scope_index: usize) -> Self {
        Self {
            authorized: true,
            matched_scope_index: Some(scope_index),
            requires_revalidation: false,
            revalidation_interval: None,
        }
    }

    pub fn with_revalidation(mut self, interval: f64) -> Self {
        self.requires_revalidation = interval > 0.0;
        self.revalidation_interval = Some(interval);
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

    /// Enable DPoP validation with settings
    pub fn with_dpop_validation(mut self, settings: CatDpopSettings) -> Self {
        self.dpop_validator = Some(DpopValidator::new(settings));
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

    /// Check if a specific MOQT action is authorized
    /// "Evaluation stops after the first acceptable result is discovered"
    pub fn authorize(&self, token: &CatToken, request: &MoqtAuthRequest) -> MoqtAuthResult {
        let scopes = match &token.moqt.moqt {
            Some(s) => s,
            None => return MoqtAuthResult::denied(), // No MOQT claims means blocked
        };

        // Evaluate scopes in order, stop at first match
        for (index, scope) in scopes.iter().enumerate() {
            if self.scope_matches(scope, request) {
                let mut result = MoqtAuthResult::allowed(index);

                // Add revalidation info if present
                if let Some(reval) = token.moqt.moqt_reval {
                    result = result.with_revalidation(reval);
                }

                return result;
            }
        }

        // "The default for all actions is 'Blocked'"
        MoqtAuthResult::denied()
    }

    /// Authorize with full DPoP proof validation including signature verification.
    ///
    /// This method validates both the claims and the cryptographic signature of the DPoP proof.
    pub fn authorize_with_dpop(
        &self,
        token: &CatToken,
        request: &MoqtAuthRequest,
        algorithm: &dyn CryptographicAlgorithm,
    ) -> Result<MoqtAuthResult, CatError> {
        // First check basic authorization
        let auth_result = self.authorize(token, request);
        if !auth_result.authorized {
            return Ok(auth_result);
        }

        // If token has DPoP binding, validate the proof with full signature verification
        if let Some(ref cnf) = token.dpop.cnf {
            let proof = request.dpop_proof.as_ref().ok_or_else(|| {
                CatError::DpopValidationFailed(
                    "Token requires DPoP proof but none provided".to_string(),
                )
            })?;

            // Validate DPoP proof
            let validator = self.dpop_validator.as_ref().ok_or_else(|| {
                CatError::DpopValidationFailed("DPoP validation not configured".to_string())
            })?;

            // Check key binding
            if !confirmation_matches_jwk(cnf, &proof.header.jwk)? {
                return Err(CatError::InvalidDpopBinding);
            }

            // Validate the proof with full signature verification
            validator.validate_with_algorithm(proof, request.action, &cnf.jkt, algorithm)?;
        }

        Ok(auth_result)
    }

    /// Check if a scope matches the request
    fn scope_matches(&self, scope: &MoqtScope, request: &MoqtAuthRequest) -> bool {
        // Check if action is allowed
        if !scope.allows_action(&request.action) {
            return false;
        }

        // Check namespace matches
        // "Matches are performed bytewise against the corresponding field of the Full Track Name"
        if !scope.namespace_matches.is_empty() {
            for (i, ns_match) in scope.namespace_matches.iter().enumerate() {
                let tuple_elem = request.namespace.get(i).map(|v| v.as_slice());
                if !ns_match.matches(tuple_elem) {
                    return false;
                }
            }
        }

        // Check track match
        if let Some(ref track_match) = scope.track_match
            && !track_match.matches(&request.track)
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

    /// Add namespace matches from a `/`-separated path.
    /// Each segment becomes a separate exact-match element in the namespace tuple.
    /// For example, `namespace_path(b"sports/football")` is equivalent to
    /// calling `.namespace_exact(b"sports").namespace_exact(b"football")`.
    pub fn namespace_path(mut self, path: &[u8]) -> Self {
        for segment in path.split(|&b| b == b'/') {
            if !segment.is_empty() {
                self.namespace_matches
                    .push(NamespaceMatch::exact(segment.to_vec()));
            }
        }
        self
    }

    /// Add namespace prefix matches from a `/`-separated path.
    /// Each segment becomes a prefix-match element in the namespace tuple.
    /// The last segment uses prefix matching, all preceding use exact matching.
    /// For example, `namespace_path_prefix(b"sports/foot")` exact-matches "sports"
    /// and prefix-matches "foot" (matching "football", "footwear", etc.).
    pub fn namespace_path_prefix(mut self, path: &[u8]) -> Self {
        let segments: Vec<&[u8]> = path.split(|&b| b == b'/').filter(|s| !s.is_empty()).collect();
        if let Some((last, preceding)) = segments.split_last() {
            for segment in preceding {
                self.namespace_matches
                    .push(NamespaceMatch::exact(segment.to_vec()));
            }
            self.namespace_matches
                .push(NamespaceMatch::prefix(last.to_vec()));
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CatTokenBuilder;

    #[test]
    fn test_moqt_auth_request() {
        let request = MoqtAuthRequest::new(
            MoqtAction::Publish,
            vec![b"example.com".to_vec()],
            b"/stream/video".to_vec(),
        );

        assert_eq!(request.action, MoqtAction::Publish);
        assert_eq!(request.namespace, vec![b"example.com".to_vec()]);
        assert_eq!(request.track, b"/stream/video".to_vec());
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
            .moqt_scope(scope)
            .build();

        let validator = MoqtValidator::new();

        // Should allow
        let request = MoqtAuthRequest::new(
            MoqtAction::Publish,
            vec![b"example.com".to_vec()],
            b"/stream/video".to_vec(),
        );
        let result = validator.authorize(&token, &request);
        assert!(result.authorized);

        // Should deny (wrong action)
        let request = MoqtAuthRequest::new(
            MoqtAction::Fetch,
            vec![b"example.com".to_vec()],
            b"/stream/video".to_vec(),
        );
        let result = validator.authorize(&token, &request);
        assert!(!result.authorized);

        // Should deny (wrong namespace)
        let request = MoqtAuthRequest::new(
            MoqtAction::Publish,
            vec![b"other.com".to_vec()],
            b"/stream/video".to_vec(),
        );
        let result = validator.authorize(&token, &request);
        assert!(!result.authorized);

        // Should deny (wrong track)
        let request = MoqtAuthRequest::new(
            MoqtAction::Publish,
            vec![b"example.com".to_vec()],
            b"/other/video".to_vec(),
        );
        let result = validator.authorize(&token, &request);
        assert!(!result.authorized);
    }

    #[test]
    fn test_moqt_validator_revalidation() {
        let scope = MoqtScopeBuilder::new()
            .publisher()
            .namespace_exact(b"example.com")
            .build();

        let token = CatTokenBuilder::new()
            .issuer("https://test.com")
            .moqt_scope(scope)
            .moqt_reval(300.0)
            .build();

        let validator = MoqtValidator::new();

        let request = MoqtAuthRequest::new(
            MoqtAction::Publish,
            vec![b"example.com".to_vec()],
            b"/stream".to_vec(),
        );
        let result = validator.authorize(&token, &request);

        assert!(result.authorized);
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
            .build();

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
            .build();

        let validator = MoqtValidator::new().with_min_revalidation_interval(300.0); // 5 minutes minimum

        let result = validator.validate_moqt_claims(&token);
        assert!(matches!(
            result,
            Err(CatError::RevalidationIntervalTooShort)
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
        // Create two scopes - first denies Fetch, second allows it
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
            .moqt_scopes(vec![scope1, scope2])
            .build();

        let validator = MoqtValidator::new();

        // Publish should match scope 0
        let request = MoqtAuthRequest::new(
            MoqtAction::Publish,
            vec![b"example.com".to_vec()],
            b"/stream/1".to_vec(),
        );
        let result = validator.authorize(&token, &request);
        assert!(result.authorized);
        assert_eq!(result.matched_scope_index, Some(0));

        // Fetch should match scope 1
        let request = MoqtAuthRequest::new(
            MoqtAction::Fetch,
            vec![b"example.com".to_vec()],
            b"/stream/1".to_vec(),
        );
        let result = validator.authorize(&token, &request);
        assert!(result.authorized);
        assert_eq!(result.matched_scope_index, Some(1));
    }
}
