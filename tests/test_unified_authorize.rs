// Tests for P0-1: unified fail-closed `MoqtValidator::authorize`.
//
// The audit finding: `authorize_request` only enforced audience, ALPN, MOQT
// scopes, and DPoP. Every other signed CAT claim (`catu`, `catm`, `cath`,
// `catnip`, `catpor`, `catreplay`, `catv`, `catr`) was either silently ignored
// or required a separate manual call. These tests exercise the new
// `authorize` entry point, which enforces every signed claim and returns
// `AuthorizedRequest` only when all of them are satisfied.

#![cfg(feature = "moqt")]

use cat_token::moqt::{AuthorizedRequest, MoqtScopeBuilder, MoqtValidator, RelayRequestContext};
use cat_token::*;
use std::net::IpAddr;
use std::sync::Mutex;

struct MemReplayGuard {
    seen: Mutex<Vec<Vec<u8>>>,
}

impl MemReplayGuard {
    fn new() -> Self {
        Self {
            seen: Mutex::new(Vec::new()),
        }
    }
}

impl ReplayGuard for MemReplayGuard {
    fn check_and_record(&self, cti: &[u8]) -> Result<bool, CatError> {
        let mut seen = self.seen.lock().unwrap();
        let already = seen.iter().any(|s| s.as_slice() == cti);
        if !already {
            seen.push(cti.to_vec());
        }
        Ok(already)
    }
}

fn make_validated(token: &CatToken) -> ValidatedToken {
    let key = HmacSha256Algorithm::new(b"test-key-for-roundtrip-000000000");
    let encoded = encode_token(token, &key).unwrap();
    let validator = CatTokenValidator::new().allow_unencrypted_privacy_claims();
    decode_token(&encoded, &key)
        .unwrap()
        .validate(&validator)
        .unwrap()
}

fn scope() -> MoqtScope {
    MoqtScopeBuilder::new()
        .subscriber()
        .namespace_exact(b"ns")
        .track_prefix(b"track")
        .build()
}

fn baseline_token() -> CatToken {
    CatTokenBuilder::new()
        .issuer("https://issuer.example")
        .single_audience("relay")
        .moqt_scope(scope())
        .build()
        .unwrap()
}

fn baseline_ctx() -> RelayRequestContext {
    RelayRequestContext::new(
        "relay",
        MoqtAction::Subscribe,
        vec![b"ns".to_vec()],
        b"track".to_vec(),
    )
}

fn ok(token: &CatToken, ctx: &RelayRequestContext) -> Result<AuthorizedRequest, CatError> {
    MoqtValidator::new().authorize::<MemReplayGuard>(&make_validated(token), ctx, None, None)
}

#[test]
fn test_baseline_authorizes() {
    let token = baseline_token();
    let ctx = baseline_ctx();
    let result = ok(&token, &ctx).expect("baseline must authorize");
    assert_eq!(result.matched_scope_index, 0);
    assert!(!result.reuse_detected);
    assert!(!result.requires_revalidation);
}

// --- catv ---

#[test]
fn test_authorize_rejects_unknown_catv() {
    // catv=2 is not something this library implements; a fail-closed
    // pipeline must reject rather than silently accept. `CatTokenValidator`
    // catches this during validation, so the token never reaches
    // `MoqtValidator::authorize` — verify the earlier gate here.
    let token = CatTokenBuilder::new()
        .issuer("https://issuer.example")
        .single_audience("relay")
        .moqt_scope(scope())
        .version(2)
        .build()
        .unwrap();
    let key = HmacSha256Algorithm::new(b"test-key-for-roundtrip-000000000");
    let encoded = encode_token(&token, &key).unwrap();
    let validator = CatTokenValidator::new().allow_unencrypted_privacy_claims();
    let result = decode_token(&encoded, &key).unwrap().validate(&validator);
    assert!(matches!(result, Err(CatError::InvalidClaimValue(_))));
}

// --- catu ---

#[test]
fn test_authorize_enforces_catu_match() {
    let rules = vec![UriMatchRule {
        component: URI_COMPONENT_HOST,
        matches: vec![MatchValue::Exact("api.example.com".to_string())],
    }];
    let token = CatTokenBuilder::new()
        .issuer("https://issuer.example")
        .single_audience("relay")
        .moqt_scope(scope())
        .uri_match_rules(rules)
        .build()
        .unwrap();

    let ctx = baseline_ctx().with_request_uri("https://api.example.com/v1/stream");
    ok(&token, &ctx).expect("matching URI must authorize");
}

#[test]
fn test_authorize_rejects_catu_mismatch() {
    let rules = vec![UriMatchRule {
        component: URI_COMPONENT_HOST,
        matches: vec![MatchValue::Exact("api.example.com".to_string())],
    }];
    let token = CatTokenBuilder::new()
        .issuer("https://issuer.example")
        .single_audience("relay")
        .moqt_scope(scope())
        .uri_match_rules(rules)
        .build()
        .unwrap();

    let ctx = baseline_ctx().with_request_uri("https://evil.example/v1/stream");
    let err = ok(&token, &ctx).unwrap_err();
    assert!(matches!(err, CatError::InvalidClaimValue(_)));
}

#[test]
fn test_authorize_rejects_catu_without_uri_context() {
    let rules = vec![UriMatchRule {
        component: URI_COMPONENT_HOST,
        matches: vec![MatchValue::Exact("api.example.com".to_string())],
    }];
    let token = CatTokenBuilder::new()
        .issuer("https://issuer.example")
        .single_audience("relay")
        .moqt_scope(scope())
        .uri_match_rules(rules)
        .build()
        .unwrap();
    let err = ok(&token, &baseline_ctx()).unwrap_err();
    assert!(matches!(err, CatError::InvalidClaimValue(_)));
}

// --- catm ---

#[test]
fn test_authorize_enforces_catm() {
    let mut token = baseline_token();
    token.cat.catm = Some(vec!["GET".to_string(), "HEAD".to_string()]);

    let ctx = baseline_ctx().with_request_method("GET");
    ok(&token, &ctx).expect("allowed method must authorize");

    let ctx_bad = baseline_ctx().with_request_method("POST");
    assert!(matches!(
        ok(&token, &ctx_bad),
        Err(CatError::InvalidClaimValue(_))
    ));

    let ctx_missing = baseline_ctx();
    assert!(matches!(
        ok(&token, &ctx_missing),
        Err(CatError::InvalidClaimValue(_))
    ));
}

// --- cath ---

#[test]
fn test_authorize_enforces_cath() {
    let mut token = baseline_token();
    token.cat.cath = Some(vec![HeaderMatchRule {
        name: "Authorization".to_string(),
        matches: vec![MatchValue::Prefix("Bearer ".to_string())],
    }]);

    let ctx = baseline_ctx().with_request_headers(vec![(
        "Authorization".to_string(),
        "Bearer abc".to_string(),
    )]);
    ok(&token, &ctx).expect("matching header must authorize");

    let ctx_bad = baseline_ctx()
        .with_request_headers(vec![("Authorization".to_string(), "Basic zzz".to_string())]);
    assert!(ok(&token, &ctx_bad).is_err());

    let ctx_missing = baseline_ctx();
    assert!(ok(&token, &ctx_missing).is_err());
}

// --- catnip ---

#[test]
fn test_authorize_enforces_catnip_ip() {
    let mut token = baseline_token();
    token.cat.catnip = Some(vec![
        NetworkIdentifier::from_cidr_str("10.0.0.0/8").unwrap(),
    ]);

    let ip: IpAddr = "10.1.2.3".parse().unwrap();
    let ctx = baseline_ctx().with_peer_ip(ip);
    ok(&token, &ctx).expect("in-prefix IP must authorize");

    let ip_bad: IpAddr = "192.168.1.1".parse().unwrap();
    let ctx_bad = baseline_ctx().with_peer_ip(ip_bad);
    assert!(ok(&token, &ctx_bad).is_err());

    let ctx_missing = baseline_ctx();
    assert!(matches!(
        ok(&token, &ctx_missing),
        Err(CatError::InvalidClaimValue(_))
    ));
}

#[test]
fn test_authorize_enforces_catnip_asn() {
    let mut token = baseline_token();
    token.cat.catnip = Some(vec![NetworkIdentifier::Asn(65001)]);

    let ctx = baseline_ctx().with_peer_asn(65001);
    ok(&token, &ctx).expect("matching ASN must authorize");

    let ctx_bad = baseline_ctx().with_peer_asn(65002);
    assert!(ok(&token, &ctx_bad).is_err());

    let ctx_missing = baseline_ctx();
    assert!(ok(&token, &ctx_missing).is_err());
}

// --- catpor ---

#[test]
fn test_authorize_rejects_catpor_without_block_list() {
    let mut token = baseline_token();
    token.cat.catpor = Some(ProbabilityOfRejection {
        probability: 0.0,
        id: b"pol-1".to_vec(),
        expiration: None,
    });

    let err = ok(&token, &baseline_ctx()).unwrap_err();
    assert!(matches!(err, CatError::InvalidClaimValue(_)));
}

#[test]
fn test_authorize_catpor_with_block_list_zero_probability() {
    let mut token = baseline_token();
    token.cat.catpor = Some(ProbabilityOfRejection {
        probability: 0.0, // never triggers a random rejection
        id: b"pol-1".to_vec(),
        expiration: None,
    });

    let list = CatPorBlockList::new();
    let result = MoqtValidator::new()
        .authorize::<MemReplayGuard>(&make_validated(&token), &baseline_ctx(), None, Some(&list))
        .expect("catpor with zero probability must not reject");
    assert_eq!(result.matched_scope_index, 0);
}

// --- catreplay ---

#[test]
fn test_authorize_catreplay_prohibited_first_call_allowed() {
    let mut token = baseline_token();
    token.core.cti = Some(b"unique-1".to_vec());
    token.cat.catreplay = Some(ReplayProtection::Prohibited);

    let guard = MemReplayGuard::new();
    MoqtValidator::new()
        .authorize(&make_validated(&token), &baseline_ctx(), Some(&guard), None)
        .expect("first call must succeed");

    let err = MoqtValidator::new()
        .authorize(&make_validated(&token), &baseline_ctx(), Some(&guard), None)
        .unwrap_err();
    assert!(matches!(err, CatError::ReplayAttackDetected));
}

#[test]
fn test_authorize_catreplay_reuse_detection_flags_but_allows() {
    let mut token = baseline_token();
    token.core.cti = Some(b"unique-2".to_vec());
    token.cat.catreplay = Some(ReplayProtection::ReuseDetection);

    let guard = MemReplayGuard::new();
    let first = MoqtValidator::new()
        .authorize(&make_validated(&token), &baseline_ctx(), Some(&guard), None)
        .expect("first call must succeed");
    assert!(!first.reuse_detected);

    let second = MoqtValidator::new()
        .authorize(&make_validated(&token), &baseline_ctx(), Some(&guard), None)
        .expect("reuse detection still authorizes");
    assert!(second.reuse_detected);
}

#[test]
fn test_authorize_catreplay_missing_guard_rejects() {
    let mut token = baseline_token();
    token.core.cti = Some(b"unique-3".to_vec());
    token.cat.catreplay = Some(ReplayProtection::Prohibited);

    let err = ok(&token, &baseline_ctx()).unwrap_err();
    assert!(matches!(err, CatError::InvalidClaimValue(_)));
}

#[test]
fn test_authorize_catreplay_missing_cti_rejects() {
    let mut token = baseline_token();
    // No cti set; catreplay=Prohibited requires one.
    token.cat.catreplay = Some(ReplayProtection::Prohibited);

    let guard = MemReplayGuard::new();
    let err = MoqtValidator::new()
        .authorize(&make_validated(&token), &baseline_ctx(), Some(&guard), None)
        .unwrap_err();
    assert!(matches!(err, CatError::MissingRequiredClaim(_)));
}

// --- catr passthrough ---

#[test]
fn test_authorize_returns_catr_renewal() {
    let token = CatTokenBuilder::new()
        .issuer("https://issuer.example")
        .single_audience("relay")
        .moqt_scope(scope())
        .renewal(CatRenewal::automatic().with_expadd(600.0).unwrap())
        .build()
        .unwrap();

    let result = ok(&token, &baseline_ctx()).expect("baseline authorizes");
    assert!(result.renewal.is_some());
    assert_eq!(result.renewal.unwrap().expadd(), Some(600.0));
}

// --- catif lookup helper ---

#[test]
fn test_catif_action_lookup() {
    let token = CatTokenBuilder::new()
        .issuer("https://issuer.example")
        .if_action(CLAIM_EXP, CatIfAction::new(401).unwrap())
        .if_action(CLAIM_AUD, CatIfAction::new(403).unwrap())
        .build()
        .unwrap();

    assert_eq!(
        MoqtValidator::catif_action_for(&token, CLAIM_EXP)
            .unwrap()
            .status(),
        401
    );
    assert_eq!(
        MoqtValidator::catif_action_for(&token, CLAIM_AUD)
            .unwrap()
            .status(),
        403
    );
    assert!(MoqtValidator::catif_action_for(&token, CLAIM_NBF).is_none());
}

// --- audience ---

#[test]
fn test_authorize_rejects_audience_mismatch() {
    let token = CatTokenBuilder::new()
        .issuer("https://issuer.example")
        .single_audience("other-relay")
        .moqt_scope(scope())
        .build()
        .unwrap();

    let err = ok(&token, &baseline_ctx()).unwrap_err();
    assert!(matches!(err, CatError::InvalidAudience));
}

// --- scope ---

#[test]
fn test_authorize_rejects_scope_mismatch() {
    let publish_scope = MoqtScopeBuilder::new()
        .action(MoqtAction::Publish)
        .namespace_exact(b"ns")
        .track_prefix(b"track")
        .build();
    let token = CatTokenBuilder::new()
        .issuer("https://issuer.example")
        .single_audience("relay")
        .moqt_scope(publish_scope)
        .build()
        .unwrap();

    // ctx asks for Subscribe, token only allows Publish.
    let err = ok(&token, &baseline_ctx()).unwrap_err();
    assert!(matches!(err, CatError::MoqtActionNotAuthorized(_)));
}

// --- replay commit ordering ---
//
// Regression for the audit finding: replay state must not be committed until
// every downstream authorization check has passed. An unauthorized request
// that reaches the pipeline with a valid token must NOT consume its cti,
// otherwise a subsequent legitimate request would be rejected as a replay.

#[test]
fn test_replay_not_committed_when_scope_fails() {
    // Token only permits Publish, request context asks for Subscribe.
    let publish_scope = MoqtScopeBuilder::new()
        .action(MoqtAction::Publish)
        .namespace_exact(b"ns")
        .track_prefix(b"track")
        .build();
    let subscribe_scope = MoqtScopeBuilder::new()
        .subscriber()
        .namespace_exact(b"ns")
        .track_prefix(b"track")
        .build();

    let mut token = CatTokenBuilder::new()
        .issuer("https://issuer.example")
        .single_audience("relay")
        .moqt_scope(publish_scope)
        .build()
        .unwrap();
    token.core.cti = Some(b"cti-scope-fail".to_vec());
    token.cat.catreplay = Some(ReplayProtection::Prohibited);

    let guard = MemReplayGuard::new();

    let bad_ctx = baseline_ctx();
    let err = MoqtValidator::new()
        .authorize(&make_validated(&token), &bad_ctx, Some(&guard), None)
        .unwrap_err();
    assert!(matches!(err, CatError::MoqtActionNotAuthorized(_)));

    // Now the legitimate follow-up request with a scope-compatible token
    // must still succeed — the failed attempt above must not have burned
    // the cti.
    let mut good_token = CatTokenBuilder::new()
        .issuer("https://issuer.example")
        .single_audience("relay")
        .moqt_scope(subscribe_scope)
        .build()
        .unwrap();
    good_token.core.cti = Some(b"cti-scope-fail".to_vec());
    good_token.cat.catreplay = Some(ReplayProtection::Prohibited);

    MoqtValidator::new()
        .authorize(
            &make_validated(&good_token),
            &baseline_ctx(),
            Some(&guard),
            None,
        )
        .expect("legitimate follow-up must not be flagged as replay");
}

#[test]
fn test_replay_not_committed_when_audience_fails() {
    // Same cti reused across two attempts, first with wrong audience, second
    // with correct audience. The first must fail without consuming the cti.
    let mut wrong_aud = CatTokenBuilder::new()
        .issuer("https://issuer.example")
        .single_audience("other-relay")
        .moqt_scope(scope())
        .build()
        .unwrap();
    wrong_aud.core.cti = Some(b"cti-aud-fail".to_vec());
    wrong_aud.cat.catreplay = Some(ReplayProtection::Prohibited);

    let guard = MemReplayGuard::new();
    let err = MoqtValidator::new()
        .authorize(
            &make_validated(&wrong_aud),
            &baseline_ctx(),
            Some(&guard),
            None,
        )
        .unwrap_err();
    assert!(matches!(err, CatError::InvalidAudience));

    let mut right_aud = CatTokenBuilder::new()
        .issuer("https://issuer.example")
        .single_audience("relay")
        .moqt_scope(scope())
        .build()
        .unwrap();
    right_aud.core.cti = Some(b"cti-aud-fail".to_vec());
    right_aud.cat.catreplay = Some(ReplayProtection::Prohibited);

    MoqtValidator::new()
        .authorize(
            &make_validated(&right_aud),
            &baseline_ctx(),
            Some(&guard),
            None,
        )
        .expect("legitimate follow-up must not be flagged as replay");
}
