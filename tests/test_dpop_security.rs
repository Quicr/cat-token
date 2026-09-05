// SPDX-FileCopyrightText: Copyright (c) 2022 Quicr
// SPDX-License-Identifier: BSD-2-Clause

#![cfg(feature = "moqt")]

use cat_token::dpop::{DpopProof, DpopValidator, compute_access_token_hash, generate_jti};
use cat_token::jwk::Jwk;
use cat_token::*;

fn make_validated(token: &CatToken) -> ValidatedToken {
    let key = HmacSha256Algorithm::new(b"test-key-for-roundtrip-000000000");
    let encoded = encode_token(token, &key).unwrap();
    let validator = CatTokenValidator::new().allow_unencrypted_privacy_claims();
    decode_token(&encoded, &key)
        .unwrap()
        .validate(&validator)
        .unwrap()
}

fn ath_for(validated: &ValidatedToken) -> Vec<u8> {
    compute_access_token_hash(validated.serialized())
}

#[test]
fn test_dpop_uses_embedded_key() {
    let alg = Es256Algorithm::new_with_key_pair().unwrap();
    let jwk = Jwk::from_es256_verifying_key(alg.verifying_key()).unwrap();
    let thumbprint = jwk.thumbprint().unwrap();

    let mut proof = DpopProof::create_for_moqt(
        MoqtAction::Subscribe,
        vec![b"ns".to_vec()],
        b"track",
        ALG_ES256,
        jwk,
    )
    .with_jti(generate_jti());
    proof.sign(&alg).unwrap();

    let settings = CatDpopSettings::new().with_window(300).unwrap();
    let validator = DpopValidator::new(settings);

    // validate() derives the key from the embedded JWK — no external algorithm needed
    validator
        .validate(&proof, MoqtAction::Subscribe, &thumbprint, None)
        .unwrap();
}

#[test]
fn test_dpop_wrong_embedded_key_rejected() {
    // CAT signing key
    let cat_alg = Es256Algorithm::new_with_key_pair().unwrap();

    // DPoP proof key (different from CAT key)
    let dpop_alg = Es256Algorithm::new_with_key_pair().unwrap();
    let dpop_jwk = Jwk::from_es256_verifying_key(dpop_alg.verifying_key()).unwrap();
    let dpop_thumbprint = dpop_jwk.thumbprint().unwrap();

    // Create proof with dpop_jwk in header but sign with cat_alg (wrong key)
    let mut proof = DpopProof::create_for_moqt(
        MoqtAction::Subscribe,
        vec![b"ns".to_vec()],
        b"track",
        ALG_ES256,
        dpop_jwk,
    )
    .with_jti(generate_jti());
    // Sign with a DIFFERENT key than the one in the JWK header
    proof.sign(&cat_alg).unwrap();

    let settings = CatDpopSettings::new().with_window(300).unwrap();
    let validator = DpopValidator::new(settings);

    // Should fail — signature was made with cat_alg but JWK advertises dpop_alg's key
    let result = validator.validate(&proof, MoqtAction::Subscribe, &dpop_thumbprint, None);
    assert!(result.is_err(), "Should reject proof signed with wrong key");
    assert!(matches!(result, Err(CatError::SignatureVerificationFailed)));
}

#[test]
fn test_dpop_namespace_mismatch_rejected() {
    let alg = Es256Algorithm::new_with_key_pair().unwrap();
    let jwk = Jwk::from_es256_verifying_key(alg.verifying_key()).unwrap();
    let thumbprint = jwk.thumbprint().unwrap();

    // Create proof bound to namespace_a
    let mut proof = DpopProof::create_for_moqt(
        MoqtAction::Publish,
        vec![b"namespace_a".to_vec()],
        b"track",
        ALG_ES256,
        jwk.clone(),
    )
    .with_jti(generate_jti());
    proof.sign(&alg).unwrap();

    let scope = cat_token::moqt::MoqtScopeBuilder::new()
        .action(MoqtAction::Publish)
        .namespace_prefix(b"namespace")
        .build();

    let token = CatTokenBuilder::new()
        .issuer("https://test.com")
        .single_audience("relay")
        .moqt_scope(scope)
        .confirmation(thumbprint)
        .build()
        .unwrap();

    let settings = CatDpopSettings::new().with_window(300).unwrap();
    let validator = cat_token::moqt::MoqtValidator::new().with_dpop_validation(settings);

    // Request for namespace_b — proof is bound to namespace_a
    let request = cat_token::moqt::RelayRequestContext::new(
        "relay",
        MoqtAction::Publish,
        vec![b"namespace_b".to_vec()],
        b"track".to_vec(),
    )
    .with_dpop_proof(proof);

    let result =
        validator.authorize::<dyn ReplayGuard>(&make_validated(&token), &request, None, None);
    assert!(result.is_err(), "Should reject namespace mismatch");
    assert!(matches!(result, Err(CatError::DpopValidationFailed(_))));
}

#[test]
fn test_dpop_track_mismatch_rejected() {
    let alg = Es256Algorithm::new_with_key_pair().unwrap();
    let jwk = Jwk::from_es256_verifying_key(alg.verifying_key()).unwrap();
    let thumbprint = jwk.thumbprint().unwrap();

    // Create proof bound to track_a
    let mut proof = DpopProof::create_for_moqt(
        MoqtAction::Publish,
        vec![b"ns".to_vec()],
        b"track_a",
        ALG_ES256,
        jwk.clone(),
    )
    .with_jti(generate_jti());
    proof.sign(&alg).unwrap();

    let scope = cat_token::moqt::MoqtScopeBuilder::new()
        .action(MoqtAction::Publish)
        .namespace_exact(b"ns")
        .build();

    let token = CatTokenBuilder::new()
        .issuer("https://test.com")
        .single_audience("relay")
        .moqt_scope(scope)
        .confirmation(thumbprint)
        .build()
        .unwrap();

    let settings = CatDpopSettings::new().with_window(300).unwrap();
    let validator = cat_token::moqt::MoqtValidator::new().with_dpop_validation(settings);

    // Request for track_b — proof is bound to track_a
    let request = cat_token::moqt::RelayRequestContext::new(
        "relay",
        MoqtAction::Publish,
        vec![b"ns".to_vec()],
        b"track_b".to_vec(),
    )
    .with_dpop_proof(proof);

    let result =
        validator.authorize::<dyn ReplayGuard>(&make_validated(&token), &request, None, None);
    assert!(result.is_err(), "Should reject track mismatch");
    assert!(matches!(result, Err(CatError::DpopValidationFailed(_))));
}

#[test]
fn test_dpop_matching_target_succeeds() {
    let alg = Es256Algorithm::new_with_key_pair().unwrap();
    let jwk = Jwk::from_es256_verifying_key(alg.verifying_key()).unwrap();
    let thumbprint = jwk.thumbprint().unwrap();

    let ns = vec![b"ns".to_vec()];
    let track = b"track";

    let scope = cat_token::moqt::MoqtScopeBuilder::new()
        .action(MoqtAction::Publish)
        .namespace_exact(b"ns")
        .build();

    let token = CatTokenBuilder::new()
        .issuer("https://test.com")
        .single_audience("relay")
        .moqt_scope(scope)
        .confirmation(thumbprint)
        .build()
        .unwrap();

    let validated = make_validated(&token);
    let mut proof = DpopProof::create_for_moqt(
        MoqtAction::Publish,
        ns.clone(),
        track,
        ALG_ES256,
        jwk.clone(),
    )
    .with_jti(generate_jti())
    .with_access_token_hash(ath_for(&validated));
    proof.sign(&alg).unwrap();

    let settings = CatDpopSettings::new().with_window(300).unwrap();
    let validator = cat_token::moqt::MoqtValidator::new().with_dpop_validation(settings);

    let request =
        cat_token::moqt::RelayRequestContext::new("relay", MoqtAction::Publish, ns, track.to_vec())
            .with_dpop_proof(proof);

    let result = validator.authorize::<dyn ReplayGuard>(&validated, &request, None, None);
    assert!(
        result.is_ok(),
        "authorize should succeed with valid ath: {result:?}"
    );
}

#[test]
fn test_replay_cache_not_polluted_on_bad_signature() {
    let good_alg = Es256Algorithm::new_with_key_pair().unwrap();
    let good_jwk = Jwk::from_es256_verifying_key(good_alg.verifying_key()).unwrap();
    let thumbprint = good_jwk.thumbprint().unwrap();

    let bad_alg = Es256Algorithm::new_with_key_pair().unwrap();
    let jti = generate_jti();

    // Create proof with good_jwk but sign with bad_alg
    let mut bad_proof = DpopProof::create_for_moqt(
        MoqtAction::Subscribe,
        vec![b"ns".to_vec()],
        b"track",
        ALG_ES256,
        good_jwk.clone(),
    )
    .with_jti(jti.clone());
    bad_proof.sign(&bad_alg).unwrap();

    let settings = CatDpopSettings::new()
        .with_window(300)
        .unwrap()
        .with_jti_processing(true);
    let validator = DpopValidator::new(settings);

    // Should fail — wrong signature
    let result = validator.validate(&bad_proof, MoqtAction::Subscribe, &thumbprint, None);
    assert!(result.is_err());

    // Now create a valid proof with the SAME JTI
    let mut good_proof = DpopProof::create_for_moqt(
        MoqtAction::Subscribe,
        vec![b"ns".to_vec()],
        b"track",
        ALG_ES256,
        good_jwk,
    )
    .with_jti(jti);
    good_proof.sign(&good_alg).unwrap();

    // Should succeed — the JTI was NOT consumed by the failed attempt
    let result = validator.validate(&good_proof, MoqtAction::Subscribe, &thumbprint, None);
    assert!(
        result.is_ok(),
        "JTI should not be consumed by failed signature verification: {:?}",
        result
    );
}

#[test]
fn test_dpop_key_mismatch_detected() {
    let alg = Es256Algorithm::new_with_key_pair().unwrap();
    let jwk = Jwk::from_es256_verifying_key(alg.verifying_key()).unwrap();

    // Different key's thumbprint
    let other_alg = Es256Algorithm::new_with_key_pair().unwrap();
    let other_jwk = Jwk::from_es256_verifying_key(other_alg.verifying_key()).unwrap();
    let other_thumbprint = other_jwk.thumbprint().unwrap();

    let mut proof = DpopProof::create_for_moqt(
        MoqtAction::Subscribe,
        vec![b"ns".to_vec()],
        b"track",
        ALG_ES256,
        jwk,
    )
    .with_jti(generate_jti());
    proof.sign(&alg).unwrap();

    let settings = CatDpopSettings::new().with_window(300).unwrap();
    let validator = DpopValidator::new(settings);

    // Should fail — embedded JWK thumbprint doesn't match expected
    let result = validator.validate(&proof, MoqtAction::Subscribe, &other_thumbprint, None);
    assert!(
        matches!(
            result,
            Err(CatError::InvalidDpopBinding) | Err(CatError::DpopKeyMismatch)
        ),
        "Should reject key mismatch: {:?}",
        result
    );
}

// --- H1: DPoP proofs accompanying a cnf-bound token must carry `ath` that
//         hashes the exact wire bytes of the token. Without this binding a
//         valid proof for one token could be reused against another token
//         issued to the same holder key.

fn dpop_bound_token(jkt: Vec<u8>) -> CatToken {
    let scope = cat_token::moqt::MoqtScopeBuilder::new()
        .action(MoqtAction::Publish)
        .namespace_exact(b"ns")
        .build();
    CatTokenBuilder::new()
        .issuer("https://test.com")
        .single_audience("relay")
        .moqt_scope(scope)
        .confirmation(jkt)
        .build()
        .unwrap()
}

fn dpop_request(proof: DpopProof) -> cat_token::moqt::RelayRequestContext {
    cat_token::moqt::RelayRequestContext::new(
        "relay",
        MoqtAction::Publish,
        vec![b"ns".to_vec()],
        b"track".to_vec(),
    )
    .with_dpop_proof(proof)
}

#[test]
fn test_authorize_rejects_missing_ath() {
    let alg = Es256Algorithm::new_with_key_pair().unwrap();
    let jwk = Jwk::from_es256_verifying_key(alg.verifying_key()).unwrap();
    let thumbprint = jwk.thumbprint().unwrap();

    let token = dpop_bound_token(thumbprint);
    let validated = make_validated(&token);

    let mut proof = DpopProof::create_for_moqt(
        MoqtAction::Publish,
        vec![b"ns".to_vec()],
        b"track",
        ALG_ES256,
        jwk,
    )
    .with_jti(generate_jti());
    proof.sign(&alg).unwrap();

    let settings = CatDpopSettings::new().with_window(300).unwrap();
    let v = cat_token::moqt::MoqtValidator::new().with_dpop_validation(settings);

    let result = v.authorize::<dyn ReplayGuard>(&validated, &dpop_request(proof), None, None);
    assert!(
        matches!(result, Err(CatError::DpopValidationFailed(_))),
        "authorize must fail closed when proof omits ath: {result:?}"
    );
}

#[test]
fn test_authorize_rejects_ath_bound_to_different_token() {
    let alg = Es256Algorithm::new_with_key_pair().unwrap();
    let jwk = Jwk::from_es256_verifying_key(alg.verifying_key()).unwrap();
    let thumbprint = jwk.thumbprint().unwrap();

    // Two tokens sharing the same holder key. A proof valid for token_a must
    // not authorize a request that presents token_b.
    let mut token_a = dpop_bound_token(thumbprint.clone());
    token_a.core.iss = Some("https://a.example".to_string());
    let mut token_b = dpop_bound_token(thumbprint);
    token_b.core.iss = Some("https://b.example".to_string());

    let validated_a = make_validated(&token_a);
    let validated_b = make_validated(&token_b);
    assert_ne!(
        validated_a.serialized(),
        validated_b.serialized(),
        "test setup: distinct tokens must serialize distinctly"
    );

    // Proof carries ath computed from token_a, presented alongside token_b.
    let mut proof = DpopProof::create_for_moqt(
        MoqtAction::Publish,
        vec![b"ns".to_vec()],
        b"track",
        ALG_ES256,
        jwk,
    )
    .with_jti(generate_jti())
    .with_access_token_hash(ath_for(&validated_a));
    proof.sign(&alg).unwrap();

    let settings = CatDpopSettings::new().with_window(300).unwrap();
    let v = cat_token::moqt::MoqtValidator::new().with_dpop_validation(settings);

    let result = v.authorize::<dyn ReplayGuard>(&validated_b, &dpop_request(proof), None, None);
    assert!(
        matches!(result, Err(CatError::DpopValidationFailed(_))),
        "cross-token proof reuse must be rejected: {result:?}"
    );
}

// Guards against reusing a proof issued for one relay endpoint against a
// different relay endpoint whose token audience happens to also permit the
// caller. The resource endpoint binding is now enforced unconditionally —
// it doesn't require the caller to have opted in via with_expected_resource.
#[test]
fn test_authorize_rejects_resource_endpoint_mismatch() {
    let alg = Es256Algorithm::new_with_key_pair().unwrap();
    let jwk = Jwk::from_es256_verifying_key(alg.verifying_key()).unwrap();
    let thumbprint = jwk.thumbprint().unwrap();

    let scope = cat_token::moqt::MoqtScopeBuilder::new()
        .action(MoqtAction::Publish)
        .namespace_exact(b"ns")
        .build();
    let token = CatTokenBuilder::new()
        .issuer("https://test.com")
        .single_audience("relay-b")
        .moqt_scope(scope)
        .confirmation(thumbprint)
        .build()
        .unwrap();
    let validated = make_validated(&token);

    let mut proof = DpopProof::create_for_moqt(
        MoqtAction::Publish,
        vec![b"ns".to_vec()],
        b"track",
        ALG_ES256,
        jwk,
    )
    .with_jti(generate_jti())
    .with_access_token_hash(ath_for(&validated))
    .with_resource("moqt://relay-a".to_string());
    proof.sign(&alg).unwrap();

    let settings = CatDpopSettings::new().with_window(300).unwrap();
    let v = cat_token::moqt::MoqtValidator::new().with_dpop_validation(settings);

    let request = cat_token::moqt::RelayRequestContext::new(
        "relay-b",
        MoqtAction::Publish,
        vec![b"ns".to_vec()],
        b"track".to_vec(),
    )
    .with_dpop_proof(proof);

    let result = v.authorize::<dyn ReplayGuard>(&validated, &request, None, None);
    assert!(
        matches!(result, Err(CatError::DpopValidationFailed(_))),
        "proof bound to relay-a must not authorize relay-b: {result:?}"
    );
}
