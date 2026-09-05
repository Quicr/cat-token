// SPDX-FileCopyrightText: Copyright (c) 2022 Quicr
// SPDX-License-Identifier: BSD-2-Clause

#![cfg(feature = "moqt")]

use cat_token::dpop::{DpopProof, DpopValidator, generate_jti};
use cat_token::jwk::Jwk;
use cat_token::*;

#[test]
fn test_dpop_uses_embedded_key() {
    let alg = Es256Algorithm::new_with_key_pair().unwrap();
    let jwk = Jwk::from_es256_verifying_key(alg.verifying_key()).unwrap();
    let thumbprint = jwk.thumbprint().unwrap();

    let mut proof = DpopProof::create_for_moqt(
        MoqtAction::Subscribe,
        vec![b"ns".to_vec()],
        b"track",
        "ES256",
        jwk,
    )
    .with_jti(generate_jti());
    proof.sign(&alg).unwrap();

    let settings = CatDpopSettings::new().with_window(300);
    let validator = DpopValidator::new(settings);

    // validate() derives the key from the embedded JWK — no external algorithm needed
    validator
        .validate(&proof, MoqtAction::Subscribe, &thumbprint)
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
        "ES256",
        dpop_jwk,
    )
    .with_jti(generate_jti());
    // Sign with a DIFFERENT key than the one in the JWK header
    proof.sign(&cat_alg).unwrap();

    let settings = CatDpopSettings::new().with_window(300);
    let validator = DpopValidator::new(settings);

    // Should fail — signature was made with cat_alg but JWK advertises dpop_alg's key
    let result = validator.validate(&proof, MoqtAction::Subscribe, &dpop_thumbprint);
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
        "ES256",
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
        .moqt_scope(scope)
        .confirmation(thumbprint)
        .build();

    let settings = CatDpopSettings::new().with_window(300);
    let validator = cat_token::moqt::MoqtValidator::new().with_dpop_validation(settings);

    // Request for namespace_b — proof is bound to namespace_a
    let request = cat_token::moqt::MoqtAuthRequest::new(
        MoqtAction::Publish,
        vec![b"namespace_b".to_vec()],
        b"track".to_vec(),
    )
    .with_dpop_proof(proof);

    let result = validator.authorize_with_dpop(&ValidatedToken::from_unchecked(token), &request);
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
        "ES256",
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
        .moqt_scope(scope)
        .confirmation(thumbprint)
        .build();

    let settings = CatDpopSettings::new().with_window(300);
    let validator = cat_token::moqt::MoqtValidator::new().with_dpop_validation(settings);

    // Request for track_b — proof is bound to track_a
    let request = cat_token::moqt::MoqtAuthRequest::new(
        MoqtAction::Publish,
        vec![b"ns".to_vec()],
        b"track_b".to_vec(),
    )
    .with_dpop_proof(proof);

    let result = validator.authorize_with_dpop(&ValidatedToken::from_unchecked(token), &request);
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

    let mut proof =
        DpopProof::create_for_moqt(MoqtAction::Publish, ns.clone(), track, "ES256", jwk.clone())
            .with_jti(generate_jti());
    proof.sign(&alg).unwrap();

    let scope = cat_token::moqt::MoqtScopeBuilder::new()
        .action(MoqtAction::Publish)
        .namespace_exact(b"ns")
        .build();

    let token = CatTokenBuilder::new()
        .issuer("https://test.com")
        .moqt_scope(scope)
        .confirmation(thumbprint)
        .build();

    let settings = CatDpopSettings::new().with_window(300);
    let validator = cat_token::moqt::MoqtValidator::new().with_dpop_validation(settings);

    let request = cat_token::moqt::MoqtAuthRequest::new(MoqtAction::Publish, ns, track.to_vec())
        .with_dpop_proof(proof);

    let result = validator.authorize_with_dpop(&ValidatedToken::from_unchecked(token), &request);
    assert!(result.is_ok());
    assert!(result.unwrap().authorized);
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
        "ES256",
        good_jwk.clone(),
    )
    .with_jti(jti.clone());
    bad_proof.sign(&bad_alg).unwrap();

    let settings = CatDpopSettings::new()
        .with_window(300)
        .with_jti_processing(true);
    let validator = DpopValidator::new(settings);

    // Should fail — wrong signature
    let result = validator.validate(&bad_proof, MoqtAction::Subscribe, &thumbprint);
    assert!(result.is_err());

    // Now create a valid proof with the SAME JTI
    let mut good_proof = DpopProof::create_for_moqt(
        MoqtAction::Subscribe,
        vec![b"ns".to_vec()],
        b"track",
        "ES256",
        good_jwk,
    )
    .with_jti(jti);
    good_proof.sign(&good_alg).unwrap();

    // Should succeed — the JTI was NOT consumed by the failed attempt
    let result = validator.validate(&good_proof, MoqtAction::Subscribe, &thumbprint);
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
        "ES256",
        jwk,
    )
    .with_jti(generate_jti());
    proof.sign(&alg).unwrap();

    let settings = CatDpopSettings::new().with_window(300);
    let validator = DpopValidator::new(settings);

    // Should fail — embedded JWK thumbprint doesn't match expected
    let result = validator.validate(&proof, MoqtAction::Subscribe, &other_thumbprint);
    assert!(
        matches!(
            result,
            Err(CatError::InvalidDpopBinding) | Err(CatError::DpopKeyMismatch)
        ),
        "Should reject key mismatch: {:?}",
        result
    );
}
