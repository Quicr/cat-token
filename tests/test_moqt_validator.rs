// SPDX-FileCopyrightText: Copyright (c) 2022 Quicr
// SPDX-License-Identifier: BSD-2-Clause

#![cfg(feature = "moqt")]

use cat_token::moqt::{MoqtAuthRequest, MoqtScopeBuilder, MoqtValidator, roles};
use cat_token::*;
use chrono::{Duration, Utc};
use std::sync::Arc;
use std::thread;

fn make_validated(token: &CatToken) -> ValidatedToken {
    let key = HmacSha256Algorithm::new(b"test-key-for-roundtrip-000000000");
    let encoded = encode_token(token, &key).unwrap();
    let validator = CatTokenValidator::new().allow_unencrypted_privacy_claims();
    decode_token(&encoded, &key)
        .unwrap()
        .validate(&validator)
        .unwrap()
}

#[test]
fn test_moqt_validator_spec_example_exact_match() {
    // Example from spec: Allow with an exact match "example.com/bob"
    let scope = MoqtScopeBuilder::new()
        .actions(&[
            MoqtAction::PublishNamespace,
            MoqtAction::SubscribeNamespace,
            MoqtAction::Publish,
            MoqtAction::Fetch,
        ])
        .namespace_exact(b"example.com")
        .track_exact(b"/bob")
        .build();

    let token = CatTokenBuilder::new()
        .issuer("https://spec-example.com")
        .moqt_scope(scope)
        .build();

    let validator = MoqtValidator::new();

    // Should permit exact match
    let request = MoqtAuthRequest::new(
        MoqtAction::PublishNamespace,
        vec![b"example.com".to_vec()],
        b"/bob".to_vec(),
    );
    assert!(
        validator
            .authorize(&make_validated(&token), &request)
            .unwrap()
            .authorized
    );

    // Should prohibit - various mismatches
    let test_cases = vec![
        (b"example.com".to_vec(), b"".to_vec()),
        (b"example.com".to_vec(), b"/bob/123".to_vec()),
        (b"example.com".to_vec(), b"/alice".to_vec()),
        (b"example.com".to_vec(), b"/bob/logs".to_vec()),
        (b"alternate/example.com".to_vec(), b"/bob".to_vec()),
    ];

    for (ns, track) in test_cases {
        let request = MoqtAuthRequest::new(
            MoqtAction::PublishNamespace,
            vec![ns.clone()],
            track.clone(),
        );
        assert!(
            !validator
                .authorize(&make_validated(&token), &request)
                .unwrap()
                .authorized,
            "Should deny ns={:?} track={:?}",
            String::from_utf8_lossy(&ns),
            String::from_utf8_lossy(&track)
        );
    }
}

#[test]
fn test_moqt_validator_spec_example_prefix_match() {
    // Example from spec: Allow with a prefix match "example.com/bob*"
    let scope = MoqtScopeBuilder::new()
        .actions(&[
            MoqtAction::PublishNamespace,
            MoqtAction::SubscribeNamespace,
            MoqtAction::Publish,
            MoqtAction::Fetch,
        ])
        .namespace_exact(b"example.com")
        .track_prefix(b"/bob")
        .build();

    let token = CatTokenBuilder::new()
        .issuer("https://spec-example.com")
        .moqt_scope(scope)
        .build();

    let validator = MoqtValidator::new();

    // Should permit - various prefix matches
    let permit_cases: Vec<(&[u8], &[u8])> = vec![
        (b"example.com", b"/bob"),
        (b"example.com", b"/bob/123"),
        (b"example.com", b"/bob/logs"),
        (b"example.com", b"/bobby"),
    ];

    for (ns, track) in permit_cases {
        let request = MoqtAuthRequest::new(
            MoqtAction::PublishNamespace,
            vec![ns.to_vec()],
            track.to_vec(),
        );
        assert!(
            validator
                .authorize(&make_validated(&token), &request)
                .unwrap()
                .authorized,
            "Should permit ns={:?} track={:?}",
            String::from_utf8_lossy(ns),
            String::from_utf8_lossy(track)
        );
    }

    // Should prohibit
    let deny_cases: Vec<(&[u8], &[u8])> =
        vec![(b"example.com", b"/alice"), (b"other.com", b"/bob")];

    for (ns, track) in deny_cases {
        let request = MoqtAuthRequest::new(
            MoqtAction::PublishNamespace,
            vec![ns.to_vec()],
            track.to_vec(),
        );
        assert!(
            !validator
                .authorize(&make_validated(&token), &request)
                .unwrap()
                .authorized,
            "Should deny ns={:?} track={:?}",
            String::from_utf8_lossy(ns),
            String::from_utf8_lossy(track)
        );
    }
}

#[test]
fn test_moqt_validator_multiple_scopes() {
    // Create multiple scopes with different permissions
    let pub_scope = roles::publisher(b"cdn.example.com", b"/live/");
    let sub_scope = roles::subscriber(b"cdn.example.com", b"/vod/");

    let token = CatTokenBuilder::new()
        .issuer("https://multi-scope.com")
        .audience(vec!["relay".to_string()])
        .expires_at(Utc::now() + Duration::hours(1))
        .moqt_scopes(vec![pub_scope, sub_scope])
        .build();

    let validator = MoqtValidator::new();

    // Publisher can publish to /live/
    let request = MoqtAuthRequest::new(
        MoqtAction::Publish,
        vec![b"cdn.example.com".to_vec()],
        b"/live/stream1".to_vec(),
    );
    let result = validator
        .authorize(&make_validated(&token), &request)
        .unwrap();
    assert!(result.authorized);
    assert_eq!(result.matched_scope_index, Some(0));

    // Publisher cannot publish to /vod/
    let request = MoqtAuthRequest::new(
        MoqtAction::Publish,
        vec![b"cdn.example.com".to_vec()],
        b"/vod/movie1".to_vec(),
    );
    assert!(
        !validator
            .authorize(&make_validated(&token), &request)
            .unwrap()
            .authorized
    );

    // Subscriber can fetch from /vod/
    let request = MoqtAuthRequest::new(
        MoqtAction::Fetch,
        vec![b"cdn.example.com".to_vec()],
        b"/vod/movie1".to_vec(),
    );
    let result = validator
        .authorize(&make_validated(&token), &request)
        .unwrap();
    assert!(result.authorized);
    assert_eq!(result.matched_scope_index, Some(1));

    // Subscriber cannot fetch from /live/
    let request = MoqtAuthRequest::new(
        MoqtAction::Fetch,
        vec![b"cdn.example.com".to_vec()],
        b"/live/stream1".to_vec(),
    );
    assert!(
        !validator
            .authorize(&make_validated(&token), &request)
            .unwrap()
            .authorized
    );
}

#[test]
fn test_moqt_validator_revalidation_required() {
    let scope = MoqtScopeBuilder::new()
        .publisher()
        .namespace_exact(b"example.com")
        .build();

    let token = CatTokenBuilder::new()
        .issuer("https://test.com")
        .moqt_scope(scope)
        .moqt_reval(300.0) // 5 minute revalidation
        .build();

    let validator = MoqtValidator::new();

    let request = MoqtAuthRequest::new(
        MoqtAction::Publish,
        vec![b"example.com".to_vec()],
        b"/stream".to_vec(),
    );
    let result = validator
        .authorize(&make_validated(&token), &request)
        .unwrap();

    assert!(result.authorized);
    assert!(result.requires_revalidation);
    assert_eq!(result.revalidation_interval, Some(300.0));
}

#[test]
fn test_moqt_validator_revalidation_zero() {
    // When moqt-reval is 0, token must not be revalidated
    let scope = MoqtScopeBuilder::new()
        .publisher()
        .namespace_exact(b"example.com")
        .build();

    let token = CatTokenBuilder::new()
        .issuer("https://test.com")
        .moqt_scope(scope)
        .moqt_reval(0.0)
        .build();

    let validator = MoqtValidator::new();

    let request = MoqtAuthRequest::new(
        MoqtAction::Publish,
        vec![b"example.com".to_vec()],
        b"/stream".to_vec(),
    );
    let result = validator
        .authorize(&make_validated(&token), &request)
        .unwrap();

    assert!(result.authorized);
    assert!(!result.requires_revalidation); // 0 means no revalidation
    assert_eq!(result.revalidation_interval, Some(0.0));
}

#[test]
fn test_moqt_validator_claims_validation() {
    let scope = MoqtScopeBuilder::new()
        .publisher()
        .namespace_exact(b"example.com")
        .build();

    // Token with short revalidation interval
    let token = CatTokenBuilder::new()
        .issuer("https://test.com")
        .moqt_scope(scope.clone())
        .moqt_reval(30.0) // 30 seconds
        .build();

    // Validator that requires at least 60 seconds
    let validator = MoqtValidator::new().with_min_revalidation_interval(60.0);

    let result = validator.validate_moqt_claims(&token);
    assert!(matches!(
        result,
        Err(CatError::RevalidationIntervalTooShort)
    ));

    // Token with acceptable revalidation interval
    let token2 = CatTokenBuilder::new()
        .issuer("https://test.com")
        .moqt_scope(scope)
        .moqt_reval(120.0) // 2 minutes
        .build();

    let result = validator.validate_moqt_claims(&token2);
    assert!(result.is_ok());
}

#[test]
fn test_moqt_validator_no_revalidation_support() {
    let scope = MoqtScopeBuilder::new()
        .publisher()
        .namespace_exact(b"example.com")
        .build();

    let token = CatTokenBuilder::new()
        .issuer("https://test.com")
        .moqt_scope(scope)
        .moqt_reval(300.0)
        .build();

    // Validator that doesn't support revalidation
    let validator = MoqtValidator::new().without_revalidation_support();

    let result = validator.validate_moqt_claims(&token);
    assert!(matches!(result, Err(CatError::RevalidationRequired)));
}

#[test]
fn test_moqt_scope_builder() {
    // Test the fluent builder API
    let scope = MoqtScopeBuilder::new()
        .action(MoqtAction::Publish)
        .action(MoqtAction::Fetch)
        .namespace_exact(b"cdn.example.com")
        .namespace_nil() // End of namespace
        .track_prefix(b"/stream/")
        .build();

    assert_eq!(scope.actions.len(), 2);
    assert!(scope.allows_action(&MoqtAction::Publish));
    assert!(scope.allows_action(&MoqtAction::Fetch));
    assert!(!scope.allows_action(&MoqtAction::Subscribe));
    assert_eq!(scope.namespace_matches.len(), 2);
    assert!(scope.track_match.is_some());
}

#[test]
fn test_moqt_roles() {
    // Test predefined roles
    let pub_scope = roles::publisher(b"example.com", b"/live/");
    assert!(pub_scope.allows_action(&MoqtAction::Publish));
    assert!(pub_scope.allows_action(&MoqtAction::PublishNamespace));
    assert!(!pub_scope.allows_action(&MoqtAction::Fetch));

    let sub_scope = roles::subscriber(b"example.com", b"/vod/");
    assert!(sub_scope.allows_action(&MoqtAction::Subscribe));
    assert!(sub_scope.allows_action(&MoqtAction::Fetch));
    assert!(!sub_scope.allows_action(&MoqtAction::Publish));

    let admin_scope = roles::admin(b"example.com");
    assert!(admin_scope.allows_action(&MoqtAction::Publish));
    assert!(admin_scope.allows_action(&MoqtAction::Subscribe));
    assert!(admin_scope.allows_action(&MoqtAction::TrackStatus));

    let ro_scope = roles::read_only(b"example.com", b"/archive/");
    assert!(ro_scope.allows_action(&MoqtAction::Subscribe));
    assert!(ro_scope.allows_action(&MoqtAction::Fetch));
    assert!(!ro_scope.allows_action(&MoqtAction::Publish));
    assert!(!ro_scope.allows_action(&MoqtAction::PublishNamespace));
}

#[test]
fn test_moqt_default_blocked() {
    // "The default for all actions is 'Blocked'"
    let token = CatTokenBuilder::new().issuer("https://test.com").build(); // No MOQT scopes

    let validator = MoqtValidator::new();

    let request = MoqtAuthRequest::new(
        MoqtAction::Publish,
        vec![b"example.com".to_vec()],
        b"/stream".to_vec(),
    );
    let result = validator
        .authorize(&make_validated(&token), &request)
        .unwrap();

    assert!(!result.authorized);
    assert!(result.matched_scope_index.is_none());
}

#[test]
fn test_moqt_empty_scopes() {
    let token = CatTokenBuilder::new()
        .issuer("https://test.com")
        .moqt_scopes(vec![]) // Empty scopes array
        .build();

    let validator = MoqtValidator::new();

    let request = MoqtAuthRequest::new(
        MoqtAction::Publish,
        vec![b"example.com".to_vec()],
        b"/stream".to_vec(),
    );
    let result = validator
        .authorize(&make_validated(&token), &request)
        .unwrap();

    assert!(!result.authorized);
}

#[test]
fn test_moqt_validator_concurrent_access() {
    let scope = MoqtScopeBuilder::new()
        .full_access()
        .namespace_prefix(b"cdn.")
        .build();

    let token = Arc::new(
        CatTokenBuilder::new()
            .issuer("https://concurrent-test.com")
            .moqt_scope(scope)
            .build(),
    );

    let validator = Arc::new(MoqtValidator::new());

    let mut handles = vec![];

    for i in 0..10 {
        let token = Arc::clone(&token);
        let validator = Arc::clone(&validator);

        let handle = thread::spawn(move || {
            for j in 0..100 {
                let track = format!("/stream/{}/{}", i, j);
                let request = MoqtAuthRequest::new(
                    MoqtAction::Publish,
                    vec![b"cdn.example.com".to_vec()],
                    track.as_bytes().to_vec(),
                );
                let result = validator
                    .authorize(&make_validated(&token), &request)
                    .unwrap();
                assert!(
                    result.authorized,
                    "Thread {} iter {} should be authorized",
                    i, j
                );
            }
        });

        handles.push(handle);
    }

    for handle in handles {
        handle.join().expect("Thread panicked");
    }
}

#[test]
fn test_dpop_validator_concurrent_jti() {
    let settings = CatDpopSettings::new()
        .with_window(300)
        .with_jti_processing(true);
    let validator = Arc::new(DpopValidator::new(settings));

    let alg = Arc::new(Es256Algorithm::new_with_key_pair().unwrap());
    let jwk = Jwk::from_es256_verifying_key(alg.verifying_key()).unwrap();
    let thumbprint = Arc::new(jwk.thumbprint().unwrap());

    let mut handles = vec![];

    for i in 0..10 {
        let validator = Arc::clone(&validator);
        let thumbprint = Arc::clone(&thumbprint);
        let jwk_clone = jwk.clone();
        let alg_clone = Arc::clone(&alg);

        let handle = thread::spawn(move || {
            for j in 0..50 {
                let jti = format!("jti-{}-{}", i, j);
                let mut proof = DpopProof::create_for_moqt(
                    MoqtAction::Publish,
                    vec![b"namespace".to_vec()],
                    b"track",
                    "ES256",
                    jwk_clone.clone(),
                )
                .with_jti(jti.clone());
                proof.sign(alg_clone.as_ref()).unwrap();

                let result = validator.validate(&proof, MoqtAction::Publish, &thumbprint);
                assert!(result.is_ok(), "First use of JTI {} should succeed", jti);

                // Second use should fail (replay)
                let result = validator.validate(&proof, MoqtAction::Publish, &thumbprint);
                assert!(
                    matches!(result, Err(CatError::ReplayAttackDetected)),
                    "Replay of JTI {} should fail",
                    jti
                );
            }
        });

        handles.push(handle);
    }

    for handle in handles {
        handle.join().expect("Thread panicked");
    }
}

#[test]
fn test_jti_cache_stats() {
    let settings = CatDpopSettings::new()
        .with_window(300)
        .with_jti_processing(true);

    // Use smaller cache size for testing
    let validator = DpopValidator::with_cache_size(settings, 1000);
    let alg = Es256Algorithm::new_with_key_pair().unwrap();
    let jwk = Jwk::from_es256_verifying_key(alg.verifying_key()).unwrap();
    let thumbprint = jwk.thumbprint().unwrap();

    // Insert 1000 unique JTIs (fills the cache)
    for i in 0..1000 {
        let jti = format!("jti-stats-{}", i);
        let mut proof = DpopProof::create_for_moqt(
            MoqtAction::Publish,
            vec![b"namespace".to_vec()],
            b"track",
            "ES256",
            jwk.clone(),
        )
        .with_jti(jti);
        proof.sign(&alg).unwrap();

        let result = validator.validate(&proof, MoqtAction::Publish, &thumbprint);
        assert!(result.is_ok(), "Validation should succeed for unique JTI");
    }

    // Check cache stats
    let stats = validator.jti_cache_stats();
    assert_eq!(stats.size, 1000);
    assert_eq!(stats.capacity, 1000);
    assert!(stats.under_pressure, "Cache should be at capacity (90%+)");
}
