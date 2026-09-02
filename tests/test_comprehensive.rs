// SPDX-FileCopyrightText: Copyright (c) 2022 Quicr
// SPDX-License-Identifier: BSD-2-Clause

use cat_token::*;
use chrono::Utc;

#[test]
fn test_comprehensive_token_creation() {
    let now = Utc::now();
    let exp = now + chrono::Duration::hours(1);
    let iat = now - chrono::Duration::minutes(1);

    let uri_patterns = vec![
        UriPattern::Exact("https://api.example.com".to_string()),
        UriPattern::Prefix("https://secure.".to_string()),
        UriPattern::Suffix("/api/v1".to_string()),
        UriPattern::Regex(r"^https://.*\.test\.com$".to_string()),
        UriPattern::Hash("abcdef123456".to_string()),
    ];

    let token = CatTokenBuilder::new()
        // Core claims
        .issuer("https://auth.example.com")
        .audience(vec![
            "client1".to_string(),
            "client2".to_string(),
            "mobile-app".to_string(),
        ])
        .expires_at(exp)
        .not_before(now)
        .cwt_id("token-12345")
        // CAT claims
        .version(1)
        .usage_limit(500)
        .replay_protection(cat_token::ReplayProtection::Prohibited)
        .geo_coordinate(40.7128, -74.0060, Some(100.0)) // New York City
        .geohash("dr5regw")
        .uri_patterns(uri_patterns.clone())
        // Informational claims
        .subject("user@example.com")
        .issued_at(iat)
        .interface_data("mobile-interface-v2")
        // DPoP claims
        .confirmation(b"jwk-thumbprint-xyz".to_vec())
        .dpop_settings(cat_token::CatDpopSettings::new().with_window(300))
        // Request claims
        .interface_claim("auth-interface")
        .request_claim("login-request-abc")
        .build();

    // Verify all claims are properly set
    assert_eq!(token.core.iss, Some("https://auth.example.com".to_string()));
    assert_eq!(token.core.aud.as_ref().unwrap().len(), 3);
    assert!(
        token
            .core
            .aud
            .as_ref()
            .unwrap()
            .contains(&"client1".to_string())
    );
    assert_eq!(token.core.cti, Some("token-12345".to_string()));

    assert_eq!(token.cat.catv, Some(1));
    assert_eq!(token.cat.catu, Some(500));
    assert_eq!(token.cat.catreplay, Some(cat_token::ReplayProtection::Prohibited));
    assert_eq!(token.cat.geohash, Some("dr5regw".to_string()));
    assert_eq!(token.cat.cath.as_ref().unwrap().len(), 5);

    assert_eq!(
        token.informational.sub,
        Some("user@example.com".to_string())
    );
    assert_eq!(token.informational.iat, Some(iat.timestamp()));
    assert_eq!(
        token.informational.catifdata,
        Some("mobile-interface-v2".to_string())
    );

    assert!(token.dpop.cnf.is_some());
    assert_eq!(
        token.dpop.cnf.as_ref().unwrap().jkt,
        b"jwk-thumbprint-xyz".to_vec()
    );
    assert!(token.dpop.catdpop.is_some());
    assert_eq!(token.dpop.catdpop.as_ref().unwrap().window, Some(300));

    assert_eq!(token.request.catif, Some("auth-interface".to_string()));
    assert_eq!(token.request.catr, Some("login-request-abc".to_string()));
}

#[test]
fn test_token_validation_comprehensive() {
    let now = Utc::now();
    let exp = now + chrono::Duration::hours(1);
    let nbf = now - chrono::Duration::minutes(5);

    let token = CatToken::new()
        .with_issuer("https://trusted.issuer.com")
        .with_audience(vec!["expected-audience".to_string()])
        .with_expiration(exp)
        .with_not_before(nbf)
        .with_geo_coordinate(37.7749, -122.4194, Some(50.0)); // San Francisco

    let validator = CatTokenValidator::new()
        .with_expected_issuers(vec!["https://trusted.issuer.com".to_string()])
        .with_expected_audiences(vec!["expected-audience".to_string()])
        .with_clock_skew_tolerance(120);

    // Should pass validation
    assert!(validator.validate(&token).is_ok());
}

#[test]
fn test_token_validation_failures() {
    let now = Utc::now();

    // Expired token
    let expired_token = CatToken::new()
        .with_issuer("https://issuer.com")
        .with_audience(vec!["audience".to_string()])
        .with_expiration(now - chrono::Duration::hours(1));

    let validator = CatTokenValidator::new()
        .with_expected_issuers(vec!["https://issuer.com".to_string()])
        .with_expected_audiences(vec!["audience".to_string()]);

    match validator.validate(&expired_token) {
        Err(CatError::TokenExpired) => (),
        _ => panic!("Expected TokenExpired error"),
    }

    // Invalid issuer
    let invalid_issuer_token = CatToken::new()
        .with_issuer("https://malicious.com")
        .with_audience(vec!["audience".to_string()])
        .with_expiration(now + chrono::Duration::hours(1));

    match validator.validate(&invalid_issuer_token) {
        Err(CatError::InvalidIssuer) => (),
        _ => panic!("Expected InvalidIssuer error"),
    }

    // Invalid audience
    let invalid_audience_token = CatToken::new()
        .with_issuer("https://issuer.com")
        .with_audience(vec!["wrong-audience".to_string()])
        .with_expiration(now + chrono::Duration::hours(1));

    match validator.validate(&invalid_audience_token) {
        Err(CatError::InvalidAudience) => (),
        _ => panic!("Expected InvalidAudience error"),
    }
}

#[test]
fn test_geographic_validation() {
    let validator = CatTokenValidator::new();

    // Valid coordinates
    let valid_token = CatToken::new()
        .with_geo_coordinate(45.0, 90.0, Some(10.0))
        .with_geohash("u4pruydq");

    assert!(validator.validate(&valid_token).is_ok());

    // Invalid latitude
    let invalid_lat_token = CatToken::new().with_geo_coordinate(91.0, 0.0, None);

    match validator.validate(&invalid_lat_token) {
        Err(CatError::GeographicValidationFailed(_)) => (),
        _ => panic!("Expected GeographicValidationFailed error"),
    }

    // Invalid longitude
    let invalid_lon_token = CatToken::new().with_geo_coordinate(0.0, 181.0, None);

    match validator.validate(&invalid_lon_token) {
        Err(CatError::GeographicValidationFailed(_)) => (),
        _ => panic!("Expected GeographicValidationFailed error"),
    }

    // Invalid geohash (too long)
    let invalid_geohash_token = CatToken::new().with_geohash("this-is-too-long-for-geohash");

    match validator.validate(&invalid_geohash_token) {
        Err(CatError::GeographicValidationFailed(_)) => (),
        _ => panic!("Expected GeographicValidationFailed error"),
    }

    // Invalid geohash (empty)
    let empty_geohash_token = CatToken::new().with_geohash("");

    match validator.validate(&empty_geohash_token) {
        Err(CatError::GeographicValidationFailed(_)) => (),
        _ => panic!("Expected GeographicValidationFailed error"),
    }
}

#[test]
fn test_cwt_encoding_decoding() {
    let now = Utc::now();
    let original_token = CatToken::new()
        .with_issuer("https://test.issuer.com")
        .with_audience(vec!["test-client".to_string()])
        .with_expiration(now + chrono::Duration::hours(1))
        .with_version(1)
        .with_subject("test-user")
        .with_confirmation(b"test-confirmation".to_vec())
        .with_interface_claim("test-interface");

    let cwt = Cwt::new(-7, original_token.clone()); // ES256 algorithm

    // Test encoding
    let encoded_payload = cwt.encode_payload().expect("Should encode successfully");
    assert!(!encoded_payload.is_empty());

    // Test decoding
    let decoded_token = Cwt::decode_payload(&encoded_payload).expect("Should decode successfully");

    // Verify decoded token matches original
    assert_eq!(decoded_token.core.iss, original_token.core.iss);
    assert_eq!(decoded_token.core.aud, original_token.core.aud);
    assert_eq!(decoded_token.cat.catv, original_token.cat.catv);
    assert_eq!(
        decoded_token.informational.sub,
        original_token.informational.sub
    );
    assert_eq!(decoded_token.dpop.cnf, original_token.dpop.cnf);
    assert_eq!(decoded_token.request.catif, original_token.request.catif);
}

#[test]
fn test_uri_pattern_encoding_decoding() {
    let patterns = vec![
        UriPattern::Exact("https://api.example.com".to_string()),
        UriPattern::Prefix("https://secure.".to_string()),
        UriPattern::Suffix("/api/data".to_string()),
        UriPattern::Regex(r"^https://.*\.test\.com$".to_string()),
        UriPattern::Hash("abcdef123456".to_string()),
    ];

    let original_token = CatToken::new().with_uri_patterns(patterns.clone());

    let cwt = Cwt::new(-7, original_token.clone());

    // Test encoding
    let encoded_payload = cwt.encode_payload().expect("Should encode successfully");

    // Test decoding
    let decoded_token = Cwt::decode_payload(&encoded_payload).expect("Should decode successfully");

    assert_eq!(
        decoded_token.cat.cath.as_ref().unwrap().len(),
        patterns.len()
    );

    // Verify pattern types and values are preserved
    let decoded_patterns = decoded_token.cat.cath.unwrap();
    assert!(
        decoded_patterns
            .iter()
            .any(|p| matches!(p, UriPattern::Exact(s) if s == "https://api.example.com"))
    );
    assert!(
        decoded_patterns
            .iter()
            .any(|p| matches!(p, UriPattern::Prefix(s) if s == "https://secure."))
    );
    assert!(
        decoded_patterns
            .iter()
            .any(|p| matches!(p, UriPattern::Suffix(s) if s == "/api/data"))
    );
    assert!(
        decoded_patterns
            .iter()
            .any(|p| matches!(p, UriPattern::Regex(s) if s == r"^https://.*\.test\.com$"))
    );
    assert!(
        decoded_patterns
            .iter()
            .any(|p| matches!(p, UriPattern::Hash(s) if s == "abcdef123456"))
    );
}

#[test]
fn test_all_claim_constants_coverage() {
    // Test that all claim constants are properly defined and unique
    let claim_ids = vec![
        CLAIM_ISS,
        CLAIM_AUD,
        CLAIM_EXP,
        CLAIM_NBF,
        CLAIM_CTI,
        CLAIM_SUB,
        CLAIM_IAT,
        CLAIM_CATIFDATA,
        CLAIM_CNF,
        CLAIM_CATDPOP,
        CLAIM_CATIF,
        CLAIM_CATR,
        CLAIM_CATREPLAY,
        CLAIM_CATPOR,
        CLAIM_CATV,
        CLAIM_CATNIP,
        CLAIM_CATU,
        CLAIM_CATM,
        CLAIM_CATALPN,
        CLAIM_CATH,
        CLAIM_CATGEOISO3166,
        CLAIM_CATGEOCOORD,
        CLAIM_GEOHASH,
        CLAIM_CATGEOALT,
        CLAIM_CATTPK,
    ];

    // Check no duplicates
    let mut sorted_ids = claim_ids.clone();
    sorted_ids.sort();
    sorted_ids.dedup();
    assert_eq!(
        claim_ids.len(),
        sorted_ids.len(),
        "Claim IDs must be unique"
    );

    // Check expected values
    assert_eq!(CLAIM_ISS, 1);
    assert_eq!(CLAIM_AUD, 3);
    assert_eq!(CLAIM_CNF, 8);
    assert_eq!(CLAIM_SUB, 2);
    assert_eq!(CLAIM_CATREPLAY, 308);
    assert_eq!(CLAIM_IAT, 6);
    assert_eq!(CLAIM_CATDPOP, 321);
    assert_eq!(CLAIM_CATIF, 322);
    assert_eq!(CLAIM_CATR, 323);
    assert_eq!(CLAIM_CATIFDATA, 320);
}

#[test]
fn test_minimal_token() {
    // Test creating and validating a minimal token with just required claims
    let token = CatToken::new().with_issuer("https://minimal.issuer.com");

    assert_eq!(
        token.core.iss,
        Some("https://minimal.issuer.com".to_string())
    );
    assert!(token.core.aud.is_none());
    assert!(token.core.exp.is_none());
    assert!(token.informational.sub.is_none());
    assert!(token.dpop.cnf.is_none());
    assert!(token.request.catif.is_none());
}

#[test]
fn test_maximal_token() {
    // Test creating a token with all possible claims
    let now = Utc::now();

    let token = CatToken::new()
        // All core claims
        .with_issuer("https://maximal.issuer.com")
        .with_audience(vec!["aud1".to_string(), "aud2".to_string()])
        .with_expiration(now + chrono::Duration::hours(1))
        .with_not_before(now - chrono::Duration::minutes(5))
        .with_cwt_id("maximal-token-id")
        // All CAT claims
        .with_version(1)
        .with_usage_limit(1000)
        .with_replay_protection(cat_token::ReplayProtection::Prohibited)
        .with_geo_coordinate(51.5074, -0.1278, Some(25.0)) // London
        .with_geohash("gcpvj0du")
        .with_uri_patterns(vec![
            UriPattern::Exact("https://maximal.example.com".to_string()),
            UriPattern::Prefix("https://api.".to_string()),
        ])
        // All informational claims
        .with_subject("maximal-user@example.com")
        .with_issued_at(now)
        .with_interface_data("maximal-interface-data")
        // All DPoP claims
        .with_confirmation(b"maximal-confirmation-key".to_vec())
        .with_dpop_settings(
            cat_token::CatDpopSettings::new()
                .with_window(600)
                .with_jti_processing(true),
        )
        // All request claims
        .with_interface_claim("maximal-interface")
        .with_request_claim("maximal-request");

    // Verify all claims are set
    assert!(token.core.iss.is_some());
    assert!(token.core.aud.is_some());
    assert!(token.core.exp.is_some());
    assert!(token.core.nbf.is_some());
    assert!(token.core.cti.is_some());

    assert!(token.cat.catv.is_some());
    assert!(token.cat.catu.is_some());
    assert!(token.cat.catreplay.is_some());
    assert!(token.cat.catgeocoord.is_some());
    assert!(token.cat.geohash.is_some());
    assert!(token.cat.cath.is_some());

    assert!(token.informational.sub.is_some());
    assert!(token.informational.iat.is_some());
    assert!(token.informational.catifdata.is_some());

    assert!(token.dpop.cnf.is_some());
    assert!(token.dpop.catdpop.is_some());

    assert!(token.request.catif.is_some());
    assert!(token.request.catr.is_some());
}
