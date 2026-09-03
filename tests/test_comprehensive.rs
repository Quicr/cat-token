// SPDX-FileCopyrightText: Copyright (c) 2022 Quicr
// SPDX-License-Identifier: BSD-2-Clause

use cat_token::*;
use chrono::Utc;

#[test]
fn test_comprehensive_token_creation() {
    let now = Utc::now();
    let exp = now + chrono::Duration::hours(1);
    let iat = now - chrono::Duration::minutes(1);

    let uri_match_rules = vec![
        UriMatchRule {
            component: URI_COMPONENT_HOST,
            matches: vec![
                MatchValue::Exact("api.example.com".to_string()),
                MatchValue::Prefix("secure.".to_string()),
            ],
        },
        UriMatchRule {
            component: URI_COMPONENT_PATH,
            matches: vec![
                MatchValue::Suffix("/api/v1".to_string()),
                MatchValue::Regex(r"^https://.*\.test\.com$".to_string()),
            ],
        },
    ];

    let header_match_rules = vec![HeaderMatchRule {
        name: "Authorization".to_string(),
        matches: vec![MatchValue::Prefix("Bearer ".to_string())],
    }];

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
        .cwt_id_str("token-12345")
        // CAT claims
        .version(1)
        .uri_match_rules(uri_match_rules.clone())
        .header_match_rules(header_match_rules.clone())
        .replay_protection(cat_token::ReplayProtection::Prohibited)
        .geo_coordinate(40.7128, -74.0060, Some(100)) // New York City
        .geohash("dr5regw")
        // Informational claims
        .subject("user@example.com")
        .issued_at(iat)
        .interface_data("mobile-interface-v2")
        // DPoP claims
        .confirmation(b"jwk-thumbprint-xyz".to_vec())
        .dpop_settings(cat_token::CatDpopSettings::new().with_window(300))
        // Request claims
        .if_action(
            CLAIM_EXP,
            CatIfAction {
                status: 401,
                headers: None,
                kid: None,
            },
        )
        .renewal(CatRenewal::automatic().with_expadd(3600))
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
    assert_eq!(token.core.cti, Some(b"token-12345".to_vec()));

    assert_eq!(token.cat.catv, Some(1));
    assert_eq!(token.cat.catu.as_ref().unwrap().len(), 2);
    assert_eq!(
        token.cat.catu.as_ref().unwrap()[0].component,
        URI_COMPONENT_HOST
    );
    assert_eq!(token.cat.catu.as_ref().unwrap()[0].matches.len(), 2);
    assert_eq!(
        token.cat.catreplay,
        Some(cat_token::ReplayProtection::Prohibited)
    );
    assert_eq!(token.cat.geohash, Some(vec!["dr5regw".to_string()]));
    assert_eq!(token.cat.cath.as_ref().unwrap().len(), 1);
    assert_eq!(token.cat.cath.as_ref().unwrap()[0].name, "Authorization");

    assert_eq!(
        token.informational.sub,
        Some("user@example.com".to_string())
    );
    assert_eq!(token.informational.iat, Some(iat.timestamp()));
    assert_eq!(
        token.informational.catifdata,
        Some(vec!["mobile-interface-v2".to_string()])
    );

    assert!(token.dpop.cnf.is_some());
    assert_eq!(
        token.dpop.cnf.as_ref().unwrap().jkt,
        b"jwk-thumbprint-xyz".to_vec()
    );
    assert!(token.dpop.catdpop.is_some());
    assert_eq!(token.dpop.catdpop.as_ref().unwrap().window, Some(300));

    let catif = token.request.catif.as_ref().unwrap();
    assert_eq!(catif[0].0, CLAIM_EXP);
    assert_eq!(catif[0].1.status, 401);
    let catr = token.request.catr.as_ref().unwrap();
    assert_eq!(catr.renewal_type, CatRenewalType::Automatic);
    assert_eq!(catr.expadd, Some(3600));
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
        .with_geo_coordinate(37.7749, -122.4194, Some(50)); // San Francisco

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
        .with_geo_coordinate(45.0, 90.0, Some(10))
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
        .with_if_action(
            CLAIM_EXP,
            CatIfAction {
                status: 403,
                headers: None,
                kid: None,
            },
        );

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
fn test_uri_match_rule_encoding_decoding() {
    let uri_rules = vec![
        UriMatchRule {
            component: URI_COMPONENT_HOST,
            matches: vec![
                MatchValue::Exact("api.example.com".to_string()),
                MatchValue::Prefix("secure.".to_string()),
            ],
        },
        UriMatchRule {
            component: URI_COMPONENT_PATH,
            matches: vec![
                MatchValue::Suffix("/api/data".to_string()),
                MatchValue::Regex(r"^https://.*\.test\.com$".to_string()),
            ],
        },
    ];

    let header_rules = vec![
        HeaderMatchRule {
            name: "Content-Type".to_string(),
            matches: vec![MatchValue::Exact("application/json".to_string())],
        },
        HeaderMatchRule {
            name: "Authorization".to_string(),
            matches: vec![MatchValue::Prefix("Bearer ".to_string())],
        },
    ];

    let original_token = CatToken::new()
        .with_uri_match_rules(uri_rules.clone())
        .with_header_match_rules(header_rules.clone());

    let cwt = Cwt::new(-7, original_token.clone());

    // Test encoding
    let encoded_payload = cwt.encode_payload().expect("Should encode successfully");

    // Test decoding
    let decoded_token = Cwt::decode_payload(&encoded_payload).expect("Should decode successfully");

    // Verify URI match rules (catu)
    let decoded_uri_rules = decoded_token.cat.catu.as_ref().unwrap();
    assert_eq!(decoded_uri_rules.len(), uri_rules.len());
    assert_eq!(decoded_uri_rules[0].component, URI_COMPONENT_HOST);
    assert_eq!(decoded_uri_rules[0].matches.len(), 2);
    assert!(
        matches!(&decoded_uri_rules[0].matches[0], MatchValue::Exact(s) if s == "api.example.com")
    );
    assert!(matches!(&decoded_uri_rules[0].matches[1], MatchValue::Prefix(s) if s == "secure."));
    assert_eq!(decoded_uri_rules[1].component, URI_COMPONENT_PATH);
    assert_eq!(decoded_uri_rules[1].matches.len(), 2);
    assert!(matches!(&decoded_uri_rules[1].matches[0], MatchValue::Suffix(s) if s == "/api/data"));
    assert!(
        matches!(&decoded_uri_rules[1].matches[1], MatchValue::Regex(s) if s == r"^https://.*\.test\.com$")
    );

    // Verify header match rules (cath)
    let decoded_header_rules = decoded_token.cat.cath.as_ref().unwrap();
    assert_eq!(decoded_header_rules.len(), header_rules.len());
    assert_eq!(decoded_header_rules[0].name, "Content-Type");
    assert!(
        matches!(&decoded_header_rules[0].matches[0], MatchValue::Exact(s) if s == "application/json")
    );
    assert_eq!(decoded_header_rules[1].name, "Authorization");
    assert!(matches!(&decoded_header_rules[1].matches[0], MatchValue::Prefix(s) if s == "Bearer "));
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
        .with_cwt_id_str("maximal-token-id")
        // All CAT claims
        .with_version(1)
        .with_uri_match_rules(vec![UriMatchRule {
            component: URI_COMPONENT_HOST,
            matches: vec![
                MatchValue::Exact("maximal.example.com".to_string()),
                MatchValue::Prefix("api.".to_string()),
            ],
        }])
        .with_replay_protection(cat_token::ReplayProtection::Prohibited)
        .with_geo_coordinate(51.5074, -0.1278, Some(25)) // London
        .with_geohash("gcpvj0du")
        .with_header_match_rules(vec![HeaderMatchRule {
            name: "Accept".to_string(),
            matches: vec![MatchValue::Exact("application/json".to_string())],
        }])
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
        .with_if_action(
            CLAIM_EXP,
            CatIfAction {
                status: 401,
                headers: None,
                kid: None,
            },
        )
        .with_renewal(CatRenewal::cookie("token").with_expadd(7200));

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
