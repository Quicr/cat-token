// SPDX-FileCopyrightText: Copyright (c) 2022 Quicr
// SPDX-License-Identifier: BSD-2-Clause

use cat_token::*;
use chrono::{Duration, Utc};

#[test]
fn test_cat_token_creation() {
    let now = Utc::now();
    let exp = now + Duration::hours(1);

    let token = CatTokenBuilder::new()
        .issuer("https://example.com")
        .audience(vec!["https://api.example.com".to_string()])
        .expires_at(exp)
        .not_before(now)
        .cwt_id_str("test-token-id")
        .version(1)
        .uri_match_rules(vec![UriMatchRule {
            component: URI_COMPONENT_HOST,
            matches: vec![MatchValue::Exact("example.com".to_string())],
        }])
        .replay_protection(cat_token::ReplayProtection::Prohibited)
        .geo_coordinate(37.7749, -122.4194, Some(100))
        .geohash("9q8yy")
        .build();

    assert_eq!(token.core.iss, Some("https://example.com".to_string()));
    assert_eq!(
        token.core.aud,
        Some(vec!["https://api.example.com".to_string()])
    );
    assert_eq!(token.core.cti, Some(b"test-token-id".to_vec()));
    assert_eq!(token.cat.catv, Some(1));
    assert_eq!(
        token.cat.catu,
        Some(vec![UriMatchRule {
            component: URI_COMPONENT_HOST,
            matches: vec![MatchValue::Exact("example.com".to_string())],
        }])
    );
    assert_eq!(
        token.cat.catreplay,
        Some(cat_token::ReplayProtection::Prohibited)
    );
    assert_eq!(token.cat.geohash, Some(vec!["9q8yy".to_string()]));

    if let Some(coords) = &token.cat.catgeocoord {
        assert_eq!(coords[0].lat, 37.7749);
        assert_eq!(coords[0].lon, -122.4194);
        assert_eq!(coords[0].radius, Some(100));
    } else {
        panic!("Expected geo coordinates");
    }
}

#[test]
fn test_hmac_token_encoding_decoding() {
    let key = HmacSha256Algorithm::generate_key().unwrap();
    let algorithm = HmacSha256Algorithm::from_secret_key(&key);

    let now = Utc::now();
    let exp = now + Duration::hours(1);

    let token = CatTokenBuilder::new()
        .issuer("https://test.com")
        .audience(vec!["https://api.test.com".to_string()])
        .expires_at(exp)
        .cwt_id_str("test-hmac-token")
        .version(1)
        .build();

    let encoded = encode_token(&token, &algorithm).unwrap();
    assert!(!encoded.is_empty());
    assert!(encoded.len() > 10);

    let decoded = decode_token(&encoded, &algorithm).unwrap();
    assert_eq!(decoded.core.iss, token.core.iss);
    assert_eq!(decoded.core.aud, token.core.aud);
    assert_eq!(decoded.core.cti, token.core.cti);
    assert_eq!(decoded.cat.catv, token.cat.catv);
}

#[test]
fn test_es256_token_encoding_decoding() {
    let algorithm = Es256Algorithm::new_with_key_pair().unwrap();

    let now = Utc::now();
    let exp = now + Duration::hours(1);

    let token = CatTokenBuilder::new()
        .issuer("https://test.com")
        .audience(vec!["https://api.test.com".to_string()])
        .expires_at(exp)
        .cwt_id_str("test-es256-token")
        .version(1)
        .build();

    let encoded = encode_token(&token, &algorithm).unwrap();
    assert!(!encoded.is_empty());
    assert!(encoded.len() > 10);

    let decoded = decode_token(&encoded, &algorithm).unwrap();
    assert_eq!(decoded.core.iss, token.core.iss);
    assert_eq!(decoded.core.aud, token.core.aud);
    assert_eq!(decoded.core.cti, token.core.cti);
    assert_eq!(decoded.cat.catv, token.cat.catv);
}

#[test]
fn test_ps256_token_encoding_decoding() {
    let algorithm = Ps256Algorithm::new_with_key_pair().unwrap();

    let now = Utc::now();
    let exp = now + Duration::hours(1);

    let token = CatTokenBuilder::new()
        .issuer("https://test.com")
        .audience(vec!["https://api.test.com".to_string()])
        .expires_at(exp)
        .cwt_id_str("test-ps256-token")
        .version(1)
        .build();

    let encoded = encode_token(&token, &algorithm).unwrap();
    assert!(!encoded.is_empty());
    assert!(encoded.len() > 10);

    let decoded = decode_token(&encoded, &algorithm).unwrap();
    assert_eq!(decoded.core.iss, token.core.iss);
    assert_eq!(decoded.core.aud, token.core.aud);
    assert_eq!(decoded.core.cti, token.core.cti);
    assert_eq!(decoded.cat.catv, token.cat.catv);
}

#[test]
fn test_token_validation_success() {
    let now = Utc::now();
    let exp = now + Duration::hours(1);

    let token = CatTokenBuilder::new()
        .issuer("https://trusted-issuer.com")
        .audience(vec!["https://my-service.com".to_string()])
        .expires_at(exp)
        .not_before(now)
        .cwt_id_str("valid-token")
        .version(1)
        .geo_coordinate(40.7128, -74.0060, Some(50))
        .geohash("dr5reg")
        .build();

    let validator = CatTokenValidator::new()
        .with_expected_issuers(vec!["https://trusted-issuer.com".to_string()])
        .with_expected_audiences(vec!["https://my-service.com".to_string()])
        .with_clock_skew_tolerance(60);

    assert!(validator.validate(&token).is_ok());
}

#[test]
fn test_token_validation_expired() {
    let now = Utc::now();
    let exp = now - Duration::hours(1); // Expired 1 hour ago

    let token = CatTokenBuilder::new()
        .issuer("https://trusted-issuer.com")
        .audience(vec!["https://my-service.com".to_string()])
        .expires_at(exp)
        .cwt_id_str("expired-token")
        .build();

    let validator = CatTokenValidator::new()
        .with_expected_issuers(vec!["https://trusted-issuer.com".to_string()])
        .with_expected_audiences(vec!["https://my-service.com".to_string()]);

    let result = validator.validate(&token);
    assert!(matches!(result, Err(CatError::TokenExpired)));
}

#[test]
fn test_token_validation_not_yet_valid() {
    let now = Utc::now();
    let nbf = now + Duration::hours(1); // Valid starting 1 hour from now
    let exp = now + Duration::hours(2);

    let token = CatTokenBuilder::new()
        .issuer("https://trusted-issuer.com")
        .audience(vec!["https://my-service.com".to_string()])
        .expires_at(exp)
        .not_before(nbf)
        .cwt_id_str("future-token")
        .build();

    let validator = CatTokenValidator::new()
        .with_expected_issuers(vec!["https://trusted-issuer.com".to_string()])
        .with_expected_audiences(vec!["https://my-service.com".to_string()]);

    let result = validator.validate(&token);
    assert!(matches!(result, Err(CatError::TokenNotYetValid)));
}

#[test]
fn test_token_validation_invalid_issuer() {
    let now = Utc::now();
    let exp = now + Duration::hours(1);

    let token = CatTokenBuilder::new()
        .issuer("https://untrusted-issuer.com")
        .audience(vec!["https://my-service.com".to_string()])
        .expires_at(exp)
        .cwt_id_str("invalid-issuer-token")
        .build();

    let validator = CatTokenValidator::new()
        .with_expected_issuers(vec!["https://trusted-issuer.com".to_string()])
        .with_expected_audiences(vec!["https://my-service.com".to_string()]);

    let result = validator.validate(&token);
    assert!(matches!(result, Err(CatError::InvalidIssuer)));
}

#[test]
fn test_token_validation_invalid_audience() {
    let now = Utc::now();
    let exp = now + Duration::hours(1);

    let token = CatTokenBuilder::new()
        .issuer("https://trusted-issuer.com")
        .audience(vec!["https://other-service.com".to_string()])
        .expires_at(exp)
        .cwt_id_str("invalid-audience-token")
        .build();

    let validator = CatTokenValidator::new()
        .with_expected_issuers(vec!["https://trusted-issuer.com".to_string()])
        .with_expected_audiences(vec!["https://my-service.com".to_string()]);

    let result = validator.validate(&token);
    assert!(matches!(result, Err(CatError::InvalidAudience)));
}

#[test]
fn test_cwt_payload_encoding_decoding() {
    let now = Utc::now();
    let exp = now + Duration::hours(1);

    let token = CatTokenBuilder::new()
        .issuer("https://example.com")
        .audience(vec!["https://api.example.com".to_string()])
        .expires_at(exp)
        .not_before(now)
        .cwt_id_str("test-payload")
        .version(1)
        .uri_match_rules(vec![UriMatchRule {
            component: URI_COMPONENT_PATH,
            matches: vec![MatchValue::Prefix("/api/".to_string())],
        }])
        .replay_protection(cat_token::ReplayProtection::Prohibited)
        .geo_coordinate(51.5074, -0.1278, None)
        .geohash("gcpvj")
        .build();

    let cwt = Cwt::new(-7, token.clone()); // ES256 algorithm
    let encoded_payload = cwt.encode_payload().unwrap();
    let decoded_token = Cwt::decode_payload(&encoded_payload).unwrap();

    assert_eq!(decoded_token.core.iss, token.core.iss);
    assert_eq!(decoded_token.core.aud, token.core.aud);
    assert_eq!(decoded_token.core.cti, token.core.cti);
    assert_eq!(decoded_token.cat.catv, token.cat.catv);
    assert_eq!(decoded_token.cat.catu, token.cat.catu);
    assert_eq!(decoded_token.cat.catreplay, token.cat.catreplay);
    assert_eq!(decoded_token.cat.geohash, token.cat.geohash);

    if let (Some(orig_coords), Some(decoded_coords)) =
        (&token.cat.catgeocoord, &decoded_token.cat.catgeocoord)
    {
        assert_eq!(orig_coords[0].lat, decoded_coords[0].lat);
        assert_eq!(orig_coords[0].lon, decoded_coords[0].lon);
        assert_eq!(orig_coords[0].radius, decoded_coords[0].radius);
    }
}

#[test]
fn test_all_cat_claims() {
    let token = CatToken {
        core: CoreClaims {
            iss: Some("https://issuer.com".to_string()),
            aud: Some(vec!["aud1".to_string(), "aud2".to_string()]),
            exp: Some(1234567890),
            nbf: Some(1234567800),
            cti: Some(b"unique-token-id".to_vec()),
        },
        cat: CatClaims {
            catreplay: Some(cat_token::ReplayProtection::Prohibited),
            catpor: None,
            catv: Some(1),
            catnip: Some(vec![
                NetworkIdentifier::IpPrefix("192.168.1.0".parse().unwrap(), 24),
                NetworkIdentifier::IpPrefix("10.0.0.0".parse().unwrap(), 8),
            ]),
            catu: Some(vec![
                UriMatchRule {
                    component: URI_COMPONENT_HOST,
                    matches: vec![MatchValue::Exact("api.example.com".to_string())],
                },
                UriMatchRule {
                    component: URI_COMPONENT_PATH,
                    matches: vec![MatchValue::Prefix("/v1/".to_string())],
                },
            ]),
            catm: Some(vec!["GET".to_string(), "POST".to_string()]),
            catalpn: Some(vec![b"h2".to_vec(), b"http/1.1".to_vec()]),
            cath: Some(vec![
                HeaderMatchRule {
                    name: "Host".to_string(),
                    matches: vec![MatchValue::Exact("api.example.com".to_string())],
                },
                HeaderMatchRule {
                    name: "Host".to_string(),
                    matches: vec![MatchValue::Suffix(".example.org".to_string())],
                },
            ]),
            catgeoiso3166: Some(vec!["US".to_string(), "CA".to_string()]),
            catgeocoord: Some(vec![GeoCoordinate {
                lat: 34.0522,
                lon: -118.2437,
                radius: Some(25),
            }]),
            geohash: Some(vec!["9q5ct".to_string()]),
            catgeoalt: Some(cat_token::GeoAltitude {
                altitude: 100.0,
                deviation: 10.0,
            }),
            cattpk: Some(b"thumbprint-data".to_vec()),
        },
        informational: InformationalClaims {
            sub: None,
            iat: None,
            catifdata: None,
        },
        dpop: DpopClaims {
            cnf: None,
            catdpop: None,
        },
        request: RequestClaims {
            catif: None,
            catr: None,
        },
        composite: cat_token::claims::CompositeClaims::default(),
        moqt: cat_token::claims::MoqtClaims {
            moqt: None,
            moqt_reval: None,
        },
        custom: std::collections::HashMap::new(),
    };

    let cwt = Cwt::new(-4, token.clone()); // HMAC256
    let encoded_payload = cwt.encode_payload().unwrap();
    let decoded_token = Cwt::decode_payload(&encoded_payload).unwrap();

    // Verify all core claims
    assert_eq!(decoded_token.core.iss, token.core.iss);
    assert_eq!(decoded_token.core.aud, token.core.aud);
    assert_eq!(decoded_token.core.exp, token.core.exp);
    assert_eq!(decoded_token.core.nbf, token.core.nbf);
    assert_eq!(decoded_token.core.cti, token.core.cti);

    // Verify all CAT claims
    assert_eq!(decoded_token.cat.catreplay, token.cat.catreplay);
    assert_eq!(decoded_token.cat.catv, token.cat.catv);
    assert_eq!(decoded_token.cat.catnip, token.cat.catnip);
    assert_eq!(decoded_token.cat.catu, token.cat.catu);
    assert_eq!(decoded_token.cat.catm, token.cat.catm);
    assert_eq!(decoded_token.cat.catalpn, token.cat.catalpn);
    assert_eq!(decoded_token.cat.cath, token.cat.cath);
    assert_eq!(decoded_token.cat.catgeoiso3166, token.cat.catgeoiso3166);
    assert_eq!(decoded_token.cat.geohash, token.cat.geohash);
    assert_eq!(decoded_token.cat.catgeoalt, token.cat.catgeoalt);
    assert_eq!(decoded_token.cat.cattpk, token.cat.cattpk);

    // Verify geo coordinates
    if let (Some(orig), Some(decoded)) = (&token.cat.catgeocoord, &decoded_token.cat.catgeocoord) {
        assert_eq!(orig[0].lat, decoded[0].lat);
        assert_eq!(orig[0].lon, decoded[0].lon);
        assert_eq!(orig[0].radius, decoded[0].radius);
    }
}

#[test]
fn test_invalid_signature_verification() {
    let key1 = HmacSha256Algorithm::generate_key().unwrap();
    let key2 = HmacSha256Algorithm::generate_key().unwrap();
    let algorithm1 = HmacSha256Algorithm::from_secret_key(&key1);
    let algorithm2 = HmacSha256Algorithm::from_secret_key(&key2);

    let token = CatTokenBuilder::new()
        .issuer("https://test.com")
        .cwt_id_str("signature-test")
        .build();

    let encoded = encode_token(&token, &algorithm1).unwrap();

    // Try to verify with different key - should fail
    let result = decode_token(&encoded, &algorithm2);
    assert!(matches!(result, Err(CatError::SignatureVerificationFailed)));
}

#[test]
fn test_invalid_token_format() {
    let key = HmacSha256Algorithm::generate_key().unwrap();
    let algorithm = HmacSha256Algorithm::from_secret_key(&key);

    // Test with invalid CBOR bytes
    let result = decode_token(b"invalid", &algorithm);
    assert!(result.is_err());

    let result = decode_token(b"\x00\x01", &algorithm);
    assert!(result.is_err());

    let result = decode_token(&[], &algorithm);
    assert!(result.is_err());
}

#[test]
fn test_geographic_validation() {
    let validator = CatTokenValidator::new();

    // Test invalid coordinates
    let mut token = CatToken::new();
    token.cat.catgeocoord = Some(vec![GeoCoordinate {
        lat: 91.0, // Invalid latitude
        lon: 0.0,
        radius: None,
    }]);

    let result = validator.validate(&token);
    assert!(matches!(
        result,
        Err(CatError::GeographicValidationFailed(_))
    ));

    // Test invalid geohash
    token.cat.catgeocoord = None;
    token.cat.geohash = Some(vec!["".to_string()]); // Empty geohash

    let result = validator.validate(&token);
    assert!(matches!(
        result,
        Err(CatError::GeographicValidationFailed(_))
    ));
}

#[test]
fn test_moqt_claims_creation() {
    use cat_token::claims::{BinaryMatch, MoqtAction, MoqtScope, NamespaceMatch};

    let namespace_match = NamespaceMatch::exact(b"example.com".to_vec());
    let track_match = BinaryMatch::prefix(b"/bob".to_vec());

    let scope = MoqtScope::new()
        .with_actions(vec![
            MoqtAction::PublishNamespace,
            MoqtAction::SubscribeNamespace,
            MoqtAction::Publish,
            MoqtAction::Fetch,
        ])
        .with_namespace_match(namespace_match)
        .with_track_match(track_match);

    let token = CatTokenBuilder::new()
        .issuer("https://moqt-issuer.com")
        .audience(vec!["moqt-relay".to_string()])
        .expires_at(Utc::now() + Duration::hours(1))
        .cwt_id_str("moqt-token")
        .moqt_scope(scope)
        .moqt_reval(300.0)
        .build();

    // Test MOQT claims are present
    assert!(token.moqt.moqt.is_some());
    assert_eq!(token.moqt.moqt_reval, Some(300.0));

    let scopes = token.moqt.moqt.as_ref().unwrap();
    assert_eq!(scopes.len(), 1);
    assert_eq!(scopes[0].actions.len(), 4);
    assert!(scopes[0].actions.contains(&MoqtAction::PublishNamespace));
    assert!(scopes[0].actions.contains(&MoqtAction::Publish));

    // Test action authorization
    assert!(token.allows_moqt_action(
        &MoqtAction::PublishNamespace,
        b"example.com",
        b"/bob/stream1"
    ));

    assert!(!token.allows_moqt_action(
        &MoqtAction::Subscribe, // Not in allowed actions
        b"example.com",
        b"/bob/stream1"
    ));

    assert!(!token.allows_moqt_action(
        &MoqtAction::PublishNamespace,
        b"other.com", // Doesn't match namespace
        b"/bob/stream1"
    ));

    assert!(!token.allows_moqt_action(
        &MoqtAction::PublishNamespace,
        b"example.com",
        b"/alice/stream1" // Doesn't match track prefix
    ));
}

#[test]
fn test_moqt_binary_match() {
    use cat_token::claims::BinaryMatch;

    // Test exact match
    let exact_match = BinaryMatch::exact(b"example.com".to_vec());
    assert!(exact_match.matches(b"example.com"));
    assert!(!exact_match.matches(b"example.org"));
    assert!(!exact_match.matches(b"sub.example.com"));

    // Test prefix match
    let prefix_match = BinaryMatch::prefix(b"/bob".to_vec());
    assert!(prefix_match.matches(b"/bob"));
    assert!(prefix_match.matches(b"/bob/stream1"));
    assert!(prefix_match.matches(b"/bob/logs"));
    assert!(!prefix_match.matches(b"/alice"));
    assert!(!prefix_match.matches(b""));

    // Test suffix match
    let suffix_match = BinaryMatch::suffix(b".mp4".to_vec());
    assert!(suffix_match.matches(b"video.mp4"));
    assert!(suffix_match.matches(b"/path/to/video.mp4"));
    assert!(!suffix_match.matches(b"video.mp3"));
    assert!(!suffix_match.matches(b"video.mp4.bak"));

    // Note: contains match was removed from spec, now only exact/prefix/suffix are supported

    // Test empty match (should match everything)
    let empty_match = BinaryMatch::default();
    assert!(empty_match.matches(b"anything"));
    assert!(empty_match.matches(b""));
    assert!(empty_match.matches(b"example.com"));
}

#[test]
fn test_moqt_token_encoding_decoding() {
    use cat_token::claims::{BinaryMatch, MoqtAction, MoqtScope, NamespaceMatch};

    let key = HmacSha256Algorithm::generate_key().unwrap();
    let algorithm = HmacSha256Algorithm::from_secret_key(&key);

    let scope1 = MoqtScope::new()
        .with_actions(vec![MoqtAction::PublishNamespace, MoqtAction::Publish])
        .with_namespace_match(NamespaceMatch::exact(b"example.com".to_vec()))
        .with_track_match(BinaryMatch::prefix(b"/bob".to_vec()));

    let scope2 = MoqtScope::new()
        .with_actions(vec![MoqtAction::Fetch])
        .with_namespace_match(NamespaceMatch::exact(b"example.com".to_vec()))
        .with_track_match(BinaryMatch::exact(b"logs/12345/bob".to_vec()));

    let token = CatTokenBuilder::new()
        .issuer("https://moqt-test.com")
        .audience(vec!["moqt-relay".to_string()])
        .expires_at(Utc::now() + Duration::hours(1))
        .cwt_id_str("moqt-encode-test")
        .moqt_scopes(vec![scope1, scope2])
        .moqt_reval(600.0)
        .build();

    let encoded = encode_token(&token, &algorithm).unwrap();
    let decoded = decode_token(&encoded, &algorithm).unwrap();

    // Verify MOQT claims were preserved
    assert_eq!(decoded.moqt.moqt_reval, Some(600.0));
    assert!(decoded.moqt.moqt.is_some());

    let decoded_scopes = decoded.moqt.moqt.as_ref().unwrap();
    assert_eq!(decoded_scopes.len(), 2);

    // Verify first scope
    assert_eq!(decoded_scopes[0].actions.len(), 2);
    assert!(
        decoded_scopes[0]
            .actions
            .contains(&MoqtAction::PublishNamespace)
    );
    assert!(decoded_scopes[0].actions.contains(&MoqtAction::Publish));
    assert!(decoded_scopes[0].matches_namespace(b"example.com"));
    assert!(decoded_scopes[0].matches_track(b"/bob/stream1"));

    // Verify second scope
    assert_eq!(decoded_scopes[1].actions.len(), 1);
    assert!(decoded_scopes[1].actions.contains(&MoqtAction::Fetch));
    assert!(decoded_scopes[1].matches_track(b"logs/12345/bob"));
    assert!(!decoded_scopes[1].matches_track(b"logs/12345/alice"));
}

#[test]
fn test_moqt_multiple_scopes_authorization() {
    use cat_token::claims::{BinaryMatch, MoqtAction, MoqtScope, NamespaceMatch};

    // Create multiple scopes with different permissions
    let scope1 = MoqtScope::new()
        .with_actions(vec![
            MoqtAction::PublishNamespace,
            MoqtAction::SubscribeNamespace,
        ])
        .with_namespace_match(NamespaceMatch::exact(b"example.com".to_vec()))
        .with_track_match(BinaryMatch::prefix(b"/public".to_vec()));

    let scope2 = MoqtScope::new()
        .with_actions(vec![MoqtAction::Publish, MoqtAction::Fetch])
        .with_namespace_match(NamespaceMatch::exact(b"example.com".to_vec()))
        .with_track_match(BinaryMatch::prefix(b"/private".to_vec()));

    let token = CatTokenBuilder::new()
        .issuer("https://multi-scope-test.com")
        .audience(vec!["moqt-relay".to_string()])
        .expires_at(Utc::now() + Duration::hours(1))
        .moqt_scopes(vec![scope1, scope2])
        .build();

    // Test permissions for public namespace (scope1)
    assert!(token.allows_moqt_action(
        &MoqtAction::PublishNamespace,
        b"example.com",
        b"/public/stream1"
    ));
    assert!(token.allows_moqt_action(
        &MoqtAction::SubscribeNamespace,
        b"example.com",
        b"/public/events"
    ));
    assert!(!token.allows_moqt_action(
        &MoqtAction::Publish, // Not allowed in scope1
        b"example.com",
        b"/public/stream1"
    ));

    // Test permissions for private namespace (scope2)
    assert!(token.allows_moqt_action(&MoqtAction::Publish, b"example.com", b"/private/stream1"));
    assert!(token.allows_moqt_action(&MoqtAction::Fetch, b"example.com", b"/private/data"));
    assert!(!token.allows_moqt_action(
        &MoqtAction::PublishNamespace, // Not allowed in scope2
        b"example.com",
        b"/private/stream1"
    ));

    // Test no permissions for other paths
    assert!(!token.allows_moqt_action(
        &MoqtAction::PublishNamespace,
        b"example.com",
        b"/restricted/stream1" // No matching scope
    ));
}

#[test]
fn test_moqt_action_conversion() {
    use cat_token::claims::MoqtAction;

    // Test TryFrom<i32> conversion
    assert_eq!(MoqtAction::try_from(0).unwrap(), MoqtAction::ClientSetup);
    assert_eq!(MoqtAction::try_from(1).unwrap(), MoqtAction::ServerSetup);
    assert_eq!(
        MoqtAction::try_from(2).unwrap(),
        MoqtAction::PublishNamespace
    );
    assert_eq!(
        MoqtAction::try_from(3).unwrap(),
        MoqtAction::SubscribeNamespace
    );
    assert_eq!(MoqtAction::try_from(4).unwrap(), MoqtAction::Subscribe);
    assert_eq!(MoqtAction::try_from(5).unwrap(), MoqtAction::RequestUpdate);
    assert_eq!(MoqtAction::try_from(6).unwrap(), MoqtAction::Publish);
    assert_eq!(MoqtAction::try_from(7).unwrap(), MoqtAction::Fetch);
    assert_eq!(MoqtAction::try_from(8).unwrap(), MoqtAction::TrackStatus);

    // Test unknown action returns error (not silent fallback)
    assert!(MoqtAction::try_from(99).is_err());
    assert!(MoqtAction::try_from(-1).is_err());
}

#[test]
fn test_moqt_spec_example_exact_match() {
    use cat_token::claims::{BinaryMatch, MoqtAction, MoqtScope, NamespaceMatch};

    // Example from spec: Allow with an exact match "example.com/bob"
    let scope = MoqtScope::new()
        .with_actions(vec![
            MoqtAction::PublishNamespace,
            MoqtAction::SubscribeNamespace,
            MoqtAction::Publish,
            MoqtAction::Fetch,
        ])
        .with_namespace_match(NamespaceMatch::exact(b"example.com".to_vec()))
        .with_track_match(BinaryMatch::exact(b"/bob".to_vec()));

    let token = CatTokenBuilder::new()
        .issuer("https://spec-example.com")
        .moqt_scope(scope)
        .build();

    // Should permit
    assert!(token.allows_moqt_action(&MoqtAction::PublishNamespace, b"example.com", b"/bob"));

    // Should prohibit
    assert!(!token.allows_moqt_action(&MoqtAction::PublishNamespace, b"example.com", b""));
    assert!(!token.allows_moqt_action(&MoqtAction::PublishNamespace, b"example.com", b"/bob/123"));
    assert!(!token.allows_moqt_action(&MoqtAction::PublishNamespace, b"example.com", b"/alice"));
    assert!(!token.allows_moqt_action(&MoqtAction::PublishNamespace, b"example.com", b"/bob/logs"));
    assert!(!token.allows_moqt_action(
        &MoqtAction::PublishNamespace,
        b"alternate/example.com",
        b"/bob"
    ));
    assert!(!token.allows_moqt_action(&MoqtAction::PublishNamespace, b"12345", b""));
    assert!(!token.allows_moqt_action(&MoqtAction::PublishNamespace, b"example", b".com/bob"));
}

#[test]
fn test_moqt_spec_example_prefix_match() {
    use cat_token::claims::{BinaryMatch, MoqtAction, MoqtScope, NamespaceMatch};

    // Example from spec: Allow with a prefix match "example.com/bob"
    let scope = MoqtScope::new()
        .with_actions(vec![
            MoqtAction::PublishNamespace,
            MoqtAction::SubscribeNamespace,
            MoqtAction::Publish,
            MoqtAction::Fetch,
        ])
        .with_namespace_match(NamespaceMatch::exact(b"example.com".to_vec()))
        .with_track_match(BinaryMatch::prefix(b"/bob".to_vec()));

    let token = CatTokenBuilder::new()
        .issuer("https://spec-prefix-example.com")
        .moqt_scope(scope)
        .build();

    // Should permit
    assert!(token.allows_moqt_action(&MoqtAction::PublishNamespace, b"example.com", b"/bob"));
    assert!(token.allows_moqt_action(&MoqtAction::PublishNamespace, b"example.com", b"/bob/123"));
    assert!(token.allows_moqt_action(&MoqtAction::PublishNamespace, b"example.com", b"/bob/logs"));

    // Should prohibit
    assert!(!token.allows_moqt_action(&MoqtAction::PublishNamespace, b"example.com", b""));
    assert!(!token.allows_moqt_action(&MoqtAction::PublishNamespace, b"example.com", b"/alice"));
    assert!(!token.allows_moqt_action(
        &MoqtAction::PublishNamespace,
        b"alternate/example.com",
        b"/bob"
    ));
    assert!(!token.allows_moqt_action(&MoqtAction::PublishNamespace, b"12345", b""));
    assert!(!token.allows_moqt_action(&MoqtAction::PublishNamespace, b"example", b".com/bob"));
}
