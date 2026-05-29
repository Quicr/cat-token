// SPDX-FileCopyrightText: Copyright (c) 2022 Quicr
// SPDX-License-Identifier: BSD-2-Clause
//
// Tests that validate against the deterministic test vectors in tests/test_data/.
// These same vectors can be used by other CAT/MoQT implementations for interop testing.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use cat_token::*;
use p256::ecdsa::{SigningKey, VerifyingKey};
use serde_json::Value as JsonValue;

const HMAC_KEY_HEX: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
const ES256_PRIVATE_KEY_HEX: &str =
    "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721";

fn load_vectors() -> JsonValue {
    let data = include_str!("test_data/cat_test_vectors.json");
    serde_json::from_str(data).expect("Failed to parse test vectors JSON")
}

fn hmac_key() -> Vec<u8> {
    hex::decode(HMAC_KEY_HEX).unwrap()
}

fn es256_algorithm() -> Es256Algorithm {
    let key_bytes = hex::decode(ES256_PRIVATE_KEY_HEX).unwrap();
    let signing_key = SigningKey::from_bytes(key_bytes.as_slice().into()).unwrap();
    let verifying_key = VerifyingKey::from(&signing_key);
    Es256Algorithm::from_key_pair(signing_key, verifying_key)
}

// =============================================================================
// Category 1: CBOR Encoding Tests
// =============================================================================

#[test]
fn test_vector_cbor_issuer_only() {
    let vectors = load_vectors();
    let cbor_vectors = &vectors["vectors"]["cbor_encoding"]["vectors"];
    let v = &cbor_vectors[0];

    assert_eq!(v["id"], "cbor_issuer_only");

    let token = CatToken::new().with_issuer("https://auth.example.com");
    let cwt = Cwt::new(ALG_HMAC256_256, token);
    let payload = cwt.encode_payload().unwrap();

    let expected_hex = v["payload_cbor_hex"].as_str().unwrap();
    assert_eq!(hex::encode(&payload), expected_hex);
}

#[test]
fn test_vector_cbor_core_claims() {
    let vectors = load_vectors();
    let cbor_vectors = &vectors["vectors"]["cbor_encoding"]["vectors"];
    let v = &cbor_vectors[1];

    assert_eq!(v["id"], "cbor_core_claims");

    let token = CatToken::new()
        .with_issuer("https://auth.example.com")
        .with_audience(vec!["https://relay.example.com".to_string()])
        .with_cwt_id("test-token-001");
    let mut token = token;
    token.core.exp = Some(v["claims"]["exp"].as_i64().unwrap());
    token.core.nbf = Some(v["claims"]["nbf"].as_i64().unwrap());

    let cwt = Cwt::new(ALG_HMAC256_256, token);
    let payload = cwt.encode_payload().unwrap();

    let expected_hex = v["payload_cbor_hex"].as_str().unwrap();
    assert_eq!(hex::encode(&payload), expected_hex);
}

#[test]
fn test_vector_cbor_cat_version_usage() {
    let vectors = load_vectors();
    let cbor_vectors = &vectors["vectors"]["cbor_encoding"]["vectors"];
    let v = &cbor_vectors[2];

    assert_eq!(v["id"], "cbor_cat_version_usage");

    let token = CatToken::new().with_version("CAT-v1").with_usage_limit(5);
    let cwt = Cwt::new(ALG_HMAC256_256, token);
    let payload = cwt.encode_payload().unwrap();

    let expected_hex = v["payload_cbor_hex"].as_str().unwrap();
    assert_eq!(hex::encode(&payload), expected_hex);
}

#[test]
fn test_vector_cbor_network_identifiers() {
    let vectors = load_vectors();
    let cbor_vectors = &vectors["vectors"]["cbor_encoding"]["vectors"];
    let v = &cbor_vectors[3];

    assert_eq!(v["id"], "cbor_network_identifiers");

    let token = CatToken::new()
        .with_ip_address("192.168.1.100")
        .with_ip_range("10.0.0.0/8")
        .with_asn(64512)
        .with_asn_range(64512, 64768);
    let cwt = Cwt::new(ALG_HMAC256_256, token);
    let payload = cwt.encode_payload().unwrap();

    let expected_hex = v["payload_cbor_hex"].as_str().unwrap();
    assert_eq!(hex::encode(&payload), expected_hex);
}

#[test]
fn test_vector_cbor_geographic_claims() {
    let vectors = load_vectors();
    let cbor_vectors = &vectors["vectors"]["cbor_encoding"]["vectors"];
    let v = &cbor_vectors[4];

    assert_eq!(v["id"], "cbor_geographic_claims");

    let token = CatToken::new()
        .with_geo_coordinate(37.7749, -122.4194, Some(100.0))
        .with_geohash("9q8yyk");
    let mut token = token;
    token.cat.catgeoiso3166 = Some(vec!["US".to_string(), "CA".to_string()]);
    token.cat.catgeoalt = Some(10);

    let cwt = Cwt::new(ALG_HMAC256_256, token);
    let payload = cwt.encode_payload().unwrap();

    let expected_hex = v["payload_cbor_hex"].as_str().unwrap();
    assert_eq!(hex::encode(&payload), expected_hex);
}

#[test]
fn test_vector_cbor_uri_patterns() {
    let vectors = load_vectors();
    let cbor_vectors = &vectors["vectors"]["cbor_encoding"]["vectors"];
    let v = &cbor_vectors[5];

    assert_eq!(v["id"], "cbor_uri_patterns");

    let token = CatToken::new().with_uri_patterns(vec![
        UriPattern::Exact("https://example.com/live/stream1".to_string()),
        UriPattern::Prefix("https://example.com/vod/".to_string()),
        UriPattern::Suffix(".m3u8".to_string()),
    ]);
    let cwt = Cwt::new(ALG_HMAC256_256, token);
    let payload = cwt.encode_payload().unwrap();

    let expected_hex = v["payload_cbor_hex"].as_str().unwrap();
    assert_eq!(hex::encode(&payload), expected_hex);
}

#[test]
fn test_vector_cbor_alpn() {
    let vectors = load_vectors();
    let cbor_vectors = &vectors["vectors"]["cbor_encoding"]["vectors"];
    let v = &cbor_vectors[6];

    assert_eq!(v["id"], "cbor_alpn");

    let mut token = CatToken::new();
    token.cat.catalpn = Some(vec!["moq-00".to_string(), "h3".to_string()]);
    let cwt = Cwt::new(ALG_HMAC256_256, token);
    let payload = cwt.encode_payload().unwrap();

    let expected_hex = v["payload_cbor_hex"].as_str().unwrap();
    assert_eq!(hex::encode(&payload), expected_hex);
}

// =============================================================================
// Category 2: Token Structure Tests
// =============================================================================

#[test]
fn test_vector_token_hmac_minimal() {
    let vectors = load_vectors();
    let token_vectors = &vectors["vectors"]["token_structure"]["vectors"];
    let v = &token_vectors[0];

    assert_eq!(v["id"], "token_hmac_minimal");

    let alg = HmacSha256Algorithm::new(&hmac_key());
    let token_str = v["token"].as_str().unwrap();

    // Verify the token decodes correctly
    let decoded = decode_token(token_str, &alg).unwrap();
    assert_eq!(
        decoded.core.iss.as_deref(),
        Some("https://auth.example.com")
    );
    assert_eq!(
        decoded.core.aud.as_deref(),
        Some(vec!["https://relay.example.com".to_string()].as_slice())
    );
    assert_eq!(decoded.core.exp, Some(v["claims"]["exp"].as_i64().unwrap()));
}

#[test]
fn test_vector_token_hmac_minimal_reproduces() {
    let vectors = load_vectors();
    let token_vectors = &vectors["vectors"]["token_structure"]["vectors"];
    let v = &token_vectors[0];

    // Re-create the token from scratch and verify it produces the same encoding
    let token = CatToken::new()
        .with_issuer("https://auth.example.com")
        .with_audience(vec!["https://relay.example.com".to_string()]);
    let mut token = token;
    token.core.exp = Some(v["claims"]["exp"].as_i64().unwrap());

    let alg = HmacSha256Algorithm::new(&hmac_key());
    let encoded = encode_token(&token, &alg).unwrap();

    assert_eq!(encoded, v["token"].as_str().unwrap());
}

#[test]
fn test_vector_token_hmac_full() {
    let vectors = load_vectors();
    let token_vectors = &vectors["vectors"]["token_structure"]["vectors"];
    let v = &token_vectors[1];

    assert_eq!(v["id"], "token_hmac_full");

    let alg = HmacSha256Algorithm::new(&hmac_key());
    let token_str = v["token"].as_str().unwrap();

    let decoded = decode_token(token_str, &alg).unwrap();
    assert_eq!(
        decoded.core.iss.as_deref(),
        Some("https://issuer.moq.example")
    );
    assert_eq!(decoded.core.aud.as_ref().unwrap().len(), 2);
    assert_eq!(decoded.core.cti.as_deref(), Some("vector-002"));
    assert_eq!(decoded.cat.catv.as_deref(), Some("CAT-v1"));
    assert_eq!(decoded.cat.catu, Some(10));
    assert_eq!(
        decoded.informational.sub.as_deref(),
        Some("user:alice@example.com")
    );
    assert_eq!(
        decoded.informational.iat,
        Some(v["claims"]["iat"].as_i64().unwrap())
    );
}

#[test]
fn test_vector_token_es256() {
    let vectors = load_vectors();
    let token_vectors = &vectors["vectors"]["token_structure"]["vectors"];
    let v = &token_vectors[2];

    assert_eq!(v["id"], "token_es256");

    let alg = es256_algorithm();
    let token_str = v["token"].as_str().unwrap();

    let decoded = decode_token(token_str, &alg).unwrap();
    assert_eq!(
        decoded.core.iss.as_deref(),
        Some("https://auth.example.com")
    );
    assert_eq!(
        decoded.core.aud.as_deref(),
        Some(vec!["https://moq-relay.example.com".to_string()].as_slice())
    );
}

#[test]
fn test_vector_token_es256_reproduces() {
    let vectors = load_vectors();
    let token_vectors = &vectors["vectors"]["token_structure"]["vectors"];
    let v = &token_vectors[2];

    let token = CatToken::new()
        .with_issuer("https://auth.example.com")
        .with_audience(vec!["https://moq-relay.example.com".to_string()]);
    let mut token = token;
    token.core.exp = Some(v["claims"]["exp"].as_i64().unwrap());
    token.core.nbf = Some(v["claims"]["nbf"].as_i64().unwrap());

    let alg = es256_algorithm();
    let encoded = encode_token(&token, &alg).unwrap();

    // ES256 with p256 crate uses RFC 6979 deterministic signatures
    assert_eq!(encoded, v["token"].as_str().unwrap());
}

#[test]
fn test_vector_token_parts_match() {
    let vectors = load_vectors();
    let token_vectors = &vectors["vectors"]["token_structure"]["vectors"];

    for v in token_vectors.as_array().unwrap() {
        let token_str = v["token"].as_str().unwrap();
        let parts: Vec<&str> = token_str.split('.').collect();
        assert_eq!(parts.len(), 3, "Token {} should have 3 parts", v["id"]);

        // Verify header CBOR hex matches
        let header_bytes = URL_SAFE_NO_PAD.decode(parts[0]).unwrap();
        assert_eq!(
            hex::encode(&header_bytes),
            v["header_cbor_hex"].as_str().unwrap(),
            "Header mismatch for {}",
            v["id"]
        );

        // Verify payload CBOR hex matches
        let payload_bytes = URL_SAFE_NO_PAD.decode(parts[1]).unwrap();
        assert_eq!(
            hex::encode(&payload_bytes),
            v["payload_cbor_hex"].as_str().unwrap(),
            "Payload mismatch for {}",
            v["id"]
        );

        // Verify signature hex matches
        let sig_bytes = URL_SAFE_NO_PAD.decode(parts[2]).unwrap();
        assert_eq!(
            hex::encode(&sig_bytes),
            v["signature_hex"].as_str().unwrap(),
            "Signature mismatch for {}",
            v["id"]
        );
    }
}

// =============================================================================
// Category 3: MOQT Scope Tests
// =============================================================================

#[test]
fn test_vector_moqt_publisher_exact() {
    let vectors = load_vectors();
    let moqt_vectors = &vectors["vectors"]["moqt_scopes"]["vectors"];
    let v = &moqt_vectors[0];

    assert_eq!(v["id"], "moqt_publisher_exact");

    let alg = HmacSha256Algorithm::new(&hmac_key());
    let token_str = v["token"].as_str().unwrap();
    let decoded = decode_token(token_str, &alg).unwrap();

    let scopes = decoded.moqt.moqt.as_ref().unwrap();
    assert_eq!(scopes.len(), 1);
    assert_eq!(scopes[0].actions.len(), 2);
    assert!(scopes[0].actions.contains(&MoqtAction::PublishNamespace));
    assert!(scopes[0].actions.contains(&MoqtAction::Publish));

    // Run authorization tests from the vector
    for test in v["authorization_tests"].as_array().unwrap() {
        let action_id = test["action"].as_i64().unwrap() as i32;
        let action = MoqtAction::try_from(action_id).unwrap();
        let ns: Vec<&str> = test["namespace"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        let ns_bytes: Vec<&[u8]> = ns.iter().map(|s| s.as_bytes()).collect();
        let track = test["track"].as_str().unwrap();
        let expected = test["expected"].as_bool().unwrap();

        let result = scopes.iter().any(|scope| {
            scope.allows_action(&action)
                && scope.matches_full_track_name(&ns_bytes, track.as_bytes())
        });

        assert_eq!(
            result, expected,
            "Authorization test failed for action={}, ns={:?}, track={}",
            action_id, ns, track
        );
    }
}

#[test]
fn test_vector_moqt_subscriber_prefix() {
    let vectors = load_vectors();
    let moqt_vectors = &vectors["vectors"]["moqt_scopes"]["vectors"];
    let v = &moqt_vectors[1];

    assert_eq!(v["id"], "moqt_subscriber_prefix");

    let alg = HmacSha256Algorithm::new(&hmac_key());
    let token_str = v["token"].as_str().unwrap();
    let decoded = decode_token(token_str, &alg).unwrap();

    let scopes = decoded.moqt.moqt.as_ref().unwrap();
    assert_eq!(scopes.len(), 1);
    assert_eq!(scopes[0].actions.len(), 3);

    for test in v["authorization_tests"].as_array().unwrap() {
        let action_id = test["action"].as_i64().unwrap() as i32;
        let action = MoqtAction::try_from(action_id).unwrap();
        let ns: Vec<&str> = test["namespace"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        let ns_bytes: Vec<&[u8]> = ns.iter().map(|s| s.as_bytes()).collect();
        let track = test["track"].as_str().unwrap();
        let expected = test["expected"].as_bool().unwrap();

        let result = scopes.iter().any(|scope| {
            scope.allows_action(&action)
                && scope.matches_full_track_name(&ns_bytes, track.as_bytes())
        });

        assert_eq!(
            result, expected,
            "Authorization test failed for action={}, ns={:?}, track={}",
            action_id, ns, track
        );
    }
}

#[test]
fn test_vector_moqt_multi_scope() {
    let vectors = load_vectors();
    let moqt_vectors = &vectors["vectors"]["moqt_scopes"]["vectors"];
    let v = &moqt_vectors[2];

    assert_eq!(v["id"], "moqt_multi_scope");

    let alg = HmacSha256Algorithm::new(&hmac_key());
    let token_str = v["token"].as_str().unwrap();
    let decoded = decode_token(token_str, &alg).unwrap();

    let scopes = decoded.moqt.moqt.as_ref().unwrap();
    assert_eq!(scopes.len(), 2);
    assert_eq!(decoded.moqt.moqt_reval, Some(300.0));

    for test in v["authorization_tests"].as_array().unwrap() {
        let action_id = test["action"].as_i64().unwrap() as i32;
        let action = MoqtAction::try_from(action_id).unwrap();
        let ns: Vec<&str> = test["namespace"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        let ns_bytes: Vec<&[u8]> = ns.iter().map(|s| s.as_bytes()).collect();
        let track = test["track"].as_str().unwrap();
        let expected = test["expected"].as_bool().unwrap();

        let result = scopes.iter().any(|scope| {
            scope.allows_action(&action)
                && scope.matches_full_track_name(&ns_bytes, track.as_bytes())
        });

        assert_eq!(
            result, expected,
            "Multi-scope auth test failed for action={}, ns={:?}, track={}",
            action_id, ns, track
        );
    }
}

#[test]
fn test_vector_moqt_admin_wildcard() {
    let vectors = load_vectors();
    let moqt_vectors = &vectors["vectors"]["moqt_scopes"]["vectors"];
    let v = &moqt_vectors[3];

    assert_eq!(v["id"], "moqt_admin_wildcard");

    let alg = HmacSha256Algorithm::new(&hmac_key());
    let token_str = v["token"].as_str().unwrap();
    let decoded = decode_token(token_str, &alg).unwrap();

    let scopes = decoded.moqt.moqt.as_ref().unwrap();
    assert_eq!(scopes.len(), 1);
    assert_eq!(scopes[0].actions.len(), 9);

    for test in v["authorization_tests"].as_array().unwrap() {
        let action_id = test["action"].as_i64().unwrap() as i32;
        let action = MoqtAction::try_from(action_id).unwrap();
        let ns: Vec<&str> = test["namespace"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        let ns_bytes: Vec<&[u8]> = ns.iter().map(|s| s.as_bytes()).collect();
        let track = test["track"].as_str().unwrap();
        let expected = test["expected"].as_bool().unwrap();

        let result = scopes.iter().any(|scope| {
            scope.allows_action(&action)
                && scope.matches_full_track_name(&ns_bytes, track.as_bytes())
        });

        assert_eq!(result, expected);
    }
}

#[test]
fn test_vector_moqt_suffix_match() {
    let vectors = load_vectors();
    let moqt_vectors = &vectors["vectors"]["moqt_scopes"]["vectors"];
    let v = &moqt_vectors[4];

    assert_eq!(v["id"], "moqt_suffix_match");

    let alg = HmacSha256Algorithm::new(&hmac_key());
    let token_str = v["token"].as_str().unwrap();
    let decoded = decode_token(token_str, &alg).unwrap();

    let scopes = decoded.moqt.moqt.as_ref().unwrap();
    assert_eq!(scopes.len(), 1);

    for test in v["authorization_tests"].as_array().unwrap() {
        let action_id = test["action"].as_i64().unwrap() as i32;
        let action = MoqtAction::try_from(action_id).unwrap();
        let ns: Vec<&str> = test["namespace"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        let ns_bytes: Vec<&[u8]> = ns.iter().map(|s| s.as_bytes()).collect();
        let track = test["track"].as_str().unwrap();
        let expected = test["expected"].as_bool().unwrap();

        let result = scopes.iter().any(|scope| {
            scope.allows_action(&action)
                && scope.matches_full_track_name(&ns_bytes, track.as_bytes())
        });

        assert_eq!(
            result, expected,
            "Suffix match test failed for action={}, ns={:?}, track={}",
            action_id, ns, track
        );
    }
}

#[test]
fn test_vector_moqt_payload_cbor_matches() {
    let vectors = load_vectors();
    let moqt_vectors = &vectors["vectors"]["moqt_scopes"]["vectors"];

    for v in moqt_vectors.as_array().unwrap() {
        let token_str = v["token"].as_str().unwrap();
        let parts: Vec<&str> = token_str.split('.').collect();
        let payload_bytes = URL_SAFE_NO_PAD.decode(parts[1]).unwrap();

        assert_eq!(
            hex::encode(&payload_bytes),
            v["payload_cbor_hex"].as_str().unwrap(),
            "MOQT payload CBOR mismatch for {}",
            v["id"]
        );
    }
}

// =============================================================================
// Category 4: Validation Tests
// =============================================================================

#[test]
fn test_vector_valid_basic() {
    let vectors = load_vectors();
    let val_vectors = &vectors["vectors"]["validation"]["vectors"];
    let v = &val_vectors[0];

    assert_eq!(v["id"], "valid_basic");

    let alg = HmacSha256Algorithm::new(&hmac_key());
    let token_str = v["token"].as_str().unwrap();

    // Token should decode without error
    let decoded = decode_token(token_str, &alg).unwrap();
    assert_eq!(
        decoded.core.iss.as_deref(),
        Some("https://auth.example.com")
    );
}

#[test]
fn test_vector_invalid_tampered_signature() {
    let vectors = load_vectors();
    let val_vectors = &vectors["vectors"]["validation"]["vectors"];
    let v = &val_vectors[5];

    assert_eq!(v["id"], "invalid_tampered_signature");

    let alg = HmacSha256Algorithm::new(&hmac_key());
    let tampered_token = v["token"].as_str().unwrap();

    let result = decode_token(tampered_token, &alg);
    assert!(result.is_err());
    match result.unwrap_err() {
        CatError::SignatureVerificationFailed => {}
        other => panic!("Expected SignatureVerificationFailed, got {:?}", other),
    }
}

#[test]
fn test_vector_invalid_wrong_key() {
    let vectors = load_vectors();
    let val_vectors = &vectors["vectors"]["validation"]["vectors"];
    let v = &val_vectors[6];

    assert_eq!(v["id"], "invalid_wrong_key");

    let wrong_key = hex::decode(v["validation"]["wrong_key_hex"].as_str().unwrap()).unwrap();
    let alg = HmacSha256Algorithm::new(&wrong_key);
    let token_str = v["token"].as_str().unwrap();

    let result = decode_token(token_str, &alg);
    assert!(result.is_err());
    match result.unwrap_err() {
        CatError::SignatureVerificationFailed => {}
        other => panic!("Expected SignatureVerificationFailed, got {:?}", other),
    }
}

#[test]
fn test_vector_invalid_algorithm_mismatch() {
    let vectors = load_vectors();
    let val_vectors = &vectors["vectors"]["validation"]["vectors"];
    let v = &val_vectors[7];

    assert_eq!(v["id"], "invalid_algorithm_mismatch");

    // Token was signed with HMAC but we try to verify with ES256
    let alg = es256_algorithm();
    let token_str = v["token"].as_str().unwrap();

    let result = decode_token(token_str, &alg);
    assert!(result.is_err());
    match result.unwrap_err() {
        CatError::AlgorithmMismatch { expected, found } => {
            assert_eq!(found, ALG_HMAC256_256);
            assert_eq!(expected, ALG_ES256);
        }
        other => panic!("Expected AlgorithmMismatch, got {:?}", other),
    }
}

// =============================================================================
// Category 5: DPoP Binding Tests
// =============================================================================

#[test]
fn test_vector_dpop_jwk_binding() {
    let vectors = load_vectors();
    let dpop_vectors = &vectors["vectors"]["dpop_binding"]["vectors"];
    let v = &dpop_vectors[0];

    assert_eq!(v["id"], "dpop_jwk_binding");

    let alg = HmacSha256Algorithm::new(&hmac_key());
    let token_str = v["token"].as_str().unwrap();
    let decoded = decode_token(token_str, &alg).unwrap();

    // Verify cnf claim
    let cnf = decoded.dpop.cnf.as_ref().unwrap();
    let expected_jkt = hex::decode(v["dpop"]["cnf_jkt_hex"].as_str().unwrap()).unwrap();
    assert_eq!(cnf.jkt, expected_jkt);

    // Verify DPoP settings
    let settings = decoded.dpop.catdpop.as_ref().unwrap();
    assert_eq!(settings.window, Some(60));
    assert_eq!(settings.honor_jti, Some(true));
}

#[test]
fn test_vector_dpop_no_jti() {
    let vectors = load_vectors();
    let dpop_vectors = &vectors["vectors"]["dpop_binding"]["vectors"];
    let v = &dpop_vectors[1];

    assert_eq!(v["id"], "dpop_no_jti");

    let alg = HmacSha256Algorithm::new(&hmac_key());
    let token_str = v["token"].as_str().unwrap();
    let decoded = decode_token(token_str, &alg).unwrap();

    let settings = decoded.dpop.catdpop.as_ref().unwrap();
    assert_eq!(settings.window, Some(300));
    assert_eq!(settings.honor_jti, Some(false));
    assert!(!settings.should_honor_jti());
}

#[test]
fn test_vector_dpop_es256_real_binding() {
    let vectors = load_vectors();
    let dpop_vectors = &vectors["vectors"]["dpop_binding"]["vectors"];
    let v = &dpop_vectors[2];

    assert_eq!(v["id"], "dpop_es256_real_binding");

    let alg = es256_algorithm();
    let token_str = v["token"].as_str().unwrap();
    let decoded = decode_token(token_str, &alg).unwrap();

    // Verify JWK thumbprint matches the expected value
    let cnf = decoded.dpop.cnf.as_ref().unwrap();
    let expected_jkt = hex::decode(v["dpop"]["cnf_jkt_hex"].as_str().unwrap()).unwrap();
    assert_eq!(cnf.jkt, expected_jkt);

    // Verify the JWK thumbprint was correctly derived
    let jwk_input = v["jwk_thumbprint_input"].as_str().unwrap();
    let computed_jkt = crypto::hash_sha256(jwk_input.as_bytes());
    assert_eq!(cnf.jkt, computed_jkt);
}

// =============================================================================
// Cross-cutting: Verify all tokens in vectors are reproducible
// =============================================================================

#[test]
fn test_vector_all_hmac_tokens_reproducible() {
    let vectors = load_vectors();

    // Check token_structure HMAC tokens
    let token_vectors = &vectors["vectors"]["token_structure"]["vectors"];
    for v in token_vectors.as_array().unwrap() {
        if v["algorithm"].as_str() != Some("HMAC-SHA256") {
            continue;
        }

        let alg = HmacSha256Algorithm::new(&hmac_key());
        let token_str = v["token"].as_str().unwrap();

        // Decode and re-encode should produce identical token
        let decoded = decode_token(token_str, &alg).unwrap();
        let re_encoded = encode_token(&decoded, &alg).unwrap();
        assert_eq!(
            re_encoded, token_str,
            "HMAC token {} not reproducible after decode/re-encode",
            v["id"]
        );
    }
}
