// SPDX-FileCopyrightText: Copyright (c) 2022 Quicr
// SPDX-License-Identifier: BSD-2-Clause
//
// Deterministic test vector generator for CAT/MoQT cross-implementation testing.
// Outputs JSON files with hex-encoded CBOR, tokens, and expected validation results.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use cat_token::*;
use p256::ecdsa::SigningKey;
use serde_json::{Value as JsonValue, json};
use std::collections::BTreeMap;
use std::fs;

// Fixed test keys (deterministic, NOT for production use)
const HMAC_KEY_HEX: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
const ES256_PRIVATE_KEY_HEX: &str =
    "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721";

// Fixed timestamps for deterministic output
const FIXED_IAT: i64 = 1700000000; // 2023-11-14T22:13:20Z
const FIXED_EXP: i64 = 1700086400; // 2023-11-15T22:13:20Z (24h later)
const FIXED_NBF: i64 = 1700000000; // same as iat

fn hmac_key() -> Vec<u8> {
    hex::decode(HMAC_KEY_HEX).unwrap()
}

fn es256_signing_key() -> SigningKey {
    let key_bytes = hex::decode(ES256_PRIVATE_KEY_HEX).unwrap();
    SigningKey::from_bytes(key_bytes.as_slice().into()).unwrap()
}

fn es256_algorithm() -> Es256Algorithm {
    let signing_key = es256_signing_key();
    let verifying_key = p256::ecdsa::VerifyingKey::from(&signing_key);
    // We need to construct with both keys for signing
    // Use the internal constructor pattern
    Es256Algorithm::from_key_pair(signing_key, verifying_key)
}

fn main() {
    let output_dir = std::path::Path::new("tests/test_data");
    fs::create_dir_all(output_dir).unwrap();

    let mut all_vectors: BTreeMap<String, JsonValue> = BTreeMap::new();

    // Category 1: CBOR Encoding vectors
    all_vectors.insert(
        "cbor_encoding".to_string(),
        generate_cbor_encoding_vectors(),
    );

    // Category 2: Full token structure vectors
    all_vectors.insert(
        "token_structure".to_string(),
        generate_token_structure_vectors(),
    );

    // Category 3: MOQT scope encoding vectors
    all_vectors.insert("moqt_scopes".to_string(), generate_moqt_scope_vectors());

    // Category 4: Validation vectors (pass/fail)
    all_vectors.insert("validation".to_string(), generate_validation_vectors());

    // Category 5: DPoP binding vectors
    all_vectors.insert("dpop_binding".to_string(), generate_dpop_vectors());

    // Write combined file
    let combined = json!({
        "description": "CAT/MoQT test vectors for cross-implementation validation",
        "specification": "CTA-5007-B / draft-ietf-moq-c4m",
        "generator": "cat-token (Rust)",
        "generated_at": "2023-11-14T22:13:20Z",
        "keys": {
            "hmac_sha256": HMAC_KEY_HEX,
            "es256_private_key": ES256_PRIVATE_KEY_HEX,
            "es256_public_key_x": hex::encode(es256_signing_key().verifying_key().to_encoded_point(false).x().unwrap()),
            "es256_public_key_y": hex::encode(es256_signing_key().verifying_key().to_encoded_point(false).y().unwrap()),
        },
        "vectors": all_vectors,
    });

    let json_str = serde_json::to_string_pretty(&combined).unwrap();
    fs::write(output_dir.join("cat_test_vectors.json"), &json_str).unwrap();

    // Also write individual category files for easier consumption
    for (name, vectors) in &all_vectors {
        let category_json = serde_json::to_string_pretty(vectors).unwrap();
        fs::write(output_dir.join(format!("{}.json", name)), &category_json).unwrap();
    }

    println!("Generated test vectors in tests/test_data/");
    println!("  - cat_test_vectors.json (combined)");
    for name in all_vectors.keys() {
        println!("  - {}.json", name);
    }
}

/// Category 1: CBOR encoding of individual claims
/// Verifies that each claim type serializes to the expected CBOR bytes.
fn generate_cbor_encoding_vectors() -> JsonValue {
    let mut vectors = Vec::new();

    // 1.1: Minimal token (issuer only)
    {
        let token = CatToken::new().with_issuer("https://auth.example.com");
        let cwt = Cwt::new(ALG_HMAC256_256, token);
        let payload_cbor = cwt.encode_payload().unwrap();
        vectors.push(json!({
            "id": "cbor_issuer_only",
            "description": "Minimal token with only issuer claim",
            "claims": {"iss": "https://auth.example.com"},
            "payload_cbor_hex": hex::encode(&payload_cbor),
        }));
    }

    // 1.2: Core claims (iss, aud, exp, nbf, cti)
    {
        let token = CatToken::new()
            .with_issuer("https://auth.example.com")
            .with_audience(vec!["https://relay.example.com".to_string()])
            .with_cwt_id("test-token-001");
        let mut token = token;
        token.core.exp = Some(FIXED_EXP);
        token.core.nbf = Some(FIXED_NBF);

        let cwt = Cwt::new(ALG_HMAC256_256, token);
        let payload_cbor = cwt.encode_payload().unwrap();
        vectors.push(json!({
            "id": "cbor_core_claims",
            "description": "All core CWT claims (iss, aud, exp, nbf, cti)",
            "claims": {
                "iss": "https://auth.example.com",
                "aud": ["https://relay.example.com"],
                "exp": FIXED_EXP,
                "nbf": FIXED_NBF,
                "cti": "test-token-001"
            },
            "payload_cbor_hex": hex::encode(&payload_cbor),
        }));
    }

    // 1.3: CAT version and usage limit
    {
        let token = CatToken::new().with_version("CAT-v1").with_usage_limit(5);
        let cwt = Cwt::new(ALG_HMAC256_256, token);
        let payload_cbor = cwt.encode_payload().unwrap();
        vectors.push(json!({
            "id": "cbor_cat_version_usage",
            "description": "CAT version string and usage limit",
            "claims": {"catv": "CAT-v1", "catu": 5},
            "payload_cbor_hex": hex::encode(&payload_cbor),
        }));
    }

    // 1.4: Network identifiers
    {
        let token = CatToken::new()
            .with_ip_address("192.168.1.100")
            .with_ip_range("10.0.0.0/8")
            .with_asn(64512)
            .with_asn_range(64512, 64768);
        let cwt = Cwt::new(ALG_HMAC256_256, token);
        let payload_cbor = cwt.encode_payload().unwrap();
        vectors.push(json!({
            "id": "cbor_network_identifiers",
            "description": "Network identifiers: IP, CIDR, ASN, ASN range",
            "claims": {
                "catnip": [
                    {"type": "ip_address", "value": "192.168.1.100"},
                    {"type": "ip_range", "value": "10.0.0.0/8"},
                    {"type": "asn", "value": 64512},
                    {"type": "asn_range", "value": [64512, 64768]}
                ]
            },
            "payload_cbor_hex": hex::encode(&payload_cbor),
        }));
    }

    // 1.5: Geographic claims
    {
        let token = CatToken::new()
            .with_geo_coordinate(37.7749, -122.4194, Some(100.0))
            .with_geohash("9q8yyk");
        let mut token = token;
        token.cat.catgeoiso3166 = Some(vec!["US".to_string(), "CA".to_string()]);
        token.cat.catgeoalt = Some(10);

        let cwt = Cwt::new(ALG_HMAC256_256, token);
        let payload_cbor = cwt.encode_payload().unwrap();
        vectors.push(json!({
            "id": "cbor_geographic_claims",
            "description": "Geographic claims: coordinates, geohash, ISO 3166, altitude",
            "claims": {
                "catgeocoord": {"lat": 37.7749, "lon": -122.4194, "accuracy": 100.0},
                "geohash": "9q8yyk",
                "catgeoiso3166": ["US", "CA"],
                "catgeoalt": 10
            },
            "payload_cbor_hex": hex::encode(&payload_cbor),
        }));
    }

    // 1.6: URI patterns
    {
        let token = CatToken::new().with_uri_patterns(vec![
            UriPattern::Exact("https://example.com/live/stream1".to_string()),
            UriPattern::Prefix("https://example.com/vod/".to_string()),
            UriPattern::Suffix(".m3u8".to_string()),
        ]);
        let cwt = Cwt::new(ALG_HMAC256_256, token);
        let payload_cbor = cwt.encode_payload().unwrap();
        vectors.push(json!({
            "id": "cbor_uri_patterns",
            "description": "URI patterns: exact, prefix, suffix",
            "claims": {
                "cath": [
                    {"type": "exact", "value": "https://example.com/live/stream1"},
                    {"type": "prefix", "value": "https://example.com/vod/"},
                    {"type": "suffix", "value": ".m3u8"}
                ]
            },
            "payload_cbor_hex": hex::encode(&payload_cbor),
        }));
    }

    // 1.7: ALPN protocols
    {
        let mut token = CatToken::new();
        token.cat.catalpn = Some(vec!["moq-00".to_string(), "h3".to_string()]);
        let cwt = Cwt::new(ALG_HMAC256_256, token);
        let payload_cbor = cwt.encode_payload().unwrap();
        vectors.push(json!({
            "id": "cbor_alpn",
            "description": "ALPN protocol identifiers",
            "claims": {"catalpn": ["moq-00", "h3"]},
            "payload_cbor_hex": hex::encode(&payload_cbor),
        }));
    }

    json!({
        "description": "CBOR encoding of individual claim types",
        "vectors": vectors,
    })
}

/// Category 2: Full token encode/decode with signatures
fn generate_token_structure_vectors() -> JsonValue {
    let mut vectors = Vec::new();

    // 2.1: Minimal HMAC token
    {
        let token = CatToken::new()
            .with_issuer("https://auth.example.com")
            .with_audience(vec!["https://relay.example.com".to_string()]);
        let mut token = token;
        token.core.exp = Some(FIXED_EXP);

        let alg = HmacSha256Algorithm::new(&hmac_key());
        let encoded = encode_token(&token, &alg).unwrap();

        let parts: Vec<&str> = encoded.split('.').collect();
        vectors.push(json!({
            "id": "token_hmac_minimal",
            "description": "Minimal token signed with HMAC-SHA256",
            "algorithm": "HMAC-SHA256",
            "algorithm_id": ALG_HMAC256_256,
            "key_hex": HMAC_KEY_HEX,
            "token": encoded,
            "header_b64": parts[0],
            "payload_b64": parts[1],
            "signature_b64": parts[2],
            "header_cbor_hex": hex::encode(URL_SAFE_NO_PAD.decode(parts[0]).unwrap()),
            "payload_cbor_hex": hex::encode(URL_SAFE_NO_PAD.decode(parts[1]).unwrap()),
            "signature_hex": hex::encode(URL_SAFE_NO_PAD.decode(parts[2]).unwrap()),
            "claims": {
                "iss": "https://auth.example.com",
                "aud": ["https://relay.example.com"],
                "exp": FIXED_EXP,
            },
            "valid": true,
        }));
    }

    // 2.2: Full HMAC token with many claims
    {
        let token = CatToken::new()
            .with_issuer("https://issuer.moq.example")
            .with_audience(vec![
                "https://relay1.example.com".to_string(),
                "https://relay2.example.com".to_string(),
            ])
            .with_cwt_id("vector-002")
            .with_version("CAT-v1")
            .with_usage_limit(10)
            .with_subject("user:alice@example.com")
            .with_ip_address("203.0.113.50");
        let mut token = token;
        token.core.exp = Some(FIXED_EXP);
        token.core.nbf = Some(FIXED_NBF);
        token.informational.iat = Some(FIXED_IAT);

        let alg = HmacSha256Algorithm::new(&hmac_key());
        let encoded = encode_token(&token, &alg).unwrap();

        let parts: Vec<&str> = encoded.split('.').collect();
        vectors.push(json!({
            "id": "token_hmac_full",
            "description": "Token with core + CAT + informational claims, HMAC-SHA256",
            "algorithm": "HMAC-SHA256",
            "algorithm_id": ALG_HMAC256_256,
            "key_hex": HMAC_KEY_HEX,
            "token": encoded,
            "header_b64": parts[0],
            "payload_b64": parts[1],
            "signature_b64": parts[2],
            "header_cbor_hex": hex::encode(URL_SAFE_NO_PAD.decode(parts[0]).unwrap()),
            "payload_cbor_hex": hex::encode(URL_SAFE_NO_PAD.decode(parts[1]).unwrap()),
            "signature_hex": hex::encode(URL_SAFE_NO_PAD.decode(parts[2]).unwrap()),
            "claims": {
                "iss": "https://issuer.moq.example",
                "aud": ["https://relay1.example.com", "https://relay2.example.com"],
                "exp": FIXED_EXP,
                "nbf": FIXED_NBF,
                "cti": "vector-002",
                "sub": "user:alice@example.com",
                "iat": FIXED_IAT,
                "catv": "CAT-v1",
                "catu": 10,
                "catnip": [{"type": "ip_address", "value": "203.0.113.50"}],
            },
            "valid": true,
        }));
    }

    // 2.3: ES256 token (deterministic via RFC 6979)
    {
        let token = CatToken::new()
            .with_issuer("https://auth.example.com")
            .with_audience(vec!["https://moq-relay.example.com".to_string()]);
        let mut token = token;
        token.core.exp = Some(FIXED_EXP);
        token.core.nbf = Some(FIXED_NBF);

        let alg = es256_algorithm();
        let encoded = encode_token(&token, &alg).unwrap();

        let parts: Vec<&str> = encoded.split('.').collect();
        let vk = *es256_signing_key().verifying_key();
        let point = vk.to_encoded_point(false);

        vectors.push(json!({
            "id": "token_es256",
            "description": "Token signed with ES256 (P-256 ECDSA, deterministic RFC 6979)",
            "algorithm": "ES256",
            "algorithm_id": ALG_ES256,
            "private_key_hex": ES256_PRIVATE_KEY_HEX,
            "public_key_x_hex": hex::encode(point.x().unwrap()),
            "public_key_y_hex": hex::encode(point.y().unwrap()),
            "token": encoded,
            "header_b64": parts[0],
            "payload_b64": parts[1],
            "signature_b64": parts[2],
            "header_cbor_hex": hex::encode(URL_SAFE_NO_PAD.decode(parts[0]).unwrap()),
            "payload_cbor_hex": hex::encode(URL_SAFE_NO_PAD.decode(parts[1]).unwrap()),
            "signature_hex": hex::encode(URL_SAFE_NO_PAD.decode(parts[2]).unwrap()),
            "claims": {
                "iss": "https://auth.example.com",
                "aud": ["https://moq-relay.example.com"],
                "exp": FIXED_EXP,
                "nbf": FIXED_NBF,
            },
            "valid": true,
        }));
    }

    json!({
        "description": "Full token structure (header.payload.signature) with cryptographic verification",
        "vectors": vectors,
    })
}

/// Category 3: MOQT scope encoding
fn generate_moqt_scope_vectors() -> JsonValue {
    let mut vectors = Vec::new();

    // 3.1: Publisher scope with exact namespace
    {
        let scope = MoqtScope::new()
            .with_actions(vec![MoqtAction::PublishNamespace, MoqtAction::Publish])
            .with_namespace_match(NamespaceMatch::exact(b"example.com".to_vec()))
            .with_namespace_match(NamespaceMatch::exact(b"alice".to_vec()))
            .with_track_match(BinaryMatch::prefix_str("video-"));

        let token = CatToken::new()
            .with_issuer("https://auth.example.com")
            .with_moqt_scope(scope);
        let mut token = token;
        token.core.exp = Some(FIXED_EXP);

        let alg = HmacSha256Algorithm::new(&hmac_key());
        let encoded = encode_token(&token, &alg).unwrap();
        let parts: Vec<&str> = encoded.split('.').collect();

        vectors.push(json!({
            "id": "moqt_publisher_exact",
            "description": "Publisher scope: exact namespace match, prefix track match",
            "token": encoded,
            "payload_cbor_hex": hex::encode(URL_SAFE_NO_PAD.decode(parts[1]).unwrap()),
            "moqt_scopes": [{
                "actions": [2, 6],
                "action_names": ["PublishNamespace", "Publish"],
                "namespace_matches": [
                    {"type": "exact", "pattern_hex": hex::encode(b"example.com"), "pattern_utf8": "example.com"},
                    {"type": "exact", "pattern_hex": hex::encode(b"alice"), "pattern_utf8": "alice"},
                ],
                "track_match": {"type": "prefix", "pattern_hex": hex::encode(b"video-"), "pattern_utf8": "video-"},
            }],
            "authorization_tests": [
                {"action": 2, "namespace": ["example.com", "alice"], "track": "video-hd", "expected": true},
                {"action": 6, "namespace": ["example.com", "alice"], "track": "video-sd", "expected": true},
                {"action": 6, "namespace": ["example.com", "alice"], "track": "audio-main", "expected": false},
                {"action": 4, "namespace": ["example.com", "alice"], "track": "video-hd", "expected": false},
                {"action": 6, "namespace": ["example.com", "bob"], "track": "video-hd", "expected": false},
            ],
        }));
    }

    // 3.2: Subscriber scope with prefix namespace
    {
        let scope = MoqtScope::new()
            .with_actions(vec![
                MoqtAction::SubscribeNamespace,
                MoqtAction::Subscribe,
                MoqtAction::Fetch,
            ])
            .with_namespace_match(NamespaceMatch::prefix(b"conference.example".to_vec()));

        let token = CatToken::new()
            .with_issuer("https://auth.example.com")
            .with_moqt_scope(scope);
        let mut token = token;
        token.core.exp = Some(FIXED_EXP);

        let alg = HmacSha256Algorithm::new(&hmac_key());
        let encoded = encode_token(&token, &alg).unwrap();
        let parts: Vec<&str> = encoded.split('.').collect();

        vectors.push(json!({
            "id": "moqt_subscriber_prefix",
            "description": "Subscriber scope: prefix namespace match, any track",
            "token": encoded,
            "payload_cbor_hex": hex::encode(URL_SAFE_NO_PAD.decode(parts[1]).unwrap()),
            "moqt_scopes": [{
                "actions": [3, 4, 7],
                "action_names": ["SubscribeNamespace", "Subscribe", "Fetch"],
                "namespace_matches": [
                    {"type": "prefix", "pattern_hex": hex::encode(b"conference.example"), "pattern_utf8": "conference.example"},
                ],
                "track_match": null,
            }],
            "authorization_tests": [
                {"action": 4, "namespace": ["conference.example.room1"], "track": "audio", "expected": true},
                {"action": 7, "namespace": ["conference.example.room2"], "track": "video", "expected": true},
                {"action": 4, "namespace": ["other.domain"], "track": "audio", "expected": false},
                {"action": 6, "namespace": ["conference.example.room1"], "track": "audio", "expected": false},
            ],
        }));
    }

    // 3.3: Multi-scope token (publisher + subscriber)
    {
        let pub_scope = MoqtScope::new()
            .with_actions(vec![MoqtAction::PublishNamespace, MoqtAction::Publish])
            .with_namespace_match(NamespaceMatch::exact(b"live.example".to_vec()))
            .with_namespace_match(NamespaceMatch::exact(b"studio-a".to_vec()));

        let sub_scope = MoqtScope::new()
            .with_actions(vec![MoqtAction::Subscribe, MoqtAction::Fetch])
            .with_namespace_match(NamespaceMatch::prefix(b"live.example".to_vec()));

        let token = CatToken::new()
            .with_issuer("https://auth.example.com")
            .with_moqt_scopes(vec![pub_scope, sub_scope])
            .with_moqt_reval(300.0);
        let mut token = token;
        token.core.exp = Some(FIXED_EXP);

        let alg = HmacSha256Algorithm::new(&hmac_key());
        let encoded = encode_token(&token, &alg).unwrap();
        let parts: Vec<&str> = encoded.split('.').collect();

        vectors.push(json!({
            "id": "moqt_multi_scope",
            "description": "Multi-scope token: publish to specific namespace, subscribe to prefix, with revalidation",
            "token": encoded,
            "payload_cbor_hex": hex::encode(URL_SAFE_NO_PAD.decode(parts[1]).unwrap()),
            "moqt_reval": 300.0,
            "moqt_scopes": [
                {
                    "actions": [2, 6],
                    "action_names": ["PublishNamespace", "Publish"],
                    "namespace_matches": [
                        {"type": "exact", "pattern_hex": hex::encode(b"live.example"), "pattern_utf8": "live.example"},
                        {"type": "exact", "pattern_hex": hex::encode(b"studio-a"), "pattern_utf8": "studio-a"},
                    ],
                    "track_match": null,
                },
                {
                    "actions": [4, 7],
                    "action_names": ["Subscribe", "Fetch"],
                    "namespace_matches": [
                        {"type": "prefix", "pattern_hex": hex::encode(b"live.example"), "pattern_utf8": "live.example"},
                    ],
                    "track_match": null,
                }
            ],
            "authorization_tests": [
                {"action": 6, "namespace": ["live.example", "studio-a"], "track": "cam1", "expected": true},
                {"action": 4, "namespace": ["live.example.studio-b"], "track": "cam1", "expected": true},
                {"action": 6, "namespace": ["live.example", "studio-b"], "track": "cam1", "expected": false},
                {"action": 2, "namespace": ["other.example", "studio-a"], "track": "", "expected": false},
            ],
        }));
    }

    // 3.4: Admin scope (all actions, wildcard namespace)
    {
        let scope = MoqtScope::new().with_actions(vec![
            MoqtAction::ClientSetup,
            MoqtAction::ServerSetup,
            MoqtAction::PublishNamespace,
            MoqtAction::SubscribeNamespace,
            MoqtAction::Subscribe,
            MoqtAction::RequestUpdate,
            MoqtAction::Publish,
            MoqtAction::Fetch,
            MoqtAction::TrackStatus,
        ]);

        let token = CatToken::new()
            .with_issuer("https://auth.example.com")
            .with_moqt_scope(scope);
        let mut token = token;
        token.core.exp = Some(FIXED_EXP);

        let alg = HmacSha256Algorithm::new(&hmac_key());
        let encoded = encode_token(&token, &alg).unwrap();
        let parts: Vec<&str> = encoded.split('.').collect();

        vectors.push(json!({
            "id": "moqt_admin_wildcard",
            "description": "Admin scope: all actions, no namespace/track restriction",
            "token": encoded,
            "payload_cbor_hex": hex::encode(URL_SAFE_NO_PAD.decode(parts[1]).unwrap()),
            "moqt_scopes": [{
                "actions": [0, 1, 2, 3, 4, 5, 6, 7, 8],
                "action_names": ["ClientSetup", "ServerSetup", "PublishNamespace", "SubscribeNamespace", "Subscribe", "RequestUpdate", "Publish", "Fetch", "TrackStatus"],
                "namespace_matches": [],
                "track_match": null,
            }],
            "authorization_tests": [
                {"action": 0, "namespace": ["any.namespace"], "track": "any-track", "expected": true},
                {"action": 6, "namespace": ["any.namespace"], "track": "any-track", "expected": true},
                {"action": 8, "namespace": ["any.namespace"], "track": "status", "expected": true},
            ],
        }));
    }

    // 3.5: Suffix namespace match
    {
        let scope = MoqtScope::new()
            .with_actions(vec![MoqtAction::Subscribe])
            .with_namespace_match(NamespaceMatch::suffix(b".example.com".to_vec()))
            .with_track_match(BinaryMatch::suffix_str("-audio"));

        let token = CatToken::new()
            .with_issuer("https://auth.example.com")
            .with_moqt_scope(scope);
        let mut token = token;
        token.core.exp = Some(FIXED_EXP);

        let alg = HmacSha256Algorithm::new(&hmac_key());
        let encoded = encode_token(&token, &alg).unwrap();
        let parts: Vec<&str> = encoded.split('.').collect();

        vectors.push(json!({
            "id": "moqt_suffix_match",
            "description": "Suffix matching on both namespace and track",
            "token": encoded,
            "payload_cbor_hex": hex::encode(URL_SAFE_NO_PAD.decode(parts[1]).unwrap()),
            "moqt_scopes": [{
                "actions": [4],
                "action_names": ["Subscribe"],
                "namespace_matches": [
                    {"type": "suffix", "pattern_hex": hex::encode(b".example.com"), "pattern_utf8": ".example.com"},
                ],
                "track_match": {"type": "suffix", "pattern_hex": hex::encode(b"-audio"), "pattern_utf8": "-audio"},
            }],
            "authorization_tests": [
                {"action": 4, "namespace": ["cdn.example.com"], "track": "stream1-audio", "expected": true},
                {"action": 4, "namespace": ["cdn.example.com"], "track": "stream1-video", "expected": false},
                {"action": 4, "namespace": ["cdn.other.org"], "track": "stream1-audio", "expected": false},
            ],
        }));
    }

    json!({
        "description": "MOQT authorization scope encoding and matching",
        "vectors": vectors,
    })
}

/// Category 4: Validation vectors (tokens that should pass or fail validation)
fn generate_validation_vectors() -> JsonValue {
    let mut vectors = Vec::new();
    let alg = HmacSha256Algorithm::new(&hmac_key());

    // 4.1: Valid token (passes all checks)
    {
        let token = CatToken::new()
            .with_issuer("https://auth.example.com")
            .with_audience(vec!["https://relay.example.com".to_string()]);
        let mut token = token;
        token.core.exp = Some(FIXED_EXP);
        token.core.nbf = Some(FIXED_NBF);

        let encoded = encode_token(&token, &alg).unwrap();
        vectors.push(json!({
            "id": "valid_basic",
            "description": "Valid token with correct issuer, audience, and time bounds",
            "token": encoded,
            "validation": {
                "expected_issuers": ["https://auth.example.com"],
                "expected_audiences": ["https://relay.example.com"],
                "reference_time": FIXED_IAT + 3600,
                "expected_result": "valid",
            },
        }));
    }

    // 4.2: Expired token
    {
        let token = CatToken::new().with_issuer("https://auth.example.com");
        let mut token = token;
        token.core.exp = Some(1600000000); // well in the past

        let encoded = encode_token(&token, &alg).unwrap();
        vectors.push(json!({
            "id": "invalid_expired",
            "description": "Token with expiration in the past",
            "token": encoded,
            "validation": {
                "reference_time": FIXED_IAT,
                "expected_result": "error",
                "expected_error": "TokenExpired",
            },
        }));
    }

    // 4.3: Not-yet-valid token
    {
        let token = CatToken::new().with_issuer("https://auth.example.com");
        let mut token = token;
        token.core.exp = Some(FIXED_EXP + 86400);
        token.core.nbf = Some(FIXED_EXP); // nbf is in the future relative to reference_time

        let encoded = encode_token(&token, &alg).unwrap();
        vectors.push(json!({
            "id": "invalid_not_yet_valid",
            "description": "Token with not-before in the future",
            "token": encoded,
            "validation": {
                "reference_time": FIXED_IAT,
                "expected_result": "error",
                "expected_error": "TokenNotYetValid",
            },
        }));
    }

    // 4.4: Wrong issuer
    {
        let token = CatToken::new()
            .with_issuer("https://evil.example.com")
            .with_audience(vec!["https://relay.example.com".to_string()]);
        let mut token = token;
        token.core.exp = Some(FIXED_EXP);

        let encoded = encode_token(&token, &alg).unwrap();
        vectors.push(json!({
            "id": "invalid_wrong_issuer",
            "description": "Token from untrusted issuer",
            "token": encoded,
            "validation": {
                "expected_issuers": ["https://auth.example.com"],
                "reference_time": FIXED_IAT + 3600,
                "expected_result": "error",
                "expected_error": "InvalidIssuer",
            },
        }));
    }

    // 4.5: Wrong audience
    {
        let token = CatToken::new()
            .with_issuer("https://auth.example.com")
            .with_audience(vec!["https://other-relay.example.com".to_string()]);
        let mut token = token;
        token.core.exp = Some(FIXED_EXP);

        let encoded = encode_token(&token, &alg).unwrap();
        vectors.push(json!({
            "id": "invalid_wrong_audience",
            "description": "Token not intended for this audience",
            "token": encoded,
            "validation": {
                "expected_issuers": ["https://auth.example.com"],
                "expected_audiences": ["https://relay.example.com"],
                "reference_time": FIXED_IAT + 3600,
                "expected_result": "error",
                "expected_error": "InvalidAudience",
            },
        }));
    }

    // 4.6: Tampered signature
    {
        let token = CatToken::new()
            .with_issuer("https://auth.example.com")
            .with_audience(vec!["https://relay.example.com".to_string()]);
        let mut token = token;
        token.core.exp = Some(FIXED_EXP);

        let encoded = encode_token(&token, &alg).unwrap();
        // Tamper with the signature by flipping a byte
        let parts: Vec<&str> = encoded.split('.').collect();
        let mut sig_bytes = URL_SAFE_NO_PAD.decode(parts[2]).unwrap();
        sig_bytes[0] ^= 0xff;
        let tampered_sig = URL_SAFE_NO_PAD.encode(&sig_bytes);
        let tampered_token = format!("{}.{}.{}", parts[0], parts[1], tampered_sig);

        vectors.push(json!({
            "id": "invalid_tampered_signature",
            "description": "Token with corrupted signature (first byte flipped)",
            "token": tampered_token,
            "original_token": encoded,
            "validation": {
                "key_hex": HMAC_KEY_HEX,
                "expected_result": "error",
                "expected_error": "SignatureVerificationFailed",
            },
        }));
    }

    // 4.7: Wrong key
    {
        let token = CatToken::new().with_issuer("https://auth.example.com");
        let mut token = token;
        token.core.exp = Some(FIXED_EXP);

        let encoded = encode_token(&token, &alg).unwrap();
        let wrong_key_hex = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";

        vectors.push(json!({
            "id": "invalid_wrong_key",
            "description": "Token verified with incorrect key",
            "token": encoded,
            "validation": {
                "correct_key_hex": HMAC_KEY_HEX,
                "wrong_key_hex": wrong_key_hex,
                "expected_result": "error",
                "expected_error": "SignatureVerificationFailed",
            },
        }));
    }

    // 4.8: Algorithm mismatch
    {
        let token = CatToken::new().with_issuer("https://auth.example.com");
        let mut token = token;
        token.core.exp = Some(FIXED_EXP);

        let encoded = encode_token(&token, &alg).unwrap();
        vectors.push(json!({
            "id": "invalid_algorithm_mismatch",
            "description": "Token header says HMAC-SHA256 but verifier expects ES256",
            "token": encoded,
            "validation": {
                "token_algorithm_id": ALG_HMAC256_256,
                "verifier_algorithm_id": ALG_ES256,
                "expected_result": "error",
                "expected_error": "AlgorithmMismatch",
            },
        }));
    }

    json!({
        "description": "Token validation test cases (expected pass and fail scenarios)",
        "vectors": vectors,
    })
}

/// Category 5: DPoP binding vectors
fn generate_dpop_vectors() -> JsonValue {
    let mut vectors = Vec::new();

    // 5.1: Token with JWK thumbprint binding
    {
        let jkt_bytes = hex::decode(
            "a]b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1".replace(']', "0"),
        )
        .unwrap();

        let token = CatToken::new()
            .with_issuer("https://auth.example.com")
            .with_confirmation(jkt_bytes.clone())
            .with_dpop_settings(
                CatDpopSettings::new()
                    .with_window(60)
                    .with_jti_processing(true),
            );
        let mut token = token;
        token.core.exp = Some(FIXED_EXP);

        let alg = HmacSha256Algorithm::new(&hmac_key());
        let encoded = encode_token(&token, &alg).unwrap();
        let parts: Vec<&str> = encoded.split('.').collect();

        vectors.push(json!({
            "id": "dpop_jwk_binding",
            "description": "Token with DPoP key binding (JWK thumbprint in cnf claim)",
            "token": encoded,
            "payload_cbor_hex": hex::encode(URL_SAFE_NO_PAD.decode(parts[1]).unwrap()),
            "dpop": {
                "cnf_jkt_hex": hex::encode(&jkt_bytes),
                "window_seconds": 60,
                "honor_jti": true,
            },
        }));
    }

    // 5.2: Token with DPoP window only (no JTI)
    {
        let jkt_bytes = crypto::hash_sha256(b"test-public-key-material");

        let token = CatToken::new()
            .with_issuer("https://auth.example.com")
            .with_confirmation(jkt_bytes.clone())
            .with_dpop_settings(
                CatDpopSettings::new()
                    .with_window(300)
                    .with_jti_processing(false),
            );
        let mut token = token;
        token.core.exp = Some(FIXED_EXP);

        let alg = HmacSha256Algorithm::new(&hmac_key());
        let encoded = encode_token(&token, &alg).unwrap();
        let parts: Vec<&str> = encoded.split('.').collect();

        vectors.push(json!({
            "id": "dpop_no_jti",
            "description": "DPoP binding with longer window, JTI processing disabled",
            "token": encoded,
            "payload_cbor_hex": hex::encode(URL_SAFE_NO_PAD.decode(parts[1]).unwrap()),
            "dpop": {
                "cnf_jkt_hex": hex::encode(&jkt_bytes),
                "cnf_jkt_source": "SHA-256 of 'test-public-key-material'",
                "window_seconds": 300,
                "honor_jti": false,
            },
        }));
    }

    // 5.3: ES256 token with DPoP (real key binding)
    {
        let sk = es256_signing_key();
        let vk = sk.verifying_key();
        let point = vk.to_encoded_point(false);

        // Compute JWK thumbprint per RFC 7638
        let jwk_json = format!(
            r#"{{"crv":"P-256","kty":"EC","x":"{}","y":"{}"}}"#,
            URL_SAFE_NO_PAD.encode(point.x().unwrap()),
            URL_SAFE_NO_PAD.encode(point.y().unwrap()),
        );
        let jkt = crypto::hash_sha256(jwk_json.as_bytes());

        let token = CatToken::new()
            .with_issuer("https://auth.example.com")
            .with_audience(vec!["https://relay.example.com".to_string()])
            .with_confirmation(jkt.clone())
            .with_dpop_settings(CatDpopSettings::new().with_window(120));
        let mut token = token;
        token.core.exp = Some(FIXED_EXP);

        let alg = es256_algorithm();
        let encoded = encode_token(&token, &alg).unwrap();
        let parts: Vec<&str> = encoded.split('.').collect();

        vectors.push(json!({
            "id": "dpop_es256_real_binding",
            "description": "ES256 token with real JWK thumbprint binding to the signing key",
            "token": encoded,
            "payload_cbor_hex": hex::encode(URL_SAFE_NO_PAD.decode(parts[1]).unwrap()),
            "algorithm": "ES256",
            "public_key_x_hex": hex::encode(point.x().unwrap()),
            "public_key_y_hex": hex::encode(point.y().unwrap()),
            "jwk_thumbprint_input": jwk_json,
            "dpop": {
                "cnf_jkt_hex": hex::encode(&jkt),
                "window_seconds": 120,
                "honor_jti": null,
            },
        }));
    }

    json!({
        "description": "DPoP (Demonstrating Proof-of-Possession) binding vectors",
        "vectors": vectors,
    })
}
