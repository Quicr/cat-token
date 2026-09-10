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
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};

const DEFAULT_DRAFT_URL: &str =
    "https://raw.githubusercontent.com/moq-wg/CAT-4-MOQT/main/draft-ietf-moq-c4m.md";
const HEX_FIELDS: &[&str] = &[
    "cose_hex",
    "payload_cbor_hex",
    "header_cbor_hex",
    "tag_hex",
    "signature_hex",
    "cnf_jkt_hex",
    "key_hex",
    "public_key_x_hex",
    "public_key_y_hex",
    "private_key_hex",
];

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

struct CoseComponents {
    protected_header: Vec<u8>,
    payload: Vec<u8>,
    signature: Vec<u8>,
}

fn extract_cose_components(cose_bytes: &[u8]) -> CoseComponents {
    let value: ciborium::Value = ciborium::de::from_reader(cose_bytes).unwrap();
    let arr = match value {
        ciborium::Value::Tag(_, inner) => match *inner {
            ciborium::Value::Array(a) => a,
            _ => panic!("expected COSE array"),
        },
        _ => panic!("expected COSE tag"),
    };
    CoseComponents {
        protected_header: match &arr[0] {
            ciborium::Value::Bytes(b) => b.clone(),
            _ => panic!("expected bytes"),
        },
        payload: match &arr[2] {
            ciborium::Value::Bytes(b) => b.clone(),
            _ => panic!("expected bytes"),
        },
        signature: match &arr[3] {
            ciborium::Value::Bytes(b) => b.clone(),
            _ => panic!("expected bytes"),
        },
    }
}

fn tamper_cose_signature(cose_bytes: &[u8]) -> Vec<u8> {
    let value: ciborium::Value = ciborium::de::from_reader(cose_bytes).unwrap();
    let (tag, arr) = match value {
        ciborium::Value::Tag(tag, inner) => match *inner {
            ciborium::Value::Array(a) => (tag, a),
            _ => panic!("expected COSE array"),
        },
        _ => panic!("expected COSE tag"),
    };
    let mut parts: Vec<ciborium::Value> = arr;
    if let ciborium::Value::Bytes(ref mut sig) = parts[3] {
        sig[0] ^= 0xff;
    }
    let tampered = ciborium::Value::Tag(tag, Box::new(ciborium::Value::Array(parts)));
    let mut buf = Vec::new();
    ciborium::ser::into_writer(&tampered, &mut buf).unwrap();
    buf
}

fn build_all_vectors() -> BTreeMap<String, JsonValue> {
    let mut all_vectors: BTreeMap<String, JsonValue> = BTreeMap::new();
    all_vectors.insert(
        "cbor_encoding".to_string(),
        generate_cbor_encoding_vectors(),
    );
    all_vectors.insert(
        "token_structure".to_string(),
        generate_token_structure_vectors(),
    );
    all_vectors.insert("moqt_scopes".to_string(), generate_moqt_scope_vectors());
    all_vectors.insert("validation".to_string(), generate_validation_vectors());
    all_vectors.insert("dpop_binding".to_string(), generate_dpop_vectors());
    all_vectors.insert(
        "composite_claims".to_string(),
        generate_composite_claim_vectors(),
    );
    all_vectors
}

fn build_combined(all_vectors: &BTreeMap<String, JsonValue>) -> JsonValue {
    json!({
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
    })
}

fn print_usage(prog: &str) {
    eprintln!(
        "usage:\n  \
         {prog}                      # write tests/test_data/*.json (default)\n  \
         {prog} --emit json          # same as default\n  \
         {prog} --emit draft-md [--out FILE]\n  \
         {prog} --verify [--from URL | --from-file PATH]\n\n\
         Emits the Appendix-A vector blocks in a form the CAT-4-MOQT draft\n\
         can consume verbatim, or verifies that the draft's embedded vectors\n\
         match what cat.rs currently produces."
    );
}

fn main() {
    let argv: Vec<String> = std::env::args().collect();
    let prog = argv
        .first()
        .map(String::as_str)
        .unwrap_or("generate-test-vectors");

    let mut mode: &str = "json";
    let mut out: Option<PathBuf> = None;
    let mut source: Option<String> = None;
    let mut source_is_file = false;

    let mut i = 1;
    while i < argv.len() {
        match argv[i].as_str() {
            "--emit" => {
                i += 1;
                let v = argv.get(i).cloned().unwrap_or_default();
                match v.as_str() {
                    "json" | "draft-md" => mode = Box::leak(v.into_boxed_str()),
                    _ => {
                        eprintln!("--emit: expected 'json' or 'draft-md', got {v:?}");
                        print_usage(prog);
                        std::process::exit(2);
                    }
                }
            }
            "--verify" => mode = "verify",
            "--out" => {
                i += 1;
                out = Some(PathBuf::from(argv.get(i).cloned().unwrap_or_default()));
            }
            "--from" => {
                i += 1;
                source = Some(argv.get(i).cloned().unwrap_or_default());
                source_is_file = false;
            }
            "--from-file" => {
                i += 1;
                source = Some(argv.get(i).cloned().unwrap_or_default());
                source_is_file = true;
            }
            "-h" | "--help" => {
                print_usage(prog);
                return;
            }
            other => {
                eprintln!("unknown argument: {other}");
                print_usage(prog);
                std::process::exit(2);
            }
        }
        i += 1;
    }

    let all_vectors = build_all_vectors();
    let combined = build_combined(&all_vectors);

    match mode {
        "json" => run_emit_json(&all_vectors, &combined),
        "draft-md" => {
            let path = out.unwrap_or_else(|| PathBuf::from("tests/test_data/draft_appendix_a.md"));
            run_emit_draft_md(&combined, &path);
        }
        "verify" => {
            let src = source.unwrap_or_else(|| DEFAULT_DRAFT_URL.to_string());
            let code = run_verify(&combined, &src, source_is_file);
            std::process::exit(code);
        }
        _ => unreachable!(),
    }
}

fn run_emit_json(all_vectors: &BTreeMap<String, JsonValue>, combined: &JsonValue) {
    let output_dir = Path::new("tests/test_data");
    fs::create_dir_all(output_dir).unwrap();

    let json_str = serde_json::to_string_pretty(combined).unwrap();
    fs::write(output_dir.join("cat_test_vectors.json"), &json_str).unwrap();

    for (name, vectors) in all_vectors {
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
            .with_cwt_id_str("test-token-001");
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
        let token =
            CatToken::new()
                .with_version(1)
                .with_uri_match_rules(vec![cat_token::UriMatchRule {
                    component: cat_token::URI_COMPONENT_HOST,
                    matches: vec![cat_token::MatchValue::Exact("example.com".to_string())],
                }]);
        let cwt = Cwt::new(ALG_HMAC256_256, token);
        let payload_cbor = cwt.encode_payload().unwrap();
        vectors.push(json!({
            "id": "cbor_cat_version_uri",
            "description": "CAT version (uint 1) and URI match rule",
            "claims": {"catv": 1, "catu": {"host": "example.com"}},
            "payload_cbor_hex": hex::encode(&payload_cbor),
        }));
    }

    // 1.4: Network identifiers
    {
        let token = CatToken::new()
            .with_ip_address("192.168.1.100")
            .unwrap()
            .with_ip_range("10.0.0.0/8")
            .unwrap()
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
            .with_geo_coordinate(37.7749, -122.4194, 100)
            .with_geohash("9q8yyk");
        let mut token = token;
        token.cat.catgeoiso3166 = Some(vec!["US".to_string(), "CA".to_string()]);
        token.cat.catgeoalt = Some(cat_token::GeoAltitude::new(10.0, 5.0));

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

    // 1.6: URI match rules (catu)
    {
        let token = CatToken::new().with_uri_match_rules(vec![
            UriMatchRule {
                component: URI_COMPONENT_HOST,
                matches: vec![MatchValue::Exact("example.com".to_string())],
            },
            UriMatchRule {
                component: URI_COMPONENT_PATH,
                matches: vec![MatchValue::Prefix("/vod/".to_string())],
            },
            UriMatchRule {
                component: URI_COMPONENT_EXTENSION,
                matches: vec![MatchValue::Exact("m3u8".to_string())],
            },
        ]);
        let cwt = Cwt::new(ALG_HMAC256_256, token);
        let payload_cbor = cwt.encode_payload().unwrap();
        vectors.push(json!({
            "id": "cbor_uri_match_rules",
            "description": "URI match rules: host exact, path prefix, extension exact",
            "claims": {
                "catu": [
                    {"component": "host", "match": "exact", "value": "example.com"},
                    {"component": "path", "match": "prefix", "value": "/vod/"},
                    {"component": "extension", "match": "exact", "value": "m3u8"}
                ]
            },
            "payload_cbor_hex": hex::encode(&payload_cbor),
        }));
    }

    // 1.7: ALPN protocols
    {
        let mut token = CatToken::new();
        token.cat.catalpn = Some(vec![b"moq-00".to_vec(), b"h3".to_vec()]);
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
        let c = extract_cose_components(&encoded);

        vectors.push(json!({
            "id": "token_hmac_minimal",
            "description": "Minimal COSE_Mac0 token signed with HMAC-SHA256",
            "algorithm": "HMAC-SHA256",
            "algorithm_id": ALG_HMAC256_256,
            "key_hex": HMAC_KEY_HEX,
            "cose_hex": hex::encode(&encoded),
            "cose_b64": URL_SAFE_NO_PAD.encode(&encoded),
            "header_cbor_hex": hex::encode(&c.protected_header),
            "payload_cbor_hex": hex::encode(&c.payload),
            "tag_hex": hex::encode(&c.signature),
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
            .with_cwt_id_str("vector-002")
            .with_version(1)
            .with_uri_match_rules(vec![UriMatchRule {
                component: URI_COMPONENT_PATH,
                matches: vec![MatchValue::Prefix("/live/".to_string())],
            }])
            .with_subject("user:alice@example.com")
            .with_ip_address("203.0.113.50")
            .unwrap();
        let mut token = token;
        token.core.exp = Some(FIXED_EXP);
        token.core.nbf = Some(FIXED_NBF);
        token.informational.iat = Some(FIXED_IAT);

        let alg = HmacSha256Algorithm::new(&hmac_key());
        let encoded = encode_token(&token, &alg).unwrap();
        let c = extract_cose_components(&encoded);

        vectors.push(json!({
            "id": "token_hmac_full",
            "description": "COSE_Mac0 token with core + CAT + informational claims, HMAC-SHA256",
            "algorithm": "HMAC-SHA256",
            "algorithm_id": ALG_HMAC256_256,
            "key_hex": HMAC_KEY_HEX,
            "cose_hex": hex::encode(&encoded),
            "cose_b64": URL_SAFE_NO_PAD.encode(&encoded),
            "header_cbor_hex": hex::encode(&c.protected_header),
            "payload_cbor_hex": hex::encode(&c.payload),
            "tag_hex": hex::encode(&c.signature),
            "claims": {
                "iss": "https://issuer.moq.example",
                "aud": ["https://relay1.example.com", "https://relay2.example.com"],
                "exp": FIXED_EXP,
                "nbf": FIXED_NBF,
                "cti": "vector-002",
                "sub": "user:alice@example.com",
                "iat": FIXED_IAT,
                "catv": 1,
                "catu": [{"component": "path", "matches": [{"prefix": "/live/"}]}],
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
        let c = extract_cose_components(&encoded);
        let vk = *es256_signing_key().verifying_key();
        let point = vk.to_encoded_point(false);

        vectors.push(json!({
            "id": "token_es256",
            "description": "COSE_Sign1 token signed with ES256 (P-256 ECDSA, deterministic RFC 6979)",
            "algorithm": "ES256",
            "algorithm_id": ALG_ES256,
            "private_key_hex": ES256_PRIVATE_KEY_HEX,
            "public_key_x_hex": hex::encode(point.x().unwrap()),
            "public_key_y_hex": hex::encode(point.y().unwrap()),
            "cose_hex": hex::encode(&encoded),
            "cose_b64": URL_SAFE_NO_PAD.encode(&encoded),
            "header_cbor_hex": hex::encode(&c.protected_header),
            "payload_cbor_hex": hex::encode(&c.payload),
            "signature_hex": hex::encode(&c.signature),
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
        "description": "COSE_Sign1/COSE_Mac0 token structure with cryptographic verification",
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
        let c = extract_cose_components(&encoded);

        vectors.push(json!({
            "id": "moqt_publisher_exact",
            "description": "Publisher scope: exact namespace match, prefix track match",
            "cose_hex": hex::encode(&encoded),
            "cose_b64": URL_SAFE_NO_PAD.encode(&encoded),
            "payload_cbor_hex": hex::encode(&c.payload),
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
        let c = extract_cose_components(&encoded);

        vectors.push(json!({
            "id": "moqt_subscriber_prefix",
            "description": "Subscriber scope: prefix namespace match, any track",
            "cose_hex": hex::encode(&encoded),
            "cose_b64": URL_SAFE_NO_PAD.encode(&encoded),
            "payload_cbor_hex": hex::encode(&c.payload),
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
        let c = extract_cose_components(&encoded);

        vectors.push(json!({
            "id": "moqt_multi_scope",
            "description": "Multi-scope token: publish to specific namespace, subscribe to prefix, with revalidation",
            "cose_hex": hex::encode(&encoded),
            "cose_b64": URL_SAFE_NO_PAD.encode(&encoded),
            "payload_cbor_hex": hex::encode(&c.payload),
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
        let c = extract_cose_components(&encoded);

        vectors.push(json!({
            "id": "moqt_admin_wildcard",
            "description": "Admin scope: all actions, no namespace/track restriction",
            "cose_hex": hex::encode(&encoded),
            "cose_b64": URL_SAFE_NO_PAD.encode(&encoded),
            "payload_cbor_hex": hex::encode(&c.payload),
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
        let c = extract_cose_components(&encoded);

        vectors.push(json!({
            "id": "moqt_suffix_match",
            "description": "Suffix matching on both namespace and track",
            "cose_hex": hex::encode(&encoded),
            "cose_b64": URL_SAFE_NO_PAD.encode(&encoded),
            "payload_cbor_hex": hex::encode(&c.payload),
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
            "cose_hex": hex::encode(&encoded),
            "cose_b64": URL_SAFE_NO_PAD.encode(&encoded),
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
            "cose_hex": hex::encode(&encoded),
            "cose_b64": URL_SAFE_NO_PAD.encode(&encoded),
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
            "cose_hex": hex::encode(&encoded),
            "cose_b64": URL_SAFE_NO_PAD.encode(&encoded),
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
            "cose_hex": hex::encode(&encoded),
            "cose_b64": URL_SAFE_NO_PAD.encode(&encoded),
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
            "cose_hex": hex::encode(&encoded),
            "cose_b64": URL_SAFE_NO_PAD.encode(&encoded),
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
        let tampered = tamper_cose_signature(&encoded);

        vectors.push(json!({
            "id": "invalid_tampered_signature",
            "description": "COSE_Mac0 token with corrupted tag (first byte flipped)",
            "cose_hex": hex::encode(&tampered),
            "cose_b64": URL_SAFE_NO_PAD.encode(&tampered),
            "original_cose_hex": hex::encode(&encoded),
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
            "cose_hex": hex::encode(&encoded),
            "cose_b64": URL_SAFE_NO_PAD.encode(&encoded),
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
            "description": "COSE_Mac0 token but verifier expects COSE_Sign1/ES256",
            "cose_hex": hex::encode(&encoded),
            "cose_b64": URL_SAFE_NO_PAD.encode(&encoded),
            "validation": {
                "token_algorithm_id": ALG_HMAC256_256,
                "verifier_algorithm_id": ALG_ES256,
                "expected_result": "error",
                "expected_error": "InvalidTokenFormat",
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

    // 5.1: Token with JWK thumbprint binding derived from the fixed ES256
    // test key via RFC 7638. Uses HMAC as the outer token MAC so the vector
    // exercises the cnf-jkt path independently of ES256 signing.
    {
        let sk = es256_signing_key();
        let vk = sk.verifying_key();
        let point = vk.to_encoded_point(false);
        let jwk_json = format!(
            r#"{{"crv":"P-256","kty":"EC","x":"{}","y":"{}"}}"#,
            URL_SAFE_NO_PAD.encode(point.x().unwrap()),
            URL_SAFE_NO_PAD.encode(point.y().unwrap()),
        );
        let jkt_bytes = crypto::hash_sha256(jwk_json.as_bytes());

        let token = CatToken::new()
            .with_issuer("https://auth.example.com")
            .with_confirmation(jkt_bytes.clone())
            .with_dpop_settings(
                CatDpopSettings::new()
                    .with_window(60)
                    .unwrap()
                    .with_jti_processing(true),
            );
        let mut token = token;
        token.core.exp = Some(FIXED_EXP);

        let alg = HmacSha256Algorithm::new(&hmac_key());
        let encoded = encode_token(&token, &alg).unwrap();
        let c = extract_cose_components(&encoded);

        vectors.push(json!({
            "id": "dpop_jwk_binding",
            "description": "HMAC token with DPoP cnf-jkt derived from fixed ES256 test key (RFC 7638)",
            "cose_hex": hex::encode(&encoded),
            "cose_b64": URL_SAFE_NO_PAD.encode(&encoded),
            "payload_cbor_hex": hex::encode(&c.payload),
            "dpop": {
                "cnf_jkt_hex": hex::encode(&jkt_bytes),
                "cnf_jkt_source": "SHA-256(RFC 7638 canonical JWK of ES256 test key)",
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
                    .unwrap()
                    .with_jti_processing(false),
            );
        let mut token = token;
        token.core.exp = Some(FIXED_EXP);

        let alg = HmacSha256Algorithm::new(&hmac_key());
        let encoded = encode_token(&token, &alg).unwrap();
        let c = extract_cose_components(&encoded);

        vectors.push(json!({
            "id": "dpop_no_jti",
            "description": "DPoP binding with longer window, JTI processing disabled",
            "cose_hex": hex::encode(&encoded),
            "cose_b64": URL_SAFE_NO_PAD.encode(&encoded),
            "payload_cbor_hex": hex::encode(&c.payload),
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
            .with_dpop_settings(CatDpopSettings::new().with_window(120).unwrap());
        let mut token = token;
        token.core.exp = Some(FIXED_EXP);

        let alg = es256_algorithm();
        let encoded = encode_token(&token, &alg).unwrap();
        let c = extract_cose_components(&encoded);

        vectors.push(json!({
            "id": "dpop_es256_real_binding",
            "description": "ES256 token with real JWK thumbprint binding to the signing key",
            "cose_hex": hex::encode(&encoded),
            "cose_b64": URL_SAFE_NO_PAD.encode(&encoded),
            "payload_cbor_hex": hex::encode(&c.payload),
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

/// Category 6: Composite claim encoding vectors
fn generate_composite_claim_vectors() -> JsonValue {
    let mut vectors = Vec::new();
    let alg = HmacSha256Algorithm::new(&hmac_key());

    // 6.1: Simple OR composite — two alternative claim sets
    {
        let mut token_a = CatToken::new()
            .with_issuer("https://auth.example.com")
            .with_version(1);
        token_a.core.exp = Some(FIXED_EXP);

        let mut token_b = CatToken::new()
            .with_issuer("https://auth-backup.example.com")
            .with_version(1);
        token_b.core.exp = Some(FIXED_EXP + 3600);

        let mut or_claim = claims::CompositeClaim::new(claims::CompositeOperator::Or);
        or_claim.add_token(token_a);
        or_claim.add_token(token_b);

        let mut token = CatToken::new().with_issuer("https://auth.example.com");
        token.core.exp = Some(FIXED_EXP);
        token.composite.or_claim = Some(or_claim);

        let encoded = encode_token(&token, &alg).unwrap();
        let c = extract_cose_components(&encoded);

        vectors.push(json!({
            "id": "composite_or_simple",
            "description": "OR composite: at least one of two alternative claim sets must be acceptable",
            "cose_hex": hex::encode(&encoded),
            "payload_cbor_hex": hex::encode(&c.payload),
            "composite": {
                "operator": "OR",
                "claim_key": 324,
                "claim_sets": [
                    {"iss": "https://auth.example.com", "catv": 1, "exp": FIXED_EXP},
                    {"iss": "https://auth-backup.example.com", "catv": 1, "exp": FIXED_EXP + 3600},
                ],
            },
        }));
    }

    // 6.2: AND composite — both claim sets must be acceptable
    {
        let mut token_a = CatToken::new().with_version(1);
        token_a.core.exp = Some(FIXED_EXP);

        let mut token_b = CatToken::new().with_ip_address("10.0.0.0").unwrap();
        token_b.core.exp = Some(FIXED_EXP);

        let mut and_claim = claims::CompositeClaim::new(claims::CompositeOperator::And);
        and_claim.add_token(token_a);
        and_claim.add_token(token_b);

        let mut token = CatToken::new().with_issuer("https://auth.example.com");
        token.core.exp = Some(FIXED_EXP);
        token.composite.and_claim = Some(and_claim);

        let encoded = encode_token(&token, &alg).unwrap();
        let c = extract_cose_components(&encoded);

        vectors.push(json!({
            "id": "composite_and",
            "description": "AND composite: both claim sets must be acceptable",
            "cose_hex": hex::encode(&encoded),
            "payload_cbor_hex": hex::encode(&c.payload),
            "composite": {
                "operator": "AND",
                "claim_key": 326,
                "claim_sets": [
                    {"catv": 1, "exp": FIXED_EXP},
                    {"catnip": [{"type": "ip_address", "value": "10.0.0.0"}], "exp": FIXED_EXP},
                ],
            },
        }));
    }

    // 6.3: NOR composite — none of the claim sets can be acceptable
    {
        let mut blocked = CatToken::new().with_issuer("https://revoked.example.com");
        blocked.core.exp = Some(FIXED_EXP);

        let mut nor_claim = claims::CompositeClaim::new(claims::CompositeOperator::Nor);
        nor_claim.add_token(blocked);

        let mut token = CatToken::new().with_issuer("https://auth.example.com");
        token.core.exp = Some(FIXED_EXP);
        token.composite.nor_claim = Some(nor_claim);

        let encoded = encode_token(&token, &alg).unwrap();
        let c = extract_cose_components(&encoded);

        vectors.push(json!({
            "id": "composite_nor",
            "description": "NOR composite: none of the listed claim sets can be acceptable",
            "cose_hex": hex::encode(&encoded),
            "payload_cbor_hex": hex::encode(&c.payload),
            "composite": {
                "operator": "NOR",
                "claim_key": 325,
                "claim_sets": [
                    {"iss": "https://revoked.example.com", "exp": FIXED_EXP},
                ],
            },
        }));
    }

    // 6.4: Nested composite — OR containing a nested AND
    {
        let mut token_standalone = CatToken::new().with_issuer("https://primary.example.com");
        token_standalone.core.exp = Some(FIXED_EXP);

        let mut and_a = CatToken::new().with_issuer("https://secondary.example.com");
        and_a.core.exp = Some(FIXED_EXP);
        let mut and_b = CatToken::new().with_version(1);
        and_b.core.exp = Some(FIXED_EXP);

        let mut nested_and = claims::CompositeClaim::new(claims::CompositeOperator::And);
        nested_and.add_token(and_a);
        nested_and.add_token(and_b);

        let mut or_claim = claims::CompositeClaim::new(claims::CompositeOperator::Or);
        or_claim.add_token(token_standalone);
        or_claim.add_composite(nested_and);

        let mut token = CatToken::new().with_issuer("https://auth.example.com");
        token.core.exp = Some(FIXED_EXP);
        token.composite.or_claim = Some(or_claim);

        let encoded = encode_token(&token, &alg).unwrap();
        let c = extract_cose_components(&encoded);

        vectors.push(json!({
            "id": "composite_nested",
            "description": "Nested composite: OR containing a standalone claim set and a nested AND",
            "cose_hex": hex::encode(&encoded),
            "payload_cbor_hex": hex::encode(&c.payload),
            "composite": {
                "operator": "OR",
                "claim_key": 324,
                "claim_sets": [
                    {"iss": "https://primary.example.com", "exp": FIXED_EXP},
                    {
                        "nested": {
                            "operator": "AND",
                            "claim_key": 326,
                            "claim_sets": [
                                {"iss": "https://secondary.example.com", "exp": FIXED_EXP},
                                {"catv": 1, "exp": FIXED_EXP},
                            ],
                        },
                    },
                ],
            },
        }));
    }

    json!({
        "description": "Composite claim encoding (draft-lemmons-cose-composite-claims-01)",
        "vectors": vectors,
    })
}

// -------------------------------------------------------------------------
// Draft-markdown emitter
// -------------------------------------------------------------------------
//
// The CAT-4-MOQT Appendix A embeds vectors as JSON blocks fenced with `~~~`.
// Historically these blocks were hand-copied from `tests/test_data/*.json`,
// which produced hex fields wrapped at 60 chars with stray spaces at every
// wrap boundary — see the Copilot review on moq-wg/CAT-4-MOQT#47 (byte
// string vs text string mismatch, odd-length hex, mid-token space
// injections). This emitter writes the same JSON but keeps every hex-shaped
// field on a single line so no wrap-based corruption is possible when the
// output is pasted verbatim into the draft. The `--verify` pass strips
// interior whitespace inside recognised hex fields before comparing, so a
// hand-wrapped block in the draft still verifies as long as it decodes to
// the same bytes.

fn is_hex_field(key: &str) -> bool {
    HEX_FIELDS.contains(&key)
}

fn stringify_json_compact_hex(value: &JsonValue, indent: usize) -> String {
    let mut out = String::new();
    write_json(&mut out, value, indent, 0, None);
    out
}

fn write_json(out: &mut String, value: &JsonValue, indent: usize, level: usize, key: Option<&str>) {
    let pad = " ".repeat(level * indent);
    match value {
        JsonValue::Null => out.push_str("null"),
        JsonValue::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        JsonValue::Number(n) => out.push_str(&n.to_string()),
        JsonValue::String(s) => {
            out.push('"');
            for c in s.chars() {
                match c {
                    '"' => out.push_str("\\\""),
                    '\\' => out.push_str("\\\\"),
                    '\n' => out.push_str("\\n"),
                    '\r' => out.push_str("\\r"),
                    '\t' => out.push_str("\\t"),
                    c if (c as u32) < 0x20 => {
                        let _ = write!(out, "\\u{:04x}", c as u32);
                    }
                    c => out.push(c),
                }
            }
            out.push('"');
            let _ = key; // key parameter is used by the caller to decide leaf layout
        }
        JsonValue::Array(arr) => {
            if arr.is_empty() {
                out.push_str("[]");
                return;
            }
            out.push('[');
            out.push('\n');
            for (i, v) in arr.iter().enumerate() {
                out.push_str(&" ".repeat((level + 1) * indent));
                write_json(out, v, indent, level + 1, None);
                if i + 1 < arr.len() {
                    out.push(',');
                }
                out.push('\n');
            }
            out.push_str(&pad);
            out.push(']');
        }
        JsonValue::Object(map) => {
            if map.is_empty() {
                out.push_str("{}");
                return;
            }
            out.push('{');
            out.push('\n');
            let entries: Vec<_> = map.iter().collect();
            for (i, (k, v)) in entries.iter().enumerate() {
                out.push_str(&" ".repeat((level + 1) * indent));
                out.push('"');
                out.push_str(k);
                out.push_str("\": ");
                write_json(out, v, indent, level + 1, Some(k.as_str()));
                if i + 1 < entries.len() {
                    out.push(',');
                }
                out.push('\n');
            }
            out.push_str(&pad);
            out.push('}');
        }
    }
}

fn emit_json_block(category: &str, vectors: &[JsonValue]) -> String {
    let arr = JsonValue::Array(vectors.to_vec());
    let body = stringify_json_compact_hex(&arr, 2);
    let _ = category;
    format!("~~~ json\n{body}\n~~~\n")
}

fn run_emit_draft_md(combined: &JsonValue, out_path: &Path) {
    let mut md = String::new();
    md.push_str("# Appendix A: Test Vectors\n\n");
    md.push_str(
        "This appendix provides test vectors in JSON format for cross-implementation\n\
         validation of CAT tokens for MOQT. Tokens use COSE_Mac0 (CBOR tag 17) for\n\
         HMAC-SHA256 or COSE_Sign1 (CBOR tag 18) for ES256. Token strings are the\n\
         base64url encoding of the full COSE structure.\n\n",
    );
    md.push_str(
        "The blocks below are emitted verbatim by\n\
         `cargo run --bin generate-test-vectors --features moqt -- --emit draft-md`.\n\
         Every hex-shaped field (`cose_hex`, `payload_cbor_hex`, ...) is kept on a\n\
         single line so the draft cannot introduce mid-hex whitespace or truncation\n\
         when the block is pasted. Do not hand-edit; regenerate the block instead.\n\n",
    );

    md.push_str("## Keys\n\nThe following keys are used throughout these test vectors:\n\n");
    md.push_str("~~~ json\n");
    md.push_str(&stringify_json_compact_hex(&combined["keys"], 2));
    md.push_str("\n~~~\n\n");

    let sections: &[(&str, &str)] = &[
        ("cbor_encoding", "CBOR Encoding of Claims"),
        ("token_structure", "Token Structure"),
        ("dpop_binding", "DPoP Binding"),
        ("moqt_scopes", "MOQT Authorization Scopes"),
        ("validation", "Validation Vectors"),
        ("composite_claims", "Composite Claims"),
    ];
    for (key, title) in sections {
        let category = &combined["vectors"][key];
        let vectors = category["vectors"].as_array().cloned().unwrap_or_default();
        let desc = category["description"].as_str().unwrap_or("");
        md.push_str(&format!("## {title}\n\n"));
        if !desc.is_empty() {
            md.push_str(desc);
            md.push_str("\n\n");
        }
        md.push_str(&emit_json_block(key, &vectors));
        md.push('\n');
    }

    if let Some(parent) = out_path.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent).unwrap();
    }
    fs::write(out_path, &md).unwrap();
    println!("wrote {}", out_path.display());
}

// -------------------------------------------------------------------------
// Verify mode
// -------------------------------------------------------------------------
//
// Walks the draft markdown, pulls out every fenced JSON block under
// Appendix A, and for each vector confirms that its hex-shaped fields
// match what cat.rs currently emits — after stripping interior whitespace
// so a hand-wrapped block still verifies if the bytes decode identically.
// A mismatch prints a diff-style summary and exits non-zero.

fn strip_hex_ws(s: &str) -> String {
    s.chars()
        .filter(|c| !c.is_whitespace())
        .collect::<String>()
        .to_ascii_lowercase()
}

/// Fold line-wrapped JSON string literals into single-line form. RFC 7159
/// rejects raw newlines inside strings, and the draft's Appendix A blocks
/// wrap long hex/base64 values across lines with leading indent. Walk the
/// block character-by-character, and inside `"..."` collapse each run of
/// whitespace-including-newlines to a single ASCII space so serde_json
/// accepts the block. Escape sequences (`\"`, `\\`) still terminate the
/// string correctly; nothing outside strings is touched.
fn fold_string_wraps(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut in_str = false;
    let mut escape = false;
    for c in s.chars() {
        if !in_str {
            if c == '"' {
                in_str = true;
            }
            out.push(c);
            continue;
        }
        if escape {
            out.push(c);
            escape = false;
            continue;
        }
        match c {
            '\\' => {
                escape = true;
                out.push(c);
            }
            '"' => {
                in_str = false;
                out.push(c);
            }
            '\n' | '\r' | '\t' => {
                // collapse run of interior whitespace; peek is unnecessary,
                // consecutive whitespace becomes a single space and hex
                // parsers ignore whitespace anyway.
                if !out.ends_with(' ') {
                    out.push(' ');
                }
            }
            _ => out.push(c),
        }
    }
    out
}

fn fetch_draft(source: &str, is_file: bool) -> Result<String, String> {
    if is_file {
        return fs::read_to_string(source).map_err(|e| format!("read {source}: {e}"));
    }
    let output = std::process::Command::new("curl")
        .args([
            "--silent",
            "--show-error",
            "--fail",
            "--location",
            "--max-time",
            "30",
            source,
        ])
        .output()
        .map_err(|e| format!("curl exec: {e}"))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!(
            "curl {source}: exit={:?} stderr={stderr}",
            output.status.code()
        ));
    }
    String::from_utf8(output.stdout).map_err(|e| format!("curl stdout not utf-8: {e}"))
}

fn extract_appendix_a(md: &str) -> &str {
    let start = match md.find("Appendix A") {
        Some(i) => i,
        None => return md,
    };
    &md[start..]
}

fn extract_json_blocks(md: &str) -> Vec<String> {
    let mut blocks = Vec::new();
    let mut lines = md.lines();
    while let Some(line) = lines.next() {
        let t = line.trim();
        if t.starts_with("~~~") && t.contains("json") {
            let mut body = String::new();
            for l in lines.by_ref() {
                if l.trim().starts_with("~~~") {
                    break;
                }
                body.push_str(l);
                body.push('\n');
            }
            blocks.push(body);
        } else if t.starts_with("```") && t.contains("json") {
            let mut body = String::new();
            for l in lines.by_ref() {
                if l.trim().starts_with("```") {
                    break;
                }
                body.push_str(l);
                body.push('\n');
            }
            blocks.push(body);
        }
    }
    blocks
}

fn collect_expected_hex(combined: &JsonValue) -> BTreeMap<String, BTreeMap<String, String>> {
    let mut expected: BTreeMap<String, BTreeMap<String, String>> = BTreeMap::new();
    let cats = combined["vectors"].as_object().unwrap();
    for (_cat, cat_body) in cats {
        let vectors = match cat_body["vectors"].as_array() {
            Some(v) => v,
            None => continue,
        };
        for v in vectors {
            let id = match v["id"].as_str() {
                Some(s) => s.to_string(),
                None => continue,
            };
            let entry = expected.entry(id.clone()).or_default();
            collect_hex_recursive(v, entry);
        }
    }
    expected
}

fn collect_hex_recursive(value: &JsonValue, out: &mut BTreeMap<String, String>) {
    if let JsonValue::Object(map) = value {
        for (k, v) in map {
            if is_hex_field(k)
                && let Some(s) = v.as_str()
            {
                out.insert(k.clone(), s.to_ascii_lowercase());
            }
            collect_hex_recursive(v, out);
        }
    } else if let JsonValue::Array(arr) = value {
        for v in arr {
            collect_hex_recursive(v, out);
        }
    }
}

fn run_verify(combined: &JsonValue, source: &str, is_file: bool) -> i32 {
    let md = match fetch_draft(source, is_file) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("verify: failed to load draft: {e}");
            return 2;
        }
    };
    let appendix = extract_appendix_a(&md);
    let blocks = extract_json_blocks(appendix);
    if blocks.is_empty() {
        eprintln!("verify: found no JSON blocks under Appendix A in {source}");
        return 2;
    }

    let mut draft_vectors: BTreeMap<String, BTreeMap<String, String>> = BTreeMap::new();
    let mut parse_errors: Vec<String> = Vec::new();

    for (i, block) in blocks.iter().enumerate() {
        let folded = fold_string_wraps(block);
        match serde_json::from_str::<JsonValue>(&folded) {
            Ok(v) => harvest_vectors(&v, &mut draft_vectors),
            Err(e) => parse_errors.push(format!("block #{i}: {e}")),
        }
    }

    let expected = collect_expected_hex(combined);

    let mut mismatches: Vec<String> = Vec::new();
    let mut missing_in_draft: Vec<String> = Vec::new();
    let mut checked_ids = 0usize;

    for (id, exp_fields) in &expected {
        let Some(draft_fields) = draft_vectors.get(id) else {
            missing_in_draft.push(id.clone());
            continue;
        };
        checked_ids += 1;
        for (field, exp_hex) in exp_fields {
            match draft_fields.get(field) {
                None => mismatches.push(format!(
                    "  {id}.{field}: MISSING in draft (cat.rs emits {} bytes)",
                    exp_hex.len() / 2
                )),
                Some(draft_hex) => {
                    let draft_norm = strip_hex_ws(draft_hex);
                    if &draft_norm != exp_hex {
                        mismatches.push(format!(
                            "  {id}.{field}: MISMATCH\n    draft: {draft_norm}\n    cat.rs: {exp_hex}"
                        ));
                    }
                }
            }
        }
    }

    println!(
        "verify: source={source} appendix_blocks={} vectors_in_draft={} vectors_checked={} mismatches={} missing={} parse_errors={}",
        blocks.len(),
        draft_vectors.len(),
        checked_ids,
        mismatches.len(),
        missing_in_draft.len(),
        parse_errors.len(),
    );

    if !parse_errors.is_empty() {
        eprintln!("verify: JSON parse errors under Appendix A:");
        for e in &parse_errors {
            eprintln!("  {e}");
        }
    }
    if !mismatches.is_empty() {
        eprintln!("verify: hex mismatches vs cat.rs:");
        for m in &mismatches {
            eprintln!("{m}");
        }
    }
    if !missing_in_draft.is_empty() {
        eprintln!(
            "verify: vectors emitted by cat.rs but not present in the draft: {}",
            missing_in_draft.join(", ")
        );
    }

    if !mismatches.is_empty() || !parse_errors.is_empty() {
        1
    } else {
        0
    }
}

fn harvest_vectors(value: &JsonValue, out: &mut BTreeMap<String, BTreeMap<String, String>>) {
    match value {
        JsonValue::Array(arr) => {
            for v in arr {
                harvest_vectors(v, out);
            }
        }
        JsonValue::Object(map) => {
            if let Some(JsonValue::String(id)) = map.get("id") {
                let entry = out.entry(id.clone()).or_default();
                collect_hex_recursive(value, entry);
            }
            for v in map.values() {
                harvest_vectors(v, out);
            }
        }
        _ => {}
    }
}
