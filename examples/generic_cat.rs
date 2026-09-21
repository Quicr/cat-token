// SPDX-FileCopyrightText: Copyright (c) 2022 Quicr
// SPDX-License-Identifier: BSD-2-Clause

//! Example: Generic CAT Token (non-MOQT)
//!
//! CAT (Common Access Token) can be used for any protocol, not just MOQT.
//! This example shows how to create tokens for a generic CDN or API gateway.

use cat_token::{
    CatToken, CatTokenValidator, Decoder, Es256Algorithm, MatchValue, NetworkIdentifier,
    URI_COMPONENT_EXTENSION, URI_COMPONENT_PATH, UriMatchRule, encode_token, encode_token_base64,
};
use chrono::{Duration, Utc};

fn main() {
    println!("=== Generic CAT Token Example ===\n");

    let key = Es256Algorithm::new_with_key_pair().unwrap();

    // Example 1: CDN edge authorization token
    println!("1. CDN Edge Token");
    let cdn_token = CatToken::new()
        .with_issuer("https://auth.cdn.example.com")
        .with_audience(vec!["edge-pop-us-west".to_string()])
        .with_subject("customer-12345")
        .with_expiration(Utc::now() + Duration::hours(24))
        .with_issued_at(Utc::now())
        .with_uri_match_rules(vec![
            UriMatchRule {
                component: URI_COMPONENT_PATH,
                matches: vec![MatchValue::Prefix("/customer-12345/".to_string())],
            },
            UriMatchRule {
                component: URI_COMPONENT_EXTENSION,
                matches: vec![
                    MatchValue::Exact("m3u8".to_string()),
                    MatchValue::Exact("ts".to_string()),
                ],
            },
        ]);

    let encoded = encode_token(&cdn_token, &key).unwrap();
    let encoded_b64 = encode_token_base64(&cdn_token, &key).unwrap();
    println!(
        "   Encoded (b64): {}... ({} COSE bytes)",
        &encoded_b64[..40],
        encoded.len()
    );

    // Example 2: API gateway token with network restrictions
    println!("\n2. API Gateway Token (with network restrictions)");
    let api_token = CatToken::new()
        .with_issuer("https://auth.api.example.com")
        .with_audience(vec!["api-gateway".to_string()])
        .with_subject("service-account-xyz")
        .with_expiration(Utc::now() + Duration::hours(1))
        .with_network_identifiers(vec![
            NetworkIdentifier::IpPrefix("10.0.0.0".parse().unwrap(), 8),
            NetworkIdentifier::IpPrefix("192.168.0.0".parse().unwrap(), 16),
            NetworkIdentifier::Asn(64512),
        ])
        .with_uri_match_rules(vec![UriMatchRule {
            component: URI_COMPONENT_PATH,
            matches: vec![
                MatchValue::Prefix("/api/v1/".to_string()),
                MatchValue::Exact("/health".to_string()),
            ],
        }]);

    let encoded_b64 = encode_token_base64(&api_token, &key).unwrap();
    println!(
        "   Encoded (b64): {}... ({} chars)",
        &encoded_b64[..40],
        encoded_b64.len()
    );

    // Example 3: Geo-restricted token
    println!("\n3. Geo-Restricted Token");
    let geo_token = CatToken::new()
        .with_issuer("https://auth.streaming.com")
        .with_audience(vec!["streaming-service".to_string()])
        .with_subject("subscriber-789")
        .with_expiration(Utc::now() + Duration::hours(4))
        .with_geo_coordinate(37.7749, -122.4194, 50000) // San Francisco, 50km radius
        .with_geohash("9q8yy"); // SF area geohash

    let encoded = encode_token(&geo_token, &key).unwrap();
    let encoded_b64 = encode_token_base64(&geo_token, &key).unwrap();
    println!(
        "   Encoded (b64): {}... ({} COSE bytes)",
        &encoded_b64[..40],
        encoded.len()
    );

    // Validation example
    println!("\n4. Token Validation");
    let decoded = Decoder::with_algorithm(&key)
        .decode(&encoded)
        .unwrap()
        .into_unvalidated_token();

    let validator = CatTokenValidator::for_expected_issuers(["https://auth.streaming.com"])
        .with_expected_audiences(vec!["streaming-service".to_string()])
        .with_clock_skew_tolerance(60)
        .unwrap();

    match validator.validate(&decoded) {
        Ok(()) => println!("   Token is valid"),
        Err(e) => println!("   Validation failed: {}", e),
    }

    println!("\n=== Generic CAT Complete ===");
    println!("\nCAT tokens can authorize any protocol:");
    println!("  - HTTP/REST APIs");
    println!("  - CDN edge caching");
    println!("  - WebSocket connections");
    println!("  - gRPC services");
    println!("  - Custom protocols");
}
