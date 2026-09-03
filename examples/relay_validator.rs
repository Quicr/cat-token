// SPDX-FileCopyrightText: Copyright (c) 2022 Quicr
// SPDX-License-Identifier: BSD-2-Clause

//! Example: MOQT Relay - Token Validation
//!
//! This example shows how a MOQT relay would validate incoming tokens
//! and authorize MOQT operations.

use cat_token::prelude::*;
use chrono::{Duration, Utc};

fn main() {
    println!("=== MOQT Relay Token Validation Example ===\n");

    // In production: auth server has private key, relay has public key from JWKS
    // For this demo: we use the same key for both
    let key = Es256Algorithm::new_with_key_pair().unwrap();

    // Create a token (simulates what auth server issues)
    let token_str = create_test_token(&key);

    // Setup validators
    let token_validator = CatTokenValidator::new()
        .with_expected_issuers(vec!["https://auth.example.com".to_string()])
        .with_expected_audiences(vec!["moqt-relay.example.com".to_string()])
        .with_clock_skew_tolerance(60);

    let moqt_validator = MoqtValidator::new().with_min_revalidation_interval(60.0);

    println!("--- Test Scenarios ---\n");

    // Scenario 1: Valid publish request
    print!("1. PUBLISH to allowed namespace/track: ");
    match validate_and_authorize(
        &token_str,
        &key,
        &token_validator,
        &moqt_validator,
        MoqtAction::Publish,
        b"live.sports.example.com",
        b"/football/match123",
    ) {
        Ok(result) => println!("ALLOWED (scope {})", result.matched_scope_index.unwrap()),
        Err(e) => println!("DENIED - {}", e),
    }

    // Scenario 2: Action not in scope
    print!("2. FETCH (not in publisher scope): ");
    match validate_and_authorize(
        &token_str,
        &key,
        &token_validator,
        &moqt_validator,
        MoqtAction::Fetch,
        b"live.sports.example.com",
        b"/football/match123",
    ) {
        Ok(_) => println!("ALLOWED"),
        Err(e) => println!("DENIED - {}", e),
    }

    // Scenario 3: Wrong namespace
    print!("3. PUBLISH to wrong namespace: ");
    match validate_and_authorize(
        &token_str,
        &key,
        &token_validator,
        &moqt_validator,
        MoqtAction::Publish,
        b"live.news.example.com",
        b"/breaking/story1",
    ) {
        Ok(_) => println!("ALLOWED"),
        Err(e) => println!("DENIED - {}", e),
    }

    // Scenario 4: Invalid token
    print!("4. Invalid token: ");
    match validate_and_authorize(
        b"invalid-cose-bytes",
        &key,
        &token_validator,
        &moqt_validator,
        MoqtAction::Publish,
        b"live.sports.example.com",
        b"/football/match123",
    ) {
        Ok(_) => println!("ALLOWED"),
        Err(e) => println!("DENIED - {}", e),
    }

    // Scenario 5: Expired token
    print!("5. Expired token: ");
    let expired_token = create_expired_token(&key);
    match validate_and_authorize(
        &expired_token,
        &key,
        &token_validator,
        &moqt_validator,
        MoqtAction::Publish,
        b"live.sports.example.com",
        b"/football/match123",
    ) {
        Ok(_) => println!("ALLOWED"),
        Err(e) => println!("DENIED - {}", e),
    }

    println!("\n=== Validation Complete ===");
}

fn validate_and_authorize(
    token_bytes: &[u8],
    key: &Es256Algorithm,
    token_validator: &CatTokenValidator,
    moqt_validator: &MoqtValidator,
    action: MoqtAction,
    namespace: &[u8],
    track: &[u8],
) -> Result<MoqtAuthResult, String> {
    // Step 1: Decode and verify COSE structure
    let token = decode_token(token_bytes, key).map_err(|e| e.to_string())?;

    // Step 2: Validate standard claims
    token_validator
        .validate(&token)
        .map_err(|e| e.to_string())?;

    // Step 3: Validate MOQT claims
    moqt_validator
        .validate_moqt_claims(&token)
        .map_err(|e| e.to_string())?;

    // Step 4: Authorize the action
    let request = MoqtAuthRequest::new(action, vec![namespace.to_vec()], track.to_vec());
    let result = moqt_validator.authorize(&token, &request);

    if result.authorized {
        Ok(result)
    } else {
        Err("Action not permitted by token scopes".to_string())
    }
}

fn create_test_token(key: &Es256Algorithm) -> Vec<u8> {
    let now = Utc::now();

    let scope = MoqtScopeBuilder::new()
        .publisher()
        .namespace_exact(b"live.sports.example.com")
        .track_prefix(b"/")
        .build();

    let token = CatTokenBuilder::new()
        .issuer("https://auth.example.com")
        .audience(vec!["moqt-relay.example.com".to_string()])
        .subject("broadcaster123")
        .issued_at(now)
        .expires_at(now + Duration::hours(2))
        .moqt_scope(scope)
        .moqt_reval(300.0)
        .build();

    encode_token(&token, key).expect("Failed to encode token")
}

fn create_expired_token(key: &Es256Algorithm) -> Vec<u8> {
    let now = Utc::now();

    let token = CatTokenBuilder::new()
        .issuer("https://auth.example.com")
        .audience(vec!["moqt-relay.example.com".to_string()])
        .expires_at(now - Duration::hours(1)) // Expired 1 hour ago
        .moqt_scope(MoqtScopeBuilder::new().publisher().build())
        .build();

    encode_token(&token, key).expect("Failed to encode token")
}
