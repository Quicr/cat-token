// SPDX-FileCopyrightText: Copyright (c) 2022 Quicr
// SPDX-License-Identifier: BSD-2-Clause

//! Example: Authorization Server - Token Issuance
//!
//! This example shows how an authorization server would create and issue
//! CAT tokens for MOQT clients. In production, this would be called after
//! the user authenticates (e.g., OAuth2 flow).

use cat_token::prelude::*;
use chrono::{Duration, Utc};

/// Your authorization server's signing key (in production, load from secure storage)
fn get_signing_key() -> Es256Algorithm {
    // In production: load from HSM, KMS, or secure key storage
    // For this example, we generate a new key pair
    Es256Algorithm::new_with_key_pair().expect("Failed to create signing key")
}

/// Issue a publisher token for a live streaming client
fn issue_publisher_token(
    algorithm: &Es256Algorithm,
    user_id: &str,
    namespace: &str,
    client_jwk: Option<&Jwk>, // For DPoP binding
) -> Result<String, CatError> {
    let now = Utc::now();

    let scope = MoqtScopeBuilder::new()
        .publisher() // PublishNamespace + Publish
        .namespace_exact(namespace.as_bytes())
        .track_prefix(b"/") // All tracks under this namespace
        .build();

    let mut builder = CatTokenBuilder::new()
        .issuer("https://auth.example.com")
        .audience(vec!["moqt-relay.example.com".to_string()])
        .subject(user_id)
        .issued_at(now)
        .expires_at(now + Duration::hours(2))
        .cwt_id_str(format!("pub-{}-{}", user_id, now.timestamp()))
        .moqt_scope(scope)
        .moqt_reval(300.0); // 5-minute revalidation

    // Add DPoP binding if client provided their public key
    if let Some(jwk) = client_jwk {
        let cnf = confirmation_from_jwk(jwk)?;
        builder = builder.confirmation(cnf.jkt).dpop_settings(
            CatDpopSettings::new()
                .with_window(300)
                .with_jti_processing(true),
        );
    }

    let token = builder.build();
    encode_token(&token, algorithm)
}

/// Issue a subscriber token for a viewer client
fn issue_subscriber_token(
    algorithm: &Es256Algorithm,
    user_id: &str,
    namespaces: &[&str], // Multiple namespaces the user can subscribe to
) -> Result<String, CatError> {
    let now = Utc::now();

    // Create a scope for each namespace
    let scopes: Vec<MoqtScope> = namespaces
        .iter()
        .map(|ns| {
            MoqtScopeBuilder::new()
                .subscriber() // SubscribeNamespace + Subscribe + Fetch
                .namespace_exact(ns.as_bytes())
                .build()
        })
        .collect();

    let token = CatTokenBuilder::new()
        .issuer("https://auth.example.com")
        .audience(vec!["moqt-relay.example.com".to_string()])
        .subject(user_id)
        .issued_at(now)
        .expires_at(now + Duration::hours(24)) // Longer validity for viewers
        .cwt_id_str(format!("sub-{}-{}", user_id, now.timestamp()))
        .moqt_scopes(scopes)
        .build();

    encode_token(&token, algorithm)
}

/// Issue an admin token with full access
fn issue_admin_token(
    algorithm: &Es256Algorithm,
    admin_id: &str,
    client_jwk: &Jwk, // DPoP required for admin
) -> Result<String, CatError> {
    let now = Utc::now();

    let scope = MoqtScopeBuilder::new()
        .full_access() // All 9 MOQT actions
        .namespace_prefix(b"") // All namespaces
        .build();

    let cnf = confirmation_from_jwk(client_jwk)?;

    let token = CatTokenBuilder::new()
        .issuer("https://auth.example.com")
        .audience(vec!["moqt-relay.example.com".to_string()])
        .subject(admin_id)
        .issued_at(now)
        .expires_at(now + Duration::minutes(30)) // Short validity for admin
        .cwt_id_str(format!("admin-{}-{}", admin_id, now.timestamp()))
        .moqt_scope(scope)
        .moqt_reval(60.0) // 1-minute revalidation for admin ops
        .confirmation(cnf.jkt)
        .dpop_settings(
            CatDpopSettings::new()
                .with_window(60)
                .with_jti_processing(true),
        )
        .build();

    encode_token(&token, algorithm)
}

fn main() {
    println!("=== Authorization Server Token Issuance Example ===\n");

    let algorithm = get_signing_key();

    // Scenario 1: Publisher requesting token to stream
    println!("1. Issuing publisher token for user 'broadcaster123'");
    let pub_token = issue_publisher_token(
        &algorithm,
        "broadcaster123",
        "live.sports.example.com",
        None, // No DPoP for this example
    )
    .expect("Failed to issue publisher token");

    println!("   Token length: {} bytes", pub_token.len());
    println!("   Token (truncated): {}...\n", &pub_token[..50]);

    // Scenario 2: Viewer requesting token to watch multiple channels
    println!("2. Issuing subscriber token for user 'viewer456'");
    let sub_token = issue_subscriber_token(
        &algorithm,
        "viewer456",
        &[
            "live.sports.example.com",
            "live.news.example.com",
            "vod.movies.example.com",
        ],
    )
    .expect("Failed to issue subscriber token");

    println!("   Token length: {} bytes", sub_token.len());
    println!("   Token (truncated): {}...\n", &sub_token[..50]);

    // Scenario 3: Admin with DPoP binding
    println!("3. Issuing admin token for 'admin@example.com' (with DPoP)");

    // Simulate admin's key pair
    let admin_key = Es256Algorithm::new_with_key_pair().unwrap();
    let admin_jwk = Jwk::from_es256_verifying_key(admin_key.verifying_key()).unwrap();

    let admin_token = issue_admin_token(&algorithm, "admin@example.com", &admin_jwk)
        .expect("Failed to issue admin token");

    println!("   Token length: {} bytes", admin_token.len());
    println!("   Token (truncated): {}...\n", &admin_token[..50]);

    println!("=== Token Issuance Complete ===");
    println!("\nIn production, these tokens would be returned to clients via:");
    println!("  - OAuth2 token endpoint response");
    println!("  - REST API response body");
    println!("  - WebSocket connection establishment");
}
