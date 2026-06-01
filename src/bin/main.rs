// SPDX-FileCopyrightText: Copyright (c) 2022 Quicr
// SPDX-License-Identifier: BSD-2-Clause

use cat_token::*;
use chrono::{Duration, Utc};
use p256::ecdsa::SigningKey;
use p256::pkcs8::DecodePrivateKey;
use std::env;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        println!("Usage: {} <command> [args...]", args[0]);
        println!("Commands:");
        println!("  generate-hmac        - Generate HMAC key and sample token");
        println!("  generate-es256       - Generate ES256 key pair and sample token");
        println!("  generate-ps256       - Generate PS256 key pair and sample token");
        println!("  verify <token> <alg> - Verify a token");
        println!("  moqt-token <key.pem> <role> <namespace> [options]");
        println!("    Generate a MOQT-scoped C4M token for relay auth testing.");
        println!("    role: publisher | subscriber");
        println!("    Options: --issuer <iss> --audience <aud> --subject <sub> --expires <secs>");
        return Ok(());
    }

    match args[1].as_str() {
        "generate-hmac" => generate_hmac_example()?,
        "generate-es256" => generate_es256_example()?,
        "generate-ps256" => generate_ps256_example()?,
        "verify" => {
            if args.len() < 4 {
                println!("Usage: {} verify <token> <algorithm>", args[0]);
                return Ok(());
            }
            verify_token(&args[2], &args[3])?;
        }
        "moqt-token" => {
            if args.len() < 5 {
                println!("Usage: {} moqt-token <key.pem> <role> <namespace> [--issuer X] [--audience X] [--subject X] [--expires SECS]", args[0]);
                return Ok(());
            }
            generate_moqt_token(&args[2..])
                .map_err(|e| { eprintln!("Error: {e}"); e })?;
        }
        _ => {
            println!("Unknown command: {}", args[1]);
            return Ok(());
        }
    }

    Ok(())
}

fn generate_hmac_example() -> Result<(), Box<dyn std::error::Error>> {
    let key = HmacSha256Algorithm::generate_key()?;
    let algorithm = HmacSha256Algorithm::from_secret_key(&key);

    let token = create_sample_token();
    let encoded = encode_token(&token, &algorithm)?;

    // Security: Do not print key material in production
    // To display the key, use: --show-key flag (not implemented in this example)
    println!(
        "HMAC256 Key: [REDACTED - {} bytes generated]",
        key.as_bytes().len()
    );
    println!("Sample CAT Token: {}", encoded);

    let decoded = decode_token(&encoded, &algorithm)?;
    println!("Token verified and decoded successfully!");
    println!("Issuer: {:?}", decoded.core.iss);
    println!("Audience: {:?}", decoded.core.aud);
    println!("Version: {:?}", decoded.cat.catv);

    Ok(())
}

fn generate_es256_example() -> Result<(), Box<dyn std::error::Error>> {
    let algorithm = Es256Algorithm::new_with_key_pair()?;

    let token = create_sample_token();
    let encoded = encode_token(&token, &algorithm)?;

    // Output public key as JWK for structured, portable format
    let jwk = cat_token::Jwk::from_es256_verifying_key(algorithm.verifying_key())?;
    println!(
        "ES256 Public Key (JWK): {}",
        serde_json::to_string(&jwk).unwrap_or_else(|_| "Error serializing JWK".to_string())
    );
    println!("Sample CAT Token: {}", encoded);

    let decoded = decode_token(&encoded, &algorithm)?;
    println!("Token verified and decoded successfully!");
    println!("Issuer: {:?}", decoded.core.iss);
    println!("Audience: {:?}", decoded.core.aud);
    println!("Version: {:?}", decoded.cat.catv);

    Ok(())
}

fn generate_ps256_example() -> Result<(), Box<dyn std::error::Error>> {
    let algorithm = Ps256Algorithm::new_with_key_pair()?;

    let token = create_sample_token();
    let encoded = encode_token(&token, &algorithm)?;

    // Output public key as JWK for structured, portable format
    let jwk = cat_token::Jwk::from_rsa_public_key(algorithm.public_key());
    println!(
        "PS256 Public Key (JWK): {}",
        serde_json::to_string(&jwk).unwrap_or_else(|_| "Error serializing JWK".to_string())
    );
    println!("Sample CAT Token: {}", encoded);

    let decoded = decode_token(&encoded, &algorithm)?;
    println!("Token verified and decoded successfully!");
    println!("Issuer: {:?}", decoded.core.iss);
    println!("Audience: {:?}", decoded.core.aud);
    println!("Version: {:?}", decoded.cat.catv);

    Ok(())
}

fn verify_token(token_str: &str, alg: &str) -> Result<(), Box<dyn std::error::Error>> {
    println!("Token verification requires algorithm-specific keys.");
    println!("This is a placeholder for token verification logic.");
    println!("Token: {}", token_str);
    println!("Algorithm: {}", alg);
    Ok(())
}

fn generate_moqt_token(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let key_path = &args[0];
    let role = &args[1];
    let namespace = &args[2];

    let mut issuer = "cat-cli".to_string();
    let mut audience = "moq-relay".to_string();
    let mut subject = "user".to_string();
    let mut expires: i64 = 3600;

    let mut i = 3;
    while i < args.len() {
        match args[i].as_str() {
            "--issuer" => { i += 1; issuer = args[i].clone(); }
            "--audience" => { i += 1; audience = args[i].clone(); }
            "--subject" => { i += 1; subject = args[i].clone(); }
            "--expires" => { i += 1; expires = args[i].parse()?; }
            other => return Err(format!("unknown option: {other}").into()),
        }
        i += 1;
    }

    let pem = std::fs::read_to_string(key_path)?;
    let signing_key = SigningKey::from_pkcs8_pem(&pem)
        .or_else(|_| {
            p256::SecretKey::from_sec1_pem(&pem)
                .map(SigningKey::from)
        })
        .map_err(|e| format!("failed to load private key: {e}"))?;
    let verifying_key = p256::ecdsa::VerifyingKey::from(&signing_key);
    let algorithm = Es256Algorithm::from_key_pair(signing_key, verifying_key);

    let mut scope_builder = match role.as_str() {
        "publisher" => MoqtScopeBuilder::new().publisher(),
        "subscriber" => MoqtScopeBuilder::new().subscriber(),
        _ => return Err(format!("unknown role: {role} (use publisher or subscriber)").into()),
    };
    scope_builder = scope_builder.namespace_path(namespace.as_bytes()).track_prefix(b"");
    let scope = scope_builder.build();

    let setup_scope = MoqtScopeBuilder::new()
        .action(MoqtAction::ClientSetup)
        .build();

    let token = CatTokenBuilder::new()
        .issuer(&issuer)
        .single_audience(&audience)
        .subject(&subject)
        .expires_in(expires)
        .moqt_scope(scope)
        .moqt_scope(setup_scope)
        .build();

    let encoded = encode_token(&token, &algorithm)?;
    println!("{encoded}");

    Ok(())
}

fn create_sample_token() -> CatToken {
    let now = Utc::now();
    let exp = now + Duration::hours(1);

    CatTokenBuilder::new()
        .issuer("https://example.com")
        .audience(vec!["https://api.example.com".to_string()])
        .expires_at(exp)
        .not_before(now)
        .cwt_id(uuid::Uuid::new_v4().to_string())
        .version("1.0")
        .usage_limit(100)
        .replay_protection(uuid::Uuid::new_v4().to_string())
        .proof_of_possession(true)
        .geo_coordinate(37.7749, -122.4194, Some(100.0))
        .geohash("9q8yy")
        .build()
}
