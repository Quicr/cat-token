// SPDX-FileCopyrightText: Copyright (c) 2022 Quicr
// SPDX-License-Identifier: BSD-2-Clause

//! Quickstart Example
//!
//! Minimal example showing token creation, encoding, decoding, and validation
//! in under 50 lines. Start here if you're new to the library.

use cat_token::prelude::*;
use chrono::{Duration, Utc};

fn main() -> Result<(), CatError> {
    // 1. Create a signing key (auth server keeps this secret)
    let key = Es256Algorithm::new_with_key_pair()?;

    // 2. Build a token with MOQT permissions
    let token = CatTokenBuilder::new()
        .issuer("https://auth.example.com")
        .audience(vec!["relay.example.com".to_string()])
        .expires_at(Utc::now() + Duration::hours(1))
        .moqt_scope(
            MoqtScopeBuilder::new()
                .publisher() // Allows PublishNamespace + Publish
                .namespace_exact(b"live.example.com")
                .track_prefix(b"/streams/")
                .build(),
        )
        .build();

    // 3. Encode the token (returns COSE_Sign1 CBOR bytes)
    let encoded = encode_token(&token, &key)?;
    let encoded_b64 = encode_token_base64(&token, &key)?;
    println!(
        "Token (b64): {}...({} bytes)",
        &encoded_b64[..40],
        encoded.len()
    );

    // 4. Decode and verify (relay does this)
    let decoded = decode_token(&encoded, &key)?;

    // 5. Validate claims
    let validator = CatTokenValidator::new()
        .with_expected_issuers(vec!["https://auth.example.com".to_string()])
        .with_expected_audiences(vec!["relay.example.com".to_string()]);
    validator.validate(&decoded)?;

    // 6. Authorize MOQT action
    let moqt_validator = MoqtValidator::new();
    let request = MoqtAuthRequest::new(
        MoqtAction::Publish,
        vec![b"live.example.com".to_vec(), b"streaming-123".to_vec()],
        b"/video".to_vec(),
    );
    let result = moqt_validator.authorize(&decoded, &request);

    println!("Authorized: {}", result.authorized);
    Ok(())
}
