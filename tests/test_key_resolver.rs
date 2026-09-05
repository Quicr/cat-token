// SPDX-FileCopyrightText: Copyright (c) 2022 Quicr
// SPDX-License-Identifier: BSD-2-Clause

use cat_token::prelude::*;
use chrono::{Duration, Utc};

#[test]
fn test_static_resolver_decodes_token() {
    let key = Es256Algorithm::new_with_key_pair().unwrap();
    let token = CatTokenBuilder::new()
        .issuer("https://test.com")
        .expires_at(Utc::now() + Duration::hours(1))
        .build()
        .unwrap();
    let encoded = encode_token(&token, &key).unwrap();

    let resolver = StaticKeyResolver::new(Es256Algorithm::new_verifier(*key.verifying_key()));

    let verified = decode_token_with_resolver(&encoded, &resolver).unwrap();
    let decoded = verified.into_unvalidated_token();
    assert_eq!(decoded.core.iss, Some("https://test.com".to_string()));
}

#[test]
fn test_keyring_resolver_multiple_keys() {
    let key1 = Es256Algorithm::new_with_key_pair().unwrap();
    let key2 = Es256Algorithm::new_with_key_pair().unwrap();

    let resolver = KeyRingResolver::new()
        .with_key(
            b"key-1".to_vec(),
            Box::new(Es256Algorithm::new_verifier(*key1.verifying_key())),
        )
        .with_key(
            b"key-2".to_vec(),
            Box::new(Es256Algorithm::new_verifier(*key2.verifying_key())),
        );

    assert_eq!(resolver.key_count(), 2);

    let hint_1 = KeyHint {
        algorithm_id: -7,
        kid: Some(b"key-1".to_vec()),
    };
    assert!(resolver.resolve(&hint_1).is_ok());

    let hint_2 = KeyHint {
        algorithm_id: -7,
        kid: Some(b"key-2".to_vec()),
    };
    assert!(resolver.resolve(&hint_2).is_ok());

    let hint_missing = KeyHint {
        algorithm_id: -7,
        kid: Some(b"key-3".to_vec()),
    };
    assert!(resolver.resolve(&hint_missing).is_err());
}

#[test]
fn test_keyring_resolver_with_default() {
    let key = Es256Algorithm::new_with_key_pair().unwrap();
    let token = CatTokenBuilder::new()
        .issuer("https://test.com")
        .expires_at(Utc::now() + Duration::hours(1))
        .build()
        .unwrap();
    let encoded = encode_token(&token, &key).unwrap();

    let resolver = KeyRingResolver::new()
        .with_default(Box::new(Es256Algorithm::new_verifier(*key.verifying_key())));

    let verified = decode_token_with_resolver(&encoded, &resolver).unwrap();
    let decoded = verified.into_unvalidated_token();
    assert_eq!(decoded.core.iss, Some("https://test.com".to_string()));
}

#[test]
fn test_keyring_resolver_no_matching_key() {
    let key = Es256Algorithm::new_with_key_pair().unwrap();
    let token = CatTokenBuilder::new()
        .issuer("https://test.com")
        .expires_at(Utc::now() + Duration::hours(1))
        .build()
        .unwrap();
    let encoded = encode_token(&token, &key).unwrap();

    let resolver = KeyRingResolver::new().with_key(
        b"other-kid".to_vec(),
        Box::new(Es256Algorithm::new_verifier(*key.verifying_key())),
    );

    let result = decode_token_with_resolver(&encoded, &resolver);
    assert!(result.is_err());
}

#[test]
fn test_keyring_add_remove_keys() {
    let key = Es256Algorithm::new_with_key_pair().unwrap();
    let mut resolver = KeyRingResolver::new();

    assert_eq!(resolver.key_count(), 0);

    resolver.add_key(
        b"k1".to_vec(),
        Box::new(Es256Algorithm::new_verifier(*key.verifying_key())),
    );
    assert_eq!(resolver.key_count(), 1);

    resolver.add_key(
        b"k2".to_vec(),
        Box::new(Es256Algorithm::new_verifier(*key.verifying_key())),
    );
    assert_eq!(resolver.key_count(), 2);

    assert!(resolver.remove_key(b"k1"));
    assert_eq!(resolver.key_count(), 1);

    assert!(!resolver.remove_key(b"nonexistent"));
    assert_eq!(resolver.key_count(), 1);
}

#[test]
fn test_static_resolver_wrong_key_fails() {
    let signing_key = Es256Algorithm::new_with_key_pair().unwrap();
    let wrong_key = Es256Algorithm::new_with_key_pair().unwrap();

    let token = CatTokenBuilder::new()
        .issuer("https://test.com")
        .expires_at(Utc::now() + Duration::hours(1))
        .build()
        .unwrap();
    let encoded = encode_token(&token, &signing_key).unwrap();

    let resolver = StaticKeyResolver::new(wrong_key);
    let result = decode_token_with_resolver(&encoded, &resolver);
    assert!(result.is_err());
}

#[test]
fn test_keyring_default_used_when_kid_absent() {
    let key = Es256Algorithm::new_with_key_pair().unwrap();
    let token = CatTokenBuilder::new()
        .issuer("https://test.com")
        .expires_at(Utc::now() + Duration::hours(1))
        .build()
        .unwrap();
    let encoded = encode_token(&token, &key).unwrap();

    let other_key = Es256Algorithm::new_with_key_pair().unwrap();
    let resolver = KeyRingResolver::new()
        .with_key(
            b"some-kid".to_vec(),
            Box::new(Es256Algorithm::new_verifier(*other_key.verifying_key())),
        )
        .with_default(Box::new(Es256Algorithm::new_verifier(*key.verifying_key())));

    let verified = decode_token_with_resolver(&encoded, &resolver).unwrap();
    let decoded = verified.into_unvalidated_token();
    assert_eq!(decoded.core.iss, Some("https://test.com".to_string()));
}

#[test]
fn test_resolver_full_pipeline() {
    let key = Es256Algorithm::new_with_key_pair().unwrap();
    let token = CatTokenBuilder::new()
        .issuer("https://auth.example.com")
        .audience(vec!["relay.example.com".to_string()])
        .expires_at(Utc::now() + Duration::hours(1))
        .build()
        .unwrap();
    let encoded = encode_token(&token, &key).unwrap();

    let resolver = StaticKeyResolver::new(Es256Algorithm::new_verifier(*key.verifying_key()));

    let verified = decode_token_with_resolver(&encoded, &resolver).unwrap();

    let validator = CatTokenValidator::new()
        .with_expected_issuers(vec!["https://auth.example.com".to_string()])
        .with_expected_audiences(vec!["relay.example.com".to_string()]);

    let validated = verified.validate(&validator).unwrap();
    assert_eq!(
        validated.claims().core.iss,
        Some("https://auth.example.com".to_string())
    );
}
