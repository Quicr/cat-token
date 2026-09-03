// SPDX-FileCopyrightText: Copyright (c) 2022 Quicr
// SPDX-License-Identifier: BSD-2-Clause

use cat_token::*;

#[test]
fn test_catv_version_1_passes() {
    let token = CatTokenBuilder::new().version(1).build();
    let validator = CatTokenValidator::new();
    assert!(validator.validate(&token).is_ok());
}

#[test]
fn test_catv_version_2_rejected() {
    let token = CatTokenBuilder::new().version(2).build();
    let validator = CatTokenValidator::new();
    let err = validator.validate(&token).unwrap_err();
    assert!(matches!(err, CatError::InvalidClaimValue(_)));
}

#[test]
fn test_catv_version_0_rejected() {
    let token = CatTokenBuilder::new().version(0).build();
    let validator = CatTokenValidator::new();
    assert!(validator.validate(&token).is_err());
}

#[test]
fn test_catv_absent_passes() {
    let token = CatTokenBuilder::new().build();
    let validator = CatTokenValidator::new();
    assert!(validator.validate(&token).is_ok());
}

#[test]
fn test_catm_50_methods_accepted() {
    let key = HmacSha256Algorithm::generate_key().unwrap();
    let alg = HmacSha256Algorithm::from_secret_key(&key);

    let methods: Vec<String> = (0..50).map(|i| format!("METHOD{i}")).collect();
    let token = CatToken {
        cat: CatClaims {
            catm: Some(methods),
            ..Default::default()
        },
        ..CatToken::new()
    };

    let encoded = encode_token(&token, &alg).unwrap();
    assert!(decode_token(&encoded, &alg).is_ok());
}

#[test]
fn test_catm_51_methods_rejected() {
    let key = HmacSha256Algorithm::generate_key().unwrap();
    let alg = HmacSha256Algorithm::from_secret_key(&key);

    let methods: Vec<String> = (0..51).map(|i| format!("METHOD{i}")).collect();
    let token = CatToken {
        cat: CatClaims {
            catm: Some(methods),
            ..Default::default()
        },
        ..CatToken::new()
    };

    let encoded = encode_token(&token, &alg).unwrap();
    let result = decode_token(&encoded, &alg);
    assert!(result.is_err());
}

#[test]
fn test_catalpn_50_entries_accepted() {
    let key = HmacSha256Algorithm::generate_key().unwrap();
    let alg = HmacSha256Algorithm::from_secret_key(&key);

    let alpns: Vec<Vec<u8>> = (0..50).map(|i| format!("alpn{i}").into_bytes()).collect();
    let token = CatToken {
        cat: CatClaims {
            catalpn: Some(alpns),
            ..Default::default()
        },
        ..CatToken::new()
    };

    let encoded = encode_token(&token, &alg).unwrap();
    assert!(decode_token(&encoded, &alg).is_ok());
}

#[test]
fn test_catalpn_51_entries_rejected() {
    let key = HmacSha256Algorithm::generate_key().unwrap();
    let alg = HmacSha256Algorithm::from_secret_key(&key);

    let alpns: Vec<Vec<u8>> = (0..51).map(|i| format!("alpn{i}").into_bytes()).collect();
    let token = CatToken {
        cat: CatClaims {
            catalpn: Some(alpns),
            ..Default::default()
        },
        ..CatToken::new()
    };

    let encoded = encode_token(&token, &alg).unwrap();
    let result = decode_token(&encoded, &alg);
    assert!(result.is_err());
}
