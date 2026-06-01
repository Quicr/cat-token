// SPDX-FileCopyrightText: Copyright (c) 2022 Quicr
// SPDX-License-Identifier: BSD-2-Clause

use cat_token::moqt::{C4M_TOKEN_TYPE, MoqtAuthRequest, MoqtScopeBuilder, MoqtValidator};
use cat_token::*;

// --- CatTokenBuilder::expires_in ---

#[test]
fn test_expires_in_creates_future_expiration() {
    let key = Es256Algorithm::new_with_key_pair().unwrap();
    let token = CatTokenBuilder::new()
        .issuer("test")
        .single_audience("relay")
        .expires_in(3600)
        .build();

    let encoded = encode_token(&token, &key).unwrap();
    let decoded = decode_token(&encoded, &key).unwrap();

    // Token should be valid (exp is in the future)
    let validator = CatTokenValidator::new()
        .with_expected_issuers(vec!["test".to_string()])
        .with_expected_audiences(vec!["relay".to_string()]);
    assert!(validator.validate(&decoded).is_ok());
}

#[test]
fn test_expires_in_negative_already_expired() {
    let key = Es256Algorithm::new_with_key_pair().unwrap();
    let token = CatTokenBuilder::new()
        .issuer("test")
        .single_audience("relay")
        .expires_in(-10)
        .build();

    let encoded = encode_token(&token, &key).unwrap();
    let decoded = decode_token(&encoded, &key).unwrap();

    let validator = CatTokenValidator::new().with_clock_skew_tolerance(0);
    assert!(matches!(
        validator.validate(&decoded),
        Err(CatError::TokenExpired)
    ));
}

// --- CatTokenBuilder::single_audience ---

#[test]
fn test_single_audience_convenience() {
    let key = Es256Algorithm::new_with_key_pair().unwrap();
    let token = CatTokenBuilder::new()
        .issuer("issuer")
        .single_audience("my-relay")
        .expires_in(3600)
        .build();

    let encoded = encode_token(&token, &key).unwrap();
    let decoded = decode_token(&encoded, &key).unwrap();

    let validator = CatTokenValidator::new().with_expected_audiences(vec!["my-relay".to_string()]);
    assert!(validator.validate(&decoded).is_ok());

    let validator_wrong =
        CatTokenValidator::new().with_expected_audiences(vec!["other-relay".to_string()]);
    assert!(matches!(
        validator_wrong.validate(&decoded),
        Err(CatError::InvalidAudience)
    ));
}

// --- decode_token_bytes ---

#[test]
fn test_decode_token_bytes_valid() {
    let key = Es256Algorithm::new_with_key_pair().unwrap();
    let token = CatTokenBuilder::new()
        .issuer("test-issuer")
        .single_audience("relay")
        .subject("user-1")
        .expires_in(3600)
        .build();

    let encoded = encode_token(&token, &key).unwrap();
    let decoded = decode_token_bytes(encoded.as_bytes(), &key).unwrap();

    assert_eq!(decoded.informational.sub.as_deref(), Some("user-1"));
}

#[test]
fn test_decode_token_bytes_invalid_utf8() {
    let key = Es256Algorithm::new_with_key_pair().unwrap();
    let invalid_bytes: &[u8] = &[0xFF, 0xFE, 0xFD];

    let result = decode_token_bytes(invalid_bytes, &key);
    assert!(matches!(result, Err(CatError::InvalidTokenFormat)));
}

#[test]
fn test_decode_token_bytes_malformed() {
    let key = Es256Algorithm::new_with_key_pair().unwrap();
    let malformed = b"not.a.valid.token.at.all";

    let result = decode_token_bytes(malformed, &key);
    assert!(result.is_err());
}

// --- Es256Algorithm::from_public_key_pem / from_public_key_der ---

#[test]
fn test_from_public_key_pem_roundtrip() {
    use p256::pkcs8::EncodePublicKey;

    let key_pair = Es256Algorithm::new_with_key_pair().unwrap();
    let pem = key_pair
        .verifying_key()
        .to_public_key_pem(p256::pkcs8::LineEnding::LF)
        .unwrap();

    let verifier = Es256Algorithm::from_public_key_pem(&pem).unwrap();

    // Sign with original, verify with PEM-loaded key
    let token = CatTokenBuilder::new()
        .issuer("pem-test")
        .expires_in(3600)
        .build();

    let encoded = encode_token(&token, &key_pair).unwrap();
    let decoded = decode_token(&encoded, &verifier).unwrap();
    assert_eq!(decoded.core.iss.as_deref(), Some("pem-test"));
}

#[test]
fn test_from_public_key_pem_invalid() {
    let result = Es256Algorithm::from_public_key_pem("not a valid pem");
    assert!(result.is_err());
}

#[test]
fn test_from_public_key_der_roundtrip() {
    use p256::pkcs8::EncodePublicKey;

    let key_pair = Es256Algorithm::new_with_key_pair().unwrap();
    let der = key_pair.verifying_key().to_public_key_der().unwrap();

    let verifier = Es256Algorithm::from_public_key_der(der.as_bytes()).unwrap();

    let token = CatTokenBuilder::new()
        .issuer("der-test")
        .expires_in(3600)
        .build();

    let encoded = encode_token(&token, &key_pair).unwrap();
    let decoded = decode_token(&encoded, &verifier).unwrap();
    assert_eq!(decoded.core.iss.as_deref(), Some("der-test"));
}

#[test]
fn test_from_public_key_der_invalid() {
    let result = Es256Algorithm::from_public_key_der(&[0, 1, 2, 3]);
    assert!(result.is_err());
}

// --- Es256VerifyingKey re-export ---

#[test]
fn test_verifying_key_reexport() {
    let key_pair = Es256Algorithm::new_with_key_pair().unwrap();
    // This proves Es256VerifyingKey is usable from the public API
    let vk: &Es256VerifyingKey = key_pair.verifying_key();
    let verifier = Es256Algorithm::new_verifier(vk.clone());

    let token = CatTokenBuilder::new()
        .issuer("reexport-test")
        .expires_in(60)
        .build();

    let encoded = encode_token(&token, &key_pair).unwrap();
    assert!(decode_token(&encoded, &verifier).is_ok());
}

// --- MoqtScopeBuilder::namespace_path ---

#[test]
fn test_namespace_path_splits_by_slash() {
    let scope = MoqtScopeBuilder::new()
        .publisher()
        .namespace_path(b"sports/football/live")
        .track_prefix(b"")
        .build();

    let token = CatTokenBuilder::new()
        .issuer("test")
        .moqt_scope(scope)
        .build();

    let validator = MoqtValidator::new();

    // Exact match on all 3 elements
    let request = MoqtAuthRequest::new(
        MoqtAction::Publish,
        vec![b"sports".to_vec(), b"football".to_vec(), b"live".to_vec()],
        b"video".to_vec(),
    );
    assert!(validator.authorize(&token, &request).authorized);

    // Wrong first element
    let request = MoqtAuthRequest::new(
        MoqtAction::Publish,
        vec![b"music".to_vec(), b"football".to_vec(), b"live".to_vec()],
        b"video".to_vec(),
    );
    assert!(!validator.authorize(&token, &request).authorized);

    // Wrong second element
    let request = MoqtAuthRequest::new(
        MoqtAction::Publish,
        vec![b"sports".to_vec(), b"basketball".to_vec(), b"live".to_vec()],
        b"video".to_vec(),
    );
    assert!(!validator.authorize(&token, &request).authorized);
}

#[test]
fn test_namespace_path_ignores_empty_segments() {
    let scope = MoqtScopeBuilder::new()
        .publisher()
        .namespace_path(b"/sports//football/")
        .track_prefix(b"")
        .build();

    let token = CatTokenBuilder::new()
        .issuer("test")
        .moqt_scope(scope)
        .build();

    let validator = MoqtValidator::new();

    // Should only match ["sports", "football"] (empty segments ignored)
    let request = MoqtAuthRequest::new(
        MoqtAction::Publish,
        vec![b"sports".to_vec(), b"football".to_vec()],
        b"video".to_vec(),
    );
    assert!(validator.authorize(&token, &request).authorized);
}

// --- MoqtScopeBuilder::namespace_path tuple-prefix semantics ---

#[test]
fn test_namespace_path_allows_additional_trailing_elements() {
    // namespace_path(b"sports/football") should match requests with
    // more tuple elements like ["sports", "football", "spain"]
    let scope = MoqtScopeBuilder::new()
        .publisher()
        .namespace_path(b"sports/football")
        .track_prefix(b"")
        .build();

    let token = CatTokenBuilder::new()
        .issuer("test")
        .moqt_scope(scope)
        .build();

    let validator = MoqtValidator::new();

    // Exact 2-element match
    let request = MoqtAuthRequest::new(
        MoqtAction::Publish,
        vec![b"sports".to_vec(), b"football".to_vec()],
        b"video".to_vec(),
    );
    assert!(validator.authorize(&token, &request).authorized);

    // 3 elements — trailing "spain" is allowed (tuple-prefix semantics)
    let request = MoqtAuthRequest::new(
        MoqtAction::Publish,
        vec![b"sports".to_vec(), b"football".to_vec(), b"spain".to_vec()],
        b"video".to_vec(),
    );
    assert!(validator.authorize(&token, &request).authorized);

    // Partial byte match on a tuple element must NOT work
    let request = MoqtAuthRequest::new(
        MoqtAction::Publish,
        vec![b"sports".to_vec(), b"foot".to_vec()],
        b"video".to_vec(),
    );
    assert!(!validator.authorize(&token, &request).authorized);
}

// --- C4M_TOKEN_TYPE constant ---

#[test]
fn test_c4m_token_type_value() {
    // "c4m" = 0x63 ('c'), 0x34 ('4'), 0x6d ('m') → 0x63346d
    assert_eq!(C4M_TOKEN_TYPE, 0x63346d);
    assert_eq!(
        C4M_TOKEN_TYPE,
        (b'c' as u64) << 16 | (b'4' as u64) << 8 | (b'm' as u64)
    );
}

// --- Full round-trip with new APIs ---

#[test]
fn test_full_roundtrip_new_apis() {
    let key_pair = Es256Algorithm::new_with_key_pair().unwrap();

    // Use from_public_key_pem to load verifier
    use p256::pkcs8::EncodePublicKey;
    let pem = key_pair
        .verifying_key()
        .to_public_key_pem(p256::pkcs8::LineEnding::LF)
        .unwrap();
    let verifier = Es256Algorithm::from_public_key_pem(&pem).unwrap();

    // Build token with new convenience methods
    let scope = MoqtScopeBuilder::new()
        .publisher()
        .namespace_path(b"live/sports/football")
        .track_prefix(b"")
        .build();

    let setup_scope = MoqtScopeBuilder::new()
        .action(MoqtAction::ClientSetup)
        .build();

    let token = CatTokenBuilder::new()
        .issuer("auth-server")
        .single_audience("relay-01")
        .subject("publisher-42")
        .expires_in(7200)
        .moqt_scope(scope)
        .moqt_scope(setup_scope)
        .build();

    // Encode with signing key, decode with PEM-loaded verifier
    let encoded = encode_token(&token, &key_pair).unwrap();
    let decoded = decode_token_bytes(encoded.as_bytes(), &verifier).unwrap();

    // Validate standard claims
    let validator = CatTokenValidator::new()
        .with_expected_issuers(vec!["auth-server".to_string()])
        .with_expected_audiences(vec!["relay-01".to_string()]);
    assert!(validator.validate(&decoded).is_ok());

    // Authorize operations
    let moqt_validator = MoqtValidator::new();

    let setup_req = MoqtAuthRequest::new(MoqtAction::ClientSetup, vec![], vec![]);
    assert!(moqt_validator.authorize(&decoded, &setup_req).authorized);

    let publish_req = MoqtAuthRequest::new(
        MoqtAction::Publish,
        vec![b"live".to_vec(), b"sports".to_vec(), b"football".to_vec()],
        b"video-1080p".to_vec(),
    );
    assert!(moqt_validator.authorize(&decoded, &publish_req).authorized);

    // Subscribe should be denied (publisher token)
    let sub_req = MoqtAuthRequest::new(
        MoqtAction::Subscribe,
        vec![b"live".to_vec(), b"sports".to_vec(), b"football".to_vec()],
        b"video-1080p".to_vec(),
    );
    assert!(!moqt_validator.authorize(&decoded, &sub_req).authorized);
}
