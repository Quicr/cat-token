// SPDX-FileCopyrightText: Copyright (c) 2022 Quicr
// SPDX-License-Identifier: BSD-2-Clause

use cat_token::*;
use chrono::{Duration, Utc};

#[test]
fn test_cose_sig_structure_es256() {
    let alg = Es256Algorithm::new_with_key_pair().unwrap();
    let token = CatTokenBuilder::new()
        .issuer("https://example.com")
        .expires_in(3600)
        .build();

    let encoded = encode_token(&token, &alg).unwrap();
    let decoded = decode_token(&encoded, &alg).unwrap();
    assert_eq!(decoded.core.iss, token.core.iss);
}

#[test]
fn test_cose_sig_structure_ps256() {
    let alg = Ps256Algorithm::new_with_key_pair().unwrap();
    let token = CatTokenBuilder::new()
        .issuer("https://example.com")
        .expires_in(3600)
        .build();

    let encoded = encode_token(&token, &alg).unwrap();
    let decoded = decode_token(&encoded, &alg).unwrap();
    assert_eq!(decoded.core.iss, token.core.iss);
}

#[test]
fn test_cose_mac0_structure_hmac() {
    let key = HmacSha256Algorithm::generate_key().unwrap();
    let alg = HmacSha256Algorithm::from_secret_key(&key);
    let token = CatTokenBuilder::new()
        .issuer("https://example.com")
        .expires_in(3600)
        .build();

    let encoded = encode_token(&token, &alg).unwrap();
    let decoded = decode_token(&encoded, &alg).unwrap();
    assert_eq!(decoded.core.iss, token.core.iss);
}

#[test]
fn test_cose_signing_input_is_cbor_array() {
    let header = vec![0xa1, 0x01, 0x26]; // {1: -7} (ES256)
    let payload = vec![0xa1, 0x01, 0x66, 0x69, 0x73, 0x73, 0x75, 0x65, 0x72]; // {1: "issuer"}

    let signing_input = crypto::create_signing_input(&header, &payload, ALG_ES256);

    // The signing input must be a valid CBOR array
    let value: ciborium::Value = ciborium::de::from_reader(signing_input.as_slice())
        .expect("signing input must be valid CBOR");

    match value {
        ciborium::Value::Array(arr) => {
            assert_eq!(arr.len(), 4, "COSE structure must have 4 elements");

            // Element 0: context string
            match &arr[0] {
                ciborium::Value::Text(s) => assert_eq!(s, "Signature1"),
                _ => panic!("Element 0 must be text"),
            }

            // Element 1: body_protected (bstr containing the header CBOR)
            match &arr[1] {
                ciborium::Value::Bytes(b) => assert_eq!(b, &header),
                _ => panic!("Element 1 must be bstr"),
            }

            // Element 2: external_aad (empty bstr)
            match &arr[2] {
                ciborium::Value::Bytes(b) => assert!(b.is_empty()),
                _ => panic!("Element 2 must be empty bstr"),
            }

            // Element 3: payload (bstr containing the payload CBOR)
            match &arr[3] {
                ciborium::Value::Bytes(b) => assert_eq!(b, &payload),
                _ => panic!("Element 3 must be bstr"),
            }
        }
        _ => panic!("Signing input must be a CBOR array"),
    }
}

#[test]
fn test_cose_mac0_context_string_for_hmac() {
    let header = vec![0xa1, 0x01, 0x05]; // {1: 5} (HMAC 256/256)
    let payload = vec![0xa0]; // empty map

    let signing_input = crypto::create_signing_input(&header, &payload, ALG_HMAC256_256);

    let value: ciborium::Value = ciborium::de::from_reader(signing_input.as_slice())
        .expect("signing input must be valid CBOR");

    match value {
        ciborium::Value::Array(arr) => {
            match &arr[0] {
                ciborium::Value::Text(s) => assert_eq!(s, "MAC0"),
                _ => panic!("Element 0 must be text"),
            }
        }
        _ => panic!("MAC input must be a CBOR array"),
    }
}

#[test]
fn test_cross_algorithm_signing_input_differs() {
    let header = vec![0xa0]; // empty map
    let payload = vec![0xa0]; // empty map

    let sig_input = crypto::create_signing_input(&header, &payload, ALG_ES256);
    let mac_input = crypto::create_signing_input(&header, &payload, ALG_HMAC256_256);

    // Different context strings mean different signing inputs
    assert_ne!(sig_input, mac_input);
}

#[test]
fn test_tampered_token_rejected_with_cose_structure() {
    let key = HmacSha256Algorithm::generate_key().unwrap();
    let alg = HmacSha256Algorithm::from_secret_key(&key);

    let token = CatTokenBuilder::new()
        .issuer("https://example.com")
        .audience(vec!["https://api.example.com".to_string()])
        .expires_at(Utc::now() + Duration::hours(1))
        .build();

    let encoded = encode_token(&token, &alg).unwrap();

    // Tamper with the payload (change a character in the base64 payload)
    let parts: Vec<&str> = encoded.split('.').collect();
    let tampered = format!("{}{}{}{}{}",
        parts[0], ".",
        "AAAA", // replaced payload
        ".", parts[2]
    );

    let result = decode_token(&tampered, &alg);
    assert!(result.is_err());
}

#[test]
fn test_wrong_key_rejected_with_cose_structure() {
    let key1 = HmacSha256Algorithm::generate_key().unwrap();
    let key2 = HmacSha256Algorithm::generate_key().unwrap();
    let alg1 = HmacSha256Algorithm::from_secret_key(&key1);
    let alg2 = HmacSha256Algorithm::from_secret_key(&key2);

    let token = CatTokenBuilder::new()
        .issuer("https://example.com")
        .build();

    let encoded = encode_token(&token, &alg1).unwrap();
    let result = decode_token(&encoded, &alg2);
    assert!(matches!(result, Err(CatError::SignatureVerificationFailed)));
}

#[test]
fn test_roundtrip_all_algorithms_with_cose() {
    let now = Utc::now();
    let token = CatTokenBuilder::new()
        .issuer("https://roundtrip.example.com")
        .audience(vec!["aud1".to_string(), "aud2".to_string()])
        .expires_at(now + Duration::hours(1))
        .not_before(now)
        .cwt_id("roundtrip-test")
        .subject("test-user")
        .build();

    // HMAC
    let hmac_key = HmacSha256Algorithm::generate_key().unwrap();
    let hmac_alg = HmacSha256Algorithm::from_secret_key(&hmac_key);
    let hmac_encoded = encode_token(&token, &hmac_alg).unwrap();
    let hmac_decoded = decode_token(&hmac_encoded, &hmac_alg).unwrap();
    assert_eq!(hmac_decoded.core.iss, token.core.iss);
    assert_eq!(hmac_decoded.core.aud, token.core.aud);
    assert_eq!(hmac_decoded.informational.sub, token.informational.sub);

    // ES256
    let es256_alg = Es256Algorithm::new_with_key_pair().unwrap();
    let es256_encoded = encode_token(&token, &es256_alg).unwrap();
    let es256_decoded = decode_token(&es256_encoded, &es256_alg).unwrap();
    assert_eq!(es256_decoded.core.iss, token.core.iss);
    assert_eq!(es256_decoded.core.aud, token.core.aud);

    // PS256
    let ps256_alg = Ps256Algorithm::new_with_key_pair().unwrap();
    let ps256_encoded = encode_token(&token, &ps256_alg).unwrap();
    let ps256_decoded = decode_token(&ps256_encoded, &ps256_alg).unwrap();
    assert_eq!(ps256_decoded.core.iss, token.core.iss);
    assert_eq!(ps256_decoded.core.aud, token.core.aud);
}
