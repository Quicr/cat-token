// SPDX-FileCopyrightText: Copyright (c) 2022 Quicr
// SPDX-License-Identifier: BSD-2-Clause

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use cat_token::*;

#[test]
fn test_hmac_alg_id_is_5() {
    assert_eq!(ALG_HMAC256_256, 5, "HMAC 256/256 must use COSE alg ID 5 per RFC 9053");
}

#[test]
fn test_es256_alg_id_is_negative_7() {
    assert_eq!(ALG_ES256, -7);
}

#[test]
fn test_ps256_alg_id_is_negative_37() {
    assert_eq!(ALG_PS256, -37);
}

#[test]
fn test_hmac_algorithm_reports_correct_id() {
    let key = HmacSha256Algorithm::generate_key().unwrap();
    let alg = HmacSha256Algorithm::from_secret_key(&key);
    assert_eq!(alg.algorithm_id(), 5);
}

#[test]
fn test_hmac_token_header_contains_alg_5() {
    let key = HmacSha256Algorithm::generate_key().unwrap();
    let alg = HmacSha256Algorithm::from_secret_key(&key);

    let token = CatTokenBuilder::new()
        .issuer("https://example.com")
        .build();

    let encoded = encode_token(&token, &alg).unwrap();
    let parts: Vec<&str> = encoded.split('.').collect();
    let header_cbor = URL_SAFE_NO_PAD.decode(parts[0]).unwrap();

    let value: ciborium::Value = ciborium::de::from_reader(header_cbor.as_slice()).unwrap();
    if let ciborium::Value::Map(map) = value {
        for (k, v) in &map {
            if let ciborium::Value::Integer(key_int) = k {
                let key_val: i64 = (*key_int).try_into().unwrap();
                if key_val == 1 {
                    // alg header parameter
                    if let ciborium::Value::Integer(alg_val) = v {
                        let alg_id: i64 = (*alg_val).try_into().unwrap();
                        assert_eq!(alg_id, 5, "HMAC header must contain alg=5");
                        return;
                    }
                }
            }
        }
        panic!("alg header parameter not found");
    } else {
        panic!("header must be a CBOR map");
    }
}

#[test]
fn test_cose_jose_algorithm_mapping() {
    assert_eq!(crypto::cose_to_jose_algorithm(5), Some("HS256"));
    assert_eq!(crypto::cose_to_jose_algorithm(-7), Some("ES256"));
    assert_eq!(crypto::cose_to_jose_algorithm(-37), Some("PS256"));
    assert_eq!(crypto::cose_to_jose_algorithm(999), None);

    assert_eq!(crypto::jose_to_cose_algorithm("HS256"), Some(5));
    assert_eq!(crypto::jose_to_cose_algorithm("ES256"), Some(-7));
    assert_eq!(crypto::jose_to_cose_algorithm("PS256"), Some(-37));
    assert_eq!(crypto::jose_to_cose_algorithm("unknown"), None);
}
