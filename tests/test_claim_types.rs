// SPDX-FileCopyrightText: Copyright (c) 2022 Quicr
// SPDX-License-Identifier: BSD-2-Clause

use cat_token::*;

#[test]
fn test_catv_is_u32() {
    let token = CatToken::new().with_version(1);
    assert_eq!(token.cat.catv, Some(1));

    let cwt = Cwt::new(ALG_ES256, token);
    let payload = cwt.encode_payload().unwrap();
    let decoded = Cwt::decode_payload(&payload).unwrap();
    assert_eq!(decoded.cat.catv, Some(1));
}

#[test]
fn test_catv_roundtrip_encoding() {
    let token = CatToken::new().with_version(1);
    let cwt = Cwt::new(ALG_ES256, token);
    let payload = cwt.encode_payload().unwrap();

    let value: ciborium::Value = ciborium::de::from_reader(payload.as_slice()).unwrap();
    if let ciborium::Value::Map(map) = value {
        for (k, v) in &map {
            if let ciborium::Value::Integer(key_int) = k {
                let key_val: i64 = (*key_int).try_into().unwrap();
                if key_val == 310 {
                    // CLAIM_CATV
                    assert!(
                        matches!(v, ciborium::Value::Integer(_)),
                        "catv must encode as CBOR integer, got {:?}",
                        v
                    );
                    return;
                }
            }
        }
        panic!("catv claim not found in payload");
    }
}

#[test]
fn test_catreplay_enum_values() {
    assert_eq!(ReplayProtection::Permitted as u32, 0);
    assert_eq!(ReplayProtection::Prohibited as u32, 1);
    assert_eq!(ReplayProtection::ReuseDetection as u32, 2);
}

#[test]
fn test_catreplay_roundtrip() {
    for mode in [
        ReplayProtection::Permitted,
        ReplayProtection::Prohibited,
        ReplayProtection::ReuseDetection,
    ] {
        let token = CatToken::new().with_replay_protection(mode);
        let cwt = Cwt::new(ALG_ES256, token);
        let payload = cwt.encode_payload().unwrap();
        let decoded = Cwt::decode_payload(&payload).unwrap();
        assert_eq!(decoded.cat.catreplay, Some(mode));
    }
}

#[test]
fn test_catreplay_try_from_invalid() {
    assert!(ReplayProtection::try_from(3u32).is_err());
    assert!(ReplayProtection::try_from(255u32).is_err());
}

#[test]
fn test_catpor_structured_type() {
    let por = ProbabilityOfRejection {
        probability: 0.01,
        id: b"block-id-123".to_vec(),
        expiration: Some(1700000000),
    };

    let token = CatToken::new().with_probability_of_rejection(
        por.probability,
        por.id.clone(),
        por.expiration,
    );

    let cwt = Cwt::new(ALG_ES256, token);
    let payload = cwt.encode_payload().unwrap();
    let decoded = Cwt::decode_payload(&payload).unwrap();

    let decoded_por = decoded.cat.catpor.unwrap();
    assert_eq!(decoded_por.probability, 0.01);
    assert_eq!(decoded_por.id, b"block-id-123".to_vec());
    assert_eq!(decoded_por.expiration, Some(1700000000));
}

#[test]
fn test_catpor_without_expiration() {
    let token =
        CatToken::new().with_probability_of_rejection(0.05, b"test-id".to_vec(), None);
    let cwt = Cwt::new(ALG_ES256, token);
    let payload = cwt.encode_payload().unwrap();
    let decoded = Cwt::decode_payload(&payload).unwrap();

    let decoded_por = decoded.cat.catpor.unwrap();
    assert_eq!(decoded_por.probability, 0.05);
    assert_eq!(decoded_por.id, b"test-id".to_vec());
    assert_eq!(decoded_por.expiration, None);
}

#[test]
fn test_catm_is_vec_string() {
    let mut token = CatToken::new();
    token.cat.catm = Some(vec![
        "GET".to_string(),
        "POST".to_string(),
        "PUT".to_string(),
    ]);

    let cwt = Cwt::new(ALG_ES256, token);
    let payload = cwt.encode_payload().unwrap();
    let decoded = Cwt::decode_payload(&payload).unwrap();

    assert_eq!(
        decoded.cat.catm,
        Some(vec![
            "GET".to_string(),
            "POST".to_string(),
            "PUT".to_string()
        ])
    );
}

#[test]
fn test_catgeoalt_is_altitude_deviation_pair() {
    let mut token = CatToken::new();
    token.cat.catgeoalt = Some(GeoAltitude {
        altitude: 150.5,
        deviation: 10.0,
    });

    let cwt = Cwt::new(ALG_ES256, token);
    let payload = cwt.encode_payload().unwrap();
    let decoded = Cwt::decode_payload(&payload).unwrap();

    let alt = decoded.cat.catgeoalt.unwrap();
    assert_eq!(alt.altitude, 150.5);
    assert_eq!(alt.deviation, 10.0);
}

#[test]
fn test_catgeoalt_cbor_is_array() {
    let mut token = CatToken::new();
    token.cat.catgeoalt = Some(GeoAltitude {
        altitude: 100.0,
        deviation: 5.0,
    });

    let cwt = Cwt::new(ALG_ES256, token);
    let payload = cwt.encode_payload().unwrap();

    let value: ciborium::Value = ciborium::de::from_reader(payload.as_slice()).unwrap();
    if let ciborium::Value::Map(map) = value {
        for (k, v) in &map {
            if let ciborium::Value::Integer(key_int) = k {
                let key_val: i64 = (*key_int).try_into().unwrap();
                if key_val == 318 {
                    // CLAIM_CATGEOALT
                    match v {
                        ciborium::Value::Array(arr) => {
                            assert_eq!(arr.len(), 2, "catgeoalt must be [altitude, deviation]");
                        }
                        _ => panic!("catgeoalt must encode as CBOR array, got {:?}", v),
                    }
                    return;
                }
            }
        }
        panic!("catgeoalt claim not found");
    }
}

#[test]
fn test_cattpk_is_bytes() {
    let der_bytes = vec![0x30, 0x59, 0x30, 0x13]; // beginning of DER-encoded SPKI
    let mut token = CatToken::new();
    token.cat.cattpk = Some(der_bytes.clone());

    let cwt = Cwt::new(ALG_ES256, token);
    let payload = cwt.encode_payload().unwrap();
    let decoded = Cwt::decode_payload(&payload).unwrap();

    assert_eq!(decoded.cat.cattpk, Some(der_bytes));
}

#[test]
fn test_cattpk_cbor_is_bstr() {
    let mut token = CatToken::new();
    token.cat.cattpk = Some(vec![0x01, 0x02, 0x03]);

    let cwt = Cwt::new(ALG_ES256, token);
    let payload = cwt.encode_payload().unwrap();

    let value: ciborium::Value = ciborium::de::from_reader(payload.as_slice()).unwrap();
    if let ciborium::Value::Map(map) = value {
        for (k, v) in &map {
            if let ciborium::Value::Integer(key_int) = k {
                let key_val: i64 = (*key_int).try_into().unwrap();
                if key_val == 319 {
                    // CLAIM_CATTPK
                    assert!(
                        matches!(v, ciborium::Value::Bytes(_)),
                        "cattpk must encode as CBOR bstr, got {:?}",
                        v
                    );
                    return;
                }
            }
        }
        panic!("cattpk claim not found");
    }
}

#[test]
fn test_full_roundtrip_with_all_fixed_claim_types() {
    let key = HmacSha256Algorithm::generate_key().unwrap();
    let alg = HmacSha256Algorithm::from_secret_key(&key);

    let token = CatTokenBuilder::new()
        .issuer("https://example.com")
        .version(1)
        .replay_protection(ReplayProtection::ReuseDetection)
        .probability_of_rejection(0.02, b"block-list-1".to_vec(), Some(1700000000))
        .expires_in(3600)
        .build();

    let encoded = encode_token(&token, &alg).unwrap();
    let decoded = decode_token(&encoded, &alg).unwrap();

    assert_eq!(decoded.cat.catv, Some(1));
    assert_eq!(
        decoded.cat.catreplay,
        Some(ReplayProtection::ReuseDetection)
    );
    let por = decoded.cat.catpor.unwrap();
    assert_eq!(por.probability, 0.02);
    assert_eq!(por.id, b"block-list-1".to_vec());
    assert_eq!(por.expiration, Some(1700000000));
}
