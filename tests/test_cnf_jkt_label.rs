// SPDX-FileCopyrightText: Copyright (c) 2022 Quicr
// SPDX-License-Identifier: BSD-2-Clause

use cat_token::*;

#[test]
fn test_cnf_jkt_label_is_323() {
    assert_eq!(CNF_JKT, 323, "CNF_JKT must be 323 per CTA-5007-B §4.8.1");
}

#[test]
fn test_cnf_jkt_legacy_label_is_3() {
    assert_eq!(CNF_JKT_LEGACY, 3);
}

#[test]
fn test_encoded_token_uses_label_323() {
    let key = HmacSha256Algorithm::generate_key().unwrap();
    let alg = HmacSha256Algorithm::from_secret_key(&key);

    let jkt_bytes = vec![0xAA; 32];
    let token = CatTokenBuilder::new()
        .issuer("https://example.com")
        .confirmation(jkt_bytes.clone())
        .build();

    let cose_bytes = encode_token(&token, &alg).unwrap();

    let value: ciborium::Value = ciborium::de::from_reader(cose_bytes.as_slice()).unwrap();
    let arr = match value {
        ciborium::Value::Tag(17, inner) => match *inner {
            ciborium::Value::Array(a) => a,
            _ => panic!("expected array"),
        },
        _ => panic!("expected COSE_Mac0 tag"),
    };

    let payload_cbor = match &arr[2] {
        ciborium::Value::Bytes(b) => b.clone(),
        _ => panic!("expected bytes"),
    };

    let payload: ciborium::Value = ciborium::de::from_reader(payload_cbor.as_slice()).unwrap();
    if let ciborium::Value::Map(map) = payload {
        for (k, v) in &map {
            if let ciborium::Value::Integer(ki) = k {
                let key_val: i64 = (*ki).try_into().unwrap();
                if key_val == 8 {
                    // cnf claim
                    if let ciborium::Value::Map(cnf_map) = v {
                        for (ck, _cv) in cnf_map {
                            if let ciborium::Value::Integer(cki) = ck {
                                let cnf_key: i64 = (*cki).try_into().unwrap();
                                assert_eq!(cnf_key, 323, "jkt must be encoded at label 323");
                                return;
                            }
                        }
                    }
                }
            }
        }
        panic!("cnf claim not found in payload");
    }
}

#[test]
fn test_decode_legacy_label_3() {
    let key = HmacSha256Algorithm::generate_key().unwrap();
    let alg = HmacSha256Algorithm::from_secret_key(&key);

    let jkt_bytes = vec![0xBB; 32];

    // Manually build a payload with cnf using legacy label 3
    let mut claims_map = std::collections::BTreeMap::new();
    claims_map.insert(
        1i64,
        ciborium::Value::Text("https://example.com".to_string()),
    );
    let cnf_map = vec![(
        ciborium::Value::Integer(3.into()), // legacy label
        ciborium::Value::Bytes(jkt_bytes.clone()),
    )];
    claims_map.insert(8i64, ciborium::Value::Map(cnf_map));

    let cbor_map: Vec<(ciborium::Value, ciborium::Value)> = claims_map
        .into_iter()
        .map(|(k, v)| (ciborium::Value::Integer(k.into()), v))
        .collect();

    let mut payload_buf = Vec::new();
    ciborium::ser::into_writer(&ciborium::Value::Map(cbor_map), &mut payload_buf).unwrap();

    // Build a proper COSE_Mac0 around it
    let mut header_map = std::collections::BTreeMap::new();
    header_map.insert(1i64, ciborium::Value::Integer(5.into()));
    let header_cbor_map: Vec<(ciborium::Value, ciborium::Value)> = header_map
        .into_iter()
        .map(|(k, v)| (ciborium::Value::Integer(k.into()), v))
        .collect();
    let mut header_buf = Vec::new();
    ciborium::ser::into_writer(&ciborium::Value::Map(header_cbor_map), &mut header_buf).unwrap();

    let signing_input =
        cat_token::crypto::create_signing_input(&header_buf, &payload_buf, ALG_HMAC256_256);
    let signature = alg.sign(&signing_input).unwrap();

    let cose_array = ciborium::Value::Array(vec![
        ciborium::Value::Bytes(header_buf),
        ciborium::Value::Map(vec![]),
        ciborium::Value::Bytes(payload_buf),
        ciborium::Value::Bytes(signature),
    ]);
    let tagged = ciborium::Value::Tag(17, Box::new(cose_array));
    let mut cose_bytes = Vec::new();
    ciborium::ser::into_writer(&tagged, &mut cose_bytes).unwrap();

    let decoded = decode_token(&cose_bytes, &alg).unwrap();
    assert!(decoded.dpop.cnf.is_some());
    assert_eq!(decoded.dpop.cnf.unwrap().jkt, jkt_bytes);
}

#[test]
fn test_roundtrip_with_label_323() {
    let key = HmacSha256Algorithm::generate_key().unwrap();
    let alg = HmacSha256Algorithm::from_secret_key(&key);

    let jkt_bytes = vec![0xCC; 32];
    let token = CatTokenBuilder::new()
        .issuer("https://example.com")
        .confirmation(jkt_bytes.clone())
        .build();

    let encoded = encode_token(&token, &alg).unwrap();
    let decoded = decode_token(&encoded, &alg).unwrap();
    assert_eq!(decoded.dpop.cnf.unwrap().jkt, jkt_bytes);
}
