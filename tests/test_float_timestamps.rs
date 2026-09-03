// SPDX-FileCopyrightText: Copyright (c) 2022 Quicr
// SPDX-License-Identifier: BSD-2-Clause

use cat_token::*;

fn build_cose_mac0_with_payload(payload_cbor: &[u8], alg: &HmacSha256Algorithm) -> Vec<u8> {
    let mut header_map = std::collections::BTreeMap::new();
    header_map.insert(1i64, ciborium::Value::Integer(5.into()));
    let header_cbor_map: Vec<(ciborium::Value, ciborium::Value)> = header_map
        .into_iter()
        .map(|(k, v)| (ciborium::Value::Integer(k.into()), v))
        .collect();
    let mut header_buf = Vec::new();
    ciborium::ser::into_writer(&ciborium::Value::Map(header_cbor_map), &mut header_buf).unwrap();

    let signing_input = crypto::create_signing_input(&header_buf, payload_cbor, ALG_HMAC256_256);
    let signature = alg.sign(&signing_input).unwrap();

    let cose_array = ciborium::Value::Array(vec![
        ciborium::Value::Bytes(header_buf),
        ciborium::Value::Map(vec![]),
        ciborium::Value::Bytes(payload_cbor.to_vec()),
        ciborium::Value::Bytes(signature),
    ]);
    let tagged = ciborium::Value::Tag(17, Box::new(cose_array));
    let mut buf = Vec::new();
    ciborium::ser::into_writer(&tagged, &mut buf).unwrap();
    buf
}

#[test]
fn test_float_exp_decoded() {
    let key = HmacSha256Algorithm::generate_key().unwrap();
    let alg = HmacSha256Algorithm::from_secret_key(&key);

    let ts = 1700000000.75_f64;
    let mut claims = std::collections::BTreeMap::new();
    claims.insert(1i64, ciborium::Value::Text("iss".to_string()));
    claims.insert(4i64, ciborium::Value::Float(ts));

    let cbor_map: Vec<(ciborium::Value, ciborium::Value)> = claims
        .into_iter()
        .map(|(k, v)| (ciborium::Value::Integer(k.into()), v))
        .collect();
    let mut payload_buf = Vec::new();
    ciborium::ser::into_writer(&ciborium::Value::Map(cbor_map), &mut payload_buf).unwrap();

    let cose_bytes = build_cose_mac0_with_payload(&payload_buf, &alg);
    let decoded = decode_token(&cose_bytes, &alg).unwrap();
    assert_eq!(decoded.core.exp, Some(1700000000));
}

#[test]
fn test_float_nbf_decoded() {
    let key = HmacSha256Algorithm::generate_key().unwrap();
    let alg = HmacSha256Algorithm::from_secret_key(&key);

    let mut claims = std::collections::BTreeMap::new();
    claims.insert(1i64, ciborium::Value::Text("iss".to_string()));
    claims.insert(5i64, ciborium::Value::Float(1700000000.5));

    let cbor_map: Vec<(ciborium::Value, ciborium::Value)> = claims
        .into_iter()
        .map(|(k, v)| (ciborium::Value::Integer(k.into()), v))
        .collect();
    let mut payload_buf = Vec::new();
    ciborium::ser::into_writer(&ciborium::Value::Map(cbor_map), &mut payload_buf).unwrap();

    let cose_bytes = build_cose_mac0_with_payload(&payload_buf, &alg);
    let decoded = decode_token(&cose_bytes, &alg).unwrap();
    assert_eq!(decoded.core.nbf, Some(1700000000));
}

#[test]
fn test_float_iat_decoded() {
    let key = HmacSha256Algorithm::generate_key().unwrap();
    let alg = HmacSha256Algorithm::from_secret_key(&key);

    let mut claims = std::collections::BTreeMap::new();
    claims.insert(1i64, ciborium::Value::Text("iss".to_string()));
    claims.insert(6i64, ciborium::Value::Float(1700000000.9));

    let cbor_map: Vec<(ciborium::Value, ciborium::Value)> = claims
        .into_iter()
        .map(|(k, v)| (ciborium::Value::Integer(k.into()), v))
        .collect();
    let mut payload_buf = Vec::new();
    ciborium::ser::into_writer(&ciborium::Value::Map(cbor_map), &mut payload_buf).unwrap();

    let cose_bytes = build_cose_mac0_with_payload(&payload_buf, &alg);
    let decoded = decode_token(&cose_bytes, &alg).unwrap();
    assert_eq!(decoded.informational.iat, Some(1700000000));
}

#[test]
fn test_nan_timestamp_rejected() {
    let key = HmacSha256Algorithm::generate_key().unwrap();
    let alg = HmacSha256Algorithm::from_secret_key(&key);

    let mut claims = std::collections::BTreeMap::new();
    claims.insert(1i64, ciborium::Value::Text("iss".to_string()));
    claims.insert(4i64, ciborium::Value::Float(f64::NAN));

    let cbor_map: Vec<(ciborium::Value, ciborium::Value)> = claims
        .into_iter()
        .map(|(k, v)| (ciborium::Value::Integer(k.into()), v))
        .collect();
    let mut payload_buf = Vec::new();
    ciborium::ser::into_writer(&ciborium::Value::Map(cbor_map), &mut payload_buf).unwrap();

    let cose_bytes = build_cose_mac0_with_payload(&payload_buf, &alg);
    assert!(decode_token(&cose_bytes, &alg).is_err());
}

#[test]
fn test_negative_zero_timestamp_rejected() {
    let key = HmacSha256Algorithm::generate_key().unwrap();
    let alg = HmacSha256Algorithm::from_secret_key(&key);

    let mut claims = std::collections::BTreeMap::new();
    claims.insert(1i64, ciborium::Value::Text("iss".to_string()));
    claims.insert(5i64, ciborium::Value::Float(-0.0));

    let cbor_map: Vec<(ciborium::Value, ciborium::Value)> = claims
        .into_iter()
        .map(|(k, v)| (ciborium::Value::Integer(k.into()), v))
        .collect();
    let mut payload_buf = Vec::new();
    ciborium::ser::into_writer(&ciborium::Value::Map(cbor_map), &mut payload_buf).unwrap();

    let cose_bytes = build_cose_mac0_with_payload(&payload_buf, &alg);
    assert!(decode_token(&cose_bytes, &alg).is_err());
}
