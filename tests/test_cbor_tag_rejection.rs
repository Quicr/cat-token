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
fn test_tagged_iss_rejected() {
    let key = HmacSha256Algorithm::generate_key().unwrap();
    let alg = HmacSha256Algorithm::from_secret_key(&key);

    let mut claims = std::collections::BTreeMap::new();
    // Wrap iss value in a CBOR tag
    claims.insert(
        1i64,
        ciborium::Value::Tag(
            99,
            Box::new(ciborium::Value::Text("https://example.com".to_string())),
        ),
    );

    let cbor_map: Vec<(ciborium::Value, ciborium::Value)> = claims
        .into_iter()
        .map(|(k, v)| (ciborium::Value::Integer(k.into()), v))
        .collect();
    let mut payload_buf = Vec::new();
    ciborium::ser::into_writer(&ciborium::Value::Map(cbor_map), &mut payload_buf).unwrap();

    let cose_bytes = build_cose_mac0_with_payload(&payload_buf, &alg);
    let result = decode_token(&cose_bytes, &alg);
    assert!(result.is_err());
}

#[test]
fn test_tagged_exp_rejected() {
    let key = HmacSha256Algorithm::generate_key().unwrap();
    let alg = HmacSha256Algorithm::from_secret_key(&key);

    let mut claims = std::collections::BTreeMap::new();
    claims.insert(
        4i64,
        ciborium::Value::Tag(99, Box::new(ciborium::Value::Integer(1700000000.into()))),
    );

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
fn test_catnip_with_proper_tags_still_works() {
    let key = HmacSha256Algorithm::generate_key().unwrap();
    let alg = HmacSha256Algorithm::from_secret_key(&key);

    let token = CatTokenBuilder::new()
        .ip_address("192.168.1.1")
        .build();

    let encoded = encode_token(&token, &alg).unwrap();
    let decoded = decode_token(&encoded, &alg).unwrap();
    assert!(decoded.cat.catnip.is_some());
}

#[test]
fn test_catgeocoord_with_crs_wrapper_still_works() {
    let key = HmacSha256Algorithm::generate_key().unwrap();
    let alg = HmacSha256Algorithm::from_secret_key(&key);

    let token = CatTokenBuilder::new()
        .geo_coordinate(45.5, -90.5, Some(1000))
        .build();

    let encoded = encode_token(&token, &alg).unwrap();
    let decoded = decode_token(&encoded, &alg).unwrap();
    assert!(decoded.cat.catgeocoord.is_some());
}
