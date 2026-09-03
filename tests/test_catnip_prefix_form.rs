// SPDX-FileCopyrightText: Copyright (c) 2022 Quicr
// SPDX-License-Identifier: BSD-2-Clause

use cat_token::*;

#[test]
fn test_valid_prefix_form_accepted() {
    let key = HmacSha256Algorithm::generate_key().unwrap();
    let alg = HmacSha256Algorithm::from_secret_key(&key);

    let token = CatTokenBuilder::new().ip_range("192.168.0.0/16").build();

    let encoded = encode_token(&token, &alg).unwrap();
    let decoded = decode_token(&encoded, &alg).unwrap();
    assert!(decoded.cat.catnip.is_some());
}

#[test]
fn test_address_with_prefix_form_rejected() {
    let key = HmacSha256Algorithm::generate_key().unwrap();
    let alg = HmacSha256Algorithm::from_secret_key(&key);

    // Manually build a COSE_Mac0 with a catnip containing address-with-prefix form:
    // prefix length /8 but 4 bytes (full address) instead of 1 byte
    let mut claims = std::collections::BTreeMap::new();
    let nip_array = ciborium::Value::Array(vec![ciborium::Value::Tag(
        52,
        Box::new(ciborium::Value::Map(vec![(
            ciborium::Value::Integer(8.into()), // /8 prefix
            ciborium::Value::Bytes(vec![192, 168, 1, 1]), // 4 bytes = address-with-prefix form
        )])),
    )]);
    claims.insert(311i64, nip_array);

    let cbor_map: Vec<(ciborium::Value, ciborium::Value)> = claims
        .into_iter()
        .map(|(k, v)| (ciborium::Value::Integer(k.into()), v))
        .collect();
    let mut payload_buf = Vec::new();
    ciborium::ser::into_writer(&ciborium::Value::Map(cbor_map), &mut payload_buf).unwrap();

    let mut header_map = std::collections::BTreeMap::new();
    header_map.insert(1i64, ciborium::Value::Integer(5.into()));
    let header_cbor_map: Vec<(ciborium::Value, ciborium::Value)> = header_map
        .into_iter()
        .map(|(k, v)| (ciborium::Value::Integer(k.into()), v))
        .collect();
    let mut header_buf = Vec::new();
    ciborium::ser::into_writer(&ciborium::Value::Map(header_cbor_map), &mut header_buf).unwrap();

    let signing_input =
        crypto::create_signing_input(&header_buf, &payload_buf, ALG_HMAC256_256);
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

    let result = decode_token(&cose_bytes, &alg);
    assert!(result.is_err(), "address-with-prefix form must be rejected");
}

#[test]
fn test_ipv6_address_with_prefix_form_rejected() {
    let key = HmacSha256Algorithm::generate_key().unwrap();
    let alg = HmacSha256Algorithm::from_secret_key(&key);

    // /48 prefix with 16 bytes (full address) instead of 6 bytes
    let mut claims = std::collections::BTreeMap::new();
    let nip_array = ciborium::Value::Array(vec![ciborium::Value::Tag(
        54,
        Box::new(ciborium::Value::Map(vec![(
            ciborium::Value::Integer(48.into()),
            ciborium::Value::Bytes(vec![0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
        )])),
    )]);
    claims.insert(311i64, nip_array);

    let cbor_map: Vec<(ciborium::Value, ciborium::Value)> = claims
        .into_iter()
        .map(|(k, v)| (ciborium::Value::Integer(k.into()), v))
        .collect();
    let mut payload_buf = Vec::new();
    ciborium::ser::into_writer(&ciborium::Value::Map(cbor_map), &mut payload_buf).unwrap();

    let mut header_map = std::collections::BTreeMap::new();
    header_map.insert(1i64, ciborium::Value::Integer(5.into()));
    let header_cbor_map: Vec<(ciborium::Value, ciborium::Value)> = header_map
        .into_iter()
        .map(|(k, v)| (ciborium::Value::Integer(k.into()), v))
        .collect();
    let mut header_buf = Vec::new();
    ciborium::ser::into_writer(&ciborium::Value::Map(header_cbor_map), &mut header_buf).unwrap();

    let signing_input =
        crypto::create_signing_input(&header_buf, &payload_buf, ALG_HMAC256_256);
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

    assert!(decode_token(&cose_bytes, &alg).is_err());
}
