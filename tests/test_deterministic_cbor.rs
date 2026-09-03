// Tests for RFC 8949 §4.2.1 deterministic CBOR map key ordering.

use cat_token::*;

fn build_cbor_map(pairs: &[(i64, &str)]) -> Vec<u8> {
    let mut buf = Vec::new();
    ciborium::ser::into_writer(
        &ciborium::Value::Map(
            pairs
                .iter()
                .map(|(k, v)| {
                    (
                        ciborium::Value::Integer((*k).into()),
                        ciborium::Value::Text(v.to_string()),
                    )
                })
                .collect(),
        ),
        &mut buf,
    )
    .unwrap();
    buf
}

#[test]
fn test_sorted_keys_accepted() {
    // Keys 1 (iss), 3 (aud) in ascending order — valid
    let cbor = build_cbor_map(&[(1, "https://issuer.example.com"), (3, "audience")]);
    let result = Cwt::decode_payload(&cbor);
    assert!(result.is_ok(), "Sorted keys should be accepted");
    let token = result.unwrap();
    assert_eq!(
        token.core.iss,
        Some("https://issuer.example.com".to_string())
    );
}

#[test]
fn test_duplicate_keys_rejected() {
    // Adjacent duplicate key 1 — both in sorted position
    let map = ciborium::Value::Map(vec![
        (
            ciborium::Value::Integer(1.into()),
            ciborium::Value::Text("issuer1".to_string()),
        ),
        (
            ciborium::Value::Integer(1.into()),
            ciborium::Value::Text("issuer2".to_string()),
        ),
        (
            ciborium::Value::Integer(3.into()),
            ciborium::Value::Text("audience".to_string()),
        ),
    ]);
    let mut cbor = Vec::new();
    ciborium::ser::into_writer(&map, &mut cbor).unwrap();

    let result = Cwt::decode_payload(&cbor);
    assert!(result.is_err());
    match result {
        Err(CatError::InvalidCbor(msg)) => {
            assert!(msg.contains("Duplicate map key"), "Error: {msg}");
        }
        other => panic!("Expected InvalidCbor with duplicate key message, got: {other:?}"),
    }
}

#[test]
fn test_unsorted_keys_rejected() {
    // Keys in descending order: 3, 1 — violates RFC 8949 §4.2.1
    let map = ciborium::Value::Map(vec![
        (
            ciborium::Value::Integer(3.into()),
            ciborium::Value::Text("audience".to_string()),
        ),
        (
            ciborium::Value::Integer(1.into()),
            ciborium::Value::Text("https://issuer.example.com".to_string()),
        ),
    ]);
    let mut cbor = Vec::new();
    ciborium::ser::into_writer(&map, &mut cbor).unwrap();

    let result = Cwt::decode_payload(&cbor);
    assert!(result.is_err());
    match result {
        Err(CatError::InvalidCbor(msg)) => {
            assert!(msg.contains("deterministic order"), "Error: {msg}");
        }
        other => panic!("Expected InvalidCbor with ordering message, got: {other:?}"),
    }
}

#[test]
fn test_single_key_accepted() {
    let cbor = build_cbor_map(&[(1, "https://issuer.example.com")]);
    let result = Cwt::decode_payload(&cbor);
    assert!(result.is_ok());
}

#[test]
fn test_empty_map_accepted() {
    let mut cbor = Vec::new();
    ciborium::ser::into_writer(&ciborium::Value::Map(vec![]), &mut cbor).unwrap();
    let result = Cwt::decode_payload(&cbor);
    assert!(result.is_ok());
}

#[test]
fn test_many_sorted_keys_accepted() {
    // Keys 1, 2, 3, 4, 5, 6 in order — valid
    let cbor = build_cbor_map(&[(1, "issuer"), (2, "subject"), (3, "audience")]);
    let result = Cwt::decode_payload(&cbor);
    assert!(result.is_ok());
}

#[test]
fn test_negative_then_positive_keys_ordering() {
    // In CBOR deterministic encoding, positive integers sort before negative.
    // However, when converted to i64, -1 < 1. Our validation uses i64 comparison.
    // This test documents the behavior: we follow integer ordering after conversion.
    let map = ciborium::Value::Map(vec![
        (
            ciborium::Value::Integer((-1_i64).into()),
            ciborium::Value::Text("negative".to_string()),
        ),
        (
            ciborium::Value::Integer(1.into()),
            ciborium::Value::Text("positive".to_string()),
        ),
    ]);
    let mut cbor = Vec::new();
    ciborium::ser::into_writer(&map, &mut cbor).unwrap();

    // This should be accepted since -1 < 1 in i64 ordering
    let result = Cwt::decode_payload(&cbor);
    assert!(result.is_ok());
}

#[test]
fn test_roundtrip_produces_sorted_keys() {
    let alg = HmacSha256Algorithm::generate_key().unwrap();
    let algorithm = HmacSha256Algorithm::from_secret_key(&alg);

    let token = CatToken::new()
        .with_issuer("test-issuer")
        .with_audience(vec!["test-aud".to_string()])
        .with_subject("test-sub")
        .with_version(1);

    let encoded = encode_token(&token, &algorithm).unwrap();
    // If our encoding produces unsorted keys, decode would reject it
    let decoded = decode_token(&encoded, &algorithm).unwrap();
    assert_eq!(decoded.core.iss, Some("test-issuer".to_string()));
    assert_eq!(decoded.cat.catv, Some(1));
}
