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
    // Keys 1 (iss), 2 (sub) in ascending order — valid
    let cbor = build_cbor_map(&[(1, "https://issuer.example.com"), (2, "subject")]);
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
    // Keys 1 (iss), 2 (sub) in order — valid (uses only text-typed claims)
    let cbor = build_cbor_map(&[(1, "issuer"), (2, "subject")]);
    let result = Cwt::decode_payload(&cbor);
    assert!(result.is_ok());
}

#[test]
fn test_canonical_ordering_positive_before_negative() {
    // RFC 8949 §4.2.1: non-negative (major type 0) sorts before negative (major type 1).
    // Correct canonical order: 0, 1, ..., -1, -2, ...
    let correct_map = ciborium::Value::Map(vec![
        (
            ciborium::Value::Integer(1.into()),
            ciborium::Value::Text("positive".to_string()),
        ),
        (
            ciborium::Value::Integer((-1_i64).into()),
            ciborium::Value::Text("negative".to_string()),
        ),
    ]);
    let mut cbor = Vec::new();
    ciborium::ser::into_writer(&correct_map, &mut cbor).unwrap();
    assert!(Cwt::decode_payload(&cbor).is_ok());

    // Wrong order: negative before positive must be rejected
    let wrong_map = ciborium::Value::Map(vec![
        (
            ciborium::Value::Integer((-1_i64).into()),
            ciborium::Value::Text("negative".to_string()),
        ),
        (
            ciborium::Value::Integer(1.into()),
            ciborium::Value::Text("positive".to_string()),
        ),
    ]);
    let mut cbor2 = Vec::new();
    ciborium::ser::into_writer(&wrong_map, &mut cbor2).unwrap();
    assert!(Cwt::decode_payload(&cbor2).is_err());
}

#[test]
fn test_canonical_ordering_multiple_negatives() {
    // RFC 8949 §4.2.1: non-negative keys before negative, ascending within each group
    // Use high custom claim keys to avoid collision with known claims
    let correct_map = ciborium::Value::Map(vec![
        (
            ciborium::Value::Integer(1000.into()),
            ciborium::Value::Integer(0.into()),
        ),
        (
            ciborium::Value::Integer(1001.into()),
            ciborium::Value::Integer(1.into()),
        ),
        (
            ciborium::Value::Integer((-1_i64).into()),
            ciborium::Value::Integer(2.into()),
        ),
        (
            ciborium::Value::Integer((-2_i64).into()),
            ciborium::Value::Integer(3.into()),
        ),
    ]);
    let mut cbor = Vec::new();
    ciborium::ser::into_writer(&correct_map, &mut cbor).unwrap();
    assert!(Cwt::decode_payload(&cbor).is_ok());
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
    let decoded = Decoder::with_algorithm(&algorithm)
        .decode(&encoded)
        .unwrap()
        .into_unvalidated_token();
    assert_eq!(decoded.core.iss, Some("test-issuer".to_string()));
    assert_eq!(decoded.cat.catv, Some(1));
}
