// Tests for CTA-5007-B §4.6.5: cti MUST be bstr (arbitrary bytes).

use cat_token::*;

#[test]
fn test_cti_utf8_string_roundtrip() {
    let alg = HmacSha256Algorithm::generate_key().unwrap();
    let algorithm = HmacSha256Algorithm::from_secret_key(&alg);

    let token = CatToken::new()
        .with_issuer("test")
        .with_cwt_id_str("my-token-id");

    let encoded = encode_token(&token, &algorithm).unwrap();
    let decoded = decode_token(&encoded, &algorithm).unwrap();

    assert_eq!(decoded.core.cti, Some(b"my-token-id".to_vec()));
}

#[test]
fn test_cti_arbitrary_bytes_roundtrip() {
    let alg = HmacSha256Algorithm::generate_key().unwrap();
    let algorithm = HmacSha256Algorithm::from_secret_key(&alg);

    let cti_bytes: Vec<u8> = vec![0x00, 0x01, 0xFF, 0xFE, 0x80, 0x90, 0xAB, 0xCD];
    let token = CatToken::new()
        .with_issuer("test")
        .with_cwt_id(cti_bytes.clone());

    let encoded = encode_token(&token, &algorithm).unwrap();
    let decoded = decode_token(&encoded, &algorithm).unwrap();

    assert_eq!(decoded.core.cti, Some(cti_bytes));
}

#[test]
fn test_cti_uuid_bytes() {
    let alg = HmacSha256Algorithm::generate_key().unwrap();
    let algorithm = HmacSha256Algorithm::from_secret_key(&alg);

    let uuid_bytes = uuid::Uuid::new_v4().as_bytes().to_vec();
    let token = CatToken::new()
        .with_issuer("test")
        .with_cwt_id(uuid_bytes.clone());

    let encoded = encode_token(&token, &algorithm).unwrap();
    let decoded = decode_token(&encoded, &algorithm).unwrap();

    assert_eq!(decoded.core.cti, Some(uuid_bytes));
}

#[test]
fn test_cti_empty_bytes() {
    let token = CatToken::new().with_cwt_id(vec![]);
    assert_eq!(token.core.cti, Some(vec![]));
}

#[test]
fn test_builder_cwt_id_str() {
    let token = CatTokenBuilder::new().cwt_id_str("test-id").build();
    assert_eq!(token.core.cti, Some(b"test-id".to_vec()));
}

#[test]
fn test_builder_cwt_id_bytes() {
    let bytes = vec![0xDE, 0xAD, 0xBE, 0xEF];
    let token = CatTokenBuilder::new().cwt_id(bytes.clone()).build();
    assert_eq!(token.core.cti, Some(bytes));
}
