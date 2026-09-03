// Tests for CTA-5007-B §4.6.16: geohash as text string or array of text strings.

use cat_token::*;

#[test]
fn test_single_geohash_roundtrip() {
    let alg = HmacSha256Algorithm::generate_key().unwrap();
    let algorithm = HmacSha256Algorithm::from_secret_key(&alg);

    let token = CatToken::new().with_issuer("test").with_geohash("9q8yyk");

    let encoded = encode_token(&token, &algorithm).unwrap();
    let decoded = decode_token(&encoded, &algorithm).unwrap();

    assert_eq!(decoded.cat.geohash, Some(vec!["9q8yyk".to_string()]));
}

#[test]
fn test_multiple_geohashes_roundtrip() {
    let alg = HmacSha256Algorithm::generate_key().unwrap();
    let algorithm = HmacSha256Algorithm::from_secret_key(&alg);

    let token = CatToken::new()
        .with_issuer("test")
        .with_geohash("9q8yyk")
        .with_geohash("dr5regw")
        .with_geohash("u4pruydqqv");

    let encoded = encode_token(&token, &algorithm).unwrap();
    let decoded = decode_token(&encoded, &algorithm).unwrap();

    assert_eq!(
        decoded.cat.geohash,
        Some(vec![
            "9q8yyk".to_string(),
            "dr5regw".to_string(),
            "u4pruydqqv".to_string()
        ])
    );
}

#[test]
fn test_geohash_builder_accumulates() {
    let token = CatTokenBuilder::new()
        .geohash("9q8yyk")
        .geohash("dr5regw")
        .build();

    let hashes = token.cat.geohash.unwrap();
    assert_eq!(hashes.len(), 2);
    assert_eq!(hashes[0], "9q8yyk");
    assert_eq!(hashes[1], "dr5regw");
}

#[test]
fn test_validator_rejects_invalid_in_array() {
    let validator = CatTokenValidator::new();

    let mut token = CatToken::new();
    token.cat.geohash = Some(vec![
        "9q8yyk".to_string(),
        "XYZ".to_string(), // too short
    ]);

    assert!(matches!(
        validator.validate(&token),
        Err(CatError::GeographicValidationFailed(_))
    ));
}

#[test]
fn test_validator_accepts_valid_array() {
    let validator = CatTokenValidator::new();

    let mut token = CatToken::new();
    token.cat.geohash = Some(vec!["9q8yyk".to_string(), "dr5regw".to_string()]);

    assert!(validator.validate(&token).is_ok());
}
