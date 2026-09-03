// Tests for CTA-5007-B §4.6.3/§4.6.4: exp/nbf MUST NOT allow leeway by default.

use cat_token::*;

#[test]
fn test_default_validator_has_zero_tolerance() {
    let validator = CatTokenValidator::new();
    let key = Es256Algorithm::new_with_key_pair().unwrap();

    let token = CatTokenBuilder::new()
        .issuer("test")
        .single_audience("aud")
        .expires_in(-1)
        .build();

    let encoded = encode_token(&token, &key).unwrap();
    let decoded = decode_token(&encoded, &key).unwrap();

    assert!(matches!(
        validator.validate(&decoded),
        Err(CatError::TokenExpired)
    ));
}

#[test]
fn test_default_validator_rejects_nbf_in_future() {
    let validator = CatTokenValidator::new();
    let key = Es256Algorithm::new_with_key_pair().unwrap();

    let nbf = chrono::Utc::now() + chrono::Duration::seconds(5);
    let token = CatTokenBuilder::new()
        .issuer("test")
        .single_audience("aud")
        .expires_in(3600)
        .not_before(nbf)
        .build();

    let encoded = encode_token(&token, &key).unwrap();
    let decoded = decode_token(&encoded, &key).unwrap();

    assert!(matches!(
        validator.validate(&decoded),
        Err(CatError::TokenNotYetValid)
    ));
}

#[test]
fn test_explicit_tolerance_allows_skew() {
    let validator = CatTokenValidator::new().with_clock_skew_tolerance(60);
    let key = Es256Algorithm::new_with_key_pair().unwrap();

    let token = CatTokenBuilder::new()
        .issuer("test")
        .single_audience("aud")
        .expires_in(-5)
        .build();

    let encoded = encode_token(&token, &key).unwrap();
    let decoded = decode_token(&encoded, &key).unwrap();

    assert!(validator.validate(&decoded).is_ok());
}

#[test]
fn test_separate_tolerances() {
    let validator = CatTokenValidator::new().with_separate_tolerances(10, 0);
    let key = Es256Algorithm::new_with_key_pair().unwrap();

    let token = CatTokenBuilder::new()
        .issuer("test")
        .single_audience("aud")
        .expires_in(-5)
        .build();

    let encoded = encode_token(&token, &key).unwrap();
    let decoded = decode_token(&encoded, &key).unwrap();

    assert!(validator.validate(&decoded).is_ok());
}
