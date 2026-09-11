// Tests for CTA-5007-B §4.6.3/§4.6.4: exp/nbf MUST NOT allow leeway by default.

use cat_token::*;

#[test]
fn test_default_validator_has_zero_tolerance() {
    let validator = CatTokenValidator::dangerously_any_issuer();
    let key = Es256Algorithm::new_with_key_pair().unwrap();

    let token = CatTokenBuilder::new()
        .issuer("test")
        .single_audience("aud")
        .expires_in(-1)
        .build()
        .unwrap();

    let encoded = encode_token(&token, &key).unwrap();
    let decoded = Decoder::with_algorithm(&key)
        .decode(&encoded)
        .unwrap()
        .into_unvalidated_token();

    assert!(matches!(
        validator.validate(&decoded),
        Err(CatError::TokenExpired)
    ));
}

#[test]
fn test_default_validator_rejects_nbf_in_future() {
    let validator = CatTokenValidator::dangerously_any_issuer();
    let key = Es256Algorithm::new_with_key_pair().unwrap();

    let nbf = chrono::Utc::now() + chrono::Duration::seconds(5);
    let token = CatTokenBuilder::new()
        .issuer("test")
        .single_audience("aud")
        .expires_in(3600)
        .not_before(nbf)
        .build()
        .unwrap();

    let encoded = encode_token(&token, &key).unwrap();
    let decoded = Decoder::with_algorithm(&key)
        .decode(&encoded)
        .unwrap()
        .into_unvalidated_token();

    assert!(matches!(
        validator.validate(&decoded),
        Err(CatError::TokenNotYetValid)
    ));
}

#[test]
fn test_explicit_tolerance_allows_skew() {
    let validator = CatTokenValidator::dangerously_any_issuer()
        .with_clock_skew_tolerance(60)
        .unwrap();
    let key = Es256Algorithm::new_with_key_pair().unwrap();

    let token = CatTokenBuilder::new()
        .issuer("test")
        .single_audience("aud")
        .expires_in(-5)
        .build()
        .unwrap();

    let encoded = encode_token(&token, &key).unwrap();
    let decoded = Decoder::with_algorithm(&key)
        .decode(&encoded)
        .unwrap()
        .into_unvalidated_token();

    assert!(validator.validate(&decoded).is_ok());
}

#[test]
fn test_separate_tolerances() {
    let validator = CatTokenValidator::dangerously_any_issuer()
        .with_separate_tolerances(10, 0)
        .unwrap();
    let key = Es256Algorithm::new_with_key_pair().unwrap();

    let token = CatTokenBuilder::new()
        .issuer("test")
        .single_audience("aud")
        .expires_in(-5)
        .build()
        .unwrap();

    let encoded = encode_token(&token, &key).unwrap();
    let decoded = Decoder::with_algorithm(&key)
        .decode(&encoded)
        .unwrap()
        .into_unvalidated_token();

    assert!(validator.validate(&decoded).is_ok());
}

#[test]
fn test_tolerance_above_cap_rejected() {
    // Above the 1 hour cap: reject.
    assert!(matches!(
        CatTokenValidator::dangerously_any_issuer()
            .with_clock_skew_tolerance(MAX_CLOCK_SKEW_TOLERANCE_SECS + 1),
        Err(CatError::InvalidClaimValue(_))
    ));
    assert!(matches!(
        CatTokenValidator::dangerously_any_issuer()
            .with_separate_tolerances(MAX_CLOCK_SKEW_TOLERANCE_SECS + 1, 0),
        Err(CatError::InvalidClaimValue(_))
    ));
    assert!(matches!(
        CatTokenValidator::dangerously_any_issuer()
            .with_separate_tolerances(0, MAX_CLOCK_SKEW_TOLERANCE_SECS + 1),
        Err(CatError::InvalidClaimValue(_))
    ));

    // At the cap: accept.
    assert!(
        CatTokenValidator::dangerously_any_issuer()
            .with_clock_skew_tolerance(MAX_CLOCK_SKEW_TOLERANCE_SECS)
            .is_ok()
    );
}

#[test]
fn test_exp_overflow_rejected() {
    // An attacker-supplied exp near i64::MAX combined with a positive tolerance
    // must not silently saturate into an unbounded acceptance window.
    let validator = CatTokenValidator::dangerously_any_issuer()
        .with_clock_skew_tolerance(600)
        .unwrap();
    let key = Es256Algorithm::new_with_key_pair().unwrap();

    let mut token = CatTokenBuilder::new()
        .issuer("test")
        .single_audience("aud")
        .expires_in(3600)
        .build()
        .unwrap();
    // Force exp to i64::MAX post-build so the checked_add overflows.
    token.core.exp = Some(i64::MAX);

    let encoded = encode_token(&token, &key).unwrap();
    let decoded = Decoder::with_algorithm(&key)
        .decode(&encoded)
        .unwrap()
        .into_unvalidated_token();

    assert!(matches!(
        validator.validate(&decoded),
        Err(CatError::InvalidClaimValue(_))
    ));
}

#[test]
fn test_nbf_underflow_rejected() {
    let validator = CatTokenValidator::dangerously_any_issuer()
        .with_clock_skew_tolerance(600)
        .unwrap();
    let key = Es256Algorithm::new_with_key_pair().unwrap();

    let mut token = CatTokenBuilder::new()
        .issuer("test")
        .single_audience("aud")
        .expires_in(3600)
        .build()
        .unwrap();
    // Force nbf to i64::MIN post-build so the checked_sub underflows.
    token.core.nbf = Some(i64::MIN);

    let encoded = encode_token(&token, &key).unwrap();
    let decoded = Decoder::with_algorithm(&key)
        .decode(&encoded)
        .unwrap()
        .into_unvalidated_token();

    assert!(matches!(
        validator.validate(&decoded),
        Err(CatError::InvalidClaimValue(_))
    ));
}
