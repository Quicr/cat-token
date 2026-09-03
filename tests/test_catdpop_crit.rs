// Tests for CTA-5007-B §4.8.2.1: catdpop critical settings (key -1).

use cat_token::*;

#[test]
fn test_crit_known_keys_accepted() {
    let settings = CatDpopSettings::new()
        .with_critical(vec![0, 1])
        .with_window(300)
        .with_jti_processing(true);

    assert!(settings.validate_crit().is_ok());
}

#[test]
fn test_crit_unknown_key_rejected() {
    let settings = CatDpopSettings::new()
        .with_critical(vec![0, 1, 99]);

    assert!(settings.validate_crit().is_err());
}

#[test]
fn test_crit_absent_is_ok() {
    let settings = CatDpopSettings::new().with_window(300);
    assert!(settings.validate_crit().is_ok());
}

#[test]
fn test_crit_empty_array_is_ok() {
    let settings = CatDpopSettings::new().with_critical(vec![]);
    assert!(settings.validate_crit().is_ok());
}

#[test]
fn test_crit_roundtrip_encode_decode() {
    let alg = HmacSha256Algorithm::generate_key().unwrap();
    let algorithm = HmacSha256Algorithm::from_secret_key(&alg);

    let settings = CatDpopSettings::new()
        .with_critical(vec![0, 1])
        .with_window(600);

    let token = CatToken::new()
        .with_issuer("test")
        .with_dpop_settings(settings);

    let encoded = encode_token(&token, &algorithm).unwrap();
    let decoded = decode_token(&encoded, &algorithm).unwrap();

    let dpop = decoded.dpop.catdpop.unwrap();
    assert_eq!(dpop.crit, Some(vec![0, 1]));
    assert_eq!(dpop.window, Some(600));
}

#[test]
fn test_crit_with_negative_one_key() {
    let settings = CatDpopSettings::new()
        .with_critical(vec![-1, 0]);

    assert!(settings.validate_crit().is_ok());
}
