// Tests for CTA-5007-B §4.8.2.1: catdpop critical settings (key -1).
// crit MUST NOT contain always-understood keys (-1, 0, 1). Enforced at build time.

use cat_token::*;

#[test]
fn test_crit_known_keys_rejected() {
    // Reject at build time
    let result = CatDpopSettings::new().with_critical(vec![0, 1]);
    assert!(result.is_err());
}

#[test]
fn test_crit_unknown_extension_key_accepted() {
    let settings = CatDpopSettings::new().with_critical(vec![99]).unwrap();
    assert!(settings.validate_crit().is_ok());
}

#[test]
fn test_crit_absent_is_ok() {
    let settings = CatDpopSettings::new().with_window(300).unwrap();
    assert!(settings.validate_crit().is_ok());
}

#[test]
fn test_crit_empty_array_is_ok() {
    let settings = CatDpopSettings::new().with_critical(vec![]).unwrap();
    assert!(settings.validate_crit().is_ok());
}

#[test]
fn test_crit_roundtrip_encode_decode() {
    let alg = HmacSha256Algorithm::generate_key().unwrap();
    let algorithm = HmacSha256Algorithm::from_secret_key(&alg);

    let settings = CatDpopSettings::new()
        .with_critical(vec![99])
        .unwrap()
        .with_window(600)
        .unwrap();

    let token = CatToken::new()
        .with_issuer("test")
        .with_dpop_settings(settings);

    let encoded = encode_token(&token, &algorithm).unwrap();
    let decoded = Decoder::with_algorithm(&algorithm)
        .decode(&encoded)
        .unwrap()
        .into_unvalidated_token();

    let dpop = decoded.dpop.catdpop.unwrap();
    assert_eq!(dpop.crit(), Some(&[99][..]));
    assert_eq!(dpop.window(), Some(600));
}

#[test]
fn test_crit_with_negative_one_key_rejected() {
    assert!(CatDpopSettings::new().with_critical(vec![-1, 0]).is_err());
}

#[test]
fn test_crit_negative_one_alone_rejected() {
    assert!(CatDpopSettings::new().with_critical(vec![-1]).is_err());
}

#[test]
fn test_crit_zero_alone_rejected() {
    assert!(CatDpopSettings::new().with_critical(vec![0]).is_err());
}

#[test]
fn test_crit_one_alone_rejected() {
    assert!(CatDpopSettings::new().with_critical(vec![1]).is_err());
}

#[test]
fn test_window_zero_rejected() {
    assert!(CatDpopSettings::new().with_window(0).is_err());
}

#[test]
fn test_window_negative_rejected() {
    assert!(CatDpopSettings::new().with_window(-1).is_err());
}

#[test]
fn test_window_over_cap_rejected() {
    assert!(CatDpopSettings::new().with_window(4000).is_err());
}

// Decoder must enforce the same 1..=3600 range as CatDpopSettings::with_window.
// Sub-key 0 = window per CTA-5007-B §4.8.2.
fn encode_catdpop_window(window_val: i64) -> Vec<u8> {
    use ciborium::Value;
    let payload = Value::Map(vec![(
        Value::Integer(CLAIM_CATDPOP.into()),
        Value::Map(vec![(
            Value::Integer(0.into()),
            Value::Integer(window_val.into()),
        )]),
    )]);
    let mut buf = Vec::new();
    ciborium::ser::into_writer(&payload, &mut buf).unwrap();
    buf
}

#[test]
fn test_catdpop_decoder_rejects_zero_window() {
    let cbor = encode_catdpop_window(0);
    let err = Cwt::decode_payload(&cbor).unwrap_err();
    assert!(matches!(err, CatError::InvalidClaimValue(_)));
}

#[test]
fn test_catdpop_decoder_rejects_negative_window() {
    let cbor = encode_catdpop_window(-1);
    let err = Cwt::decode_payload(&cbor).unwrap_err();
    assert!(matches!(err, CatError::InvalidClaimValue(_)));
}

#[test]
fn test_catdpop_decoder_rejects_window_over_cap() {
    let cbor = encode_catdpop_window(3601);
    let err = Cwt::decode_payload(&cbor).unwrap_err();
    assert!(matches!(err, CatError::InvalidClaimValue(_)));
}

#[test]
fn test_catdpop_decoder_accepts_window_at_bounds() {
    for good in [1i64, 300, 3600] {
        let cbor = encode_catdpop_window(good);
        let cwt = Cwt::decode_payload(&cbor).expect("well-formed catdpop window");
        assert_eq!(cwt.dpop.catdpop.unwrap().window(), Some(good));
    }
}
