// Tests for CTA-5007-B §4.9.1 (catif) and §4.9.2 (catr) structured claims.

use cat_token::*;

// --- catif tests ---

#[test]
fn test_catif_single_action() {
    let token = CatToken::new().with_if_action(CLAIM_EXP, CatIfAction::new(401).unwrap());

    let actions = token.request.catif.unwrap();
    assert_eq!(actions.len(), 1);
    assert_eq!(actions[0].0, CLAIM_EXP);
    assert_eq!(actions[0].1.status(), 401);
    assert!(actions[0].1.headers().is_none());
    assert!(actions[0].1.kid().is_none());
}

#[test]
fn test_catif_multiple_actions() {
    let token = CatToken::new()
        .with_if_action(CLAIM_EXP, CatIfAction::new(401).unwrap())
        .with_if_action(CLAIM_AUD, CatIfAction::new(403).unwrap());

    let actions = token.request.catif.unwrap();
    assert_eq!(actions.len(), 2);
    assert_eq!(actions[0].0, CLAIM_EXP);
    assert_eq!(actions[1].0, CLAIM_AUD);
}

#[test]
fn test_catif_with_headers() {
    let headers = vec![(
        "WWW-Authenticate".to_string(),
        "Bearer realm=\"example\"".to_string(),
    )];
    let action = CatIfAction::new(401)
        .unwrap()
        .with_headers(headers.clone())
        .unwrap();
    let token = CatToken::new().with_if_action(CLAIM_EXP, action);

    let action = &token.request.catif.unwrap()[0].1;
    assert_eq!(action.status(), 401);
    assert_eq!(action.headers().unwrap()[0].0, "WWW-Authenticate");
}

#[test]
fn test_catif_with_kid() {
    let action = CatIfAction::new(401).unwrap().with_kid("key-123");
    let token = CatToken::new().with_if_action(CLAIM_EXP, action);

    let action = &token.request.catif.unwrap()[0].1;
    assert_eq!(action.kid().unwrap(), "key-123");
}

#[test]
fn test_catif_with_headers_and_kid() {
    let headers = vec![("X-Custom".to_string(), "value".to_string())];
    let action = CatIfAction::new(425)
        .unwrap()
        .with_headers(headers)
        .unwrap()
        .with_kid("signing-key");
    let token = CatToken::new().with_if_action(CLAIM_NBF, action);

    let action = &token.request.catif.unwrap()[0].1;
    assert_eq!(action.status(), 425);
    assert!(action.headers().is_some());
    assert_eq!(action.kid().unwrap(), "signing-key");
}

#[test]
fn test_catif_status_out_of_range_rejected() {
    assert!(CatIfAction::new(0).is_err());
    assert!(CatIfAction::new(99).is_err());
    assert!(CatIfAction::new(600).is_err());
}

#[test]
fn test_catif_header_with_crlf_rejected() {
    let bad = vec![("X-Injected".to_string(), "value\r\nEvil: yes".to_string())];
    let result = CatIfAction::new(400).unwrap().with_headers(bad);
    assert!(result.is_err());
}

#[test]
fn test_catif_header_name_with_colon_rejected() {
    let bad = vec![("X-Bad:Header".to_string(), "value".to_string())];
    let result = CatIfAction::new(400).unwrap().with_headers(bad);
    assert!(result.is_err());
}

#[test]
fn test_catif_roundtrip() {
    let alg = HmacSha256Algorithm::generate_key().unwrap();
    let algorithm = HmacSha256Algorithm::from_secret_key(&alg);

    let headers = vec![("WWW-Authenticate".to_string(), "Bearer".to_string())];
    let token = CatToken::new()
        .with_issuer("test")
        .with_if_action(
            CLAIM_EXP,
            CatIfAction::new(401)
                .unwrap()
                .with_headers(headers)
                .unwrap(),
        )
        .with_if_action(CLAIM_AUD, CatIfAction::new(403).unwrap().with_kid("k1"));

    let encoded = encode_token(&token, &algorithm).unwrap();
    let decoded = Decoder::with_algorithm(&algorithm)
        .decode(&encoded)
        .unwrap()
        .into_unvalidated_token();

    let actions = decoded.request.catif.unwrap();
    assert_eq!(actions.len(), 2);
    // After encoding, entries are sorted by claim key (AUD=3 before EXP=4)
    assert_eq!(actions[0].0, CLAIM_AUD);
    assert_eq!(actions[0].1.status(), 403);
    assert_eq!(actions[0].1.kid().unwrap(), "k1");
    assert_eq!(actions[1].0, CLAIM_EXP);
    assert_eq!(actions[1].1.status(), 401);
    assert_eq!(actions[1].1.headers().unwrap()[0].0, "WWW-Authenticate");
}

#[test]
fn test_catif_builder() {
    let token = CatTokenBuilder::new()
        .issuer("test")
        .if_action(CLAIM_EXP, CatIfAction::new(401).unwrap())
        .build()
        .unwrap();

    assert!(token.request.catif.is_some());
    assert_eq!(token.request.catif.unwrap()[0].1.status(), 401);
}

// Narrow-profile decoder rejections (see src/claims.rs module docs). These
// hand-construct CBOR maps because the safe builder API cannot produce these
// shapes — that's the point of a narrow profile.

fn encode_catif_action(action: ciborium::Value) -> Vec<u8> {
    use ciborium::Value;
    let payload = Value::Map(vec![(
        Value::Integer(CLAIM_CATIF.into()),
        Value::Map(vec![(Value::Integer(CLAIM_EXP.into()), action)]),
    )]);
    let mut buf = Vec::new();
    ciborium::ser::into_writer(&payload, &mut buf).unwrap();
    buf
}

#[test]
fn test_catif_decoder_rejects_bytes_header_value() {
    use ciborium::Value;
    let action = Value::Array(vec![
        Value::Integer(401.into()),
        Value::Map(vec![(
            Value::Text("X-Custom".to_string()),
            Value::Bytes(vec![0xDE, 0xAD]),
        )]),
    ]);
    let cbor = encode_catif_action(action);
    let err = Cwt::decode_payload(&cbor).unwrap_err();
    assert!(matches!(err, CatError::InvalidClaimValue(_)));
}

#[test]
fn test_catif_decoder_rejects_integer_header_value() {
    use ciborium::Value;
    let action = Value::Array(vec![
        Value::Integer(401.into()),
        Value::Map(vec![(
            Value::Text("Retry-After".to_string()),
            Value::Integer(60.into()),
        )]),
    ]);
    let cbor = encode_catif_action(action);
    let err = Cwt::decode_payload(&cbor).unwrap_err();
    assert!(matches!(err, CatError::InvalidClaimValue(_)));
}

#[test]
fn test_catif_decoder_rejects_crlf_header_value() {
    use ciborium::Value;
    let action = Value::Array(vec![
        Value::Integer(401.into()),
        Value::Map(vec![(
            Value::Text("X-Injected".to_string()),
            Value::Text("value\r\nEvil: yes".to_string()),
        )]),
    ]);
    let cbor = encode_catif_action(action);
    let err = Cwt::decode_payload(&cbor).unwrap_err();
    assert!(matches!(err, CatError::InvalidClaimValue(_)));
}

#[test]
fn test_catif_decoder_rejects_colon_in_header_name() {
    use ciborium::Value;
    let action = Value::Array(vec![
        Value::Integer(401.into()),
        Value::Map(vec![(
            Value::Text("X-Bad:Header".to_string()),
            Value::Text("value".to_string()),
        )]),
    ]);
    let cbor = encode_catif_action(action);
    let err = Cwt::decode_payload(&cbor).unwrap_err();
    assert!(matches!(err, CatError::InvalidClaimValue(_)));
}

#[test]
fn test_catif_decoder_rejects_out_of_range_status() {
    use ciborium::Value;
    for bad in [0i64, 99, 600, 999] {
        let action = Value::Array(vec![Value::Integer(bad.into()), Value::Map(vec![])]);
        let cbor = encode_catif_action(action);
        let err = Cwt::decode_payload(&cbor).unwrap_err();
        assert!(matches!(err, CatError::InvalidClaimValue(_)));
    }
}

#[test]
fn test_catif_decoder_rejects_extra_array_member() {
    use ciborium::Value;
    let action = Value::Array(vec![
        Value::Integer(401.into()),
        Value::Map(vec![]),
        Value::Text("kid-1".to_string()),
        Value::Text("unexpected-fourth-member".to_string()),
    ]);
    let cbor = encode_catif_action(action);
    let err = Cwt::decode_payload(&cbor).unwrap_err();
    assert!(matches!(err, CatError::InvalidClaimValue(_)));
}

// --- catr tests ---

#[test]
fn test_catr_automatic_renewal() {
    let token = CatToken::new().with_renewal(CatRenewal::automatic().with_expadd(3600.0).unwrap());

    let catr = token.request.catr.unwrap();
    assert_eq!(catr.renewal_type(), CatRenewalType::Automatic);
    assert_eq!(catr.expadd(), Some(3600.0));
    assert!(catr.cookie_name().is_none());
    assert!(catr.status_code().is_none());
}

#[test]
fn test_catr_cookie_renewal() {
    let token = CatToken::new().with_renewal(
        CatRenewal::cookie("session_token")
            .with_expadd(7200.0)
            .unwrap()
            .with_cookie_params(vec!["SameSite=Strict".to_string(), "Secure".to_string()]),
    );

    let catr = token.request.catr.unwrap();
    assert_eq!(catr.renewal_type(), CatRenewalType::Cookie);
    assert_eq!(catr.cookie_name().unwrap(), "session_token");
    assert_eq!(catr.expadd(), Some(7200.0));
    assert_eq!(catr.cookie_params().unwrap().len(), 2);
}

#[test]
fn test_catr_header_renewal() {
    let token = CatToken::new().with_renewal(
        CatRenewal::header("X-Auth-Token")
            .with_expadd(1800.0)
            .unwrap(),
    );

    let catr = token.request.catr.unwrap();
    assert_eq!(catr.renewal_type(), CatRenewalType::Header);
    assert_eq!(catr.header_name().unwrap(), "X-Auth-Token");
}

#[test]
fn test_catr_redirect_renewal() {
    let token =
        CatToken::new().with_renewal(CatRenewal::redirect(302).with_expadd(3600.0).unwrap());

    let catr = token.request.catr.unwrap();
    assert_eq!(catr.renewal_type(), CatRenewalType::Redirect);
    assert_eq!(catr.status_code(), Some(302));
    assert_eq!(catr.expadd(), Some(3600.0));
}

#[test]
fn test_catr_with_deadline() {
    let deadline = chrono::Utc::now().timestamp() + 86400;
    let token = CatToken::new().with_renewal(
        CatRenewal::automatic()
            .with_expadd(3600.0)
            .unwrap()
            .with_deadline(deadline as f64)
            .unwrap(),
    );

    let catr = token.request.catr.unwrap();
    assert_eq!(catr.deadline(), Some(deadline as f64));
}

#[test]
fn test_catr_nan_rejected() {
    assert!(CatRenewal::automatic().with_expadd(f64::NAN).is_err());
    assert!(
        CatRenewal::automatic()
            .with_deadline(f64::INFINITY)
            .is_err()
    );
}

#[test]
fn test_catr_roundtrip() {
    let alg = HmacSha256Algorithm::generate_key().unwrap();
    let algorithm = HmacSha256Algorithm::from_secret_key(&alg);

    let token = CatToken::new().with_issuer("test").with_renewal(
        CatRenewal::cookie("token")
            .with_expadd(3600.0)
            .unwrap()
            .with_deadline(1700000000.0)
            .unwrap()
            .with_cookie_params(vec!["Secure".to_string()]),
    );

    let encoded = encode_token(&token, &algorithm).unwrap();
    let decoded = Decoder::with_algorithm(&algorithm)
        .decode(&encoded)
        .unwrap()
        .into_unvalidated_token();

    let catr = decoded.request.catr.unwrap();
    assert_eq!(catr.renewal_type(), CatRenewalType::Cookie);
    assert_eq!(catr.cookie_name().unwrap(), "token");
    assert_eq!(catr.expadd(), Some(3600.0));
    assert_eq!(catr.deadline(), Some(1700000000.0));
    assert_eq!(catr.cookie_params().unwrap()[0], "Secure");
}

#[test]
fn test_catr_redirect_roundtrip() {
    let alg = HmacSha256Algorithm::generate_key().unwrap();
    let algorithm = HmacSha256Algorithm::from_secret_key(&alg);

    let token = CatToken::new()
        .with_issuer("test")
        .with_renewal(CatRenewal::redirect(307).with_expadd(1800.0).unwrap());

    let encoded = encode_token(&token, &algorithm).unwrap();
    let decoded = Decoder::with_algorithm(&algorithm)
        .decode(&encoded)
        .unwrap()
        .into_unvalidated_token();

    let catr = decoded.request.catr.unwrap();
    assert_eq!(catr.renewal_type(), CatRenewalType::Redirect);
    assert_eq!(catr.status_code(), Some(307));
    assert_eq!(catr.expadd(), Some(1800.0));
}

#[test]
fn test_catr_builder() {
    let token = CatTokenBuilder::new()
        .issuer("test")
        .renewal(CatRenewal::automatic().with_expadd(600.0).unwrap())
        .build()
        .unwrap();

    let catr = token.request.catr.unwrap();
    assert_eq!(catr.renewal_type(), CatRenewalType::Automatic);
    assert_eq!(catr.expadd(), Some(600.0));
}

#[test]
fn test_renewal_type_values() {
    assert_eq!(CatRenewalType::from_u32(0), Some(CatRenewalType::Automatic));
    assert_eq!(CatRenewalType::from_u32(1), Some(CatRenewalType::Cookie));
    assert_eq!(CatRenewalType::from_u32(2), Some(CatRenewalType::Header));
    assert_eq!(CatRenewalType::from_u32(3), Some(CatRenewalType::Redirect));
    assert_eq!(CatRenewalType::from_u32(4), None);
    assert_eq!(CatRenewalType::from_u32(99), None);
}

// --- Combined catif + catr ---

#[test]
fn test_catif_and_catr_together_roundtrip() {
    let alg = HmacSha256Algorithm::generate_key().unwrap();
    let algorithm = HmacSha256Algorithm::from_secret_key(&alg);

    let token = CatToken::new()
        .with_issuer("test")
        .with_if_action(CLAIM_EXP, CatIfAction::new(401).unwrap())
        .with_renewal(CatRenewal::automatic().with_expadd(3600.0).unwrap());

    let encoded = encode_token(&token, &algorithm).unwrap();
    let decoded = Decoder::with_algorithm(&algorithm)
        .decode(&encoded)
        .unwrap()
        .into_unvalidated_token();

    assert!(decoded.request.catif.is_some());
    assert!(decoded.request.catr.is_some());
    assert_eq!(decoded.request.catif.unwrap()[0].1.status(), 401);
    assert_eq!(
        decoded.request.catr.unwrap().renewal_type(),
        CatRenewalType::Automatic
    );
}
