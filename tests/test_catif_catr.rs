// Tests for CTA-5007-B §4.9.1 (catif) and §4.9.2 (catr) structured claims.

use cat_token::*;

// --- catif tests ---

#[test]
fn test_catif_single_action() {
    let token = CatToken::new().with_if_action(
        CLAIM_EXP,
        CatIfAction { status: 401, headers: None, kid: None },
    );

    let actions = token.request.catif.unwrap();
    assert_eq!(actions.len(), 1);
    assert_eq!(actions[0].0, CLAIM_EXP);
    assert_eq!(actions[0].1.status, 401);
    assert!(actions[0].1.headers.is_none());
    assert!(actions[0].1.kid.is_none());
}

#[test]
fn test_catif_multiple_actions() {
    let token = CatToken::new()
        .with_if_action(CLAIM_EXP, CatIfAction { status: 401, headers: None, kid: None })
        .with_if_action(CLAIM_AUD, CatIfAction { status: 403, headers: None, kid: None });

    let actions = token.request.catif.unwrap();
    assert_eq!(actions.len(), 2);
    assert_eq!(actions[0].0, CLAIM_EXP);
    assert_eq!(actions[1].0, CLAIM_AUD);
}

#[test]
fn test_catif_with_headers() {
    let headers = vec![
        ("WWW-Authenticate".to_string(), "Bearer realm=\"example\"".to_string()),
    ];
    let token = CatToken::new().with_if_action(
        CLAIM_EXP,
        CatIfAction { status: 401, headers: Some(headers.clone()), kid: None },
    );

    let action = &token.request.catif.unwrap()[0].1;
    assert_eq!(action.status, 401);
    assert_eq!(action.headers.as_ref().unwrap()[0].0, "WWW-Authenticate");
}

#[test]
fn test_catif_with_kid() {
    let token = CatToken::new().with_if_action(
        CLAIM_EXP,
        CatIfAction { status: 401, headers: None, kid: Some("key-123".to_string()) },
    );

    let action = &token.request.catif.unwrap()[0].1;
    assert_eq!(action.kid.as_ref().unwrap(), "key-123");
}

#[test]
fn test_catif_with_headers_and_kid() {
    let headers = vec![("X-Custom".to_string(), "value".to_string())];
    let token = CatToken::new().with_if_action(
        CLAIM_NBF,
        CatIfAction {
            status: 425,
            headers: Some(headers),
            kid: Some("signing-key".to_string()),
        },
    );

    let action = &token.request.catif.unwrap()[0].1;
    assert_eq!(action.status, 425);
    assert!(action.headers.is_some());
    assert_eq!(action.kid.as_ref().unwrap(), "signing-key");
}

#[test]
fn test_catif_roundtrip() {
    let alg = HmacSha256Algorithm::generate_key().unwrap();
    let algorithm = HmacSha256Algorithm::from_secret_key(&alg);

    let headers = vec![
        ("WWW-Authenticate".to_string(), "Bearer".to_string()),
    ];
    let token = CatToken::new()
        .with_issuer("test")
        .with_if_action(CLAIM_EXP, CatIfAction { status: 401, headers: Some(headers), kid: None })
        .with_if_action(CLAIM_AUD, CatIfAction { status: 403, headers: None, kid: Some("k1".to_string()) });

    let encoded = encode_token(&token, &algorithm).unwrap();
    let decoded = decode_token(&encoded, &algorithm).unwrap();

    let actions = decoded.request.catif.unwrap();
    assert_eq!(actions.len(), 2);
    assert_eq!(actions[0].0, CLAIM_EXP);
    assert_eq!(actions[0].1.status, 401);
    assert_eq!(actions[0].1.headers.as_ref().unwrap()[0].0, "WWW-Authenticate");
    assert_eq!(actions[1].0, CLAIM_AUD);
    assert_eq!(actions[1].1.status, 403);
    assert_eq!(actions[1].1.kid.as_ref().unwrap(), "k1");
}

#[test]
fn test_catif_builder() {
    let token = CatTokenBuilder::new()
        .issuer("test")
        .if_action(CLAIM_EXP, CatIfAction { status: 401, headers: None, kid: None })
        .build();

    assert!(token.request.catif.is_some());
    assert_eq!(token.request.catif.unwrap()[0].1.status, 401);
}

// --- catr tests ---

#[test]
fn test_catr_automatic_renewal() {
    let token = CatToken::new().with_renewal(CatRenewal::automatic().with_expadd(3600));

    let catr = token.request.catr.unwrap();
    assert_eq!(catr.renewal_type, CatRenewalType::Automatic);
    assert_eq!(catr.expadd, Some(3600));
    assert!(catr.name.is_none());
    assert!(catr.code.is_none());
}

#[test]
fn test_catr_cookie_renewal() {
    let token = CatToken::new().with_renewal(
        CatRenewal::cookie("session_token")
            .with_expadd(7200)
            .with_params(vec![
                ("SameSite".to_string(), "Strict".to_string()),
                ("Secure".to_string(), "true".to_string()),
            ]),
    );

    let catr = token.request.catr.unwrap();
    assert_eq!(catr.renewal_type, CatRenewalType::Cookie);
    assert_eq!(catr.name.as_ref().unwrap(), "session_token");
    assert_eq!(catr.expadd, Some(7200));
    assert_eq!(catr.params.as_ref().unwrap().len(), 2);
}

#[test]
fn test_catr_header_renewal() {
    let token = CatToken::new().with_renewal(
        CatRenewal::header("X-Auth-Token").with_expadd(1800),
    );

    let catr = token.request.catr.unwrap();
    assert_eq!(catr.renewal_type, CatRenewalType::Header);
    assert_eq!(catr.name.as_ref().unwrap(), "X-Auth-Token");
}

#[test]
fn test_catr_redirect_renewal() {
    let token = CatToken::new().with_renewal(CatRenewal::redirect(302));

    let catr = token.request.catr.unwrap();
    assert_eq!(catr.renewal_type, CatRenewalType::Redirect);
    assert_eq!(catr.code, Some(302));
}

#[test]
fn test_catr_with_deadline() {
    let deadline = chrono::Utc::now().timestamp() + 86400;
    let token = CatToken::new().with_renewal(
        CatRenewal::automatic()
            .with_expadd(3600)
            .with_deadline(deadline),
    );

    let catr = token.request.catr.unwrap();
    assert_eq!(catr.deadline, Some(deadline));
}

#[test]
fn test_catr_roundtrip() {
    let alg = HmacSha256Algorithm::generate_key().unwrap();
    let algorithm = HmacSha256Algorithm::from_secret_key(&alg);

    let token = CatToken::new()
        .with_issuer("test")
        .with_renewal(
            CatRenewal::cookie("token")
                .with_expadd(3600)
                .with_deadline(1700000000)
                .with_params(vec![("Secure".to_string(), "true".to_string())]),
        );

    let encoded = encode_token(&token, &algorithm).unwrap();
    let decoded = decode_token(&encoded, &algorithm).unwrap();

    let catr = decoded.request.catr.unwrap();
    assert_eq!(catr.renewal_type, CatRenewalType::Cookie);
    assert_eq!(catr.name.as_ref().unwrap(), "token");
    assert_eq!(catr.expadd, Some(3600));
    assert_eq!(catr.deadline, Some(1700000000));
    assert_eq!(catr.params.as_ref().unwrap()[0].0, "Secure");
}

#[test]
fn test_catr_redirect_roundtrip() {
    let alg = HmacSha256Algorithm::generate_key().unwrap();
    let algorithm = HmacSha256Algorithm::from_secret_key(&alg);

    let token = CatToken::new()
        .with_issuer("test")
        .with_renewal(CatRenewal::redirect(307));

    let encoded = encode_token(&token, &algorithm).unwrap();
    let decoded = decode_token(&encoded, &algorithm).unwrap();

    let catr = decoded.request.catr.unwrap();
    assert_eq!(catr.renewal_type, CatRenewalType::Redirect);
    assert_eq!(catr.code, Some(307));
}

#[test]
fn test_catr_builder() {
    let token = CatTokenBuilder::new()
        .issuer("test")
        .renewal(CatRenewal::automatic().with_expadd(600))
        .build();

    let catr = token.request.catr.unwrap();
    assert_eq!(catr.renewal_type, CatRenewalType::Automatic);
    assert_eq!(catr.expadd, Some(600));
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
        .with_if_action(CLAIM_EXP, CatIfAction { status: 401, headers: None, kid: None })
        .with_renewal(CatRenewal::automatic().with_expadd(3600));

    let encoded = encode_token(&token, &algorithm).unwrap();
    let decoded = decode_token(&encoded, &algorithm).unwrap();

    assert!(decoded.request.catif.is_some());
    assert!(decoded.request.catr.is_some());
    assert_eq!(decoded.request.catif.unwrap()[0].1.status, 401);
    assert_eq!(decoded.request.catr.unwrap().renewal_type, CatRenewalType::Automatic);
}
