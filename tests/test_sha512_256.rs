// Tests for CTA-5007-B §4.6.10: SHA-512/256 hash match type (-2).

use cat_token::*;

#[test]
fn test_sha512_256_match_roundtrip() {
    let alg = HmacSha256Algorithm::generate_key().unwrap();
    let algorithm = HmacSha256Algorithm::from_secret_key(&alg);

    let hash = vec![0xAA; 32];
    let rules = vec![UriMatchRule {
        component: URI_COMPONENT_PATH,
        matches: vec![MatchValue::Sha512_256(hash.clone())],
    }];

    let token = CatToken::new()
        .with_issuer("test")
        .with_uri_match_rules(rules.clone());

    let encoded = encode_token(&token, &algorithm).unwrap();
    let decoded = decode_token(&encoded, &algorithm).unwrap();

    assert_eq!(decoded.cat.catu, Some(rules));
}

#[test]
fn test_sha512_256_in_header_match() {
    let alg = HmacSha256Algorithm::generate_key().unwrap();
    let algorithm = HmacSha256Algorithm::from_secret_key(&alg);

    let hash = vec![0xBB; 32];
    let rules = vec![HeaderMatchRule {
        name: "Authorization".to_string(),
        matches: vec![MatchValue::Sha512_256(hash.clone())],
    }];

    let token = CatToken::new()
        .with_issuer("test")
        .with_header_match_rules(rules.clone());

    let encoded = encode_token(&token, &algorithm).unwrap();
    let decoded = decode_token(&encoded, &algorithm).unwrap();

    assert_eq!(decoded.cat.cath, Some(rules));
}

#[test]
fn test_sha256_and_sha512_256_coexist() {
    let alg = HmacSha256Algorithm::generate_key().unwrap();
    let algorithm = HmacSha256Algorithm::from_secret_key(&alg);

    let rules = vec![UriMatchRule {
        component: URI_COMPONENT_PATH,
        matches: vec![
            MatchValue::Sha256(vec![0x11; 32]),
            MatchValue::Sha512_256(vec![0x22; 32]),
        ],
    }];

    let token = CatToken::new()
        .with_issuer("test")
        .with_uri_match_rules(rules.clone());

    let encoded = encode_token(&token, &algorithm).unwrap();
    let decoded = decode_token(&encoded, &algorithm).unwrap();

    let decoded_rules = decoded.cat.catu.unwrap();
    assert_eq!(decoded_rules[0].matches.len(), 2);
    assert!(matches!(decoded_rules[0].matches[0], MatchValue::Sha256(_)));
    assert!(matches!(
        decoded_rules[0].matches[1],
        MatchValue::Sha512_256(_)
    ));
}
