// Tests for catu (URI match rules) and cath (header match rules) per CTA-5007-B spec.
// catu: map of URI component → match-map
// cath: map of header-name → match-map

use cat_token::*;

#[test]
fn test_catu_single_component_exact_match() {
    let rules = vec![UriMatchRule {
        component: URI_COMPONENT_HOST,
        matches: vec![MatchValue::Exact("example.com".to_string())],
    }];
    let token = CatToken::new().with_uri_match_rules(rules.clone());
    assert_eq!(token.cat.catu, Some(rules));
}

#[test]
fn test_catu_multiple_components() {
    let rules = vec![
        UriMatchRule {
            component: URI_COMPONENT_SCHEME,
            matches: vec![MatchValue::Exact("https".to_string())],
        },
        UriMatchRule {
            component: URI_COMPONENT_HOST,
            matches: vec![MatchValue::Exact("cdn.example.com".to_string())],
        },
        UriMatchRule {
            component: URI_COMPONENT_PATH,
            matches: vec![MatchValue::Prefix("/media/".to_string())],
        },
    ];
    let token = CatToken::new().with_uri_match_rules(rules.clone());
    assert_eq!(token.cat.catu.as_ref().unwrap().len(), 3);
    assert_eq!(token.cat.catu, Some(rules));
}

#[test]
fn test_catu_multiple_match_values_per_component() {
    let rules = vec![UriMatchRule {
        component: URI_COMPONENT_EXTENSION,
        matches: vec![
            MatchValue::Exact("m3u8".to_string()),
            MatchValue::Exact("ts".to_string()),
            MatchValue::Exact("mp4".to_string()),
        ],
    }];
    let token = CatToken::new().with_uri_match_rules(rules.clone());
    let catu = token.cat.catu.unwrap();
    assert_eq!(catu[0].matches.len(), 3);
}

#[test]
fn test_catu_all_match_types() {
    let rules = vec![UriMatchRule {
        component: URI_COMPONENT_PATH,
        matches: vec![
            MatchValue::Exact("/api/v1/resource".to_string()),
            MatchValue::Prefix("/api/".to_string()),
            MatchValue::Suffix(".json".to_string()),
            MatchValue::Contains("v1".to_string()),
            MatchValue::Regex("^/api/v[0-9]+/".to_string()),
            MatchValue::Sha256(vec![0xab; 32]),
        ],
    }];
    let token = CatToken::new().with_uri_match_rules(rules.clone());
    let catu = token.cat.catu.unwrap();
    assert_eq!(catu[0].matches.len(), 6);
    assert!(matches!(catu[0].matches[0], MatchValue::Exact(_)));
    assert!(matches!(catu[0].matches[1], MatchValue::Prefix(_)));
    assert!(matches!(catu[0].matches[2], MatchValue::Suffix(_)));
    assert!(matches!(catu[0].matches[3], MatchValue::Contains(_)));
    assert!(matches!(catu[0].matches[4], MatchValue::Regex(_)));
    assert!(matches!(catu[0].matches[5], MatchValue::Sha256(_)));
}

#[test]
fn test_catu_all_uri_components() {
    let components = [
        URI_COMPONENT_SCHEME,
        URI_COMPONENT_HOST,
        URI_COMPONENT_PORT,
        URI_COMPONENT_PATH,
        URI_COMPONENT_QUERY,
        URI_COMPONENT_PARENT_PATH,
        URI_COMPONENT_FILENAME,
        URI_COMPONENT_STEM,
        URI_COMPONENT_EXTENSION,
    ];
    let rules: Vec<UriMatchRule> = components
        .iter()
        .map(|&c| UriMatchRule {
            component: c,
            matches: vec![MatchValue::Exact("test".to_string())],
        })
        .collect();
    let token = CatToken::new().with_uri_match_rules(rules);
    assert_eq!(token.cat.catu.as_ref().unwrap().len(), 9);
}

#[test]
fn test_cath_single_header() {
    let rules = vec![HeaderMatchRule {
        name: "Authorization".to_string(),
        matches: vec![MatchValue::Prefix("Bearer ".to_string())],
    }];
    let token = CatToken::new().with_header_match_rules(rules.clone());
    assert_eq!(token.cat.cath, Some(rules));
}

#[test]
fn test_cath_multiple_headers() {
    let rules = vec![
        HeaderMatchRule {
            name: "Content-Type".to_string(),
            matches: vec![MatchValue::Exact("application/json".to_string())],
        },
        HeaderMatchRule {
            name: "Accept".to_string(),
            matches: vec![
                MatchValue::Exact("application/json".to_string()),
                MatchValue::Prefix("text/".to_string()),
            ],
        },
    ];
    let token = CatToken::new().with_header_match_rules(rules.clone());
    let cath = token.cat.cath.unwrap();
    assert_eq!(cath.len(), 2);
    assert_eq!(cath[0].name, "Content-Type");
    assert_eq!(cath[1].matches.len(), 2);
}

#[test]
fn test_catu_roundtrip_encode_decode() {
    let rules = vec![
        UriMatchRule {
            component: URI_COMPONENT_HOST,
            matches: vec![MatchValue::Exact("example.com".to_string())],
        },
        UriMatchRule {
            component: URI_COMPONENT_PATH,
            matches: vec![
                MatchValue::Prefix("/api/".to_string()),
                MatchValue::Suffix(".json".to_string()),
            ],
        },
    ];
    let token = CatToken::new()
        .with_issuer("test")
        .with_uri_match_rules(rules.clone());

    let alg = HmacSha256Algorithm::generate_key().unwrap();
    let algorithm = HmacSha256Algorithm::from_secret_key(&alg);
    let encoded = encode_token(&token, &algorithm).unwrap();
    let decoded = decode_token(&encoded, &algorithm).unwrap();

    assert_eq!(decoded.cat.catu, Some(rules));
}

#[test]
fn test_cath_roundtrip_encode_decode() {
    let rules = vec![HeaderMatchRule {
        name: "X-Custom-Header".to_string(),
        matches: vec![MatchValue::Contains("token".to_string())],
    }];
    let token = CatToken::new()
        .with_issuer("test")
        .with_header_match_rules(rules.clone());

    let alg = HmacSha256Algorithm::generate_key().unwrap();
    let algorithm = HmacSha256Algorithm::from_secret_key(&alg);
    let encoded = encode_token(&token, &algorithm).unwrap();
    let decoded = decode_token(&encoded, &algorithm).unwrap();

    assert_eq!(decoded.cat.cath, Some(rules));
}

#[test]
fn test_catu_and_cath_together() {
    let uri_rules = vec![UriMatchRule {
        component: URI_COMPONENT_PATH,
        matches: vec![MatchValue::Prefix("/stream/".to_string())],
    }];
    let header_rules = vec![HeaderMatchRule {
        name: "Authorization".to_string(),
        matches: vec![MatchValue::Prefix("Bearer ".to_string())],
    }];
    let token = CatToken::new()
        .with_issuer("test")
        .with_uri_match_rules(uri_rules.clone())
        .with_header_match_rules(header_rules.clone());

    let alg = HmacSha256Algorithm::generate_key().unwrap();
    let algorithm = HmacSha256Algorithm::from_secret_key(&alg);
    let encoded = encode_token(&token, &algorithm).unwrap();
    let decoded = decode_token(&encoded, &algorithm).unwrap();

    assert_eq!(decoded.cat.catu, Some(uri_rules));
    assert_eq!(decoded.cat.cath, Some(header_rules));
}

#[test]
fn test_catu_sha256_match_roundtrip() {
    let hash = vec![
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
        0x1d, 0x1e, 0x1f, 0x20,
    ];
    let rules = vec![UriMatchRule {
        component: URI_COMPONENT_PATH,
        matches: vec![MatchValue::Sha256(hash.clone())],
    }];
    let token = CatToken::new()
        .with_issuer("test")
        .with_uri_match_rules(rules.clone());

    let alg = HmacSha256Algorithm::generate_key().unwrap();
    let algorithm = HmacSha256Algorithm::from_secret_key(&alg);
    let encoded = encode_token(&token, &algorithm).unwrap();
    let decoded = decode_token(&encoded, &algorithm).unwrap();

    assert_eq!(decoded.cat.catu, Some(rules));
}

#[test]
fn test_builder_uri_match_rules() {
    let rules = vec![UriMatchRule {
        component: URI_COMPONENT_HOST,
        matches: vec![MatchValue::Exact("api.example.com".to_string())],
    }];
    let token = CatTokenBuilder::new()
        .uri_match_rules(rules.clone())
        .build();
    assert_eq!(token.cat.catu, Some(rules));
}

#[test]
fn test_builder_header_match_rules() {
    let rules = vec![HeaderMatchRule {
        name: "Content-Type".to_string(),
        matches: vec![MatchValue::Exact("application/cbor".to_string())],
    }];
    let token = CatTokenBuilder::new()
        .header_match_rules(rules.clone())
        .build();
    assert_eq!(token.cat.cath, Some(rules));
}
