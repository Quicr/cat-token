// Tests for POSIX ERE regex validation (IEEE 1003.1-2017 §9.4).

use cat_token::*;

#[test]
fn test_valid_ere_patterns() {
    assert!(validate_posix_ere("^https://.*\\.example\\.com$").is_none());
    assert!(validate_posix_ere("[0-9]+").is_none());
    assert!(validate_posix_ere("(a|b|c)").is_none());
    assert!(validate_posix_ere("^/v[0-9]+/.*$").is_none());
    assert!(validate_posix_ere("[[:alpha:]]+").is_none());
    assert!(validate_posix_ere("a{2,5}").is_none());
    assert!(validate_posix_ere("\\(literal\\)").is_none());
}

#[test]
fn test_perl_shortcut_d_rejected() {
    let result = validate_posix_ere("\\d+");
    assert!(result.is_some());
    assert!(result.unwrap().contains("\\d"));
}

#[test]
fn test_perl_shortcut_w_rejected() {
    let result = validate_posix_ere("\\w+");
    assert!(result.is_some());
    assert!(result.unwrap().contains("\\w"));
}

#[test]
fn test_perl_shortcut_s_rejected() {
    let result = validate_posix_ere("\\s+");
    assert!(result.is_some());
    assert!(result.unwrap().contains("\\s"));
}

#[test]
fn test_perl_word_boundary_rejected() {
    let result = validate_posix_ere("\\bword\\b");
    assert!(result.is_some());
    assert!(result.unwrap().contains("\\b"));
}

#[test]
fn test_non_greedy_quantifier_rejected() {
    assert!(validate_posix_ere("a*?").is_some());
    assert!(validate_posix_ere("a+?").is_some());
    assert!(validate_posix_ere("a??").is_some());
}

#[test]
fn test_lookahead_rejected() {
    assert!(validate_posix_ere("(?=foo)bar").is_some());
    assert!(validate_posix_ere("(?!foo)bar").is_some());
}

#[test]
fn test_validator_rejects_non_ere_regex_in_catu() {
    let token = CatToken::new()
        .with_uri_match_rules(vec![UriMatchRule {
            component: URI_COMPONENT_PATH,
            matches: vec![MatchValue::Regex("\\d+".to_string())],
        }]);

    let validator = CatTokenValidator::new();
    let result = validator.validate(&token);
    assert!(result.is_err());
    match result {
        Err(CatError::InvalidClaimValue(msg)) => {
            assert!(msg.contains("catu regex"), "Error: {msg}");
        }
        other => panic!("Expected InvalidClaimValue, got: {other:?}"),
    }
}

#[test]
fn test_validator_rejects_non_ere_regex_in_cath() {
    let token = CatToken::new()
        .with_header_match_rules(vec![HeaderMatchRule {
            name: "Content-Type".to_string(),
            matches: vec![MatchValue::Regex("\\w+/\\w+".to_string())],
        }]);

    let validator = CatTokenValidator::new();
    let result = validator.validate(&token);
    assert!(result.is_err());
    match result {
        Err(CatError::InvalidClaimValue(msg)) => {
            assert!(msg.contains("cath regex"), "Error: {msg}");
        }
        other => panic!("Expected InvalidClaimValue, got: {other:?}"),
    }
}

#[test]
fn test_validator_accepts_ere_regex() {
    let token = CatToken::new()
        .with_uri_match_rules(vec![UriMatchRule {
            component: URI_COMPONENT_PATH,
            matches: vec![MatchValue::Regex("^/v[0-9]+/.*$".to_string())],
        }]);

    let validator = CatTokenValidator::new();
    assert!(validator.validate(&token).is_ok());
}
