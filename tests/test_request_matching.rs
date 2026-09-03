// SPDX-FileCopyrightText: Copyright (c) 2022 Quicr
// SPDX-License-Identifier: BSD-2-Clause

use cat_token::*;

// --- catm method matching (§4.6.11) ---

#[test]
fn test_catm_get_allowed() {
    let mut token = CatToken::new();
    token.cat.catm = Some(vec!["GET".to_string(), "POST".to_string()]);
    assert!(validate_method(&token, "GET").is_ok());
}

#[test]
fn test_catm_case_sensitive() {
    let mut token = CatToken::new();
    token.cat.catm = Some(vec!["GET".to_string(), "POST".to_string()]);
    assert!(validate_method(&token, "get").is_err());
}

#[test]
fn test_catm_unlisted_rejected() {
    let mut token = CatToken::new();
    token.cat.catm = Some(vec!["GET".to_string(), "POST".to_string()]);
    assert!(validate_method(&token, "DELETE").is_err());
}

#[test]
fn test_catm_absent_allows_all() {
    let token = CatToken::new();
    assert!(validate_method(&token, "GET").is_ok());
    assert!(validate_method(&token, "ANYTHING").is_ok());
}

// --- cath header matching (§4.6.13) ---

#[test]
fn test_cath_case_insensitive_name() {
    let mut token = CatToken::new();
    token.cat.cath = Some(vec![claims::HeaderMatchRule {
        name: "Content-Type".to_string(),
        matches: vec![claims::MatchValue::Exact("text/html".to_string())],
    }]);
    assert!(validate_header(&token, "content-type", "text/html").is_ok());
    assert!(validate_header(&token, "CONTENT-TYPE", "text/html").is_ok());
}

#[test]
fn test_cath_value_mismatch() {
    let mut token = CatToken::new();
    token.cat.cath = Some(vec![claims::HeaderMatchRule {
        name: "Content-Type".to_string(),
        matches: vec![claims::MatchValue::Exact("text/html".to_string())],
    }]);
    assert!(validate_header(&token, "Content-Type", "application/json").is_err());
}

#[test]
fn test_cath_prefix_match() {
    let mut token = CatToken::new();
    token.cat.cath = Some(vec![claims::HeaderMatchRule {
        name: "Authorization".to_string(),
        matches: vec![claims::MatchValue::Prefix("Bearer ".to_string())],
    }]);
    assert!(validate_header(&token, "authorization", "Bearer abc123").is_ok());
    assert!(validate_header(&token, "authorization", "Basic abc123").is_err());
}

#[test]
fn test_cath_absent_allows_all() {
    let token = CatToken::new();
    assert!(validate_header(&token, "Any-Header", "any-value").is_ok());
}

// --- header folding (RFC 9110 §5.2) ---

#[test]
fn test_unfold_obs_fold() {
    let val = "value1\r\n value2";
    assert_eq!(unfold_header_value(val), "value1 value2");
}

#[test]
fn test_unfold_obs_fold_tab() {
    let val = "value1\r\n\tvalue2";
    assert_eq!(unfold_header_value(val), "value1 value2");
}

#[test]
fn test_unfold_no_fold() {
    let val = "value1, value2";
    assert_eq!(unfold_header_value(val), "value1, value2");
}

// --- catu token stripping (§4.6.10) ---

#[test]
fn test_strip_cat_token_from_uri() {
    let uri = "https://example.com/path?CATToken=abc123&key=value";
    let stripped = strip_token_from_uri(uri, &["CATToken", "token"]);
    assert_eq!(stripped, "https://example.com/path?key=value");
}

#[test]
fn test_strip_token_only_param() {
    let uri = "https://example.com/path?token=xyz";
    let stripped = strip_token_from_uri(uri, &["CATToken", "token"]);
    assert_eq!(stripped, "https://example.com/path");
}

#[test]
fn test_strip_no_token_param() {
    let uri = "https://example.com/path?key=value";
    let stripped = strip_token_from_uri(uri, &["CATToken", "token"]);
    assert_eq!(stripped, "https://example.com/path?key=value");
}

#[test]
fn test_strip_no_query() {
    let uri = "https://example.com/path";
    let stripped = strip_token_from_uri(uri, &["CATToken", "token"]);
    assert_eq!(stripped, "https://example.com/path");
}

// --- catpor enforcement (§4.6.7) ---

#[test]
fn test_catpor_probability_1_always_rejected() {
    let token = CatTokenBuilder::new()
        .probability_of_rejection(1.0, vec![1, 2, 3], None)
        .build();
    let block_list = CatPorBlockList::new();
    assert!(enforce_catpor(&token, &block_list).is_err());
}

#[test]
fn test_catpor_probability_0_never_rejected() {
    let token = CatTokenBuilder::new()
        .probability_of_rejection(0.0, vec![1, 2, 3], None)
        .build();
    let block_list = CatPorBlockList::new();
    // With probability 0, should never be rejected (run multiple times)
    for _ in 0..100 {
        assert!(enforce_catpor(&token, &block_list).is_ok());
    }
}

#[test]
fn test_catpor_block_list_persists() {
    let block_list = CatPorBlockList::new();
    // Manually block an ID
    block_list.add(vec![1, 2, 3], None);

    let token = CatTokenBuilder::new()
        .probability_of_rejection(0.0, vec![1, 2, 3], None)
        .build();

    // Even with 0 probability, blocked ID is rejected
    assert!(enforce_catpor(&token, &block_list).is_err());
}

#[test]
fn test_catpor_block_list_expiration() {
    let block_list = CatPorBlockList::new();
    // Block with an expiration in the past
    block_list.add(vec![1, 2, 3], Some(0));

    let token = CatTokenBuilder::new()
        .probability_of_rejection(0.0, vec![1, 2, 3], None)
        .build();

    // Expired block = not blocked
    assert!(enforce_catpor(&token, &block_list).is_ok());
}

#[test]
fn test_catpor_absent_passes() {
    let token = CatToken::new();
    let block_list = CatPorBlockList::new();
    assert!(enforce_catpor(&token, &block_list).is_ok());
}

// --- apply_match_value ---

#[test]
fn test_match_exact() {
    assert!(apply_match_value(
        &claims::MatchValue::Exact("hello".to_string()),
        "hello"
    ));
    assert!(!apply_match_value(
        &claims::MatchValue::Exact("hello".to_string()),
        "world"
    ));
}

#[test]
fn test_match_prefix() {
    assert!(apply_match_value(
        &claims::MatchValue::Prefix("/api/".to_string()),
        "/api/users"
    ));
    assert!(!apply_match_value(
        &claims::MatchValue::Prefix("/api/".to_string()),
        "/web/users"
    ));
}

#[test]
fn test_match_suffix() {
    assert!(apply_match_value(
        &claims::MatchValue::Suffix(".html".to_string()),
        "index.html"
    ));
}

#[test]
fn test_match_contains() {
    assert!(apply_match_value(
        &claims::MatchValue::Contains("user".to_string()),
        "/api/users/123"
    ));
}

#[test]
fn test_match_regex() {
    assert!(apply_match_value(
        &claims::MatchValue::Regex("^/api/v[0-9]+".to_string()),
        "/api/v2/users"
    ));
}
