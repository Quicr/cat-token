// SPDX-FileCopyrightText: Copyright (c) 2022 Quicr
// SPDX-License-Identifier: BSD-2-Clause

use cat_token::structured_header::*;

// --- SF-Item parsing ---

#[test]
fn test_parse_sf_item_integer() {
    let val = parse_sf_item("42").unwrap();
    assert_eq!(val, "42");
}

#[test]
fn test_parse_sf_item_string() {
    let val = parse_sf_item("\"hello\"").unwrap();
    assert_eq!(val, "\"hello\"");
}

#[test]
fn test_parse_sf_item_token() {
    let val = parse_sf_item("gzip").unwrap();
    assert_eq!(val, "gzip");
}

#[test]
fn test_parse_sf_item_boolean() {
    let val = parse_sf_item("?1").unwrap();
    assert_eq!(val, "?1");
}

#[test]
fn test_parse_sf_item_decimal() {
    let val = parse_sf_item("3.14").unwrap();
    assert!(val.starts_with("3.14"));
}

// --- SF-List parsing ---

#[test]
fn test_parse_sf_list_basic() {
    let vals = parse_sf_list("gzip, deflate, br").unwrap();
    assert_eq!(vals, vec!["gzip", "deflate", "br"]);
}

#[test]
fn test_parse_sf_list_integers() {
    let vals = parse_sf_list("1, 2, 3").unwrap();
    assert_eq!(vals, vec!["1", "2", "3"]);
}

#[test]
fn test_parse_sf_list_inner_list() {
    let vals = parse_sf_list("(gzip br), deflate").unwrap();
    assert_eq!(vals.len(), 2);
    assert_eq!(vals[0], "(gzip br)");
    assert_eq!(vals[1], "deflate");
}

// --- SF-Dictionary parsing ---

#[test]
fn test_parse_sf_dictionary() {
    let pairs = parse_sf_dictionary("a=1, b=2").unwrap();
    assert_eq!(pairs.len(), 2);
    assert_eq!(pairs[0], ("a".to_string(), "1".to_string()));
    assert_eq!(pairs[1], ("b".to_string(), "2".to_string()));
}

#[test]
fn test_parse_sf_dictionary_boolean_member() {
    let pairs = parse_sf_dictionary("gzip, br").unwrap();
    assert_eq!(pairs.len(), 2);
    assert_eq!(pairs[0].0, "gzip");
    assert_eq!(pairs[0].1, "?1");
    assert_eq!(pairs[1].0, "br");
    assert_eq!(pairs[1].1, "?1");
}

// --- get_sf_dictionary_member ---

#[test]
fn test_get_dictionary_member_found() {
    let val = get_sf_dictionary_member("a=1, b=2, c=3", "b").unwrap();
    assert_eq!(val, Some("2".to_string()));
}

#[test]
fn test_get_dictionary_member_not_found() {
    let val = get_sf_dictionary_member("a=1, b=2", "z").unwrap();
    assert_eq!(val, None);
}

// --- normalize_sf_value ---

#[test]
fn test_normalize_item() {
    let normalized = normalize_sf_value("42").unwrap();
    assert_eq!(normalized, "42");
}

#[test]
fn test_normalize_list() {
    let normalized = normalize_sf_value("gzip,  deflate,   br").unwrap();
    assert_eq!(normalized, "gzip, deflate, br");
}

#[test]
fn test_normalize_dictionary() {
    let normalized = normalize_sf_value("a=1,  b=2").unwrap();
    assert_eq!(normalized, "a=1, b=2");
}

// --- Error cases ---

#[test]
fn test_parse_sf_item_invalid() {
    assert!(parse_sf_item("(not an item)").is_err());
}

#[test]
fn test_normalize_invalid() {
    assert!(normalize_sf_value("\x00\x01\x02").is_err());
}

// --- Integration with cath matching ---

#[test]
fn test_sf_normalized_matching_with_cath() {
    use cat_token::*;

    let mut token = CatToken::new();
    let normalized = normalize_sf_value("gzip, deflate, br").unwrap();
    token.cat.cath = Some(vec![claims::HeaderMatchRule {
        name: "Accept-Encoding".to_string(),
        matches: vec![claims::MatchValue::Exact(normalized)],
    }]);

    let input = normalize_sf_value("gzip,  deflate,   br").unwrap();
    assert!(validate_header(&token, "accept-encoding", &input).is_ok());
}
