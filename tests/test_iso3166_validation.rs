// SPDX-FileCopyrightText: Copyright (c) 2022 Quicr
// SPDX-License-Identifier: BSD-2-Clause

use cat_token::*;

#[test]
fn test_alpha2_accepted() {
    assert!(claims::validate_iso3166_code("US").is_ok());
    assert!(claims::validate_iso3166_code("GB").is_ok());
    assert!(claims::validate_iso3166_code("DE").is_ok());
}

#[test]
fn test_alpha3_accepted() {
    assert!(claims::validate_iso3166_code("USA").is_ok());
    assert!(claims::validate_iso3166_code("GBR").is_ok());
}

#[test]
fn test_subdivision_accepted() {
    assert!(claims::validate_iso3166_code("US-CA").is_ok());
    assert!(claims::validate_iso3166_code("GB-ENG").is_ok());
    assert!(claims::validate_iso3166_code("CA-QC").is_ok());
}

#[test]
fn test_lowercase_rejected() {
    assert!(claims::validate_iso3166_code("us").is_err());
    assert!(claims::validate_iso3166_code("gb").is_err());
}

#[test]
fn test_empty_rejected() {
    assert!(claims::validate_iso3166_code("").is_err());
}

#[test]
fn test_numeric_rejected() {
    assert!(claims::validate_iso3166_code("1234").is_err());
}

#[test]
fn test_single_char_rejected() {
    assert!(claims::validate_iso3166_code("U").is_err());
}

#[test]
fn test_four_chars_rejected() {
    assert!(claims::validate_iso3166_code("USAA").is_err());
}

#[test]
fn test_validator_checks_iso3166() {
    let mut token = CatToken::new();
    token.cat.catgeoiso3166 = Some(vec!["US".to_string(), "GB".to_string()]);
    let validator = CatTokenValidator::new();
    assert!(validator.validate(&token).is_ok());
}

#[test]
fn test_validator_rejects_invalid_iso3166() {
    let mut token = CatToken::new();
    token.cat.catgeoiso3166 = Some(vec!["US".to_string(), "invalid".to_string()]);
    let validator = CatTokenValidator::new();
    assert!(validator.validate(&token).is_err());
}
