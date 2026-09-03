// SPDX-FileCopyrightText: Copyright (c) 2022 Quicr
// SPDX-License-Identifier: BSD-2-Clause

//! RFC 8941 Structured Field Values parsing for HTTP header matching.
//!
//! Provides utilities to parse and normalize structured header fields
//! (Items, Lists, Dictionaries) before matching against cath rules.

use crate::CatError;

/// Parse a structured field value as an Item and return its serialized bare value.
pub fn parse_sf_item(input: &str) -> Result<String, CatError> {
    let item = sfv::Parser::parse_item(input.as_bytes())
        .map_err(|_| CatError::InvalidClaimValue("Not a valid SF-Item".to_string()))?;
    Ok(serialize_bare_item(&item.bare_item))
}

/// Parse a structured field value as a List and return the serialized member values.
pub fn parse_sf_list(input: &str) -> Result<Vec<String>, CatError> {
    let list = sfv::Parser::parse_list(input.as_bytes())
        .map_err(|_| CatError::InvalidClaimValue("Not a valid SF-List".to_string()))?;
    Ok(list
        .iter()
        .map(|member| match member {
            sfv::ListEntry::Item(item) => serialize_bare_item(&item.bare_item),
            sfv::ListEntry::InnerList(inner) => {
                let parts: Vec<String> = inner
                    .items
                    .iter()
                    .map(|i| serialize_bare_item(&i.bare_item))
                    .collect();
                format!("({})", parts.join(" "))
            }
        })
        .collect())
}

/// Parse a structured field value as a Dictionary and return key-value pairs.
pub fn parse_sf_dictionary(input: &str) -> Result<Vec<(String, String)>, CatError> {
    let dict = sfv::Parser::parse_dictionary(input.as_bytes())
        .map_err(|_| CatError::InvalidClaimValue("Not a valid SF-Dictionary".to_string()))?;
    Ok(dict
        .iter()
        .map(|(key, member)| {
            let val = match member {
                sfv::ListEntry::Item(item) => serialize_bare_item(&item.bare_item),
                sfv::ListEntry::InnerList(inner) => {
                    let parts: Vec<String> = inner
                        .items
                        .iter()
                        .map(|i| serialize_bare_item(&i.bare_item))
                        .collect();
                    format!("({})", parts.join(" "))
                }
            };
            (key.clone(), val)
        })
        .collect())
}

/// Normalize a structured header value by parsing and re-serializing per RFC 8941.
/// This handles whitespace normalization, quoting, etc.
pub fn normalize_sf_value(input: &str) -> Result<String, CatError> {
    if let Ok(item) = sfv::Parser::parse_item(input.as_bytes()) {
        return Ok(sfv::SerializeValue::serialize_value(&item).map_err(|_| {
            CatError::InvalidClaimValue("Failed to serialize SF-Item".to_string())
        })?);
    }
    if let Ok(list) = sfv::Parser::parse_list(input.as_bytes()) {
        return Ok(sfv::SerializeValue::serialize_value(&list).map_err(|_| {
            CatError::InvalidClaimValue("Failed to serialize SF-List".to_string())
        })?);
    }
    if let Ok(dict) = sfv::Parser::parse_dictionary(input.as_bytes()) {
        return Ok(sfv::SerializeValue::serialize_value(&dict).map_err(|_| {
            CatError::InvalidClaimValue("Failed to serialize SF-Dictionary".to_string())
        })?);
    }
    Err(CatError::InvalidClaimValue(
        "Not a valid RFC 8941 structured field value".to_string(),
    ))
}

/// Extract the value of a specific member from a structured dictionary header.
pub fn get_sf_dictionary_member(input: &str, key: &str) -> Result<Option<String>, CatError> {
    let dict = parse_sf_dictionary(input)?;
    Ok(dict.into_iter().find(|(k, _)| k == key).map(|(_, v)| v))
}

fn serialize_bare_item(item: &sfv::BareItem) -> String {
    match item {
        sfv::BareItem::Integer(i) => i.to_string(),
        sfv::BareItem::Decimal(d) => format!("{d}"),
        sfv::BareItem::String(s) => format!("\"{s}\""),
        sfv::BareItem::Token(t) => t.clone(),
        sfv::BareItem::ByteSeq(b) => {
            use base64::Engine;
            format!(":{}:", base64::engine::general_purpose::STANDARD.encode(b))
        }
        sfv::BareItem::Boolean(b) => if *b { "?1" } else { "?0" }.to_string(),
    }
}
