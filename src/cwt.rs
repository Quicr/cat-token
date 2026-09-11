// SPDX-FileCopyrightText: Copyright (c) 2022 Quicr
// SPDX-License-Identifier: BSD-2-Clause

use crate::claims::*;
use crate::claims::{CatClaims, CoreClaims};
use crate::{CatError, CatToken, GeoCoordinate};
use ciborium::Value;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::net::IpAddr;

const CBOR_TAG_IPV4: u64 = 52;
const CBOR_TAG_IPV6: u64 = 54;
const CBOR_TAG_CRS: u64 = 279;
const CRS_WGS84: u64 = 0;

fn unwrap_crs_tag(value: Value) -> Result<Value, CatError> {
    match value {
        Value::Tag(tag, inner) if tag == CBOR_TAG_CRS => {
            if let Value::Array(ref arr) = *inner
                && arr.len() == 2
            {
                let crs_id = match &arr[0] {
                    Value::Integer(i) => {
                        let v: u64 = (*i).try_into().unwrap_or(u64::MAX);
                        v
                    }
                    _ => {
                        return Err(CatError::InvalidClaimValue(
                            "CRS Wrapper: invalid CRS identifier type".to_string(),
                        ));
                    }
                };
                if crs_id != CRS_WGS84 {
                    return Err(CatError::InvalidClaimValue(format!(
                        "Unsupported CRS identifier: {crs_id} (only WGS84/0 is supported)"
                    )));
                }
                return Ok(arr[1].clone());
            }
            Err(CatError::InvalidClaimValue(
                "CRS Wrapper tag 279: expected [crs_id, value]".to_string(),
            ))
        }
        other => Ok(other),
    }
}

fn validate_cbor_map_ordering_limited(
    map: &[(Value, Value)],
    max_depth: usize,
) -> Result<(), CatError> {
    validate_cbor_map_ordering_with_depth(map, 0, max_depth)
}

/// RFC 8949 §4.2.1 canonical ordering for integer keys.
/// Major type 0 (unsigned/non-negative) sorts before major type 1 (negative).
/// Within each group, keys sort by ascending absolute value.
/// Correct order: 0, 1, 2, ..., -1, -2, -3, ...
fn cbor_canonical_key_cmp(a: i64, b: i64) -> std::cmp::Ordering {
    match (a >= 0, b >= 0) {
        (true, true) => a.cmp(&b),
        (false, false) => {
            // Both negative: -1 < -2 < -3 in canonical order (smaller abs first)
            // -1 has abs 1, -2 has abs 2, so compare absolute values ascending
            b.cmp(&a) // reverse because more negative = larger abs
        }
        (true, false) => std::cmp::Ordering::Less, // non-negative before negative
        (false, true) => std::cmp::Ordering::Greater,
    }
}

/// Canonical fingerprint for a CBOR key, used only for duplicate detection.
/// Integers are represented natively; text/byte strings are tagged with major
/// type; other types (float, bool, null) get their own bucket. This is
/// intentionally distinct from any wire representation — its only job is to
/// make "the same key twice" observable at every nesting level.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum KeyFingerprint {
    Int(i128),
    Text(String),
    Bytes(Vec<u8>),
    Other(&'static str),
}

fn key_fingerprint(v: &Value) -> Option<KeyFingerprint> {
    match v {
        Value::Integer(i) => Some(KeyFingerprint::Int(i128::from(*i))),
        Value::Text(s) => Some(KeyFingerprint::Text(s.clone())),
        Value::Bytes(b) => Some(KeyFingerprint::Bytes(b.clone())),
        Value::Bool(_) => Some(KeyFingerprint::Other("bool")),
        Value::Null => Some(KeyFingerprint::Other("null")),
        Value::Float(_) => Some(KeyFingerprint::Other("float")),
        // Arrays/maps/tags are not valid CBOR map keys in CTA-5007-B's profile
        _ => None,
    }
}

fn validate_cbor_map_ordering_with_depth(
    map: &[(Value, Value)],
    depth: usize,
    max_depth: usize,
) -> Result<(), CatError> {
    if depth > max_depth {
        return Err(CatError::InvalidCbor(format!(
            "CBOR nesting depth exceeds limit of {max_depth}"
        )));
    }
    let mut prev_key: Option<i64> = None;
    let mut seen: std::collections::HashSet<KeyFingerprint> =
        std::collections::HashSet::with_capacity(map.len());
    for (key, value) in map {
        // Detect duplicate map keys at every nesting depth, regardless of key type.
        // RFC 8949 §4.2.2 forbids duplicate map keys in a validity-critical profile.
        if let Some(fp) = key_fingerprint(key)
            && !seen.insert(fp)
        {
            return Err(CatError::InvalidCbor("Duplicate map key".to_string()));
        }
        // Only enforce deterministic ordering on integer-keyed top-level maps.
        // Nested claim structures (catif, catr, catnip, catdpop) may use
        // arbitrary orderings.
        if let Value::Integer(i) = key {
            let k: i64 = (*i).try_into().unwrap_or(i64::MAX);
            if let Some(prev) = prev_key
                && cbor_canonical_key_cmp(k, prev) != std::cmp::Ordering::Greater
            {
                return Err(CatError::InvalidCbor(
                    "Map keys not in deterministic order per RFC 8949 §4.2.1".to_string(),
                ));
            }
            prev_key = Some(k);
        }
        validate_nested_maps_with_depth(value, depth + 1, max_depth)?;
    }
    Ok(())
}

fn validate_nested_maps_with_depth(
    value: &Value,
    depth: usize,
    max_depth: usize,
) -> Result<(), CatError> {
    if depth > max_depth {
        return Err(CatError::InvalidCbor(format!(
            "CBOR nesting depth exceeds limit of {max_depth}"
        )));
    }
    match value {
        Value::Map(nested_map) => {
            validate_cbor_map_ordering_with_depth(nested_map, depth, max_depth)?;
        }
        Value::Array(arr) => {
            for item in arr {
                validate_nested_maps_with_depth(item, depth + 1, max_depth)?;
            }
        }
        Value::Tag(_, inner) => {
            validate_nested_maps_with_depth(inner, depth + 1, max_depth)?;
        }
        _ => {}
    }
    Ok(())
}

fn validate_float(f: f64, claim_name: &str) -> Result<(), CatError> {
    if f.is_nan() {
        return Err(CatError::InvalidClaimValue(format!(
            "{claim_name}: NaN is not permitted per CTA-5007-B §4.5"
        )));
    }
    if f.is_infinite() {
        return Err(CatError::InvalidClaimValue(format!(
            "{claim_name}: infinity is not permitted per CTA-5007-B §4.5"
        )));
    }
    if f == 0.0 && f.is_sign_negative() {
        return Err(CatError::InvalidClaimValue(format!(
            "{claim_name}: negative zero is not permitted per CTA-5007-B §4.5"
        )));
    }
    Ok(())
}

/// Convert a float claim value to `i64`, rejecting fractional or out-of-range
/// values. This is the strict profile: an authorization decision must never
/// silently change semantics through truncation. Callers that need fractional
/// preservation should keep the value as `f64` (see `catr.expadd`).
fn safe_float_to_i64(f: f64, claim_name: &str) -> Result<i64, CatError> {
    validate_float(f, claim_name)?;
    if f != f.trunc() {
        return Err(CatError::InvalidClaimValue(format!(
            "{claim_name}: fractional numeric dates are not permitted in this profile"
        )));
    }
    // f.trunc() equals f, and |f| <= 2^63 — use a strict comparison since
    // (i64::MAX as f64) rounds up to 2^63, which is NOT representable in i64.
    if f >= (i64::MAX as f64) || f <= (i64::MIN as f64) {
        return Err(CatError::InvalidClaimValue(format!(
            "{claim_name}: float magnitude {f} exceeds i64 range"
        )));
    }
    Ok(f as i64)
}

fn safe_float_to_u32(f: f64, claim_name: &str) -> Result<u32, CatError> {
    validate_float(f, claim_name)?;
    if f < 0.0 {
        return Err(CatError::InvalidClaimValue(format!(
            "{claim_name}: value must not be negative"
        )));
    }
    if f != f.trunc() {
        return Err(CatError::InvalidClaimValue(format!(
            "{claim_name}: fractional values are not permitted in this profile"
        )));
    }
    if f > (u32::MAX as f64) {
        return Err(CatError::InvalidClaimValue(format!(
            "{claim_name}: float magnitude {f} exceeds u32 range"
        )));
    }
    Ok(f as u32)
}

fn reject_unexpected_tag(value: &Value, claim_name: &str) -> Result<(), CatError> {
    if let Value::Tag(tag, _) = value {
        return Err(CatError::InvalidClaimValue(format!(
            "{claim_name}: unexpected CBOR tag {tag} (claims MUST NOT be tagged per CTA-5007-B §4.5)"
        )));
    }
    Ok(())
}

fn decode_text_array(value: Value, context: &str) -> Result<Vec<String>, CatError> {
    if let Value::Array(arr) = value {
        let mut result = Vec::new();
        for item in arr {
            if let Value::Text(s) = item {
                result.push(s);
            } else {
                return Err(CatError::InvalidClaimValue(format!(
                    "{context} must contain only text strings"
                )));
            }
        }
        Ok(result)
    } else {
        Err(CatError::InvalidClaimValue(format!(
            "{context} must be an array"
        )))
    }
}

fn sort_integer_keyed_map(map: &mut [(Value, Value)]) {
    map.sort_by(|(a, _), (b, _)| {
        let a_key = match a {
            Value::Integer(i) => (*i).try_into().unwrap_or(i64::MAX),
            _ => i64::MAX,
        };
        let b_key = match b {
            Value::Integer(i) => (*i).try_into().unwrap_or(i64::MAX),
            _ => i64::MAX,
        };
        cbor_canonical_key_cmp(a_key, b_key)
    });
}

fn encode_composite_claim(composite: &crate::claims::CompositeClaim) -> Result<Value, CatError> {
    let mut claim_sets = Vec::new();
    for cs in &composite.claims {
        match cs {
            crate::claims::ClaimSet::Token(token) => {
                let cwt = Cwt::new(0, (**token).clone());
                let encoded = cwt.encode_payload()?;
                let value: Value = ciborium::de::from_reader(encoded.as_slice())
                    .map_err(|e| CatError::InvalidCbor(e.to_string()))?;
                claim_sets.push(value);
            }
            crate::claims::ClaimSet::Composite(nested) => {
                let nested_claim_id = match nested.op {
                    crate::claims::CompositeOperator::Or => CLAIM_OR,
                    crate::claims::CompositeOperator::Nor => CLAIM_NOR,
                    crate::claims::CompositeOperator::And => CLAIM_AND,
                };
                let nested_value = encode_composite_claim(nested)?;
                let wrapper =
                    Value::Map(vec![(Value::Integer(nested_claim_id.into()), nested_value)]);
                claim_sets.push(wrapper);
            }
        }
    }
    Ok(Value::Array(claim_sets))
}

fn encode_number_shortest(f: f64) -> Value {
    if f.is_finite() && f == f.trunc() && f.abs() < (i64::MAX as f64) {
        Value::Integer((f as i64).into())
    } else {
        Value::Float(f)
    }
}

fn encode_match_value(m: &MatchValue) -> (Value, Value) {
    match m {
        MatchValue::Exact(s) => (Value::Integer(MATCH_EXACT.into()), Value::Text(s.clone())),
        MatchValue::Prefix(s) => (Value::Integer(MATCH_PREFIX.into()), Value::Text(s.clone())),
        MatchValue::Suffix(s) => (Value::Integer(MATCH_SUFFIX.into()), Value::Text(s.clone())),
        MatchValue::Contains(s) => (
            Value::Integer(MATCH_CONTAINS.into()),
            Value::Text(s.clone()),
        ),
        MatchValue::Regex(s) => (Value::Integer(MATCH_REGEX.into()), Value::Text(s.clone())),
        MatchValue::Sha256(h) => (Value::Integer(MATCH_SHA256.into()), Value::Bytes(h.clone())),
        MatchValue::Sha512_256(h) => (
            Value::Integer(MATCH_SHA512_256.into()),
            Value::Bytes(h.clone()),
        ),
    }
}

fn decode_match_value(key: &Value, val: &Value) -> Result<MatchValue, CatError> {
    let match_type: i64 = match key {
        Value::Integer(i) => (*i).try_into().map_err(|_| CatError::InvalidTokenFormat)?,
        _ => return Err(CatError::InvalidTokenFormat),
    };
    match match_type {
        MATCH_EXACT => {
            if let Value::Text(s) = val {
                Ok(MatchValue::Exact(s.clone()))
            } else {
                Err(CatError::InvalidTokenFormat)
            }
        }
        MATCH_PREFIX => {
            if let Value::Text(s) = val {
                Ok(MatchValue::Prefix(s.clone()))
            } else {
                Err(CatError::InvalidTokenFormat)
            }
        }
        MATCH_SUFFIX => {
            if let Value::Text(s) = val {
                Ok(MatchValue::Suffix(s.clone()))
            } else {
                Err(CatError::InvalidTokenFormat)
            }
        }
        MATCH_CONTAINS => {
            if let Value::Text(s) = val {
                Ok(MatchValue::Contains(s.clone()))
            } else {
                Err(CatError::InvalidTokenFormat)
            }
        }
        MATCH_REGEX => {
            if let Value::Text(s) = val {
                Ok(MatchValue::Regex(s.clone()))
            } else {
                Err(CatError::InvalidTokenFormat)
            }
        }
        MATCH_SHA256 => {
            if let Value::Bytes(b) = val {
                Ok(MatchValue::Sha256(b.clone()))
            } else {
                Err(CatError::InvalidTokenFormat)
            }
        }
        MATCH_SHA512_256 => {
            if let Value::Bytes(b) = val {
                Ok(MatchValue::Sha512_256(b.clone()))
            } else {
                Err(CatError::InvalidTokenFormat)
            }
        }
        _ => Err(CatError::InvalidClaimValue(format!(
            "Unknown match type: {match_type}"
        ))),
    }
}

fn encode_network_identifier(nip: &NetworkIdentifier) -> Value {
    match nip {
        NetworkIdentifier::IpAddress(addr) => match addr {
            IpAddr::V4(v4) => {
                Value::Tag(CBOR_TAG_IPV4, Box::new(Value::Bytes(v4.octets().to_vec())))
            }
            IpAddr::V6(v6) => {
                Value::Tag(CBOR_TAG_IPV6, Box::new(Value::Bytes(v6.octets().to_vec())))
            }
        },
        NetworkIdentifier::IpPrefix(addr, prefix_len) => {
            let (tag, addr_bytes) = match addr {
                IpAddr::V4(v4) => (CBOR_TAG_IPV4, v4.octets().to_vec()),
                IpAddr::V6(v6) => (CBOR_TAG_IPV6, v6.octets().to_vec()),
            };
            let prefix_bytes = prefix_byte_count(*prefix_len);
            Value::Tag(
                tag,
                Box::new(Value::Map(vec![(
                    Value::Integer((*prefix_len as i64).into()),
                    Value::Bytes(addr_bytes[..prefix_bytes].to_vec()),
                )])),
            )
        }
        NetworkIdentifier::Asn(asn) => Value::Integer((*asn).into()),
        NetworkIdentifier::AsnRange(start, end) => Value::Array(vec![
            Value::Integer((*start).into()),
            Value::Integer((*end).into()),
        ]),
    }
}

fn prefix_byte_count(prefix_len: u8) -> usize {
    (prefix_len as usize).div_ceil(8)
}

fn validate_host_bits_zero(prefix_bytes: &[u8], prefix_len: u8) -> Result<(), CatError> {
    let bits_in_last_byte = prefix_len % 8;
    if bits_in_last_byte != 0 && !prefix_bytes.is_empty() {
        let last = prefix_bytes[prefix_bytes.len() - 1];
        let host_mask = 0xFFu8 >> bits_in_last_byte;
        if last & host_mask != 0 {
            return Err(CatError::InvalidClaimValue(format!(
                "catnip: non-zero host bits in prefix /{prefix_len}"
            )));
        }
    }
    Ok(())
}

fn decode_network_identifier(value: &Value) -> Result<NetworkIdentifier, CatError> {
    match value {
        Value::Tag(tag, inner) => match inner.as_ref() {
            Value::Bytes(bytes) => match *tag {
                CBOR_TAG_IPV4 if bytes.len() == 4 => {
                    let addr = std::net::Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]);
                    Ok(NetworkIdentifier::IpAddress(IpAddr::V4(addr)))
                }
                CBOR_TAG_IPV6 if bytes.len() == 16 => {
                    let mut octets = [0u8; 16];
                    octets.copy_from_slice(bytes);
                    let addr = std::net::Ipv6Addr::from(octets);
                    Ok(NetworkIdentifier::IpAddress(IpAddr::V6(addr)))
                }
                _ => Err(CatError::InvalidClaimValue(format!(
                    "Invalid IP tag/size: tag={tag}, len={}",
                    bytes.len()
                ))),
            },
            Value::Map(map) if map.len() == 1 => {
                let (k, v) = &map[0];
                let prefix_len: u8 = match k {
                    Value::Integer(i) => {
                        let val: i64 = (*i).try_into().map_err(|_| CatError::InvalidTokenFormat)?;
                        let max_bits = match *tag {
                            CBOR_TAG_IPV4 => 32u8,
                            CBOR_TAG_IPV6 => 128u8,
                            _ => {
                                return Err(CatError::InvalidClaimValue(format!(
                                    "Unknown IP tag: {tag}"
                                )));
                            }
                        };
                        if val < 0 || val > max_bits as i64 {
                            return Err(CatError::InvalidClaimValue(format!(
                                "catnip: prefix length {val} out of range for tag {tag} (max {max_bits})"
                            )));
                        }
                        val as u8
                    }
                    _ => return Err(CatError::InvalidTokenFormat),
                };
                let prefix_bytes = match v {
                    Value::Bytes(b) => b,
                    _ => return Err(CatError::InvalidTokenFormat),
                };
                let expected_byte_count = prefix_byte_count(prefix_len);
                if prefix_bytes.len() != expected_byte_count {
                    return Err(CatError::InvalidClaimValue(format!(
                        "catnip: address-with-prefix form not allowed (got {} bytes for /{} prefix, expected {})",
                        prefix_bytes.len(),
                        prefix_len,
                        expected_byte_count
                    )));
                }
                validate_host_bits_zero(prefix_bytes, prefix_len)?;
                match *tag {
                    CBOR_TAG_IPV4 => {
                        let mut octets = [0u8; 4];
                        let copy_len = prefix_bytes.len().min(4);
                        octets[..copy_len].copy_from_slice(&prefix_bytes[..copy_len]);
                        let addr = std::net::Ipv4Addr::from(octets);
                        Ok(NetworkIdentifier::IpPrefix(IpAddr::V4(addr), prefix_len))
                    }
                    CBOR_TAG_IPV6 => {
                        let mut octets = [0u8; 16];
                        let copy_len = prefix_bytes.len().min(16);
                        octets[..copy_len].copy_from_slice(&prefix_bytes[..copy_len]);
                        let addr = std::net::Ipv6Addr::from(octets);
                        Ok(NetworkIdentifier::IpPrefix(IpAddr::V6(addr), prefix_len))
                    }
                    _ => Err(CatError::InvalidClaimValue(format!(
                        "Unknown IP tag: {tag}"
                    ))),
                }
            }
            _ => Err(CatError::InvalidTokenFormat),
        },
        Value::Integer(i) => {
            let asn: u32 = (*i).try_into().map_err(|_| CatError::InvalidTokenFormat)?;
            Ok(NetworkIdentifier::Asn(asn))
        }
        Value::Array(arr) if arr.len() == 2 => {
            let start: u32 = match &arr[0] {
                Value::Integer(i) => (*i).try_into().map_err(|_| CatError::InvalidTokenFormat)?,
                _ => return Err(CatError::InvalidTokenFormat),
            };
            let end: u32 = match &arr[1] {
                Value::Integer(i) => (*i).try_into().map_err(|_| CatError::InvalidTokenFormat)?,
                _ => return Err(CatError::InvalidTokenFormat),
            };
            Ok(NetworkIdentifier::AsnRange(start, end))
        }
        _ => Err(CatError::InvalidTokenFormat),
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CwtHeader {
    pub alg: i64,
    pub kid: Option<String>,
    pub typ: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Cwt {
    pub header: CwtHeader,
    pub payload: CatToken,
    pub signature: Vec<u8>,
}

impl Cwt {
    pub fn new(alg: i64, payload: CatToken) -> Self {
        Self {
            header: CwtHeader {
                alg,
                kid: None,
                typ: Some("CAT".to_string()),
            },
            payload,
            signature: Vec::new(),
        }
    }

    pub fn with_key_id(mut self, kid: impl Into<String>) -> Self {
        self.header.kid = Some(kid.into());
        self
    }

    pub fn encode_payload(&self) -> Result<Vec<u8>, CatError> {
        let mut claims_map: BTreeMap<i64, Value> = BTreeMap::new();

        if let Some(ref iss) = self.payload.core.iss {
            claims_map.insert(CLAIM_ISS, Value::Text(iss.clone()));
        }

        if let Some(ref aud) = self.payload.core.aud {
            let aud_values: Vec<Value> = aud.iter().map(|a| Value::Text(a.clone())).collect();
            claims_map.insert(CLAIM_AUD, Value::Array(aud_values));
        }

        if let Some(exp) = self.payload.core.exp {
            claims_map.insert(CLAIM_EXP, Value::Integer(exp.into()));
        }

        if let Some(nbf) = self.payload.core.nbf {
            claims_map.insert(CLAIM_NBF, Value::Integer(nbf.into()));
        }

        if let Some(ref cti) = self.payload.core.cti {
            claims_map.insert(CLAIM_CTI, Value::Bytes(cti.clone()));
        }

        if let Some(catreplay) = self.payload.cat.catreplay {
            claims_map.insert(CLAIM_CATREPLAY, Value::Integer((catreplay as u32).into()));
        }

        if let Some(ref catpor) = self.payload.cat.catpor {
            validate_float(catpor.probability, "catpor.probability")?;
            let mut arr = vec![
                encode_number_shortest(catpor.probability),
                Value::Bytes(catpor.id.clone()),
            ];
            if let Some(exp) = catpor.expiration {
                arr.push(Value::Integer(exp.into()));
            }
            claims_map.insert(CLAIM_CATPOR, Value::Array(arr));
        }

        if let Some(catv) = self.payload.cat.catv {
            claims_map.insert(CLAIM_CATV, Value::Integer(catv.into()));
        }

        if let Some(ref catnip) = self.payload.cat.catnip {
            let nip_values: Vec<Value> = catnip.iter().map(encode_network_identifier).collect();
            claims_map.insert(CLAIM_CATNIP, Value::Array(nip_values));
        }

        if let Some(ref catu) = self.payload.cat.catu {
            let mut uri_map: Vec<(Value, Value)> = catu
                .iter()
                .map(|rule| {
                    let mut match_map: Vec<(Value, Value)> =
                        rule.matches.iter().map(encode_match_value).collect();
                    sort_integer_keyed_map(&mut match_map);
                    (Value::Integer(rule.component.into()), Value::Map(match_map))
                })
                .collect();
            sort_integer_keyed_map(&mut uri_map);
            claims_map.insert(CLAIM_CATU, Value::Map(uri_map));
        }

        if let Some(ref catm) = self.payload.cat.catm {
            let methods: Vec<Value> = catm.iter().map(|m| Value::Text(m.clone())).collect();
            claims_map.insert(CLAIM_CATM, Value::Array(methods));
        }

        if let Some(ref catalpn) = self.payload.cat.catalpn {
            let alpn_values: Vec<Value> = catalpn.iter().map(|a| Value::Bytes(a.clone())).collect();
            claims_map.insert(CLAIM_CATALPN, Value::Array(alpn_values));
        }

        if let Some(ref cath) = self.payload.cat.cath {
            let header_map: Vec<(Value, Value)> = cath
                .iter()
                .map(|rule| {
                    let mut match_map: Vec<(Value, Value)> =
                        rule.matches.iter().map(encode_match_value).collect();
                    sort_integer_keyed_map(&mut match_map);
                    (Value::Text(rule.name.clone()), Value::Map(match_map))
                })
                .collect();
            claims_map.insert(CLAIM_CATH, Value::Map(header_map));
        }

        if let Some(ref catgeoiso3166) = self.payload.cat.catgeoiso3166 {
            let geo_values: Vec<Value> = catgeoiso3166
                .iter()
                .map(|g| Value::Text(g.clone()))
                .collect();
            claims_map.insert(CLAIM_CATGEOISO3166, Value::Array(geo_values));
        }

        if let Some(ref catgeocoord) = self.payload.cat.catgeocoord {
            for coord in catgeocoord {
                validate_float(coord.lat, "catgeocoord.lat")?;
                validate_float(coord.lon, "catgeocoord.lon")?;
            }
            let zones: Vec<Value> = catgeocoord
                .iter()
                .map(|coord| {
                    Value::Array(vec![
                        encode_number_shortest(coord.lat),
                        encode_number_shortest(coord.lon),
                        Value::Integer((coord.radius as i64).into()),
                    ])
                })
                .collect();
            claims_map.insert(CLAIM_CATGEOCOORD, Value::Array(zones));
        }

        if let Some(ref geohash) = self.payload.cat.geohash {
            if geohash.len() == 1 {
                claims_map.insert(CLAIM_GEOHASH, Value::Text(geohash[0].clone()));
            } else {
                let arr: Vec<Value> = geohash.iter().map(|g| Value::Text(g.clone())).collect();
                claims_map.insert(CLAIM_GEOHASH, Value::Array(arr));
            }
        }

        if let Some(ref catgeoalt) = self.payload.cat.catgeoalt {
            validate_float(catgeoalt.altitude, "catgeoalt.altitude")?;
            validate_float(catgeoalt.deviation, "catgeoalt.deviation")?;
            claims_map.insert(
                CLAIM_CATGEOALT,
                Value::Array(vec![
                    encode_number_shortest(catgeoalt.altitude),
                    encode_number_shortest(catgeoalt.deviation),
                ]),
            );
        }

        if let Some(ref cattpk) = self.payload.cat.cattpk {
            claims_map.insert(CLAIM_CATTPK, Value::Bytes(cattpk.clone()));
        }

        // Informational claims
        if let Some(ref sub) = self.payload.informational.sub {
            claims_map.insert(CLAIM_SUB, Value::Text(sub.clone()));
        }

        if let Some(iat) = self.payload.informational.iat {
            claims_map.insert(CLAIM_IAT, Value::Integer(iat.into()));
        }

        if let Some(ref catifdata) = self.payload.informational.catifdata {
            if catifdata.len() == 1 {
                claims_map.insert(CLAIM_CATIFDATA, Value::Text(catifdata[0].clone()));
            } else {
                let arr: Vec<Value> = catifdata.iter().map(|s| Value::Text(s.clone())).collect();
                claims_map.insert(CLAIM_CATIFDATA, Value::Array(arr));
            }
        }

        // DPoP claims - cnf is a map with jkt (key 3) containing the JWK thumbprint
        if let Some(ref cnf) = self.payload.dpop.cnf {
            let mut cnf_map = Vec::new();
            if let Some(ref ckt) = cnf.ckt {
                cnf_map.push((Value::Integer(CNF_CKT.into()), Value::Bytes(ckt.clone())));
            }
            if !cnf.jkt.is_empty() {
                cnf_map.push((
                    Value::Integer(CNF_JKT.into()),
                    Value::Bytes(cnf.jkt.clone()),
                ));
            }
            if !cnf_map.is_empty() {
                claims_map.insert(CLAIM_CNF, Value::Map(cnf_map));
            }
        }

        if let Some(ref catdpop) = self.payload.dpop.catdpop {
            let mut dpop_map = Vec::new();
            // Canonical order per RFC 8949 §4.2.1: non-negative first (0, 1), then negative (-1)
            if let Some(window) = catdpop.window {
                dpop_map.push((
                    Value::Integer(CATDPOP_WINDOW.into()),
                    Value::Integer(window.into()),
                ));
            }
            if let Some(honor_jti) = catdpop.honor_jti {
                let jti_value = if honor_jti { 1i64 } else { 0i64 };
                dpop_map.push((
                    Value::Integer(CATDPOP_HONOR_JTI.into()),
                    Value::Integer(jti_value.into()),
                ));
            }
            if let Some(ref crit) = catdpop.crit {
                let crit_array: Vec<Value> =
                    crit.iter().map(|&k| Value::Integer(k.into())).collect();
                dpop_map.push((
                    Value::Integer(CATDPOP_CRIT.into()),
                    Value::Array(crit_array),
                ));
            }
            if !dpop_map.is_empty() {
                claims_map.insert(CLAIM_CATDPOP, Value::Map(dpop_map));
            }
        }

        // Request claims
        if let Some(ref catif) = self.payload.request.catif {
            let mut sorted_catif = catif.clone();
            sorted_catif.sort_by_key(|(k, _)| *k);
            let entries: Vec<(Value, Value)> = sorted_catif
                .iter()
                .map(|(claim_key, action)| {
                    let mut arr = vec![Value::Integer(action.status.into())];
                    if let Some(ref headers) = action.headers {
                        let header_map: Vec<(Value, Value)> = headers
                            .iter()
                            .map(|(k, v)| (Value::Text(k.clone()), Value::Text(v.clone())))
                            .collect();
                        arr.push(Value::Map(header_map));
                    }
                    if let Some(ref kid) = action.kid {
                        if action.headers.is_none() {
                            arr.push(Value::Map(vec![]));
                        }
                        arr.push(Value::Text(kid.clone()));
                    }
                    (Value::Integer((*claim_key).into()), Value::Array(arr))
                })
                .collect();
            claims_map.insert(CLAIM_CATIF, Value::Map(entries));
        }

        if let Some(ref catr) = self.payload.request.catr {
            let mut renewal_map: Vec<(Value, Value)> = Vec::new();
            renewal_map.push((
                Value::Integer(CATR_TYPE.into()),
                Value::Integer((catr.renewal_type as u32).into()),
            ));
            if let Some(expadd) = catr.expadd {
                renewal_map.push((
                    Value::Integer(CATR_EXPADD.into()),
                    encode_number_shortest(expadd),
                ));
            }
            if let Some(deadline) = catr.deadline {
                renewal_map.push((
                    Value::Integer(CATR_DEADLINE.into()),
                    encode_number_shortest(deadline),
                ));
            }
            if let Some(ref name) = catr.cookie_name {
                renewal_map.push((
                    Value::Integer(CATR_COOKIE_NAME.into()),
                    Value::Text(name.clone()),
                ));
            }
            if let Some(ref name) = catr.header_name {
                renewal_map.push((
                    Value::Integer(CATR_HEADER_NAME.into()),
                    Value::Text(name.clone()),
                ));
            }
            if let Some(ref params) = catr.cookie_params {
                let param_arr: Vec<Value> = params.iter().map(|s| Value::Text(s.clone())).collect();
                renewal_map.push((
                    Value::Integer(CATR_ADDITIONAL_COOKIE_PARAMS.into()),
                    Value::Array(param_arr),
                ));
            }
            if let Some(ref params) = catr.header_params {
                let param_arr: Vec<Value> = params.iter().map(|s| Value::Text(s.clone())).collect();
                renewal_map.push((
                    Value::Integer(CATR_ADDITIONAL_HEADER_PARAMS.into()),
                    Value::Array(param_arr),
                ));
            }
            if let Some(code) = catr.status_code {
                renewal_map.push((
                    Value::Integer(CATR_STATUS_CODE.into()),
                    Value::Integer(code.into()),
                ));
            }
            claims_map.insert(CLAIM_CATR, Value::Map(renewal_map));
        }

        #[cfg(feature = "moqt")]
        if let Some(ref moqt_scopes) = self.payload.moqt.moqt {
            let mut scopes_array = Vec::new();
            for scope in moqt_scopes {
                if scope.actions.is_empty() {
                    return Err(CatError::InvalidClaimValue(
                        "MOQT scope must have at least one action".to_string(),
                    ));
                }

                let actions: Vec<Value> = scope
                    .actions
                    .iter()
                    .map(|action| Value::Integer((*action as i32).into()))
                    .collect();

                let mut scope_array = vec![Value::Array(actions)];

                if !scope.namespace_matches.is_empty() {
                    let mut ns_matches = Vec::new();
                    let mut seen_nil = false;
                    for ns in &scope.namespace_matches {
                        if seen_nil {
                            return Err(CatError::InvalidClaimValue(
                                "Namespace nil must be the last element".to_string(),
                            ));
                        }
                        if matches!(ns, NamespaceMatch::Nil) {
                            seen_nil = true;
                        }
                        ns_matches.push(encode_namespace_match(ns)?);
                    }
                    scope_array.push(Value::Array(ns_matches));
                }

                if let Some(ref track_match) = scope.track_match {
                    if track_match.match_type == BinaryMatchType::Any {
                        return Err(CatError::InvalidClaimValue(
                            "Track wildcard must use Option::None, not BinaryMatch::Any"
                                .to_string(),
                        ));
                    }
                    if scope.namespace_matches.is_empty() {
                        scope_array.push(Value::Array(vec![]));
                    }
                    scope_array.push(encode_binary_match(track_match)?);
                }

                scopes_array.push(Value::Array(scope_array));
            }
            claims_map.insert(CLAIM_MOQT, Value::Array(scopes_array));
        }

        #[cfg(feature = "moqt")]
        if let Some(moqt_reval) = self.payload.moqt.moqt_reval {
            validate_float(moqt_reval, "moqt_reval")?;
            claims_map.insert(CLAIM_MOQT_REVAL, encode_number_shortest(moqt_reval));
        }

        if let Some(ref or_claim) = self.payload.composite.or_claim {
            claims_map.insert(CLAIM_OR, encode_composite_claim(or_claim)?);
        }
        if let Some(ref nor_claim) = self.payload.composite.nor_claim {
            claims_map.insert(CLAIM_NOR, encode_composite_claim(nor_claim)?);
        }
        if let Some(ref and_claim) = self.payload.composite.and_claim {
            claims_map.insert(CLAIM_AND, encode_composite_claim(and_claim)?);
        }

        for (key, value) in &self.payload.custom {
            claims_map.insert(*key, value.clone());
        }

        let cbor_map: Vec<(Value, Value)> = claims_map
            .into_iter()
            .map(|(k, v)| (Value::Integer(k.into()), v))
            .collect();

        let mut buffer = Vec::new();
        ciborium::ser::into_writer(&Value::Map(cbor_map), &mut buffer)
            .map_err(|e| CatError::InvalidCbor(e.to_string()))?;

        Ok(buffer)
    }
}

#[cfg(feature = "moqt")]
fn encode_binary_match(binary_match: &crate::claims::BinaryMatch) -> Result<Value, CatError> {
    match binary_match.match_type {
        BinaryMatchType::Any => Err(CatError::InvalidClaimValue(
            "BinaryMatch::Any cannot be encoded on the wire; use Option::None to omit".to_string(),
        )),
        BinaryMatchType::Exact => Ok(Value::Bytes(binary_match.pattern.clone())),
        BinaryMatchType::Prefix => Ok(Value::Array(vec![
            Value::Integer(MATCH_TYPE_PREFIX.into()),
            Value::Bytes(binary_match.pattern.clone()),
        ])),
        BinaryMatchType::Suffix => Ok(Value::Array(vec![
            Value::Integer(MATCH_TYPE_SUFFIX.into()),
            Value::Bytes(binary_match.pattern.clone()),
        ])),
    }
}

#[cfg(feature = "moqt")]
fn encode_namespace_match(ns_match: &crate::claims::NamespaceMatch) -> Result<Value, CatError> {
    match ns_match {
        NamespaceMatch::Nil => Ok(Value::Null),
        NamespaceMatch::Match(binary_match) => {
            if binary_match.match_type == BinaryMatchType::Any {
                return Err(CatError::InvalidClaimValue(
                    "Namespace wildcard must use Option::None, not BinaryMatch::Any".to_string(),
                ));
            }
            encode_binary_match(binary_match)
        }
    }
}

#[cfg(feature = "moqt")]
fn decode_binary_match(value: &Value) -> Result<crate::claims::BinaryMatch, CatError> {
    match value {
        Value::Null => Err(CatError::InvalidClaimValue(
            "CBOR null is not a valid binary match; use omission for wildcard".to_string(),
        )),
        Value::Bytes(data) => Ok(BinaryMatch::exact(data.clone())),
        Value::Array(arr) if arr.len() == 2 => {
            let match_type = match &arr[0] {
                Value::Integer(i) => {
                    let i_val: i64 = (*i).try_into().map_err(|_| CatError::InvalidTokenFormat)?;
                    i_val
                }
                _ => return Err(CatError::InvalidTokenFormat),
            };
            let pattern = match &arr[1] {
                Value::Bytes(data) => data.clone(),
                _ => return Err(CatError::InvalidTokenFormat),
            };

            match match_type {
                1 => Ok(BinaryMatch::prefix(pattern)),
                2 => Ok(BinaryMatch::suffix(pattern)),
                _ => Err(CatError::InvalidClaimValue(format!(
                    "Unknown match type: {}",
                    match_type
                ))),
            }
        }
        _ => Err(CatError::InvalidTokenFormat),
    }
}

#[cfg(feature = "moqt")]
fn decode_namespace_match(value: &Value) -> Result<crate::claims::NamespaceMatch, CatError> {
    match value {
        Value::Null => Ok(NamespaceMatch::Nil),
        _ => Ok(NamespaceMatch::Match(decode_binary_match(value)?)),
    }
}

pub(crate) const DEFAULT_MAX_CBOR_PAYLOAD_SIZE: usize = 16 * 1024;
pub(crate) const DEFAULT_MAX_MOQT_SCOPES: usize = 1000;
pub(crate) const DEFAULT_MAX_CUSTOM_CLAIMS: usize = 100;
pub(crate) const DEFAULT_MAX_STRING_CLAIM_LENGTH: usize = 8 * 1024;
pub(crate) const DEFAULT_MAX_NAMESPACE_MATCHES_PER_SCOPE: usize = 100;
pub(crate) const DEFAULT_MAX_URI_PATTERNS: usize = 1000;
pub(crate) const DEFAULT_MAX_NESTING_DEPTH: usize = 8;
pub(crate) const DEFAULT_MAX_TOTAL_ITEMS: usize = 10_000;
pub(crate) const DEFAULT_MAX_TOTAL_STRING_BYTES: usize = 512 * 1024;
pub(crate) const DEFAULT_MAX_REGEX_COUNT: usize = 50;
pub(crate) const DEFAULT_MAX_CATNIP_ENTRIES: usize = 1000;

// Upper caps to protect against configurations that would defeat the purpose of the limits.
const MAX_CBOR_PAYLOAD_CAP: usize = 4 * 1024 * 1024; // 4 MiB
const MAX_NESTING_DEPTH_CAP: usize = 32;
const MAX_TOTAL_ITEMS_CAP: usize = 1_000_000;
const MAX_TOTAL_STRING_BYTES_CAP: usize = 16 * 1024 * 1024; // 16 MiB
const MAX_STRING_CLAIM_LENGTH_CAP: usize = 1024 * 1024; // 1 MiB
const MAX_SCOPES_CAP: usize = 100_000;
const MAX_CUSTOM_CLAIMS_CAP: usize = 10_000;
const MAX_NAMESPACE_MATCHES_CAP: usize = 10_000;
const MAX_URI_PATTERNS_CAP: usize = 100_000;
const MAX_REGEX_COUNT_CAP: usize = 10_000;
const MAX_CATNIP_ENTRIES_CAP: usize = 100_000;

/// Configuration for CWT validation limits.
///
/// All limits have sensible defaults. Custom limits must be built via [`CwtLimitsBuilder`]
/// so that policy-invalid values (zero, absurd upper bounds) are rejected at construction.
#[derive(Debug, Clone)]
pub struct CwtLimits {
    pub(crate) max_cbor_payload_size: usize,
    pub(crate) max_moqt_scopes: usize,
    pub(crate) max_custom_claims: usize,
    pub(crate) max_string_claim_length: usize,
    pub(crate) max_namespace_matches_per_scope: usize,
    pub(crate) max_uri_patterns: usize,
    pub(crate) max_nesting_depth: usize,
    pub(crate) max_total_items: usize,
    pub(crate) max_total_string_bytes: usize,
    pub(crate) max_regex_count: usize,
    pub(crate) max_catnip_entries: usize,
}

impl Default for CwtLimits {
    fn default() -> Self {
        Self {
            max_cbor_payload_size: DEFAULT_MAX_CBOR_PAYLOAD_SIZE,
            max_moqt_scopes: DEFAULT_MAX_MOQT_SCOPES,
            max_custom_claims: DEFAULT_MAX_CUSTOM_CLAIMS,
            max_string_claim_length: DEFAULT_MAX_STRING_CLAIM_LENGTH,
            max_namespace_matches_per_scope: DEFAULT_MAX_NAMESPACE_MATCHES_PER_SCOPE,
            max_uri_patterns: DEFAULT_MAX_URI_PATTERNS,
            max_nesting_depth: DEFAULT_MAX_NESTING_DEPTH,
            max_total_items: DEFAULT_MAX_TOTAL_ITEMS,
            max_total_string_bytes: DEFAULT_MAX_TOTAL_STRING_BYTES,
            max_regex_count: DEFAULT_MAX_REGEX_COUNT,
            max_catnip_entries: DEFAULT_MAX_CATNIP_ENTRIES,
        }
    }
}

impl CwtLimits {
    /// Returns the default limits (equivalent to `CwtLimits::default()`).
    pub fn new() -> Self {
        Self::default()
    }

    /// Start building customized limits from the defaults.
    pub fn builder() -> CwtLimitsBuilder {
        CwtLimitsBuilder::new()
    }

    pub fn max_cbor_payload_size(&self) -> usize {
        self.max_cbor_payload_size
    }
    pub fn max_moqt_scopes(&self) -> usize {
        self.max_moqt_scopes
    }
    pub fn max_custom_claims(&self) -> usize {
        self.max_custom_claims
    }
    pub fn max_string_claim_length(&self) -> usize {
        self.max_string_claim_length
    }
    pub fn max_namespace_matches_per_scope(&self) -> usize {
        self.max_namespace_matches_per_scope
    }
    pub fn max_uri_patterns(&self) -> usize {
        self.max_uri_patterns
    }
    pub fn max_nesting_depth(&self) -> usize {
        self.max_nesting_depth
    }
    pub fn max_total_items(&self) -> usize {
        self.max_total_items
    }
    pub fn max_total_string_bytes(&self) -> usize {
        self.max_total_string_bytes
    }
    pub fn max_regex_count(&self) -> usize {
        self.max_regex_count
    }
    pub fn max_catnip_entries(&self) -> usize {
        self.max_catnip_entries
    }
}

/// Fallible builder for [`CwtLimits`]. All setters enforce that values are non-zero
/// and within a policy-safe upper cap. Building returns an error if any value is invalid.
#[derive(Debug, Clone)]
pub struct CwtLimitsBuilder {
    inner: CwtLimits,
}

impl Default for CwtLimitsBuilder {
    fn default() -> Self {
        Self::new()
    }
}

fn check_range(name: &'static str, value: usize, cap: usize) -> Result<usize, CatError> {
    if value == 0 {
        return Err(CatError::InvalidClaimValue(format!(
            "{name}: limit must be > 0"
        )));
    }
    if value > cap {
        return Err(CatError::InvalidClaimValue(format!(
            "{name}: {value} exceeds policy cap {cap}"
        )));
    }
    Ok(value)
}

impl CwtLimitsBuilder {
    pub fn new() -> Self {
        Self {
            inner: CwtLimits::default(),
        }
    }

    pub fn max_cbor_payload_size(mut self, size: usize) -> Result<Self, CatError> {
        self.inner.max_cbor_payload_size =
            check_range("max_cbor_payload_size", size, MAX_CBOR_PAYLOAD_CAP)?;
        Ok(self)
    }

    pub fn max_moqt_scopes(mut self, count: usize) -> Result<Self, CatError> {
        self.inner.max_moqt_scopes = check_range("max_moqt_scopes", count, MAX_SCOPES_CAP)?;
        Ok(self)
    }

    pub fn max_custom_claims(mut self, count: usize) -> Result<Self, CatError> {
        self.inner.max_custom_claims =
            check_range("max_custom_claims", count, MAX_CUSTOM_CLAIMS_CAP)?;
        Ok(self)
    }

    pub fn max_string_claim_length(mut self, length: usize) -> Result<Self, CatError> {
        self.inner.max_string_claim_length = check_range(
            "max_string_claim_length",
            length,
            MAX_STRING_CLAIM_LENGTH_CAP,
        )?;
        Ok(self)
    }

    pub fn max_namespace_matches_per_scope(mut self, count: usize) -> Result<Self, CatError> {
        self.inner.max_namespace_matches_per_scope = check_range(
            "max_namespace_matches_per_scope",
            count,
            MAX_NAMESPACE_MATCHES_CAP,
        )?;
        Ok(self)
    }

    pub fn max_uri_patterns(mut self, count: usize) -> Result<Self, CatError> {
        self.inner.max_uri_patterns = check_range("max_uri_patterns", count, MAX_URI_PATTERNS_CAP)?;
        Ok(self)
    }

    pub fn max_nesting_depth(mut self, depth: usize) -> Result<Self, CatError> {
        self.inner.max_nesting_depth =
            check_range("max_nesting_depth", depth, MAX_NESTING_DEPTH_CAP)?;
        Ok(self)
    }

    pub fn max_total_items(mut self, count: usize) -> Result<Self, CatError> {
        self.inner.max_total_items = check_range("max_total_items", count, MAX_TOTAL_ITEMS_CAP)?;
        Ok(self)
    }

    pub fn max_total_string_bytes(mut self, bytes: usize) -> Result<Self, CatError> {
        self.inner.max_total_string_bytes =
            check_range("max_total_string_bytes", bytes, MAX_TOTAL_STRING_BYTES_CAP)?;
        Ok(self)
    }

    pub fn max_regex_count(mut self, count: usize) -> Result<Self, CatError> {
        self.inner.max_regex_count = check_range("max_regex_count", count, MAX_REGEX_COUNT_CAP)?;
        Ok(self)
    }

    pub fn max_catnip_entries(mut self, count: usize) -> Result<Self, CatError> {
        self.inner.max_catnip_entries =
            check_range("max_catnip_entries", count, MAX_CATNIP_ENTRIES_CAP)?;
        Ok(self)
    }

    /// Finalize the builder. Cross-field consistency checks run here.
    pub fn build(self) -> Result<CwtLimits, CatError> {
        // The single string claim length must not exceed the aggregate string budget.
        if self.inner.max_string_claim_length > self.inner.max_total_string_bytes {
            return Err(CatError::InvalidClaimValue(
                "max_string_claim_length must not exceed max_total_string_bytes".to_string(),
            ));
        }
        Ok(self.inner)
    }
}

fn validate_string_length_with_limit(
    s: &str,
    claim_name: &str,
    max_length: usize,
) -> Result<(), CatError> {
    if s.len() > max_length {
        return Err(CatError::InvalidClaimValue(format!(
            "{} too long: {} bytes (max {} bytes)",
            claim_name,
            s.len(),
            max_length
        )));
    }
    Ok(())
}

#[derive(Default)]
struct DecodeCounters {
    total_items: usize,
    total_string_bytes: usize,
    regex_count: usize,
    uri_pattern_count: usize,
}

impl DecodeCounters {
    fn count_item(&mut self, limits: &CwtLimits) -> Result<(), CatError> {
        self.total_items += 1;
        if self.total_items > limits.max_total_items {
            return Err(CatError::InvalidCbor(format!(
                "Too many CBOR items: exceeds limit of {}",
                limits.max_total_items
            )));
        }
        Ok(())
    }

    fn count_string(&mut self, len: usize, limits: &CwtLimits) -> Result<(), CatError> {
        self.total_string_bytes += len;
        if self.total_string_bytes > limits.max_total_string_bytes {
            return Err(CatError::InvalidCbor(format!(
                "Total string bytes exceeds limit of {}",
                limits.max_total_string_bytes
            )));
        }
        Ok(())
    }

    fn count_uri_pattern(&mut self, limits: &CwtLimits) -> Result<(), CatError> {
        self.uri_pattern_count += 1;
        if self.uri_pattern_count > limits.max_uri_patterns {
            return Err(CatError::InvalidCbor(format!(
                "Too many URI patterns: exceeds limit of {}",
                limits.max_uri_patterns
            )));
        }
        Ok(())
    }

    fn count_regex(&mut self, limits: &CwtLimits) -> Result<(), CatError> {
        self.regex_count += 1;
        if self.regex_count > limits.max_regex_count {
            return Err(CatError::InvalidCbor(format!(
                "Too many regex patterns: exceeds limit of {}",
                limits.max_regex_count
            )));
        }
        Ok(())
    }
}

impl Cwt {
    /// Decode CBOR payload with default limits
    pub fn decode_payload(cbor_data: &[u8]) -> Result<CatToken, CatError> {
        Self::decode_payload_with_limits(cbor_data, &CwtLimits::default())
    }

    /// Decode CBOR payload with custom limits
    pub fn decode_payload_with_limits(
        cbor_data: &[u8],
        limits: &CwtLimits,
    ) -> Result<CatToken, CatError> {
        let mut counters = DecodeCounters::default();
        Self::decode_payload_with_limits_and_counters(cbor_data, limits, &mut counters)
    }

    fn decode_payload_with_limits_and_counters(
        cbor_data: &[u8],
        limits: &CwtLimits,
        counters: &mut DecodeCounters,
    ) -> Result<CatToken, CatError> {
        // Limit CBOR payload size to prevent memory exhaustion
        if cbor_data.len() > limits.max_cbor_payload_size {
            return Err(CatError::InvalidCbor(format!(
                "CBOR payload too large: {} bytes (max {} bytes)",
                cbor_data.len(),
                limits.max_cbor_payload_size
            )));
        }

        let mut cursor = std::io::Cursor::new(cbor_data);
        let value: Value = ciborium::de::from_reader(&mut cursor)
            .map_err(|e| CatError::InvalidCbor(e.to_string()))?;
        if (cursor.position() as usize) < cbor_data.len() {
            return Err(CatError::InvalidCbor(format!(
                "Trailing bytes after CBOR payload: {} unconsumed bytes",
                cbor_data.len() - cursor.position() as usize
            )));
        }

        let claims_map = match value {
            Value::Map(map) => map,
            _ => return Err(CatError::InvalidTokenFormat),
        };

        validate_cbor_map_ordering_limited(&claims_map, limits.max_nesting_depth)?;

        let mut core = CoreClaims {
            iss: None,
            aud: None,
            exp: None,
            nbf: None,
            cti: None,
        };

        let mut cat = CatClaims {
            catreplay: None,
            catpor: None,
            catv: None,
            catnip: None,
            catu: None,
            catm: None,
            catalpn: None,
            cath: None,
            catgeoiso3166: None,
            catgeocoord: None,
            geohash: None,
            catgeoalt: None,
            cattpk: None,
        };

        let mut informational = InformationalClaims {
            sub: None,
            iat: None,
            catifdata: None,
        };

        let mut dpop = DpopClaims {
            cnf: None,
            catdpop: None,
        };

        let mut request = RequestClaims {
            catif: None,
            catr: None,
        };

        #[cfg(feature = "moqt")]
        let mut moqt = crate::claims::MoqtClaims {
            moqt: None,
            moqt_reval: None,
        };

        let mut composite_claims = crate::claims::CompositeClaims::default();
        let mut custom = HashMap::new();

        for (key, value) in claims_map {
            counters.count_item(limits)?;

            let claim_id = match key {
                Value::Integer(i) => i.try_into().map_err(|_| CatError::InvalidTokenFormat)?,
                _ => {
                    return Err(CatError::InvalidCbor(
                        "non-integer claim label rejected".to_string(),
                    ));
                }
            };

            match claim_id {
                CLAIM_ISS => {
                    reject_unexpected_tag(&value, "iss")?;
                    if let Value::Text(s) = value {
                        validate_string_length_with_limit(
                            &s,
                            "issuer",
                            limits.max_string_claim_length,
                        )?;
                        counters.count_string(s.len(), limits)?;
                        core.iss = Some(s);
                    } else {
                        return Err(CatError::InvalidClaimValue(
                            "iss must be a text string".to_string(),
                        ));
                    }
                }
                CLAIM_AUD => {
                    reject_unexpected_tag(&value, "aud")?;
                    if let Value::Text(s) = value {
                        validate_string_length_with_limit(
                            &s,
                            "audience",
                            limits.max_string_claim_length,
                        )?;
                        counters.count_string(s.len(), limits)?;
                        core.aud = Some(vec![s]);
                    } else if let Value::Array(arr) = value {
                        let mut audiences = Vec::new();
                        for item in arr {
                            counters.count_item(limits)?;
                            if let Value::Text(s) = item {
                                validate_string_length_with_limit(
                                    &s,
                                    "audience",
                                    limits.max_string_claim_length,
                                )?;
                                counters.count_string(s.len(), limits)?;
                                audiences.push(s);
                            } else {
                                return Err(CatError::InvalidClaimValue(
                                    "aud array items must be text strings".to_string(),
                                ));
                            }
                        }
                        core.aud = Some(audiences);
                    } else {
                        return Err(CatError::InvalidClaimValue(
                            "aud must be a text string or array of text strings".to_string(),
                        ));
                    }
                }
                CLAIM_EXP => {
                    reject_unexpected_tag(&value, "exp")?;
                    match value {
                        Value::Integer(i) => {
                            core.exp =
                                Some(i.try_into().map_err(|_| CatError::InvalidTokenFormat)?);
                        }
                        Value::Float(f) => {
                            core.exp = Some(safe_float_to_i64(f, "exp")?);
                        }
                        _ => {
                            return Err(CatError::InvalidClaimValue(
                                "exp must be an integer or float".to_string(),
                            ));
                        }
                    }
                }
                CLAIM_NBF => {
                    reject_unexpected_tag(&value, "nbf")?;
                    match value {
                        Value::Integer(i) => {
                            core.nbf =
                                Some(i.try_into().map_err(|_| CatError::InvalidTokenFormat)?);
                        }
                        Value::Float(f) => {
                            core.nbf = Some(safe_float_to_i64(f, "nbf")?);
                        }
                        _ => {
                            return Err(CatError::InvalidClaimValue(
                                "nbf must be an integer or float".to_string(),
                            ));
                        }
                    }
                }
                CLAIM_CTI => {
                    reject_unexpected_tag(&value, "cti")?;
                    match value {
                        Value::Bytes(b) => {
                            core.cti = Some(b);
                        }
                        _ => {
                            return Err(CatError::InvalidClaimValue(
                                "cti must be a byte string".to_string(),
                            ));
                        }
                    }
                }
                CLAIM_CATREPLAY => {
                    reject_unexpected_tag(&value, "catreplay")?;
                    if let Value::Integer(i) = value {
                        let v: u32 = i.try_into().map_err(|_| {
                            CatError::InvalidClaimValue("Invalid catreplay value".to_string())
                        })?;
                        cat.catreplay = Some(crate::claims::ReplayProtection::try_from(v)?);
                    } else {
                        return Err(CatError::InvalidClaimValue(
                            "catreplay must be an integer".to_string(),
                        ));
                    }
                }
                CLAIM_CATPOR => {
                    reject_unexpected_tag(&value, "catpor")?;
                    let arr = match value {
                        Value::Array(arr) if arr.len() >= 2 && arr.len() <= 3 => arr,
                        _ => {
                            return Err(CatError::InvalidClaimValue(
                                "catpor must be an array with 2 or 3 elements".to_string(),
                            ));
                        }
                    };
                    {
                        let probability = match &arr[0] {
                            Value::Float(f) => *f,
                            Value::Integer(i) => {
                                let v: i64 =
                                    (*i).try_into().map_err(|_| CatError::InvalidTokenFormat)?;
                                v as f64
                            }
                            _ => {
                                return Err(CatError::InvalidClaimValue(
                                    "Invalid catpor probability".to_string(),
                                ));
                            }
                        };
                        let id = match &arr[1] {
                            Value::Bytes(b) => b.clone(),
                            _ => {
                                return Err(CatError::InvalidClaimValue(
                                    "Invalid catpor id".to_string(),
                                ));
                            }
                        };
                        let expiration = if arr.len() > 2 {
                            match &arr[2] {
                                Value::Integer(i) => Some(
                                    (*i).try_into().map_err(|_| CatError::InvalidTokenFormat)?,
                                ),
                                _ => {
                                    return Err(CatError::InvalidClaimValue(
                                        "catpor expiration must be an integer".to_string(),
                                    ));
                                }
                            }
                        } else {
                            None
                        };
                        validate_float(probability, "catpor.probability")?;
                        if !(0.0..=1.0).contains(&probability) {
                            return Err(CatError::InvalidClaimValue(format!(
                                "catpor probability must be in [0.0, 1.0], got {probability}"
                            )));
                        }
                        cat.catpor = Some(crate::claims::ProbabilityOfRejection {
                            probability,
                            id,
                            expiration,
                        });
                    }
                }
                CLAIM_CATV => {
                    reject_unexpected_tag(&value, "catv")?;
                    if let Value::Integer(i) = value {
                        cat.catv = Some(i.try_into().map_err(|_| {
                            CatError::InvalidClaimValue("Invalid catv value".to_string())
                        })?);
                    } else {
                        return Err(CatError::InvalidClaimValue(
                            "catv must be an integer".to_string(),
                        ));
                    }
                }
                CLAIM_CATNIP => {
                    reject_unexpected_tag(&value, "catnip")?;
                    if let Value::Array(arr) = value {
                        if arr.len() > limits.max_catnip_entries {
                            return Err(CatError::InvalidCbor(format!(
                                "Too many catnip entries: {} exceeds limit of {}",
                                arr.len(),
                                limits.max_catnip_entries
                            )));
                        }
                        let mut nips = Vec::new();
                        for item in arr {
                            counters.count_item(limits)?;
                            nips.push(decode_network_identifier(&item)?);
                        }
                        cat.catnip = Some(nips);
                    } else {
                        return Err(CatError::InvalidClaimValue(
                            "catnip must be an array".to_string(),
                        ));
                    }
                }
                CLAIM_CATU => {
                    reject_unexpected_tag(&value, "catu")?;
                    if let Value::Map(map) = value {
                        let mut rules = Vec::new();
                        for (k, v) in map {
                            let component: i64 = match k {
                                Value::Integer(i) => {
                                    i.try_into().map_err(|_| CatError::InvalidTokenFormat)?
                                }
                                _ => {
                                    return Err(CatError::InvalidClaimValue(
                                        "catu map keys must be integers".to_string(),
                                    ));
                                }
                            };
                            let match_map = match v {
                                Value::Map(m) => m,
                                _ => {
                                    return Err(CatError::InvalidClaimValue(
                                        "catu map values must be maps".to_string(),
                                    ));
                                }
                            };
                            let mut matches = Vec::new();
                            for (mk, mv) in &match_map {
                                let mv_decoded = decode_match_value(mk, mv)?;
                                if matches!(mv_decoded, MatchValue::Regex(_)) {
                                    counters.count_regex(limits)?;
                                }
                                matches.push(mv_decoded);
                            }
                            counters.count_uri_pattern(limits)?;
                            rules.push(UriMatchRule { component, matches });
                        }
                        cat.catu = Some(rules);
                    } else {
                        return Err(CatError::InvalidClaimValue(
                            "catu must be a map".to_string(),
                        ));
                    }
                }
                CLAIM_CATM => {
                    reject_unexpected_tag(&value, "catm")?;
                    if let Value::Array(arr) = value {
                        if arr.len() > 50 {
                            return Err(CatError::InvalidClaimValue(format!(
                                "catm: too many methods ({}, max 50)",
                                arr.len()
                            )));
                        }
                        let mut methods = Vec::new();
                        for item in arr {
                            counters.count_item(limits)?;
                            if let Value::Text(s) = item {
                                methods.push(s);
                            } else {
                                return Err(CatError::InvalidClaimValue(
                                    "catm array items must be text strings".to_string(),
                                ));
                            }
                        }
                        cat.catm = Some(methods);
                    } else {
                        return Err(CatError::InvalidClaimValue(
                            "catm must be an array".to_string(),
                        ));
                    }
                }
                CLAIM_CATALPN => {
                    reject_unexpected_tag(&value, "catalpn")?;
                    if let Value::Array(arr) = value {
                        if arr.len() > 50 {
                            return Err(CatError::InvalidClaimValue(format!(
                                "catalpn: too many entries ({}, max 50)",
                                arr.len()
                            )));
                        }
                        let mut alpns = Vec::new();
                        for item in arr {
                            counters.count_item(limits)?;
                            match item {
                                Value::Bytes(b) => alpns.push(b),
                                _ => {
                                    return Err(CatError::InvalidClaimValue(
                                        "catalpn array items must be byte strings per CTA-5007-B §4.6.8".to_string(),
                                    ));
                                }
                            }
                        }
                        cat.catalpn = Some(alpns);
                    } else {
                        return Err(CatError::InvalidClaimValue(
                            "catalpn must be an array".to_string(),
                        ));
                    }
                }
                CLAIM_CATH => {
                    reject_unexpected_tag(&value, "cath")?;
                    if let Value::Map(map) = value {
                        let mut rules = Vec::new();
                        for (k, v) in map {
                            let name = match k {
                                Value::Text(s) => s,
                                _ => {
                                    return Err(CatError::InvalidClaimValue(
                                        "cath map keys must be text strings".to_string(),
                                    ));
                                }
                            };
                            let match_map = match v {
                                Value::Map(m) => m,
                                _ => {
                                    return Err(CatError::InvalidClaimValue(
                                        "cath map values must be maps".to_string(),
                                    ));
                                }
                            };
                            let mut matches = Vec::new();
                            for (mk, mv) in &match_map {
                                let mv_decoded = decode_match_value(mk, mv)?;
                                if matches!(mv_decoded, MatchValue::Regex(_)) {
                                    counters.count_regex(limits)?;
                                }
                                matches.push(mv_decoded);
                            }
                            rules.push(HeaderMatchRule { name, matches });
                        }
                        cat.cath = Some(rules);
                    } else {
                        return Err(CatError::InvalidClaimValue(
                            "cath must be a map".to_string(),
                        ));
                    }
                }
                CLAIM_CATGEOISO3166 => {
                    reject_unexpected_tag(&value, "catgeoiso3166")?;
                    if let Value::Array(arr) = value {
                        let mut countries = Vec::new();
                        for item in arr {
                            counters.count_item(limits)?;
                            if let Value::Text(s) = item {
                                countries.push(s);
                            } else {
                                return Err(CatError::InvalidClaimValue(
                                    "catgeoiso3166 array items must be text strings".to_string(),
                                ));
                            }
                        }
                        cat.catgeoiso3166 = Some(countries);
                    } else {
                        return Err(CatError::InvalidClaimValue(
                            "catgeoiso3166 must be an array".to_string(),
                        ));
                    }
                }
                CLAIM_CATGEOCOORD => {
                    let value = unwrap_crs_tag(value)?;
                    if let Value::Array(zones) = value {
                        let mut coords = Vec::new();
                        for zone in zones {
                            counters.count_item(limits)?;
                            if let Value::Array(elements) = zone {
                                if elements.len() != 3 {
                                    return Err(CatError::InvalidClaimValue(format!(
                                        "catgeocoord zone must have exactly 3 elements (lat, lon, radius), got {}",
                                        elements.len()
                                    )));
                                }
                                let lat = match &elements[0] {
                                    Value::Float(f) => *f,
                                    Value::Integer(i) => {
                                        let v: i64 = (*i).try_into().map_err(|_| {
                                            CatError::InvalidClaimValue(
                                                "Invalid catgeocoord latitude".to_string(),
                                            )
                                        })?;
                                        v as f64
                                    }
                                    _ => {
                                        return Err(CatError::InvalidClaimValue(
                                            "catgeocoord latitude must be a number".to_string(),
                                        ));
                                    }
                                };
                                let lon = match &elements[1] {
                                    Value::Float(f) => *f,
                                    Value::Integer(i) => {
                                        let v: i64 = (*i).try_into().map_err(|_| {
                                            CatError::InvalidClaimValue(
                                                "Invalid catgeocoord longitude".to_string(),
                                            )
                                        })?;
                                        v as f64
                                    }
                                    _ => {
                                        return Err(CatError::InvalidClaimValue(
                                            "catgeocoord longitude must be a number".to_string(),
                                        ));
                                    }
                                };
                                let radius = match &elements[2] {
                                    Value::Integer(r) => {
                                        let v: i64 = (*r).try_into().map_err(|_| {
                                            CatError::InvalidClaimValue(
                                                "Invalid catgeocoord radius".to_string(),
                                            )
                                        })?;
                                        if v < 0 {
                                            return Err(CatError::InvalidClaimValue(
                                                "catgeocoord radius must not be negative"
                                                    .to_string(),
                                            ));
                                        }
                                        u32::try_from(v).map_err(|_| {
                                            CatError::InvalidClaimValue(
                                                "catgeocoord radius exceeds u32 range".to_string(),
                                            )
                                        })?
                                    }
                                    Value::Float(f) => safe_float_to_u32(*f, "catgeocoord radius")?,
                                    _ => {
                                        return Err(CatError::InvalidClaimValue(
                                            "catgeocoord radius must be a number".to_string(),
                                        ));
                                    }
                                };
                                validate_float(lat, "catgeocoord.lat")?;
                                validate_float(lon, "catgeocoord.lon")?;
                                if lat.abs() > 90.0 {
                                    return Err(CatError::InvalidClaimValue(
                                        "catgeocoord latitude out of range (-90 to 90)".to_string(),
                                    ));
                                }
                                if lon.abs() > 180.0 {
                                    return Err(CatError::InvalidClaimValue(
                                        "catgeocoord longitude out of range (-180 to 180)"
                                            .to_string(),
                                    ));
                                }
                                coords.push(GeoCoordinate { lat, lon, radius });
                            } else {
                                return Err(CatError::InvalidClaimValue(
                                    "catgeocoord zones must be arrays".to_string(),
                                ));
                            }
                        }
                        if !coords.is_empty() {
                            cat.catgeocoord = Some(coords);
                        }
                    } else {
                        return Err(CatError::InvalidClaimValue(
                            "catgeocoord must be an array".to_string(),
                        ));
                    }
                }
                CLAIM_GEOHASH => {
                    let value = unwrap_crs_tag(value)?;
                    match value {
                        Value::Text(s) => {
                            cat.geohash = Some(vec![s]);
                        }
                        Value::Array(arr) => {
                            let mut hashes = Vec::new();
                            for item in arr {
                                if let Value::Text(s) = item {
                                    hashes.push(s);
                                } else {
                                    return Err(CatError::InvalidClaimValue(
                                        "geohash array items must be text strings".to_string(),
                                    ));
                                }
                            }
                            if !hashes.is_empty() {
                                cat.geohash = Some(hashes);
                            }
                        }
                        _ => {
                            return Err(CatError::InvalidClaimValue(
                                "geohash must be text or an array of text".to_string(),
                            ));
                        }
                    }
                }
                CLAIM_CATGEOALT => {
                    let value = unwrap_crs_tag(value)?;
                    match value {
                        Value::Array(arr) if arr.len() == 2 => {
                            let altitude = match &arr[0] {
                                Value::Float(f) => *f,
                                Value::Integer(i) => {
                                    let v: i64 = (*i)
                                        .try_into()
                                        .map_err(|_| CatError::InvalidTokenFormat)?;
                                    v as f64
                                }
                                _ => {
                                    return Err(CatError::InvalidClaimValue(
                                        "Invalid catgeoalt altitude".to_string(),
                                    ));
                                }
                            };
                            let deviation = match &arr[1] {
                                Value::Float(f) => *f,
                                Value::Integer(i) => {
                                    let v: i64 = (*i)
                                        .try_into()
                                        .map_err(|_| CatError::InvalidTokenFormat)?;
                                    v as f64
                                }
                                _ => {
                                    return Err(CatError::InvalidClaimValue(
                                        "Invalid catgeoalt deviation".to_string(),
                                    ));
                                }
                            };
                            validate_float(altitude, "catgeoalt.altitude")?;
                            validate_float(deviation, "catgeoalt.deviation")?;
                            cat.catgeoalt = Some(crate::claims::GeoAltitude {
                                altitude,
                                deviation,
                            });
                        }
                        _ => {
                            return Err(CatError::InvalidClaimValue(
                                "catgeoalt must be an array of [altitude, deviation]".to_string(),
                            ));
                        }
                    }
                }
                CLAIM_CATTPK => {
                    reject_unexpected_tag(&value, "cattpk")?;
                    if let Value::Bytes(b) = value {
                        cat.cattpk = Some(b);
                    } else {
                        return Err(CatError::InvalidClaimValue(
                            "cattpk must be bytes".to_string(),
                        ));
                    }
                }
                CLAIM_SUB => {
                    reject_unexpected_tag(&value, "sub")?;
                    if let Value::Text(s) = value {
                        validate_string_length_with_limit(
                            &s,
                            "subject",
                            limits.max_string_claim_length,
                        )?;
                        counters.count_string(s.len(), limits)?;
                        informational.sub = Some(s);
                    } else {
                        return Err(CatError::InvalidClaimValue(
                            "sub must be a text string".to_string(),
                        ));
                    }
                }
                CLAIM_IAT => {
                    reject_unexpected_tag(&value, "iat")?;
                    match value {
                        Value::Integer(i) => {
                            informational.iat =
                                Some(i.try_into().map_err(|_| CatError::InvalidTokenFormat)?);
                        }
                        Value::Float(f) => {
                            informational.iat = Some(safe_float_to_i64(f, "iat")?);
                        }
                        _ => {
                            return Err(CatError::InvalidClaimValue(
                                "iat must be an integer or float".to_string(),
                            ));
                        }
                    }
                }
                CLAIM_CATIFDATA => {
                    reject_unexpected_tag(&value, "catifdata")?;
                    match value {
                        Value::Text(s) => {
                            informational.catifdata = Some(vec![s]);
                        }
                        Value::Array(arr) => {
                            let mut items = Vec::new();
                            for item in arr {
                                counters.count_item(limits)?;
                                if let Value::Text(s) = item {
                                    items.push(s);
                                } else {
                                    return Err(CatError::InvalidClaimValue(
                                        "catifdata array items must be text strings".to_string(),
                                    ));
                                }
                            }
                            if !items.is_empty() {
                                informational.catifdata = Some(items);
                            }
                        }
                        _ => {
                            return Err(CatError::InvalidClaimValue(
                                "catifdata must be text or an array of text".to_string(),
                            ));
                        }
                    }
                }
                CLAIM_CNF => {
                    reject_unexpected_tag(&value, "cnf")?;
                    if let Value::Map(map) = value {
                        let mut jkt = Vec::new();
                        let mut ckt = None;
                        for (k, v) in map {
                            let key_val: i64 = match k {
                                Value::Integer(key_int) => key_int.try_into().map_err(|_| {
                                    CatError::InvalidClaimValue("Invalid cnf map key".to_string())
                                })?,
                                _ => {
                                    return Err(CatError::InvalidClaimValue(
                                        "cnf map keys must be integers".to_string(),
                                    ));
                                }
                            };
                            match key_val {
                                CNF_JKT | CNF_JKT_LEGACY => {
                                    if let Value::Bytes(b) = v {
                                        jkt = b;
                                    } else {
                                        return Err(CatError::InvalidClaimValue(
                                            "cnf jkt value must be bytes".to_string(),
                                        ));
                                    }
                                }
                                CNF_CKT => {
                                    if let Value::Bytes(b) = v {
                                        ckt = Some(b);
                                    } else {
                                        return Err(CatError::InvalidClaimValue(
                                            "cnf ckt value must be bytes".to_string(),
                                        ));
                                    }
                                }
                                _ => {}
                            }
                        }
                        if !jkt.is_empty() || ckt.is_some() {
                            dpop.cnf = Some(ConfirmationClaim { jkt, ckt });
                        }
                    } else {
                        return Err(CatError::InvalidClaimValue("cnf must be a map".to_string()));
                    }
                }
                CLAIM_CATDPOP => {
                    reject_unexpected_tag(&value, "catdpop")?;
                    if let Value::Map(map) = value {
                        let mut settings = CatDpopSettings::new();
                        for (k, v) in map {
                            let key_val: i64 = match k {
                                Value::Integer(key_int) => key_int.try_into().map_err(|_| {
                                    CatError::InvalidClaimValue(
                                        "Invalid catdpop map key".to_string(),
                                    )
                                })?,
                                _ => {
                                    return Err(CatError::InvalidClaimValue(
                                        "catdpop map keys must be integers".to_string(),
                                    ));
                                }
                            };
                            match key_val {
                                CATDPOP_CRIT => {
                                    if let Value::Array(arr) = v {
                                        let mut crit_keys = Vec::new();
                                        for item in arr {
                                            if let Value::Integer(i) = item {
                                                let val: i64 = i.try_into().map_err(|_| {
                                                    CatError::InvalidClaimValue(
                                                        "Invalid catdpop crit value".to_string(),
                                                    )
                                                })?;
                                                crit_keys.push(val);
                                            } else {
                                                return Err(CatError::InvalidClaimValue(
                                                    "catdpop crit items must be integers"
                                                        .to_string(),
                                                ));
                                            }
                                        }
                                        settings.set_crit_from_decode(crit_keys);
                                    } else {
                                        return Err(CatError::InvalidClaimValue(
                                            "catdpop crit must be an array".to_string(),
                                        ));
                                    }
                                }
                                CATDPOP_WINDOW => {
                                    if let Value::Integer(window) = v {
                                        let window_val: i64 = window.try_into().map_err(|_| {
                                            CatError::InvalidClaimValue(
                                                "Invalid DPoP window value".to_string(),
                                            )
                                        })?;
                                        if !(1..=crate::claims::CATDPOP_MAX_WINDOW_SECS)
                                            .contains(&window_val)
                                        {
                                            return Err(CatError::InvalidClaimValue(format!(
                                                "catdpop window must be in 1..={} seconds (got {window_val})",
                                                crate::claims::CATDPOP_MAX_WINDOW_SECS
                                            )));
                                        }
                                        settings.set_window_from_decode(window_val);
                                    } else {
                                        return Err(CatError::InvalidClaimValue(
                                            "catdpop window must be an integer".to_string(),
                                        ));
                                    }
                                }
                                CATDPOP_HONOR_JTI => {
                                    if let Value::Integer(jti_val) = v {
                                        let jti_i64: i64 = jti_val.try_into().map_err(|_| {
                                            CatError::InvalidClaimValue(
                                                "Invalid catdpop honor_jti value".to_string(),
                                            )
                                        })?;
                                        match jti_i64 {
                                            0 => settings.set_honor_jti_from_decode(false),
                                            1 => settings.set_honor_jti_from_decode(true),
                                            _ => {
                                                return Err(CatError::InvalidClaimValue(
                                                    "catdpop honor_jti must be 0 or 1".to_string(),
                                                ));
                                            }
                                        }
                                    } else {
                                        return Err(CatError::InvalidClaimValue(
                                            "catdpop honor_jti must be an integer".to_string(),
                                        ));
                                    }
                                }
                                _ => {
                                    return Err(CatError::InvalidClaimValue(format!(
                                        "Unknown catdpop sub-key: {key_val}"
                                    )));
                                }
                            }
                        }
                        settings.validate_crit()?;
                        dpop.catdpop = Some(settings);
                    } else {
                        return Err(CatError::InvalidClaimValue(
                            "catdpop must be a map".to_string(),
                        ));
                    }
                }
                CLAIM_CATIF => {
                    reject_unexpected_tag(&value, "catif")?;
                    if let Value::Map(entries) = value {
                        let mut actions = Vec::new();
                        for (k, v) in entries {
                            counters.count_item(limits)?;
                            let claim_key: i64 = match k {
                                Value::Integer(i) => i.try_into().map_err(|_| {
                                    CatError::InvalidClaimValue("Invalid catif map key".to_string())
                                })?,
                                _ => {
                                    return Err(CatError::InvalidClaimValue(
                                        "catif map keys must be integers".to_string(),
                                    ));
                                }
                            };
                            if let Value::Array(arr) = v {
                                if arr.is_empty() {
                                    return Err(CatError::InvalidClaimValue(
                                        "catif action array must not be empty".to_string(),
                                    ));
                                }
                                if arr.len() > 3 {
                                    return Err(CatError::InvalidClaimValue(
                                        "catif action array must have at most 3 members (status, headers, kid)".to_string(),
                                    ));
                                }
                                let status: u32 = match &arr[0] {
                                    Value::Integer(i) => (*i).try_into().map_err(|_| {
                                        CatError::InvalidClaimValue(
                                            "Invalid catif status value".to_string(),
                                        )
                                    })?,
                                    _ => {
                                        return Err(CatError::InvalidClaimValue(
                                            "catif status must be an integer".to_string(),
                                        ));
                                    }
                                };
                                let headers = if arr.len() > 1 {
                                    if let Value::Map(hmap) = &arr[1] {
                                        if hmap.is_empty() {
                                            None
                                        } else {
                                            let mut hdrs = Vec::new();
                                            for (hk, hv) in hmap {
                                                let key = match hk {
                                                    Value::Text(k) => k.clone(),
                                                    _ => {
                                                        return Err(CatError::InvalidClaimValue(
                                                            "catif header keys must be text"
                                                                .to_string(),
                                                        ));
                                                    }
                                                };
                                                let val = match hv {
                                                    Value::Text(v) => v.clone(),
                                                    _ => {
                                                        return Err(CatError::InvalidClaimValue(
                                                            "catif header values must be text strings".to_string(),
                                                        ));
                                                    }
                                                };
                                                hdrs.push((key, val));
                                            }
                                            Some(hdrs)
                                        }
                                    } else {
                                        return Err(CatError::InvalidClaimValue(
                                            "catif headers must be a map".to_string(),
                                        ));
                                    }
                                } else {
                                    None
                                };
                                let kid = if arr.len() > 2 {
                                    if let Value::Text(s) = &arr[2] {
                                        Some(s.clone())
                                    } else {
                                        return Err(CatError::InvalidClaimValue(
                                            "catif kid must be a text string".to_string(),
                                        ));
                                    }
                                } else {
                                    None
                                };
                                let mut action = CatIfAction::new(status)?;
                                if let Some(hdrs) = headers {
                                    action = action.with_headers(hdrs)?;
                                }
                                if let Some(k) = kid {
                                    action = action.with_kid(k);
                                }
                                actions.push((claim_key, action));
                            } else {
                                return Err(CatError::InvalidClaimValue(
                                    "catif action values must be arrays".to_string(),
                                ));
                            }
                        }
                        if !actions.is_empty() {
                            request.catif = Some(actions);
                        }
                    } else {
                        return Err(CatError::InvalidClaimValue(
                            "catif must be a map".to_string(),
                        ));
                    }
                }
                CLAIM_CATR => {
                    reject_unexpected_tag(&value, "catr")?;
                    if let Value::Map(entries) = value {
                        let mut renewal_type = None;
                        let mut expadd = None;
                        let mut deadline = None;
                        let mut cookie_name = None;
                        let mut header_name = None;
                        let mut cookie_params = None;
                        let mut header_params = None;
                        let mut status_code = None;

                        for (k, v) in entries {
                            counters.count_item(limits)?;
                            let key: i64 = match k {
                                Value::Integer(i) => i.try_into().map_err(|_| {
                                    CatError::InvalidClaimValue("Invalid catr map key".to_string())
                                })?,
                                _ => {
                                    return Err(CatError::InvalidClaimValue(
                                        "catr map keys must be integers".to_string(),
                                    ));
                                }
                            };
                            match key {
                                CATR_TYPE => {
                                    if let Value::Integer(i) = v {
                                        let t: u32 = i.try_into().map_err(|_| {
                                            CatError::InvalidClaimValue(
                                                "Invalid catr type value".to_string(),
                                            )
                                        })?;
                                        renewal_type = CatRenewalType::from_u32(t);
                                        if renewal_type.is_none() {
                                            return Err(CatError::InvalidClaimValue(format!(
                                                "Unknown catr type: {t}"
                                            )));
                                        }
                                    } else {
                                        return Err(CatError::InvalidClaimValue(
                                            "catr type must be an integer".to_string(),
                                        ));
                                    }
                                }
                                CATR_EXPADD => {
                                    expadd = Some(match v {
                                        Value::Integer(i) => {
                                            let val: i64 = i.try_into().map_err(|_| {
                                                CatError::InvalidClaimValue(
                                                    "Invalid catr expadd value".to_string(),
                                                )
                                            })?;
                                            val as f64
                                        }
                                        Value::Float(f) => {
                                            validate_float(f, "catr expadd")?;
                                            f
                                        }
                                        _ => {
                                            return Err(CatError::InvalidClaimValue(
                                                "catr expadd must be a number".to_string(),
                                            ));
                                        }
                                    });
                                }
                                CATR_DEADLINE => {
                                    deadline = Some(match v {
                                        Value::Integer(i) => {
                                            let val: i64 = i.try_into().map_err(|_| {
                                                CatError::InvalidClaimValue(
                                                    "Invalid catr deadline value".to_string(),
                                                )
                                            })?;
                                            val as f64
                                        }
                                        Value::Float(f) => {
                                            validate_float(f, "catr deadline")?;
                                            f
                                        }
                                        _ => {
                                            return Err(CatError::InvalidClaimValue(
                                                "catr deadline must be a number".to_string(),
                                            ));
                                        }
                                    });
                                }
                                CATR_COOKIE_NAME => {
                                    if let Value::Text(s) = v {
                                        cookie_name = Some(s);
                                    } else {
                                        return Err(CatError::InvalidClaimValue(
                                            "catr cookie_name must be text".to_string(),
                                        ));
                                    }
                                }
                                CATR_HEADER_NAME => {
                                    if let Value::Text(s) = v {
                                        header_name = Some(s);
                                    } else {
                                        return Err(CatError::InvalidClaimValue(
                                            "catr header_name must be text".to_string(),
                                        ));
                                    }
                                }
                                CATR_ADDITIONAL_COOKIE_PARAMS => {
                                    cookie_params =
                                        Some(decode_text_array(v, "catr cookie_params")?);
                                }
                                CATR_ADDITIONAL_HEADER_PARAMS => {
                                    header_params =
                                        Some(decode_text_array(v, "catr header_params")?);
                                }
                                CATR_STATUS_CODE => {
                                    if let Value::Integer(i) = v {
                                        status_code = Some(i.try_into().map_err(|_| {
                                            CatError::InvalidClaimValue(
                                                "Invalid catr status_code value".to_string(),
                                            )
                                        })?);
                                    } else {
                                        return Err(CatError::InvalidClaimValue(
                                            "catr status_code must be an integer".to_string(),
                                        ));
                                    }
                                }
                                _ => {} // CTA allows extension members
                            }
                        }
                        if let Some(rt) = renewal_type {
                            if let Some(ea) = expadd {
                                if ea <= 0.0 {
                                    return Err(CatError::InvalidClaimValue(
                                        "catr expadd must be a positive integer".to_string(),
                                    ));
                                }
                            } else {
                                return Err(CatError::InvalidClaimValue(
                                    "catr expadd is required when renewal type is present"
                                        .to_string(),
                                ));
                            }
                            request.catr = Some(CatRenewal::from_parts_unchecked(
                                rt,
                                expadd,
                                deadline,
                                cookie_name,
                                header_name,
                                cookie_params,
                                header_params,
                                status_code,
                            ));
                        }
                    } else {
                        return Err(CatError::InvalidClaimValue(
                            "catr must be a map".to_string(),
                        ));
                    }
                }
                #[cfg(feature = "moqt")]
                CLAIM_MOQT => {
                    reject_unexpected_tag(&value, "moqt")?;
                    if let Value::Array(scopes_array) = value {
                        if scopes_array.len() > limits.max_moqt_scopes {
                            return Err(CatError::InvalidClaimValue(format!(
                                "Too many MOQT scopes: {} (max {})",
                                scopes_array.len(),
                                limits.max_moqt_scopes
                            )));
                        }
                        let mut scopes = Vec::new();
                        for scope_value in scopes_array {
                            if let Value::Array(scope_array) = scope_value {
                                if scope_array.is_empty() || scope_array.len() > 3 {
                                    return Err(CatError::InvalidClaimValue(format!(
                                        "MOQT scope array must have 1-3 elements, got {}",
                                        scope_array.len()
                                    )));
                                }

                                let mut actions = Vec::new();
                                match &scope_array[0] {
                                    Value::Array(actions_array) => {
                                        for action_value in actions_array {
                                            if let Value::Integer(action_int) = action_value
                                                && let Ok(action_i32) =
                                                    TryInto::<i32>::try_into(*action_int)
                                            {
                                                match MoqtAction::try_from(action_i32) {
                                                    Ok(action) => actions.push(action),
                                                    Err(_) => {
                                                        return Err(CatError::InvalidClaimValue(
                                                            format!(
                                                                "Invalid MOQT action: {}",
                                                                action_i32
                                                            ),
                                                        ));
                                                    }
                                                }
                                            } else {
                                                return Err(CatError::InvalidClaimValue(
                                                    "MOQT action values must be integers"
                                                        .to_string(),
                                                ));
                                            }
                                        }
                                    }
                                    _ => {
                                        return Err(CatError::InvalidClaimValue(
                                            "MOQT scope actions must be an array".to_string(),
                                        ));
                                    }
                                }

                                if actions.is_empty() {
                                    return Err(CatError::InvalidClaimValue(
                                        "MOQT scope must have at least one action".to_string(),
                                    ));
                                }

                                let mut namespace_matches = Vec::new();
                                let mut track_match = None;

                                if scope_array.len() > 1 {
                                    match &scope_array[1] {
                                        Value::Array(ns_array) => {
                                            if ns_array.len()
                                                > limits.max_namespace_matches_per_scope
                                            {
                                                return Err(CatError::InvalidClaimValue(format!(
                                                    "Too many namespace matches per scope: {} (max {})",
                                                    ns_array.len(),
                                                    limits.max_namespace_matches_per_scope
                                                )));
                                            }
                                            for ns_value in ns_array {
                                                namespace_matches
                                                    .push(decode_namespace_match(ns_value)?);
                                            }
                                        }
                                        _ => {
                                            return Err(CatError::InvalidClaimValue(
                                                "MOQT namespace matches must be an array"
                                                    .to_string(),
                                            ));
                                        }
                                    }
                                }

                                // Enforce nil-last: once a Nil is seen, no further elements are allowed
                                let mut seen_nil = false;
                                for (idx, ns) in namespace_matches.iter().enumerate() {
                                    if seen_nil {
                                        return Err(CatError::InvalidClaimValue(format!(
                                            "Namespace nil must be the last element (found element at index {idx} after nil)"
                                        )));
                                    }
                                    if matches!(ns, NamespaceMatch::Nil) {
                                        seen_nil = true;
                                    }
                                }

                                if scope_array.len() > 2 {
                                    track_match = Some(decode_binary_match(&scope_array[2])?);
                                }

                                scopes.push(MoqtScope {
                                    actions,
                                    namespace_matches,
                                    track_match,
                                });
                            } else {
                                return Err(CatError::InvalidClaimValue(
                                    "MOQT scope values must be arrays".to_string(),
                                ));
                            }
                        }
                        moqt.moqt = Some(scopes);
                    } else {
                        return Err(CatError::InvalidClaimValue(
                            "moqt must be an array".to_string(),
                        ));
                    }
                }
                #[cfg(feature = "moqt")]
                CLAIM_MOQT_REVAL => {
                    reject_unexpected_tag(&value, "moqt_reval")?;
                    match value {
                        Value::Float(f) => {
                            validate_float(f, "moqt_reval")?;
                            moqt.moqt_reval = Some(f);
                        }
                        Value::Integer(i) => {
                            let i_i64: i64 = i.try_into().map_err(|_| {
                                CatError::InvalidClaimValue("Invalid moqt_reval value".to_string())
                            })?;
                            moqt.moqt_reval = Some(i_i64 as f64);
                        }
                        _ => {
                            return Err(CatError::InvalidClaimValue(
                                "moqt_reval must be a number".to_string(),
                            ));
                        }
                    }
                }
                CLAIM_OR | CLAIM_NOR | CLAIM_AND => {
                    reject_unexpected_tag(&value, "composite")?;
                    let composite =
                        decode_composite_claim_with_counters(claim_id, value, limits, 0, counters)?;
                    match claim_id {
                        CLAIM_OR => composite_claims.or_claim = Some(composite),
                        CLAIM_NOR => composite_claims.nor_claim = Some(composite),
                        CLAIM_AND => composite_claims.and_claim = Some(composite),
                        _ => unreachable!(),
                    }
                }
                _ => {
                    if custom.len() >= limits.max_custom_claims {
                        return Err(CatError::InvalidClaimValue(format!(
                            "Too many custom claims (max {})",
                            limits.max_custom_claims
                        )));
                    }
                    custom.insert(claim_id, value);
                }
            }
        }

        Ok(CatToken {
            core,
            cat,
            informational,
            dpop,
            request,
            composite: composite_claims,
            #[cfg(feature = "moqt")]
            moqt,
            custom,
        })
    }
}

/// Extract only the `iss` claim from a CWT payload without running the full
/// decoder. Called before signature verification so the resolver contract sees
/// the same `iss` that the (yet-unverified) token asserts; the peeked value is
/// only trusted for key selection. If the payload later verifies, the same
/// `iss` is re-parsed by the real decoder and enforced by the validator.
///
/// Returns `Ok(None)` if the payload is well-formed CBOR but has no `iss`.
/// Returns `Err` only if the outer structure is not a CBOR map or an `iss`
/// entry is present but not a text string — a hostile issuer must not be able
/// to smuggle bytes/integer-typed `iss` past the resolver.
pub fn peek_issuer(cbor_payload: &[u8]) -> Result<Option<String>, CatError> {
    let mut c = PeekCursor::new(cbor_payload);
    let (mt, ai) = c.read_header()?;
    if mt != 5 {
        return Err(CatError::InvalidTokenFormat);
    }
    let (len, indef) = c.count_from_ai(ai)?;

    let max_entries = len.min(PEEK_MAX_MAP_ENTRIES);
    let mut i: u64 = 0;
    loop {
        if !indef && i >= len {
            break;
        }
        if i >= max_entries {
            break;
        }
        if indef && c.peek_break()? {
            c.consume_byte();
            break;
        }
        let (kmt, kai) = c.read_header()?;
        if kmt == 0 && matches_ai_as_i64(kai, &mut c)? == Some(CLAIM_ISS) {
            let (vmt, vai) = c.read_header()?;
            if vmt != 3 {
                return Err(CatError::malformed(
                    "iss",
                    "iss must be a text string",
                ));
            }
            let n = c.length_from_ai(vai)? as usize;
            let bytes = c.read_bytes(n)?;
            let s = std::str::from_utf8(bytes)
                .map_err(|_| CatError::malformed("iss", "iss is not valid UTF-8"))?;
            return Ok(Some(s.to_string()));
        }
        c.skip_after_header(kmt, kai)?;
        c.skip_next_item()?;
        i += 1;
    }
    Ok(None)
}

/// Cap on the number of top-level map entries the [`peek_issuer`] byte
/// walker will scan. Well-formed CAT tokens carry a small number of
/// top-level claims; this cap prevents a hostile payload from forcing
/// unbounded pre-signature scanning.
const PEEK_MAX_MAP_ENTRIES: u64 = 128;
/// Cap on nested CBOR item depth traversed while skipping non-`iss`
/// entries in [`peek_issuer`]. Independent of the full-decode limits;
/// the peek walker sees fewer bytes and can afford a tighter bound.
const PEEK_MAX_DEPTH: u32 = 16;

/// Minimal, non-recursive CBOR byte-cursor used exclusively by
/// [`peek_issuer`]. No intermediate `Value` allocation, no ciborium
/// dependency reachable from this path — an attacker cannot inflate
/// pre-signature CPU by presenting a maximally-nested payload.
struct PeekCursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> PeekCursor<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn read_u8(&mut self) -> Result<u8, CatError> {
        if self.pos >= self.buf.len() {
            return Err(CatError::InvalidCbor("truncated".to_string()));
        }
        let b = self.buf[self.pos];
        self.pos += 1;
        Ok(b)
    }

    fn read_bytes(&mut self, n: usize) -> Result<&'a [u8], CatError> {
        let end = self
            .pos
            .checked_add(n)
            .ok_or_else(|| CatError::InvalidCbor("length overflow".to_string()))?;
        if end > self.buf.len() {
            return Err(CatError::InvalidCbor("truncated".to_string()));
        }
        let out = &self.buf[self.pos..end];
        self.pos = end;
        Ok(out)
    }

    fn consume_byte(&mut self) {
        self.pos = self.pos.saturating_add(1);
    }

    fn peek_break(&self) -> Result<bool, CatError> {
        if self.pos >= self.buf.len() {
            return Err(CatError::InvalidCbor("truncated".to_string()));
        }
        Ok(self.buf[self.pos] == 0xff)
    }

    fn read_header(&mut self) -> Result<(u8, u8), CatError> {
        let b = self.read_u8()?;
        Ok((b >> 5, b & 0x1f))
    }

    fn length_from_ai(&mut self, ai: u8) -> Result<u64, CatError> {
        match ai {
            0..=23 => Ok(ai as u64),
            24 => Ok(self.read_u8()? as u64),
            25 => {
                let hi = self.read_u8()? as u64;
                let lo = self.read_u8()? as u64;
                Ok((hi << 8) | lo)
            }
            26 => {
                let mut acc: u64 = 0;
                for _ in 0..4 {
                    acc = (acc << 8) | self.read_u8()? as u64;
                }
                Ok(acc)
            }
            27 => {
                let mut acc: u64 = 0;
                for _ in 0..8 {
                    acc = (acc << 8) | self.read_u8()? as u64;
                }
                Ok(acc)
            }
            _ => Err(CatError::InvalidCbor(
                "unexpected indefinite length".to_string(),
            )),
        }
    }

    /// Returns `(count, indefinite)` for the outer map header.
    fn count_from_ai(&mut self, ai: u8) -> Result<(u64, bool), CatError> {
        if ai == 31 {
            Ok((0, true))
        } else {
            Ok((self.length_from_ai(ai)?, false))
        }
    }

    fn skip_after_header(&mut self, mt: u8, ai: u8) -> Result<(), CatError> {
        match mt {
            0 | 1 => {
                let _ = self.length_from_ai(ai)?;
                Ok(())
            }
            2 | 3 => {
                if ai == 31 {
                    self.skip_indefinite_string()
                } else {
                    let n = self.length_from_ai(ai)? as usize;
                    let _ = self.read_bytes(n)?;
                    Ok(())
                }
            }
            4 => self.skip_array_or_map(ai, false, 1),
            5 => self.skip_array_or_map(ai, true, 1),
            6 => {
                let _ = self.length_from_ai(ai)?;
                self.skip_next_item()
            }
            7 => {
                if ai <= 23 {
                    return Ok(());
                }
                match ai {
                    24 => {
                        let _ = self.read_u8()?;
                        Ok(())
                    }
                    25 => {
                        let _ = self.read_bytes(2)?;
                        Ok(())
                    }
                    26 => {
                        let _ = self.read_bytes(4)?;
                        Ok(())
                    }
                    27 => {
                        let _ = self.read_bytes(8)?;
                        Ok(())
                    }
                    _ => Err(CatError::InvalidCbor(
                        "unexpected simple/float".to_string(),
                    )),
                }
            }
            _ => Err(CatError::InvalidCbor("unknown major type".to_string())),
        }
    }

    fn skip_next_item(&mut self) -> Result<(), CatError> {
        self.skip_next_item_at_depth(0)
    }

    fn skip_next_item_at_depth(&mut self, depth: u32) -> Result<(), CatError> {
        if depth > PEEK_MAX_DEPTH {
            return Err(CatError::InvalidCbor("peek nesting too deep".to_string()));
        }
        let (mt, ai) = self.read_header()?;
        match mt {
            0 | 1 => {
                let _ = self.length_from_ai(ai)?;
                Ok(())
            }
            2 | 3 => {
                if ai == 31 {
                    self.skip_indefinite_string()
                } else {
                    let n = self.length_from_ai(ai)? as usize;
                    let _ = self.read_bytes(n)?;
                    Ok(())
                }
            }
            4 => self.skip_array_or_map(ai, false, depth + 1),
            5 => self.skip_array_or_map(ai, true, depth + 1),
            6 => {
                let _ = self.length_from_ai(ai)?;
                self.skip_next_item_at_depth(depth + 1)
            }
            7 => {
                if ai <= 23 {
                    Ok(())
                } else {
                    match ai {
                        24 => {
                            let _ = self.read_u8()?;
                            Ok(())
                        }
                        25 => {
                            let _ = self.read_bytes(2)?;
                            Ok(())
                        }
                        26 => {
                            let _ = self.read_bytes(4)?;
                            Ok(())
                        }
                        27 => {
                            let _ = self.read_bytes(8)?;
                            Ok(())
                        }
                        _ => Err(CatError::InvalidCbor(
                            "unexpected simple/float".to_string(),
                        )),
                    }
                }
            }
            _ => Err(CatError::InvalidCbor("unknown major type".to_string())),
        }
    }

    fn skip_indefinite_string(&mut self) -> Result<(), CatError> {
        loop {
            if self.peek_break()? {
                self.consume_byte();
                return Ok(());
            }
            let (mt, ai) = self.read_header()?;
            if mt != 2 && mt != 3 {
                return Err(CatError::InvalidCbor(
                    "indefinite chunk wrong type".to_string(),
                ));
            }
            let n = self.length_from_ai(ai)? as usize;
            let _ = self.read_bytes(n)?;
        }
    }

    fn skip_array_or_map(
        &mut self,
        ai: u8,
        is_map: bool,
        depth: u32,
    ) -> Result<(), CatError> {
        if depth > PEEK_MAX_DEPTH {
            return Err(CatError::InvalidCbor("peek nesting too deep".to_string()));
        }
        let (len, indef) = self.count_from_ai(ai)?;
        let entries_per = if is_map { 2u64 } else { 1u64 };
        if indef {
            loop {
                if self.peek_break()? {
                    self.consume_byte();
                    return Ok(());
                }
                self.skip_next_item_at_depth(depth)?;
                if is_map {
                    self.skip_next_item_at_depth(depth)?;
                }
            }
        } else {
            let total = len
                .checked_mul(entries_per)
                .ok_or_else(|| CatError::InvalidCbor("map length overflow".to_string()))?;
            for _ in 0..total {
                self.skip_next_item_at_depth(depth)?;
            }
            Ok(())
        }
    }
}

fn matches_ai_as_i64(ai: u8, c: &mut PeekCursor<'_>) -> Result<Option<i64>, CatError> {
    let n = c.length_from_ai(ai)?;
    if n > i64::MAX as u64 {
        return Ok(None);
    }
    Ok(Some(n as i64))
}

fn decode_composite_claim_with_counters(
    claim_id: i64,
    value: Value,
    limits: &CwtLimits,
    depth: usize,
    counters: &mut DecodeCounters,
) -> Result<crate::claims::CompositeClaim, CatError> {
    if depth >= limits.max_nesting_depth {
        return Err(CatError::InvalidClaimValue(
            "Composite claim nesting too deep".to_string(),
        ));
    }
    let op = match claim_id {
        CLAIM_OR => crate::claims::CompositeOperator::Or,
        CLAIM_NOR => crate::claims::CompositeOperator::Nor,
        CLAIM_AND => crate::claims::CompositeOperator::And,
        _ => {
            return Err(CatError::InvalidClaimValue(
                "Unknown composite operator".to_string(),
            ));
        }
    };
    let arr = match value {
        Value::Array(a) => a,
        _ => {
            return Err(CatError::InvalidClaimValue(
                "Composite claim must be an array".to_string(),
            ));
        }
    };
    let mut composite = crate::claims::CompositeClaim::new(op);
    for item in arr {
        counters.count_item(limits)?;
        match item {
            Value::Map(ref map) => {
                let has_nested_composite = map.iter().any(|(k, _)| {
                    if let Value::Integer(i) = k {
                        let id: i64 = (*i).try_into().unwrap_or(0);
                        id == CLAIM_OR || id == CLAIM_NOR || id == CLAIM_AND
                    } else {
                        false
                    }
                });
                if has_nested_composite && map.len() == 1 {
                    let (k, v) = map.iter().next().unwrap();
                    let nested_id: i64 = match k {
                        Value::Integer(i) => (*i)
                            .try_into()
                            .map_err(|_| CatError::InvalidClaimValue("Invalid key".to_string()))?,
                        _ => {
                            return Err(CatError::InvalidClaimValue(
                                "Composite key must be integer".to_string(),
                            ));
                        }
                    };
                    let nested = decode_composite_claim_with_counters(
                        nested_id,
                        v.clone(),
                        limits,
                        depth + 1,
                        counters,
                    )?;
                    composite.add_composite(nested);
                } else {
                    let mut buf = Vec::new();
                    ciborium::ser::into_writer(&item, &mut buf)
                        .map_err(|e| CatError::InvalidCbor(e.to_string()))?;
                    let token =
                        Cwt::decode_payload_with_limits_and_counters(&buf, limits, counters)?;
                    composite.add_token(token);
                }
            }
            _ => {
                return Err(CatError::InvalidClaimValue(
                    "Composite claim set must be a map".to_string(),
                ));
            }
        }
    }
    Ok(composite)
}
