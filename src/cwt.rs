// SPDX-FileCopyrightText: Copyright (c) 2022 Quicr
// SPDX-License-Identifier: BSD-2-Clause

use crate::claims::*;
use crate::{CatClaims, CatError, CatToken, CoreClaims, GeoCoordinate};
use ciborium::Value;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};

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
            claims_map.insert(CLAIM_CTI, Value::Bytes(cti.as_bytes().to_vec()));
        }

        if let Some(ref catreplay) = self.payload.cat.catreplay {
            claims_map.insert(CLAIM_CATREPLAY, Value::Text(catreplay.clone()));
        }

        if let Some(catpor) = self.payload.cat.catpor {
            claims_map.insert(CLAIM_CATPOR, Value::Bool(catpor));
        }

        if let Some(ref catv) = self.payload.cat.catv {
            claims_map.insert(CLAIM_CATV, Value::Text(catv.clone()));
        }

        if let Some(ref catnip) = self.payload.cat.catnip {
            let nip_values: Vec<Value> = catnip
                .iter()
                .map(|nip| match nip {
                    NetworkIdentifier::IpAddress(ip) => Value::Text(ip.clone()),
                    NetworkIdentifier::IpRange(range) => Value::Map(vec![(
                        Value::Text("ip_range".to_string()),
                        Value::Text(range.clone()),
                    )]),
                    NetworkIdentifier::Asn(asn) => Value::Map(vec![(
                        Value::Text("asn".to_string()),
                        Value::Integer((*asn).into()),
                    )]),
                    NetworkIdentifier::AsnRange(start, end) => Value::Map(vec![(
                        Value::Text("asn_range".to_string()),
                        Value::Array(vec![
                            Value::Integer((*start).into()),
                            Value::Integer((*end).into()),
                        ]),
                    )]),
                })
                .collect();
            claims_map.insert(CLAIM_CATNIP, Value::Array(nip_values));
        }

        if let Some(catu) = self.payload.cat.catu {
            claims_map.insert(CLAIM_CATU, Value::Integer(catu.into()));
        }

        if let Some(ref catm) = self.payload.cat.catm {
            claims_map.insert(CLAIM_CATM, Value::Text(catm.clone()));
        }

        if let Some(ref catalpn) = self.payload.cat.catalpn {
            let alpn_values: Vec<Value> = catalpn.iter().map(|a| Value::Text(a.clone())).collect();
            claims_map.insert(CLAIM_CATALPN, Value::Array(alpn_values));
        }

        if let Some(ref cath) = self.payload.cat.cath {
            let pattern_values: Vec<Value> = cath
                .iter()
                .map(|pattern| match pattern {
                    UriPattern::Exact(s) => Value::Text(s.clone()),
                    UriPattern::Prefix(s) => Value::Map(vec![(
                        Value::Text("prefix".to_string()),
                        Value::Text(s.clone()),
                    )]),
                    UriPattern::Suffix(s) => Value::Map(vec![(
                        Value::Text("suffix".to_string()),
                        Value::Text(s.clone()),
                    )]),
                    UriPattern::Regex(s) => Value::Map(vec![(
                        Value::Text("regex".to_string()),
                        Value::Text(s.clone()),
                    )]),
                    UriPattern::Hash(s) => Value::Map(vec![(
                        Value::Text("hash".to_string()),
                        Value::Text(s.clone()),
                    )]),
                })
                .collect();
            claims_map.insert(CLAIM_CATH, Value::Array(pattern_values));
        }

        if let Some(ref catgeoiso3166) = self.payload.cat.catgeoiso3166 {
            let geo_values: Vec<Value> = catgeoiso3166
                .iter()
                .map(|g| Value::Text(g.clone()))
                .collect();
            claims_map.insert(CLAIM_CATGEOISO3166, Value::Array(geo_values));
        }

        if let Some(ref catgeocoord) = self.payload.cat.catgeocoord {
            let mut coord_map = Vec::new();
            coord_map.push((
                Value::Text("lat".to_string()),
                Value::Float(catgeocoord.lat),
            ));
            coord_map.push((
                Value::Text("lon".to_string()),
                Value::Float(catgeocoord.lon),
            ));
            if let Some(accuracy) = catgeocoord.accuracy {
                coord_map.push((Value::Text("accuracy".to_string()), Value::Float(accuracy)));
            }
            claims_map.insert(CLAIM_CATGEOCOORD, Value::Map(coord_map));
        }

        if let Some(ref geohash) = self.payload.cat.geohash {
            claims_map.insert(CLAIM_GEOHASH, Value::Text(geohash.clone()));
        }

        if let Some(catgeoalt) = self.payload.cat.catgeoalt {
            claims_map.insert(CLAIM_CATGEOALT, Value::Integer(catgeoalt.into()));
        }

        if let Some(ref cattpk) = self.payload.cat.cattpk {
            claims_map.insert(CLAIM_CATTPK, Value::Text(cattpk.clone()));
        }

        // Informational claims
        if let Some(ref sub) = self.payload.informational.sub {
            claims_map.insert(CLAIM_SUB, Value::Text(sub.clone()));
        }

        if let Some(iat) = self.payload.informational.iat {
            claims_map.insert(CLAIM_IAT, Value::Integer(iat.into()));
        }

        if let Some(ref catifdata) = self.payload.informational.catifdata {
            claims_map.insert(CLAIM_CATIFDATA, Value::Text(catifdata.clone()));
        }

        // DPoP claims - cnf is a map with jkt (key 3) containing the JWK thumbprint
        if let Some(ref cnf) = self.payload.dpop.cnf {
            let cnf_map = vec![(
                Value::Integer(CNF_JKT.into()),
                Value::Bytes(cnf.jkt.clone()),
            )];
            claims_map.insert(CLAIM_CNF, Value::Map(cnf_map));
        }

        // catdpop is a map with window (key 0) and honor_jti (key 1)
        if let Some(ref catdpop) = self.payload.dpop.catdpop {
            let mut dpop_map = Vec::new();
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
            if !dpop_map.is_empty() {
                claims_map.insert(CLAIM_CATDPOP, Value::Map(dpop_map));
            }
        }

        // Request claims
        if let Some(ref catif) = self.payload.request.catif {
            claims_map.insert(CLAIM_CATIF, Value::Text(catif.clone()));
        }

        if let Some(ref catr) = self.payload.request.catr {
            claims_map.insert(CLAIM_CATR, Value::Text(catr.clone()));
        }

        #[cfg(feature = "moqt")]
        if let Some(ref moqt_scopes) = self.payload.moqt.moqt {
            let scopes_array: Vec<Value> = moqt_scopes
                .iter()
                .map(|scope| {
                    let actions: Vec<Value> = scope
                        .actions
                        .iter()
                        .map(|action| Value::Integer((*action as i32).into()))
                        .collect();

                    let mut scope_array = vec![Value::Array(actions)];

                    if !scope.namespace_matches.is_empty() {
                        let ns_matches: Vec<Value> = scope
                            .namespace_matches
                            .iter()
                            .map(encode_namespace_match)
                            .collect();
                        scope_array.push(Value::Array(ns_matches));
                    }

                    if let Some(ref track_match) = scope.track_match {
                        if scope.namespace_matches.is_empty() {
                            scope_array.push(Value::Array(vec![]));
                        }
                        scope_array.push(encode_binary_match(track_match));
                    }

                    Value::Array(scope_array)
                })
                .collect();
            claims_map.insert(CLAIM_MOQT, Value::Array(scopes_array));
        }

        #[cfg(feature = "moqt")]
        if let Some(moqt_reval) = self.payload.moqt.moqt_reval {
            claims_map.insert(CLAIM_MOQT_REVAL, Value::Float(moqt_reval));
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
fn encode_binary_match(binary_match: &crate::claims::BinaryMatch) -> Value {
    if binary_match.is_empty() {
        return Value::Bytes(vec![]);
    }

    match binary_match.match_type {
        BinaryMatchType::Exact => Value::Bytes(binary_match.pattern.clone()),
        BinaryMatchType::Prefix => Value::Array(vec![
            Value::Integer(MATCH_TYPE_PREFIX.into()),
            Value::Bytes(binary_match.pattern.clone()),
        ]),
        BinaryMatchType::Suffix => Value::Array(vec![
            Value::Integer(MATCH_TYPE_SUFFIX.into()),
            Value::Bytes(binary_match.pattern.clone()),
        ]),
    }
}

#[cfg(feature = "moqt")]
fn encode_namespace_match(ns_match: &crate::claims::NamespaceMatch) -> Value {
    match ns_match {
        NamespaceMatch::Nil => Value::Null,
        NamespaceMatch::Match(binary_match) => encode_binary_match(binary_match),
    }
}

#[cfg(feature = "moqt")]
fn decode_binary_match(value: &Value) -> Result<crate::claims::BinaryMatch, CatError> {
    match value {
        Value::Bytes(data) => {
            if data.is_empty() {
                Ok(BinaryMatch::any())
            } else {
                Ok(BinaryMatch::exact(data.clone()))
            }
        }
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

/// Default maximum CBOR payload size (1MB)
pub const DEFAULT_MAX_CBOR_PAYLOAD_SIZE: usize = 1024 * 1024;

/// Default maximum number of MOQT scopes allowed in a token
pub const DEFAULT_MAX_MOQT_SCOPES: usize = 1000;

/// Default maximum number of custom claims allowed in a token
pub const DEFAULT_MAX_CUSTOM_CLAIMS: usize = 100;

/// Default maximum length for individual string claims (8KB)
pub const DEFAULT_MAX_STRING_CLAIM_LENGTH: usize = 8 * 1024;

/// Default maximum number of namespace matches per scope
pub const DEFAULT_MAX_NAMESPACE_MATCHES_PER_SCOPE: usize = 100;

/// Default maximum number of URI patterns allowed
pub const DEFAULT_MAX_URI_PATTERNS: usize = 1000;

/// Configuration for CWT validation limits.
///
/// All limits have sensible defaults but can be customized for specific use cases.
#[derive(Debug, Clone)]
pub struct CwtLimits {
    /// Maximum CBOR payload size in bytes
    pub max_cbor_payload_size: usize,
    /// Maximum number of MOQT scopes per token
    pub max_moqt_scopes: usize,
    /// Maximum number of custom claims per token
    pub max_custom_claims: usize,
    /// Maximum length for string claims in bytes
    pub max_string_claim_length: usize,
    /// Maximum namespace matches per scope
    pub max_namespace_matches_per_scope: usize,
    /// Maximum URI patterns
    pub max_uri_patterns: usize,
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
        }
    }
}

impl CwtLimits {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_max_cbor_payload_size(mut self, size: usize) -> Self {
        self.max_cbor_payload_size = size;
        self
    }

    pub fn with_max_moqt_scopes(mut self, count: usize) -> Self {
        self.max_moqt_scopes = count;
        self
    }

    pub fn with_max_custom_claims(mut self, count: usize) -> Self {
        self.max_custom_claims = count;
        self
    }

    pub fn with_max_string_claim_length(mut self, length: usize) -> Self {
        self.max_string_claim_length = length;
        self
    }
}

/// Validate string length to prevent memory exhaustion
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

/// Validate string length using default limit
fn validate_string_length(s: &str, claim_name: &str) -> Result<(), CatError> {
    validate_string_length_with_limit(s, claim_name, DEFAULT_MAX_STRING_CLAIM_LENGTH)
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
        // Limit CBOR payload size to prevent memory exhaustion
        if cbor_data.len() > limits.max_cbor_payload_size {
            return Err(CatError::InvalidCbor(format!(
                "CBOR payload too large: {} bytes (max {} bytes)",
                cbor_data.len(),
                limits.max_cbor_payload_size
            )));
        }

        let value: Value = ciborium::de::from_reader(cbor_data)
            .map_err(|e| CatError::InvalidCbor(e.to_string()))?;

        let claims_map = match value {
            Value::Map(map) => map,
            _ => return Err(CatError::InvalidTokenFormat),
        };

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

        let mut custom = HashMap::new();

        for (key, value) in claims_map {
            let claim_id = match key {
                Value::Integer(i) => i.try_into().map_err(|_| CatError::InvalidTokenFormat)?,
                _ => continue,
            };

            match claim_id {
                CLAIM_ISS => {
                    if let Value::Text(s) = value {
                        validate_string_length(&s, "issuer")?;
                        core.iss = Some(s);
                    }
                }
                CLAIM_AUD => {
                    if let Value::Array(arr) = value {
                        let mut audiences = Vec::new();
                        for item in arr {
                            if let Value::Text(s) = item {
                                validate_string_length(&s, "audience")?;
                                audiences.push(s);
                            }
                        }
                        core.aud = Some(audiences);
                    }
                }
                CLAIM_EXP => {
                    if let Value::Integer(i) = value {
                        core.exp = Some(i.try_into().map_err(|_| CatError::InvalidTokenFormat)?);
                    }
                }
                CLAIM_NBF => {
                    if let Value::Integer(i) = value {
                        core.nbf = Some(i.try_into().map_err(|_| CatError::InvalidTokenFormat)?);
                    }
                }
                CLAIM_CTI => match value {
                    Value::Bytes(b) => {
                        // Reject invalid UTF-8 instead of silently replacing
                        core.cti = Some(String::from_utf8(b).map_err(|_| {
                            CatError::InvalidClaimValue("CTI contains invalid UTF-8".to_string())
                        })?);
                    }
                    Value::Text(s) => {
                        core.cti = Some(s);
                    }
                    _ => {}
                },
                CLAIM_CATREPLAY => {
                    if let Value::Text(s) = value {
                        cat.catreplay = Some(s);
                    }
                }
                CLAIM_CATPOR => {
                    if let Value::Bool(b) = value {
                        cat.catpor = Some(b);
                    }
                }
                CLAIM_CATV => {
                    if let Value::Text(s) = value {
                        cat.catv = Some(s);
                    }
                }
                CLAIM_CATNIP => {
                    if let Value::Array(arr) = value {
                        let mut nips = Vec::new();
                        for item in arr {
                            match item {
                                Value::Text(s) => {
                                    nips.push(NetworkIdentifier::IpAddress(s));
                                }
                                Value::Map(map) => {
                                    for (k, v) in map {
                                        if let Value::Text(key_str) = k {
                                            match key_str.as_str() {
                                                "ip_range" => {
                                                    if let Value::Text(range) = v {
                                                        nips.push(NetworkIdentifier::IpRange(
                                                            range,
                                                        ));
                                                    }
                                                }
                                                "asn" => {
                                                    if let Value::Integer(asn) = v
                                                        && let Ok(asn_u32) =
                                                            TryInto::<u32>::try_into(asn)
                                                    {
                                                        nips.push(NetworkIdentifier::Asn(asn_u32));
                                                    }
                                                }
                                                "asn_range" => {
                                                    if let Value::Array(range_arr) = v
                                                        && range_arr.len() == 2
                                                        && let (
                                                            Value::Integer(start),
                                                            Value::Integer(end),
                                                        ) = (&range_arr[0], &range_arr[1])
                                                        && let (Ok(start_u32), Ok(end_u32)) = (
                                                            TryInto::<u32>::try_into(*start),
                                                            TryInto::<u32>::try_into(*end),
                                                        )
                                                    {
                                                        nips.push(NetworkIdentifier::AsnRange(
                                                            start_u32, end_u32,
                                                        ));
                                                    }
                                                }
                                                _ => {}
                                            }
                                        }
                                    }
                                }
                                _ => {}
                            }
                        }
                        cat.catnip = Some(nips);
                    }
                }
                CLAIM_CATU => {
                    if let Value::Integer(i) = value {
                        cat.catu = Some(i.try_into().map_err(|_| CatError::InvalidTokenFormat)?);
                    }
                }
                CLAIM_CATM => {
                    if let Value::Text(s) = value {
                        cat.catm = Some(s);
                    }
                }
                CLAIM_CATALPN => {
                    if let Value::Array(arr) = value {
                        let mut alpns = Vec::new();
                        for item in arr {
                            if let Value::Text(s) = item {
                                alpns.push(s);
                            }
                        }
                        cat.catalpn = Some(alpns);
                    }
                }
                CLAIM_CATH => {
                    if let Value::Array(arr) = value {
                        // Limit URI pattern count
                        if arr.len() > DEFAULT_MAX_URI_PATTERNS {
                            return Err(CatError::InvalidClaimValue(format!(
                                "Too many URI patterns: {} (max {})",
                                arr.len(),
                                DEFAULT_MAX_URI_PATTERNS
                            )));
                        }
                        let mut patterns = Vec::new();
                        for item in arr {
                            if let Value::Text(s) = item {
                                validate_string_length(&s, "URI pattern")?;
                                patterns.push(UriPattern::Exact(s));
                            } else if let Value::Map(pattern_map) = item
                                && let Some((key, val)) = pattern_map.into_iter().next()
                                && let (Value::Text(pattern_type), Value::Text(pattern_value)) =
                                    (key, val)
                            {
                                validate_string_length(&pattern_value, "URI pattern")?;
                                match pattern_type.as_str() {
                                    "exact" => patterns.push(UriPattern::Exact(pattern_value)),
                                    "prefix" => patterns.push(UriPattern::Prefix(pattern_value)),
                                    "suffix" => patterns.push(UriPattern::Suffix(pattern_value)),
                                    "regex" => patterns.push(UriPattern::Regex(pattern_value)),
                                    "hash" => patterns.push(UriPattern::Hash(pattern_value)),
                                    _ => {}
                                }
                            }
                        }
                        cat.cath = Some(patterns);
                    }
                }
                CLAIM_CATGEOISO3166 => {
                    if let Value::Array(arr) = value {
                        let mut countries = Vec::new();
                        for item in arr {
                            if let Value::Text(s) = item {
                                countries.push(s);
                            }
                        }
                        cat.catgeoiso3166 = Some(countries);
                    }
                }
                CLAIM_CATGEOCOORD => {
                    if let Value::Map(map) = value {
                        let mut lat = None;
                        let mut lon = None;
                        let mut accuracy = None;

                        for (k, v) in map {
                            if let Value::Text(key_str) = k {
                                match key_str.as_str() {
                                    "lat" => {
                                        if let Value::Float(f) = v {
                                            lat = Some(f);
                                        }
                                    }
                                    "lon" => {
                                        if let Value::Float(f) = v {
                                            lon = Some(f);
                                        }
                                    }
                                    "accuracy" => {
                                        if let Value::Float(f) = v {
                                            accuracy = Some(f);
                                        }
                                    }
                                    _ => {}
                                }
                            }
                        }

                        if let (Some(lat), Some(lon)) = (lat, lon) {
                            cat.catgeocoord = Some(GeoCoordinate { lat, lon, accuracy });
                        }
                    }
                }
                CLAIM_GEOHASH => {
                    if let Value::Text(s) = value {
                        cat.geohash = Some(s);
                    }
                }
                CLAIM_CATGEOALT => {
                    if let Value::Integer(i) = value {
                        cat.catgeoalt =
                            Some(i.try_into().map_err(|_| CatError::InvalidTokenFormat)?);
                    }
                }
                CLAIM_CATTPK => {
                    if let Value::Text(s) = value {
                        cat.cattpk = Some(s);
                    }
                }
                CLAIM_SUB => {
                    if let Value::Text(s) = value {
                        validate_string_length(&s, "subject")?;
                        informational.sub = Some(s);
                    }
                }
                CLAIM_IAT => {
                    if let Value::Integer(i) = value {
                        informational.iat =
                            Some(i.try_into().map_err(|_| CatError::InvalidTokenFormat)?);
                    }
                }
                CLAIM_CATIFDATA => {
                    if let Value::Text(s) = value {
                        informational.catifdata = Some(s);
                    }
                }
                CLAIM_CNF => {
                    // cnf is a map with jkt (key 3) containing the JWK thumbprint
                    if let Value::Map(map) = value {
                        for (k, v) in map {
                            if let Value::Integer(key_int) = k {
                                // Unknown keys (conversion failure) default to -1, which is ignored
                                let key_val: i64 = key_int.try_into().unwrap_or(-1);
                                if key_val == CNF_JKT
                                    && let Value::Bytes(jkt) = v
                                {
                                    dpop.cnf = Some(ConfirmationClaim::new(jkt));
                                }
                            }
                        }
                    }
                }
                CLAIM_CATDPOP => {
                    // catdpop is a map with window (key 0) and honor_jti (key 1)
                    if let Value::Map(map) = value {
                        let mut settings = CatDpopSettings::new();
                        for (k, v) in map {
                            if let Value::Integer(key_int) = k {
                                // Unknown keys (conversion failure) default to -1, which is ignored
                                let key_val: i64 = key_int.try_into().unwrap_or(-1);
                                match key_val {
                                    0 => {
                                        if let Value::Integer(window) = v {
                                            // Reject invalid window values instead of defaulting
                                            let window_val: i64 =
                                                window.try_into().map_err(|_| {
                                                    CatError::InvalidClaimValue(
                                                        "Invalid DPoP window value".to_string(),
                                                    )
                                                })?;
                                            if window_val <= 0 {
                                                return Err(CatError::InvalidClaimValue(
                                                    "DPoP window must be positive".to_string(),
                                                ));
                                            }
                                            settings.window = Some(window_val);
                                        }
                                    }
                                    1 => {
                                        if let Value::Integer(jti_val) = v {
                                            // Invalid boolean defaults to true (honor_jti=true is safer)
                                            let jti_i64: i64 = jti_val.try_into().unwrap_or(1);
                                            settings.honor_jti = Some(jti_i64 != 0);
                                        }
                                    }
                                    _ => {} // Unknown keys are ignored per forward compatibility
                                }
                            }
                        }
                        dpop.catdpop = Some(settings);
                    }
                }
                CLAIM_CATIF => {
                    if let Value::Text(s) = value {
                        request.catif = Some(s);
                    }
                }
                CLAIM_CATR => {
                    if let Value::Text(s) = value {
                        request.catr = Some(s);
                    }
                }
                #[cfg(feature = "moqt")]
                CLAIM_MOQT => {
                    if let Value::Array(scopes_array) = value {
                        // Limit scope count to prevent memory exhaustion
                        if scopes_array.len() > DEFAULT_MAX_MOQT_SCOPES {
                            return Err(CatError::InvalidClaimValue(format!(
                                "Too many MOQT scopes: {} (max {})",
                                scopes_array.len(),
                                DEFAULT_MAX_MOQT_SCOPES
                            )));
                        }
                        let mut scopes = Vec::new();
                        for scope_value in scopes_array {
                            if let Value::Array(scope_array) = scope_value {
                                if scope_array.is_empty() {
                                    continue;
                                }

                                let mut actions = Vec::new();
                                if let Value::Array(ref actions_array) = scope_array[0] {
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
                                        }
                                    }
                                }

                                let mut namespace_matches = Vec::new();
                                let mut track_match = None;

                                if scope_array.len() > 1
                                    && let Value::Array(ref ns_array) = scope_array[1]
                                {
                                    // Limit namespace matches per scope
                                    if ns_array.len() > DEFAULT_MAX_NAMESPACE_MATCHES_PER_SCOPE {
                                        return Err(CatError::InvalidClaimValue(format!(
                                            "Too many namespace matches per scope: {} (max {})",
                                            ns_array.len(),
                                            DEFAULT_MAX_NAMESPACE_MATCHES_PER_SCOPE
                                        )));
                                    }
                                    for ns_value in ns_array {
                                        namespace_matches.push(decode_namespace_match(ns_value)?);
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
                            }
                        }
                        moqt.moqt = Some(scopes);
                    }
                }
                #[cfg(feature = "moqt")]
                CLAIM_MOQT_REVAL => {
                    if let Value::Float(f) = value {
                        moqt.moqt_reval = Some(f);
                    } else if let Value::Integer(i) = value
                        && let Ok(i_i64) = TryInto::<i64>::try_into(i)
                    {
                        moqt.moqt_reval = Some(i_i64 as f64);
                    }
                }
                _ => {
                    // Limit custom claims count to prevent memory exhaustion
                    if custom.len() >= DEFAULT_MAX_CUSTOM_CLAIMS {
                        return Err(CatError::InvalidClaimValue(format!(
                            "Too many custom claims (max {})",
                            DEFAULT_MAX_CUSTOM_CLAIMS
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
            composite: crate::claims::CompositeClaims::default(),
            #[cfg(feature = "moqt")]
            moqt,
            custom,
        })
    }
}
