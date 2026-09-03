// SPDX-FileCopyrightText: Copyright (c) 2022 Quicr
// SPDX-License-Identifier: BSD-2-Clause

use crate::{CatError, CatToken, CryptographicAlgorithm, Cwt, CwtHeader, NetworkIdentifier};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Utc};
use std::collections::HashSet;

const COSE_TAG_SIGN1: u64 = 18;
const COSE_TAG_MAC0: u64 = 17;

pub struct CatTokenValidator {
    expected_issuers: Option<HashSet<String>>,
    expected_audiences: Option<HashSet<String>>,
    /// Clock skew tolerance for expiration (seconds past exp that token is still valid)
    exp_tolerance: i64,
    /// Clock skew tolerance for not-before (seconds before nbf that token is valid)
    nbf_tolerance: i64,
}

impl Default for CatTokenValidator {
    fn default() -> Self {
        Self::new()
    }
}

impl CatTokenValidator {
    pub fn new() -> Self {
        Self {
            expected_issuers: None,
            expected_audiences: None,
            exp_tolerance: 0,
            nbf_tolerance: 0,
        }
    }

    pub fn with_expected_issuers(mut self, issuers: Vec<String>) -> Self {
        self.expected_issuers = Some(issuers.into_iter().collect());
        self
    }

    pub fn with_expected_audiences(mut self, audiences: Vec<String>) -> Self {
        self.expected_audiences = Some(audiences.into_iter().collect());
        self
    }

    /// Set symmetric clock skew tolerance for both exp and nbf
    pub fn with_clock_skew_tolerance(mut self, tolerance_seconds: i64) -> Self {
        self.exp_tolerance = tolerance_seconds;
        self.nbf_tolerance = tolerance_seconds;
        self
    }

    /// Set separate tolerances for expiration and not-before checks.
    ///
    /// - `exp_tolerance`: seconds past expiration that token is still accepted
    /// - `nbf_tolerance`: seconds before not-before that token is accepted
    pub fn with_separate_tolerances(mut self, exp_tolerance: i64, nbf_tolerance: i64) -> Self {
        self.exp_tolerance = exp_tolerance;
        self.nbf_tolerance = nbf_tolerance;
        self
    }

    pub fn validate(&self, token: &CatToken) -> Result<(), CatError> {
        let now = Utc::now().timestamp();

        if let Some(exp) = token.core.exp
            && now > exp + self.exp_tolerance
        {
            return Err(CatError::TokenExpired);
        }

        if let Some(nbf) = token.core.nbf
            && now < nbf - self.nbf_tolerance
        {
            return Err(CatError::TokenNotYetValid);
        }

        if let Some(ref expected_issuers) = self.expected_issuers {
            if let Some(ref iss) = token.core.iss {
                if !expected_issuers.contains(iss) {
                    return Err(CatError::InvalidIssuer);
                }
            } else {
                return Err(CatError::MissingRequiredClaim("iss".to_string()));
            }
        }

        if let Some(ref expected_audiences) = self.expected_audiences {
            if let Some(ref aud) = token.core.aud {
                if !aud.iter().any(|a| expected_audiences.contains(a)) {
                    return Err(CatError::InvalidAudience);
                }
            } else {
                return Err(CatError::MissingRequiredClaim("aud".to_string()));
            }
        }

        self.validate_geographic_restrictions(token)?;
        self.validate_usage_limits(token)?;
        self.validate_regex_ere(token)?;
        self.validate_composite_claims(token)?;

        Ok(())
    }

    fn validate_geographic_restrictions(&self, token: &CatToken) -> Result<(), CatError> {
        if let Some(ref coords) = token.cat.catgeocoord {
            for coord in coords {
                if coord.lat.abs() > 90.0 || coord.lon.abs() > 180.0 {
                    return Err(CatError::GeographicValidationFailed(
                        "Invalid coordinates".to_string(),
                    ));
                }
            }
        }

        if let Some(ref geohashes) = token.cat.geohash {
            const MIN_GEOHASH_LENGTH: usize = 4;
            const MAX_GEOHASH_LENGTH: usize = 12;
            const VALID_GEOHASH_CHARS: &str = "0123456789bcdefghjkmnpqrstuvwxyz";

            for geohash in geohashes {
                if geohash.len() < MIN_GEOHASH_LENGTH || geohash.len() > MAX_GEOHASH_LENGTH {
                    return Err(CatError::GeographicValidationFailed(format!(
                        "Invalid geohash length: {} (must be {}-{} characters for meaningful precision)",
                        geohash.len(),
                        MIN_GEOHASH_LENGTH,
                        MAX_GEOHASH_LENGTH
                    )));
                }
                for c in geohash.chars() {
                    if !VALID_GEOHASH_CHARS.contains(c) {
                        return Err(CatError::GeographicValidationFailed(format!(
                            "Invalid geohash character: '{}'",
                            c
                        )));
                    }
                }
            }
        }

        // Validate network identifiers if present
        if let Some(ref nips) = token.cat.catnip {
            for nip in nips {
                nip.validate()?;
            }
        }

        Ok(())
    }

    fn validate_usage_limits(&self, _token: &CatToken) -> Result<(), CatError> {
        Ok(())
    }

    fn validate_regex_ere(&self, token: &CatToken) -> Result<(), CatError> {
        if let Some(ref rules) = token.cat.catu {
            for rule in rules {
                for mv in &rule.matches {
                    if let crate::claims::MatchValue::Regex(pattern) = mv {
                        if let Some(err) = crate::claims::validate_posix_ere(pattern) {
                            return Err(CatError::InvalidClaimValue(format!("catu regex: {err}")));
                        }
                    }
                }
            }
        }
        if let Some(ref rules) = token.cat.cath {
            for rule in rules {
                for mv in &rule.matches {
                    if let crate::claims::MatchValue::Regex(pattern) = mv {
                        if let Some(err) = crate::claims::validate_posix_ere(pattern) {
                            return Err(CatError::InvalidClaimValue(format!("cath regex: {err}")));
                        }
                    }
                }
            }
        }
        Ok(())
    }

    fn validate_composite_claims(&self, token: &CatToken) -> Result<(), CatError> {
        if token.composite.has_composites() {
            // Check nesting depth limit (spec requires minimum support of 4 levels)
            const MAX_NESTING_DEPTH: usize = 10; // Conservative limit to prevent stack overflow

            // Use bounded depth check to prevent stack overflow before validation
            if token.composite.exceeds_depth_limit(MAX_NESTING_DEPTH) {
                return Err(CatError::InvalidClaimValue(
                    "Composite claim nesting depth exceeds maximum".to_string(),
                ));
            }

            // Validate all composite claims using this validator
            let validator_fn = |token: &CatToken| -> Result<(), Box<dyn std::error::Error>> {
                self.validate(token)
                    .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)
            };

            token
                .composite
                .validate_all(&validator_fn)
                .map_err(|e| CatError::InvalidClaimValue(e.to_string()))?;
        }

        Ok(())
    }
}

pub struct CatTokenBuilder {
    inner: CatToken,
}

impl Default for CatTokenBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl CatTokenBuilder {
    pub fn new() -> Self {
        Self {
            inner: CatToken::new(),
        }
    }

    pub fn issuer(mut self, issuer: impl Into<String>) -> Self {
        self.inner = self.inner.with_issuer(issuer);
        self
    }

    pub fn audience(mut self, audiences: Vec<String>) -> Self {
        self.inner = self.inner.with_audience(audiences);
        self
    }

    pub fn single_audience(self, audience: impl Into<String>) -> Self {
        self.audience(vec![audience.into()])
    }

    pub fn expires_at(mut self, exp: DateTime<Utc>) -> Self {
        self.inner = self.inner.with_expiration(exp);
        self
    }

    pub fn expires_in(self, seconds: i64) -> Self {
        self.expires_at(Utc::now() + chrono::Duration::seconds(seconds))
    }

    pub fn not_before(mut self, nbf: DateTime<Utc>) -> Self {
        self.inner = self.inner.with_not_before(nbf);
        self
    }

    pub fn cwt_id(mut self, cti: impl Into<Vec<u8>>) -> Self {
        self.inner = self.inner.with_cwt_id(cti);
        self
    }

    pub fn cwt_id_str(mut self, cti: impl AsRef<str>) -> Self {
        self.inner = self.inner.with_cwt_id_str(cti);
        self
    }

    pub fn version(mut self, version: u32) -> Self {
        self.inner = self.inner.with_version(version);
        self
    }

    pub fn uri_match_rules(mut self, rules: Vec<crate::claims::UriMatchRule>) -> Self {
        self.inner = self.inner.with_uri_match_rules(rules);
        self
    }

    pub fn replay_protection(mut self, mode: crate::claims::ReplayProtection) -> Self {
        self.inner = self.inner.with_replay_protection(mode);
        self
    }

    pub fn probability_of_rejection(
        mut self,
        probability: f64,
        id: Vec<u8>,
        expiration: Option<i64>,
    ) -> Self {
        self.inner = self
            .inner
            .with_probability_of_rejection(probability, id, expiration);
        self
    }

    pub fn geo_coordinate(mut self, lat: f64, lon: f64, radius: Option<u32>) -> Self {
        self.inner = self.inner.with_geo_coordinate(lat, lon, radius);
        self
    }

    pub fn geo_coordinates(mut self, coords: Vec<crate::claims::GeoCoordinate>) -> Self {
        self.inner = self.inner.with_geo_coordinates(coords);
        self
    }

    pub fn geohash(mut self, geohash: impl Into<String>) -> Self {
        self.inner = self.inner.with_geohash(geohash);
        self
    }

    pub fn subject(mut self, subject: impl Into<String>) -> Self {
        self.inner = self.inner.with_subject(subject);
        self
    }

    pub fn issued_at(mut self, iat: chrono::DateTime<chrono::Utc>) -> Self {
        self.inner = self.inner.with_issued_at(iat);
        self
    }

    pub fn interface_data(mut self, data: impl Into<String>) -> Self {
        self.inner = self.inner.with_interface_data(data);
        self
    }

    pub fn confirmation(mut self, jkt: Vec<u8>) -> Self {
        self.inner = self.inner.with_confirmation(jkt);
        self
    }

    pub fn cose_key_thumbprint(mut self, ckt: Vec<u8>) -> Self {
        self.inner = self.inner.with_cose_key_thumbprint(ckt);
        self
    }

    pub fn dpop_settings(mut self, settings: crate::claims::CatDpopSettings) -> Self {
        self.inner = self.inner.with_dpop_settings(settings);
        self
    }

    pub fn dpop_window(mut self, window_seconds: i64) -> Self {
        self.inner = self.inner.with_dpop_window(window_seconds);
        self
    }

    pub fn if_action(mut self, claim_key: i64, action: crate::claims::CatIfAction) -> Self {
        self.inner = self.inner.with_if_action(claim_key, action);
        self
    }

    pub fn if_actions(mut self, actions: Vec<(i64, crate::claims::CatIfAction)>) -> Self {
        self.inner = self.inner.with_if_actions(actions);
        self
    }

    pub fn renewal(mut self, renewal: crate::claims::CatRenewal) -> Self {
        self.inner = self.inner.with_renewal(renewal);
        self
    }

    pub fn header_match_rules(mut self, rules: Vec<crate::claims::HeaderMatchRule>) -> Self {
        self.inner = self.inner.with_header_match_rules(rules);
        self
    }

    pub fn network_identifiers(mut self, nips: Vec<NetworkIdentifier>) -> Self {
        self.inner = self.inner.with_network_identifiers(nips);
        self
    }

    pub fn ip_address(mut self, ip: impl Into<String>) -> Self {
        self.inner = self.inner.with_ip_address(ip);
        self
    }

    pub fn ip_range(mut self, range: impl Into<String>) -> Self {
        self.inner = self.inner.with_ip_range(range);
        self
    }

    pub fn asn(mut self, asn: u32) -> Self {
        self.inner = self.inner.with_asn(asn);
        self
    }

    pub fn asn_range(mut self, start: u32, end: u32) -> Self {
        self.inner = self.inner.with_asn_range(start, end);
        self
    }

    // Composite claims builder methods
    pub fn or_composite(mut self, or_claim: crate::claims::CompositeClaim) -> Self {
        self.inner = self.inner.with_or_composite(or_claim);
        self
    }

    pub fn nor_composite(mut self, nor_claim: crate::claims::CompositeClaim) -> Self {
        self.inner = self.inner.with_nor_composite(nor_claim);
        self
    }

    pub fn and_composite(mut self, and_claim: crate::claims::CompositeClaim) -> Self {
        self.inner = self.inner.with_and_composite(and_claim);
        self
    }

    #[cfg(feature = "moqt")]
    pub fn moqt_scopes(mut self, scopes: Vec<crate::claims::MoqtScope>) -> Self {
        self.inner = self.inner.with_moqt_scopes(scopes);
        self
    }

    #[cfg(feature = "moqt")]
    pub fn moqt_scope(mut self, scope: crate::claims::MoqtScope) -> Self {
        self.inner = self.inner.with_moqt_scope(scope);
        self
    }

    #[cfg(feature = "moqt")]
    pub fn moqt_reval(mut self, interval_seconds: f64) -> Self {
        self.inner = self.inner.with_moqt_reval(interval_seconds);
        self
    }

    pub fn build(self) -> CatToken {
        self.inner
    }
}

fn encode_protected_header(algorithm: &dyn CryptographicAlgorithm) -> Result<Vec<u8>, CatError> {
    let cwt = Cwt::new(algorithm.algorithm_id(), CatToken::new());
    let header = CwtHeader {
        alg: algorithm.algorithm_id(),
        kid: cwt.header.kid.clone(),
        typ: cwt.header.typ.clone(),
    };

    let mut header_map = std::collections::BTreeMap::new();
    header_map.insert(1i64, ciborium::Value::Integer(header.alg.into()));
    if let Some(ref kid) = header.kid {
        header_map.insert(4i64, ciborium::Value::Text(kid.clone()));
    }
    if let Some(ref typ) = header.typ {
        header_map.insert(16i64, ciborium::Value::Text(typ.clone()));
    }

    let cbor_map: Vec<(ciborium::Value, ciborium::Value)> = header_map
        .into_iter()
        .map(|(k, v)| (ciborium::Value::Integer(k.into()), v))
        .collect();

    let mut buffer = Vec::new();
    ciborium::ser::into_writer(&ciborium::Value::Map(cbor_map), &mut buffer)
        .map_err(|e| CatError::InvalidCbor(e.to_string()))?;
    Ok(buffer)
}

/// Encode a CatToken as COSE_Sign1 (tag 18) or COSE_Mac0 (tag 17) CBOR bytes
/// per RFC 8392 §7 and RFC 9052.
pub fn encode_token(
    token: &CatToken,
    algorithm: &dyn CryptographicAlgorithm,
) -> Result<Vec<u8>, CatError> {
    let cwt = Cwt::new(algorithm.algorithm_id(), token.clone());
    let header_cbor = encode_protected_header(algorithm)?;
    let payload_cbor = cwt.encode_payload()?;

    let signing_input =
        crate::crypto::create_signing_input(&header_cbor, &payload_cbor, algorithm.algorithm_id());
    let signature = algorithm.sign(&signing_input)?;

    let alg_id = algorithm.algorithm_id();
    let tag = if alg_id == crate::crypto::ALG_HMAC256_256 {
        COSE_TAG_MAC0
    } else {
        COSE_TAG_SIGN1
    };

    // COSE_Sign1 = [protected, unprotected, payload, signature]
    // COSE_Mac0  = [protected, unprotected, payload, tag]
    let cose_array = ciborium::Value::Array(vec![
        ciborium::Value::Bytes(header_cbor),
        ciborium::Value::Map(vec![]), // unprotected header (empty)
        ciborium::Value::Bytes(payload_cbor),
        ciborium::Value::Bytes(signature),
    ]);

    let tagged = ciborium::Value::Tag(tag, Box::new(cose_array));
    let mut buffer = Vec::new();
    ciborium::ser::into_writer(&tagged, &mut buffer)
        .map_err(|e| CatError::InvalidCbor(e.to_string()))?;

    Ok(buffer)
}

/// Encode a CatToken and return it as a base64url string for text transport.
pub fn encode_token_base64(
    token: &CatToken,
    algorithm: &dyn CryptographicAlgorithm,
) -> Result<String, CatError> {
    let bytes = encode_token(token, algorithm)?;
    Ok(URL_SAFE_NO_PAD.encode(&bytes))
}

/// Decode a CatToken from COSE_Sign1 (tag 18) or COSE_Mac0 (tag 17) CBOR bytes.
pub fn decode_token(
    cose_bytes: &[u8],
    algorithm: &dyn CryptographicAlgorithm,
) -> Result<CatToken, CatError> {
    let value: ciborium::Value =
        ciborium::de::from_reader(cose_bytes).map_err(|e| CatError::InvalidCbor(e.to_string()))?;

    let (expected_tag, arr) = match value {
        ciborium::Value::Tag(tag, inner) => {
            if tag != COSE_TAG_SIGN1 && tag != COSE_TAG_MAC0 {
                return Err(CatError::InvalidTokenFormat);
            }
            match *inner {
                ciborium::Value::Array(a) if a.len() == 4 => (tag, a),
                _ => return Err(CatError::InvalidTokenFormat),
            }
        }
        _ => return Err(CatError::InvalidTokenFormat),
    };

    let header_cbor = match &arr[0] {
        ciborium::Value::Bytes(b) => b.clone(),
        _ => return Err(CatError::InvalidTokenFormat),
    };
    // arr[1] is the unprotected header — we ignore it
    let payload_cbor = match &arr[2] {
        ciborium::Value::Bytes(b) => b.clone(),
        _ => return Err(CatError::InvalidTokenFormat),
    };
    let signature = match &arr[3] {
        ciborium::Value::Bytes(b) => b.clone(),
        _ => return Err(CatError::InvalidTokenFormat),
    };

    // Verify the COSE tag matches the algorithm type
    let alg_id = algorithm.algorithm_id();
    let correct_tag = if alg_id == crate::crypto::ALG_HMAC256_256 {
        COSE_TAG_MAC0
    } else {
        COSE_TAG_SIGN1
    };
    if expected_tag != correct_tag {
        return Err(CatError::InvalidTokenFormat);
    }

    let header_alg = extract_algorithm_from_header(&header_cbor)?;
    if header_alg != alg_id {
        return Err(CatError::AlgorithmMismatch {
            expected: alg_id,
            found: header_alg,
        });
    }

    let signing_input = crate::crypto::create_signing_input(&header_cbor, &payload_cbor, alg_id);

    if !algorithm.verify(&signing_input, &signature)? {
        return Err(CatError::SignatureVerificationFailed);
    }

    Cwt::decode_payload(&payload_cbor)
}

/// Decode a CatToken from a base64url-encoded COSE structure.
pub fn decode_token_base64(
    token_str: &str,
    algorithm: &dyn CryptographicAlgorithm,
) -> Result<CatToken, CatError> {
    let bytes = URL_SAFE_NO_PAD
        .decode(token_str)
        .map_err(|e| CatError::InvalidBase64(e.to_string()))?;
    decode_token(&bytes, algorithm)
}

fn extract_algorithm_from_header(header_cbor: &[u8]) -> Result<i64, CatError> {
    let value: ciborium::Value =
        ciborium::de::from_reader(header_cbor).map_err(|e| CatError::InvalidCbor(e.to_string()))?;

    let map = match value {
        ciborium::Value::Map(m) => m,
        _ => return Err(CatError::InvalidTokenFormat),
    };

    for (key, val) in map {
        if let ciborium::Value::Integer(k) = key {
            let k_i64: i64 = k.try_into().map_err(|_| CatError::InvalidTokenFormat)?;
            if k_i64 == 1 {
                if let ciborium::Value::Integer(alg) = val {
                    return alg.try_into().map_err(|_| CatError::InvalidTokenFormat);
                }
            }
        }
    }

    Err(CatError::MissingRequiredClaim("alg".to_string()))
}
