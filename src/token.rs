// SPDX-FileCopyrightText: Copyright (c) 2022 Quicr
// SPDX-License-Identifier: BSD-2-Clause

use crate::cwt::{Cwt, CwtHeader, CwtLimits};
use crate::pipeline::{TokenHeader, TokenProvenance, VerifiedToken};
use crate::{CatError, CatToken, CryptographicAlgorithm, NetworkIdentifier};
use base64::{
    Engine as _,
    engine::general_purpose::{URL_SAFE, URL_SAFE_NO_PAD},
};
use chrono::{DateTime, Utc};
use lru::LruCache;
#[cfg(feature = "moqt")]
use std::cell::RefCell;
use std::collections::HashSet;
use std::num::NonZeroUsize;
use std::sync::Mutex;

const COSE_TAG_SIGN1: u64 = 18;
const COSE_TAG_MAC0: u64 = 17;
#[cfg(feature = "moqt")]
const REGEX_CACHE_SIZE: usize = 64;

/// Maximum accepted clock-skew tolerance (seconds). RFC 8392 and CTA-5007-B do
/// not specify a cap; we bound it defensively so operators cannot inadvertently
/// disable expiry enforcement by configuring an unbounded tolerance. 1 hour is
/// well above realistic NTP drift while keeping expired tokens meaningfully
/// rejected.
pub const MAX_CLOCK_SKEW_TOLERANCE_SECS: i64 = 3600;

#[cfg(feature = "moqt")]
thread_local! {
    static REGEX_CACHE: RefCell<LruCache<String, regex::Regex>> = RefCell::new(
        LruCache::new(NonZeroUsize::new(REGEX_CACHE_SIZE).unwrap())
    );
}

pub struct CatTokenValidator {
    expected_issuers: Option<HashSet<String>>,
    expected_audiences: Option<HashSet<String>>,
    exp_tolerance: i64,
    nbf_tolerance: i64,
    dangerously_allow_unencrypted_privacy_claims: bool,
}

impl Default for CatTokenValidator {
    fn default() -> Self {
        Self::new()
    }
}

fn check_tolerance(name: &str, seconds: i64) -> Result<(), CatError> {
    if seconds < 0 {
        return Err(CatError::InvalidClaimValue(format!(
            "{name} must not be negative"
        )));
    }
    if seconds > MAX_CLOCK_SKEW_TOLERANCE_SECS {
        return Err(CatError::InvalidClaimValue(format!(
            "{name} {seconds}s exceeds cap of {MAX_CLOCK_SKEW_TOLERANCE_SECS}s"
        )));
    }
    Ok(())
}

impl CatTokenValidator {
    pub fn new() -> Self {
        Self {
            expected_issuers: None,
            expected_audiences: None,
            exp_tolerance: 0,
            nbf_tolerance: 0,
            dangerously_allow_unencrypted_privacy_claims: false,
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

    pub fn with_clock_skew_tolerance(mut self, tolerance_seconds: i64) -> Result<Self, CatError> {
        check_tolerance("clock skew tolerance", tolerance_seconds)?;
        self.exp_tolerance = tolerance_seconds;
        self.nbf_tolerance = tolerance_seconds;
        Ok(self)
    }

    pub fn with_separate_tolerances(
        mut self,
        exp_tolerance: i64,
        nbf_tolerance: i64,
    ) -> Result<Self, CatError> {
        check_tolerance("exp tolerance", exp_tolerance)?;
        check_tolerance("nbf tolerance", nbf_tolerance)?;
        self.exp_tolerance = exp_tolerance;
        self.nbf_tolerance = nbf_tolerance;
        Ok(self)
    }

    pub fn dangerously_allow_unencrypted_privacy_claims(mut self) -> Self {
        self.dangerously_allow_unencrypted_privacy_claims = true;
        self
    }

    pub fn validate(&self, token: &CatToken) -> Result<(), CatError> {
        self.validate_with_provenance(token, TokenProvenance::Signed)
    }

    pub fn validate_with_provenance(
        &self,
        token: &CatToken,
        provenance: TokenProvenance,
    ) -> Result<(), CatError> {
        let now = Utc::now().timestamp();

        if let Some(exp) = token.core.exp {
            let effective_exp = exp.checked_add(self.exp_tolerance).ok_or_else(|| {
                CatError::InvalidClaimValue(
                    "exp + tolerance overflows i64 — reject rather than accept an unbounded window"
                        .to_string(),
                )
            })?;
            if now > effective_exp {
                return Err(CatError::TokenExpired);
            }
        }

        if let Some(nbf) = token.core.nbf {
            let effective_nbf = nbf.checked_sub(self.nbf_tolerance).ok_or_else(|| {
                CatError::InvalidClaimValue(
                    "nbf - tolerance underflows i64 — reject rather than accept an unbounded window"
                        .to_string(),
                )
            })?;
            if now < effective_nbf {
                return Err(CatError::TokenNotYetValid);
            }
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

        if let Some(catv) = token.cat.catv
            && catv != 1
        {
            return Err(CatError::InvalidClaimValue(format!(
                "Unsupported CAT version: {catv} (only version 1 is supported)"
            )));
        }

        self.validate_privacy_claims(token, provenance)?;
        self.validate_geographic_restrictions(token)?;
        self.validate_regex_ere(token)?;
        self.validate_composite_claims(token)?;

        Ok(())
    }

    fn validate_privacy_claims(
        &self,
        token: &CatToken,
        provenance: TokenProvenance,
    ) -> Result<(), CatError> {
        if self.dangerously_allow_unencrypted_privacy_claims
            || provenance == TokenProvenance::Encrypted
        {
            return Ok(());
        }
        if token.informational.sub.is_some() {
            return Err(CatError::UnencryptedPrivacyClaim("sub".to_string()));
        }
        if token.cat.catgeocoord.is_some() {
            return Err(CatError::UnencryptedPrivacyClaim("catgeocoord".to_string()));
        }
        if token.cat.geohash.is_some() {
            return Err(CatError::UnencryptedPrivacyClaim("geohash".to_string()));
        }
        if token.cat.catgeoalt.is_some() {
            return Err(CatError::UnencryptedPrivacyClaim("catgeoalt".to_string()));
        }
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

        if let Some(ref codes) = token.cat.catgeoiso3166 {
            for code in codes {
                crate::claims::validate_iso3166_code(code)?;
            }
        }

        if let Some(ref nips) = token.cat.catnip {
            for nip in nips {
                nip.validate()?;
            }
        }

        Ok(())
    }

    fn validate_regex_ere(&self, token: &CatToken) -> Result<(), CatError> {
        if let Some(ref rules) = token.cat.catu {
            for rule in rules {
                for mv in &rule.matches {
                    if let crate::claims::MatchValue::Regex(pattern) = mv
                        && let Some(err) = crate::claims::validate_posix_ere(pattern)
                    {
                        return Err(CatError::InvalidClaimValue(format!("catu regex: {err}")));
                    }
                }
            }
        }
        if let Some(ref rules) = token.cat.cath {
            for rule in rules {
                for mv in &rule.matches {
                    if let crate::claims::MatchValue::Regex(pattern) = mv
                        && let Some(err) = crate::claims::validate_posix_ere(pattern)
                    {
                        return Err(CatError::InvalidClaimValue(format!("cath regex: {err}")));
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

/// Check whether `method` is allowed by the token's `catm` claim.
/// Case-sensitive comparison per CTA-5007-B §4.6.11.
#[cfg(feature = "moqt")]
pub(crate) fn validate_method(token: &CatToken, method: &str) -> Result<(), CatError> {
    if let Some(ref methods) = token.cat.catm
        && !methods.iter().any(|m| m == method)
    {
        return Err(CatError::InvalidClaimValue(format!(
            "Method not allowed: {method}"
        )));
    }
    Ok(())
}

/// Apply a single `MatchValue` against an input string.
#[cfg(feature = "moqt")]
pub(crate) fn apply_match_value(mv: &crate::claims::MatchValue, input: &str) -> bool {
    use crate::claims::MatchValue;
    match mv {
        MatchValue::Exact(s) => input == s,
        MatchValue::Prefix(s) => input.starts_with(s.as_str()),
        MatchValue::Suffix(s) => input.ends_with(s.as_str()),
        MatchValue::Contains(s) => input.contains(s.as_str()),
        MatchValue::Regex(pattern) => REGEX_CACHE.with(|cache| {
            let mut cache = cache.borrow_mut();
            if let Some(re) = cache.get(pattern) {
                return re.is_match(input);
            }
            match regex::RegexBuilder::new(pattern)
                .size_limit(1 << 20)
                .dfa_size_limit(1 << 20)
                .build()
            {
                Ok(re) => {
                    let result = re.is_match(input);
                    cache.put(pattern.clone(), re);
                    result
                }
                Err(_) => false,
            }
        }),
        MatchValue::Sha256(expected) => {
            use sha2::{Digest, Sha256};
            let hash = Sha256::digest(input.as_bytes());
            hash.as_slice() == expected.as_slice()
        }
        MatchValue::Sha512_256(expected) => {
            use sha2::{Digest, Sha512_256};
            let hash = Sha512_256::digest(input.as_bytes());
            hash.as_slice() == expected.as_slice()
        }
    }
}

/// Validate every `cath` header rule against the request's full header set.
///
/// This is the only supported entry point for `cath` enforcement. It is
/// fail-closed: every rule in the token must be satisfied by at least one
/// matching header in `request_headers`, and a missing header is a failure.
///
/// Header name comparison is case-insensitive per CTA-5007-B §4.6.13. Values
/// are unfolded per RFC 9110 §5.2 before matching.
///
/// A previous single-header entry point that silently succeeded when the
/// caller failed to check a header has been removed: callers must pass the
/// complete header list so no rule can be bypassed.
#[cfg(feature = "moqt")]
pub(crate) fn validate_all_headers(
    token: &CatToken,
    request_headers: &[(&str, &str)],
) -> Result<(), CatError> {
    if let Some(ref rules) = token.cat.cath {
        for rule in rules {
            let matching_header = request_headers
                .iter()
                .find(|(name, _)| rule.name.eq_ignore_ascii_case(name));
            match matching_header {
                Some((_, value)) => {
                    let unfolded = unfold_header_value(value);
                    if !rule
                        .matches
                        .iter()
                        .any(|mv| apply_match_value(mv, &unfolded))
                    {
                        return Err(CatError::InvalidClaimValue(format!(
                            "Header '{}' value does not match any rule",
                            rule.name
                        )));
                    }
                }
                None => {
                    return Err(CatError::InvalidClaimValue(format!(
                        "Required header '{}' is missing from request",
                        rule.name
                    )));
                }
            }
        }
    }
    Ok(())
}

/// Unfold multi-line header values per RFC 9110 §5.2.
/// Joins comma-separated values and removes obs-fold (CRLF + whitespace).
#[cfg(feature = "moqt")]
pub(crate) fn unfold_header_value(value: &str) -> String {
    let mut result = String::with_capacity(value.len());
    let bytes = value.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if i + 2 < bytes.len()
            && bytes[i] == b'\r'
            && bytes[i + 1] == b'\n'
            && (bytes[i + 2] == b' ' || bytes[i + 2] == b'\t')
        {
            result.push(' ');
            i += 3;
            while i < bytes.len() && (bytes[i] == b' ' || bytes[i] == b'\t') {
                i += 1;
            }
        } else {
            result.push(bytes[i] as char);
            i += 1;
        }
    }
    result
}

/// Caller-side replay guard used to enforce the token's `catreplay` claim.
///
/// Implementations back this with whatever storage matches the deployment
/// (e.g. in-memory LRU, Redis, distributed key-value store). The
/// authorization pipeline calls `check_and_record` before granting the
/// request: the guard returns whether the token's cti has been seen
/// previously and atomically records the observation for future calls.
///
/// Called only when the token carries a `catreplay` claim that requires
/// per-cti bookkeeping (`Prohibited` or `ReuseDetection`).
pub trait ReplayGuard: Send + Sync {
    /// Returns true if the token's `cti` has been observed before. Records
    /// this observation atomically so a concurrent request sees the same
    /// answer. Callers pass the token's `cti` (which the encoder guarantees
    /// is non-empty when `catreplay` is `Prohibited` or `ReuseDetection`).
    fn check_and_record(&self, cti: &[u8]) -> Result<bool, CatError>;
}

/// Enforce a token's `catu` URI match rules against a request URI. Fail-closed:
/// every rule in the token must be satisfied by at least one match value on
/// the corresponding component of `request_uri`. A missing token claim is a
/// no-op; a malformed request URI or an unsatisfied rule is an error.
#[cfg(feature = "moqt")]
pub(crate) fn enforce_catu(token: &CatToken, request_uri: &str) -> Result<(), CatError> {
    let rules = match token.cat.catu.as_ref() {
        Some(r) => r,
        None => return Ok(()),
    };
    let components = crate::uri::decompose_uri(request_uri)?;
    for rule in rules {
        let target = components.component(rule.component);
        if !rule.matches.iter().any(|mv| apply_match_value(mv, target)) {
            return Err(CatError::InvalidClaimValue(format!(
                "catu: URI component {} does not match any allowed value",
                rule.component
            )));
        }
    }
    Ok(())
}

/// Enforce a token's `catnip` (network identifier) claim against the peer's
/// IP address and/or ASN. Fail-closed: if the token has any IP-typed
/// identifier, the caller must supply `peer_ip`; likewise for ASN-typed
/// identifiers and `peer_asn`. Approval requires at least one identifier
/// (across both families) to match.
#[cfg(feature = "moqt")]
pub(crate) fn enforce_catnip(
    token: &CatToken,
    peer_ip: Option<std::net::IpAddr>,
    peer_asn: Option<u32>,
) -> Result<(), CatError> {
    let nips = match token.cat.catnip.as_ref() {
        Some(n) => n,
        None => return Ok(()),
    };
    if nips.is_empty() {
        return Ok(());
    }

    let has_ip_rule = nips.iter().any(|n| n.is_ip_based());
    let has_asn_rule = nips.iter().any(|n| n.is_asn_based());

    if has_ip_rule && peer_ip.is_none() {
        return Err(CatError::MissingRelayContext {
            claim: "catnip",
            field: "peer_ip",
        });
    }
    if has_asn_rule && peer_asn.is_none() {
        return Err(CatError::MissingRelayContext {
            claim: "catnip",
            field: "peer_asn",
        });
    }

    let matched = nips.iter().any(|n| {
        if let Some(ip) = peer_ip
            && n.matches_ip(ip)
        {
            return true;
        }
        if let Some(asn) = peer_asn
            && n.matches_asn(asn)
        {
            return true;
        }
        false
    });
    if !matched {
        return Err(CatError::InvalidClaimValue(
            "catnip: peer network identifier does not match any token identifier".to_string(),
        ));
    }
    Ok(())
}

/// Block list for catpor probability-of-rejection enforcement.
/// Uses a bounded LRU cache to prevent unbounded memory growth.
pub struct CatPorBlockList {
    entries: Mutex<LruCache<Vec<u8>, Option<i64>>>,
}

const DEFAULT_POR_BLOCK_LIST_SIZE: usize = 100_000;

impl CatPorBlockList {
    pub fn new() -> Self {
        Self::with_capacity(DEFAULT_POR_BLOCK_LIST_SIZE)
    }

    pub fn with_capacity(capacity: usize) -> Self {
        let cap = NonZeroUsize::new(capacity.max(1)).expect("capacity is at least 1");
        Self {
            entries: Mutex::new(LruCache::new(cap)),
        }
    }

    pub fn is_blocked(&self, id: &[u8]) -> bool {
        let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(exp) = entries.get(id) {
            if let Some(exp_ts) = exp {
                Utc::now().timestamp() < *exp_ts
            } else {
                true
            }
        } else {
            false
        }
    }

    pub fn add(&self, id: Vec<u8>, expiration: Option<i64>) {
        let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        entries.put(id, expiration);
    }
}

impl Default for CatPorBlockList {
    fn default() -> Self {
        Self::new()
    }
}

/// Enforce the catpor (probability of rejection) claim.
/// Returns `Err(RejectedByProbability)` if the token should be rejected,
/// either by random chance or by block list.
#[cfg(feature = "moqt")]
pub(crate) fn enforce_catpor(
    token: &CatToken,
    block_list: &CatPorBlockList,
) -> Result<(), CatError> {
    if let Some(ref catpor) = token.cat.catpor {
        if block_list.is_blocked(&catpor.id) {
            return Err(CatError::RejectedByProbability);
        }

        let random: f64 = {
            use ring::rand::{SecureRandom, SystemRandom};
            let rng = SystemRandom::new();
            let mut buf = [0u8; 8];
            rng.fill(&mut buf)
                .map_err(|_| CatError::KeyOperationFailed("RNG failed".to_string()))?;
            let val = u64::from_le_bytes(buf);
            (val as f64) / (u64::MAX as f64)
        };

        if random < catpor.probability {
            block_list.add(catpor.id.clone(), catpor.expiration);
            return Err(CatError::RejectedByProbability);
        }
    }
    Ok(())
}

pub(crate) fn strip_token_from_uri(uri: &str, param_names: &[&str]) -> String {
    if let Some(qmark) = uri.find('?') {
        let base = &uri[..qmark];
        let query = &uri[qmark + 1..];
        let filtered: Vec<&str> = query
            .split('&')
            .filter(|param| {
                let key = param.split('=').next().unwrap_or("");
                let decoded_key = percent_decode(key);
                !param_names.contains(&decoded_key.as_str())
            })
            .collect();
        if filtered.is_empty() {
            base.to_string()
        } else {
            format!("{base}?{}", filtered.join("&"))
        }
    } else {
        uri.to_string()
    }
}

fn percent_decode(s: &str) -> String {
    let mut result = Vec::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && i + 2 < bytes.len()
            && let Ok(byte) =
                u8::from_str_radix(std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or(""), 16)
        {
            result.push(byte);
            i += 3;
            continue;
        }
        result.push(bytes[i]);
        i += 1;
    }
    String::from_utf8(result).unwrap_or_else(|_| s.to_string())
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

    pub fn geo_coordinate(mut self, lat: f64, lon: f64, radius: u32) -> Self {
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

    pub fn dpop_window(mut self, window_seconds: i64) -> Result<Self, CatError> {
        self.inner = self.inner.with_dpop_window(window_seconds)?;
        Ok(self)
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

    pub fn ip_address(mut self, ip: impl Into<String>) -> Result<Self, CatError> {
        self.inner = self.inner.with_ip_address(ip)?;
        Ok(self)
    }

    pub fn ip_range(mut self, range: impl Into<String>) -> Result<Self, CatError> {
        self.inner = self.inner.with_ip_range(range)?;
        Ok(self)
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

    pub fn build(self) -> Result<CatToken, CatError> {
        if let Some(ref coords) = self.inner.cat.catgeocoord {
            for coord in coords {
                if coord.lat < -90.0 || coord.lat > 90.0 {
                    return Err(CatError::InvalidClaimValue(format!(
                        "latitude {} out of range [-90, 90]",
                        coord.lat
                    )));
                }
                if coord.lon < -180.0 || coord.lon > 180.0 {
                    return Err(CatError::InvalidClaimValue(format!(
                        "longitude {} out of range [-180, 180]",
                        coord.lon
                    )));
                }
            }
        }
        if let Some(ref dpop) = self.inner.dpop.catdpop
            && dpop.effective_window() < 0
        {
            return Err(CatError::InvalidClaimValue(
                "DPoP window must not be negative".to_string(),
            ));
        }
        Ok(self.inner)
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
        crate::crypto::create_signing_input(&header_cbor, &payload_cbor, algorithm.algorithm_id())?;
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

const MAX_TOKEN_SIZE: usize = 16 * 1024; // 16KB — relay-appropriate default

/// Encode a CatToken into a COSE_Encrypt0 envelope wrapping a signed/MACed token.
pub fn encode_encrypted_token(
    token: &CatToken,
    signing_algorithm: &dyn CryptographicAlgorithm,
    encryption_key: &[u8],
    encryption_algorithm: &crate::encrypt::EncryptionAlgorithm,
) -> Result<Vec<u8>, CatError> {
    let signed_bytes = encode_token(token, signing_algorithm)?;
    crate::encrypt::cose_encrypt0(&signed_bytes, encryption_key, encryption_algorithm)
}

/// Which key material the [`Decoder`] verifies against.
enum DecoderKey<'a> {
    /// A single caller-supplied algorithm — chosen when the deployment
    /// binds every accepted token to one signing key.
    Algorithm(&'a dyn CryptographicAlgorithm),
    /// A [`KeyResolver`] that maps `(iss, kid, alg)` to a verifying
    /// algorithm at decode time — for issuer/key rotation.
    Resolver(&'a dyn crate::key_resolver::KeyResolver),
}

/// One-stop builder for every supported decode variant.
///
/// Instead of memorising the seven `decode_token_*` free functions, callers
/// pick a verifying key (via [`Decoder::with_algorithm`] or
/// [`Decoder::with_resolver`]) and layer on the optional pieces:
///
/// ```ignore
/// use cat_token::prelude::*;
///
/// // Simplest: one signing key, defaults everywhere else.
/// let verified = Decoder::with_algorithm(&key).decode(&cose_bytes)?;
///
/// // Rotation-friendly: resolver + admission policy + tighter CBOR limits.
/// let verified = Decoder::with_resolver(&resolver)
///     .admission(&policy)
///     .limits(CwtLimits::default())
///     .decode(&cose_bytes)?;
///
/// // Encrypted-envelope: layer the encryption key on top of either flavour.
/// let verified = Decoder::with_algorithm(&key)
///     .encryption_key(&enc_key)
///     .decode(&cose_bytes)?;
///
/// // Text transport: `decode_base64` accepts either padded or unpadded input.
/// let verified = Decoder::with_algorithm(&key).decode_base64(token_b64)?;
/// ```
///
/// The builder is cheap to construct (all references and one small
/// enum, no heap allocation) but does not implement `Copy` — each
/// method takes `self` by value and returns a new builder. Build once
/// per configuration and call `.decode()` for every request.
pub struct Decoder<'a> {
    key: DecoderKey<'a>,
    admission: Option<&'a crate::pipeline::AdmissionPolicy>,
    encryption_key: Option<&'a [u8]>,
    limits: CwtLimits,
}

impl<'a> Decoder<'a> {
    /// Start a decoder pinned to a single caller-supplied verifying
    /// algorithm. Use this when the relay accepts tokens signed by exactly
    /// one issuer key.
    pub fn with_algorithm(algorithm: &'a dyn CryptographicAlgorithm) -> Self {
        Self {
            key: DecoderKey::Algorithm(algorithm),
            admission: None,
            encryption_key: None,
            limits: CwtLimits::default(),
        }
    }

    /// Start a decoder backed by a [`KeyResolver`], which selects the
    /// verifying algorithm from the token's protected header and issuer at
    /// decode time. Use this for issuer / key rotation.
    pub fn with_resolver(resolver: &'a dyn crate::key_resolver::KeyResolver) -> Self {
        Self {
            key: DecoderKey::Resolver(resolver),
            admission: None,
            encryption_key: None,
            limits: CwtLimits::default(),
        }
    }

    /// Attach an [`AdmissionPolicy`] evaluated before signature verification.
    /// Only meaningful when the decoder was constructed with a resolver;
    /// on the algorithm path the policy is applied identically.
    pub fn admission(mut self, policy: &'a crate::pipeline::AdmissionPolicy) -> Self {
        self.admission = Some(policy);
        self
    }

    /// Attach an encryption key so the decoder accepts a COSE_Encrypt0
    /// envelope wrapping the signed/MACed token. Without this the decoder
    /// rejects encrypted envelopes.
    pub fn encryption_key(mut self, key: &'a [u8]) -> Self {
        self.encryption_key = Some(key);
        self
    }

    /// Override the CBOR decode budgets. Defaults to
    /// [`CwtLimits::default`], which reflects the CDN-scale profile the
    /// crate ships. Tighten for constrained clients; do not loosen unless
    /// the deployment has audited the exposure.
    pub fn limits(mut self, limits: CwtLimits) -> Self {
        self.limits = limits;
        self
    }

    /// Decode the supplied COSE-encoded bytes.
    pub fn decode(&self, cose_bytes: &[u8]) -> Result<VerifiedToken, CatError> {
        if let Some(enc_key) = self.encryption_key {
            // The inner signed token is bounded by MAX_TOKEN_SIZE; the CBOR
            // payload inside that signed token is further bounded by
            // limits.max_cbor_payload_size. Use the tighter of the two so a
            // hostile Encrypt0 cannot bypass the CBOR budget by hiding
            // oversize plaintext inside an outer envelope.
            let max_plaintext = MAX_TOKEN_SIZE.min(self.limits.max_cbor_payload_size());
            let inner_bytes = crate::encrypt::cose_decrypt0_with_max_plaintext(
                cose_bytes,
                enc_key,
                max_plaintext,
            )?;
            let verified = self.decode_signed(&inner_bytes)?;
            let header = verified.header().clone();
            // Preserve the *outer* Encrypt0 wire bytes so DPoP `ath` binds
            // to what the client sent — the inner signed COSE is an
            // implementation detail the peer never sees on the wire.
            return Ok(VerifiedToken::new(
                verified.into_unvalidated_token(),
                TokenHeader {
                    algorithm_id: header.algorithm_id,
                    kid: header.kid,
                },
                TokenProvenance::Encrypted,
                cose_bytes.to_vec(),
            ));
        }
        self.decode_signed(cose_bytes)
    }

    /// Decode a base64url-encoded (padded or unpadded) COSE token.
    pub fn decode_base64(&self, token_str: &str) -> Result<VerifiedToken, CatError> {
        let bytes = URL_SAFE_NO_PAD
            .decode(token_str)
            .or_else(|_| URL_SAFE.decode(token_str))
            .map_err(|e| CatError::InvalidBase64(e.to_string()))?;
        self.decode(&bytes)
    }

    fn decode_signed(&self, cose_bytes: &[u8]) -> Result<VerifiedToken, CatError> {
        let envelope = parse_cose_envelope(cose_bytes)?;

        let algorithm: &dyn CryptographicAlgorithm = match self.key {
            DecoderKey::Algorithm(alg) => {
                if let Some(policy) = self.admission {
                    let header = TokenHeader {
                        algorithm_id: envelope.header_alg,
                        kid: envelope.header_kid.clone(),
                    };
                    policy.check(cose_bytes, &header)?;
                }
                alg
            }
            DecoderKey::Resolver(resolver) => {
                let header = TokenHeader {
                    algorithm_id: envelope.header_alg,
                    kid: envelope.header_kid.clone(),
                };
                if let Some(policy) = self.admission {
                    policy.check(cose_bytes, &header)?;
                }

                // Peek `iss` from the still-unverified payload so the
                // resolver can enforce an (iss, kid, alg) exact match. The
                // peeked value is only trusted for key selection: if the
                // wrong key is selected, signature verification below
                // rejects the token, and if the right key is selected the
                // full decoder re-parses `iss` for downstream validation.
                let peeked_issuer = crate::cwt::peek_issuer(&envelope.payload_cbor)?;
                let hint = crate::key_resolver::KeyHint {
                    algorithm_id: envelope.header_alg,
                    kid: envelope.header_kid.clone(),
                    issuer: peeked_issuer,
                };
                resolver.resolve(&hint)?
            }
        };

        verify_and_decode(&envelope, algorithm, &self.limits, cose_bytes.to_vec())
    }
}

struct ParsedCoseEnvelope {
    tag: u64,
    header_cbor: Vec<u8>,
    payload_cbor: Vec<u8>,
    signature: Vec<u8>,
    header_alg: i64,
    header_kid: Option<Vec<u8>>,
}

fn parse_cose_envelope(cose_bytes: &[u8]) -> Result<ParsedCoseEnvelope, CatError> {
    if cose_bytes.len() > MAX_TOKEN_SIZE {
        return Err(CatError::InvalidTokenFormat);
    }

    let mut cursor = std::io::Cursor::new(cose_bytes);
    let value: ciborium::Value =
        ciborium::de::from_reader(&mut cursor).map_err(|e| CatError::InvalidCbor(e.to_string()))?;
    if (cursor.position() as usize) < cose_bytes.len() {
        return Err(CatError::InvalidCbor(format!(
            "Trailing bytes after COSE envelope: {} unconsumed bytes",
            cose_bytes.len() - cursor.position() as usize
        )));
    }

    let (tag, arr) = match value {
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

    match &arr[1] {
        ciborium::Value::Map(m) if m.is_empty() => {}
        ciborium::Value::Bytes(b) if b.is_empty() => {}
        _ => {
            return Err(CatError::InvalidTokenFormat);
        }
    }

    let payload_cbor = match &arr[2] {
        ciborium::Value::Bytes(b) => b.clone(),
        _ => return Err(CatError::InvalidTokenFormat),
    };
    let signature = match &arr[3] {
        ciborium::Value::Bytes(b) => b.clone(),
        _ => return Err(CatError::InvalidTokenFormat),
    };

    let (header_alg, header_kid) = extract_header_info(&header_cbor)?;

    Ok(ParsedCoseEnvelope {
        tag,
        header_cbor,
        payload_cbor,
        signature,
        header_alg,
        header_kid,
    })
}

fn verify_and_decode(
    envelope: &ParsedCoseEnvelope,
    algorithm: &dyn CryptographicAlgorithm,
    limits: &CwtLimits,
    serialized: Vec<u8>,
) -> Result<VerifiedToken, CatError> {
    let alg_id = algorithm.algorithm_id();
    let correct_tag = if alg_id == crate::crypto::ALG_HMAC256_256 {
        COSE_TAG_MAC0
    } else {
        COSE_TAG_SIGN1
    };
    if envelope.tag != correct_tag {
        return Err(CatError::InvalidTokenFormat);
    }

    if envelope.header_alg != alg_id {
        return Err(CatError::AlgorithmMismatch {
            expected: alg_id,
            found: envelope.header_alg,
        });
    }

    let signing_input =
        crate::crypto::create_signing_input(&envelope.header_cbor, &envelope.payload_cbor, alg_id)?;
    algorithm.verify(&signing_input, &envelope.signature)?;

    let token = Cwt::decode_payload_with_limits(&envelope.payload_cbor, limits)?;
    let header = TokenHeader {
        algorithm_id: envelope.header_alg,
        kid: envelope.header_kid.clone(),
    };
    Ok(VerifiedToken::new(
        token,
        header,
        TokenProvenance::Signed,
        serialized,
    ))
}

fn extract_header_info(header_cbor: &[u8]) -> Result<(i64, Option<Vec<u8>>), CatError> {
    let value: ciborium::Value =
        ciborium::de::from_reader(header_cbor).map_err(|e| CatError::InvalidCbor(e.to_string()))?;

    let map = match value {
        ciborium::Value::Map(m) => m,
        _ => return Err(CatError::InvalidTokenFormat),
    };

    let mut found_alg: Option<i64> = None;
    let mut found_kid: Option<Vec<u8>> = None;
    for (key, val) in &map {
        if let ciborium::Value::Integer(k) = key {
            let k_i64: i64 = (*k).try_into().map_err(|_| CatError::InvalidTokenFormat)?;
            match k_i64 {
                1 => {
                    if found_alg.is_some() {
                        return Err(CatError::InvalidCbor(
                            "Duplicate alg in protected header".to_string(),
                        ));
                    }
                    if let ciborium::Value::Integer(alg) = val {
                        found_alg = Some(
                            (*alg)
                                .try_into()
                                .map_err(|_| CatError::InvalidTokenFormat)?,
                        );
                    } else {
                        return Err(CatError::InvalidClaimValue(
                            "alg must be an integer".to_string(),
                        ));
                    }
                }
                4 => match val {
                    ciborium::Value::Bytes(b) => found_kid = Some(b.clone()),
                    ciborium::Value::Text(s) => found_kid = Some(s.as_bytes().to_vec()),
                    _ => {}
                },
                _ => {}
            }
        }
    }

    let alg = found_alg.ok_or_else(|| CatError::MissingRequiredClaim("alg".to_string()))?;
    Ok((alg, found_kid))
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- catu token stripping (§4.6.10) ---
    // These live outside the moqt-gated sub-module because
    // `strip_token_from_uri` is used from the non-moqt `response.rs`.

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
}

#[cfg(all(test, feature = "moqt"))]
mod moqt_helper_tests {
    use super::*;
    use crate::claims;

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
        assert!(validate_all_headers(&token, &[("content-type", "text/html")]).is_ok());
        assert!(validate_all_headers(&token, &[("CONTENT-TYPE", "text/html")]).is_ok());
    }

    #[test]
    fn test_cath_value_mismatch() {
        let mut token = CatToken::new();
        token.cat.cath = Some(vec![claims::HeaderMatchRule {
            name: "Content-Type".to_string(),
            matches: vec![claims::MatchValue::Exact("text/html".to_string())],
        }]);
        assert!(validate_all_headers(&token, &[("Content-Type", "application/json")]).is_err());
    }

    #[test]
    fn test_cath_prefix_match() {
        let mut token = CatToken::new();
        token.cat.cath = Some(vec![claims::HeaderMatchRule {
            name: "Authorization".to_string(),
            matches: vec![claims::MatchValue::Prefix("Bearer ".to_string())],
        }]);
        assert!(validate_all_headers(&token, &[("authorization", "Bearer abc123")]).is_ok());
        assert!(validate_all_headers(&token, &[("authorization", "Basic abc123")]).is_err());
    }

    #[test]
    fn test_cath_absent_allows_all() {
        let token = CatToken::new();
        assert!(validate_all_headers(&token, &[("Any-Header", "any-value")]).is_ok());
    }

    #[test]
    fn test_cath_missing_required_header_rejected() {
        let mut token = CatToken::new();
        token.cat.cath = Some(vec![claims::HeaderMatchRule {
            name: "Content-Type".to_string(),
            matches: vec![claims::MatchValue::Exact("text/html".to_string())],
        }]);
        assert!(validate_all_headers(&token, &[("X-Other", "value")]).is_err());
        assert!(validate_all_headers(&token, &[]).is_err());
    }

    #[test]
    fn test_cath_sf_normalized_matching() {
        use crate::structured_header::normalize_sf_value;
        let mut token = CatToken::new();
        let normalized = normalize_sf_value("gzip, deflate, br").unwrap();
        token.cat.cath = Some(vec![claims::HeaderMatchRule {
            name: "Accept-Encoding".to_string(),
            matches: vec![claims::MatchValue::Exact(normalized)],
        }]);

        let input = normalize_sf_value("gzip,  deflate,   br").unwrap();
        assert!(validate_all_headers(&token, &[("accept-encoding", &input)]).is_ok());
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

    // --- catpor enforcement (§4.6.7) ---

    #[test]
    fn test_catpor_probability_1_always_rejected() {
        let token = CatTokenBuilder::new()
            .probability_of_rejection(1.0, vec![1, 2, 3], None)
            .build()
            .unwrap();
        let block_list = CatPorBlockList::new();
        assert!(enforce_catpor(&token, &block_list).is_err());
    }

    #[test]
    fn test_catpor_probability_0_never_rejected() {
        let token = CatTokenBuilder::new()
            .probability_of_rejection(0.0, vec![1, 2, 3], None)
            .build()
            .unwrap();
        let block_list = CatPorBlockList::new();
        for _ in 0..100 {
            assert!(enforce_catpor(&token, &block_list).is_ok());
        }
    }

    #[test]
    fn test_catpor_block_list_persists() {
        let block_list = CatPorBlockList::new();
        block_list.add(vec![1, 2, 3], None);

        let token = CatTokenBuilder::new()
            .probability_of_rejection(0.0, vec![1, 2, 3], None)
            .build()
            .unwrap();

        assert!(enforce_catpor(&token, &block_list).is_err());
    }

    #[test]
    fn test_catpor_block_list_expiration() {
        let block_list = CatPorBlockList::new();
        block_list.add(vec![1, 2, 3], Some(0));

        let token = CatTokenBuilder::new()
            .probability_of_rejection(0.0, vec![1, 2, 3], None)
            .build()
            .unwrap();

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
}
