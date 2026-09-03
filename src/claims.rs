// SPDX-FileCopyrightText: Copyright (c) 2022 Quicr
// SPDX-License-Identifier: BSD-2-Clause

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

pub const CLAIM_ISS: i64 = 1;
pub const CLAIM_AUD: i64 = 3;
pub const CLAIM_EXP: i64 = 4;
pub const CLAIM_NBF: i64 = 5;
pub const CLAIM_CTI: i64 = 7;

pub const CLAIM_CATREPLAY: i64 = 308;
pub const CLAIM_CATPOR: i64 = 309;
pub const CLAIM_CATV: i64 = 310;
pub const CLAIM_CATNIP: i64 = 311;
pub const CLAIM_CATU: i64 = 312;
pub const CLAIM_CATM: i64 = 313;
pub const CLAIM_CATALPN: i64 = 314;
pub const CLAIM_CATH: i64 = 315;
pub const CLAIM_CATGEOISO3166: i64 = 316;
pub const CLAIM_CATGEOCOORD: i64 = 317;
pub const CLAIM_GEOHASH: i64 = 282;
pub const CLAIM_CATGEOALT: i64 = 318;
pub const CLAIM_CATTPK: i64 = 319;

// Informational Claims
pub const CLAIM_SUB: i64 = 2;
pub const CLAIM_IAT: i64 = 6;
pub const CLAIM_CATIFDATA: i64 = 320;

// DPoP Claims
pub const CLAIM_CNF: i64 = 8;
pub const CLAIM_CATDPOP: i64 = 321;

// DPoP sub-claim keys (within cnf map)
pub const CNF_JKT: i64 = 3; // JWK Thumbprint

// catdpop sub-claim keys
pub const CATDPOP_WINDOW: i64 = 0;
pub const CATDPOP_HONOR_JTI: i64 = 1;

// Request Claims
pub const CLAIM_CATIF: i64 = 322;
pub const CLAIM_CATR: i64 = 323;

// Composite Claims (RFC draft-lemmons-cose-composite-claims-01)
pub const CLAIM_OR: i64 = 324;
pub const CLAIM_NOR: i64 = 325;
pub const CLAIM_AND: i64 = 326;

// MOQT Claims (draft-ietf-moq-c4m)
pub const CLAIM_MOQT: i64 = 327; // TBD_MOQT in the spec
pub const CLAIM_MOQT_REVAL: i64 = 328; // TBD_MOQT_REVAL in the spec

// MOQT Binary match types per spec
pub const MATCH_TYPE_PREFIX: i64 = 1;
pub const MATCH_TYPE_SUFFIX: i64 = 2;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CoreClaims {
    pub iss: Option<String>,
    pub aud: Option<Vec<String>>,
    pub exp: Option<i64>,
    pub nbf: Option<i64>,
    pub cti: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u32)]
pub enum ReplayProtection {
    Permitted = 0,
    Prohibited = 1,
    ReuseDetection = 2,
}

impl TryFrom<u32> for ReplayProtection {
    type Error = crate::CatError;
    fn try_from(v: u32) -> Result<Self, Self::Error> {
        match v {
            0 => Ok(Self::Permitted),
            1 => Ok(Self::Prohibited),
            2 => Ok(Self::ReuseDetection),
            _ => Err(crate::CatError::InvalidClaimValue(format!(
                "Invalid catreplay value: {v}"
            ))),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProbabilityOfRejection {
    pub probability: f64,
    pub id: Vec<u8>,
    pub expiration: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GeoAltitude {
    pub altitude: f64,
    pub deviation: f64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CatClaims {
    pub catreplay: Option<ReplayProtection>,
    pub catpor: Option<ProbabilityOfRejection>,
    pub catv: Option<u32>,
    pub catnip: Option<Vec<NetworkIdentifier>>,
    pub catu: Option<Vec<UriMatchRule>>,
    pub catm: Option<Vec<String>>,
    pub catalpn: Option<Vec<String>>,
    pub cath: Option<Vec<HeaderMatchRule>>,
    pub catgeoiso3166: Option<Vec<String>>,
    pub catgeocoord: Option<GeoCoordinate>,
    pub geohash: Option<String>,
    pub catgeoalt: Option<GeoAltitude>,
    pub cattpk: Option<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct InformationalClaims {
    pub sub: Option<String>,
    pub iat: Option<i64>,
    pub catifdata: Option<String>,
}

/// Confirmation claim for DPoP key binding.
///
/// The `jkt` field contains a JWK Thumbprint (SHA-256 hash of the public key).
/// This is not sensitive data - it's derived from the public key and is safe to clone.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct ConfirmationClaim {
    pub jkt: Vec<u8>,
}

impl std::fmt::Debug for ConfirmationClaim {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConfirmationClaim")
            .field("jkt", &format!("[REDACTED {} bytes]", self.jkt.len()))
            .finish()
    }
}

impl ConfirmationClaim {
    pub fn new(jkt: Vec<u8>) -> Self {
        Self { jkt }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct CatDpopSettings {
    pub window: Option<i64>,
    pub honor_jti: Option<bool>,
}

impl CatDpopSettings {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_window(mut self, seconds: i64) -> Self {
        self.window = Some(seconds);
        self
    }

    pub fn with_jti_processing(mut self, honor: bool) -> Self {
        self.honor_jti = Some(honor);
        self
    }

    pub fn effective_window(&self) -> i64 {
        self.window.unwrap_or(300)
    }

    pub fn should_honor_jti(&self) -> bool {
        self.honor_jti.unwrap_or(true)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DpopClaims {
    pub cnf: Option<ConfirmationClaim>,
    pub catdpop: Option<CatDpopSettings>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RequestClaims {
    pub catif: Option<String>,
    pub catr: Option<String>,
}

/// Logical operators for composite claims
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum CompositeOperator {
    /// At least one claim set must be acceptable
    Or,
    /// No claim sets can be acceptable
    Nor,
    /// All claim sets must be acceptable
    And,
}

/// A claim set that can contain either a token or a nested composite claim
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ClaimSet {
    /// A regular CAT token
    Token(Box<CatToken>),
    /// A nested composite claim for arbitrary nesting depth
    Composite(Box<CompositeClaim>),
}

/// Composite claim structure implementing logical relationships between claim sets
/// as defined in draft-lemmons-cose-composite-claims-01
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CompositeClaim {
    /// The logical operator for this composite claim
    pub op: CompositeOperator,
    /// Array of claim sets to evaluate
    pub claims: Vec<ClaimSet>,
}

impl CompositeClaim {
    /// Create a new composite claim with the specified operator
    pub fn new(op: CompositeOperator) -> Self {
        Self {
            op,
            claims: Vec::new(),
        }
    }

    /// Add a token as a claim set
    pub fn add_token(&mut self, token: CatToken) {
        self.claims.push(ClaimSet::Token(Box::new(token)));
    }

    /// Add a nested composite claim
    pub fn add_composite(&mut self, composite: CompositeClaim) {
        self.claims.push(ClaimSet::Composite(Box::new(composite)));
    }

    /// Add a claim set directly
    pub fn add_claim_set(&mut self, claim_set: ClaimSet) {
        self.claims.push(claim_set);
    }

    /// Get the maximum nesting depth of this composite claim.
    /// Returns an error if depth exceeds the limit to prevent stack overflow.
    pub fn get_depth(&self) -> usize {
        self.get_depth_bounded(0, 100).unwrap_or(100)
    }

    /// Get depth with bounds checking to prevent stack overflow
    fn get_depth_bounded(
        &self,
        current_depth: usize,
        max_allowed: usize,
    ) -> Result<usize, crate::CatError> {
        if current_depth > max_allowed {
            return Err(crate::CatError::InvalidClaimValue(
                "Composite claim nesting depth exceeds maximum".to_string(),
            ));
        }

        let mut max_depth = 1;
        for claim_set in &self.claims {
            if let ClaimSet::Composite(composite) = claim_set {
                let child_depth = composite.get_depth_bounded(current_depth + 1, max_allowed)?;
                max_depth = max_depth.max(child_depth + 1);
            }
        }
        Ok(max_depth)
    }

    /// Check if depth exceeds limit without full traversal
    pub fn exceeds_depth_limit(&self, limit: usize) -> bool {
        self.check_depth_limit(0, limit)
    }

    fn check_depth_limit(&self, current: usize, limit: usize) -> bool {
        if current >= limit {
            return true;
        }
        for claim_set in &self.claims {
            if let ClaimSet::Composite(composite) = claim_set
                && composite.check_depth_limit(current + 1, limit)
            {
                return true;
            }
        }
        false
    }

    /// Maximum depth for evaluate() to prevent stack overflow
    const MAX_EVALUATE_DEPTH: usize = 100;

    /// Evaluate this composite claim against a validation context
    pub fn evaluate<V>(&self, validator: &V) -> bool
    where
        V: Fn(&CatToken) -> Result<(), Box<dyn std::error::Error>>,
    {
        self.evaluate_with_depth(validator, 0)
    }

    /// Evaluate with depth tracking to prevent stack overflow
    fn evaluate_with_depth<V>(&self, validator: &V, depth: usize) -> bool
    where
        V: Fn(&CatToken) -> Result<(), Box<dyn std::error::Error>>,
    {
        // Depth limit check to prevent stack overflow
        if depth > Self::MAX_EVALUATE_DEPTH {
            return false;
        }

        match self.op {
            CompositeOperator::Or => {
                // At least one claim set must be acceptable
                self.claims.iter().any(|claim_set| {
                    self.evaluate_claim_set_with_depth(claim_set, validator, depth)
                })
            }
            CompositeOperator::Nor => {
                // No claim sets can be acceptable
                !self.claims.iter().any(|claim_set| {
                    self.evaluate_claim_set_with_depth(claim_set, validator, depth)
                })
            }
            CompositeOperator::And => {
                // All claim sets must be acceptable
                self.claims.iter().all(|claim_set| {
                    self.evaluate_claim_set_with_depth(claim_set, validator, depth)
                })
            }
        }
    }

    fn evaluate_claim_set_with_depth<V>(
        &self,
        claim_set: &ClaimSet,
        validator: &V,
        depth: usize,
    ) -> bool
    where
        V: Fn(&CatToken) -> Result<(), Box<dyn std::error::Error>>,
    {
        match claim_set {
            ClaimSet::Token(token) => validator(token.as_ref()).is_ok(),
            ClaimSet::Composite(composite) => composite.evaluate_with_depth(validator, depth + 1),
        }
    }
}

/// Container for composite claims in a CAT token
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct CompositeClaims {
    /// OR composite claim
    pub or_claim: Option<CompositeClaim>,
    /// NOR composite claim
    pub nor_claim: Option<CompositeClaim>,
    /// AND composite claim
    pub and_claim: Option<CompositeClaim>,
}

impl CompositeClaims {
    /// Check if any composite claims are present
    pub fn has_composites(&self) -> bool {
        self.or_claim.is_some() || self.nor_claim.is_some() || self.and_claim.is_some()
    }

    /// Validate all composite claims
    pub fn validate_all<V>(&self, validator: &V) -> Result<(), Box<dyn std::error::Error>>
    where
        V: Fn(&CatToken) -> Result<(), Box<dyn std::error::Error>>,
    {
        if let Some(ref or_claim) = self.or_claim
            && !or_claim.evaluate(validator)
        {
            return Err("OR composite claim validation failed".into());
        }

        if let Some(ref nor_claim) = self.nor_claim
            && !nor_claim.evaluate(validator)
        {
            return Err("NOR composite claim validation failed".into());
        }

        if let Some(ref and_claim) = self.and_claim
            && !and_claim.evaluate(validator)
        {
            return Err("AND composite claim validation failed".into());
        }

        Ok(())
    }

    /// Get the maximum nesting depth across all composite claims
    pub fn get_max_depth(&self) -> usize {
        let mut max_depth = 0;

        if let Some(ref claim) = self.or_claim {
            max_depth = max_depth.max(claim.get_depth());
        }
        if let Some(ref claim) = self.nor_claim {
            max_depth = max_depth.max(claim.get_depth());
        }
        if let Some(ref claim) = self.and_claim {
            max_depth = max_depth.max(claim.get_depth());
        }

        max_depth
    }

    /// Check if any composite claim exceeds the depth limit
    pub fn exceeds_depth_limit(&self, limit: usize) -> bool {
        if let Some(ref claim) = self.or_claim
            && claim.exceeds_depth_limit(limit)
        {
            return true;
        }
        if let Some(ref claim) = self.nor_claim
            && claim.exceeds_depth_limit(limit)
        {
            return true;
        }
        if let Some(ref claim) = self.and_claim
            && claim.exceeds_depth_limit(limit)
        {
            return true;
        }
        false
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GeoCoordinate {
    pub lat: f64,
    pub lon: f64,
    pub accuracy: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum UriPattern {
    Exact(String),
    Prefix(String),
    Suffix(String),
    Regex(String),
    Hash(String),
}

pub const URI_COMPONENT_SCHEME: i64 = 0;
pub const URI_COMPONENT_HOST: i64 = 1;
pub const URI_COMPONENT_PORT: i64 = 2;
pub const URI_COMPONENT_PATH: i64 = 3;
pub const URI_COMPONENT_QUERY: i64 = 4;
pub const URI_COMPONENT_PARENT_PATH: i64 = 5;
pub const URI_COMPONENT_FILENAME: i64 = 6;
pub const URI_COMPONENT_STEM: i64 = 7;
pub const URI_COMPONENT_EXTENSION: i64 = 8;

pub const MATCH_EXACT: i64 = 0;
pub const MATCH_PREFIX: i64 = 1;
pub const MATCH_SUFFIX: i64 = 2;
pub const MATCH_CONTAINS: i64 = 3;
pub const MATCH_REGEX: i64 = 4;
pub const MATCH_SHA256: i64 = -1;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum MatchValue {
    Exact(String),
    Prefix(String),
    Suffix(String),
    Contains(String),
    Regex(String),
    Sha256(Vec<u8>),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UriMatchRule {
    pub component: i64,
    pub matches: Vec<MatchValue>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HeaderMatchRule {
    pub name: String,
    pub matches: Vec<MatchValue>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum NetworkIdentifier {
    IpAddress(std::net::IpAddr),
    IpPrefix(std::net::IpAddr, u8),
    Asn(u32),
    AsnRange(u32, u32),
}

impl NetworkIdentifier {
    pub fn from_ip_str(ip: &str) -> Result<Self, crate::CatError> {
        let addr: std::net::IpAddr = ip
            .parse()
            .map_err(|_| crate::CatError::InvalidClaimValue(format!("Invalid IP address: {ip}")))?;
        Ok(Self::IpAddress(addr))
    }

    pub fn from_cidr_str(cidr: &str) -> Result<Self, crate::CatError> {
        let parts: Vec<&str> = cidr.split('/').collect();
        if parts.len() != 2 {
            return Err(crate::CatError::InvalidClaimValue(format!(
                "Invalid CIDR: {cidr}"
            )));
        }
        let addr: std::net::IpAddr = parts[0].parse().map_err(|_| {
            crate::CatError::InvalidClaimValue(format!("Invalid IP in CIDR: {}", parts[0]))
        })?;
        let prefix_len: u8 = parts[1].parse().map_err(|_| {
            crate::CatError::InvalidClaimValue(format!("Invalid prefix length: {}", parts[1]))
        })?;
        let max_prefix = match addr {
            std::net::IpAddr::V4(_) => 32,
            std::net::IpAddr::V6(_) => 128,
        };
        if prefix_len > max_prefix {
            return Err(crate::CatError::InvalidClaimValue(format!(
                "Prefix length {prefix_len} exceeds max {max_prefix}"
            )));
        }
        Ok(Self::IpPrefix(addr, prefix_len))
    }

    pub fn validate(&self) -> Result<(), crate::CatError> {
        match self {
            NetworkIdentifier::IpAddress(_) => Ok(()),
            NetworkIdentifier::IpPrefix(addr, prefix_len) => {
                let max_prefix = match addr {
                    std::net::IpAddr::V4(_) => 32,
                    std::net::IpAddr::V6(_) => 128,
                };
                if *prefix_len > max_prefix {
                    return Err(crate::CatError::InvalidClaimValue(format!(
                        "Prefix length {} exceeds max {max_prefix}",
                        prefix_len
                    )));
                }
                Ok(())
            }
            NetworkIdentifier::Asn(_) => Ok(()),
            NetworkIdentifier::AsnRange(start, end) => {
                if start > end {
                    return Err(crate::CatError::InvalidClaimValue(format!(
                        "Invalid ASN range: start ({start}) > end ({end})"
                    )));
                }
                const MAX_REASONABLE_ASN_RANGE: u32 = 65536;
                let range_size = end.saturating_sub(*start);
                if range_size > MAX_REASONABLE_ASN_RANGE {
                    return Err(crate::CatError::InvalidClaimValue(format!(
                        "ASN range too broad: {range_size} ASNs (max {MAX_REASONABLE_ASN_RANGE})"
                    )));
                }
                Ok(())
            }
        }
    }
}

#[cfg(feature = "moqt")]
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum MoqtAction {
    ClientSetup = 0,
    ServerSetup = 1,
    PublishNamespace = 2, // Was Announce per spec update
    SubscribeNamespace = 3,
    Subscribe = 4,
    RequestUpdate = 5, // Was SubscribeUpdate per spec update
    Publish = 6,
    Fetch = 7,
    TrackStatus = 8,
}

#[cfg(feature = "moqt")]
pub type Announce = MoqtAction;
#[cfg(feature = "moqt")]
pub type SubscribeUpdate = MoqtAction;

#[cfg(feature = "moqt")]
impl MoqtAction {
    pub const ANNOUNCE: MoqtAction = MoqtAction::PublishNamespace;
    pub const SUBSCRIBE_UPDATE: MoqtAction = MoqtAction::RequestUpdate;

    pub fn action_name(&self) -> &'static str {
        match self {
            MoqtAction::ClientSetup => "CLIENT_SETUP",
            MoqtAction::ServerSetup => "SERVER_SETUP",
            MoqtAction::PublishNamespace => "PUBLISH_NAMESPACE",
            MoqtAction::SubscribeNamespace => "SUBSCRIBE_NAMESPACE",
            MoqtAction::Subscribe => "SUBSCRIBE",
            MoqtAction::RequestUpdate => "REQUEST_UPDATE",
            MoqtAction::Publish => "PUBLISH",
            MoqtAction::Fetch => "FETCH",
            MoqtAction::TrackStatus => "TRACK_STATUS",
        }
    }

    pub fn is_valid(value: i32) -> bool {
        (0..=8).contains(&value)
    }
}

#[cfg(feature = "moqt")]
impl TryFrom<i32> for MoqtAction {
    type Error = crate::CatError;

    fn try_from(value: i32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(MoqtAction::ClientSetup),
            1 => Ok(MoqtAction::ServerSetup),
            2 => Ok(MoqtAction::PublishNamespace),
            3 => Ok(MoqtAction::SubscribeNamespace),
            4 => Ok(MoqtAction::Subscribe),
            5 => Ok(MoqtAction::RequestUpdate),
            6 => Ok(MoqtAction::Publish),
            7 => Ok(MoqtAction::Fetch),
            8 => Ok(MoqtAction::TrackStatus),
            _ => Err(crate::CatError::InvalidClaimValue(format!(
                "Invalid MOQT action: {}",
                value
            ))),
        }
    }
}

#[cfg(feature = "moqt")]
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum BinaryMatchType {
    Exact = 0,
    Prefix = 1,
    Suffix = 2,
}

#[cfg(feature = "moqt")]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BinaryMatch {
    pub match_type: BinaryMatchType,
    pub pattern: Vec<u8>,
}

#[cfg(feature = "moqt")]
impl Default for BinaryMatch {
    fn default() -> Self {
        Self {
            match_type: BinaryMatchType::Exact,
            pattern: Vec::new(),
        }
    }
}

#[cfg(feature = "moqt")]
impl BinaryMatch {
    pub fn any() -> Self {
        Self::default()
    }

    pub fn exact(data: Vec<u8>) -> Self {
        Self {
            match_type: BinaryMatchType::Exact,
            pattern: data,
        }
    }

    pub fn prefix(data: Vec<u8>) -> Self {
        Self {
            match_type: BinaryMatchType::Prefix,
            pattern: data,
        }
    }

    pub fn suffix(data: Vec<u8>) -> Self {
        Self {
            match_type: BinaryMatchType::Suffix,
            pattern: data,
        }
    }

    pub fn exact_str(s: &str) -> Self {
        Self::exact(s.as_bytes().to_vec())
    }

    pub fn prefix_str(s: &str) -> Self {
        Self::prefix(s.as_bytes().to_vec())
    }

    pub fn suffix_str(s: &str) -> Self {
        Self::suffix(s.as_bytes().to_vec())
    }

    pub fn is_empty(&self) -> bool {
        self.pattern.is_empty()
    }

    pub fn matches(&self, input: &[u8]) -> bool {
        if self.pattern.is_empty() {
            return true;
        }

        match self.match_type {
            BinaryMatchType::Exact => input == self.pattern.as_slice(),
            BinaryMatchType::Prefix => input.starts_with(&self.pattern),
            BinaryMatchType::Suffix => input.ends_with(&self.pattern),
        }
    }

    pub fn matches_str(&self, input: &str) -> bool {
        self.matches(input.as_bytes())
    }
}

#[cfg(feature = "moqt")]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum NamespaceMatch {
    Match(BinaryMatch),
    Nil,
}

#[cfg(feature = "moqt")]
impl NamespaceMatch {
    pub fn exact(data: Vec<u8>) -> Self {
        Self::Match(BinaryMatch::exact(data))
    }

    pub fn prefix(data: Vec<u8>) -> Self {
        Self::Match(BinaryMatch::prefix(data))
    }

    pub fn suffix(data: Vec<u8>) -> Self {
        Self::Match(BinaryMatch::suffix(data))
    }

    pub fn nil() -> Self {
        Self::Nil
    }

    pub fn matches(&self, tuple_element: Option<&[u8]>) -> bool {
        match (self, tuple_element) {
            (NamespaceMatch::Nil, None) => true,
            (NamespaceMatch::Nil, Some(_)) => false,
            (NamespaceMatch::Match(_), None) => false,
            (NamespaceMatch::Match(m), Some(data)) => m.matches(data),
        }
    }
}

#[cfg(feature = "moqt")]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MoqtScope {
    pub actions: Vec<MoqtAction>,
    pub namespace_matches: Vec<NamespaceMatch>,
    pub track_match: Option<BinaryMatch>,
}

#[cfg(feature = "moqt")]
impl Default for MoqtScope {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "moqt")]
impl MoqtScope {
    pub fn new() -> Self {
        Self {
            actions: Vec::new(),
            namespace_matches: Vec::new(),
            track_match: None,
        }
    }

    pub fn with_actions(mut self, actions: Vec<MoqtAction>) -> Self {
        self.actions = actions;
        self
    }

    pub fn with_action(mut self, action: MoqtAction) -> Self {
        self.actions.push(action);
        self
    }

    pub fn with_namespace_match(mut self, ns_match: NamespaceMatch) -> Self {
        self.namespace_matches.push(ns_match);
        self
    }

    pub fn with_namespace_matches(mut self, matches: Vec<NamespaceMatch>) -> Self {
        self.namespace_matches = matches;
        self
    }

    pub fn with_track_match(mut self, track_match: BinaryMatch) -> Self {
        self.track_match = Some(track_match);
        self
    }

    pub fn allows_action(&self, action: &MoqtAction) -> bool {
        self.actions.contains(action)
    }

    pub fn matches_full_track_name(&self, namespace_tuple: &[&[u8]], track: &[u8]) -> bool {
        if !self.namespace_matches.is_empty() {
            for (i, ns_match) in self.namespace_matches.iter().enumerate() {
                let tuple_elem = namespace_tuple.get(i).copied();
                if !ns_match.matches(tuple_elem) {
                    return false;
                }
            }
        }

        if let Some(ref track_match) = self.track_match
            && !track_match.matches(track)
        {
            return false;
        }

        true
    }

    pub fn matches_namespace(&self, namespace: &[u8]) -> bool {
        if self.namespace_matches.is_empty() {
            return true;
        }
        if let Some(first) = self.namespace_matches.first() {
            first.matches(Some(namespace))
        } else {
            true
        }
    }

    pub fn matches_track(&self, track: &[u8]) -> bool {
        match &self.track_match {
            Some(m) => m.matches(track),
            None => true,
        }
    }
}

#[cfg(feature = "moqt")]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MoqtClaims {
    pub moqt: Option<Vec<MoqtScope>>,
    pub moqt_reval: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CatToken {
    pub core: CoreClaims,
    pub cat: CatClaims,
    pub informational: InformationalClaims,
    pub dpop: DpopClaims,
    pub request: RequestClaims,
    pub composite: CompositeClaims,
    #[cfg(feature = "moqt")]
    pub moqt: MoqtClaims,
    pub custom: HashMap<i64, ciborium::Value>,
}

impl Default for CatToken {
    fn default() -> Self {
        Self::new()
    }
}

impl CatToken {
    pub fn new() -> Self {
        Self {
            core: CoreClaims {
                iss: None,
                aud: None,
                exp: None,
                nbf: None,
                cti: None,
            },
            cat: CatClaims {
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
            },
            informational: InformationalClaims {
                sub: None,
                iat: None,
                catifdata: None,
            },
            dpop: DpopClaims {
                cnf: None,
                catdpop: None,
            },
            request: RequestClaims {
                catif: None,
                catr: None,
            },
            composite: CompositeClaims::default(),
            #[cfg(feature = "moqt")]
            moqt: MoqtClaims {
                moqt: None,
                moqt_reval: None,
            },
            custom: HashMap::new(),
        }
    }

    pub fn with_issuer(mut self, issuer: impl Into<String>) -> Self {
        self.core.iss = Some(issuer.into());
        self
    }

    pub fn with_audience(mut self, audience: Vec<String>) -> Self {
        self.core.aud = Some(audience);
        self
    }

    pub fn with_expiration(mut self, exp: DateTime<Utc>) -> Self {
        self.core.exp = Some(exp.timestamp());
        self
    }

    pub fn with_not_before(mut self, nbf: DateTime<Utc>) -> Self {
        self.core.nbf = Some(nbf.timestamp());
        self
    }

    pub fn with_cwt_id(mut self, cti: impl Into<Vec<u8>>) -> Self {
        self.core.cti = Some(cti.into());
        self
    }

    pub fn with_cwt_id_str(mut self, cti: impl AsRef<str>) -> Self {
        self.core.cti = Some(cti.as_ref().as_bytes().to_vec());
        self
    }

    pub fn with_version(mut self, version: u32) -> Self {
        self.cat.catv = Some(version);
        self
    }

    pub fn with_uri_match_rules(mut self, rules: Vec<UriMatchRule>) -> Self {
        self.cat.catu = Some(rules);
        self
    }

    pub fn with_replay_protection(mut self, mode: ReplayProtection) -> Self {
        self.cat.catreplay = Some(mode);
        self
    }

    pub fn with_probability_of_rejection(
        mut self,
        probability: f64,
        id: Vec<u8>,
        expiration: Option<i64>,
    ) -> Self {
        self.cat.catpor = Some(ProbabilityOfRejection {
            probability,
            id,
            expiration,
        });
        self
    }

    pub fn with_geo_coordinate(mut self, lat: f64, lon: f64, accuracy: Option<f64>) -> Self {
        self.cat.catgeocoord = Some(GeoCoordinate { lat, lon, accuracy });
        self
    }

    pub fn with_geohash(mut self, geohash: impl Into<String>) -> Self {
        self.cat.geohash = Some(geohash.into());
        self
    }

    pub fn with_subject(mut self, subject: impl Into<String>) -> Self {
        self.informational.sub = Some(subject.into());
        self
    }

    pub fn with_issued_at(mut self, iat: chrono::DateTime<chrono::Utc>) -> Self {
        self.informational.iat = Some(iat.timestamp());
        self
    }

    pub fn with_interface_data(mut self, data: impl Into<String>) -> Self {
        self.informational.catifdata = Some(data.into());
        self
    }

    pub fn with_confirmation(mut self, jkt: Vec<u8>) -> Self {
        self.dpop.cnf = Some(ConfirmationClaim::new(jkt));
        self
    }

    pub fn with_dpop_settings(mut self, settings: CatDpopSettings) -> Self {
        self.dpop.catdpop = Some(settings);
        self
    }

    pub fn with_dpop_window(mut self, window_seconds: i64) -> Self {
        let settings = self.dpop.catdpop.take().unwrap_or_default();
        self.dpop.catdpop = Some(settings.with_window(window_seconds));
        self
    }

    pub fn with_interface_claim(mut self, interface: impl Into<String>) -> Self {
        self.request.catif = Some(interface.into());
        self
    }

    pub fn with_request_claim(mut self, request: impl Into<String>) -> Self {
        self.request.catr = Some(request.into());
        self
    }

    pub fn with_header_match_rules(mut self, rules: Vec<HeaderMatchRule>) -> Self {
        self.cat.cath = Some(rules);
        self
    }

    pub fn with_network_identifiers(mut self, nips: Vec<NetworkIdentifier>) -> Self {
        self.cat.catnip = Some(nips);
        self
    }

    pub fn with_ip_address(mut self, ip: impl Into<String>) -> Self {
        let nip = NetworkIdentifier::from_ip_str(&ip.into()).expect("invalid IP address");
        if let Some(ref mut nips) = self.cat.catnip {
            nips.push(nip);
        } else {
            self.cat.catnip = Some(vec![nip]);
        }
        self
    }

    pub fn with_ip_range(mut self, range: impl Into<String>) -> Self {
        let nip = NetworkIdentifier::from_cidr_str(&range.into()).expect("invalid CIDR range");
        if let Some(ref mut nips) = self.cat.catnip {
            nips.push(nip);
        } else {
            self.cat.catnip = Some(vec![nip]);
        }
        self
    }

    pub fn with_asn(mut self, asn: u32) -> Self {
        let nip = NetworkIdentifier::Asn(asn);
        if let Some(ref mut nips) = self.cat.catnip {
            nips.push(nip);
        } else {
            self.cat.catnip = Some(vec![nip]);
        }
        self
    }

    pub fn with_asn_range(mut self, start: u32, end: u32) -> Self {
        let nip = NetworkIdentifier::AsnRange(start, end);
        if let Some(ref mut nips) = self.cat.catnip {
            nips.push(nip);
        } else {
            self.cat.catnip = Some(vec![nip]);
        }
        self
    }

    /// Add an OR composite claim
    pub fn with_or_composite(mut self, or_claim: CompositeClaim) -> Self {
        self.composite.or_claim = Some(or_claim);
        self
    }

    /// Add a NOR composite claim
    pub fn with_nor_composite(mut self, nor_claim: CompositeClaim) -> Self {
        self.composite.nor_claim = Some(nor_claim);
        self
    }

    /// Add an AND composite claim
    pub fn with_and_composite(mut self, and_claim: CompositeClaim) -> Self {
        self.composite.and_claim = Some(and_claim);
        self
    }

    #[cfg(feature = "moqt")]
    pub fn with_moqt_scopes(mut self, scopes: Vec<MoqtScope>) -> Self {
        self.moqt.moqt = Some(scopes);
        self
    }

    #[cfg(feature = "moqt")]
    pub fn with_moqt_scope(mut self, scope: MoqtScope) -> Self {
        if let Some(ref mut scopes) = self.moqt.moqt {
            scopes.push(scope);
        } else {
            self.moqt.moqt = Some(vec![scope]);
        }
        self
    }

    #[cfg(feature = "moqt")]
    pub fn with_moqt_reval(mut self, interval_seconds: f64) -> Self {
        self.moqt.moqt_reval = Some(interval_seconds);
        self
    }

    #[cfg(feature = "moqt")]
    pub fn allows_moqt_action(&self, action: &MoqtAction, namespace: &[u8], track: &[u8]) -> bool {
        if let Some(ref scopes) = self.moqt.moqt {
            scopes.iter().any(|scope| {
                scope.allows_action(action)
                    && scope.matches_namespace(namespace)
                    && scope.matches_track(track)
            })
        } else {
            false
        }
    }
}

/// Utility functions for creating composite claims
pub mod composite_utils {
    use super::*;

    /// Create an OR composite claim from a vector of tokens
    pub fn create_or_from_tokens(tokens: Vec<CatToken>) -> CompositeClaim {
        let mut composite = CompositeClaim::new(CompositeOperator::Or);
        for token in tokens {
            composite.add_token(token);
        }
        composite
    }

    /// Create a NOR composite claim from a vector of tokens
    pub fn create_nor_from_tokens(tokens: Vec<CatToken>) -> CompositeClaim {
        let mut composite = CompositeClaim::new(CompositeOperator::Nor);
        for token in tokens {
            composite.add_token(token);
        }
        composite
    }

    /// Create an AND composite claim from a vector of tokens
    pub fn create_and_from_tokens(tokens: Vec<CatToken>) -> CompositeClaim {
        let mut composite = CompositeClaim::new(CompositeOperator::And);
        for token in tokens {
            composite.add_token(token);
        }
        composite
    }

    /// Create an OR composite claim from a vector of claim sets
    pub fn create_or_from_claim_sets(claim_sets: Vec<ClaimSet>) -> CompositeClaim {
        let mut composite = CompositeClaim::new(CompositeOperator::Or);
        for claim_set in claim_sets {
            composite.add_claim_set(claim_set);
        }
        composite
    }

    /// Create a NOR composite claim from a vector of claim sets
    pub fn create_nor_from_claim_sets(claim_sets: Vec<ClaimSet>) -> CompositeClaim {
        let mut composite = CompositeClaim::new(CompositeOperator::Nor);
        for claim_set in claim_sets {
            composite.add_claim_set(claim_set);
        }
        composite
    }

    /// Create an AND composite claim from a vector of claim sets
    pub fn create_and_from_claim_sets(claim_sets: Vec<ClaimSet>) -> CompositeClaim {
        let mut composite = CompositeClaim::new(CompositeOperator::And);
        for claim_set in claim_sets {
            composite.add_claim_set(claim_set);
        }
        composite
    }
}
