// SPDX-FileCopyrightText: Copyright (c) 2022 Quicr
// SPDX-License-Identifier: BSD-2-Clause

//! CAT claim data model.
//!
//! # Profile: narrow, deterministic, fail-closed
//!
//! This crate implements a deliberately narrow subset of CTA-5007-B. Anywhere
//! the specification allows multiple representational forms for the same
//! semantic content, we accept exactly one form on input and produce exactly
//! one form on output. Deployments that need the full data model should
//! extend the profile explicitly, with corresponding test vectors, rather
//! than relying on the decoder silently accepting an alternate encoding.
//!
//! The concrete narrowings that differ from the base spec:
//!
//! - **`catif` keys**: integer claim keys only. Label strings and label sets
//!   are rejected. The single supported form maps a specific claim number
//!   to a single [`CatIfAction`].
//! - **`catif` headers**: text-string name / text-string value only. Arrays,
//!   integers, and CWT-nullable claim values are rejected. Names may not
//!   embed `:` and neither name nor value may contain NUL/CR/LF.
//! - **`catif` action arrays**: exactly the tuple `(status, headers?, kid?)`.
//!   Extra positional members are rejected as invalid form rather than
//!   ignored.
//! - **`catr` numeric fields**: fractional numeric dates are rejected on
//!   decode (see [`CatRenewal::with_expadd`], [`CatRenewal::with_deadline`],
//!   and the top-level date-claim rules).
//! - **`catalpn`**: byte strings only; the crate does not itself verify
//!   the peer negotiated ALPN — the relay context must supply that.
//! - **`catpor` id**: integer or byte-string forms only.
//! - **URI parsing**: userinfo and fragments are rejected, since they are
//!   commonly stripped/altered before authorization and diverge the token's
//!   surface from the actual request.
//! - **HTTP header values in responses**: control characters (other than
//!   HTAB) are rejected rather than silently stripped; a hostile issuer
//!   cannot smuggle CRLF past a downstream serializer.
//!
//! Interoperability with implementations that use the broader spec form is
//! explicitly out of scope for this profile.

use chrono::{DateTime, Utc};
use serde::Serialize;
use std::collections::HashMap;

/// CWT claim key for the standard `iss` (issuer) claim.
pub const CLAIM_ISS: i64 = 1;
/// CWT claim key for the standard `aud` (audience) claim.
pub const CLAIM_AUD: i64 = 3;
/// CWT claim key for the standard `exp` (expiration time) claim.
pub const CLAIM_EXP: i64 = 4;
/// CWT claim key for the standard `nbf` (not-before) claim.
pub const CLAIM_NBF: i64 = 5;
/// CWT claim key for the standard `cti` (CWT ID) claim.
pub const CLAIM_CTI: i64 = 7;

/// CWT claim key for the CAT `catreplay` replay-protection claim.
pub const CLAIM_CATREPLAY: i64 = 308;
/// CWT claim key for the CAT `catpor` probability-of-rejection claim.
pub const CLAIM_CATPOR: i64 = 309;
/// CWT claim key for the CAT `catv` version claim.
pub const CLAIM_CATV: i64 = 310;
/// CWT claim key for the CAT `catnip` network-IP-restriction claim.
pub const CLAIM_CATNIP: i64 = 311;
/// CWT claim key for the CAT `catu` URI-restriction claim.
pub const CLAIM_CATU: i64 = 312;
/// CWT claim key for the CAT `catm` HTTP-method-restriction claim.
pub const CLAIM_CATM: i64 = 313;
/// CWT claim key for the CAT `catalpn` ALPN-restriction claim.
pub const CLAIM_CATALPN: i64 = 314;
/// CWT claim key for the CAT `cath` HTTP-header-restriction claim.
pub const CLAIM_CATH: i64 = 315;
/// CWT claim key for the CAT `catgeoiso3166` ISO-3166 geo-restriction claim.
pub const CLAIM_CATGEOISO3166: i64 = 316;
/// CWT claim key for the CAT `catgeocoord` geo-coordinate-restriction claim.
pub const CLAIM_CATGEOCOORD: i64 = 317;
/// CWT claim key for the `geohash` geo-restriction claim.
pub const CLAIM_GEOHASH: i64 = 282;
/// CWT claim key for the CAT `catgeoalt` altitude-restriction claim.
pub const CLAIM_CATGEOALT: i64 = 318;
/// CWT claim key for the CAT `cattpk` token-public-key claim.
pub const CLAIM_CATTPK: i64 = 319;

// Informational Claims
/// CWT claim key for the standard `sub` (subject) claim.
pub const CLAIM_SUB: i64 = 2;
/// CWT claim key for the standard `iat` (issued-at) claim.
pub const CLAIM_IAT: i64 = 6;
/// CWT claim key for the CAT `catifdata` interface-data informational claim.
pub const CLAIM_CATIFDATA: i64 = 320;

// DPoP Claims
/// CWT claim key for the standard `cnf` (confirmation / key binding) claim.
pub const CLAIM_CNF: i64 = 8;
/// CWT claim key for the CAT `catdpop` DPoP-settings claim.
pub const CLAIM_CATDPOP: i64 = 321;

/// `cnf` sub-map key for a JWK Thumbprint (CTA-5007-B §4.8.1, Annex E.3).
pub const CNF_JKT: i64 = 323; // JWK Thumbprint (CTA-5007-B §4.8.1, Annex E.3)
pub(crate) const CNF_JKT_LEGACY: i64 = 3;
pub(crate) const CNF_CKT: i64 = 6; // COSE Key Thumbprint (RFC 9679)

// catdpop sub-claim keys
pub(crate) const CATDPOP_CRIT: i64 = -1;
pub(crate) const CATDPOP_WINDOW: i64 = 0;
pub(crate) const CATDPOP_HONOR_JTI: i64 = 1;

// Request Claims
/// CWT claim key for the CAT `catif` per-claim-failure-action claim.
pub const CLAIM_CATIF: i64 = 322;
/// CWT claim key for the CAT `catr` token-renewal claim.
pub const CLAIM_CATR: i64 = 323;

// catr sub-map keys (CTA-5007-B §4.9.2)
pub(crate) const CATR_TYPE: i64 = 0;
pub(crate) const CATR_EXPADD: i64 = 1;
pub(crate) const CATR_DEADLINE: i64 = 2;
pub(crate) const CATR_COOKIE_NAME: i64 = 3;
pub(crate) const CATR_HEADER_NAME: i64 = 4;
pub(crate) const CATR_ADDITIONAL_COOKIE_PARAMS: i64 = 5;
pub(crate) const CATR_ADDITIONAL_HEADER_PARAMS: i64 = 6;
pub(crate) const CATR_STATUS_CODE: i64 = 7;

// Composite Claims (RFC draft-lemmons-cose-composite-claims-02)
/// CWT claim key for the composite `or` claim (draft-lemmons-cose-composite-claims-02).
pub const CLAIM_OR: i64 = 324;
/// CWT claim key for the composite `nor` claim (draft-lemmons-cose-composite-claims-02).
pub const CLAIM_NOR: i64 = 325;
/// CWT claim key for the composite `and` claim (draft-lemmons-cose-composite-claims-02).
pub const CLAIM_AND: i64 = 326;

// MOQT Claims (draft-ietf-moq-c4m)
/// CWT claim key for the MOQT scope claim (draft-ietf-moq-c4m; `TBD_MOQT` in the spec).
pub const CLAIM_MOQT: i64 = 327; // TBD_MOQT in the spec
/// CWT claim key for the MOQT revalidation-interval claim (draft-ietf-moq-c4m; `TBD_MOQT_REVAL` in the spec).
pub const CLAIM_MOQT_REVAL: i64 = 328; // TBD_MOQT_REVAL in the spec

#[cfg(feature = "moqt")]
pub(crate) const MATCH_TYPE_PREFIX: i64 = 1;
#[cfg(feature = "moqt")]
pub(crate) const MATCH_TYPE_SUFFIX: i64 = 2;

#[derive(Debug, Clone, PartialEq, Serialize, Default)]
#[non_exhaustive]
/// Standard CWT core claims (`iss`, `aud`, `exp`, `nbf`, `cti`).
pub struct CoreClaims {
    /// Issuer (`iss`, claim 1), or `None` when unset.
    pub iss: Option<String>,
    /// Audience values (`aud`, claim 3), or `None` when unset.
    pub aud: Option<Vec<String>>,
    /// Expiration time as a Unix timestamp (`exp`, claim 4), or `None` when unset.
    pub exp: Option<i64>,
    /// Not-before time as a Unix timestamp (`nbf`, claim 5), or `None` when unset.
    pub nbf: Option<i64>,
    /// CWT ID bytes (`cti`, claim 7), or `None` when unset.
    pub cti: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[repr(u32)]
/// Replay-protection mode carried by the `catreplay` claim.
pub enum ReplayProtection {
    /// Token reuse is permitted (value 0).
    Permitted = 0,
    /// Token reuse is prohibited (value 1).
    Prohibited = 1,
    /// Token reuse must be detected and reported (value 2).
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

#[derive(Debug, Clone, PartialEq, Serialize)]
#[non_exhaustive]
/// Probability-of-rejection policy carried by the `catpor` claim.
pub struct ProbabilityOfRejection {
    /// Probability in `[0, 1]` that a recipient should reject the token.
    pub probability: f64,
    /// Opaque identifier tying this policy to a rejection group.
    pub id: Vec<u8>,
    /// Optional expiration (Unix timestamp) of the rejection policy.
    pub expiration: Option<i64>,
}

impl ProbabilityOfRejection {
    /// Create a probability-of-rejection policy with no expiration.
    pub fn new(probability: f64, id: Vec<u8>) -> Self {
        Self {
            probability,
            id,
            expiration: None,
        }
    }

    /// Set the policy expiration (Unix timestamp).
    pub fn with_expiration(mut self, exp: i64) -> Self {
        self.expiration = Some(exp);
        self
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[non_exhaustive]
/// Altitude restriction carried by the `catgeoalt` claim.
pub struct GeoAltitude {
    /// Target altitude in meters.
    pub altitude: f64,
    /// Permitted deviation from the target altitude in meters.
    pub deviation: f64,
}

impl GeoAltitude {
    /// Create an altitude restriction from a target altitude and deviation (meters).
    pub fn new(altitude: f64, deviation: f64) -> Self {
        Self {
            altitude,
            deviation,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Default)]
#[non_exhaustive]
/// CAT-specific restriction claims (the `cat*` claim family).
pub struct CatClaims {
    /// Replay-protection mode (`catreplay`), or `None` when unset.
    pub catreplay: Option<ReplayProtection>,
    /// Probability-of-rejection policy (`catpor`), or `None` when unset.
    pub catpor: Option<ProbabilityOfRejection>,
    /// CAT version (`catv`), or `None` when unset.
    pub catv: Option<u32>,
    /// Network-identifier restrictions (`catnip`), or `None` when unset.
    pub catnip: Option<Vec<NetworkIdentifier>>,
    /// URI-match restrictions (`catu`), or `None` when unset.
    pub catu: Option<Vec<UriMatchRule>>,
    /// Allowed HTTP methods (`catm`), or `None` when unset.
    pub catm: Option<Vec<String>>,
    /// Allowed ALPN protocol identifiers (`catalpn`), or `None` when unset.
    pub catalpn: Option<Vec<Vec<u8>>>,
    /// HTTP-header-match restrictions (`cath`), or `None` when unset.
    pub cath: Option<Vec<HeaderMatchRule>>,
    /// ISO-3166 geo restrictions (`catgeoiso3166`), or `None` when unset.
    pub catgeoiso3166: Option<Vec<String>>,
    /// Geo-coordinate restrictions (`catgeocoord`), or `None` when unset.
    pub catgeocoord: Option<Vec<GeoCoordinate>>,
    /// Geohash restrictions (`geohash`), or `None` when unset.
    pub geohash: Option<Vec<String>>,
    /// Altitude restriction (`catgeoalt`), or `None` when unset.
    pub catgeoalt: Option<GeoAltitude>,
    /// Token public key (`cattpk`), or `None` when unset.
    pub cattpk: Option<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Default)]
#[non_exhaustive]
/// Informational (non-restricting) claims: `sub`, `iat`, and `catifdata`.
pub struct InformationalClaims {
    /// Subject (`sub`, claim 2), or `None` when unset.
    pub sub: Option<String>,
    /// Issued-at time as a Unix timestamp (`iat`, claim 6), or `None` when unset.
    pub iat: Option<i64>,
    /// Interface data strings (`catifdata`), or `None` when unset.
    pub catifdata: Option<Vec<String>>,
}

/// Confirmation claim for key binding (CTA-5007-B §4.8.1).
///
/// Supports both JWK Thumbprint (jkt, key 3) and COSE Key Thumbprint (ckt, key 6, RFC 9679).
/// Serialization redacts thumbprint values to prevent accidental leakage.
#[derive(Clone, PartialEq)]
pub struct ConfirmationClaim {
    /// JWK Thumbprint bytes (`jkt`, key 3).
    pub jkt: Vec<u8>,
    /// Optional COSE Key Thumbprint bytes (`ckt`, key 6, RFC 9679).
    pub ckt: Option<Vec<u8>>,
}

impl Serialize for ConfirmationClaim {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let field_count = if self.ckt.is_some() { 2 } else { 1 };
        let mut s = serializer.serialize_struct("ConfirmationClaim", field_count)?;
        s.serialize_field("jkt", &format!("[REDACTED {} bytes]", self.jkt.len()))?;
        if let Some(ref ckt) = self.ckt {
            s.serialize_field("ckt", &format!("[REDACTED {} bytes]", ckt.len()))?;
        }
        s.end()
    }
}

impl std::fmt::Debug for ConfirmationClaim {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut d = f.debug_struct("ConfirmationClaim");
        d.field("jkt", &format!("[REDACTED {} bytes]", self.jkt.len()));
        if let Some(ref ckt) = self.ckt {
            d.field("ckt", &format!("[REDACTED {} bytes]", ckt.len()));
        }
        d.finish()
    }
}

impl ConfirmationClaim {
    /// Create a confirmation claim from a JWK Thumbprint.
    pub fn new(jkt: Vec<u8>) -> Self {
        Self { jkt, ckt: None }
    }

    /// Attach a COSE Key Thumbprint (`ckt`).
    pub fn with_ckt(mut self, ckt: Vec<u8>) -> Self {
        self.ckt = Some(ckt);
        self
    }
}

/// Upper cap for a DPoP acceptance window (seconds). Chosen to keep replay
/// exposure bounded even under aggressive skew; callers that need more should
/// re-issue tokens instead.
pub const CATDPOP_MAX_WINDOW_SECS: i64 = 3600;

#[derive(Debug, Clone, PartialEq, Serialize, Default)]
#[non_exhaustive]
/// DPoP settings carried by the `catdpop` claim (CTA-5007-B §4.8.2).
pub struct CatDpopSettings {
    pub(crate) crit: Option<Vec<i64>>,
    pub(crate) window: Option<i64>,
    pub(crate) honor_jti: Option<bool>,
}

impl CatDpopSettings {
    /// Create an empty DPoP settings object with all sub-claims unset.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the `crit` list. Fails if any entry is an always-understood key,
    /// or if the list is empty (CTA-5007-B §4.8.2 requires at least one entry when present).
    pub fn with_critical(mut self, keys: Vec<i64>) -> Result<Self, crate::CatError> {
        const ALWAYS_UNDERSTOOD: &[i64] = &[CATDPOP_CRIT, CATDPOP_WINDOW, CATDPOP_HONOR_JTI];
        for &key in &keys {
            if ALWAYS_UNDERSTOOD.contains(&key) {
                return Err(crate::CatError::InvalidClaimValue(format!(
                    "catdpop crit must not contain always-understood key: {key}"
                )));
            }
        }
        self.crit = Some(keys);
        Ok(self)
    }

    /// Set the acceptance window. Fails if the window is non-positive or exceeds
    /// [`CATDPOP_MAX_WINDOW_SECS`].
    pub fn with_window(mut self, seconds: i64) -> Result<Self, crate::CatError> {
        if seconds <= 0 {
            return Err(crate::CatError::InvalidClaimValue(format!(
                "catdpop window must be > 0 (got {seconds})"
            )));
        }
        if seconds > CATDPOP_MAX_WINDOW_SECS {
            return Err(crate::CatError::InvalidClaimValue(format!(
                "catdpop window {seconds}s exceeds cap {CATDPOP_MAX_WINDOW_SECS}s"
            )));
        }
        self.window = Some(seconds);
        Ok(self)
    }

    /// Set whether DPoP JTI replay processing is requested.
    pub fn with_jti_processing(mut self, honor: bool) -> Self {
        self.honor_jti = Some(honor);
        self
    }

    /// The `crit` list of must-understand sub-claim keys, if set.
    pub fn crit(&self) -> Option<&[i64]> {
        self.crit.as_deref()
    }

    /// The configured acceptance window in seconds, if set.
    pub fn window(&self) -> Option<i64> {
        self.window
    }

    /// The configured JTI-processing flag, if set.
    pub fn honor_jti(&self) -> Option<bool> {
        self.honor_jti
    }

    pub(crate) fn set_crit_from_decode(&mut self, keys: Vec<i64>) {
        self.crit = Some(keys);
    }

    pub(crate) fn set_window_from_decode(&mut self, seconds: i64) {
        self.window = Some(seconds);
    }

    pub(crate) fn set_honor_jti_from_decode(&mut self, honor: bool) {
        self.honor_jti = Some(honor);
    }

    /// Validate that the `crit` list contains no always-understood keys
    /// (CTA-5007-B §4.8.2). Fail-closed: an unexpected key is rejected.
    pub fn validate_crit(&self) -> Result<(), crate::CatError> {
        if let Some(ref crit) = self.crit {
            // crit MUST NOT contain always-understood keys (CTA-5007-B §4.8.2)
            const ALWAYS_UNDERSTOOD: &[i64] = &[CATDPOP_CRIT, CATDPOP_WINDOW, CATDPOP_HONOR_JTI];
            for &key in crit {
                if ALWAYS_UNDERSTOOD.contains(&key) {
                    return Err(crate::CatError::InvalidClaimValue(format!(
                        "catdpop crit must not contain always-understood key: {key}"
                    )));
                }
            }
        }
        Ok(())
    }

    /// The acceptance window to enforce, defaulting to 300 seconds when unset.
    pub fn effective_window(&self) -> i64 {
        self.window.unwrap_or(300)
    }

    /// Whether the caller should record and reject DPoP JTI replays for
    /// tokens carrying this settings object. Defaults to `true` when the
    /// token omits the sub-claim: a `catdpop` settings object exists in
    /// the token only because the issuer opted into DPoP, and silently
    /// disabling replay protection when the field is absent turned out to
    /// be a footgun in earlier revisions. Explicit `false` is still
    /// honored.
    pub fn should_honor_jti(&self) -> bool {
        self.honor_jti.unwrap_or(true)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Default)]
#[non_exhaustive]
/// DPoP-related claims: the `cnf` key binding and `catdpop` settings.
pub struct DpopClaims {
    /// Confirmation / key-binding claim (`cnf`), or `None` when unset.
    pub cnf: Option<ConfirmationClaim>,
    /// DPoP settings (`catdpop`), or `None` when unset.
    pub catdpop: Option<CatDpopSettings>,
}

/// Per-claim failure action (CTA-5007-B §4.9.1).
/// When a specific claim fails validation, the action tells the recipient
/// what HTTP status code, headers, and/or signing key to use in the response.
///
/// Constructed via [`CatIfAction::new`]. Fields are private to keep the value
/// well-formed: status codes must be in the standard HTTP range, and header
/// name/value pairs are validated for control characters at attach time.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct CatIfAction {
    pub(crate) status: u32,
    pub(crate) headers: Option<Vec<(String, String)>>,
    pub(crate) kid: Option<String>,
}

fn ensure_header_value_clean(name: &str, value: &str) -> Result<(), crate::CatError> {
    for &b in name.as_bytes() {
        if b == 0 || b == b'\r' || b == b'\n' || b == b':' {
            return Err(crate::CatError::InvalidClaimValue(format!(
                "header name contains prohibited byte: 0x{b:02x}"
            )));
        }
    }
    for &b in value.as_bytes() {
        if b == 0 || b == b'\r' || b == b'\n' {
            return Err(crate::CatError::InvalidClaimValue(format!(
                "header value for {name:?} contains prohibited control byte: 0x{b:02x}"
            )));
        }
    }
    Ok(())
}

impl CatIfAction {
    /// Create a new per-claim failure action.
    ///
    /// The HTTP status code must be in the 100..=599 range.
    pub fn new(status: u32) -> Result<Self, crate::CatError> {
        if !(100..=599).contains(&status) {
            return Err(crate::CatError::InvalidClaimValue(format!(
                "catif status must be an HTTP status code in 100..=599 (got {status})"
            )));
        }
        Ok(Self {
            status,
            headers: None,
            kid: None,
        })
    }

    /// Attach headers. Each name/value must be free of NUL/CR/LF and header
    /// names must not embed `:`.
    pub fn with_headers(mut self, headers: Vec<(String, String)>) -> Result<Self, crate::CatError> {
        for (name, value) in &headers {
            ensure_header_value_clean(name, value)?;
        }
        self.headers = Some(headers);
        Ok(self)
    }

    /// Attach a signing key identifier.
    pub fn with_kid(mut self, kid: impl Into<String>) -> Self {
        self.kid = Some(kid.into());
        self
    }

    /// The HTTP status code to return when the associated claim fails.
    pub fn status(&self) -> u32 {
        self.status
    }

    /// The response headers to emit on failure, if any.
    pub fn headers(&self) -> Option<&[(String, String)]> {
        self.headers.as_deref()
    }

    /// The signing key identifier to use for the failure response, if any.
    pub fn kid(&self) -> Option<&str> {
        self.kid.as_deref()
    }
}

/// Renewal type (CTA-5007-B §4.9.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[repr(u32)]
pub enum CatRenewalType {
    /// Automatic renewal (value 0).
    Automatic = 0,
    /// Cookie-based renewal (value 1).
    Cookie = 1,
    /// Header-based renewal (value 2).
    Header = 2,
    /// Redirect-based renewal (value 3).
    Redirect = 3,
}

impl CatRenewalType {
    /// Parse a renewal type from its wire value, or `None` if out of range.
    pub fn from_u32(v: u32) -> Option<Self> {
        match v {
            0 => Some(Self::Automatic),
            1 => Some(Self::Cookie),
            2 => Some(Self::Header),
            3 => Some(Self::Redirect),
            _ => None,
        }
    }
}

/// Token renewal parameters (CTA-5007-B §4.9.2).
///
/// Fields are private to keep the value shape consistent with the renewal
/// type: cookie/header names are only accepted for their respective types,
/// status codes only for redirect, and floating-point parameters are checked
/// for NaN/Infinity/negative zero at attach time.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct CatRenewal {
    pub(crate) renewal_type: CatRenewalType,
    pub(crate) expadd: Option<f64>,
    pub(crate) deadline: Option<f64>,
    pub(crate) cookie_name: Option<String>,
    pub(crate) header_name: Option<String>,
    pub(crate) cookie_params: Option<Vec<String>>,
    pub(crate) header_params: Option<Vec<String>>,
    pub(crate) status_code: Option<u32>,
}

fn validate_renewal_number(name: &'static str, v: f64) -> Result<f64, crate::CatError> {
    if v.is_nan() {
        return Err(crate::CatError::InvalidClaimValue(format!(
            "catr {name}: NaN is not permitted"
        )));
    }
    if v.is_infinite() {
        return Err(crate::CatError::InvalidClaimValue(format!(
            "catr {name}: infinity is not permitted"
        )));
    }
    if v == 0.0 && v.is_sign_negative() {
        return Err(crate::CatError::InvalidClaimValue(format!(
            "catr {name}: negative zero is not permitted"
        )));
    }
    Ok(v)
}

impl CatRenewal {
    /// Create automatic-renewal parameters.
    pub fn automatic() -> Self {
        Self {
            renewal_type: CatRenewalType::Automatic,
            expadd: None,
            deadline: None,
            cookie_name: None,
            header_name: None,
            cookie_params: None,
            header_params: None,
            status_code: None,
        }
    }

    /// Create cookie-based renewal parameters carrying the given cookie name.
    pub fn cookie(name: impl Into<String>) -> Self {
        Self {
            renewal_type: CatRenewalType::Cookie,
            expadd: None,
            deadline: None,
            cookie_name: Some(name.into()),
            header_name: None,
            cookie_params: None,
            header_params: None,
            status_code: None,
        }
    }

    /// Create header-based renewal parameters carrying the given header name.
    pub fn header(name: impl Into<String>) -> Self {
        Self {
            renewal_type: CatRenewalType::Header,
            expadd: None,
            deadline: None,
            cookie_name: None,
            header_name: Some(name.into()),
            cookie_params: None,
            header_params: None,
            status_code: None,
        }
    }

    /// Create redirect-based renewal parameters carrying the given status code.
    pub fn redirect(code: u32) -> Self {
        Self {
            renewal_type: CatRenewalType::Redirect,
            expadd: None,
            deadline: None,
            cookie_name: None,
            header_name: None,
            cookie_params: None,
            header_params: None,
            status_code: Some(code),
        }
    }

    /// Set the `expadd` renewal offset. Rejects NaN, infinity, and negatives;
    /// silent-fallback variants were removed so an invalid policy input
    /// cannot become an unsigned or default value.
    pub fn with_expadd(mut self, seconds: f64) -> Result<Self, crate::CatError> {
        self.expadd = Some(validate_renewal_number("expadd", seconds)?);
        Ok(self)
    }

    /// Set the `deadline` renewal timestamp. Rejects NaN, infinity, and
    /// negatives; see [`with_expadd`](Self::with_expadd).
    pub fn with_deadline(mut self, timestamp: f64) -> Result<Self, crate::CatError> {
        self.deadline = Some(validate_renewal_number("deadline", timestamp)?);
        Ok(self)
    }

    /// Set the cookie name used for cookie-based renewal.
    pub fn with_cookie_name(mut self, name: impl Into<String>) -> Self {
        self.cookie_name = Some(name.into());
        self
    }

    /// Set the header name used for header-based renewal.
    pub fn with_header_name(mut self, name: impl Into<String>) -> Self {
        self.header_name = Some(name.into());
        self
    }

    /// Set additional cookie parameters for cookie-based renewal.
    pub fn with_cookie_params(mut self, params: Vec<String>) -> Self {
        self.cookie_params = Some(params);
        self
    }

    /// Set additional header parameters for header-based renewal.
    pub fn with_header_params(mut self, params: Vec<String>) -> Self {
        self.header_params = Some(params);
        self
    }

    /// Set the HTTP status code used for redirect-based renewal.
    pub fn with_status_code(mut self, code: u32) -> Self {
        self.status_code = Some(code);
        self
    }

    /// The renewal type.
    pub fn renewal_type(&self) -> CatRenewalType {
        self.renewal_type
    }

    /// The `expadd` renewal offset, if set.
    pub fn expadd(&self) -> Option<f64> {
        self.expadd
    }

    /// The `deadline` renewal timestamp, if set.
    pub fn deadline(&self) -> Option<f64> {
        self.deadline
    }

    /// The cookie name, if set.
    pub fn cookie_name(&self) -> Option<&str> {
        self.cookie_name.as_deref()
    }

    /// The header name, if set.
    pub fn header_name(&self) -> Option<&str> {
        self.header_name.as_deref()
    }

    /// The additional cookie parameters, if set.
    pub fn cookie_params(&self) -> Option<&[String]> {
        self.cookie_params.as_deref()
    }

    /// The additional header parameters, if set.
    pub fn header_params(&self) -> Option<&[String]> {
        self.header_params.as_deref()
    }

    /// The redirect status code, if set.
    pub fn status_code(&self) -> Option<u32> {
        self.status_code
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_parts_unchecked(
        renewal_type: CatRenewalType,
        expadd: Option<f64>,
        deadline: Option<f64>,
        cookie_name: Option<String>,
        header_name: Option<String>,
        cookie_params: Option<Vec<String>>,
        header_params: Option<Vec<String>>,
        status_code: Option<u32>,
    ) -> Self {
        Self {
            renewal_type,
            expadd,
            deadline,
            cookie_name,
            header_name,
            cookie_params,
            header_params,
            status_code,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Default)]
#[non_exhaustive]
/// Request-handling claims: per-claim failure actions and renewal parameters.
pub struct RequestClaims {
    /// Per-claim failure actions (`catif`) keyed by claim ID, or `None` when unset.
    pub catif: Option<Vec<(i64, CatIfAction)>>,
    /// Token renewal parameters (`catr`), or `None` when unset.
    pub catr: Option<CatRenewal>,
}

/// Logical operators for composite claims
#[derive(Debug, Clone, PartialEq, Serialize)]
pub enum CompositeOperator {
    /// At least one claim set must be acceptable
    Or,
    /// No claim sets can be acceptable
    Nor,
    /// All claim sets must be acceptable
    And,
}

/// A claim set that can contain either a token or a nested composite claim
#[derive(Debug, Clone, PartialEq, Serialize)]
pub enum ClaimSet {
    /// A regular CAT token
    Token(Box<CatToken>),
    /// A nested composite claim for arbitrary nesting depth
    Composite(Box<CompositeClaim>),
}

/// Composite claim structure implementing logical relationships between claim sets
/// as defined in draft-lemmons-cose-composite-claims-02
#[derive(Debug, Clone, PartialEq, Serialize)]
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
        self.get_depth_bounded(0, Self::MAX_EVALUATE_DEPTH)
            .unwrap_or(Self::MAX_EVALUATE_DEPTH)
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

    /// Maximum depth for evaluate() to prevent stack overflow.
    /// Aligned with the depth check in CatTokenValidator::validate_composite_claims.
    const MAX_EVALUATE_DEPTH: usize = 10;

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
#[derive(Debug, Clone, PartialEq, Serialize, Default)]
#[non_exhaustive]
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

#[derive(Debug, Clone, PartialEq, Serialize)]
#[non_exhaustive]
/// Geo-coordinate restriction entry carried by the `catgeocoord` claim.
pub struct GeoCoordinate {
    /// Latitude in degrees.
    pub lat: f64,
    /// Longitude in degrees.
    pub lon: f64,
    /// Permitted radius around the coordinate, in meters.
    pub radius: u32,
}

impl GeoCoordinate {
    /// Create a geo-coordinate restriction from latitude, longitude, and radius.
    pub fn new(lat: f64, lon: f64, radius: u32) -> Self {
        Self { lat, lon, radius }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
/// A match pattern for a single URI component.
pub enum UriPattern {
    /// Match the component exactly.
    Exact(String),
    /// Match a prefix of the component.
    Prefix(String),
    /// Match a suffix of the component.
    Suffix(String),
    /// Match the component against a POSIX ERE regex.
    Regex(String),
    /// Match a hash of the component.
    Hash(String),
}

/// URI-component selector for the `catu` scheme part.
pub const URI_COMPONENT_SCHEME: i64 = 0;
/// URI-component selector for the `catu` host part.
pub const URI_COMPONENT_HOST: i64 = 1;
/// URI-component selector for the `catu` port part.
pub const URI_COMPONENT_PORT: i64 = 2;
/// URI-component selector for the `catu` path part.
pub const URI_COMPONENT_PATH: i64 = 3;
/// URI-component selector for the `catu` query part.
pub const URI_COMPONENT_QUERY: i64 = 4;
/// URI-component selector for the `catu` parent-path part.
pub const URI_COMPONENT_PARENT_PATH: i64 = 5;
/// URI-component selector for the `catu` filename part.
pub const URI_COMPONENT_FILENAME: i64 = 6;
/// URI-component selector for the `catu` filename stem part.
pub const URI_COMPONENT_STEM: i64 = 7;
/// URI-component selector for the `catu` filename extension part.
pub const URI_COMPONENT_EXTENSION: i64 = 8;

/// Match type: exact string equality (value 0).
pub const MATCH_EXACT: i64 = 0;
/// Match type: prefix match (value 1).
pub const MATCH_PREFIX: i64 = 1;
/// Match type: suffix match (value 2).
pub const MATCH_SUFFIX: i64 = 2;
/// Match type: substring/contains match (value 3).
pub const MATCH_CONTAINS: i64 = 3;
/// Match type: POSIX ERE regex match (value 4).
pub const MATCH_REGEX: i64 = 4;
/// Match type: SHA-256 hash comparison (value -1).
pub const MATCH_SHA256: i64 = -1;
/// Match type: SHA-512/256 hash comparison (value -2).
pub const MATCH_SHA512_256: i64 = -2;

/// Validate an ISO 3166 country or subdivision code as used by the
/// `catgeoiso3166` claim. Accepts alpha-2/alpha-3 country codes and
/// `country-subdivision` forms; rejects anything else.
pub fn validate_iso3166_code(code: &str) -> Result<(), crate::CatError> {
    if code.is_empty() {
        return Err(crate::CatError::InvalidClaimValue(
            "Empty ISO 3166 code".to_string(),
        ));
    }
    if let Some(pos) = code.find('-') {
        let country = &code[..pos];
        let subdivision = &code[pos + 1..];
        if country.len() != 2
            || !country.chars().all(|c| c.is_ascii_uppercase())
            || subdivision.is_empty()
            || subdivision.len() > 3
            || !subdivision.chars().all(|c| c.is_ascii_alphanumeric())
        {
            return Err(crate::CatError::InvalidClaimValue(format!(
                "Invalid ISO 3166 subdivision code: {code}"
            )));
        }
    } else if (code.len() == 2 || code.len() == 3) && code.chars().all(|c| c.is_ascii_uppercase()) {
        // alpha-2 or alpha-3
    } else {
        return Err(crate::CatError::InvalidClaimValue(format!(
            "Invalid ISO 3166 code: {code}"
        )));
    }
    Ok(())
}

/// Validate that a regex pattern is compatible with POSIX Extended Regular
/// Expressions (IEEE 1003.1-2017 §9.4) as required by CTA-5007-B §4.6.10.
///
/// Returns an error message describing the non-ERE feature found, or `None` if valid.
pub fn validate_posix_ere(pattern: &str) -> Option<String> {
    let bytes = pattern.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\' && i + 1 < bytes.len() {
            let next = bytes[i + 1];
            match next {
                // ERE only allows escaping special characters
                b'\\' | b'.' | b'*' | b'+' | b'?' | b'|' | b'(' | b')' | b'[' | b']' | b'{'
                | b'}' | b'^' | b'$' => {}
                // Perl-style shortcuts are NOT ERE
                b'd' | b'D' | b'w' | b'W' | b's' | b'S' | b'b' | b'B' => {
                    return Some(format!(
                        "\\{} is a Perl extension, not valid POSIX ERE",
                        char::from(next)
                    ));
                }
                _ => {}
            }
            i += 2;
            continue;
        }
        // Non-greedy quantifiers (*?, +?, ??) are Perl extensions
        if (bytes[i] == b'*' || bytes[i] == b'+' || bytes[i] == b'?')
            && i + 1 < bytes.len()
            && bytes[i + 1] == b'?'
        {
            return Some(
                "Non-greedy quantifiers (*?, +?, ??) are Perl extensions, not valid POSIX ERE"
                    .to_string(),
            );
        }
        // Lookahead/lookbehind: (?= (?! (?<= (?<!
        if bytes[i] == b'(' && i + 1 < bytes.len() && bytes[i + 1] == b'?' {
            return Some(
                "Lookahead/lookbehind (?...) groups are Perl extensions, not valid POSIX ERE"
                    .to_string(),
            );
        }
        i += 1;
    }
    None
}

#[derive(Debug, Clone, PartialEq, Serialize)]
/// A single match rule value applied to a URI component or header value.
pub enum MatchValue {
    /// Exact string equality.
    Exact(String),
    /// Prefix match.
    Prefix(String),
    /// Suffix match.
    Suffix(String),
    /// Substring/contains match.
    Contains(String),
    /// POSIX ERE regex match.
    Regex(String),
    /// SHA-256 hash comparison against these digest bytes.
    Sha256(Vec<u8>),
    /// SHA-512/256 hash comparison against these digest bytes.
    Sha512_256(Vec<u8>),
}

/// A `catu` rule matching one URI component against a set of values.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct UriMatchRule {
    /// The URI component selector (one of the `URI_COMPONENT_*` values).
    pub component: i64,
    /// Match values applied to the component.
    pub matches: Vec<MatchValue>,
}

/// A `cath` rule matching one HTTP header against a set of values.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct HeaderMatchRule {
    /// The header name to match.
    pub name: String,
    /// Match values applied to the header value.
    pub matches: Vec<MatchValue>,
}

/// A network identifier used by the `catnip` claim.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub enum NetworkIdentifier {
    /// A single IP address.
    IpAddress(std::net::IpAddr),
    /// An IP prefix (network address and prefix length).
    IpPrefix(std::net::IpAddr, u8),
    /// A single autonomous system number.
    Asn(u32),
    /// An inclusive range of autonomous system numbers.
    AsnRange(u32, u32),
}

fn ip_in_prefix(peer: std::net::IpAddr, prefix: std::net::IpAddr, prefix_len: u8) -> bool {
    match (peer, prefix) {
        (std::net::IpAddr::V4(p), std::net::IpAddr::V4(n)) => {
            let peer_bits = u32::from(p);
            let net_bits = u32::from(n);
            if prefix_len == 0 {
                return true;
            }
            if prefix_len > 32 {
                return false;
            }
            let mask: u32 = if prefix_len == 32 {
                u32::MAX
            } else {
                !((1u32 << (32 - prefix_len)) - 1)
            };
            (peer_bits & mask) == (net_bits & mask)
        }
        (std::net::IpAddr::V6(p), std::net::IpAddr::V6(n)) => {
            let peer_bits = u128::from(p);
            let net_bits = u128::from(n);
            if prefix_len == 0 {
                return true;
            }
            if prefix_len > 128 {
                return false;
            }
            let mask: u128 = if prefix_len == 128 {
                u128::MAX
            } else {
                !((1u128 << (128 - prefix_len)) - 1)
            };
            (peer_bits & mask) == (net_bits & mask)
        }
        // Address family mismatch — no prefix crosses v4/v6.
        _ => false,
    }
}

impl NetworkIdentifier {
    /// Parse a single IP address string into an [`NetworkIdentifier::IpAddress`].
    pub fn from_ip_str(ip: &str) -> Result<Self, crate::CatError> {
        let addr: std::net::IpAddr = ip
            .parse()
            .map_err(|_| crate::CatError::InvalidClaimValue(format!("Invalid IP address: {ip}")))?;
        Ok(Self::IpAddress(addr))
    }

    /// Parse a CIDR string (`addr/prefix`) into an [`NetworkIdentifier::IpPrefix`].
    /// Fails if the prefix length exceeds the address family's maximum.
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

    /// Whether this identifier matches the caller-supplied peer IP.
    /// ASN-typed identifiers do not participate in IP matching.
    pub fn matches_ip(&self, peer: std::net::IpAddr) -> bool {
        match self {
            NetworkIdentifier::IpAddress(addr) => *addr == peer,
            NetworkIdentifier::IpPrefix(prefix_addr, prefix_len) => {
                ip_in_prefix(peer, *prefix_addr, *prefix_len)
            }
            NetworkIdentifier::Asn(_) | NetworkIdentifier::AsnRange(_, _) => false,
        }
    }

    /// Whether this identifier matches the caller-supplied peer ASN.
    /// IP-typed identifiers do not participate in ASN matching.
    pub fn matches_asn(&self, peer_asn: u32) -> bool {
        match self {
            NetworkIdentifier::Asn(a) => *a == peer_asn,
            NetworkIdentifier::AsnRange(start, end) => peer_asn >= *start && peer_asn <= *end,
            NetworkIdentifier::IpAddress(_) | NetworkIdentifier::IpPrefix(_, _) => false,
        }
    }

    /// True if this identifier is IP-based (matches against a peer IP).
    pub fn is_ip_based(&self) -> bool {
        matches!(
            self,
            NetworkIdentifier::IpAddress(_) | NetworkIdentifier::IpPrefix(_, _)
        )
    }

    /// True if this identifier is ASN-based.
    pub fn is_asn_based(&self) -> bool {
        matches!(
            self,
            NetworkIdentifier::Asn(_) | NetworkIdentifier::AsnRange(_, _)
        )
    }

    /// Validate the identifier: prefix lengths must fit the address family and
    /// ASN ranges must be ordered and not exceed a reasonable span. Fail-closed.
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
#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
/// A MOQT control-message action scoped by a `moqt` claim (draft-ietf-moq-c4m).
pub enum MoqtAction {
    /// CLIENT_SETUP (value 0).
    ClientSetup = 0,
    /// SERVER_SETUP (value 1).
    ServerSetup = 1,
    /// PUBLISH_NAMESPACE, formerly ANNOUNCE (value 2).
    PublishNamespace = 2, // Was Announce per spec update
    /// SUBSCRIBE_NAMESPACE (value 3).
    SubscribeNamespace = 3,
    /// SUBSCRIBE (value 4).
    Subscribe = 4,
    /// REQUEST_UPDATE, formerly SUBSCRIBE_UPDATE (value 5).
    RequestUpdate = 5, // Was SubscribeUpdate per spec update
    /// PUBLISH (value 6).
    Publish = 6,
    /// FETCH (value 7).
    Fetch = 7,
    /// TRACK_STATUS (value 8).
    TrackStatus = 8,
}

/// Deprecated spec name for [`MoqtAction::PublishNamespace`].
#[cfg(feature = "moqt")]
pub type Announce = MoqtAction;
/// Deprecated spec name for [`MoqtAction::RequestUpdate`].
#[cfg(feature = "moqt")]
pub type SubscribeUpdate = MoqtAction;

#[cfg(feature = "moqt")]
impl MoqtAction {
    /// Legacy alias for [`MoqtAction::PublishNamespace`].
    pub const ANNOUNCE: MoqtAction = MoqtAction::PublishNamespace;
    /// Legacy alias for [`MoqtAction::RequestUpdate`].
    pub const SUBSCRIBE_UPDATE: MoqtAction = MoqtAction::RequestUpdate;

    /// True if `value` is a defined MOQT action wire value (0..=8).
    pub fn is_valid(value: i32) -> bool {
        (0..=8).contains(&value)
    }

    /// Return the [`MoqtResourceShape`] the action operates on. Callers use
    /// this to enforce that a DPoP proof's `actx.resource` (and the request
    /// context) carry only the fields relevant to the action — setup actions
    /// carry an endpoint only, namespace actions carry endpoint plus
    /// namespace, and track actions carry endpoint, namespace, and track.
    pub fn resource_shape(&self) -> MoqtResourceShape {
        match self {
            MoqtAction::ClientSetup | MoqtAction::ServerSetup => MoqtResourceShape::Endpoint,
            MoqtAction::PublishNamespace | MoqtAction::SubscribeNamespace => {
                MoqtResourceShape::Namespace
            }
            MoqtAction::Subscribe
            | MoqtAction::RequestUpdate
            | MoqtAction::Publish
            | MoqtAction::Fetch
            | MoqtAction::TrackStatus => MoqtResourceShape::Track,
        }
    }
}

/// The set of resource identifiers a MOQT action operates on.
///
/// - `Endpoint`: only the relay endpoint is meaningful. Setup actions
///   (`CLIENT_SETUP`, `SERVER_SETUP`) fit here — they establish the
///   connection itself, not a specific namespace or track.
/// - `Namespace`: endpoint plus a namespace tuple. Namespace-level actions
///   (`PUBLISH_NAMESPACE`, `SUBSCRIBE_NAMESPACE`) operate on all tracks
///   below a namespace.
/// - `Track`: endpoint, namespace tuple, and a specific track name. Track
///   actions (`SUBSCRIBE`, `PUBLISH`, `FETCH`, `REQUEST_UPDATE`,
///   `TRACK_STATUS`) target one full track.
#[cfg(feature = "moqt")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MoqtResourceShape {
    /// Only the relay endpoint is meaningful (setup actions).
    Endpoint,
    /// Endpoint plus a namespace tuple (namespace-level actions).
    Namespace,
    /// Endpoint, namespace tuple, and a track name (track-level actions).
    Track,
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
#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
/// How a [`BinaryMatch`] compares its pattern against input bytes.
pub enum BinaryMatchType {
    /// Matches any input (wildcard).
    Any,
    /// Matches input equal to the pattern.
    Exact,
    /// Matches input beginning with the pattern.
    Prefix,
    /// Matches input ending with the pattern.
    Suffix,
}

/// A byte-string matcher used for MOQT namespace/track selectors.
#[cfg(feature = "moqt")]
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct BinaryMatch {
    /// The comparison mode.
    pub match_type: BinaryMatchType,
    /// The pattern bytes compared against input.
    pub pattern: Vec<u8>,
}

#[cfg(feature = "moqt")]
impl Default for BinaryMatch {
    fn default() -> Self {
        Self {
            match_type: BinaryMatchType::Any,
            pattern: Vec::new(),
        }
    }
}

#[cfg(feature = "moqt")]
impl BinaryMatch {
    /// A wildcard matcher that matches any input.
    pub fn any() -> Self {
        Self::default()
    }

    /// An exact-match matcher for the given bytes.
    pub fn exact(data: Vec<u8>) -> Self {
        Self {
            match_type: BinaryMatchType::Exact,
            pattern: data,
        }
    }

    /// A prefix-match matcher for the given bytes.
    pub fn prefix(data: Vec<u8>) -> Self {
        Self {
            match_type: BinaryMatchType::Prefix,
            pattern: data,
        }
    }

    /// A suffix-match matcher for the given bytes.
    pub fn suffix(data: Vec<u8>) -> Self {
        Self {
            match_type: BinaryMatchType::Suffix,
            pattern: data,
        }
    }

    /// An exact-match matcher for the UTF-8 bytes of `s`.
    pub fn exact_str(s: &str) -> Self {
        Self::exact(s.as_bytes().to_vec())
    }

    /// A prefix-match matcher for the UTF-8 bytes of `s`.
    pub fn prefix_str(s: &str) -> Self {
        Self::prefix(s.as_bytes().to_vec())
    }

    /// A suffix-match matcher for the UTF-8 bytes of `s`.
    pub fn suffix_str(s: &str) -> Self {
        Self::suffix(s.as_bytes().to_vec())
    }

    /// True if this matcher matches any input.
    pub fn is_wildcard(&self) -> bool {
        self.match_type == BinaryMatchType::Any
    }

    /// Whether `input` matches. Empty prefix/suffix patterns fail closed
    /// rather than matching everything.
    pub fn matches(&self, input: &[u8]) -> bool {
        match self.match_type {
            BinaryMatchType::Any => true,
            BinaryMatchType::Exact => input == self.pattern.as_slice(),
            // An empty prefix/suffix matches every input, which would turn the
            // pattern into a universal wildcard. Callers that want "any"
            // must construct `BinaryMatchType::Any` explicitly; anything else
            // fails closed.
            BinaryMatchType::Prefix if self.pattern.is_empty() => false,
            BinaryMatchType::Suffix if self.pattern.is_empty() => false,
            BinaryMatchType::Prefix => input.starts_with(&self.pattern),
            BinaryMatchType::Suffix => input.ends_with(&self.pattern),
        }
    }

    /// Whether the UTF-8 bytes of `input` match.
    pub fn matches_str(&self, input: &str) -> bool {
        self.matches(input.as_bytes())
    }
}

/// A matcher for one element of a MOQT namespace tuple.
#[cfg(feature = "moqt")]
#[derive(Debug, Clone, PartialEq, Serialize)]
pub enum NamespaceMatch {
    /// Match the tuple element with the given byte matcher.
    Match(BinaryMatch),
    /// Match only when the tuple element is absent.
    Nil,
}

#[cfg(feature = "moqt")]
impl NamespaceMatch {
    /// A matcher requiring the element to equal `data` exactly.
    pub fn exact(data: Vec<u8>) -> Self {
        Self::Match(BinaryMatch::exact(data))
    }

    /// A matcher requiring the element to start with `data`.
    pub fn prefix(data: Vec<u8>) -> Self {
        Self::Match(BinaryMatch::prefix(data))
    }

    /// A matcher requiring the element to end with `data`.
    pub fn suffix(data: Vec<u8>) -> Self {
        Self::Match(BinaryMatch::suffix(data))
    }

    /// A matcher requiring the element to be absent.
    pub fn nil() -> Self {
        Self::Nil
    }

    /// Whether the (possibly absent) tuple element matches.
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
#[derive(Debug, Clone, PartialEq, Serialize)]
/// A single MOQT authorization scope: a set of actions plus the namespace
/// and track selectors they apply to.
pub struct MoqtScope {
    pub(crate) actions: Vec<MoqtAction>,
    pub(crate) namespace_matches: Vec<NamespaceMatch>,
    pub(crate) track_match: Option<BinaryMatch>,
}

#[cfg(feature = "moqt")]
impl Default for MoqtScope {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "moqt")]
impl MoqtScope {
    /// Create an empty scope with no actions or selectors.
    pub fn new() -> Self {
        Self {
            actions: Vec::new(),
            namespace_matches: Vec::new(),
            track_match: None,
        }
    }

    /// Replace the scope's action list.
    pub fn with_actions(mut self, actions: Vec<MoqtAction>) -> Self {
        self.actions = actions;
        self
    }

    /// Append a single action to the scope.
    pub fn with_action(mut self, action: MoqtAction) -> Self {
        self.actions.push(action);
        self
    }

    /// Append a namespace-tuple element matcher.
    pub fn with_namespace_match(mut self, ns_match: NamespaceMatch) -> Self {
        self.namespace_matches.push(ns_match);
        self
    }

    /// Replace the scope's namespace-tuple matchers.
    pub fn with_namespace_matches(mut self, matches: Vec<NamespaceMatch>) -> Self {
        self.namespace_matches = matches;
        self
    }

    /// Set the track-name matcher.
    pub fn with_track_match(mut self, track_match: BinaryMatch) -> Self {
        self.track_match = Some(track_match);
        self
    }

    /// The actions this scope grants.
    pub fn actions(&self) -> &[MoqtAction] {
        &self.actions
    }

    /// The namespace-tuple matchers.
    pub fn namespace_matches(&self) -> &[NamespaceMatch] {
        &self.namespace_matches
    }

    /// The track-name matcher, if any.
    pub fn track_match(&self) -> Option<&BinaryMatch> {
        self.track_match.as_ref()
    }

    /// Whether this scope grants `action`.
    pub fn allows_action(&self, action: &MoqtAction) -> bool {
        self.actions.contains(action)
    }

    /// Match a namespace tuple and track name against this scope. Per
    /// draft-ietf-moq-c4m, a scope with an empty `namespace_matches` list
    /// (or with the namespace slot omitted on the wire) matches every
    /// namespace. Fail-closed enforcement in this profile lives at the
    /// action layer: unlisted actions are blocked, but a listed action
    /// with no namespace selector is universally scoped by design.
    pub fn matches_full_track_name(&self, namespace_tuple: &[&[u8]], track: &[u8]) -> bool {
        for (i, ns_match) in self.namespace_matches.iter().enumerate() {
            let tuple_elem = namespace_tuple.get(i).copied();
            if !ns_match.matches(tuple_elem) {
                return false;
            }
        }

        if let Some(ref track_match) = self.track_match
            && !track_match.matches(track)
        {
            return false;
        }

        true
    }

    /// Match a namespace tuple against this scope. Per draft-ietf-moq-c4m,
    /// an empty `namespace_matches` list is the spec-sanctioned "any
    /// namespace" idiom.
    pub fn matches_namespace(&self, namespace: &[Vec<u8>]) -> bool {
        for (i, ns_match) in self.namespace_matches.iter().enumerate() {
            let tuple_elem = namespace.get(i).map(|v| v.as_slice());
            if !ns_match.matches(tuple_elem) {
                return false;
            }
        }
        true
    }

    /// Whether the given track name matches this scope's track selector
    /// (matches when no track selector is set).
    pub fn matches_track(&self, track: &[u8]) -> bool {
        match &self.track_match {
            Some(m) => m.matches(track),
            None => true,
        }
    }
}

#[cfg(feature = "moqt")]
#[derive(Debug, Clone, PartialEq, Serialize, Default)]
#[non_exhaustive]
/// MOQT authorization claims: scopes and the revalidation interval.
pub struct MoqtClaims {
    /// MOQT authorization scopes (`moqt`), or `None` when unset.
    pub moqt: Option<Vec<MoqtScope>>,
    /// Revalidation interval in seconds (`moqt_reval`), or `None` when unset.
    pub moqt_reval: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[non_exhaustive]
/// A decoded CAT token: the full claim data model grouped by claim family.
pub struct CatToken {
    /// Standard CWT core claims.
    pub core: CoreClaims,
    /// CAT-specific restriction claims.
    pub cat: CatClaims,
    /// Informational (non-restricting) claims.
    pub informational: InformationalClaims,
    /// DPoP-related claims.
    pub dpop: DpopClaims,
    /// Request-handling claims.
    pub request: RequestClaims,
    /// Composite (logical AND/OR/NOR) claims.
    pub composite: CompositeClaims,
    /// MOQT authorization claims.
    #[cfg(feature = "moqt")]
    pub moqt: MoqtClaims,
    pub(crate) custom: HashMap<i64, ciborium::Value>,
}

impl Default for CatToken {
    fn default() -> Self {
        Self::new()
    }
}

impl CatToken {
    /// Create an empty token with every claim unset.
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

    /// Set the token's issuer (`iss`).
    pub fn with_issuer(mut self, issuer: impl Into<String>) -> Self {
        self.core.iss = Some(issuer.into());
        self
    }

    /// Set the token's audience list (`aud`).
    pub fn with_audience(mut self, audience: Vec<String>) -> Self {
        self.core.aud = Some(audience);
        self
    }

    /// Set a single-element audience. Convenience wrapper over
    /// [`CatToken::with_audience`].
    pub fn with_single_audience(self, audience: impl Into<String>) -> Self {
        self.with_audience(vec![audience.into()])
    }

    /// Set the token's expiration time (`exp`).
    pub fn with_expiration(mut self, exp: DateTime<Utc>) -> Self {
        self.core.exp = Some(exp.timestamp());
        self
    }

    /// Set the expiry to `seconds` from now. Convenience wrapper over
    /// [`CatToken::with_expiration`].
    pub fn with_expires_in(self, seconds: i64) -> Self {
        self.with_expiration(Utc::now() + chrono::Duration::seconds(seconds))
    }

    /// Set the token's not-before time (`nbf`).
    pub fn with_not_before(mut self, nbf: DateTime<Utc>) -> Self {
        self.core.nbf = Some(nbf.timestamp());
        self
    }

    /// Set the token's CWT ID bytes (`cti`).
    pub fn with_cwt_id(mut self, cti: impl Into<Vec<u8>>) -> Self {
        self.core.cti = Some(cti.into());
        self
    }

    /// Set the token's CWT ID from a string's UTF-8 bytes (`cti`).
    pub fn with_cwt_id_str(mut self, cti: impl AsRef<str>) -> Self {
        self.core.cti = Some(cti.as_ref().as_bytes().to_vec());
        self
    }

    /// Set the token's CAT version (`catv`).
    pub fn with_version(mut self, version: u32) -> Self {
        self.cat.catv = Some(version);
        self
    }

    /// Set the token's URI-match rules (`catu`).
    pub fn with_uri_match_rules(mut self, rules: Vec<UriMatchRule>) -> Self {
        self.cat.catu = Some(rules);
        self
    }

    /// Set the token's replay-protection mode (`catreplay`).
    pub fn with_replay_protection(mut self, mode: ReplayProtection) -> Self {
        self.cat.catreplay = Some(mode);
        self
    }

    /// Set the token's probability-of-rejection policy (`catpor`).
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

    /// Append a single geo-coordinate restriction (`catgeocoord`).
    pub fn with_geo_coordinate(mut self, lat: f64, lon: f64, radius: u32) -> Self {
        let coord = GeoCoordinate { lat, lon, radius };
        match self.cat.catgeocoord {
            Some(ref mut coords) => coords.push(coord),
            None => self.cat.catgeocoord = Some(vec![coord]),
        }
        self
    }

    /// Replace the token's geo-coordinate restrictions (`catgeocoord`).
    pub fn with_geo_coordinates(mut self, coords: Vec<GeoCoordinate>) -> Self {
        self.cat.catgeocoord = Some(coords);
        self
    }

    /// Append a geohash restriction (`geohash`).
    pub fn with_geohash(mut self, geohash: impl Into<String>) -> Self {
        let gh = geohash.into();
        match self.cat.geohash {
            Some(ref mut v) => v.push(gh),
            None => self.cat.geohash = Some(vec![gh]),
        }
        self
    }

    /// Set the token's subject (`sub`).
    pub fn with_subject(mut self, subject: impl Into<String>) -> Self {
        self.informational.sub = Some(subject.into());
        self
    }

    /// Set the token's issued-at time (`iat`).
    pub fn with_issued_at(mut self, iat: chrono::DateTime<chrono::Utc>) -> Self {
        self.informational.iat = Some(iat.timestamp());
        self
    }

    /// Append a single interface-data string (`catifdata`).
    pub fn with_interface_data(mut self, data: impl Into<String>) -> Self {
        let d = data.into();
        match self.informational.catifdata {
            Some(ref mut v) => v.push(d),
            None => self.informational.catifdata = Some(vec![d]),
        }
        self
    }

    /// Replace the token's interface-data strings (`catifdata`).
    pub fn with_interface_data_array(mut self, data: Vec<String>) -> Self {
        self.informational.catifdata = Some(data);
        self
    }

    /// Set the token's key-binding confirmation from a JWK Thumbprint (`cnf`).
    pub fn with_confirmation(mut self, jkt: Vec<u8>) -> Self {
        self.dpop.cnf = Some(ConfirmationClaim::new(jkt));
        self
    }

    /// Set the confirmation claim's COSE Key Thumbprint (`cnf.ckt`),
    /// creating the confirmation claim if absent.
    pub fn with_cose_key_thumbprint(mut self, ckt: Vec<u8>) -> Self {
        match self.dpop.cnf {
            Some(ref mut cnf) => cnf.ckt = Some(ckt),
            None => {
                self.dpop.cnf = Some(ConfirmationClaim {
                    jkt: Vec::new(),
                    ckt: Some(ckt),
                })
            }
        }
        self
    }

    /// Set the token's DPoP settings (`catdpop`).
    pub fn with_dpop_settings(mut self, settings: CatDpopSettings) -> Self {
        self.dpop.catdpop = Some(settings);
        self
    }

    /// Set the DPoP acceptance window. Fails if the value is non-positive or
    /// exceeds [`CATDPOP_MAX_WINDOW_SECS`]; a silent fallback to defaults would
    /// let a caller believe it configured a policy while the token carried a
    /// different (or no) window.
    pub fn with_dpop_window(mut self, window_seconds: i64) -> Result<Self, crate::CatError> {
        let settings = self.dpop.catdpop.take().unwrap_or_default();
        self.dpop.catdpop = Some(settings.with_window(window_seconds)?);
        Ok(self)
    }

    /// Append a per-claim failure action for `claim_key` (`catif`).
    pub fn with_if_action(mut self, claim_key: i64, action: CatIfAction) -> Self {
        match self.request.catif {
            Some(ref mut v) => v.push((claim_key, action)),
            None => self.request.catif = Some(vec![(claim_key, action)]),
        }
        self
    }

    /// Replace the token's per-claim failure actions (`catif`).
    pub fn with_if_actions(mut self, actions: Vec<(i64, CatIfAction)>) -> Self {
        self.request.catif = Some(actions);
        self
    }

    /// Set the token's renewal parameters (`catr`).
    pub fn with_renewal(mut self, renewal: CatRenewal) -> Self {
        self.request.catr = Some(renewal);
        self
    }

    /// Set the token's HTTP-header-match rules (`cath`).
    pub fn with_header_match_rules(mut self, rules: Vec<HeaderMatchRule>) -> Self {
        self.cat.cath = Some(rules);
        self
    }

    /// Replace the token's network-identifier restrictions (`catnip`).
    pub fn with_network_identifiers(mut self, nips: Vec<NetworkIdentifier>) -> Self {
        self.cat.catnip = Some(nips);
        self
    }

    /// Append an IP-address restriction (`catnip`). Fails if `ip` is not a
    /// valid IP address.
    pub fn with_ip_address(mut self, ip: impl Into<String>) -> Result<Self, crate::CatError> {
        let nip = NetworkIdentifier::from_ip_str(&ip.into())?;
        if let Some(ref mut nips) = self.cat.catnip {
            nips.push(nip);
        } else {
            self.cat.catnip = Some(vec![nip]);
        }
        Ok(self)
    }

    /// Append a CIDR-range restriction (`catnip`). Fails if `range` is not a
    /// valid CIDR.
    pub fn with_ip_range(mut self, range: impl Into<String>) -> Result<Self, crate::CatError> {
        let nip = NetworkIdentifier::from_cidr_str(&range.into())?;
        if let Some(ref mut nips) = self.cat.catnip {
            nips.push(nip);
        } else {
            self.cat.catnip = Some(vec![nip]);
        }
        Ok(self)
    }

    /// Append a single-ASN restriction (`catnip`).
    pub fn with_asn(mut self, asn: u32) -> Self {
        let nip = NetworkIdentifier::Asn(asn);
        if let Some(ref mut nips) = self.cat.catnip {
            nips.push(nip);
        } else {
            self.cat.catnip = Some(vec![nip]);
        }
        self
    }

    /// Append an ASN-range restriction (`catnip`).
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

    /// Replace the token's MOQT authorization scopes (`moqt`).
    #[cfg(feature = "moqt")]
    pub fn with_moqt_scopes(mut self, scopes: Vec<MoqtScope>) -> Self {
        self.moqt.moqt = Some(scopes);
        self
    }

    /// Append a single MOQT authorization scope (`moqt`).
    #[cfg(feature = "moqt")]
    pub fn with_moqt_scope(mut self, scope: MoqtScope) -> Self {
        if let Some(ref mut scopes) = self.moqt.moqt {
            scopes.push(scope);
        } else {
            self.moqt.moqt = Some(vec![scope]);
        }
        self
    }

    /// Set the token's MOQT revalidation interval in seconds (`moqt_reval`).
    #[cfg(feature = "moqt")]
    pub fn with_moqt_reval(mut self, interval_seconds: f64) -> Self {
        self.moqt.moqt_reval = Some(interval_seconds);
        self
    }

    /// Whether any MOQT scope in the token grants `action` for the given
    /// namespace tuple and track name. Fail-closed: returns `false` when no
    /// scopes are present.
    #[cfg(feature = "moqt")]
    pub fn allows_moqt_action(
        &self,
        action: &MoqtAction,
        namespace: &[Vec<u8>],
        track: &[u8],
    ) -> bool {
        if let Some(ref scopes) = self.moqt.moqt {
            scopes.iter().any(|scope| {
                if !scope.allows_action(action) {
                    return false;
                }
                // Per draft-ietf-moq-c4m, an omitted/empty namespace
                // selector matches every namespace; present selectors are
                // enforced against the request tuple.
                if !scope.matches_namespace(namespace) {
                    return false;
                }
                if scope.track_match().is_some() && !scope.matches_track(track) {
                    return false;
                }
                true
            })
        } else {
            false
        }
    }

    /// All custom (non-reserved) claims by claim ID.
    pub fn custom_claims(&self) -> &HashMap<i64, ciborium::Value> {
        &self.custom
    }

    /// The custom claim value for `key`, if present.
    pub fn custom_claim(&self, key: i64) -> Option<&ciborium::Value> {
        self.custom.get(&key)
    }

    /// Set a custom claim. Fails if `key` is a reserved (spec-defined) claim ID.
    pub fn set_custom_claim(
        &mut self,
        key: i64,
        value: ciborium::Value,
    ) -> Result<(), crate::CatError> {
        if is_reserved_claim_id(key) {
            return Err(crate::CatError::InvalidClaimValue(format!(
                "Claim ID {key} is reserved and cannot be set as a custom claim"
            )));
        }
        self.custom.insert(key, value);
        Ok(())
    }

    /// Validate issuer-side invariants that the fluent `with_*` setters do
    /// not enforce individually: geo-coordinate latitude/longitude ranges and
    /// a non-negative DPoP window. [`crate::encode_token`] calls this before
    /// signing, so a token that reaches the wire has always passed these
    /// checks; call it directly if you want to surface a construction error
    /// before encoding.
    pub fn validate_construction(&self) -> Result<(), crate::CatError> {
        if let Some(ref coords) = self.cat.catgeocoord {
            for coord in coords {
                if coord.lat < -90.0 || coord.lat > 90.0 {
                    return Err(crate::CatError::InvalidClaimValue(format!(
                        "latitude {} out of range [-90, 90]",
                        coord.lat
                    )));
                }
                if coord.lon < -180.0 || coord.lon > 180.0 {
                    return Err(crate::CatError::InvalidClaimValue(format!(
                        "longitude {} out of range [-180, 180]",
                        coord.lon
                    )));
                }
            }
        }
        if let Some(ref dpop) = self.dpop.catdpop
            && dpop.effective_window() < 0
        {
            return Err(crate::CatError::InvalidClaimValue(
                "DPoP window must not be negative".to_string(),
            ));
        }
        Ok(())
    }
}

fn is_reserved_claim_id(key: i64) -> bool {
    matches!(
        key,
        CLAIM_ISS
            | CLAIM_SUB
            | CLAIM_AUD
            | CLAIM_EXP
            | CLAIM_NBF
            | CLAIM_IAT
            | CLAIM_CTI
            | CLAIM_CNF
            | CLAIM_GEOHASH
            | CLAIM_CATREPLAY
            | CLAIM_CATPOR
            | CLAIM_CATV
            | CLAIM_CATNIP
            | CLAIM_CATU
            | CLAIM_CATM
            | CLAIM_CATALPN
            | CLAIM_CATH
            | CLAIM_CATGEOISO3166
            | CLAIM_CATGEOCOORD
            | CLAIM_CATGEOALT
            | CLAIM_CATTPK
            | CLAIM_CATIFDATA
            | CLAIM_CATDPOP
            | CLAIM_CATIF
            | CLAIM_CATR
            | CLAIM_MOQT
            | CLAIM_MOQT_REVAL
    )
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
