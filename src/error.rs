// SPDX-FileCopyrightText: Copyright (c) 2022 Quicr
// SPDX-License-Identifier: BSD-2-Clause

//! Error surface for the crate.
//!
//! Every error the authorize pipeline can emit is one of the variants
//! below. The variants partition failures into three intent-explicit
//! categories:
//!
//! - **Malformed input** (the peer or issuer sent bytes that don't parse
//!   or don't respect the profile): [`CatError::InvalidCbor`],
//!   [`CatError::MalformedClaim`], [`CatError::InvalidTokenFormat`],
//!   [`CatError::UnsupportedAlgorithm`], [`CatError::InvalidBase64`].
//!   Metric: `cat_error_malformed_total{claim="..."}`.
//! - **Enforcement failure** (input is well-formed but the request does
//!   not satisfy the token's assertions):
//!   [`CatError::ClaimEnforcementFailed`],
//!   [`CatError::ReplayAttackDetected`], [`CatError::TokenExpired`],
//!   [`CatError::InvalidAudience`], [`CatError::InvalidIssuer`],
//!   [`CatError::SignatureVerificationFailed`],
//!   [`CatError::MoqtActionNotAuthorized`],
//!   [`CatError::DpopValidationFailed`], [`CatError::InvalidDpopBinding`].
//!   Metric: `cat_error_denied_total{claim="..."}`.
//! - **Wiring / policy bug** (integrator misconfiguration):
//!   [`CatError::MissingRelayContext`], [`CatError::ConfigurationRefused`],
//!   [`CatError::MissingRequiredClaim`], [`CatError::BackendUnavailable`].
//!   Metric: `cat_error_operator_total{claim="..."}`.
//!
//! ## String escaping in error messages
//!
//! Any attacker-controlled byte string (peer issuer, request URI, DPoP
//! action name, MOQT scope value) that appears inside an error's
//! `Display` output is wrapped in [`SafeDisplay`], which escapes CR/LF,
//! NUL, other C0/C1 control codes, and Unicode bidi/format controls
//! (U+202A..U+202E, U+2066..U+2069, U+2028, U+2029, U+FEFF). This
//! prevents log-injection where an attacker embeds `\r\n` in `iss` to
//! forge audit lines. Bounded to [`SAFE_DISPLAY_MAX_LEN`] Unicode
//! scalar values; longer inputs are truncated with `…`.

use std::fmt;
use thiserror::Error;

/// Maximum length (in Unicode scalar values) of an attacker-controlled
/// string embedded in an error `Display`. Longer inputs are truncated
/// with `…`. Cap chosen to comfortably fit the longest legitimate CAT
/// issuer / URI while preventing an attacker from bloating operator log
/// lines.
pub const SAFE_DISPLAY_MAX_LEN: usize = 256;

/// Wrap an attacker-controlled string for safe embedding in error
/// messages and log lines. `Display` escapes control characters,
/// Unicode bidi/format codepoints, and truncates at
/// [`SAFE_DISPLAY_MAX_LEN`]. See the [module docs](crate::error) for
/// rationale.
pub struct SafeDisplay<'a>(pub &'a str);

impl fmt::Display for SafeDisplay<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut count = 0usize;
        for c in self.0.chars() {
            if count >= SAFE_DISPLAY_MAX_LEN {
                f.write_str("…")?;
                return Ok(());
            }
            count += 1;
            match c {
                '\r' | '\n' | '\t' | '\0' | '\x08' | '\x0b' | '\x0c' | '\x7f' => {
                    write!(f, "\\x{:02x}", c as u32)?
                }
                c if (c as u32) < 0x20 || (0x80..=0x9f).contains(&(c as u32)) => {
                    write!(f, "\\u{{{:04x}}}", c as u32)?
                }
                '\u{202a}'..='\u{202e}'
                | '\u{2066}'..='\u{2069}'
                | '\u{200e}'
                | '\u{200f}'
                | '\u{061c}'
                | '\u{2028}'
                | '\u{2029}'
                | '\u{feff}' => write!(f, "\\u{{{:04x}}}", c as u32)?,
                c => write!(f, "{c}")?,
            }
        }
        Ok(())
    }
}

impl fmt::Debug for SafeDisplay<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

#[derive(Error, Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum CatError {
    /// Wire bytes do not form a valid COSE_Sign1 / COSE_Encrypt0 /
    /// COSE_Mac0 envelope, or size / admission-policy caps were
    /// exceeded before parsing began.
    #[error("Invalid token format")]
    InvalidTokenFormat,

    /// CBOR encoding is not readable, not canonical (per the profile's
    /// deterministic encoding rules), or nests deeper than the
    /// configured cap. The wrapped detail is `SafeDisplay`-sanitized
    /// before rendering.
    #[error("Invalid CBOR encoding: {}", SafeDisplay(.0))]
    InvalidCbor(String),

    /// Base64 (or base64url) decode failed for a JWT wire form, JWK
    /// component, or any other base64-carried field.
    #[error("Invalid base64 encoding: {}", SafeDisplay(.0))]
    InvalidBase64(String),

    /// COSE signature verification (ES256, PS256, HMAC-SHA-256) failed
    /// against the resolved key. No further detail is exposed to
    /// avoid oracle attacks.
    #[error("Token signature verification failed")]
    SignatureVerificationFailed,

    #[error("Token has expired")]
    TokenExpired,

    #[error("Token is not yet valid (nbf)")]
    TokenNotYetValid,

    #[error("Invalid audience")]
    InvalidAudience,

    #[error("Invalid issuer")]
    InvalidIssuer,

    /// A claim listed as required by the validator (or the profile)
    /// was absent from the decoded token. The wrapped string is the
    /// dotted claim path (e.g. "actx.type", "aud", "iss").
    #[error("Missing required claim: {0}")]
    MissingRequiredClaim(String),

    /// Catch-all for legacy claim-value errors. New code should prefer
    /// [`CatError::malformed`] (issuer produced bytes that don't respect
    /// the profile) or [`CatError::denied`] (well-formed claim not
    /// satisfied by the request) so operators can distinguish the two
    /// categories in metrics without matching on a substring.
    /// [`CatError::detail`] returns the wrapped string for either of
    /// the semantic variants and for this legacy variant.
    ///
    /// The wrapped detail is `SafeDisplay`-sanitized on render.
    #[error("Invalid claim value: {}", SafeDisplay(.0))]
    InvalidClaimValue(String),

    /// A claim's own value is malformed — the issuer produced bytes
    /// that don't respect the profile. Distinct from
    /// [`CatError::ClaimEnforcementFailed`], which signals a
    /// well-formed claim that the request fails to satisfy.
    ///
    /// `detail` may echo attacker-controlled bytes; it is
    /// `SafeDisplay`-sanitized before rendering.
    #[error("Malformed claim {claim}: {}", SafeDisplay(.detail))]
    MalformedClaim {
        claim: &'static str,
        detail: String,
    },

    /// The request/peer does not satisfy a well-formed claim (e.g.,
    /// `catu` prefix mismatch, `cath` header rule not met, `catnip`
    /// peer IP outside prefix, DPoP nonce differs). This is an
    /// authorization failure — the operator should surface it as
    /// "auth denied", not "malformed request".
    ///
    /// `detail` may echo attacker-controlled bytes; it is
    /// `SafeDisplay`-sanitized before rendering.
    #[error("Claim {claim} enforcement failed: {}", SafeDisplay(.detail))]
    ClaimEnforcementFailed {
        claim: &'static str,
        detail: String,
    },

    /// The token asserts a claim that requires a piece of request
    /// context (peer IP, ALPN, URI, request method, header set, block
    /// list, replay guard) the integrator did not populate. This is a
    /// wiring bug — authorization is refused because the required
    /// input was absent, not because the token was malformed.
    #[error("Token claim {claim} requires request context {field}, but it was not provided")]
    MissingRelayContext {
        claim: &'static str,
        field: &'static str,
    },

    #[error("Unsupported algorithm: {}", SafeDisplay(.0))]
    UnsupportedAlgorithm(String),

    #[error("Algorithm mismatch: expected {expected}, found {found}")]
    AlgorithmMismatch { expected: i64, found: i64 },

    /// The token's protected-header `alg` is not in the admission
    /// policy's allow-list. Distinct from
    /// [`CatError::AlgorithmMismatch`], which signals a resolver-vs-
    /// token disagreement on a single expected `alg`.
    #[error("Algorithm {found} not permitted by admission policy (allowed: {allowed:?})")]
    AlgorithmNotAllowed { found: i64, allowed: Vec<i64> },

    /// The token's protected-header `kid` is not in the admission
    /// policy's allow-list, or the policy requires a `kid` and none
    /// was present. `found` is `None` when the header omitted `kid`.
    #[error("Key ID {found:?} not permitted by admission policy (allowed: {allowed:?})")]
    KidNotAllowed {
        found: Option<Vec<u8>>,
        allowed: Vec<Vec<u8>>,
    },

    /// A cryptographic key operation (sign, verify, MAC, encrypt,
    /// decrypt, JWK parse) failed. Signals bad key material or
    /// corrupt input, not a storage or policy problem — those flow
    /// through [`CatError::BackendUnavailable`] or
    /// [`CatError::ConfigurationRefused`].
    #[error("Key operation failed: {}", SafeDisplay(.0))]
    KeyOperationFailed(String),

    /// A replay store, key resolver, or other pluggable backend
    /// returned an error. The validator MUST fail closed on this
    /// variant — the authorization decision cannot be trusted. Used
    /// for `Mutex` poisoning, distributed-store timeouts, and any
    /// transient outage where the authoritative answer is unavailable.
    #[error("Backend unavailable: {}", SafeDisplay(.0))]
    BackendUnavailable(String),

    /// The integrator's configuration violates a fail-closed policy
    /// contract of this crate — asking for a strict store but
    /// supplying a best-effort one, wiring a `catreplay` obligation
    /// without providing a guard, etc. This is a configuration bug,
    /// not a transient failure; retrying will not help.
    #[error("Configuration refused: {}", SafeDisplay(.0))]
    ConfigurationRefused(String),

    #[error("Geographic validation failed: {}", SafeDisplay(.0))]
    GeographicValidationFailed(String),

    #[error("Replay attack detected")]
    ReplayAttackDetected,

    #[error("MOQT action not authorized: {}", SafeDisplay(.0))]
    MoqtActionNotAuthorized(String),

    /// DPoP proof failed validation — malformed signature, expired
    /// `iat`, unknown algorithm, key/thumbprint mismatch.
    #[error("DPoP validation failed: {}", SafeDisplay(.0))]
    DpopValidationFailed(String),

    #[error("Invalid DPoP binding")]
    InvalidDpopBinding,

    #[error("Token revalidation required")]
    RevalidationRequired,

    #[error("Revalidation interval too short")]
    RevalidationIntervalTooShort,

    #[error("Token rejected by probability of rejection")]
    RejectedByProbability,

    #[error("Certificate validation failed: {}", SafeDisplay(.0))]
    CertificateValidationFailed(String),

    #[error("DPoP algorithm not supported: {}", SafeDisplay(.0))]
    DpopAlgorithmNotSupported(String),

    #[error("DPoP key mismatch: embedded JWK thumbprint does not match expected")]
    DpopKeyMismatch,

    #[error("Privacy-sensitive claim {0} requires encryption")]
    UnencryptedPrivacyClaim(String),
}

impl CatError {
    /// Convenience constructor for [`CatError::MalformedClaim`] —
    /// signals an issuer-side malformed claim value.
    pub fn malformed(claim: &'static str, detail: impl Into<String>) -> Self {
        CatError::MalformedClaim {
            claim,
            detail: detail.into(),
        }
    }

    /// Convenience constructor for [`CatError::ClaimEnforcementFailed`]
    /// — signals a well-formed claim that the request does not satisfy.
    pub fn denied(claim: &'static str, detail: impl Into<String>) -> Self {
        CatError::ClaimEnforcementFailed {
            claim,
            detail: detail.into(),
        }
    }

    /// Category label for `cat_error_*_total{category=...}` metrics.
    /// The label is a stable static string; operators partition failure
    /// alerts on it. See the [module docs](crate::error) for the three
    /// categories.
    pub fn category(&self) -> &'static str {
        use CatError::*;
        match self {
            InvalidTokenFormat
            | InvalidCbor(_)
            | InvalidBase64(_)
            | MalformedClaim { .. }
            | UnsupportedAlgorithm(_)
            | AlgorithmMismatch { .. }
            | AlgorithmNotAllowed { .. }
            | KidNotAllowed { .. }
            | DpopAlgorithmNotSupported(_) => "malformed",

            SignatureVerificationFailed
            | TokenExpired
            | TokenNotYetValid
            | InvalidAudience
            | InvalidIssuer
            | InvalidClaimValue(_)
            | ClaimEnforcementFailed { .. }
            | GeographicValidationFailed(_)
            | ReplayAttackDetected
            | MoqtActionNotAuthorized(_)
            | DpopValidationFailed(_)
            | InvalidDpopBinding
            | DpopKeyMismatch
            | RevalidationRequired
            | RevalidationIntervalTooShort
            | RejectedByProbability
            | CertificateValidationFailed(_)
            | UnencryptedPrivacyClaim(_) => "denied",

            MissingRequiredClaim(_)
            | MissingRelayContext { .. }
            | KeyOperationFailed(_)
            | BackendUnavailable(_)
            | ConfigurationRefused(_) => "operator",
        }
    }

    /// Detail portion of a claim-value error, if any. Returns the
    /// `detail` string carried by [`Self::MalformedClaim`],
    /// [`Self::ClaimEnforcementFailed`], or the legacy
    /// [`Self::InvalidClaimValue`]; `None` for other variants. Useful
    /// for metrics that want to elide the detail (which is sanitized
    /// but still high-cardinality) while keeping the claim name.
    pub fn detail(&self) -> Option<&str> {
        match self {
            CatError::MalformedClaim { detail, .. } => Some(detail.as_str()),
            CatError::ClaimEnforcementFailed { detail, .. } => Some(detail.as_str()),
            CatError::InvalidClaimValue(s) => Some(s.as_str()),
            _ => None,
        }
    }
}
