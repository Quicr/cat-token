// SPDX-FileCopyrightText: Copyright (c) 2022 Quicr
// SPDX-License-Identifier: BSD-2-Clause

use thiserror::Error;

#[derive(Error, Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum CatError {
    #[error("Invalid token format")]
    InvalidTokenFormat,

    #[error("Invalid CBOR encoding: {0}")]
    InvalidCbor(String),

    #[error("Invalid base64 encoding: {0}")]
    InvalidBase64(String),

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

    #[error("Missing required claim: {0}")]
    MissingRequiredClaim(String),

    #[error("Invalid claim value: {0}")]
    InvalidClaimValue(String),

    #[error("Unsupported algorithm: {0}")]
    UnsupportedAlgorithm(String),

    #[error("Algorithm mismatch: expected {expected}, found {found}")]
    AlgorithmMismatch { expected: i64, found: i64 },

    /// A cryptographic key operation (sign, verify, MAC, encrypt,
    /// decrypt, JWK parse) failed. Signals bad key material or corrupt
    /// input, not a storage or policy problem — those flow through
    /// [`CatError::BackendUnavailable`] or
    /// [`CatError::ConfigurationRefused`].
    #[error("Key operation failed: {0}")]
    KeyOperationFailed(String),

    /// A replay store, key resolver, or other pluggable backend returned
    /// an error. The validator MUST fail closed on this variant — the
    /// authorization decision cannot be trusted. Used for `Mutex`
    /// poisoning, distributed-store timeouts, and any transient outage
    /// where the authoritative answer is unavailable.
    #[error("Backend unavailable: {0}")]
    BackendUnavailable(String),

    /// The integrator's configuration violates a fail-closed policy
    /// contract of this crate — asking for a strict store but supplying
    /// a best-effort one, wiring a `catreplay` obligation without
    /// providing a guard, etc. This is a configuration bug, not a
    /// transient failure; retrying will not help.
    #[error("Configuration refused: {0}")]
    ConfigurationRefused(String),

    #[error("Geographic validation failed: {0}")]
    GeographicValidationFailed(String),

    #[error("Replay attack detected")]
    ReplayAttackDetected,

    #[error("MOQT action not authorized: {0}")]
    MoqtActionNotAuthorized(String),

    #[error("DPoP validation failed: {0}")]
    DpopValidationFailed(String),

    #[error("Invalid DPoP binding")]
    InvalidDpopBinding,

    #[error("Token revalidation required")]
    RevalidationRequired,

    #[error("Revalidation interval too short")]
    RevalidationIntervalTooShort,

    #[error("Token rejected by probability of rejection")]
    RejectedByProbability,

    #[error("Certificate validation failed: {0}")]
    CertificateValidationFailed(String),

    #[error("DPoP algorithm not supported: {0}")]
    DpopAlgorithmNotSupported(String),

    #[error("DPoP key mismatch: embedded JWK thumbprint does not match expected")]
    DpopKeyMismatch,

    #[error("Privacy-sensitive claim {0} requires encryption")]
    UnencryptedPrivacyClaim(String),
}
