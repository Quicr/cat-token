// SPDX-FileCopyrightText: Copyright (c) 2022 Quicr
// SPDX-License-Identifier: BSD-2-Clause

use thiserror::Error;

#[derive(Error, Debug, Clone, PartialEq)]
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

    #[error("Cryptographic operation failed: {0}")]
    CryptoError(String),

    #[error("Geographic validation failed: {0}")]
    GeographicValidationFailed(String),

    #[error("Replay attack detected")]
    ReplayAttackDetected,

    #[error("Token usage limit exceeded")]
    UsageLimitExceeded,

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

    #[error("Method not allowed: {0}")]
    MethodNotAllowed(String),

    #[error("Certificate validation failed: {0}")]
    CertificateValidationFailed(String),
}
