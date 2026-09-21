// SPDX-FileCopyrightText: Copyright (c) 2022 Quicr
// SPDX-License-Identifier: BSD-2-Clause

//! The decode → verify → validate type-state pipeline.
//!
//! A token starts as raw wire bytes, becomes a [`VerifiedToken`] once its
//! COSE signature (or encryption) has been checked, and a
//! [`ValidatedToken`] once its claims pass a [`CatTokenValidator`]. The
//! types enforce this ordering: claims cannot be consumed as validated
//! until they have actually been validated.

use crate::{CatError, CatToken, CatTokenValidator};
use std::collections::HashSet;

/// How a token's authenticity was established.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenProvenance {
    /// Authenticity established via a COSE signature or MAC.
    Signed,
    /// Authenticity established via COSE encryption (COSE_Encrypt0).
    Encrypted,
}

/// The protected-header fields used to resolve a verification key.
#[derive(Debug, Clone)]
pub struct TokenHeader {
    /// COSE algorithm identifier from the protected header.
    pub algorithm_id: i64,
    /// Key ID from the protected header, if present.
    pub kid: Option<Vec<u8>>,
}

/// A token whose signature/encryption has been verified but whose claims
/// have not yet been validated. Call [`VerifiedToken::validate`] to advance.
#[derive(Clone, Debug)]
pub struct VerifiedToken {
    token: CatToken,
    header: TokenHeader,
    provenance: TokenProvenance,
    /// Original serialized COSE bytes as received from the wire. Retained
    /// through validation so `MoqtValidator::authorize` can bind an
    /// accompanying DPoP proof to *this specific token instance* via the
    /// `ath` (access-token-hash) claim without re-encoding — reserializing
    /// would change the byte sequence and defeat proof binding.
    serialized: Vec<u8>,
}

impl VerifiedToken {
    pub(crate) fn new(
        token: CatToken,
        header: TokenHeader,
        provenance: TokenProvenance,
        serialized: Vec<u8>,
    ) -> Self {
        Self {
            token,
            header,
            provenance,
            serialized,
        }
    }

    /// The decoded CAT claims. Not yet validated against any policy.
    pub fn claims(&self) -> &CatToken {
        &self.token
    }

    /// The protected-header fields used to resolve the verification key.
    pub fn header(&self) -> &TokenHeader {
        &self.header
    }

    /// How this token's authenticity was established.
    pub fn provenance(&self) -> TokenProvenance {
        self.provenance
    }

    /// Whether the token arrived encrypted (COSE_Encrypt0).
    pub fn was_encrypted(&self) -> bool {
        self.provenance == TokenProvenance::Encrypted
    }

    /// The original wire bytes this token was decoded from. See the field
    /// documentation for why callers should not attempt to re-encode.
    pub fn serialized(&self) -> &[u8] {
        &self.serialized
    }

    /// Run `validator` against the claims, advancing to a
    /// [`ValidatedToken`] on success.
    pub fn validate(self, validator: &CatTokenValidator) -> Result<ValidatedToken, CatError> {
        validator.validate_with_provenance(&self.token, self.provenance)?;
        Ok(ValidatedToken {
            token: self.token,
            header: self.header,
            provenance: self.provenance,
            serialized: self.serialized,
        })
    }

    /// Consume the token, returning the unvalidated claims without running
    /// any validator.
    pub fn into_unvalidated_token(self) -> CatToken {
        self.token
    }
}

/// A token whose signature/encryption has been verified and whose claims
/// have passed a [`CatTokenValidator`]. The terminal state of the pipeline.
#[derive(Clone)]
pub struct ValidatedToken {
    token: CatToken,
    header: TokenHeader,
    provenance: TokenProvenance,
    serialized: Vec<u8>,
}

impl ValidatedToken {
    #[cfg(test)]
    pub(crate) fn from_unchecked(token: CatToken) -> Self {
        Self {
            token,
            header: TokenHeader {
                algorithm_id: 0,
                kid: None,
            },
            provenance: TokenProvenance::Signed,
            serialized: Vec::new(),
        }
    }

    /// The validated CAT claims.
    pub fn claims(&self) -> &CatToken {
        &self.token
    }

    /// The protected-header fields used to resolve the verification key.
    pub fn header(&self) -> &TokenHeader {
        &self.header
    }

    /// How this token's authenticity was established.
    pub fn provenance(&self) -> TokenProvenance {
        self.provenance
    }

    /// Whether the token arrived encrypted (COSE_Encrypt0).
    pub fn was_encrypted(&self) -> bool {
        self.provenance == TokenProvenance::Encrypted
    }

    /// The original wire bytes this token was decoded from. Used by
    /// [`crate::MoqtValidator::authorize`] to compute the SHA-256 hash the
    /// DPoP proof's `ath` claim must match.
    pub fn serialized(&self) -> &[u8] {
        &self.serialized
    }

    /// Consume the token, returning the validated claims.
    pub fn into_inner(self) -> CatToken {
        self.token
    }
}

const DEFAULT_MAX_TOKEN_SIZE: usize = 16 * 1024; // 16KB — relay-appropriate default

/// Pre-parse admission checks applied to raw token bytes and header before
/// signature verification: a maximum size cap plus optional `alg`/`kid`
/// allow-lists.
pub struct AdmissionPolicy {
    max_token_size: usize,
    allowed_algorithms: Option<HashSet<i64>>,
    allowed_kids: Option<HashSet<Vec<u8>>>,
}

impl Default for AdmissionPolicy {
    fn default() -> Self {
        Self {
            max_token_size: DEFAULT_MAX_TOKEN_SIZE,
            allowed_algorithms: None,
            allowed_kids: None,
        }
    }
}

impl AdmissionPolicy {
    /// Create a policy with the default size cap and no `alg`/`kid` limits.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the maximum accepted token size in bytes.
    pub fn with_max_token_size(mut self, size: usize) -> Self {
        self.max_token_size = size;
        self
    }

    /// Restrict accepted tokens to these COSE algorithm identifiers.
    pub fn with_allowed_algorithms(mut self, algorithms: Vec<i64>) -> Self {
        self.allowed_algorithms = Some(algorithms.into_iter().collect());
        self
    }

    /// Restrict accepted tokens to these `kid` values.
    pub fn with_allowed_kids(mut self, kids: Vec<Vec<u8>>) -> Self {
        self.allowed_kids = Some(kids.into_iter().collect());
        self
    }

    /// Enforce the size cap and any `alg`/`kid` allow-lists against the
    /// raw bytes and decoded header. Fails closed on the first violation.
    pub fn check(&self, raw_bytes: &[u8], header: &TokenHeader) -> Result<(), CatError> {
        if raw_bytes.len() > self.max_token_size {
            return Err(CatError::InvalidTokenFormat);
        }

        if let Some(allowed) = &self.allowed_algorithms
            && !allowed.contains(&header.algorithm_id)
        {
            let mut allowed_list: Vec<i64> = allowed.iter().copied().collect();
            allowed_list.sort();
            return Err(CatError::AlgorithmNotAllowed {
                found: header.algorithm_id,
                allowed: allowed_list,
            });
        }

        if let Some(allowed_kids) = &self.allowed_kids {
            match &header.kid {
                Some(kid) if allowed_kids.contains(kid) => {}
                found => {
                    let mut allowed_list: Vec<Vec<u8>> = allowed_kids.iter().cloned().collect();
                    allowed_list.sort();
                    return Err(CatError::KidNotAllowed {
                        found: found.clone(),
                        allowed: allowed_list,
                    });
                }
            }
        }

        Ok(())
    }
}
