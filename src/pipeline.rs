// SPDX-FileCopyrightText: Copyright (c) 2022 Quicr
// SPDX-License-Identifier: BSD-2-Clause

use crate::{CatError, CatToken, CatTokenValidator};
use std::collections::HashSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenProvenance {
    Signed,
    Encrypted,
}

#[derive(Debug, Clone)]
pub struct TokenHeader {
    pub algorithm_id: i64,
    pub kid: Option<Vec<u8>>,
}

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

    pub fn claims(&self) -> &CatToken {
        &self.token
    }

    pub fn header(&self) -> &TokenHeader {
        &self.header
    }

    pub fn provenance(&self) -> TokenProvenance {
        self.provenance
    }

    pub fn was_encrypted(&self) -> bool {
        self.provenance == TokenProvenance::Encrypted
    }

    /// The original wire bytes this token was decoded from. See the field
    /// documentation for why callers should not attempt to re-encode.
    pub fn serialized(&self) -> &[u8] {
        &self.serialized
    }

    pub fn validate(self, validator: &CatTokenValidator) -> Result<ValidatedToken, CatError> {
        validator.validate_with_provenance(&self.token, self.provenance)?;
        Ok(ValidatedToken {
            token: self.token,
            header: self.header,
            provenance: self.provenance,
            serialized: self.serialized,
        })
    }

    pub fn into_unvalidated_token(self) -> CatToken {
        self.token
    }
}

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

    pub fn claims(&self) -> &CatToken {
        &self.token
    }

    pub fn header(&self) -> &TokenHeader {
        &self.header
    }

    pub fn provenance(&self) -> TokenProvenance {
        self.provenance
    }

    pub fn was_encrypted(&self) -> bool {
        self.provenance == TokenProvenance::Encrypted
    }

    /// The original wire bytes this token was decoded from. Used by
    /// [`crate::MoqtValidator::authorize`] to compute the SHA-256 hash the
    /// DPoP proof's `ath` claim must match.
    pub fn serialized(&self) -> &[u8] {
        &self.serialized
    }

    pub fn into_inner(self) -> CatToken {
        self.token
    }
}

const DEFAULT_MAX_TOKEN_SIZE: usize = 16 * 1024; // 16KB — relay-appropriate default

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
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_max_token_size(mut self, size: usize) -> Self {
        self.max_token_size = size;
        self
    }

    pub fn with_allowed_algorithms(mut self, algorithms: Vec<i64>) -> Self {
        self.allowed_algorithms = Some(algorithms.into_iter().collect());
        self
    }

    pub fn with_allowed_kids(mut self, kids: Vec<Vec<u8>>) -> Self {
        self.allowed_kids = Some(kids.into_iter().collect());
        self
    }

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
