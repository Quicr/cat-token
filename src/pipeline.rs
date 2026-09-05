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
}

impl VerifiedToken {
    pub(crate) fn new(token: CatToken, header: TokenHeader, provenance: TokenProvenance) -> Self {
        Self {
            token,
            header,
            provenance,
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

    pub fn validate(self, validator: &CatTokenValidator) -> Result<ValidatedToken, CatError> {
        validator.validate_with_provenance(&self.token, self.provenance)?;
        Ok(ValidatedToken {
            token: self.token,
            header: self.header,
            provenance: self.provenance,
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
            return Err(CatError::AlgorithmMismatch {
                expected: *allowed.iter().next().unwrap_or(&0),
                found: header.algorithm_id,
            });
        }

        if let Some(allowed_kids) = &self.allowed_kids {
            match &header.kid {
                Some(kid) if allowed_kids.contains(kid) => {}
                Some(_) => {
                    return Err(CatError::CryptoError(
                        "kid not in admission allowlist".to_string(),
                    ));
                }
                None => {
                    return Err(CatError::CryptoError(
                        "token has no kid but admission policy requires one".to_string(),
                    ));
                }
            }
        }

        Ok(())
    }
}
