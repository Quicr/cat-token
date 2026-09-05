// SPDX-FileCopyrightText: Copyright (c) 2022 Quicr
// SPDX-License-Identifier: BSD-2-Clause

use crate::{CatError, CatToken, CatTokenValidator};

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
    /// Wrap an already-validated CatToken. The caller asserts that validation
    /// has been performed externally (e.g. in unit tests that construct tokens directly).
    pub fn from_unchecked(token: CatToken) -> Self {
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
