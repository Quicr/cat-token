// SPDX-FileCopyrightText: Copyright (c) 2022 Quicr
// SPDX-License-Identifier: BSD-2-Clause

use crate::crypto::CryptographicAlgorithm;
use crate::error::CatError;
use crate::pipeline::TokenHeader;
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct KeyHint {
    pub algorithm_id: i64,
    pub kid: Option<Vec<u8>>,
}

impl From<&TokenHeader> for KeyHint {
    fn from(header: &TokenHeader) -> Self {
        Self {
            algorithm_id: header.algorithm_id,
            kid: header.kid.clone(),
        }
    }
}

pub trait KeyResolver: Send + Sync {
    fn resolve(&self, hint: &KeyHint) -> Result<&dyn CryptographicAlgorithm, CatError>;
}

pub struct StaticKeyResolver<A: CryptographicAlgorithm> {
    algorithm: A,
}

impl<A: CryptographicAlgorithm> StaticKeyResolver<A> {
    pub fn new(algorithm: A) -> Self {
        Self { algorithm }
    }
}

impl<A: CryptographicAlgorithm + Send + Sync> KeyResolver for StaticKeyResolver<A> {
    fn resolve(&self, _hint: &KeyHint) -> Result<&dyn CryptographicAlgorithm, CatError> {
        Ok(&self.algorithm)
    }
}

pub struct KeyRingResolver {
    keys: HashMap<Vec<u8>, Box<dyn CryptographicAlgorithm + Send + Sync>>,
    default: Option<Box<dyn CryptographicAlgorithm + Send + Sync>>,
}

impl KeyRingResolver {
    pub fn new() -> Self {
        Self {
            keys: HashMap::new(),
            default: None,
        }
    }

    pub fn with_key(
        mut self,
        kid: Vec<u8>,
        algorithm: Box<dyn CryptographicAlgorithm + Send + Sync>,
    ) -> Self {
        self.keys.insert(kid, algorithm);
        self
    }

    pub fn with_default(
        mut self,
        algorithm: Box<dyn CryptographicAlgorithm + Send + Sync>,
    ) -> Self {
        self.default = Some(algorithm);
        self
    }

    pub fn add_key(
        &mut self,
        kid: Vec<u8>,
        algorithm: Box<dyn CryptographicAlgorithm + Send + Sync>,
    ) {
        self.keys.insert(kid, algorithm);
    }

    pub fn remove_key(&mut self, kid: &[u8]) -> bool {
        self.keys.remove(kid).is_some()
    }

    pub fn key_count(&self) -> usize {
        self.keys.len()
    }
}

impl Default for KeyRingResolver {
    fn default() -> Self {
        Self::new()
    }
}

impl KeyResolver for KeyRingResolver {
    fn resolve(&self, hint: &KeyHint) -> Result<&dyn CryptographicAlgorithm, CatError> {
        if let Some(kid) = &hint.kid
            && let Some(alg) = self.keys.get(kid.as_slice())
        {
            return Ok(alg.as_ref());
        }

        if let Some(default) = &self.default {
            return Ok(default.as_ref());
        }

        Err(CatError::CryptoError(match &hint.kid {
            Some(kid) => format!("no key found for kid: {}", String::from_utf8_lossy(kid)),
            None => "no key found and no default configured".to_string(),
        }))
    }
}
