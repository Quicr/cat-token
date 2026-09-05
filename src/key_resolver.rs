// SPDX-FileCopyrightText: Copyright (c) 2022 Quicr
// SPDX-License-Identifier: BSD-2-Clause

//! Key resolution for CAT verification.
//!
//! The resolver contract is fail-closed on the `(issuer, kid, algorithm)`
//! triple. A hostile issuer that reuses another tenant's `kid` or an unrelated
//! algorithm identifier must not silently land on an unintended verification
//! key; every resolver in this module refuses to match unless the caller
//! provided the exact tuple that was registered.
//!
//! - `SingleKeyResolver` — one key for one deployment. Callers may bind the
//!   accepted issuer and/or kid to make cross-tenant confusion impossible.
//! - `KeyRingResolver` — multi-key trust anchor keyed on `(issuer, kid, alg)`.
//!   No default key, no kid-only fallback, no issuer-only fallback: every entry
//!   must specify all three components.

use crate::crypto::CryptographicAlgorithm;
use crate::error::CatError;
use crate::pipeline::TokenHeader;
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct KeyHint {
    pub algorithm_id: i64,
    pub kid: Option<Vec<u8>>,
    pub issuer: Option<String>,
}

impl From<&TokenHeader> for KeyHint {
    fn from(header: &TokenHeader) -> Self {
        Self {
            algorithm_id: header.algorithm_id,
            kid: header.kid.clone(),
            issuer: None,
        }
    }
}

impl KeyHint {
    pub fn with_issuer(mut self, issuer: Option<String>) -> Self {
        self.issuer = issuer;
        self
    }
}

pub trait KeyResolver: Send + Sync {
    fn resolve(&self, hint: &KeyHint) -> Result<&dyn CryptographicAlgorithm, CatError>;
}

/// Single trust anchor. Suitable for single-issuer relays, tests, and
/// bootstrapping. Callers can pin the accepted issuer and kid so that a token
/// bearing a different iss/kid combination is rejected before signature
/// verification.
pub struct SingleKeyResolver<A: CryptographicAlgorithm> {
    algorithm: A,
    required_issuer: Option<String>,
    required_kid: Option<Vec<u8>>,
}

impl<A: CryptographicAlgorithm> SingleKeyResolver<A> {
    pub fn new(algorithm: A) -> Self {
        Self {
            algorithm,
            required_issuer: None,
            required_kid: None,
        }
    }

    /// Reject tokens whose (peeked) `iss` claim does not match `issuer`.
    pub fn require_issuer(mut self, issuer: impl Into<String>) -> Self {
        self.required_issuer = Some(issuer.into());
        self
    }

    /// Reject tokens whose protected-header `kid` does not match `kid`.
    pub fn require_kid(mut self, kid: Vec<u8>) -> Self {
        self.required_kid = Some(kid);
        self
    }
}

impl<A: CryptographicAlgorithm + Send + Sync> KeyResolver for SingleKeyResolver<A> {
    fn resolve(&self, hint: &KeyHint) -> Result<&dyn CryptographicAlgorithm, CatError> {
        let expected_alg = self.algorithm.algorithm_id();
        if hint.algorithm_id != expected_alg {
            return Err(CatError::AlgorithmMismatch {
                expected: expected_alg,
                found: hint.algorithm_id,
            });
        }

        if let Some(ref expected_iss) = self.required_issuer {
            match &hint.issuer {
                Some(actual) if actual == expected_iss => {}
                Some(actual) => {
                    return Err(CatError::CryptoError(format!(
                        "issuer mismatch: token iss '{actual}' does not match pinned '{expected_iss}'"
                    )));
                }
                None => {
                    return Err(CatError::MissingRequiredClaim("iss".to_string()));
                }
            }
        }

        if let Some(ref expected_kid) = self.required_kid {
            match &hint.kid {
                Some(actual) if actual.as_slice() == expected_kid.as_slice() => {}
                Some(_) => {
                    return Err(CatError::CryptoError(
                        "kid mismatch: header kid does not match pinned kid".to_string(),
                    ));
                }
                None => {
                    return Err(CatError::CryptoError(
                        "kid missing from protected header but required by resolver".to_string(),
                    ));
                }
            }
        }

        Ok(&self.algorithm)
    }
}

/// Multi-key trust anchor keyed on `(issuer, kid, algorithm_id)`. Every
/// registered entry must specify all three components. There is no
/// kid-only or issuer-only fallback — a hostile token that omits `iss` or
/// carries an unknown `kid` fails resolution rather than landing on any
/// key. Callers who need one key for many issuers can register the same
/// algorithm under each `(issuer, kid, alg)` triple they intend to accept.
pub struct KeyRingResolver {
    keys: HashMap<KeyEntry, Box<dyn CryptographicAlgorithm + Send + Sync>>,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
struct KeyEntry {
    issuer: String,
    kid: Vec<u8>,
    algorithm_id: i64,
}

impl KeyRingResolver {
    pub fn new() -> Self {
        Self {
            keys: HashMap::new(),
        }
    }

    pub fn with_key(
        mut self,
        issuer: impl Into<String>,
        kid: Vec<u8>,
        algorithm: Box<dyn CryptographicAlgorithm + Send + Sync>,
    ) -> Self {
        self.add_key(issuer, kid, algorithm);
        self
    }

    pub fn add_key(
        &mut self,
        issuer: impl Into<String>,
        kid: Vec<u8>,
        algorithm: Box<dyn CryptographicAlgorithm + Send + Sync>,
    ) {
        let algorithm_id = algorithm.algorithm_id();
        self.keys.insert(
            KeyEntry {
                issuer: issuer.into(),
                kid,
                algorithm_id,
            },
            algorithm,
        );
    }

    pub fn remove_key(&mut self, issuer: &str, kid: &[u8], algorithm_id: i64) -> bool {
        self.keys
            .remove(&KeyEntry {
                issuer: issuer.to_string(),
                kid: kid.to_vec(),
                algorithm_id,
            })
            .is_some()
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
        let issuer = hint
            .issuer
            .as_ref()
            .ok_or_else(|| CatError::MissingRequiredClaim("iss".to_string()))?;
        let kid = hint.kid.as_ref().ok_or_else(|| {
            CatError::CryptoError("kid missing from protected header".to_string())
        })?;

        self.keys
            .get(&KeyEntry {
                issuer: issuer.clone(),
                kid: kid.clone(),
                algorithm_id: hint.algorithm_id,
            })
            .map(|a| a.as_ref() as &dyn CryptographicAlgorithm)
            .ok_or_else(|| {
                CatError::CryptoError(format!(
                    "no key registered for (iss='{}', kid='{}', alg={})",
                    issuer,
                    String::from_utf8_lossy(kid),
                    hint.algorithm_id
                ))
            })
    }
}
