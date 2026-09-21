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

/// The `(issuer, kid, algorithm)` triple a [`KeyResolver`] matches against
/// to select a verification key.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct KeyHint {
    /// COSE algorithm identifier from the token's protected header.
    pub algorithm_id: i64,
    /// Key ID from the protected header, if present.
    pub kid: Option<Vec<u8>>,
    /// Issuer peeked from the token's `iss` claim, if present.
    pub issuer: Option<String>,
}

impl KeyHint {
    /// Create a hint carrying only the algorithm identifier.
    pub fn new(algorithm_id: i64) -> Self {
        Self {
            algorithm_id,
            kid: None,
            issuer: None,
        }
    }

    /// Set the `kid` component of the hint.
    pub fn with_kid(mut self, kid: Vec<u8>) -> Self {
        self.kid = Some(kid);
        self
    }
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
    /// Set the `issuer` component of the hint.
    pub fn with_issuer(mut self, issuer: Option<String>) -> Self {
        self.issuer = issuer;
        self
    }
}

/// Selects the verification key for a token from its `(issuer, kid, alg)`
/// hint. Implementations must fail closed: refuse to match unless the
/// exact registered tuple is supplied.
pub trait KeyResolver: Send + Sync {
    /// Return the verification key matching `hint`, or an error if no
    /// registered key matches the exact triple.
    fn resolve(&self, hint: &KeyHint) -> Result<&dyn CryptographicAlgorithm, CatError>;
}

/// Single trust anchor. Suitable for single-issuer relays, tests, and
/// bootstrapping. The constructor requires an expected issuer; the
/// resolver rejects any token whose peeked `iss` does not match. Callers
/// who genuinely need to accept any issuer must opt in explicitly via
/// [`SingleKeyResolver::dangerously_any_issuer`].
#[must_use = "SingleKeyResolver must be installed on a Decoder; discarding it means no verification key is trusted"]
pub struct SingleKeyResolver<A: CryptographicAlgorithm> {
    algorithm: A,
    required_issuer: Option<String>,
    required_kid: Option<Vec<u8>>,
}

impl<A: CryptographicAlgorithm> SingleKeyResolver<A> {
    /// Construct a resolver pinned to `issuer`. Any token whose peeked
    /// `iss` claim is absent or differs is rejected before signature
    /// verification runs. This is the fail-closed default: an
    /// unauthenticated bearer of a valid signature from another tenant
    /// cannot cause key confusion.
    pub fn new(algorithm: A, issuer: impl Into<String>) -> Self {
        Self {
            algorithm,
            required_issuer: Some(issuer.into()),
            required_kid: None,
        }
    }

    /// Construct a resolver that accepts tokens from *any* issuer. Only
    /// safe when the caller is certain the algorithm+key material is
    /// bound to a single trust anchor by some other means (e.g., a
    /// deployment with exactly one CAT issuer and no risk of key
    /// confusion with another tenant). Prefer [`SingleKeyResolver::new`]
    /// or [`KeyRingResolver`] in production.
    pub fn dangerously_any_issuer(algorithm: A) -> Self {
        Self {
            algorithm,
            required_issuer: None,
            required_kid: None,
        }
    }

    /// Reject tokens whose protected-header `kid` does not match `kid`.
    /// An empty `kid` is not a legitimate key identifier; passing one
    /// leaves the pinned `kid` unset so this resolver continues to accept
    /// any header `kid` rather than silently matching the empty variant.
    pub fn require_kid(mut self, kid: Vec<u8>) -> Self {
        if !kid.is_empty() {
            self.required_kid = Some(kid);
        }
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
                Some(_) => {
                    return Err(CatError::InvalidIssuer);
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
                    return Err(CatError::ConfigurationRefused(
                        "kid mismatch: header kid does not match pinned kid".to_string(),
                    ));
                }
                None => {
                    return Err(CatError::ConfigurationRefused(
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
    /// Create an empty key ring with no registered keys.
    pub fn new() -> Self {
        Self {
            keys: HashMap::new(),
        }
    }

    /// Register a key for `(issuer, kid, alg)` and return `self` for chaining.
    pub fn with_key(
        mut self,
        issuer: impl Into<String>,
        kid: Vec<u8>,
        algorithm: Box<dyn CryptographicAlgorithm + Send + Sync>,
    ) -> Self {
        self.add_key(issuer, kid, algorithm);
        self
    }

    /// Register a key for the `(issuer, kid, alg)` triple; the algorithm
    /// identifier is derived from `algorithm`.
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

    /// Remove the key registered for `(issuer, kid, algorithm_id)`.
    /// Returns `true` if a key was present and removed.
    pub fn remove_key(&mut self, issuer: &str, kid: &[u8], algorithm_id: i64) -> bool {
        self.keys
            .remove(&KeyEntry {
                issuer: issuer.to_string(),
                kid: kid.to_vec(),
                algorithm_id,
            })
            .is_some()
    }

    /// Number of registered keys in the ring.
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
            CatError::ConfigurationRefused("kid missing from protected header".to_string())
        })?;

        self.keys
            .get(&KeyEntry {
                issuer: issuer.clone(),
                kid: kid.clone(),
                algorithm_id: hint.algorithm_id,
            })
            .map(|a| a.as_ref() as &dyn CryptographicAlgorithm)
            .ok_or_else(|| {
                CatError::ConfigurationRefused(format!(
                    "no key registered for (iss='{}', kid='{}', alg={})",
                    issuer,
                    String::from_utf8_lossy(kid),
                    hint.algorithm_id
                ))
            })
    }
}
