// SPDX-FileCopyrightText: Copyright (c) 2022 Quicr
// SPDX-License-Identifier: BSD-2-Clause

use crate::CatError;
#[cfg(feature = "moqt")]
use crate::claims::CatDpopSettings;
use crate::claims::ConfirmationClaim;
use crate::jwk::Jwk;
#[cfg(feature = "moqt")]
use crate::{CryptographicAlgorithm, MoqtAction};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
#[cfg(feature = "moqt")]
use lru::LruCache;
use serde::{Deserialize, Serialize};
#[cfg(feature = "moqt")]
use std::num::NonZeroUsize;
#[cfg(feature = "moqt")]
use std::sync::{Arc, RwLock};
#[cfg(feature = "moqt")]
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub const DPOP_TYP: &str = "dpop+jwt";

/// Supported DPoP algorithms
pub const SUPPORTED_DPOP_ALGORITHMS: &[&str] = &["ES256", "PS256", "HS256"];

/// Maximum size for DPoP proof parts (header/payload) in bytes
const MAX_DPOP_PART_SIZE: usize = 16 * 1024; // 16KB

#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct DpopHeader {
    pub typ: String,
    pub alg: String,
    pub jwk: Jwk,
}

impl std::fmt::Debug for DpopHeader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DpopHeader")
            .field("typ", &self.typ)
            .field("alg", &self.alg)
            .field("jwk", &"[REDACTED]")
            .finish()
    }
}

impl DpopHeader {
    pub fn new(alg: &str, jwk: Jwk) -> Self {
        Self {
            typ: DPOP_TYP.to_string(),
            alg: alg.to_string(),
            jwk,
        }
    }

    pub fn is_valid(&self) -> bool {
        self.typ == DPOP_TYP && self.is_supported_algorithm()
    }

    /// Check if the algorithm is one of the supported algorithms
    pub fn is_supported_algorithm(&self) -> bool {
        SUPPORTED_DPOP_ALGORITHMS.contains(&self.alg.as_str())
    }
}

#[cfg(feature = "moqt")]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuthorizationContext {
    #[serde(rename = "type")]
    pub ctx_type: String,
    pub action: i32,
    pub tns: Vec<u8>,
    pub tn: Vec<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource: Option<String>,
}

#[cfg(feature = "moqt")]
impl AuthorizationContext {
    pub fn new_moqt(action: MoqtAction, namespace: &[u8], track: &[u8]) -> Self {
        Self {
            ctx_type: "moqt".to_string(),
            action: action as i32,
            tns: namespace.to_vec(),
            tn: track.to_vec(),
            resource: None,
        }
    }

    pub fn with_resource(mut self, resource: String) -> Self {
        self.resource = Some(resource);
        self
    }

    pub fn is_valid(&self) -> bool {
        self.ctx_type == "moqt" && !self.tns.is_empty() && !self.tn.is_empty()
    }

    pub fn action_string(&self) -> &'static str {
        match MoqtAction::try_from(self.action) {
            Ok(MoqtAction::ClientSetup) | Ok(MoqtAction::ServerSetup) => "SETUP",
            Ok(MoqtAction::PublishNamespace) => "PUB_NS",
            Ok(MoqtAction::SubscribeNamespace) => "SUB_NS",
            Ok(MoqtAction::Subscribe) => "SUBSCRIBE",
            Ok(MoqtAction::RequestUpdate) => "REQ_UPDATE",
            Ok(MoqtAction::Publish) => "PUBLISH",
            Ok(MoqtAction::Fetch) => "FETCH",
            Ok(MoqtAction::TrackStatus) => "TRK_STATUS",
            Err(_) => "UNKNOWN",
        }
    }
}

#[cfg(feature = "moqt")]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DpopPayload {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jti: Option<String>,
    pub iat: i64,
    pub actx: AuthorizationContext,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ath: Option<String>,
}

#[cfg(feature = "moqt")]
impl DpopPayload {
    pub fn new(actx: AuthorizationContext) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs() as i64;

        Self {
            jti: None,
            iat: now,
            actx,
            ath: None,
        }
    }

    pub fn with_jti(mut self, jti: String) -> Self {
        self.jti = Some(jti);
        self
    }

    pub fn with_access_token_hash(mut self, ath: String) -> Self {
        self.ath = Some(ath);
        self
    }

    pub fn is_valid(&self) -> bool {
        self.actx.is_valid() && self.iat > 0
    }

    pub fn is_fresh(&self, window_seconds: i64) -> bool {
        self.is_fresh_with_future_tolerance(window_seconds, 30) // Allow 30 seconds clock drift (conservative)
    }

    pub fn is_fresh_with_future_tolerance(
        &self,
        window_seconds: i64,
        future_tolerance_seconds: i64,
    ) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs() as i64;

        // Use checked arithmetic to prevent overflow with extreme timestamp values
        let age = match now.checked_sub(self.iat) {
            Some(a) => a,
            None => return false, // Overflow means extremely distant timestamp
        };

        // Reject if too old (past the window)
        if age > window_seconds {
            return false;
        }

        // Reject if too far in the future (with small tolerance for clock drift)
        if age < -future_tolerance_seconds {
            return false;
        }

        true
    }
}

/// Create a ConfirmationClaim from a JWK
pub fn confirmation_from_jwk(jwk: &Jwk) -> Result<ConfirmationClaim, CatError> {
    let thumbprint = jwk.thumbprint()?;
    Ok(ConfirmationClaim::new(thumbprint))
}

/// Check if a ConfirmationClaim matches a JWK (constant-time comparison)
pub fn confirmation_matches_jwk(cnf: &ConfirmationClaim, jwk: &Jwk) -> Result<bool, CatError> {
    let thumbprint = jwk.thumbprint()?;
    Ok(crate::crypto::constant_time_eq(&cnf.jkt, &thumbprint))
}

#[cfg(feature = "moqt")]
#[derive(Clone)]
pub struct DpopProof {
    pub header: DpopHeader,
    pub payload: DpopPayload,
    pub signature: Vec<u8>,
}

#[cfg(feature = "moqt")]
impl std::fmt::Debug for DpopProof {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DpopProof")
            .field("header", &self.header)
            .field("payload", &self.payload)
            .field("signature", &format!("[{} bytes]", self.signature.len()))
            .finish()
    }
}

#[cfg(feature = "moqt")]
impl DpopProof {
    pub fn new(header: DpopHeader, payload: DpopPayload, signature: Vec<u8>) -> Self {
        Self {
            header,
            payload,
            signature,
        }
    }

    pub fn create_for_moqt(
        action: MoqtAction,
        namespace: &[u8],
        track: &[u8],
        alg: &str,
        jwk: Jwk,
    ) -> Self {
        let header = DpopHeader::new(alg, jwk);
        let actx = AuthorizationContext::new_moqt(action, namespace, track);
        let payload = DpopPayload::new(actx);

        Self {
            header,
            payload,
            signature: Vec::new(),
        }
    }

    pub fn with_jti(mut self, jti: String) -> Self {
        self.payload.jti = Some(jti);
        self
    }

    pub fn with_resource(mut self, resource: String) -> Self {
        self.payload.actx.resource = Some(resource);
        self
    }

    pub fn signing_input(&self) -> Result<Vec<u8>, CatError> {
        let header_json = serde_json::to_string(&self.header)
            .map_err(|e| CatError::InvalidClaimValue(e.to_string()))?;
        let payload_json = serde_json::to_string(&self.payload)
            .map_err(|e| CatError::InvalidClaimValue(e.to_string()))?;

        let header_b64 = URL_SAFE_NO_PAD.encode(header_json.as_bytes());
        let payload_b64 = URL_SAFE_NO_PAD.encode(payload_json.as_bytes());

        Ok(format!("{}.{}", header_b64, payload_b64).into_bytes())
    }

    pub fn sign(&mut self, algorithm: &dyn CryptographicAlgorithm) -> Result<(), CatError> {
        let signing_input = self.signing_input()?;
        self.signature = algorithm.sign(&signing_input)?;
        Ok(())
    }

    pub fn encode(&self) -> Result<String, CatError> {
        let header_json = serde_json::to_string(&self.header)
            .map_err(|e| CatError::InvalidClaimValue(e.to_string()))?;
        let payload_json = serde_json::to_string(&self.payload)
            .map_err(|e| CatError::InvalidClaimValue(e.to_string()))?;

        let header_b64 = URL_SAFE_NO_PAD.encode(header_json.as_bytes());
        let payload_b64 = URL_SAFE_NO_PAD.encode(payload_json.as_bytes());
        let signature_b64 = URL_SAFE_NO_PAD.encode(&self.signature);

        Ok(format!("{}.{}.{}", header_b64, payload_b64, signature_b64))
    }

    pub fn decode(token: &str) -> Result<Self, CatError> {
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 3 {
            return Err(CatError::InvalidTokenFormat);
        }

        // Validate part sizes before decoding to prevent memory exhaustion
        for part in &parts {
            if part.len() > MAX_DPOP_PART_SIZE {
                return Err(CatError::InvalidTokenFormat);
            }
        }

        let header_json = URL_SAFE_NO_PAD
            .decode(parts[0])
            .map_err(|e| CatError::InvalidBase64(e.to_string()))?;
        let payload_json = URL_SAFE_NO_PAD
            .decode(parts[1])
            .map_err(|e| CatError::InvalidBase64(e.to_string()))?;
        let signature = URL_SAFE_NO_PAD
            .decode(parts[2])
            .map_err(|e| CatError::InvalidBase64(e.to_string()))?;

        // Additional size check after decoding
        if header_json.len() > MAX_DPOP_PART_SIZE || payload_json.len() > MAX_DPOP_PART_SIZE {
            return Err(CatError::InvalidTokenFormat);
        }

        let header: DpopHeader = serde_json::from_slice(&header_json)
            .map_err(|e| CatError::InvalidClaimValue(e.to_string()))?;
        let payload: DpopPayload = serde_json::from_slice(&payload_json)
            .map_err(|e| CatError::InvalidClaimValue(e.to_string()))?;

        Ok(Self {
            header,
            payload,
            signature,
        })
    }

    pub fn is_valid(&self, settings: &CatDpopSettings) -> bool {
        settings.validate_crit().is_ok()
            && self.header.is_valid()
            && self.payload.is_valid()
            && self.payload.is_fresh(settings.effective_window())
            && !self.signature.is_empty()
    }
}

const DEFAULT_JTI_CACHE_SIZE: usize = 100_000;

/// Minimum JTI cache size to provide meaningful replay protection
const MIN_JTI_CACHE_SIZE: usize = 1000;

/// Statistics about the JTI cache
#[cfg(feature = "moqt")]
#[derive(Debug, Clone, Default)]
pub struct JtiCacheStats {
    /// Number of JTIs currently in cache
    pub size: usize,
    /// Maximum capacity of the cache
    pub capacity: usize,
    /// True if cache is at or near capacity (>90%)
    pub under_pressure: bool,
}

#[cfg(feature = "moqt")]
#[derive(Clone)]
pub struct DpopValidator {
    settings: CatDpopSettings,
    used_jtis: Arc<RwLock<LruCache<String, i64>>>,
    jti_expiry_seconds: i64,
    cache_capacity: usize,
}

#[cfg(feature = "moqt")]
impl DpopValidator {
    pub fn new(settings: CatDpopSettings) -> Self {
        Self::with_cache_size(settings, DEFAULT_JTI_CACHE_SIZE)
    }

    pub fn with_cache_size(settings: CatDpopSettings, cache_size: usize) -> Self {
        // Enforce minimum cache size for meaningful replay protection
        let effective_size = cache_size.max(MIN_JTI_CACHE_SIZE);
        // SAFETY: effective_size >= MIN_JTI_CACHE_SIZE (1000), so always non-zero
        let nz_cache_size =
            NonZeroUsize::new(effective_size).expect("MIN_JTI_CACHE_SIZE guarantees non-zero");
        Self {
            jti_expiry_seconds: settings.effective_window() * 2,
            settings,
            used_jtis: Arc::new(RwLock::new(LruCache::new(nz_cache_size))),
            cache_capacity: effective_size,
        }
    }

    /// Get statistics about the JTI cache.
    ///
    /// Use this to monitor cache pressure. If `under_pressure` is true,
    /// consider increasing the cache size or reducing the validation window
    /// to prevent potential replay attacks due to early eviction.
    pub fn jti_cache_stats(&self) -> JtiCacheStats {
        let size = self.used_jtis.read().map(|cache| cache.len()).unwrap_or(0);
        let under_pressure = size >= (self.cache_capacity * 9 / 10);
        JtiCacheStats {
            size,
            capacity: self.cache_capacity,
            under_pressure,
        }
    }

    /// Validate DPoP proof claims (internal helper, does not verify signature).
    fn validate_claims(
        &self,
        proof: &DpopProof,
        expected_action: MoqtAction,
        expected_thumbprint: &[u8],
        access_token_hash: Option<&str>,
    ) -> Result<(), CatError> {
        if !proof.header.is_valid() {
            return Err(CatError::DpopValidationFailed("Invalid header".to_string()));
        }

        if !proof.payload.is_valid() {
            return Err(CatError::DpopValidationFailed(
                "Invalid payload".to_string(),
            ));
        }

        if !proof.payload.is_fresh(self.settings.effective_window()) {
            return Err(CatError::DpopValidationFailed("Proof expired".to_string()));
        }

        if proof.payload.actx.action != expected_action as i32 {
            return Err(CatError::DpopValidationFailed(format!(
                "Action mismatch: expected {:?}",
                expected_action
            )));
        }

        let jwk_thumbprint = proof.header.jwk.thumbprint()?;
        if !crate::crypto::constant_time_eq(&jwk_thumbprint, expected_thumbprint) {
            return Err(CatError::InvalidDpopBinding);
        }

        if let Some(expected_ath) = access_token_hash {
            match &proof.payload.ath {
                Some(ath) => {
                    // Use constant-time comparison for access token hash
                    if !crate::crypto::constant_time_eq(ath.as_bytes(), expected_ath.as_bytes()) {
                        return Err(CatError::DpopValidationFailed(
                            "Access token hash mismatch".to_string(),
                        ));
                    }
                }
                None => {
                    return Err(CatError::DpopValidationFailed(
                        "Missing access token hash (ath) in proof".to_string(),
                    ));
                }
            }
        }

        if self.settings.should_honor_jti()
            && let Some(ref jti) = proof.payload.jti
        {
            let mut jtis = self
                .used_jtis
                .write()
                .map_err(|_| CatError::CryptoError("Lock poisoned".to_string()))?;
            if jtis.contains(jti) {
                return Err(CatError::ReplayAttackDetected);
            }
            jtis.put(jti.clone(), proof.payload.iat);
        }

        Ok(())
    }

    /// Validate DPoP proof with full signature verification.
    ///
    /// Verifies both the claims and the cryptographic signature.
    pub fn validate_with_algorithm(
        &self,
        proof: &DpopProof,
        expected_action: MoqtAction,
        expected_thumbprint: &[u8],
        algorithm: &dyn CryptographicAlgorithm,
    ) -> Result<(), CatError> {
        self.validate_claims(proof, expected_action, expected_thumbprint, None)?;

        let signing_input = proof.signing_input()?;
        if !algorithm.verify(&signing_input, &proof.signature)? {
            return Err(CatError::SignatureVerificationFailed);
        }

        Ok(())
    }

    /// Validate DPoP proof with full signature verification and access token hash.
    pub fn validate_with_algorithm_and_ath(
        &self,
        proof: &DpopProof,
        expected_action: MoqtAction,
        expected_thumbprint: &[u8],
        algorithm: &dyn CryptographicAlgorithm,
        access_token_hash: Option<&str>,
    ) -> Result<(), CatError> {
        self.validate_claims(
            proof,
            expected_action,
            expected_thumbprint,
            access_token_hash,
        )?;

        let signing_input = proof.signing_input()?;
        if !algorithm.verify(&signing_input, &proof.signature)? {
            return Err(CatError::SignatureVerificationFailed);
        }

        Ok(())
    }

    pub fn cleanup_expired_jtis(&self) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs() as i64;

        if let Ok(mut jtis) = self.used_jtis.write() {
            // LruCache doesn't have retain, so we collect expired keys first
            let expired: Vec<String> = jtis
                .iter()
                .filter(|(_, iat)| now - **iat >= self.jti_expiry_seconds)
                .map(|(k, _)| k.clone())
                .collect();
            for key in expired {
                jtis.pop(&key);
            }
        }
    }
}

#[cfg(feature = "moqt")]
pub fn construct_moqt_uri(
    endpoint: &str,
    namespace: Option<&[u8]>,
    track: Option<&[u8]>,
) -> String {
    let mut uri = format!("moqt://{}", endpoint);

    if let Some(ns) = namespace {
        let ns_encoded = URL_SAFE_NO_PAD.encode(ns);
        uri.push_str("?tns=");
        uri.push_str(&ns_encoded);

        if let Some(t) = track {
            let t_encoded = URL_SAFE_NO_PAD.encode(t);
            uri.push_str("&tn=");
            uri.push_str(&t_encoded);
        }
    }

    uri
}

pub fn generate_jti() -> String {
    uuid::Uuid::new_v4().to_string()
}

/// Compute access token hash (ath) for DPoP binding
/// Returns base64url-encoded SHA-256 hash of the access token
pub fn compute_access_token_hash(access_token: &str) -> String {
    let hash = crate::crypto::hash_sha256(access_token.as_bytes());
    URL_SAFE_NO_PAD.encode(hash)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Es256Algorithm;

    #[cfg(feature = "moqt")]
    #[test]
    fn test_dpop_proof_creation() {
        let alg = Es256Algorithm::new_with_key_pair().unwrap();
        let jwk = Jwk::from_es256_verifying_key(alg.verifying_key()).unwrap();

        let mut proof =
            DpopProof::create_for_moqt(MoqtAction::Subscribe, b"namespace", b"track", "ES256", jwk);

        proof.sign(&alg).unwrap();
        assert!(!proof.signature.is_empty());

        let encoded = proof.encode().unwrap();
        let decoded = DpopProof::decode(&encoded).unwrap();

        assert_eq!(decoded.header.typ, DPOP_TYP);
        assert_eq!(decoded.payload.actx.action, MoqtAction::Subscribe as i32);
    }

    #[cfg(feature = "moqt")]
    #[test]
    fn test_dpop_validation() {
        let alg = Es256Algorithm::new_with_key_pair().unwrap();
        let jwk = Jwk::from_es256_verifying_key(alg.verifying_key()).unwrap();
        let thumbprint = jwk.thumbprint().unwrap();

        let mut proof =
            DpopProof::create_for_moqt(MoqtAction::Subscribe, b"namespace", b"track", "ES256", jwk)
                .with_jti(generate_jti());

        proof.sign(&alg).unwrap();

        let settings = CatDpopSettings::new().with_window(300);
        let validator = DpopValidator::new(settings);

        // Use validate_with_algorithm for full validation including signature verification
        validator
            .validate_with_algorithm(&proof, MoqtAction::Subscribe, &thumbprint, &alg)
            .unwrap();
    }

    #[cfg(feature = "moqt")]
    #[test]
    fn test_moqt_uri_construction() {
        let uri = construct_moqt_uri("relay.example.com", None, None);
        assert_eq!(uri, "moqt://relay.example.com");

        let uri = construct_moqt_uri("relay.example.com", Some(b"ns"), Some(b"track"));
        assert!(uri.contains("?tns="));
        assert!(uri.contains("&tn="));
    }

    #[cfg(feature = "moqt")]
    #[test]
    fn test_authorization_context() {
        let actx =
            AuthorizationContext::new_moqt(MoqtAction::Publish, b"my-namespace", b"my-track");

        assert_eq!(actx.ctx_type, "moqt");
        assert_eq!(actx.action, MoqtAction::Publish as i32);
        assert!(actx.is_valid());
        assert_eq!(actx.action_string(), "PUBLISH");
    }

    #[test]
    fn test_confirmation_claim() {
        let alg = Es256Algorithm::new_with_key_pair().unwrap();
        let jwk = Jwk::from_es256_verifying_key(alg.verifying_key()).unwrap();

        let cnf = confirmation_from_jwk(&jwk).unwrap();
        assert_eq!(cnf.jkt.len(), 32);
        assert!(confirmation_matches_jwk(&cnf, &jwk).unwrap());
    }
}
