// SPDX-FileCopyrightText: Copyright (c) 2022 Quicr
// SPDX-License-Identifier: BSD-2-Clause

use crate::CatError;
#[cfg(feature = "moqt")]
use crate::claims::CatDpopSettings;
use crate::claims::ConfirmationClaim;
use crate::jwk::Jwk;
#[cfg(feature = "moqt")]
use crate::{CryptographicAlgorithm, Es256Algorithm, MoqtAction, Ps256Algorithm};
#[cfg(feature = "moqt")]
use base64::engine::general_purpose::URL_SAFE;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
#[cfg(feature = "moqt")]
use lru::LruCache;
use serde::{Deserialize, Serialize};
#[cfg(feature = "moqt")]
use std::num::NonZeroUsize;
#[cfg(feature = "moqt")]
use std::sync::{Arc, Mutex};
#[cfg(feature = "moqt")]
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub const DPOP_TYP: &str = "dpop-proof+jwt";

/// Supported DPoP algorithms (asymmetric only per RFC 9449 §4.2)
pub const SUPPORTED_DPOP_ALGORITHMS: &[&str] = &["ES256", "PS256"];

#[cfg(feature = "moqt")]
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
    pub tns: Vec<Vec<u8>>,
    pub tn: Vec<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource: Option<String>,
}

#[cfg(feature = "moqt")]
impl AuthorizationContext {
    pub fn new_moqt(action: MoqtAction, namespace: Vec<Vec<u8>>, track: &[u8]) -> Self {
        Self {
            ctx_type: "moqt".to_string(),
            action: action as i32,
            tns: namespace,
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
    pub(crate) header: DpopHeader,
    pub(crate) payload: DpopPayload,
    pub(crate) signature: Vec<u8>,
    /// Exact bytes covered by the JWS signature: `header_b64 "." payload_b64`.
    /// Preserved verbatim on decode so that whitespace, key order, and escape
    /// choices the remote signer committed to survive round-tripping. RFC 7515
    /// §5.2 requires verification against the received input; a reserialized
    /// form is a different byte sequence and would reject valid external
    /// proofs. Populated on `sign()` for locally-built proofs.
    pub(crate) signing_input: Vec<u8>,
}

#[cfg(feature = "moqt")]
impl std::fmt::Debug for DpopProof {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DpopProof")
            .field("header", &self.header)
            .field("payload", &self.payload)
            .field("signature", &format!("[{} bytes]", self.signature.len()))
            .field(
                "signing_input",
                &format!("[{} bytes]", self.signing_input.len()),
            )
            .finish()
    }
}

#[cfg(feature = "moqt")]
fn build_signing_input(header: &DpopHeader, payload: &DpopPayload) -> Result<Vec<u8>, CatError> {
    let header_json =
        serde_json::to_string(header).map_err(|e| CatError::InvalidClaimValue(e.to_string()))?;
    let payload_json =
        serde_json::to_string(payload).map_err(|e| CatError::InvalidClaimValue(e.to_string()))?;
    let header_b64 = URL_SAFE_NO_PAD.encode(header_json.as_bytes());
    let payload_b64 = URL_SAFE_NO_PAD.encode(payload_json.as_bytes());
    Ok(format!("{header_b64}.{payload_b64}").into_bytes())
}

#[cfg(feature = "moqt")]
impl DpopProof {
    pub fn new(header: DpopHeader, payload: DpopPayload, signature: Vec<u8>) -> Self {
        Self {
            header,
            payload,
            signature,
            signing_input: Vec::new(),
        }
    }

    pub fn header(&self) -> &DpopHeader {
        &self.header
    }

    pub fn payload(&self) -> &DpopPayload {
        &self.payload
    }

    pub fn signature(&self) -> &[u8] {
        &self.signature
    }

    pub fn create_for_moqt(
        action: MoqtAction,
        namespace: Vec<Vec<u8>>,
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
            signing_input: Vec::new(),
        }
    }

    pub fn with_jti(mut self, jti: String) -> Self {
        self.payload.jti = Some(jti);
        self.signing_input.clear();
        self
    }

    pub fn with_resource(mut self, resource: String) -> Self {
        self.payload.actx.resource = Some(resource);
        self.signing_input.clear();
        self
    }

    /// Returns the exact JWS signing input this proof was verified against
    /// (for decoded proofs) or will be signed as (for locally-built proofs).
    /// For decoded proofs this is the received `header_b64.payload_b64` byte
    /// sequence and is the value that must be passed to the verifier.
    pub fn signing_input(&self) -> Result<Vec<u8>, CatError> {
        if !self.signing_input.is_empty() {
            return Ok(self.signing_input.clone());
        }
        build_signing_input(&self.header, &self.payload)
    }

    pub fn sign(&mut self, algorithm: &dyn CryptographicAlgorithm) -> Result<(), CatError> {
        self.signing_input = build_signing_input(&self.header, &self.payload)?;
        self.signature = algorithm.sign(&self.signing_input)?;
        Ok(())
    }

    pub fn encode(&self) -> Result<String, CatError> {
        let signature_b64 = URL_SAFE_NO_PAD.encode(&self.signature);
        if !self.signing_input.is_empty() {
            // Emit the exact bytes we signed, so that verifying the encoded
            // form reproduces the same signing input we used.
            let signing_str = std::str::from_utf8(&self.signing_input)
                .map_err(|_| CatError::InvalidTokenFormat)?;
            return Ok(format!("{signing_str}.{signature_b64}"));
        }
        let bytes = build_signing_input(&self.header, &self.payload)?;
        let signing_str = std::str::from_utf8(&bytes).map_err(|_| CatError::InvalidTokenFormat)?;
        Ok(format!("{signing_str}.{signature_b64}"))
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
            .or_else(|_| URL_SAFE.decode(parts[0]))
            .map_err(|e| CatError::InvalidBase64(e.to_string()))?;
        let payload_json = URL_SAFE_NO_PAD
            .decode(parts[1])
            .or_else(|_| URL_SAFE.decode(parts[1]))
            .map_err(|e| CatError::InvalidBase64(e.to_string()))?;
        let signature = URL_SAFE_NO_PAD
            .decode(parts[2])
            .or_else(|_| URL_SAFE.decode(parts[2]))
            .map_err(|e| CatError::InvalidBase64(e.to_string()))?;

        // Additional size check after decoding
        if header_json.len() > MAX_DPOP_PART_SIZE || payload_json.len() > MAX_DPOP_PART_SIZE {
            return Err(CatError::InvalidTokenFormat);
        }

        let header: DpopHeader = serde_json::from_slice(&header_json)
            .map_err(|e| CatError::InvalidClaimValue(e.to_string()))?;
        let payload: DpopPayload = serde_json::from_slice(&payload_json)
            .map_err(|e| CatError::InvalidClaimValue(e.to_string()))?;

        // Preserve the received signing input exactly. `parts[0]` and `parts[1]`
        // are borrowed from `token`, so `format!` reconstructs the byte slice
        // between them (which is a single ASCII '.').
        let signing_input = format!("{}.{}", parts[0], parts[1]).into_bytes();

        Ok(Self {
            header,
            payload,
            signature,
            signing_input,
        })
    }

    pub fn is_valid(&self, settings: &CatDpopSettings) -> bool {
        settings.validate_crit().is_ok()
            && self.header.is_valid()
            && self.payload.is_valid()
            && self.payload.is_fresh(settings.effective_window())
            && !self.signature.is_empty()
    }

    pub fn validate_with_settings(&self, settings: &CatDpopSettings) -> Result<(), CatError> {
        settings.validate_crit()?;
        if !self.header.is_valid() {
            return Err(CatError::DpopValidationFailed("Invalid header".to_string()));
        }
        if !self.payload.is_valid() {
            return Err(CatError::DpopValidationFailed(
                "Invalid payload".to_string(),
            ));
        }
        if !self.payload.is_fresh(settings.effective_window()) {
            return Err(CatError::DpopValidationFailed("Proof expired".to_string()));
        }
        if self.signature.is_empty() {
            return Err(CatError::DpopValidationFailed(
                "Missing signature".to_string(),
            ));
        }
        Ok(())
    }
}

#[cfg(feature = "moqt")]
const DEFAULT_JTI_CACHE_SIZE: usize = 100_000;

#[cfg(feature = "moqt")]
const MIN_JTI_CACHE_SIZE: usize = 1000;

#[cfg(feature = "moqt")]
pub trait JtiStore: Send + Sync {
    /// Atomically check whether `key` exists and insert it if not.
    /// Returns `Ok(())` on successful insert, or `Err(ReplayAttackDetected)` if already present.
    fn check_and_insert(&self, key: String, iat: i64) -> Result<(), CatError>;
    fn len(&self) -> usize;
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
    fn cleanup(&self, max_age_seconds: i64) {
        let _ = max_age_seconds;
    }
}

#[cfg(feature = "moqt")]
pub struct LruJtiStore {
    cache: Mutex<LruCache<String, i64>>,
    capacity: usize,
}

#[cfg(feature = "moqt")]
impl LruJtiStore {
    pub fn new(capacity: usize) -> Self {
        let effective = capacity.max(MIN_JTI_CACHE_SIZE);
        let nz = NonZeroUsize::new(effective).expect("MIN_JTI_CACHE_SIZE guarantees non-zero");
        Self {
            cache: Mutex::new(LruCache::new(nz)),
            capacity: effective,
        }
    }
}

#[cfg(feature = "moqt")]
impl JtiStore for LruJtiStore {
    fn check_and_insert(&self, key: String, iat: i64) -> Result<(), CatError> {
        let mut cache = self
            .cache
            .lock()
            .map_err(|_| CatError::CryptoError("Lock poisoned".to_string()))?;
        if cache.contains(&key) {
            return Err(CatError::ReplayAttackDetected);
        }
        if cache.len() >= self.capacity {
            return Err(CatError::DpopValidationFailed(
                "JTI cache at capacity — replay protection degraded, increase cache size"
                    .to_string(),
            ));
        }
        cache.put(key, iat);
        Ok(())
    }

    fn len(&self) -> usize {
        self.cache.lock().map(|c| c.len()).unwrap_or(0)
    }

    fn cleanup(&self, max_age_seconds: i64) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs() as i64;

        if let Ok(mut cache) = self.cache.lock() {
            let expired: Vec<String> = cache
                .iter()
                .filter(|(_, iat): &(&String, &i64)| now - **iat >= max_age_seconds)
                .map(|(k, _)| k.clone())
                .collect();
            for key in expired {
                cache.pop(&key);
            }
        }
    }
}

/// Statistics about the JTI cache
#[cfg(feature = "moqt")]
#[derive(Debug, Clone, Default)]
pub struct JtiCacheStats {
    pub size: usize,
    pub capacity: usize,
    pub under_pressure: bool,
}

#[cfg(feature = "moqt")]
pub struct DpopValidator {
    settings: CatDpopSettings,
    jti_store: Arc<dyn JtiStore>,
    jti_expiry_seconds: i64,
    cache_capacity: usize,
}

#[cfg(feature = "moqt")]
impl Clone for DpopValidator {
    fn clone(&self) -> Self {
        Self {
            settings: self.settings.clone(),
            jti_store: Arc::clone(&self.jti_store),
            jti_expiry_seconds: self.jti_expiry_seconds,
            cache_capacity: self.cache_capacity,
        }
    }
}

#[cfg(feature = "moqt")]
impl DpopValidator {
    pub fn new(settings: CatDpopSettings) -> Self {
        Self::with_cache_size(settings, DEFAULT_JTI_CACHE_SIZE)
    }

    pub fn with_cache_size(settings: CatDpopSettings, cache_size: usize) -> Self {
        let effective_size = cache_size.max(MIN_JTI_CACHE_SIZE);
        Self {
            jti_expiry_seconds: settings
                .effective_window()
                .checked_mul(2)
                .unwrap_or(i64::MAX),
            jti_store: Arc::new(LruJtiStore::new(effective_size)),
            cache_capacity: effective_size,
            settings,
        }
    }

    pub fn with_jti_store(settings: CatDpopSettings, store: Arc<dyn JtiStore>) -> Self {
        Self {
            jti_expiry_seconds: settings
                .effective_window()
                .checked_mul(2)
                .unwrap_or(i64::MAX),
            cache_capacity: 0,
            jti_store: store,
            settings,
        }
    }

    pub fn jti_cache_stats(&self) -> JtiCacheStats {
        let size = self.jti_store.len();
        let under_pressure = self.cache_capacity > 0 && size >= (self.cache_capacity * 9 / 10);
        JtiCacheStats {
            size,
            capacity: self.cache_capacity,
            under_pressure,
        }
    }

    /// Validate DPoP proof claims without JTI insertion (pre-signature-verification step).
    fn validate_claims_pre_sig(
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

        if proof.payload.jti.is_none() {
            return Err(CatError::DpopValidationFailed(
                "DPoP proof missing required jti claim".to_string(),
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

        Ok(())
    }

    fn insert_jti(
        &self,
        proof: &DpopProof,
        thumbprint: &[u8],
        issuer: Option<&str>,
    ) -> Result<(), CatError> {
        if self.settings.should_honor_jti()
            && let Some(ref jti) = proof.payload.jti
        {
            let iss = issuer.unwrap_or("_");
            let composite_key = format!("{}:{}:{}", iss, hex::encode(thumbprint), jti);
            self.jti_store
                .check_and_insert(composite_key, proof.payload.iat)?;
        }
        Ok(())
    }

    /// Derive a verifier from the proof's embedded JWK and verify the signature.
    fn verify_with_embedded_key(&self, proof: &DpopProof) -> Result<(), CatError> {
        let signing_input = proof.signing_input()?;

        match proof.header.alg.as_str() {
            "ES256" => {
                let verifying_key = proof.header.jwk.to_verifying_key()?;
                let alg = Es256Algorithm::new_verifier(verifying_key);
                alg.verify(&signing_input, &proof.signature)?;
            }
            "PS256" => {
                let rsa_pub = proof.header.jwk.to_rsa_public_key()?;
                let alg = Ps256Algorithm::new_verifier(rsa_pub)?;
                alg.verify(&signing_input, &proof.signature)?;
            }
            other => {
                return Err(CatError::DpopAlgorithmNotSupported(other.to_string()));
            }
        }

        Ok(())
    }

    pub(crate) fn validate_without_jti_commit(
        &self,
        proof: &DpopProof,
        expected_action: MoqtAction,
        expected_thumbprint: &[u8],
        _issuer: Option<&str>,
    ) -> Result<(), CatError> {
        self.validate_claims_pre_sig(proof, expected_action, expected_thumbprint, None)?;

        if !proof.header.is_supported_algorithm() {
            return Err(CatError::DpopAlgorithmNotSupported(
                proof.header.alg.clone(),
            ));
        }

        let computed_thumbprint = proof.header.jwk.thumbprint()?;
        if !crate::crypto::constant_time_eq(&computed_thumbprint, expected_thumbprint) {
            return Err(CatError::DpopKeyMismatch);
        }

        self.verify_with_embedded_key(proof)?;

        Ok(())
    }

    pub(crate) fn commit_jti(
        &self,
        proof: &DpopProof,
        thumbprint: &[u8],
        issuer: Option<&str>,
    ) -> Result<(), CatError> {
        self.insert_jti(proof, thumbprint, issuer)
    }

    /// Validate DPoP proof using the embedded JWK for signature verification.
    ///
    /// This is the recommended validation method. It derives the verification key
    /// from the JWK embedded in the proof header, verifies the thumbprint matches
    /// the expected value, and only inserts the JTI into the replay cache after
    /// successful signature verification.
    pub fn validate(
        &self,
        proof: &DpopProof,
        expected_action: MoqtAction,
        expected_thumbprint: &[u8],
        issuer: Option<&str>,
    ) -> Result<(), CatError> {
        self.validate_without_jti_commit(proof, expected_action, expected_thumbprint, issuer)?;
        self.insert_jti(proof, expected_thumbprint, issuer)?;
        Ok(())
    }

    /// Validate DPoP proof using the embedded JWK with access token hash verification.
    pub fn validate_with_ath(
        &self,
        proof: &DpopProof,
        expected_action: MoqtAction,
        expected_thumbprint: &[u8],
        access_token_hash: Option<&str>,
        issuer: Option<&str>,
    ) -> Result<(), CatError> {
        self.validate_claims_pre_sig(
            proof,
            expected_action,
            expected_thumbprint,
            access_token_hash,
        )?;

        if !proof.header.is_supported_algorithm() {
            return Err(CatError::DpopAlgorithmNotSupported(
                proof.header.alg.clone(),
            ));
        }

        let computed_thumbprint = proof.header.jwk.thumbprint()?;
        if !crate::crypto::constant_time_eq(&computed_thumbprint, expected_thumbprint) {
            return Err(CatError::DpopKeyMismatch);
        }

        self.verify_with_embedded_key(proof)?;
        self.insert_jti(proof, expected_thumbprint, issuer)?;

        Ok(())
    }

    pub fn cleanup_expired_jtis(&self) {
        self.jti_store.cleanup(self.jti_expiry_seconds);
    }
}

#[cfg(feature = "moqt")]
pub fn construct_moqt_uri(
    endpoint: &str,
    namespace: Option<&[u8]>,
    track: Option<&[u8]>,
) -> Result<String, CatError> {
    if endpoint.contains('?') || endpoint.contains('#') || endpoint.contains('/') {
        return Err(CatError::InvalidClaimValue(
            "MOQT endpoint must not contain '?', '#', or '/'".to_string(),
        ));
    }
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

    Ok(uri)
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

        let mut proof = DpopProof::create_for_moqt(
            MoqtAction::Subscribe,
            vec![b"namespace".to_vec()],
            b"track",
            "ES256",
            jwk,
        );

        proof.sign(&alg).unwrap();
        assert!(!proof.signature.is_empty());

        let encoded = proof.encode().unwrap();
        let decoded = DpopProof::decode(&encoded).unwrap();

        assert_eq!(decoded.header.typ, DPOP_TYP);
        assert_eq!(decoded.payload.actx.action, MoqtAction::Subscribe as i32);
    }

    #[cfg(feature = "moqt")]
    #[test]
    fn test_dpop_validation_with_embedded_key() {
        let alg = Es256Algorithm::new_with_key_pair().unwrap();
        let jwk = Jwk::from_es256_verifying_key(alg.verifying_key()).unwrap();
        let thumbprint = jwk.thumbprint().unwrap();

        let mut proof = DpopProof::create_for_moqt(
            MoqtAction::Subscribe,
            vec![b"namespace".to_vec()],
            b"track",
            "ES256",
            jwk,
        )
        .with_jti(generate_jti());

        proof.sign(&alg).unwrap();

        let settings = CatDpopSettings::new().with_window(300).unwrap();
        let validator = DpopValidator::new(settings);

        // Use new validate() which derives the key from the embedded JWK
        validator
            .validate(&proof, MoqtAction::Subscribe, &thumbprint, None)
            .unwrap();
    }

    #[cfg(feature = "moqt")]
    #[test]
    fn test_moqt_uri_construction() {
        let uri = construct_moqt_uri("relay.example.com", None, None).unwrap();
        assert_eq!(uri, "moqt://relay.example.com");

        let uri = construct_moqt_uri("relay.example.com", Some(b"ns"), Some(b"track")).unwrap();
        assert!(uri.contains("?tns="));
        assert!(uri.contains("&tn="));

        assert!(construct_moqt_uri("relay.example.com/path", None, None).is_err());
        assert!(construct_moqt_uri("relay.example.com?q=1", None, None).is_err());
    }

    #[cfg(feature = "moqt")]
    #[test]
    fn test_authorization_context() {
        let actx = AuthorizationContext::new_moqt(
            MoqtAction::Publish,
            vec![b"my-namespace".to_vec()],
            b"my-track",
        );

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
