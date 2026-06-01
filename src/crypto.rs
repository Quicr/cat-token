// SPDX-FileCopyrightText: Copyright (c) 2022 Quicr
// SPDX-License-Identifier: BSD-2-Clause

use crate::CatError;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac};
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};

pub use p256::ecdsa::VerifyingKey as Es256VerifyingKey;
use p256::elliptic_curve::rand_core::OsRng;
use p256::pkcs8::DecodePublicKey;
use ring::rand::SecureRandom;
use ring::{digest, rand};
use rsa::pkcs1v15::{SigningKey as RsaSigningKey, VerifyingKey as RsaVerifyingKey};
use rsa::signature::{RandomizedSigner, SignatureEncoding, Signer, Verifier};
use rsa::traits::PublicKeyParts;
use rsa::{RsaPrivateKey, RsaPublicKey};
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop};

pub const ALG_HMAC256_256: i64 = -4;
pub const ALG_ES256: i64 = -7;
pub const ALG_PS256: i64 = -37;

/// Convert COSE algorithm ID to JOSE algorithm string.
///
/// This helps bridge between CWT (COSE) and DPoP (JOSE) representations.
pub fn cose_to_jose_algorithm(cose_alg: i64) -> Option<&'static str> {
    match cose_alg {
        ALG_HMAC256_256 => Some("HS256"),
        ALG_ES256 => Some("ES256"),
        ALG_PS256 => Some("PS256"),
        _ => None,
    }
}

/// Convert JOSE algorithm string to COSE algorithm ID.
///
/// This helps bridge between DPoP (JOSE) and CWT (COSE) representations.
pub fn jose_to_cose_algorithm(jose_alg: &str) -> Option<i64> {
    match jose_alg {
        "HS256" => Some(ALG_HMAC256_256),
        "ES256" => Some(ALG_ES256),
        "PS256" => Some(ALG_PS256),
        _ => None,
    }
}

type HmacSha256 = Hmac<Sha256>;

/// Minimum RSA key size in bytes (2048 bits = 256 bytes)
pub const MIN_RSA_KEY_SIZE: usize = 256;

pub trait CryptographicAlgorithm {
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, CatError>;
    fn verify(&self, data: &[u8], signature: &[u8]) -> Result<bool, CatError>;
    fn algorithm_id(&self) -> i64;
}

/// A secret key wrapper that auto-zeroizes on drop
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecretKey(Vec<u8>);

impl SecretKey {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl std::fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("SecretKey")
            .field(&format!("[{} bytes]", self.0.len()))
            .finish()
    }
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct HmacSha256Algorithm {
    key: Vec<u8>,
}

impl HmacSha256Algorithm {
    pub fn new(key: &[u8]) -> Self {
        Self { key: key.to_vec() }
    }

    /// Create from a SecretKey (preferred - auto-zeroizes on drop)
    pub fn from_secret_key(key: &SecretKey) -> Self {
        Self { key: key.0.clone() }
    }

    /// Generate a new random key with auto-zeroize on drop
    pub fn generate_key() -> Result<SecretKey, CatError> {
        let rng = rand::SystemRandom::new();
        let mut key = vec![0u8; 32];
        rng.fill(&mut key)
            .map_err(|_| CatError::CryptoError("Failed to generate random key".to_string()))?;
        Ok(SecretKey(key))
    }
}

impl CryptographicAlgorithm for HmacSha256Algorithm {
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, CatError> {
        let mut mac = HmacSha256::new_from_slice(&self.key)
            .map_err(|e| CatError::CryptoError(e.to_string()))?;
        mac.update(data);
        Ok(mac.finalize().into_bytes().to_vec())
    }

    fn verify(&self, data: &[u8], signature: &[u8]) -> Result<bool, CatError> {
        let mut mac = HmacSha256::new_from_slice(&self.key)
            .map_err(|e| CatError::CryptoError(e.to_string()))?;
        mac.update(data);

        mac.verify_slice(signature)
            .map(|_| true)
            .map_err(|_| CatError::SignatureVerificationFailed)
    }

    fn algorithm_id(&self) -> i64 {
        ALG_HMAC256_256
    }
}

pub struct Es256Algorithm {
    signing_key: Option<SigningKey>,
    verifying_key: VerifyingKey,
}

impl Drop for Es256Algorithm {
    fn drop(&mut self) {
        // SigningKey from p256 crate implements Zeroize internally,
        // but we explicitly drop it here to ensure cleanup
        self.signing_key.take();
    }
}

impl Es256Algorithm {
    pub fn new_with_key_pair() -> Result<Self, CatError> {
        let signing_key = SigningKey::random(&mut OsRng);
        let verifying_key = VerifyingKey::from(&signing_key);

        Ok(Self {
            signing_key: Some(signing_key),
            verifying_key,
        })
    }

    pub fn from_key_pair(signing_key: SigningKey, verifying_key: VerifyingKey) -> Self {
        Self {
            signing_key: Some(signing_key),
            verifying_key,
        }
    }

    pub fn new_verifier(verifying_key: VerifyingKey) -> Self {
        Self {
            signing_key: None,
            verifying_key,
        }
    }

    pub fn from_public_key_pem(pem: &str) -> Result<Self, CatError> {
        let verifying_key = VerifyingKey::from_public_key_pem(pem)
            .map_err(|e| CatError::CryptoError(format!("invalid PEM: {e}")))?;
        Ok(Self::new_verifier(verifying_key))
    }

    pub fn from_public_key_der(der: &[u8]) -> Result<Self, CatError> {
        let verifying_key = VerifyingKey::from_public_key_der(der)
            .map_err(|e| CatError::CryptoError(format!("invalid DER: {e}")))?;
        Ok(Self::new_verifier(verifying_key))
    }

    pub fn verifying_key(&self) -> &VerifyingKey {
        &self.verifying_key
    }
}

impl CryptographicAlgorithm for Es256Algorithm {
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, CatError> {
        let signing_key = self
            .signing_key
            .as_ref()
            .ok_or_else(|| CatError::CryptoError("No signing key available".to_string()))?;

        let signature: Signature = signing_key.sign(data);
        Ok(signature.to_bytes().to_vec())
    }

    fn verify(&self, data: &[u8], signature: &[u8]) -> Result<bool, CatError> {
        let signature =
            Signature::try_from(signature).map_err(|e| CatError::CryptoError(e.to_string()))?;

        self.verifying_key
            .verify(data, &signature)
            .map(|_| true)
            .map_err(|_| CatError::SignatureVerificationFailed)
    }

    fn algorithm_id(&self) -> i64 {
        ALG_ES256
    }
}

pub struct Ps256Algorithm {
    signing_key: Option<RsaSigningKey<Sha256>>,
    public_key: RsaPublicKey,
}

impl Drop for Ps256Algorithm {
    fn drop(&mut self) {
        // RsaSigningKey internally holds the private key
        // Clear by taking and dropping
        self.signing_key.take();
    }
}

impl Ps256Algorithm {
    pub fn new_with_key_pair() -> Result<Self, CatError> {
        let bits = 2048;
        let private_key = RsaPrivateKey::new(&mut OsRng, bits)
            .map_err(|e| CatError::CryptoError(e.to_string()))?;
        let public_key = RsaPublicKey::from(&private_key);
        let signing_key = RsaSigningKey::<Sha256>::new(private_key);

        Ok(Self {
            signing_key: Some(signing_key),
            public_key,
        })
    }

    pub fn new_verifier(public_key: RsaPublicKey) -> Result<Self, CatError> {
        // Validate minimum RSA key size (2048 bits = 256 bytes)
        if public_key.size() < MIN_RSA_KEY_SIZE {
            return Err(CatError::CryptoError(format!(
                "RSA key too small: {} bytes (minimum {} bytes / 2048 bits required)",
                public_key.size(),
                MIN_RSA_KEY_SIZE
            )));
        }
        Ok(Self {
            signing_key: None,
            public_key,
        })
    }

    pub fn public_key(&self) -> &RsaPublicKey {
        &self.public_key
    }
}

impl CryptographicAlgorithm for Ps256Algorithm {
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, CatError> {
        let signing_key = self
            .signing_key
            .as_ref()
            .ok_or_else(|| CatError::CryptoError("No signing key available".to_string()))?;

        let signature = signing_key.sign_with_rng(&mut OsRng, data);

        Ok(signature.to_bytes().to_vec())
    }

    fn verify(&self, data: &[u8], signature: &[u8]) -> Result<bool, CatError> {
        let verifying_key = RsaVerifyingKey::<Sha256>::new(self.public_key.clone());
        let signature = rsa::pkcs1v15::Signature::try_from(signature)
            .map_err(|e| CatError::CryptoError(e.to_string()))?;

        verifying_key
            .verify(data, &signature)
            .map(|_| true)
            .map_err(|_| CatError::SignatureVerificationFailed)
    }

    fn algorithm_id(&self) -> i64 {
        ALG_PS256
    }
}

pub fn create_signing_input(header: &[u8], payload: &[u8]) -> Vec<u8> {
    let header_b64 = URL_SAFE_NO_PAD.encode(header);
    let payload_b64 = URL_SAFE_NO_PAD.encode(payload);
    format!("{}.{}", header_b64, payload_b64).into_bytes()
}

pub fn hash_sha256(data: &[u8]) -> Vec<u8> {
    digest::digest(&digest::SHA256, data).as_ref().to_vec()
}

/// Constant-time comparison to prevent timing attacks.
///
/// Note: The length comparison returns early if lengths differ. This is safe for
/// comparing fixed-length values like cryptographic hashes (SHA-256) and JWK
/// thumbprints where the length is not secret. Do not use this function for
/// comparing variable-length secrets where the length itself is sensitive.
#[inline]
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter()
        .zip(b.iter())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y))
        == 0
}
