// SPDX-FileCopyrightText: Copyright (c) 2022 Quicr
// SPDX-License-Identifier: BSD-2-Clause

use crate::CatError;
use hmac::{Hmac, Mac};
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};

pub use p256::ecdsa::VerifyingKey as Es256VerifyingKey;
use p256::elliptic_curve::rand_core::OsRng;
use p256::pkcs8::DecodePublicKey;
use ring::rand::SecureRandom;
use ring::{digest, rand};
use rsa::pss::{SigningKey as RsaSigningKey, VerifyingKey as RsaVerifyingKey};
use rsa::signature::{RandomizedSigner, SignatureEncoding, Signer, Verifier};
use rsa::traits::PublicKeyParts;
use rsa::{RsaPrivateKey, RsaPublicKey};
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop};

pub const ALG_HMAC256_256: i64 = 5;
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

pub trait CryptographicAlgorithm: Send + Sync {
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, CatError>;
    fn verify(&self, data: &[u8], signature: &[u8]) -> Result<(), CatError>;
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
        rng.fill(&mut key).map_err(|_| {
            CatError::KeyOperationFailed("Failed to generate random key".to_string())
        })?;
        Ok(SecretKey(key))
    }
}

impl CryptographicAlgorithm for HmacSha256Algorithm {
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, CatError> {
        let mut mac = HmacSha256::new_from_slice(&self.key)
            .map_err(|e| CatError::KeyOperationFailed(e.to_string()))?;
        mac.update(data);
        Ok(mac.finalize().into_bytes().to_vec())
    }

    fn verify(&self, data: &[u8], signature: &[u8]) -> Result<(), CatError> {
        let mut mac = HmacSha256::new_from_slice(&self.key)
            .map_err(|e| CatError::KeyOperationFailed(e.to_string()))?;
        mac.update(data);

        mac.verify_slice(signature)
            .map_err(|_| CatError::SignatureVerificationFailed)
    }

    fn algorithm_id(&self) -> i64 {
        ALG_HMAC256_256
    }
}

/// ES256 (ECDSA-P256-SHA256) signer/verifier.
///
/// The inner [`p256::ecdsa::SigningKey`] already implements
/// [`zeroize::ZeroizeOnDrop`] via the `ecdsa` crate, so the private
/// scalar is wiped when this struct drops. The marker
/// `impl ZeroizeOnDrop` on this type asserts that guarantee at the
/// crate boundary and prevents a future refactor from silently
/// introducing a field that does not zeroize. `VerifyingKey` is a
/// public value and is not zeroed.
pub struct Es256Algorithm {
    signing_key: Option<SigningKey>,
    verifying_key: VerifyingKey,
}

impl zeroize::ZeroizeOnDrop for Es256Algorithm {}

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
            .map_err(|e| CatError::KeyOperationFailed(format!("invalid PEM: {e}")))?;
        Ok(Self::new_verifier(verifying_key))
    }

    pub fn from_public_key_der(der: &[u8]) -> Result<Self, CatError> {
        let verifying_key = VerifyingKey::from_public_key_der(der)
            .map_err(|e| CatError::KeyOperationFailed(format!("invalid DER: {e}")))?;
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
            .ok_or_else(|| CatError::KeyOperationFailed("No signing key available".to_string()))?;

        let signature: Signature = signing_key.sign(data);
        Ok(signature.to_bytes().to_vec())
    }

    fn verify(&self, data: &[u8], signature: &[u8]) -> Result<(), CatError> {
        let signature = Signature::try_from(signature)
            .map_err(|e| CatError::KeyOperationFailed(e.to_string()))?;

        self.verifying_key
            .verify(data, &signature)
            .map_err(|_| CatError::SignatureVerificationFailed)
    }

    fn algorithm_id(&self) -> i64 {
        ALG_ES256
    }
}

/// PS256 (RSASSA-PSS-SHA256) signer/verifier.
///
/// The inner [`rsa::pss::SigningKey`] already implements
/// [`zeroize::ZeroizeOnDrop`], so the RSA private key is wiped on
/// drop. The marker `impl ZeroizeOnDrop` on this type asserts that
/// guarantee at the crate boundary and prevents a future refactor
/// from silently introducing a field that does not zeroize.
/// `RsaPublicKey` / `RsaVerifyingKey` are public values and are
/// intentionally not zeroed.
pub struct Ps256Algorithm {
    signing_key: Option<RsaSigningKey<Sha256>>,
    public_key: RsaPublicKey,
    verifying_key: RsaVerifyingKey<Sha256>,
}

impl zeroize::ZeroizeOnDrop for Ps256Algorithm {}

impl Ps256Algorithm {
    pub fn new_with_key_pair() -> Result<Self, CatError> {
        let bits = 2048;
        let private_key = RsaPrivateKey::new(&mut OsRng, bits)
            .map_err(|e| CatError::KeyOperationFailed(e.to_string()))?;
        let public_key = RsaPublicKey::from(&private_key);
        let signing_key = RsaSigningKey::<Sha256>::new(private_key);

        let verifying_key = RsaVerifyingKey::<Sha256>::new(public_key.clone());
        Ok(Self {
            signing_key: Some(signing_key),
            public_key,
            verifying_key,
        })
    }

    pub fn new_verifier(public_key: RsaPublicKey) -> Result<Self, CatError> {
        // Validate minimum RSA key size (2048 bits = 256 bytes)
        if public_key.size() < MIN_RSA_KEY_SIZE {
            return Err(CatError::KeyOperationFailed(format!(
                "RSA key too small: {} bytes (minimum {} bytes / 2048 bits required)",
                public_key.size(),
                MIN_RSA_KEY_SIZE
            )));
        }
        let verifying_key = RsaVerifyingKey::<Sha256>::new(public_key.clone());
        Ok(Self {
            signing_key: None,
            public_key,
            verifying_key,
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
            .ok_or_else(|| CatError::KeyOperationFailed("No signing key available".to_string()))?;

        let signature = signing_key.sign_with_rng(&mut OsRng, data);

        Ok(signature.to_bytes().to_vec())
    }

    fn verify(&self, data: &[u8], signature: &[u8]) -> Result<(), CatError> {
        let signature = rsa::pss::Signature::try_from(signature)
            .map_err(|e| CatError::KeyOperationFailed(e.to_string()))?;

        self.verifying_key
            .verify(data, &signature)
            .map_err(|_| CatError::SignatureVerificationFailed)
    }

    fn algorithm_id(&self) -> i64 {
        ALG_PS256
    }
}

pub fn create_signing_input(
    header_protected: &[u8],
    payload: &[u8],
    alg_id: i64,
) -> Result<Vec<u8>, CatError> {
    let context = cose_context_string(alg_id);
    create_cose_structure(context, header_protected, payload)
}

fn cose_context_string(alg_id: i64) -> &'static str {
    match alg_id {
        ALG_HMAC256_256 => "MAC0",
        _ => "Signature1",
    }
}

fn create_cose_structure(
    context: &str,
    body_protected: &[u8],
    payload: &[u8],
) -> Result<Vec<u8>, CatError> {
    let structure = ciborium::Value::Array(vec![
        ciborium::Value::Text(context.to_string()),
        ciborium::Value::Bytes(body_protected.to_vec()),
        ciborium::Value::Bytes(vec![]), // external_aad
        ciborium::Value::Bytes(payload.to_vec()),
    ]);
    let mut buf = Vec::new();
    ciborium::ser::into_writer(&structure, &mut buf)
        .map_err(|e| CatError::InvalidCbor(e.to_string()))?;
    Ok(buf)
}

pub fn hash_sha256(data: &[u8]) -> Vec<u8> {
    digest::digest(&digest::SHA256, data).as_ref().to_vec()
}

/// Constant-time byte-slice equality — prevents byte-by-byte timing
/// disclosure of the compared value.
///
/// The comparison is done by ORing `x ^ y` across every byte pair and
/// checking the accumulated bits at the end, so no branch in the inner
/// loop depends on the value of the compared bytes.
///
/// The length check is *not* constant-time: unequal lengths short-circuit
/// to `false`. That is intentional and safe for every current caller in
/// this crate: JWK thumbprints (fixed 32 bytes), signatures (fixed by
/// algorithm), and access-token hashes (fixed 32 bytes) all compare
/// values whose byte length is public. Do NOT use this helper to compare
/// variable-length secrets where the length itself would leak
/// information.
#[inline]
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    // Fold every byte pair into an accumulator so the loop's timing
    // depends only on `a.len()`, not on the position of the first
    // mismatched byte.
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    // Read the accumulator through a volatile pointer to defeat overly
    // clever LLVM optimizations that could otherwise reintroduce an
    // early-exit branch. Belt-and-suspenders — every current backend
    // already generates a straight-line xor/or loop, but the volatile
    // read pins that behavior.
    // Safety: `&diff` is a valid pointer to an `u8` on the stack.
    let observed = unsafe { std::ptr::read_volatile(&diff as *const u8) };
    observed == 0
}
