// SPDX-FileCopyrightText: Copyright (c) 2022 Quicr
// SPDX-License-Identifier: BSD-2-Clause

use crate::CatError;
use aes_gcm::{
    Aes128Gcm, Aes256Gcm, KeyInit, Nonce,
    aead::{Aead, AeadCore, OsRng},
};
use ciborium::Value;

const COSE_TAG_ENCRYPT0: u64 = 16;
const ALG_A128GCM: i64 = 1;
const ALG_A256GCM: i64 = 3;

pub enum EncryptionAlgorithm {
    A128Gcm,
    A256Gcm,
}

impl EncryptionAlgorithm {
    fn alg_id(&self) -> i64 {
        match self {
            EncryptionAlgorithm::A128Gcm => ALG_A128GCM,
            EncryptionAlgorithm::A256Gcm => ALG_A256GCM,
        }
    }

    fn key_size(&self) -> usize {
        match self {
            EncryptionAlgorithm::A128Gcm => 16,
            EncryptionAlgorithm::A256Gcm => 32,
        }
    }
}

fn build_enc_structure(protected: &[u8]) -> Vec<u8> {
    let structure = Value::Array(vec![
        Value::Text("Encrypt0".to_string()),
        Value::Bytes(protected.to_vec()),
        Value::Bytes(vec![]),
    ]);
    let mut buf = Vec::new();
    ciborium::ser::into_writer(&structure, &mut buf).unwrap();
    buf
}

fn encode_protected_header(alg_id: i64) -> Vec<u8> {
    let map = vec![(Value::Integer(1.into()), Value::Integer(alg_id.into()))];
    let mut buf = Vec::new();
    ciborium::ser::into_writer(&Value::Map(map), &mut buf).unwrap();
    buf
}

/// Encrypt plaintext as COSE_Encrypt0 (tag 16) per RFC 9052 §5.
pub fn cose_encrypt0(
    plaintext: &[u8],
    key: &[u8],
    algorithm: &EncryptionAlgorithm,
) -> Result<Vec<u8>, CatError> {
    if key.len() != algorithm.key_size() {
        return Err(CatError::CryptoError(format!(
            "Key size mismatch: expected {}, got {}",
            algorithm.key_size(),
            key.len()
        )));
    }

    let protected = encode_protected_header(algorithm.alg_id());
    let aad = build_enc_structure(&protected);

    let (nonce_bytes, ciphertext) = match algorithm {
        EncryptionAlgorithm::A128Gcm => {
            let cipher =
                Aes128Gcm::new_from_slice(key).map_err(|e| CatError::CryptoError(e.to_string()))?;
            let nonce = Aes128Gcm::generate_nonce(&mut OsRng);
            let ct = cipher
                .encrypt(
                    &nonce,
                    aes_gcm::aead::Payload {
                        msg: plaintext,
                        aad: &aad,
                    },
                )
                .map_err(|e| CatError::CryptoError(e.to_string()))?;
            (nonce.to_vec(), ct)
        }
        EncryptionAlgorithm::A256Gcm => {
            let cipher =
                Aes256Gcm::new_from_slice(key).map_err(|e| CatError::CryptoError(e.to_string()))?;
            let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
            let ct = cipher
                .encrypt(
                    &nonce,
                    aes_gcm::aead::Payload {
                        msg: plaintext,
                        aad: &aad,
                    },
                )
                .map_err(|e| CatError::CryptoError(e.to_string()))?;
            (nonce.to_vec(), ct)
        }
    };

    let mut unprotected = vec![(
        Value::Integer(5.into()), // IV
        Value::Bytes(nonce_bytes),
    )];
    let _ = &mut unprotected; // suppress warning

    let cose_array = Value::Array(vec![
        Value::Bytes(protected),
        Value::Map(unprotected),
        Value::Bytes(ciphertext),
    ]);

    let tagged = Value::Tag(COSE_TAG_ENCRYPT0, Box::new(cose_array));
    let mut buffer = Vec::new();
    ciborium::ser::into_writer(&tagged, &mut buffer)
        .map_err(|e| CatError::InvalidCbor(e.to_string()))?;

    Ok(buffer)
}

/// Decrypt a COSE_Encrypt0 structure.
pub fn cose_decrypt0(cose_bytes: &[u8], key: &[u8]) -> Result<Vec<u8>, CatError> {
    let value: Value =
        ciborium::de::from_reader(cose_bytes).map_err(|e| CatError::InvalidCbor(e.to_string()))?;

    let arr = match value {
        Value::Tag(tag, inner) if tag == COSE_TAG_ENCRYPT0 => match *inner {
            Value::Array(a) if a.len() == 3 => a,
            _ => return Err(CatError::InvalidTokenFormat),
        },
        _ => return Err(CatError::InvalidTokenFormat),
    };

    let protected = match &arr[0] {
        Value::Bytes(b) => b.clone(),
        _ => return Err(CatError::InvalidTokenFormat),
    };

    let nonce_bytes = match &arr[1] {
        Value::Map(map) => {
            let mut nonce = None;
            for (k, v) in map {
                if let Value::Integer(ki) = k {
                    let key_val: i64 =
                        (*ki).try_into().map_err(|_| CatError::InvalidTokenFormat)?;
                    if key_val == 5 {
                        if let Value::Bytes(b) = v {
                            nonce = Some(b.clone());
                        }
                    }
                }
            }
            nonce.ok_or(CatError::InvalidTokenFormat)?
        }
        _ => return Err(CatError::InvalidTokenFormat),
    };

    let ciphertext = match &arr[2] {
        Value::Bytes(b) => b.clone(),
        _ => return Err(CatError::InvalidTokenFormat),
    };

    let header_val: Value = ciborium::de::from_reader(protected.as_slice())
        .map_err(|e| CatError::InvalidCbor(e.to_string()))?;
    let alg_id = match header_val {
        Value::Map(map) => {
            let mut alg = None;
            for (k, v) in map {
                if let Value::Integer(ki) = k {
                    let key_val: i64 = ki.try_into().map_err(|_| CatError::InvalidTokenFormat)?;
                    if key_val == 1 {
                        if let Value::Integer(ai) = v {
                            alg = Some(ai.try_into().map_err(|_| CatError::InvalidTokenFormat)?);
                        }
                    }
                }
            }
            alg.ok_or(CatError::InvalidTokenFormat)?
        }
        _ => return Err(CatError::InvalidTokenFormat),
    };

    let aad = build_enc_structure(&protected);

    match alg_id {
        ALG_A128GCM => {
            let cipher =
                Aes128Gcm::new_from_slice(key).map_err(|e| CatError::CryptoError(e.to_string()))?;
            let nonce = Nonce::from_slice(&nonce_bytes);
            cipher
                .decrypt(
                    nonce,
                    aes_gcm::aead::Payload {
                        msg: &ciphertext,
                        aad: &aad,
                    },
                )
                .map_err(|_| CatError::CryptoError("AES-128-GCM decryption failed".to_string()))
        }
        ALG_A256GCM => {
            let cipher =
                Aes256Gcm::new_from_slice(key).map_err(|e| CatError::CryptoError(e.to_string()))?;
            let nonce = Nonce::from_slice(&nonce_bytes);
            cipher
                .decrypt(
                    nonce,
                    aes_gcm::aead::Payload {
                        msg: &ciphertext,
                        aad: &aad,
                    },
                )
                .map_err(|_| CatError::CryptoError("AES-256-GCM decryption failed".to_string()))
        }
        _ => Err(CatError::UnsupportedAlgorithm(format!(
            "Unknown encryption algorithm: {alg_id}"
        ))),
    }
}
