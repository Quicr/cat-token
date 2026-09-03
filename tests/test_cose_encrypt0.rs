// SPDX-FileCopyrightText: Copyright (c) 2022 Quicr
// SPDX-License-Identifier: BSD-2-Clause

use cat_token::encrypt::{EncryptionAlgorithm, cose_decrypt0, cose_encrypt0};

#[test]
fn test_a128gcm_roundtrip() {
    let key = [0xABu8; 16];
    let plaintext = b"hello world";
    let ciphertext = cose_encrypt0(plaintext, &key, &EncryptionAlgorithm::A128Gcm).unwrap();
    let decrypted = cose_decrypt0(&ciphertext, &key).unwrap();
    assert_eq!(decrypted, plaintext);
}

#[test]
fn test_a256gcm_roundtrip() {
    let key = [0xCDu8; 32];
    let plaintext = b"hello world from 256-bit";
    let ciphertext = cose_encrypt0(plaintext, &key, &EncryptionAlgorithm::A256Gcm).unwrap();
    let decrypted = cose_decrypt0(&ciphertext, &key).unwrap();
    assert_eq!(decrypted, plaintext);
}

#[test]
fn test_wrong_key_fails_decrypt() {
    let key = [0xABu8; 16];
    let wrong_key = [0xCDu8; 16];
    let plaintext = b"secret data";
    let ciphertext = cose_encrypt0(plaintext, &key, &EncryptionAlgorithm::A128Gcm).unwrap();
    assert!(cose_decrypt0(&ciphertext, &wrong_key).is_err());
}

#[test]
fn test_key_size_mismatch_128() {
    let key = [0xABu8; 15]; // wrong size
    assert!(cose_encrypt0(b"data", &key, &EncryptionAlgorithm::A128Gcm).is_err());
}

#[test]
fn test_key_size_mismatch_256() {
    let key = [0xABu8; 31]; // wrong size
    assert!(cose_encrypt0(b"data", &key, &EncryptionAlgorithm::A256Gcm).is_err());
}

#[test]
fn test_empty_plaintext_roundtrip() {
    let key = [0xABu8; 16];
    let ciphertext = cose_encrypt0(b"", &key, &EncryptionAlgorithm::A128Gcm).unwrap();
    let decrypted = cose_decrypt0(&ciphertext, &key).unwrap();
    assert!(decrypted.is_empty());
}

#[test]
fn test_cose_encrypt0_is_tagged() {
    let key = [0xABu8; 16];
    let ciphertext = cose_encrypt0(b"test", &key, &EncryptionAlgorithm::A128Gcm).unwrap();
    // CBOR tag 16 is encoded as 0xD0
    assert_eq!(ciphertext[0], 0xD0);
}

#[test]
fn test_different_encryptions_differ() {
    let key = [0xABu8; 16];
    let plaintext = b"same input";
    let ct1 = cose_encrypt0(plaintext, &key, &EncryptionAlgorithm::A128Gcm).unwrap();
    let ct2 = cose_encrypt0(plaintext, &key, &EncryptionAlgorithm::A128Gcm).unwrap();
    // Random nonce means ciphertexts should differ
    assert_ne!(ct1, ct2);
    // But both decrypt to same plaintext
    assert_eq!(cose_decrypt0(&ct1, &key).unwrap(), plaintext);
    assert_eq!(cose_decrypt0(&ct2, &key).unwrap(), plaintext);
}

#[test]
fn test_invalid_cbor_fails() {
    let key = [0xABu8; 16];
    assert!(cose_decrypt0(&[0xFF, 0xFF], &key).is_err());
}

#[test]
fn test_large_plaintext_roundtrip() {
    let key = [0x42u8; 32];
    let plaintext = vec![0xBB; 10_000];
    let ciphertext = cose_encrypt0(&plaintext, &key, &EncryptionAlgorithm::A256Gcm).unwrap();
    let decrypted = cose_decrypt0(&ciphertext, &key).unwrap();
    assert_eq!(decrypted, plaintext);
}
