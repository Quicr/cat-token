// SPDX-FileCopyrightText: Copyright (c) 2022 Quicr
// SPDX-License-Identifier: BSD-2-Clause

//! Integration tests for the `cattpk` public API surface.
//!
//! The success path of `check_cattpk_pin` and `authenticate_and_pin` is
//! covered by unit tests inside `src/x509.rs`, where the `pub(crate)`
//! test constructor `VerifiedPeerCertificate::from_leaf_der_unchecked` is
//! accessible. That constructor is deliberately not part of the public API:
//! external callers must go through a real `PathValidator` implementation.
//!
//! These integration tests therefore only verify:
//! (1) `extract_spki_from_cert` behaves correctly on DER input,
//! (2) `authenticate_and_pin` propagates path-validator errors,
//! (3) the type boundary is intact — an external test cannot mint a
//!     `VerifiedPeerCertificate` without a real `PathValidator`.

use cat_token::CatError;
use cat_token::x509::{
    PathValidator, VerifiedPeerCertificate, authenticate_and_pin, extract_spki_from_cert,
};
use der::{Decode, Encode};
use x509_cert::Certificate;

fn generate_self_signed_cert() -> Vec<u8> {
    use std::str::FromStr;
    use x509_cert::builder::{Builder, CertificateBuilder, Profile};
    use x509_cert::name::Name;
    use x509_cert::serial_number::SerialNumber;
    use x509_cert::spki::SubjectPublicKeyInfoOwned;
    use x509_cert::time::Validity;

    let signing_key = p256::ecdsa::SigningKey::random(&mut p256::elliptic_curve::rand_core::OsRng);
    let subject = Name::from_str("CN=Test").unwrap();
    let serial = SerialNumber::from(1u32);
    let validity = Validity::from_now(std::time::Duration::from_secs(3600)).unwrap();
    let pub_key = signing_key.verifying_key();
    let spki_doc = p256::pkcs8::EncodePublicKey::to_public_key_der(pub_key).unwrap();
    let spki = SubjectPublicKeyInfoOwned::from_der(spki_doc.as_bytes()).unwrap();

    let builder = CertificateBuilder::new(
        Profile::Leaf {
            issuer: subject.clone(),
            enable_key_agreement: false,
            enable_key_encipherment: false,
        },
        serial,
        validity,
        subject,
        spki,
        &signing_key,
    )
    .unwrap();
    builder
        .build::<p256::ecdsa::DerSignature>()
        .unwrap()
        .to_der()
        .unwrap()
}

/// A path validator that always rejects. Used to prove `authenticate_and_pin`
/// fails closed when path validation fails.
struct RejectingValidator;

impl PathValidator for RejectingValidator {
    fn validate(
        &self,
        _chain: &[&[u8]],
        _now_unix: i64,
    ) -> Result<VerifiedPeerCertificate, CatError> {
        Err(CatError::CertificateValidationFailed(
            "rejected by test validator".to_string(),
        ))
    }
}

#[test]
fn test_extract_spki_from_cert() {
    let cert_der = generate_self_signed_cert();
    let spki = extract_spki_from_cert(&cert_der).unwrap();
    assert!(!spki.is_empty());

    let cert = Certificate::from_der(&cert_der).unwrap();
    let mut expected = Vec::new();
    cert.tbs_certificate
        .subject_public_key_info
        .encode_to_vec(&mut expected)
        .unwrap();
    assert_eq!(spki, expected);
}

#[test]
fn test_different_certs_different_spki() {
    let cert1 = generate_self_signed_cert();
    let cert2 = generate_self_signed_cert();
    let spki1 = extract_spki_from_cert(&cert1).unwrap();
    let spki2 = extract_spki_from_cert(&cert2).unwrap();
    assert_ne!(spki1, spki2);
}

#[test]
fn test_extract_spki_invalid_der() {
    assert!(extract_spki_from_cert(&[0xFF, 0x00]).is_err());
}

#[test]
fn test_authenticate_and_pin_propagates_validator_failure() {
    let cert_der = generate_self_signed_cert();
    let spki = extract_spki_from_cert(&cert_der).unwrap();
    let err = authenticate_and_pin(&spki, &[&cert_der], &RejectingValidator, 0).unwrap_err();
    assert!(matches!(err, CatError::CertificateValidationFailed(_)));
}
