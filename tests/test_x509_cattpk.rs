// SPDX-FileCopyrightText: Copyright (c) 2022 Quicr
// SPDX-License-Identifier: BSD-2-Clause

use cat_token::x509::{extract_spki_from_cert, validate_cattpk, validate_cattpk_chain};
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

    let cert = builder.build::<p256::ecdsa::DerSignature>().unwrap();
    cert.to_der().unwrap()
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
fn test_validate_cattpk_matching() {
    let cert_der = generate_self_signed_cert();
    let spki = extract_spki_from_cert(&cert_der).unwrap();
    assert!(validate_cattpk(&spki, &cert_der).is_ok());
}

#[test]
fn test_validate_cattpk_mismatch() {
    let cert_der = generate_self_signed_cert();
    let wrong_spki = vec![0u8; 32];
    assert!(validate_cattpk(&wrong_spki, &cert_der).is_err());
}

#[test]
fn test_validate_cattpk_chain_leaf_matches() {
    let cert_der = generate_self_signed_cert();
    let spki = extract_spki_from_cert(&cert_der).unwrap();
    assert!(validate_cattpk_chain(&spki, &[&cert_der]).is_ok());
}

#[test]
fn test_validate_cattpk_chain_empty() {
    assert!(validate_cattpk_chain(&[0u8; 32], &[]).is_err());
}

#[test]
fn test_extract_spki_invalid_der() {
    assert!(extract_spki_from_cert(&[0xFF, 0x00]).is_err());
}

#[test]
fn test_different_certs_different_spki() {
    let cert1 = generate_self_signed_cert();
    let cert2 = generate_self_signed_cert();
    let spki1 = extract_spki_from_cert(&cert1).unwrap();
    let spki2 = extract_spki_from_cert(&cert2).unwrap();
    assert_ne!(spki1, spki2);
}
