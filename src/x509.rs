// SPDX-FileCopyrightText: Copyright (c) 2022 Quicr
// SPDX-License-Identifier: BSD-2-Clause

//! `cattpk` SPKI pinning as a post-check to real path validation.
//!
//! This module deliberately does **not** implement RFC 5280 path validation:
//! it verifies no signatures, has no trust anchor, and enforces none of the
//! extension constraints (BasicConstraints, KeyUsage, EKU, NameConstraints,
//! PolicyConstraints, path length, algorithm policy, revocation).
//!
//! It provides a single narrow operation: given a certificate whose chain has
//! already been validated by a real X.509 validator (e.g. `rustls`, `webpki`),
//! confirm that its SubjectPublicKeyInfo matches the SPKI DER bytes that the
//! CAT `cattpk` claim pins.
//!
//! The API is shaped so this ordering is enforced by the type system: the pin
//! check accepts only a [`VerifiedPeerCertificate`], and the only way to
//! construct one is through [`PathValidator::validate`]. Callers are expected
//! to implement `PathValidator` as a thin adapter around whatever validator
//! actually terminated the TLS handshake — this crate provides no default
//! implementation on purpose. Using pinning without such a validator gives no
//! assurance that the presented certificate was legitimately issued.
//!
//! Note: for **operator-controlled** certificates whose provenance is already
//! trusted (e.g. computing the pin to embed in a CAT token during token
//! issuance), use [`extract_spki_from_cert`] directly on the DER bytes. That
//! utility is not a validation entry point.

use crate::CatError;
use der::Decode;
use x509_cert::Certificate;

/// Extract the SubjectPublicKeyInfo (SPKI) DER bytes from a DER-encoded X.509
/// certificate. Useful for **issuers** computing the pin value to embed in a
/// token; not a validation entry point.
pub fn extract_spki_from_cert(cert_der: &[u8]) -> Result<Vec<u8>, CatError> {
    let cert = Certificate::from_der(cert_der).map_err(|e| {
        CatError::CertificateValidationFailed(format!("Failed to parse certificate: {e}"))
    })?;

    let spki = &cert.tbs_certificate.subject_public_key_info;
    let mut buf = Vec::new();
    der::Encode::encode_to_vec(spki, &mut buf).map_err(|e| {
        CatError::CertificateValidationFailed(format!("Failed to encode SPKI: {e}"))
    })?;
    Ok(buf)
}

/// A leaf certificate the caller has already authenticated through a real
/// X.509 path validator.
///
/// The only way to obtain one is [`PathValidator::validate`]; the internal
/// constructor is private to this module. A `VerifiedPeerCertificate` is
/// therefore evidence that *some* implementation of `PathValidator` — the one
/// the operator wired up — accepted the peer's chain.
///
/// Downstream code (in particular [`check_cattpk_pin`]) can require this type
/// in its signature to make it structurally impossible to run an SPKI pin
/// check against an unvalidated certificate.
#[derive(Clone, Debug)]
pub struct VerifiedPeerCertificate {
    leaf_der: Vec<u8>,
}

impl VerifiedPeerCertificate {
    /// Returns the DER-encoded leaf certificate.
    pub fn leaf_der(&self) -> &[u8] {
        &self.leaf_der
    }

    /// Test-only constructor for the crate's own unit tests. Not part of the
    /// public API — integration tests that need to exercise `check_cattpk_pin`
    /// must supply a real (or stub) [`PathValidator`] implementation.
    #[cfg(test)]
    pub(crate) fn from_leaf_der_unchecked(leaf_der: Vec<u8>) -> Self {
        Self { leaf_der }
    }
}

/// Adapter trait: a full RFC 5280 path validator that terminates in a
/// [`VerifiedPeerCertificate`] on success.
///
/// This crate intentionally ships no implementation. A production caller must
/// provide one that delegates to a real validator (`rustls`/`webpki` server
/// verifier, an OS trust store, etc.) — the trait exists only to make the
/// unforgeable-witness pattern work: no `VerifiedPeerCertificate` can be
/// constructed outside a `PathValidator::validate` call (or the test-only
/// `from_leaf_der_unchecked` constructor).
///
/// The receiver's implementation must return the DER of the peer's leaf
/// (end-entity) certificate; the crate uses that leaf for the SPKI pin check.
pub trait PathValidator {
    /// Validate the DER-encoded certificate `chain` at the given
    /// `now_unix` timestamp. `chain[0]` is expected to be the leaf.
    ///
    /// On success, return a `VerifiedPeerCertificate` wrapping the leaf DER.
    /// On any failure (signature, expiry, trust anchor, revocation, name
    /// constraints, etc.), return `CatError::CertificateValidationFailed`.
    fn validate(&self, chain: &[&[u8]], now_unix: i64)
    -> Result<VerifiedPeerCertificate, CatError>;
}

/// Constant-time SPKI pin check against the `cattpk` claim value.
///
/// Signature is deliberately narrow: callers pass a `VerifiedPeerCertificate`
/// obtained from their own `PathValidator`. If the two SPKI values are equal
/// in constant time, returns `Ok(())`; otherwise returns
/// `CatError::CertificateValidationFailed`.
pub fn check_cattpk_pin(cattpk: &[u8], verified: &VerifiedPeerCertificate) -> Result<(), CatError> {
    let spki = extract_spki_from_cert(&verified.leaf_der)?;
    if crate::crypto::constant_time_eq(&spki, cattpk) {
        Ok(())
    } else {
        Err(CatError::CertificateValidationFailed(
            "peer certificate SPKI does not match cattpk pin".to_string(),
        ))
    }
}

/// Convenience: run `validator.validate(...)` and then check the resulting
/// leaf's SPKI against `cattpk`. Errors from either stage are propagated.
///
/// Fails closed: any error from the path validator aborts before the pin
/// check runs, and any pin mismatch after successful path validation still
/// rejects the request.
pub fn authenticate_and_pin<V: PathValidator + ?Sized>(
    cattpk: &[u8],
    chain: &[&[u8]],
    validator: &V,
    now_unix: i64,
) -> Result<VerifiedPeerCertificate, CatError> {
    let verified = validator.validate(chain, now_unix)?;
    check_cattpk_pin(cattpk, &verified)?;
    Ok(verified)
}

#[cfg(test)]
mod tests {
    use super::*;
    use der::{Decode, Encode};

    fn generate_self_signed_cert() -> Vec<u8> {
        use std::str::FromStr;
        use x509_cert::builder::{Builder, CertificateBuilder, Profile};
        use x509_cert::name::Name;
        use x509_cert::serial_number::SerialNumber;
        use x509_cert::spki::SubjectPublicKeyInfoOwned;
        use x509_cert::time::Validity;

        let signing_key =
            p256::ecdsa::SigningKey::random(&mut p256::elliptic_curve::rand_core::OsRng);
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

    /// Passes whatever chain it is given. Only valid inside crate unit tests
    /// where `VerifiedPeerCertificate::from_leaf_der_unchecked` is reachable.
    struct AcceptingValidator;

    impl PathValidator for AcceptingValidator {
        fn validate(
            &self,
            chain: &[&[u8]],
            _now_unix: i64,
        ) -> Result<VerifiedPeerCertificate, CatError> {
            let leaf = chain
                .first()
                .ok_or_else(|| CatError::CertificateValidationFailed("empty chain".to_string()))?;
            Ok(VerifiedPeerCertificate::from_leaf_der_unchecked(
                leaf.to_vec(),
            ))
        }
    }

    #[test]
    fn check_cattpk_pin_accepts_matching_spki() {
        let cert = generate_self_signed_cert();
        let spki = extract_spki_from_cert(&cert).unwrap();
        let verified = VerifiedPeerCertificate::from_leaf_der_unchecked(cert);
        check_cattpk_pin(&spki, &verified).unwrap();
    }

    #[test]
    fn check_cattpk_pin_rejects_mismatching_spki() {
        let cert = generate_self_signed_cert();
        let verified = VerifiedPeerCertificate::from_leaf_der_unchecked(cert);
        let err = check_cattpk_pin(&[0u8; 32], &verified).unwrap_err();
        assert!(matches!(err, CatError::CertificateValidationFailed(_)));
    }

    #[test]
    fn authenticate_and_pin_success_path() {
        let cert = generate_self_signed_cert();
        let spki = extract_spki_from_cert(&cert).unwrap();
        let verified = authenticate_and_pin(&spki, &[&cert], &AcceptingValidator, 0).unwrap();
        assert_eq!(verified.leaf_der(), &cert[..]);
    }

    #[test]
    fn authenticate_and_pin_rejects_pin_mismatch_after_valid_chain() {
        let cert = generate_self_signed_cert();
        let err = authenticate_and_pin(&[0u8; 32], &[&cert], &AcceptingValidator, 0).unwrap_err();
        assert!(matches!(err, CatError::CertificateValidationFailed(_)));
    }

    #[test]
    fn leaf_der_round_trips_through_verified_type() {
        let cert = generate_self_signed_cert();
        let verified = VerifiedPeerCertificate::from_leaf_der_unchecked(cert.clone());
        assert_eq!(verified.leaf_der(), &cert[..]);
        // Ensure the leaf is parseable DER.
        let _ = x509_cert::Certificate::from_der(verified.leaf_der()).unwrap();
        // Silence unused-import warnings from the helper.
        let mut buf = Vec::new();
        x509_cert::Certificate::from_der(verified.leaf_der())
            .unwrap()
            .tbs_certificate
            .subject_public_key_info
            .encode_to_vec(&mut buf)
            .unwrap();
    }
}
