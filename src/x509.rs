// SPDX-FileCopyrightText: Copyright (c) 2022 Quicr
// SPDX-License-Identifier: BSD-2-Clause

use crate::CatError;
use der::Decode;
use x509_cert::Certificate;

/// Extract the SubjectPublicKeyInfo (SPKI) DER bytes from a DER-encoded X.509 certificate.
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

/// Validate that a presented X.509 certificate (DER-encoded) matches the
/// cattpk claim. The cattpk claim holds the expected SPKI DER bytes.
pub fn validate_cattpk(cattpk: &[u8], cert_der: &[u8]) -> Result<(), CatError> {
    let spki = extract_spki_from_cert(cert_der)?;
    if spki == cattpk {
        Ok(())
    } else {
        Err(CatError::CertificateValidationFailed(
            "Certificate SPKI does not match cattpk claim".to_string(),
        ))
    }
}

/// Validate a certificate chain where the leaf certificate must match the
/// cattpk claim. Takes a chain of DER-encoded certificates where the first
/// is the leaf (end-entity) certificate.
pub fn validate_cattpk_chain(cattpk: &[u8], cert_chain_der: &[&[u8]]) -> Result<(), CatError> {
    if cert_chain_der.is_empty() {
        return Err(CatError::CertificateValidationFailed(
            "Empty certificate chain".to_string(),
        ));
    }
    validate_cattpk(cattpk, cert_chain_der[0])
}
