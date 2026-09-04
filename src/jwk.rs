// SPDX-FileCopyrightText: Copyright (c) 2022 Quicr
// SPDX-License-Identifier: BSD-2-Clause

use crate::CatError;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use p256::EncodedPoint;
use p256::ecdsa::VerifyingKey;
use rsa::RsaPublicKey;
use rsa::traits::PublicKeyParts;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct Jwk {
    pub kty: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub crv: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub y: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub n: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub e: Option<String>,
}

impl std::fmt::Debug for Jwk {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Jwk")
            .field("kty", &self.kty)
            .field("crv", &self.crv)
            .field("key_material", &"[REDACTED]")
            .finish()
    }
}

impl Jwk {
    pub fn from_es256_verifying_key(key: &VerifyingKey) -> Result<Self, CatError> {
        let point: EncodedPoint = key.into();
        let x_bytes = point
            .x()
            .ok_or_else(|| CatError::CryptoError("Missing x coordinate in EC point".to_string()))?;
        let y_bytes = point
            .y()
            .ok_or_else(|| CatError::CryptoError("Missing y coordinate in EC point".to_string()))?;

        Ok(Self {
            kty: "EC".to_string(),
            crv: Some("P-256".to_string()),
            x: Some(URL_SAFE_NO_PAD.encode(x_bytes)),
            y: Some(URL_SAFE_NO_PAD.encode(y_bytes)),
            n: None,
            e: None,
        })
    }

    pub fn from_rsa_public_key(key: &RsaPublicKey) -> Self {
        let n_bytes = key.n().to_bytes_be();
        let e_bytes = key.e().to_bytes_be();

        Self {
            kty: "RSA".to_string(),
            crv: None,
            x: None,
            y: None,
            n: Some(URL_SAFE_NO_PAD.encode(&n_bytes)),
            e: Some(URL_SAFE_NO_PAD.encode(&e_bytes)),
        }
    }

    pub fn thumbprint(&self) -> Result<Vec<u8>, CatError> {
        let canonical = self.canonical_json()?;
        let mut hasher = Sha256::new();
        hasher.update(canonical.as_bytes());
        Ok(hasher.finalize().to_vec())
    }

    pub fn thumbprint_base64(&self) -> Result<String, CatError> {
        let thumbprint = self.thumbprint()?;
        Ok(URL_SAFE_NO_PAD.encode(&thumbprint))
    }

    /// Validate that a string contains only safe base64url characters for JSON embedding.
    /// Base64url alphabet: A-Z, a-z, 0-9, -, _
    fn validate_base64url_safe(s: &str, field_name: &str) -> Result<(), CatError> {
        for c in s.chars() {
            if !c.is_ascii_alphanumeric() && c != '-' && c != '_' {
                return Err(CatError::InvalidClaimValue(format!(
                    "JWK {} contains invalid character '{}' (expected base64url)",
                    field_name, c
                )));
            }
        }
        Ok(())
    }

    fn canonical_json(&self) -> Result<String, CatError> {
        match self.kty.as_str() {
            "EC" => {
                let crv = self
                    .crv
                    .as_ref()
                    .ok_or_else(|| CatError::InvalidClaimValue("EC JWK missing crv".to_string()))?;
                let x = self
                    .x
                    .as_ref()
                    .ok_or_else(|| CatError::InvalidClaimValue("EC JWK missing x".to_string()))?;
                let y = self
                    .y
                    .as_ref()
                    .ok_or_else(|| CatError::InvalidClaimValue("EC JWK missing y".to_string()))?;

                // Validate fields contain only safe base64url characters
                Self::validate_base64url_safe(x, "x")?;
                Self::validate_base64url_safe(y, "y")?;
                // crv is a well-known value, but validate it doesn't contain JSON-breaking chars
                if crv.contains('"') || crv.contains('\\') {
                    return Err(CatError::InvalidClaimValue(
                        "JWK crv contains invalid characters".to_string(),
                    ));
                }

                Ok(format!(
                    r#"{{"crv":"{}","kty":"EC","x":"{}","y":"{}"}}"#,
                    crv, x, y
                ))
            }
            "RSA" => {
                let e = self
                    .e
                    .as_ref()
                    .ok_or_else(|| CatError::InvalidClaimValue("RSA JWK missing e".to_string()))?;
                let n = self
                    .n
                    .as_ref()
                    .ok_or_else(|| CatError::InvalidClaimValue("RSA JWK missing n".to_string()))?;

                // Validate fields contain only safe base64url characters
                Self::validate_base64url_safe(e, "e")?;
                Self::validate_base64url_safe(n, "n")?;

                Ok(format!(r#"{{"e":"{}","kty":"RSA","n":"{}"}}"#, e, n))
            }
            _ => Err(CatError::UnsupportedAlgorithm(format!(
                "Unsupported key type: {}",
                self.kty
            ))),
        }
    }

    pub fn to_verifying_key(&self) -> Result<VerifyingKey, CatError> {
        if self.kty != "EC" {
            return Err(CatError::InvalidClaimValue("Not an EC key".to_string()));
        }
        if self.crv.as_deref() != Some("P-256") {
            return Err(CatError::InvalidClaimValue("Not a P-256 curve".to_string()));
        }

        let x = self
            .x
            .as_ref()
            .ok_or_else(|| CatError::InvalidClaimValue("Missing x coordinate".to_string()))?;
        let y = self
            .y
            .as_ref()
            .ok_or_else(|| CatError::InvalidClaimValue("Missing y coordinate".to_string()))?;

        let x_bytes = URL_SAFE_NO_PAD
            .decode(x)
            .map_err(|e| CatError::InvalidBase64(e.to_string()))?;
        let y_bytes = URL_SAFE_NO_PAD
            .decode(y)
            .map_err(|e| CatError::InvalidBase64(e.to_string()))?;

        let mut uncompressed = vec![0x04];
        uncompressed.extend_from_slice(&x_bytes);
        uncompressed.extend_from_slice(&y_bytes);

        VerifyingKey::from_sec1_bytes(&uncompressed)
            .map_err(|e| CatError::CryptoError(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::SigningKey;
    use p256::elliptic_curve::rand_core::OsRng;

    #[test]
    fn test_ec_jwk_roundtrip() {
        let signing_key = SigningKey::random(&mut OsRng);
        let verifying_key = VerifyingKey::from(&signing_key);

        let jwk = Jwk::from_es256_verifying_key(&verifying_key).unwrap();
        assert_eq!(jwk.kty, "EC");
        assert_eq!(jwk.crv, Some("P-256".to_string()));

        let recovered = jwk.to_verifying_key().unwrap();
        assert_eq!(verifying_key, recovered);
    }

    #[test]
    fn test_ec_thumbprint() {
        let signing_key = SigningKey::random(&mut OsRng);
        let verifying_key = VerifyingKey::from(&signing_key);

        let jwk = Jwk::from_es256_verifying_key(&verifying_key).unwrap();
        let thumbprint = jwk.thumbprint().unwrap();

        assert_eq!(thumbprint.len(), 32);
    }

    #[test]
    fn test_canonical_json_ec() {
        let jwk = Jwk {
            kty: "EC".to_string(),
            crv: Some("P-256".to_string()),
            x: Some("test_x".to_string()),
            y: Some("test_y".to_string()),
            n: None,
            e: None,
        };

        let canonical = jwk.canonical_json().unwrap();
        assert!(canonical.starts_with(r#"{"crv":"P-256","kty":"EC""#));
    }

    /// Test vector from RFC 7638 Section 3.1
    /// https://datatracker.ietf.org/doc/html/rfc7638#section-3.1
    #[test]
    fn test_rfc7638_rsa_thumbprint() {
        // RSA key from RFC 7638 example
        let jwk = Jwk {
            kty: "RSA".to_string(),
            crv: None,
            x: None,
            y: None,
            n: Some("0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw".to_string()),
            e: Some("AQAB".to_string()),
        };

        let thumbprint = jwk.thumbprint_base64().unwrap();
        // Expected thumbprint from RFC 7638: NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs
        assert_eq!(thumbprint, "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs");
    }

    /// Verify canonical JSON field ordering for EC keys per RFC 7638
    #[test]
    fn test_ec_canonical_json_field_order() {
        let jwk = Jwk {
            kty: "EC".to_string(),
            crv: Some("P-256".to_string()),
            x: Some("x_value".to_string()),
            y: Some("y_value".to_string()),
            n: None,
            e: None,
        };

        let canonical = jwk.canonical_json().unwrap();
        // RFC 7638 requires alphabetical ordering: crv, kty, x, y
        assert_eq!(
            canonical,
            r#"{"crv":"P-256","kty":"EC","x":"x_value","y":"y_value"}"#
        );
    }

    /// Verify canonical JSON field ordering for RSA keys per RFC 7638
    #[test]
    fn test_rsa_canonical_json_field_order() {
        let jwk = Jwk {
            kty: "RSA".to_string(),
            crv: None,
            x: None,
            y: None,
            n: Some("n_value".to_string()),
            e: Some("e_value".to_string()),
        };

        let canonical = jwk.canonical_json().unwrap();
        // RFC 7638 requires alphabetical ordering: e, kty, n
        assert_eq!(canonical, r#"{"e":"e_value","kty":"RSA","n":"n_value"}"#);
    }
}
