// Tests for COSE Key Thumbprint (ckt) confirmation method (RFC 9679).

use cat_token::*;

#[test]
fn test_ckt_on_confirmation_claim() {
    let ckt = b"cose-key-thumbprint-sha256".to_vec();
    let cnf = ConfirmationClaim::new(b"jkt-value".to_vec()).with_ckt(ckt.clone());

    assert_eq!(cnf.jkt, b"jkt-value".to_vec());
    assert_eq!(cnf.ckt, Some(ckt));
}

#[test]
fn test_ckt_only_on_token() {
    let token = CatToken::new()
        .with_cose_key_thumbprint(b"cose-thumbprint".to_vec());

    let cnf = token.dpop.cnf.unwrap();
    assert!(cnf.jkt.is_empty());
    assert_eq!(cnf.ckt.unwrap(), b"cose-thumbprint".to_vec());
}

#[test]
fn test_jkt_and_ckt_on_token() {
    let token = CatToken::new()
        .with_confirmation(b"jwk-thumbprint".to_vec())
        .with_cose_key_thumbprint(b"cose-thumbprint".to_vec());

    let cnf = token.dpop.cnf.unwrap();
    assert_eq!(cnf.jkt, b"jwk-thumbprint".to_vec());
    assert_eq!(cnf.ckt.unwrap(), b"cose-thumbprint".to_vec());
}

#[test]
fn test_ckt_roundtrip() {
    let alg = HmacSha256Algorithm::generate_key().unwrap();
    let algorithm = HmacSha256Algorithm::from_secret_key(&alg);

    let token = CatToken::new()
        .with_issuer("test")
        .with_confirmation(b"jkt-data".to_vec())
        .with_cose_key_thumbprint(b"ckt-data".to_vec());

    let encoded = encode_token(&token, &algorithm).unwrap();
    let decoded = decode_token(&encoded, &algorithm).unwrap();

    let cnf = decoded.dpop.cnf.unwrap();
    assert_eq!(cnf.jkt, b"jkt-data".to_vec());
    assert_eq!(cnf.ckt.unwrap(), b"ckt-data".to_vec());
}

#[test]
fn test_ckt_only_roundtrip() {
    let alg = HmacSha256Algorithm::generate_key().unwrap();
    let algorithm = HmacSha256Algorithm::from_secret_key(&alg);

    let token = CatToken::new()
        .with_issuer("test")
        .with_cose_key_thumbprint(b"ckt-only".to_vec());

    let encoded = encode_token(&token, &algorithm).unwrap();
    let decoded = decode_token(&encoded, &algorithm).unwrap();

    let cnf = decoded.dpop.cnf.unwrap();
    assert!(cnf.jkt.is_empty());
    assert_eq!(cnf.ckt.unwrap(), b"ckt-only".to_vec());
}

#[test]
fn test_jkt_without_ckt_roundtrip() {
    let alg = HmacSha256Algorithm::generate_key().unwrap();
    let algorithm = HmacSha256Algorithm::from_secret_key(&alg);

    let token = CatToken::new()
        .with_issuer("test")
        .with_confirmation(b"jkt-only".to_vec());

    let encoded = encode_token(&token, &algorithm).unwrap();
    let decoded = decode_token(&encoded, &algorithm).unwrap();

    let cnf = decoded.dpop.cnf.unwrap();
    assert_eq!(cnf.jkt, b"jkt-only".to_vec());
    assert!(cnf.ckt.is_none());
}

#[test]
fn test_ckt_builder() {
    let token = CatTokenBuilder::new()
        .issuer("test")
        .confirmation(b"jkt".to_vec())
        .cose_key_thumbprint(b"ckt".to_vec())
        .build();

    let cnf = token.dpop.cnf.unwrap();
    assert_eq!(cnf.jkt, b"jkt".to_vec());
    assert_eq!(cnf.ckt.unwrap(), b"ckt".to_vec());
}
