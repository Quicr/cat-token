// Tests for CTA-5007-B §4.6.12: catalpn as array of byte strings.

use cat_token::*;

#[test]
fn test_catalpn_utf8_roundtrip() {
    let alg = HmacSha256Algorithm::generate_key().unwrap();
    let algorithm = HmacSha256Algorithm::from_secret_key(&alg);

    let mut token = CatToken::new().with_issuer("test");
    token.cat.catalpn = Some(vec![b"h2".to_vec(), b"h3".to_vec()]);

    let encoded = encode_token(&token, &algorithm).unwrap();
    let decoded = decode_token(&encoded, &algorithm).unwrap();

    assert_eq!(
        decoded.cat.catalpn,
        Some(vec![b"h2".to_vec(), b"h3".to_vec()])
    );
}

#[test]
fn test_catalpn_arbitrary_bytes() {
    let alg = HmacSha256Algorithm::generate_key().unwrap();
    let algorithm = HmacSha256Algorithm::from_secret_key(&alg);

    let mut token = CatToken::new().with_issuer("test");
    token.cat.catalpn = Some(vec![vec![0x01, 0x02, 0xFF], vec![0x00]]);

    let encoded = encode_token(&token, &algorithm).unwrap();
    let decoded = decode_token(&encoded, &algorithm).unwrap();

    assert_eq!(
        decoded.cat.catalpn,
        Some(vec![vec![0x01, 0x02, 0xFF], vec![0x00]])
    );
}

#[test]
fn test_catalpn_empty() {
    let mut token = CatToken::new();
    token.cat.catalpn = Some(vec![]);
    assert_eq!(token.cat.catalpn.as_ref().unwrap().len(), 0);
}
