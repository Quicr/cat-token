// Tests for P1-3: DPoP JWS signing input preservation.
//
// RFC 7515 §5.2 requires that verification operate on the received JWS
// signing input (the exact `header_b64 "." payload_b64` byte sequence) rather
// than on any reserialized form. These tests demonstrate that a proof whose
// header/payload JSON uses whitespace or key orders that the local encoder
// would not emit still verifies correctly, because we preserve the received
// bytes verbatim.

#![cfg(feature = "moqt")]

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use cat_token::dpop::{DpopProof, DpopValidator, generate_jti};
use cat_token::jwk::Jwk;
use cat_token::*;

fn sign_raw(header_json: &str, payload_json: &str, alg: &Es256Algorithm) -> (String, Vec<u8>) {
    let h = URL_SAFE_NO_PAD.encode(header_json.as_bytes());
    let p = URL_SAFE_NO_PAD.encode(payload_json.as_bytes());
    let signing_input = format!("{h}.{p}");
    let sig = alg.sign(signing_input.as_bytes()).unwrap();
    let sig_b64 = URL_SAFE_NO_PAD.encode(&sig);
    (format!("{signing_input}.{sig_b64}"), sig)
}

/// A proof serialized with whitespace between JSON tokens still verifies:
/// the received bytes are the signing input, so extra spaces don't change
/// the hash. A reserialization-based verifier would have compacted the JSON
/// and rejected the (still-valid) signature.
#[test]
fn test_verify_preserves_whitespace_in_json() {
    let alg = Es256Algorithm::new_with_key_pair().unwrap();
    let jwk = Jwk::from_es256_verifying_key(alg.verifying_key()).unwrap();
    let thumbprint = jwk.thumbprint().unwrap();

    let jwk_json = serde_json::to_string(&jwk).unwrap();
    // Whitespace after every structural token — legal JSON, but not what
    // serde_json::to_string emits by default.
    let header_json =
        format!(r#"{{ "typ": "dpop-proof+jwt" ,  "alg": "ES256" ,  "jwk": {jwk_json} }}"#);
    let now = chrono::Utc::now().timestamp();
    let jti = generate_jti();
    let payload_json = format!(
        r#"{{  "jti": "{jti}",  "iat": {now},  "actx":  {{ "type": "moqt", "action": 4, "tns": [[110,115]], "tn": [116,114,97,99,107] }}  }}"#
    );

    let (token, _sig) = sign_raw(&header_json, &payload_json, &alg);
    let proof = DpopProof::decode(&token).unwrap();

    let settings = CatDpopSettings::new().with_window(300).unwrap();
    let validator = DpopValidator::new(settings);
    validator
        .validate(&proof, MoqtAction::Subscribe, &thumbprint, None)
        .expect("proof with whitespace-formatted JSON must still verify");
}

/// Local proof creation → encode → decode → verify still succeeds. This is
/// the round-trip that all existing DPoP tests exercise; the new invariant
/// is that we're now verifying against preserved bytes, not against
/// reserialized JSON.
#[test]
fn test_local_roundtrip_uses_preserved_signing_input() {
    let alg = Es256Algorithm::new_with_key_pair().unwrap();
    let jwk = Jwk::from_es256_verifying_key(alg.verifying_key()).unwrap();
    let thumbprint = jwk.thumbprint().unwrap();

    let mut proof = DpopProof::create_for_moqt(
        MoqtAction::Subscribe,
        vec![b"ns".to_vec()],
        b"track",
        "ES256",
        jwk,
    )
    .with_jti(generate_jti());
    proof.sign(&alg).unwrap();

    let encoded = proof.encode().unwrap();
    let decoded = DpopProof::decode(&encoded).unwrap();

    // The decoded proof carries the exact signing input the encoded token
    // committed to.
    let signing_input = decoded.signing_input().unwrap();
    let expected_prefix = encoded.rsplit_once('.').unwrap().0.as_bytes();
    assert_eq!(signing_input, expected_prefix);

    let settings = CatDpopSettings::new().with_window(300).unwrap();
    let validator = DpopValidator::new(settings);
    validator
        .validate(&decoded, MoqtAction::Subscribe, &thumbprint, None)
        .unwrap();
}

/// Tampering with the header (even if the parsed struct would deserialize
/// identically) breaks the signing input and must fail verification.
#[test]
fn test_altered_header_bytes_rejected() {
    let alg = Es256Algorithm::new_with_key_pair().unwrap();
    let jwk = Jwk::from_es256_verifying_key(alg.verifying_key()).unwrap();
    let thumbprint = jwk.thumbprint().unwrap();

    let mut proof = DpopProof::create_for_moqt(
        MoqtAction::Subscribe,
        vec![b"ns".to_vec()],
        b"track",
        "ES256",
        jwk,
    )
    .with_jti(generate_jti());
    proof.sign(&alg).unwrap();

    let encoded = proof.encode().unwrap();
    let (signing_input, sig_b64) = encoded.rsplit_once('.').unwrap();
    let (header_b64, payload_b64) = signing_input.split_once('.').unwrap();

    // Re-encode the header JSON with different whitespace, producing a
    // different base64 segment that still parses to the same DpopHeader
    // struct. The signature was computed over the original bytes, so the
    // new signing input must fail.
    let hdr_bytes = URL_SAFE_NO_PAD.decode(header_b64).unwrap();
    let hdr_val: serde_json::Value = serde_json::from_slice(&hdr_bytes).unwrap();
    let hdr_reserialized = serde_json::to_string_pretty(&hdr_val).unwrap();
    let hdr_new_b64 = URL_SAFE_NO_PAD.encode(hdr_reserialized.as_bytes());
    let tampered = format!("{hdr_new_b64}.{payload_b64}.{sig_b64}");

    let decoded = DpopProof::decode(&tampered).unwrap();
    let settings = CatDpopSettings::new().with_window(300).unwrap();
    let validator = DpopValidator::new(settings);
    assert!(
        validator
            .validate(&decoded, MoqtAction::Subscribe, &thumbprint, None)
            .is_err(),
        "changing the header signing bytes must invalidate the signature"
    );
}
