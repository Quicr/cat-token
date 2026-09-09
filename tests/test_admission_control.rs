// SPDX-FileCopyrightText: Copyright (c) 2022 Quicr
// SPDX-License-Identifier: BSD-2-Clause

use cat_token::prelude::*;
use chrono::{Duration, Utc};

fn make_token_bytes(key: &Es256Algorithm) -> Vec<u8> {
    let token = CatTokenBuilder::new()
        .issuer("https://test.com")
        .expires_at(Utc::now() + Duration::hours(1))
        .build()
        .unwrap();
    encode_token(&token, key).unwrap()
}

#[test]
fn test_admission_default_allows_normal_token() {
    let key = Es256Algorithm::new_with_key_pair().unwrap();
    let encoded = make_token_bytes(&key);
    let resolver = SingleKeyResolver::new(Es256Algorithm::new_verifier(*key.verifying_key()));
    let policy = AdmissionPolicy::new();

    let result = Decoder::with_resolver(&resolver)
        .admission(&policy)
        .decode(&encoded);
    assert!(result.is_ok());
}

#[test]
fn test_admission_rejects_oversized_token() {
    let key = Es256Algorithm::new_with_key_pair().unwrap();
    let encoded = make_token_bytes(&key);
    let resolver = SingleKeyResolver::new(Es256Algorithm::new_verifier(*key.verifying_key()));
    let policy = AdmissionPolicy::new().with_max_token_size(10);

    let result = Decoder::with_resolver(&resolver)
        .admission(&policy)
        .decode(&encoded);
    assert!(result.is_err());
}

#[test]
fn test_admission_rejects_disallowed_algorithm() {
    let key = Es256Algorithm::new_with_key_pair().unwrap();
    let encoded = make_token_bytes(&key);
    let resolver = SingleKeyResolver::new(Es256Algorithm::new_verifier(*key.verifying_key()));
    // Only allow HMAC-256 (algorithm id 5), not ES256 (algorithm id -7)
    let policy = AdmissionPolicy::new().with_allowed_algorithms(vec![5]);

    let result = Decoder::with_resolver(&resolver)
        .admission(&policy)
        .decode(&encoded);
    assert!(result.is_err());
}

#[test]
fn test_admission_allows_permitted_algorithm() {
    let key = Es256Algorithm::new_with_key_pair().unwrap();
    let encoded = make_token_bytes(&key);
    let resolver = SingleKeyResolver::new(Es256Algorithm::new_verifier(*key.verifying_key()));
    // ES256 is algorithm id -7
    let policy = AdmissionPolicy::new().with_allowed_algorithms(vec![-7]);

    let result = Decoder::with_resolver(&resolver)
        .admission(&policy)
        .decode(&encoded);
    assert!(result.is_ok());
}

#[test]
fn test_admission_rejects_missing_kid_when_required() {
    let key = Es256Algorithm::new_with_key_pair().unwrap();
    let encoded = make_token_bytes(&key);
    let resolver = SingleKeyResolver::new(Es256Algorithm::new_verifier(*key.verifying_key()));
    let policy = AdmissionPolicy::new().with_allowed_kids(vec![b"expected-kid".to_vec()]);

    let result = Decoder::with_resolver(&resolver)
        .admission(&policy)
        .decode(&encoded);
    assert!(result.is_err());
}

#[test]
fn test_admission_size_checked_before_crypto() {
    let policy = AdmissionPolicy::new().with_max_token_size(5);
    let key = Es256Algorithm::new_with_key_pair().unwrap();
    let encoded = make_token_bytes(&key);
    let wrong_key = Es256Algorithm::new_with_key_pair().unwrap();
    let resolver = SingleKeyResolver::new(wrong_key);

    // Even with wrong key, should fail on size before reaching crypto
    let result = Decoder::with_resolver(&resolver)
        .admission(&policy)
        .decode(&encoded);
    assert!(result.is_err());
}
