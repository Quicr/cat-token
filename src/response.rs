// SPDX-FileCopyrightText: Copyright (c) 2022 Quicr
// SPDX-License-Identifier: BSD-2-Clause

use crate::pipeline::ValidatedToken;

#[derive(Debug, Clone)]
pub struct CatResponsePolicy {
    pub cache_control: String,
    pub additional_headers: Vec<(String, String)>,
}

impl CatResponsePolicy {
    pub fn for_token(token: &ValidatedToken) -> Self {
        let mut cache_control = "private".to_string();

        if let Some(exp) = token.claims().core.exp {
            let now = chrono::Utc::now().timestamp();
            let remaining = exp - now;
            if remaining > 0 {
                cache_control.push_str(&format!(", max-age={remaining}"));
            } else {
                cache_control.push_str(", no-cache");
            }
        }

        let mut additional_headers = Vec::new();

        if let Some(ref catifdata) = token.claims().informational.catifdata {
            additional_headers.push(("X-CAT-Interface".to_string(), catifdata.join(", ")));
        }

        Self {
            cache_control,
            additional_headers,
        }
    }

    pub fn minimal() -> Self {
        Self {
            cache_control: "private".to_string(),
            additional_headers: Vec::new(),
        }
    }

    pub fn for_rejection() -> Self {
        Self {
            cache_control: "no-store".to_string(),
            additional_headers: Vec::new(),
        }
    }
}

pub fn sanitize_uri_for_cache(uri: &str) -> String {
    crate::token::strip_token_from_uri(uri, &["cat", "token", "access_token"])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CatTokenBuilder;
    use chrono::{Duration, Utc};

    #[test]
    fn test_minimal_policy() {
        let policy = CatResponsePolicy::minimal();
        assert_eq!(policy.cache_control, "private");
        assert!(policy.additional_headers.is_empty());
    }

    #[test]
    fn test_rejection_policy() {
        let policy = CatResponsePolicy::for_rejection();
        assert_eq!(policy.cache_control, "no-store");
    }

    #[test]
    fn test_token_policy_with_expiry() {
        let token = CatTokenBuilder::new()
            .issuer("https://test.com")
            .expires_at(Utc::now() + Duration::hours(1))
            .build()
            .unwrap();
        let validated = ValidatedToken::from_unchecked(token);

        let policy = CatResponsePolicy::for_token(&validated);
        assert!(policy.cache_control.starts_with("private, max-age="));
    }

    #[test]
    fn test_token_policy_without_expiry() {
        let token = CatTokenBuilder::new()
            .issuer("https://test.com")
            .build()
            .unwrap();
        let validated = ValidatedToken::from_unchecked(token);

        let policy = CatResponsePolicy::for_token(&validated);
        assert_eq!(policy.cache_control, "private");
    }

    #[test]
    fn test_sanitize_uri() {
        let uri = "https://example.com/video?cat=abc123&quality=hd";
        let sanitized = sanitize_uri_for_cache(uri);
        assert!(!sanitized.contains("cat=abc123"));
        assert!(sanitized.contains("quality=hd"));
    }
}
