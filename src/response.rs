// SPDX-FileCopyrightText: Copyright (c) 2022 Quicr
// SPDX-License-Identifier: BSD-2-Clause

use crate::CatError;
use crate::pipeline::ValidatedToken;

/// Cache scope for CAT-authorized responses.
///
/// The default is [`CacheScope::Private`] because CATs typically carry
/// per-user identifiers (`sub`, `cnf`, subject-scoped MOQT scopes) that a
/// shared cache must not fan out across principals. Integrators who have
/// explicitly designed a shared-cache key that segregates by principal — for
/// example, keying on the token's `sub` or on a derived pseudonymous
/// identifier — may opt into [`CacheScope::Public`], which also emits an
/// `s-maxage` for shared caches (RFC 9111 §5.2.2.10).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CacheScope {
    #[default]
    Private,
    Public,
}

#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct CatResponsePolicy {
    pub cache_control: String,
    pub additional_headers: Vec<(String, String)>,
}

impl CatResponsePolicy {
    /// Build a response policy for a validated token. Emits `Cache-Control:
    /// private` — the safe default — plus a `max-age` derived from the
    /// token's `exp` claim when present. Fails closed if any header value
    /// derived from claims contains control characters; a silent-strip
    /// approach would let a hostile issuer smuggle a CRLF past downstream
    /// serializers even though the token appeared to validate.
    ///
    /// Integrators who have designed a principal-segregated shared cache
    /// should call [`Self::for_token_with_scope`] with
    /// [`CacheScope::Public`] instead.
    pub fn for_token(token: &ValidatedToken) -> Result<Self, CatError> {
        Self::for_token_with_scope(token, CacheScope::Private)
    }

    /// Build a response policy with an explicit cache scope. See
    /// [`CacheScope`] for the caller responsibilities when selecting
    /// [`CacheScope::Public`].
    pub fn for_token_with_scope(
        token: &ValidatedToken,
        scope: CacheScope,
    ) -> Result<Self, CatError> {
        let mut cache_control = match scope {
            CacheScope::Private => "private".to_string(),
            CacheScope::Public => "public".to_string(),
        };

        if let Some(exp) = token.claims().core.exp {
            let now = chrono::Utc::now().timestamp();
            // An extreme signed `exp` (e.g. i64::MIN from a hostile token) would
            // wrap or panic under plain subtraction. Treat overflow as "no
            // cacheable remainder" rather than emitting a max-age derived from
            // wrap semantics — the caller has already validated exp against
            // now separately, so this is a defensive floor.
            match exp.checked_sub(now) {
                Some(remaining) if remaining > 0 => {
                    cache_control.push_str(&format!(", max-age={remaining}"));
                    if scope == CacheScope::Public {
                        cache_control.push_str(&format!(", s-maxage={remaining}"));
                    }
                }
                _ => cache_control.push_str(", no-cache"),
            }
        }

        let mut additional_headers = Vec::new();

        if let Some(ref catifdata) = token.claims().informational.catifdata {
            let joined = catifdata.join(", ");
            validate_header_value("X-CAT-Interface", &joined)?;
            additional_headers.push(("X-CAT-Interface".to_string(), joined));
        }

        Ok(Self {
            cache_control,
            additional_headers,
        })
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

/// Validate an HTTP header value: reject NUL, CR, LF, and other C0 controls
/// (HTAB is permitted per RFC 9110 §5.5). Reject on encounter rather than
/// silently strip — a caller that trusts a "sanitized" value would still be
/// mis-attributing the token's intent.
pub fn validate_header_value(name: &str, value: &str) -> Result<(), CatError> {
    for c in value.chars() {
        // Allow HTAB (\t) but reject every other C0 control and DEL (0x7F).
        if (c.is_control() && c != '\t') || c == '\x7f' {
            return Err(CatError::InvalidClaimValue(format!(
                "header '{name}' value contains prohibited control character U+{:04X}",
                c as u32
            )));
        }
    }
    Ok(())
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

        let policy = CatResponsePolicy::for_token(&validated).unwrap();
        assert!(policy.cache_control.starts_with("private, max-age="));
    }

    #[test]
    fn test_token_policy_extreme_exp_does_not_panic() {
        // A hostile token with i64::MIN exp would wrap or panic under plain
        // subtraction; verify the checked path emits no-cache instead.
        let mut token = CatTokenBuilder::new()
            .issuer("https://test.com")
            .build()
            .unwrap();
        token.core.exp = Some(i64::MIN);
        let validated = ValidatedToken::from_unchecked(token);

        let policy = CatResponsePolicy::for_token(&validated).unwrap();
        assert_eq!(policy.cache_control, "private, no-cache");
    }

    #[test]
    fn test_token_policy_public_scope_adds_s_maxage() {
        let token = CatTokenBuilder::new()
            .issuer("https://test.com")
            .expires_at(Utc::now() + Duration::hours(1))
            .build()
            .unwrap();
        let validated = ValidatedToken::from_unchecked(token);

        let policy =
            CatResponsePolicy::for_token_with_scope(&validated, CacheScope::Public).unwrap();
        assert!(
            policy.cache_control.starts_with("public, max-age="),
            "got: {}",
            policy.cache_control
        );
        assert!(
            policy.cache_control.contains(", s-maxage="),
            "expected s-maxage for public scope; got: {}",
            policy.cache_control
        );
    }

    #[test]
    fn test_token_policy_default_is_private() {
        let token = CatTokenBuilder::new()
            .issuer("https://test.com")
            .expires_at(Utc::now() + Duration::hours(1))
            .build()
            .unwrap();
        let validated = ValidatedToken::from_unchecked(token);

        let policy = CatResponsePolicy::for_token(&validated).unwrap();
        assert!(policy.cache_control.starts_with("private, max-age="));
        assert!(!policy.cache_control.contains("s-maxage"));
    }

    #[test]
    fn test_token_policy_without_expiry() {
        let token = CatTokenBuilder::new()
            .issuer("https://test.com")
            .build()
            .unwrap();
        let validated = ValidatedToken::from_unchecked(token);

        let policy = CatResponsePolicy::for_token(&validated).unwrap();
        assert_eq!(policy.cache_control, "private");
    }

    #[test]
    fn test_header_value_rejects_crlf() {
        assert!(validate_header_value("X-Header", "value").is_ok());
        assert!(validate_header_value("X-Header", "with\r\nCRLF").is_err());
        assert!(validate_header_value("X-Header", "with\nLF").is_err());
        assert!(validate_header_value("X-Header", "with\x00NUL").is_err());
        // HTAB is permitted per RFC 9110 §5.5.
        assert!(validate_header_value("X-Header", "with\ttab").is_ok());
    }

    #[test]
    fn test_for_token_rejects_control_char_in_catifdata() {
        let mut token = CatTokenBuilder::new()
            .issuer("https://test.com")
            .interface_data("legitimate")
            .build()
            .unwrap();
        token
            .informational
            .catifdata
            .as_mut()
            .unwrap()
            .push("hostile\r\nInjected-Header: yes".to_string());
        let validated = ValidatedToken::from_unchecked(token);

        assert!(matches!(
            CatResponsePolicy::for_token(&validated),
            Err(CatError::InvalidClaimValue(_))
        ));
    }

    #[test]
    fn test_sanitize_uri() {
        let uri = "https://example.com/video?cat=abc123&quality=hd";
        let sanitized = sanitize_uri_for_cache(uri);
        assert!(!sanitized.contains("cat=abc123"));
        assert!(sanitized.contains("quality=hd"));
    }
}
