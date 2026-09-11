// URI normalization per RFC 3986 §6.2.2-6.2.3 and RFC 9110 §4.2.3.
//
// This module provides a single URI parser used across the crate. The parser
// is fail-closed for the strict CAT profile: userinfo (`user:pass@`) and
// fragments (`#frag`) are rejected because both are stripped or ignored by
// most HTTP servers/relays before authorization, creating a divergence between
// what the token grants and what the request actually names.

use crate::CatError;
use crate::claims::*;

#[derive(Debug, Clone, Default)]
pub struct UriComponents {
    pub scheme: String,
    pub host: String,
    pub port: String,
    pub path: String,
    pub query: String,
}

impl UriComponents {
    pub fn component(&self, component: i64) -> &str {
        match component {
            URI_COMPONENT_SCHEME => &self.scheme,
            URI_COMPONENT_HOST => &self.host,
            URI_COMPONENT_PORT => &self.port,
            URI_COMPONENT_PATH => &self.path,
            URI_COMPONENT_QUERY => &self.query,
            URI_COMPONENT_PARENT_PATH => self.parent_path_str(),
            URI_COMPONENT_FILENAME => self.filename_str(),
            URI_COMPONENT_STEM => self.stem_str(),
            URI_COMPONENT_EXTENSION => self.extension_str(),
            _ => "",
        }
    }

    fn parent_path_str(&self) -> &str {
        if let Some(pos) = self.path.rfind('/') {
            &self.path[..pos + 1]
        } else {
            ""
        }
    }

    fn filename_str(&self) -> &str {
        if let Some(pos) = self.path.rfind('/') {
            &self.path[pos + 1..]
        } else {
            &self.path
        }
    }

    fn stem_str(&self) -> &str {
        let filename = self.filename_str();
        if let Some(pos) = filename.rfind('.') {
            &filename[..pos]
        } else {
            filename
        }
    }

    fn extension_str(&self) -> &str {
        let filename = self.filename_str();
        if let Some(pos) = filename.rfind('.') {
            &filename[pos + 1..]
        } else {
            ""
        }
    }
}

/// Parse and normalize a URI into components. Fail-closed per the strict
/// CAT profile: userinfo, fragments, and raw non-ASCII bytes are rejected.
/// Each form either enables a divergence between the token's authorization
/// surface and the URI a relay actually applies rules to, or (in the
/// non-ASCII case) drives the `as char` byte-to-codepoint reinterpretation
/// path that would otherwise re-encode multi-byte UTF-8 bytes as Latin-1
/// codepoints and desynchronize the normalized string from the input.
pub fn decompose_uri(uri: &str) -> Result<UriComponents, CatError> {
    let normalized = normalize_uri(uri)?;
    parse_uri(&normalized)
}

fn ensure_ascii(uri: &str) -> Result<(), CatError> {
    if !uri.is_ascii() {
        return Err(CatError::InvalidClaimValue(
            "URI contains raw non-ASCII bytes; per RFC 3986 non-ASCII must be \
             percent-encoded"
                .to_string(),
        ));
    }
    Ok(())
}

fn parse_uri(uri: &str) -> Result<UriComponents, CatError> {
    ensure_ascii(uri)?;
    let mut components = UriComponents::default();

    if uri.contains('#') {
        return Err(CatError::InvalidClaimValue(
            "URI fragments are not permitted in this profile".to_string(),
        ));
    }

    let mut rest = uri;

    if let Some(pos) = rest.find("://") {
        components.scheme = rest[..pos].to_string();
        rest = &rest[pos + 3..];
    }

    let (authority, path_and_query) = if let Some(pos) = rest.find('/') {
        (&rest[..pos], &rest[pos..])
    } else if let Some(pos) = rest.find('?') {
        (&rest[..pos], &rest[pos..])
    } else {
        (rest, "")
    };

    if authority.contains('@') {
        return Err(CatError::InvalidClaimValue(
            "URI userinfo is not permitted in this profile".to_string(),
        ));
    }

    if authority.starts_with('[') {
        if let Some(bracket_end) = authority.find(']') {
            components.host = authority[..bracket_end + 1].to_string();
            let after_bracket = &authority[bracket_end + 1..];
            if let Some(port_str) = after_bracket.strip_prefix(':')
                && !port_str.is_empty()
                && port_str.chars().all(|c| c.is_ascii_digit())
            {
                components.port = port_str.to_string();
            }
        } else {
            components.host = authority.to_string();
        }
    } else if let Some(pos) = authority.rfind(':') {
        let potential_port = &authority[pos + 1..];
        if potential_port.chars().all(|c| c.is_ascii_digit()) && !potential_port.is_empty() {
            components.host = authority[..pos].to_string();
            components.port = potential_port.to_string();
        } else {
            components.host = authority.to_string();
        }
    } else {
        components.host = authority.to_string();
    }

    if let Some(pos) = path_and_query.find('?') {
        components.path = path_and_query[..pos].to_string();
        components.query = path_and_query[pos + 1..].to_string();
    } else {
        components.path = path_and_query.to_string();
    }

    Ok(components)
}

/// Normalize a URI per RFC 3986 §6.2.2-6.2.3. Rejects userinfo and fragments
/// per the strict CAT profile — see [`decompose_uri`].
pub fn normalize_uri(uri: &str) -> Result<String, CatError> {
    ensure_ascii(uri)?;
    if uri.contains('#') {
        return Err(CatError::InvalidClaimValue(
            "URI fragments are not permitted in this profile".to_string(),
        ));
    }

    let mut result = String::with_capacity(uri.len());
    let mut rest = uri;

    // §6.2.2.1 Case normalization: scheme to lowercase
    if let Some(pos) = rest.find("://") {
        result.push_str(&rest[..pos].to_ascii_lowercase());
        result.push_str("://");
        rest = &rest[pos + 3..];
    }

    let (authority, path_and_query) = if let Some(pos) = rest.find('/') {
        (&rest[..pos], &rest[pos..])
    } else if let Some(pos) = rest.find('?') {
        (&rest[..pos], &rest[pos..])
    } else {
        (rest, "")
    };

    if authority.contains('@') {
        return Err(CatError::InvalidClaimValue(
            "URI userinfo is not permitted in this profile".to_string(),
        ));
    }

    // §6.2.2.1 Case normalization: host to lowercase
    // §6.2.3 Scheme-based: remove default ports
    if let Some(colon_pos) = authority.rfind(':') {
        let host_part = &authority[..colon_pos];
        let port_part = &authority[colon_pos + 1..];
        result.push_str(&host_part.to_ascii_lowercase());

        let scheme = if result.starts_with("http://") {
            "http"
        } else if result.starts_with("https://") {
            "https"
        } else {
            ""
        };

        let default_port = match scheme {
            "http" => "80",
            "https" => "443",
            _ => "",
        };

        if port_part != default_port {
            result.push(':');
            result.push_str(port_part);
        }
    } else {
        result.push_str(&authority.to_ascii_lowercase());
    }

    let (path, query) = if let Some(pos) = path_and_query.find('?') {
        (&path_and_query[..pos], Some(&path_and_query[pos..]))
    } else {
        (path_and_query, None)
    };

    // §6.2.3 Scheme-based: empty path → "/"
    let path = if path.is_empty() { "/" } else { path };

    // §6.2.2.3 Path segment normalization (remove dot segments per RFC 3986 §5.2.4)
    let normalized_path = remove_dot_segments(path);

    // §6.2.2.2 Percent-encoding normalization
    let normalized_path = normalize_percent_encoding(&normalized_path);

    result.push_str(&normalized_path);

    if let Some(q) = query {
        result.push_str(q);
    }

    Ok(result)
}

fn remove_dot_segments(path: &str) -> String {
    let mut output: Vec<&str> = Vec::new();

    for segment in path.split('/') {
        match segment {
            "." => {}
            ".." => {
                output.pop();
            }
            s => output.push(s),
        }
    }

    let mut result = output.join("/");
    if !result.starts_with('/') && path.starts_with('/') {
        result.insert(0, '/');
    }
    if (path.ends_with("/.") || path.ends_with("/..")) && !result.ends_with('/') {
        result.push('/');
    }
    result
}

// Caller must have already run [`ensure_ascii`] on `s`. Every byte the
// loop pushes is therefore ASCII: pass-through bytes come from an ASCII
// `&str`, decoded percent-escapes are gated by [`is_unreserved`] (ASCII
// alphanumerics and `-._~`), and hex nibbles produced by
// [`to_upper_hex`] are `0-9A-F`.
fn normalize_percent_encoding(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut i = 0;

    while i < bytes.len() {
        if bytes[i] == b'%' {
            if i + 2 < bytes.len()
                && let (Some(hi), Some(lo)) = (hex_val(bytes[i + 1]), hex_val(bytes[i + 2]))
            {
                let decoded = (hi << 4) | lo;
                if is_unreserved(decoded) {
                    result.push(char::from(decoded));
                } else {
                    result.push('%');
                    result.push(to_upper_hex(hi));
                    result.push(to_upper_hex(lo));
                }
                i += 3;
            } else {
                result.push_str("%25");
                i += 1;
            }
            continue;
        }
        result.push(char::from(bytes[i]));
        i += 1;
    }

    result
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn to_upper_hex(nibble: u8) -> char {
    if nibble < 10 {
        char::from(b'0' + nibble)
    } else {
        char::from(b'A' + nibble - 10)
    }
}

// RFC 3986 §2.3: unreserved = ALPHA / DIGIT / "-" / "." / "_" / "~"
fn is_unreserved(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'-' || b == b'.' || b == b'_' || b == b'~'
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scheme_lowercase() {
        assert_eq!(
            normalize_uri("HTTP://example.com/").unwrap(),
            "http://example.com/"
        );
        assert_eq!(
            normalize_uri("HTTPS://Example.COM/path").unwrap(),
            "https://example.com/path"
        );
    }

    #[test]
    fn test_host_lowercase() {
        assert_eq!(
            normalize_uri("https://EXAMPLE.COM/").unwrap(),
            "https://example.com/"
        );
    }

    #[test]
    fn test_default_port_removal() {
        assert_eq!(
            normalize_uri("http://example.com:80/").unwrap(),
            "http://example.com/"
        );
        assert_eq!(
            normalize_uri("https://example.com:443/").unwrap(),
            "https://example.com/"
        );
        assert_eq!(
            normalize_uri("https://example.com:8080/").unwrap(),
            "https://example.com:8080/"
        );
    }

    #[test]
    fn test_empty_path() {
        assert_eq!(
            normalize_uri("https://example.com").unwrap(),
            "https://example.com/"
        );
    }

    #[test]
    fn test_dot_segments() {
        assert_eq!(
            normalize_uri("https://example.com/a/b/../c").unwrap(),
            "https://example.com/a/c"
        );
        assert_eq!(
            normalize_uri("https://example.com/a/./b").unwrap(),
            "https://example.com/a/b"
        );
        assert_eq!(
            normalize_uri("https://example.com/a/b/c/../../d").unwrap(),
            "https://example.com/a/d"
        );
    }

    #[test]
    fn test_percent_encoding_normalization() {
        assert_eq!(
            normalize_uri("https://example.com/%61%62%63").unwrap(),
            "https://example.com/abc"
        );
        assert_eq!(
            normalize_uri("https://example.com/%2f").unwrap(),
            "https://example.com/%2F"
        );
    }

    #[test]
    fn test_decompose() {
        let c = decompose_uri("https://example.com:8080/api/v1/resource.json?key=value").unwrap();
        assert_eq!(c.scheme, "https");
        assert_eq!(c.host, "example.com");
        assert_eq!(c.port, "8080");
        assert_eq!(c.path, "/api/v1/resource.json");
        assert_eq!(c.query, "key=value");
    }

    #[test]
    fn test_decompose_components() {
        let c = decompose_uri("https://example.com/api/v1/data.json").unwrap();
        assert_eq!(c.component(URI_COMPONENT_SCHEME), "https");
        assert_eq!(c.component(URI_COMPONENT_HOST), "example.com");
        assert_eq!(c.component(URI_COMPONENT_PATH), "/api/v1/data.json");
        assert_eq!(c.component(URI_COMPONENT_PARENT_PATH), "/api/v1/");
        assert_eq!(c.component(URI_COMPONENT_FILENAME), "data.json");
        assert_eq!(c.component(URI_COMPONENT_STEM), "data");
        assert_eq!(c.component(URI_COMPONENT_EXTENSION), "json");
    }

    #[test]
    fn test_userinfo_rejected() {
        assert!(decompose_uri("https://user:pass@example.com/").is_err());
        assert!(decompose_uri("https://user@example.com/").is_err());
        assert!(normalize_uri("https://alice@example.com/api").is_err());
    }

    #[test]
    fn test_fragment_rejected() {
        assert!(decompose_uri("https://example.com/path#frag").is_err());
        assert!(normalize_uri("https://example.com/path#").is_err());
        assert!(decompose_uri("https://example.com/p?k=v#f").is_err());
    }
}
