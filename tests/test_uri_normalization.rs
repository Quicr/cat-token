// Tests for URI normalization per RFC 3986 §6.2.2-6.2.3 and RFC 9110 §4.2.3.

use cat_token::*;

#[test]
fn test_normalize_scheme_case() {
    assert_eq!(
        normalize_uri("HTTP://example.com/").unwrap(),
        "http://example.com/"
    );
    assert_eq!(
        normalize_uri("HtTpS://example.com/").unwrap(),
        "https://example.com/"
    );
}

#[test]
fn test_normalize_host_case() {
    assert_eq!(
        normalize_uri("https://EXAMPLE.COM/path").unwrap(),
        "https://example.com/path"
    );
    assert_eq!(
        normalize_uri("https://Api.Example.Com/").unwrap(),
        "https://api.example.com/"
    );
}

#[test]
fn test_normalize_default_port_http() {
    assert_eq!(
        normalize_uri("http://example.com:80/path").unwrap(),
        "http://example.com/path"
    );
}

#[test]
fn test_normalize_default_port_https() {
    assert_eq!(
        normalize_uri("https://example.com:443/path").unwrap(),
        "https://example.com/path"
    );
}

#[test]
fn test_normalize_non_default_port_kept() {
    assert_eq!(
        normalize_uri("https://example.com:8443/path").unwrap(),
        "https://example.com:8443/path"
    );
    assert_eq!(
        normalize_uri("http://example.com:3000/path").unwrap(),
        "http://example.com:3000/path"
    );
}

#[test]
fn test_normalize_empty_path_to_slash() {
    assert_eq!(
        normalize_uri("https://example.com").unwrap(),
        "https://example.com/"
    );
}

#[test]
fn test_normalize_dot_segments() {
    assert_eq!(
        normalize_uri("https://example.com/a/b/../c").unwrap(),
        "https://example.com/a/c"
    );
    assert_eq!(
        normalize_uri("https://example.com/a/./b/./c").unwrap(),
        "https://example.com/a/b/c"
    );
    assert_eq!(
        normalize_uri("https://example.com/a/b/c/../../d").unwrap(),
        "https://example.com/a/d"
    );
}

#[test]
fn test_normalize_percent_decode_unreserved() {
    // 'a' = 0x61, 'b' = 0x62, 'z' = 0x7A
    assert_eq!(
        normalize_uri("https://example.com/%61%62%7A").unwrap(),
        "https://example.com/abz"
    );
    // Tilde is unreserved
    assert_eq!(
        normalize_uri("https://example.com/%7E").unwrap(),
        "https://example.com/~"
    );
}

#[test]
fn test_normalize_percent_uppercase_reserved() {
    assert_eq!(
        normalize_uri("https://example.com/%2f").unwrap(),
        "https://example.com/%2F"
    );
    assert_eq!(
        normalize_uri("https://example.com/a%20b").unwrap(),
        "https://example.com/a%20b"
    );
}

#[test]
fn test_normalize_preserves_query() {
    assert_eq!(
        normalize_uri("https://EXAMPLE.COM/path?key=VALUE").unwrap(),
        "https://example.com/path?key=VALUE"
    );
}

#[test]
fn test_decompose_full_uri() {
    let c = decompose_uri("https://example.com:8080/api/v1/resource.json?key=value").unwrap();
    assert_eq!(c.scheme, "https");
    assert_eq!(c.host, "example.com");
    assert_eq!(c.port, "8080");
    assert_eq!(c.path, "/api/v1/resource.json");
    assert_eq!(c.query, "key=value");
    assert_eq!(c.component(URI_COMPONENT_PARENT_PATH), "/api/v1/");
    assert_eq!(c.component(URI_COMPONENT_FILENAME), "resource.json");
    assert_eq!(c.component(URI_COMPONENT_STEM), "resource");
    assert_eq!(c.component(URI_COMPONENT_EXTENSION), "json");
}

#[test]
fn test_decompose_normalizes_first() {
    let c = decompose_uri("HTTPS://EXAMPLE.COM:443/api/../v2/data").unwrap();
    assert_eq!(c.scheme, "https");
    assert_eq!(c.host, "example.com");
    assert_eq!(c.port, "");
    assert_eq!(c.path, "/v2/data");
}

#[test]
fn test_decompose_no_path() {
    let c = decompose_uri("https://example.com").unwrap();
    assert_eq!(c.scheme, "https");
    assert_eq!(c.host, "example.com");
    assert_eq!(c.path, "/");
}

#[test]
fn test_decompose_path_only() {
    let c = decompose_uri("/api/v1/data").unwrap();
    assert_eq!(c.scheme, "");
    assert_eq!(c.host, "");
    assert_eq!(c.path, "/api/v1/data");
}

#[test]
fn test_userinfo_rejected() {
    assert!(decompose_uri("https://alice:secret@example.com/api").is_err());
    assert!(normalize_uri("https://user@example.com/").is_err());
}

#[test]
fn test_fragment_rejected() {
    assert!(decompose_uri("https://example.com/p#frag").is_err());
    assert!(normalize_uri("https://example.com/p#f").is_err());
}
