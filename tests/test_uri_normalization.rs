// Tests for URI normalization per RFC 3986 §6.2.2-6.2.3 and RFC 9110 §4.2.3.

use cat_token::*;

#[test]
fn test_normalize_scheme_case() {
    assert_eq!(normalize_uri("HTTP://example.com/"), "http://example.com/");
    assert_eq!(
        normalize_uri("HtTpS://example.com/"),
        "https://example.com/"
    );
}

#[test]
fn test_normalize_host_case() {
    assert_eq!(
        normalize_uri("https://EXAMPLE.COM/path"),
        "https://example.com/path"
    );
    assert_eq!(
        normalize_uri("https://Api.Example.Com/"),
        "https://api.example.com/"
    );
}

#[test]
fn test_normalize_default_port_http() {
    assert_eq!(
        normalize_uri("http://example.com:80/path"),
        "http://example.com/path"
    );
}

#[test]
fn test_normalize_default_port_https() {
    assert_eq!(
        normalize_uri("https://example.com:443/path"),
        "https://example.com/path"
    );
}

#[test]
fn test_normalize_non_default_port_kept() {
    assert_eq!(
        normalize_uri("https://example.com:8443/path"),
        "https://example.com:8443/path"
    );
    assert_eq!(
        normalize_uri("http://example.com:3000/path"),
        "http://example.com:3000/path"
    );
}

#[test]
fn test_normalize_empty_path_to_slash() {
    assert_eq!(normalize_uri("https://example.com"), "https://example.com/");
}

#[test]
fn test_normalize_dot_segments() {
    assert_eq!(
        normalize_uri("https://example.com/a/b/../c"),
        "https://example.com/a/c"
    );
    assert_eq!(
        normalize_uri("https://example.com/a/./b/./c"),
        "https://example.com/a/b/c"
    );
    assert_eq!(
        normalize_uri("https://example.com/a/b/c/../../d"),
        "https://example.com/a/d"
    );
}

#[test]
fn test_normalize_percent_decode_unreserved() {
    // 'a' = 0x61, 'b' = 0x62, 'z' = 0x7A
    assert_eq!(
        normalize_uri("https://example.com/%61%62%7A"),
        "https://example.com/abz"
    );
    // Tilde is unreserved
    assert_eq!(
        normalize_uri("https://example.com/%7E"),
        "https://example.com/~"
    );
}

#[test]
fn test_normalize_percent_uppercase_reserved() {
    // '/' = 0x2F is reserved, should stay encoded but uppercase
    assert_eq!(
        normalize_uri("https://example.com/%2f"),
        "https://example.com/%2F"
    );
    // Space = 0x20
    assert_eq!(
        normalize_uri("https://example.com/a%20b"),
        "https://example.com/a%20b"
    );
}

#[test]
fn test_normalize_preserves_query() {
    assert_eq!(
        normalize_uri("https://EXAMPLE.COM/path?key=VALUE"),
        "https://example.com/path?key=VALUE"
    );
}

#[test]
fn test_decompose_full_uri() {
    let c = decompose_uri("https://example.com:8080/api/v1/resource.json?key=value");
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
    let c = decompose_uri("HTTPS://EXAMPLE.COM:443/api/../v2/data");
    assert_eq!(c.scheme, "https");
    assert_eq!(c.host, "example.com");
    assert_eq!(c.port, "");
    assert_eq!(c.path, "/v2/data");
}

#[test]
fn test_decompose_no_path() {
    let c = decompose_uri("https://example.com");
    assert_eq!(c.scheme, "https");
    assert_eq!(c.host, "example.com");
    assert_eq!(c.path, "/");
}

#[test]
fn test_decompose_path_only() {
    let c = decompose_uri("/api/v1/data");
    assert_eq!(c.scheme, "");
    assert_eq!(c.host, "");
    assert_eq!(c.path, "/api/v1/data");
}
