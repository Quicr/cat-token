// URI normalization per RFC 3986 §6.2.2-6.2.3 and RFC 9110 §4.2.3.

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

pub fn decompose_uri(uri: &str) -> UriComponents {
    let normalized = normalize_uri(uri);
    parse_uri(&normalized)
}

fn parse_uri(uri: &str) -> UriComponents {
    let mut components = UriComponents::default();
    let mut rest = uri;

    // Extract scheme
    if let Some(pos) = rest.find("://") {
        components.scheme = rest[..pos].to_string();
        rest = &rest[pos + 3..];
    }

    // Split authority from path
    let (authority, path_and_query) = if let Some(pos) = rest.find('/') {
        (&rest[..pos], &rest[pos..])
    } else if let Some(pos) = rest.find('?') {
        (&rest[..pos], &rest[pos..])
    } else {
        (rest, "")
    };

    // Parse authority: host[:port]
    if let Some(pos) = authority.rfind(':') {
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

    // Split path and query
    if let Some(pos) = path_and_query.find('?') {
        components.path = path_and_query[..pos].to_string();
        components.query = path_and_query[pos + 1..].to_string();
    } else {
        components.path = path_and_query.to_string();
    }

    components
}

pub fn normalize_uri(uri: &str) -> String {
    let mut result = String::with_capacity(uri.len());
    let mut rest = uri;

    // §6.2.2.1 Case normalization: scheme to lowercase
    if let Some(pos) = rest.find("://") {
        result.push_str(&rest[..pos].to_ascii_lowercase());
        result.push_str("://");
        rest = &rest[pos + 3..];
    }

    // Split authority from path+query
    let (authority, path_and_query) = if let Some(pos) = rest.find('/') {
        (&rest[..pos], &rest[pos..])
    } else if let Some(pos) = rest.find('?') {
        (&rest[..pos], &rest[pos..])
    } else {
        (rest, "")
    };

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

    // Process path
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

    result
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
    if path.ends_with("/.") || path.ends_with("/..") {
        if !result.ends_with('/') {
            result.push('/');
        }
    }
    result
}

fn normalize_percent_encoding(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut i = 0;

    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(hi), Some(lo)) = (
                hex_val(bytes[i + 1]),
                hex_val(bytes[i + 2]),
            ) {
                let decoded = (hi << 4) | lo;
                if is_unreserved(decoded) {
                    // §6.2.2.2: decode unreserved characters
                    result.push(decoded as char);
                } else {
                    // §6.2.2.2: uppercase hex digits for reserved/other
                    result.push('%');
                    result.push(to_upper_hex(hi));
                    result.push(to_upper_hex(lo));
                }
                i += 3;
                continue;
            }
        }
        result.push(bytes[i] as char);
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
        (b'0' + nibble) as char
    } else {
        (b'A' + nibble - 10) as char
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
        assert_eq!(normalize_uri("HTTP://example.com/"), "http://example.com/");
        assert_eq!(normalize_uri("HTTPS://Example.COM/path"), "https://example.com/path");
    }

    #[test]
    fn test_host_lowercase() {
        assert_eq!(normalize_uri("https://EXAMPLE.COM/"), "https://example.com/");
    }

    #[test]
    fn test_default_port_removal() {
        assert_eq!(normalize_uri("http://example.com:80/"), "http://example.com/");
        assert_eq!(normalize_uri("https://example.com:443/"), "https://example.com/");
        assert_eq!(normalize_uri("https://example.com:8080/"), "https://example.com:8080/");
    }

    #[test]
    fn test_empty_path() {
        assert_eq!(normalize_uri("https://example.com"), "https://example.com/");
    }

    #[test]
    fn test_dot_segments() {
        assert_eq!(normalize_uri("https://example.com/a/b/../c"), "https://example.com/a/c");
        assert_eq!(normalize_uri("https://example.com/a/./b"), "https://example.com/a/b");
        assert_eq!(normalize_uri("https://example.com/a/b/c/../../d"), "https://example.com/a/d");
    }

    #[test]
    fn test_percent_encoding_normalization() {
        // Unreserved chars should be decoded
        assert_eq!(normalize_uri("https://example.com/%61%62%63"), "https://example.com/abc");
        // Reserved chars stay encoded but with uppercase hex
        assert_eq!(normalize_uri("https://example.com/%2f"), "https://example.com/%2F");
    }

    #[test]
    fn test_decompose() {
        let c = decompose_uri("https://example.com:8080/api/v1/resource.json?key=value");
        assert_eq!(c.scheme, "https");
        assert_eq!(c.host, "example.com");
        assert_eq!(c.port, "8080");
        assert_eq!(c.path, "/api/v1/resource.json");
        assert_eq!(c.query, "key=value");
    }

    #[test]
    fn test_decompose_components() {
        let c = decompose_uri("https://example.com/api/v1/data.json");
        assert_eq!(c.component(URI_COMPONENT_SCHEME), "https");
        assert_eq!(c.component(URI_COMPONENT_HOST), "example.com");
        assert_eq!(c.component(URI_COMPONENT_PATH), "/api/v1/data.json");
        assert_eq!(c.component(URI_COMPONENT_PARENT_PATH), "/api/v1/");
        assert_eq!(c.component(URI_COMPONENT_FILENAME), "data.json");
        assert_eq!(c.component(URI_COMPONENT_STEM), "data");
        assert_eq!(c.component(URI_COMPONENT_EXTENSION), "json");
    }
}
