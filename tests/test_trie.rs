// SPDX-FileCopyrightText: Copyright (c) 2022 Quicr
// SPDX-License-Identifier: BSD-2-Clause

#![cfg(feature = "moqt")]

use cat_token::*;

#[test]
fn test_prefix_trie_basic_operations() {
    let mut trie = PrefixTrie::new();

    // Insert patterns
    trie.insert("https://", "https".to_string());
    trie.insert("http://", "http".to_string());
    trie.insert("ftp://", "ftp".to_string());

    assert_eq!(trie.size(), 3);

    // Test prefix matching
    let matches = trie.search_prefix("https://example.com/path");
    assert!(matches.contains(&"https"));

    let matches = trie.search_prefix("http://test.org");
    assert!(matches.contains(&"http"));

    let matches = trie.search_prefix("smtp://invalid");
    assert!(matches.is_empty());

    // Test containment
    assert!(trie.contains_prefix("https://any.site"));
    assert!(trie.contains_prefix("ftp://files"));
    assert!(!trie.contains_prefix("mailto:test@example.com"));
}

#[test]
fn test_prefix_trie_overlapping_patterns() {
    let mut trie = PrefixTrie::new();

    trie.insert("api", "api".to_string());
    trie.insert("api.v1", "api-v1".to_string());
    trie.insert("api.v2", "api-v2".to_string());

    let matches = trie.search_prefix("api.v1.users");
    assert!(matches.contains(&"api"));
    assert!(matches.contains(&"api-v1"));
    assert_eq!(matches.len(), 2);
}

#[test]
fn test_prefix_trie_removal() {
    let mut trie = PrefixTrie::new();

    trie.insert("test", "test".to_string());
    trie.insert("testing", "testing".to_string());

    assert_eq!(trie.size(), 2);
    assert!(trie.contains_prefix("testing"));

    trie.remove("test");
    assert_eq!(trie.size(), 1);
    assert!(!trie.contains_prefix("test"));
    assert!(trie.contains_prefix("testing"));
}

#[test]
fn test_suffix_trie_basic_operations() {
    let mut trie = SuffixTrie::new();

    // Insert patterns
    trie.insert(".com", "com-domain".to_string());
    trie.insert(".org", "org-domain".to_string());
    trie.insert(".json", "json-file".to_string());

    assert_eq!(trie.size(), 3);

    // Test suffix matching
    let matches = trie.search_suffix("example.com");
    assert!(matches.contains(&"com-domain"));

    let matches = trie.search_suffix("data.json");
    assert!(matches.contains(&"json-file"));

    let matches = trie.search_suffix("file.txt");
    assert!(matches.is_empty());

    // Test containment
    assert!(trie.contains_suffix("test.org"));
    assert!(trie.contains_suffix("config.json"));
    assert!(!trie.contains_suffix("readme.md"));
}

#[test]
fn test_suffix_trie_overlapping_patterns() {
    let mut trie = SuffixTrie::new();

    trie.insert("ing", "gerund".to_string());
    trie.insert("ling", "ling-suffix".to_string());
    trie.insert("ring", "ring-suffix".to_string());

    let matches = trie.search_suffix("programming");
    assert!(matches.contains(&"gerund"));
    assert_eq!(matches.len(), 1);

    let matches = trie.search_suffix("startling");
    assert!(matches.contains(&"gerund"));
    assert!(matches.contains(&"ling-suffix"));
    assert_eq!(matches.len(), 2);
}

#[test]
fn test_suffix_trie_removal() {
    let mut trie = SuffixTrie::new();

    trie.insert(".html", "html".to_string());
    trie.insert(".htm", "htm".to_string());

    assert_eq!(trie.size(), 2);
    assert!(trie.contains_suffix("index.html"));

    trie.remove(".html");
    assert_eq!(trie.size(), 1);
    assert!(!trie.contains_suffix("index.html"));
    assert!(trie.contains_suffix("page.htm"));
}

#[test]
fn test_uri_matcher_comprehensive() {
    let mut matcher = UriMatcher::new();

    // Add various pattern types
    matcher
        .add_pattern(UriPattern::Exact("https://api.example.com/v1".to_string()))
        .unwrap();
    matcher
        .add_pattern(UriPattern::Prefix("https://secure.".to_string()))
        .unwrap();
    matcher
        .add_pattern(UriPattern::Suffix("/api/data".to_string()))
        .unwrap();
    matcher
        .add_pattern(UriPattern::Regex(
            r"^https://.*\.example\.com/(users|login|[^v].*)$".to_string(),
        ))
        .unwrap();

    // Test exact match
    assert!(matcher.matches("https://api.example.com/v1"));
    assert!(!matcher.matches("https://api.example.com/v2"));

    // Test prefix match
    assert!(matcher.matches("https://secure.banking.com"));
    assert!(matcher.matches("https://secure.example.org/login"));
    assert!(!matcher.matches("https://public.example.com"));

    // Test suffix match
    assert!(matcher.matches("https://service.com/api/data"));
    assert!(matcher.matches("http://localhost:8080/api/data"));
    assert!(!matcher.matches("https://service.com/api/users"));

    // Test regex match
    assert!(matcher.matches("https://api.example.com/users"));
    assert!(matcher.matches("https://auth.example.com/login"));
    assert!(!matcher.matches("https://api.other.com/users"));
}

#[test]
fn test_uri_matcher_get_matching_patterns() {
    let mut matcher = UriMatcher::new();

    matcher
        .add_pattern(UriPattern::Prefix("https://".to_string()))
        .unwrap();
    matcher
        .add_pattern(UriPattern::Suffix(".com".to_string()))
        .unwrap();
    matcher
        .add_pattern(UriPattern::Exact("https://example.com".to_string()))
        .unwrap();

    let matches = matcher.get_matching_patterns("https://example.com");

    // Should match all three patterns
    assert!(matches.iter().any(|m| m.starts_with("exact:")));
    assert!(matches.iter().any(|m| m.starts_with("prefix:")));
    assert!(matches.iter().any(|m| m.starts_with("suffix:")));
    assert_eq!(matches.len(), 3);
}

#[test]
fn test_uri_pattern_types() {
    let exact = UriPattern::Exact("test".to_string());
    let prefix = UriPattern::Prefix("test".to_string());
    let suffix = UriPattern::Suffix("test".to_string());
    let regex = UriPattern::Regex("test".to_string());
    let hash = UriPattern::Hash("test".to_string());

    match exact {
        UriPattern::Exact(s) => assert_eq!(s, "test"),
        _ => panic!("Expected Exact pattern"),
    }

    match prefix {
        UriPattern::Prefix(s) => assert_eq!(s, "test"),
        _ => panic!("Expected Prefix pattern"),
    }

    match suffix {
        UriPattern::Suffix(s) => assert_eq!(s, "test"),
        _ => panic!("Expected Suffix pattern"),
    }

    match regex {
        UriPattern::Regex(s) => assert_eq!(s, "test"),
        _ => panic!("Expected Regex pattern"),
    }

    match hash {
        UriPattern::Hash(s) => assert_eq!(s, "test"),
        _ => panic!("Expected Hash pattern"),
    }
}

#[test]
fn test_trie_get_all_patterns() {
    let mut prefix_trie = PrefixTrie::new();
    prefix_trie.insert("api", "api".to_string());
    prefix_trie.insert("app", "app".to_string());
    prefix_trie.insert("auth", "auth".to_string());

    let patterns = prefix_trie.get_all_patterns();
    assert_eq!(patterns.len(), 3);
    assert!(patterns.contains(&"api".to_string()));
    assert!(patterns.contains(&"app".to_string()));
    assert!(patterns.contains(&"auth".to_string()));

    let mut suffix_trie = SuffixTrie::new();
    suffix_trie.insert(".com", "com".to_string());
    suffix_trie.insert(".org", "org".to_string());

    let patterns = suffix_trie.get_all_patterns();
    assert_eq!(patterns.len(), 2);
    assert!(patterns.contains(&".com".to_string()));
    assert!(patterns.contains(&".org".to_string()));
}

#[test]
fn test_empty_tries() {
    let prefix_trie = PrefixTrie::new();
    let suffix_trie = SuffixTrie::new();

    assert_eq!(prefix_trie.size(), 0);
    assert_eq!(suffix_trie.size(), 0);

    assert!(prefix_trie.search_prefix("anything").is_empty());
    assert!(suffix_trie.search_suffix("anything").is_empty());

    assert!(!prefix_trie.contains_prefix("test"));
    assert!(!suffix_trie.contains_suffix("test"));

    assert!(prefix_trie.get_all_patterns().is_empty());
    assert!(suffix_trie.get_all_patterns().is_empty());
}

#[test]
fn test_case_sensitivity() {
    let mut prefix_trie = PrefixTrie::new();
    prefix_trie.insert("API", "api-upper".to_string());
    prefix_trie.insert("api", "api-lower".to_string());

    let matches = prefix_trie.search_prefix("API-test");
    assert!(matches.contains(&"api-upper"));
    assert!(!matches.contains(&"api-lower"));

    let matches = prefix_trie.search_prefix("api-test");
    assert!(matches.contains(&"api-lower"));
    assert!(!matches.contains(&"api-upper"));
}
