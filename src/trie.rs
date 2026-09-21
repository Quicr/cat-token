// SPDX-FileCopyrightText: Copyright (c) 2022 Quicr
// SPDX-License-Identifier: BSD-2-Clause

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Maximum depth for trie traversal to prevent stack overflow
const MAX_TRIE_DEPTH: usize = 1000;

/// Default maximum regex pattern string length (4KB)
pub const DEFAULT_MAX_REGEX_PATTERN_LENGTH: usize = 4 * 1024;

/// Default maximum number of regex patterns per UriMatcher
pub const DEFAULT_MAX_REGEX_PATTERNS: usize = 100;

/// Configuration for UriMatcher limits
#[derive(Debug, Clone)]
pub struct UriMatcherLimits {
    /// Maximum regex pattern string length in bytes
    pub max_regex_pattern_length: usize,
    /// Maximum number of regex patterns
    pub max_regex_patterns: usize,
}

impl Default for UriMatcherLimits {
    fn default() -> Self {
        Self {
            max_regex_pattern_length: DEFAULT_MAX_REGEX_PATTERN_LENGTH,
            max_regex_patterns: DEFAULT_MAX_REGEX_PATTERNS,
        }
    }
}

impl UriMatcherLimits {
    /// Create limits with the crate defaults.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the maximum accepted regex pattern length in bytes.
    pub fn with_max_regex_pattern_length(mut self, length: usize) -> Self {
        self.max_regex_pattern_length = length;
        self
    }

    /// Set the maximum number of regex patterns per matcher.
    pub fn with_max_regex_patterns(mut self, count: usize) -> Self {
        self.max_regex_patterns = count;
        self
    }
}

/// A single node in a character-keyed trie.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct TrieNode {
    /// Child nodes keyed by the next character.
    pub children: HashMap<char, Box<TrieNode>>,
    /// Whether a stored pattern ends at this node.
    pub is_terminal: bool,
    /// The value associated with a terminal node, if any.
    pub value: Option<String>,
}

impl TrieNode {
    /// Create an empty node with no children.
    pub fn new() -> Self {
        Self::default()
    }
}

/// Trie of patterns matched against the leading characters of a URI.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct PrefixTrie {
    /// Root node of the trie.
    pub root: TrieNode,
    /// Number of stored patterns.
    pub size: usize,
}

impl PrefixTrie {
    /// Create an empty prefix trie.
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a prefix `pattern` mapping to `value`, replacing any existing
    /// entry for the same pattern.
    pub fn insert(&mut self, pattern: &str, value: String) {
        let mut current = &mut self.root;

        for ch in pattern.chars() {
            current = current
                .children
                .entry(ch)
                .or_insert_with(|| Box::new(TrieNode::new()));
        }

        if !current.is_terminal {
            self.size += 1;
        }

        current.is_terminal = true;
        current.value = Some(value);
    }

    /// Return the values of every stored pattern that is a prefix of `text`.
    pub fn search_prefix(&self, text: &str) -> Vec<&str> {
        let mut matches = Vec::new();
        let mut current = &self.root;
        let chars: Vec<char> = text.chars().collect();

        for &ch in chars.iter() {
            if let Some(next_node) = current.children.get(&ch) {
                current = next_node;

                if current.is_terminal
                    && let Some(ref value) = current.value
                {
                    matches.push(value.as_str());
                }
            } else {
                break;
            }
        }

        matches
    }

    /// Return `true` if any stored pattern is a prefix of `text`.
    pub fn contains_prefix(&self, text: &str) -> bool {
        let mut current = &self.root;

        for ch in text.chars() {
            if let Some(next_node) = current.children.get(&ch) {
                current = next_node;
                if current.is_terminal {
                    return true;
                }
            } else {
                return false;
            }
        }

        current.is_terminal
    }

    /// Return every stored pattern as a `String`.
    pub fn get_all_patterns(&self) -> Vec<String> {
        let mut patterns = Vec::new();
        // Use iterative approach with explicit stack to prevent stack overflow
        let mut stack: Vec<(&TrieNode, String)> = vec![(&self.root, String::new())];

        while let Some((node, prefix)) = stack.pop() {
            // Depth limit check
            if prefix.len() > MAX_TRIE_DEPTH {
                continue;
            }

            if node.is_terminal {
                patterns.push(prefix.clone());
            }

            for (ch, child) in &node.children {
                let mut new_prefix = prefix.clone();
                new_prefix.push(*ch);
                stack.push((child, new_prefix));
            }
        }

        patterns
    }

    /// Remove `pattern`; returns `true` if it was present.
    pub fn remove(&mut self, pattern: &str) -> bool {
        // Collect chars once for efficient indexing
        let chars: Vec<char> = pattern.chars().collect();
        let removed = Self::remove_recursive_static(&mut self.root, &chars, 0);
        if removed {
            self.size -= 1;
        }
        removed
    }

    fn remove_recursive_static(node: &mut TrieNode, chars: &[char], index: usize) -> bool {
        // Depth limit to prevent stack overflow
        if index > MAX_TRIE_DEPTH {
            return false;
        }

        if index == chars.len() {
            if node.is_terminal {
                node.is_terminal = false;
                node.value = None;
                return true;
            }
            return false;
        }

        let ch = match chars.get(index) {
            Some(&c) => c,
            None => return false,
        };

        if let Some(mut child) = node.children.remove(&ch) {
            let child_removed = Self::remove_recursive_static(&mut child, chars, index + 1);

            if child_removed {
                if !child.is_terminal && child.children.is_empty() {
                    // Don't reinsert the child, it should be deleted
                    return true;
                } else {
                    // Reinsert the child since it still has value or other children
                    node.children.insert(ch, child);
                    return true;
                }
            } else {
                // No removal occurred, reinsert the child
                node.children.insert(ch, child);
            }
        }

        false
    }

    /// Number of stored patterns.
    pub fn size(&self) -> usize {
        self.size
    }
}

/// Trie of patterns matched against the trailing characters of a URI.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct SuffixTrie {
    /// Root node of the trie (keyed on reversed patterns).
    pub root: TrieNode,
    /// Number of stored patterns.
    pub size: usize,
}

impl SuffixTrie {
    /// Create an empty suffix trie.
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a suffix `pattern` mapping to `value`, replacing any existing
    /// entry for the same pattern.
    pub fn insert(&mut self, pattern: &str, value: String) {
        let reversed: String = pattern.chars().rev().collect();
        let mut current = &mut self.root;

        for ch in reversed.chars() {
            current = current
                .children
                .entry(ch)
                .or_insert_with(|| Box::new(TrieNode::new()));
        }

        if !current.is_terminal {
            self.size += 1;
        }

        current.is_terminal = true;
        current.value = Some(value);
    }

    /// Return the values of every stored pattern that is a suffix of `text`.
    pub fn search_suffix(&self, text: &str) -> Vec<&str> {
        let mut matches = Vec::new();
        let reversed: String = text.chars().rev().collect();
        let mut current = &self.root;

        for ch in reversed.chars() {
            if let Some(next_node) = current.children.get(&ch) {
                current = next_node;

                if current.is_terminal
                    && let Some(ref value) = current.value
                {
                    matches.push(value.as_str());
                }
            } else {
                break;
            }
        }

        matches
    }

    /// Return `true` if any stored pattern is a suffix of `text`.
    pub fn contains_suffix(&self, text: &str) -> bool {
        let reversed: String = text.chars().rev().collect();
        let mut current = &self.root;

        for ch in reversed.chars() {
            if let Some(next_node) = current.children.get(&ch) {
                current = next_node;
                if current.is_terminal {
                    return true;
                }
            } else {
                return false;
            }
        }

        current.is_terminal
    }

    /// Return every stored pattern as a `String`.
    pub fn get_all_patterns(&self) -> Vec<String> {
        let mut patterns = Vec::new();
        // Use iterative approach with explicit stack to prevent stack overflow
        let mut stack: Vec<(&TrieNode, String)> = vec![(&self.root, String::new())];

        while let Some((node, prefix)) = stack.pop() {
            // Depth limit check
            if prefix.len() > MAX_TRIE_DEPTH {
                continue;
            }

            if node.is_terminal {
                patterns.push(prefix.clone());
            }

            for (ch, child) in &node.children {
                let mut new_prefix = prefix.clone();
                new_prefix.push(*ch);
                stack.push((child, new_prefix));
            }
        }

        // Reverse the patterns since SuffixTrie stores reversed strings
        patterns
            .into_iter()
            .map(|p| p.chars().rev().collect())
            .collect()
    }

    /// Remove `pattern`; returns `true` if it was present.
    pub fn remove(&mut self, pattern: &str) -> bool {
        let reversed: String = pattern.chars().rev().collect();
        let chars: Vec<char> = reversed.chars().collect();
        let removed = Self::remove_recursive_static(&mut self.root, &chars, 0);
        if removed {
            self.size -= 1;
        }
        removed
    }

    fn remove_recursive_static(node: &mut TrieNode, chars: &[char], index: usize) -> bool {
        // Depth limit to prevent stack overflow
        if index > MAX_TRIE_DEPTH {
            return false;
        }

        if index == chars.len() {
            if node.is_terminal {
                node.is_terminal = false;
                node.value = None;
                return true;
            }
            return false;
        }

        let ch = match chars.get(index) {
            Some(&c) => c,
            None => return false,
        };

        if let Some(mut child) = node.children.remove(&ch) {
            let child_removed = Self::remove_recursive_static(&mut child, chars, index + 1);

            if child_removed {
                if !child.is_terminal && child.children.is_empty() {
                    // Don't reinsert the child, it should be deleted
                    return true;
                } else {
                    // Reinsert the child since it still has value or other children
                    node.children.insert(ch, child);
                    return true;
                }
            } else {
                // No removal occurred, reinsert the child
                node.children.insert(ch, child);
            }
        }

        false
    }

    /// Number of stored patterns.
    pub fn size(&self) -> usize {
        self.size
    }
}

/// Matches a URI against a set of exact, prefix, suffix, regex, and hash
/// patterns for `catu`-style claim enforcement.
pub struct UriMatcher {
    prefix_trie: PrefixTrie,
    suffix_trie: SuffixTrie,
    exact_patterns: HashMap<String, String>,
    regex_patterns: Vec<(regex::Regex, String)>,
    hash_patterns: HashMap<[u8; 32], String>,
    limits: UriMatcherLimits,
}

impl Default for UriMatcher {
    fn default() -> Self {
        Self::new()
    }
}

impl UriMatcher {
    /// Create a matcher with default [`UriMatcherLimits`].
    pub fn new() -> Self {
        Self::with_limits(UriMatcherLimits::default())
    }

    /// Create a matcher with explicit regex limits.
    pub fn with_limits(limits: UriMatcherLimits) -> Self {
        Self {
            prefix_trie: PrefixTrie::default(),
            suffix_trie: SuffixTrie::default(),
            exact_patterns: HashMap::new(),
            regex_patterns: Vec::new(),
            hash_patterns: HashMap::new(),
            limits,
        }
    }

    /// Add a URI pattern (exact, prefix, suffix, regex, or hash). Regex
    /// patterns are rejected if they exceed the configured count or length
    /// limits, guarding against CPU exhaustion.
    pub fn add_pattern(
        &mut self,
        pattern: crate::claims::UriPattern,
    ) -> Result<(), Box<dyn std::error::Error>> {
        match pattern {
            crate::claims::UriPattern::Exact(uri) => {
                let key = uri.clone();
                self.exact_patterns.insert(key, uri);
            }
            crate::claims::UriPattern::Prefix(prefix) => {
                let value = prefix.clone();
                self.prefix_trie.insert(&prefix, value);
            }
            crate::claims::UriPattern::Suffix(suffix) => {
                let value = suffix.clone();
                self.suffix_trie.insert(&suffix, value);
            }
            crate::claims::UriPattern::Regex(pattern) => {
                // Limit number of regex patterns to prevent CPU exhaustion
                if self.regex_patterns.len() >= self.limits.max_regex_patterns {
                    return Err(format!(
                        "Too many regex patterns: {} (max {})",
                        self.regex_patterns.len() + 1,
                        self.limits.max_regex_patterns
                    )
                    .into());
                }
                // Validate pattern string length
                if pattern.len() > self.limits.max_regex_pattern_length {
                    return Err(format!(
                        "Regex pattern too long: {} bytes (max {} bytes)",
                        pattern.len(),
                        self.limits.max_regex_pattern_length
                    )
                    .into());
                }
                let regex = regex::RegexBuilder::new(&pattern)
                    .size_limit(1024 * 100) // 100KB compiled size limit
                    .dfa_size_limit(1024 * 100) // 100KB DFA size limit
                    .build()?;
                self.regex_patterns.push((regex, pattern));
            }
            crate::claims::UriPattern::Hash(hash) => {
                // Decode hex hash to bytes for efficient comparison
                let hash_bytes: [u8; 32] = hex::decode(&hash)
                    .map_err(|e| format!("Invalid hash hex: {}", e))?
                    .try_into()
                    .map_err(|_| "Hash must be 32 bytes (SHA-256)")?;
                self.hash_patterns.insert(hash_bytes, hash);
            }
        }
        Ok(())
    }

    /// Return `true` if `uri` matches any stored pattern.
    pub fn matches(&self, uri: &str) -> bool {
        // Check exact match
        if self.exact_patterns.contains_key(uri) {
            return true;
        }

        // Check prefix match
        if !self.prefix_trie.search_prefix(uri).is_empty() {
            return true;
        }

        // Check suffix match
        if !self.suffix_trie.search_suffix(uri).is_empty() {
            return true;
        }

        // Check regex patterns
        for (regex, _) in &self.regex_patterns {
            if regex.is_match(uri) {
                return true;
            }
        }

        // Check hash match (compare bytes directly for efficiency)
        let uri_hash = crate::crypto::hash_sha256(uri.as_bytes());
        // SHA-256 always produces exactly 32 bytes
        let uri_hash_array: [u8; 32] = uri_hash
            .try_into()
            .expect("SHA-256 always produces 32 bytes");
        if self.hash_patterns.contains_key(&uri_hash_array) {
            return true;
        }

        false
    }

    /// Return a label (`"exact:"`, `"prefix:"`, `"suffix:"`, `"regex:"`,
    /// or `"hash:"` prefixed) for every stored pattern that matches `uri`.
    pub fn get_matching_patterns(&self, uri: &str) -> Vec<String> {
        let mut matches = Vec::new();

        // Check exact match
        if let Some(pattern) = self.exact_patterns.get(uri) {
            matches.push(format!("exact:{}", pattern));
        }

        // Check prefix matches
        for prefix_match in self.prefix_trie.search_prefix(uri) {
            matches.push(format!("prefix:{}", prefix_match));
        }

        // Check suffix matches
        for suffix_match in self.suffix_trie.search_suffix(uri) {
            matches.push(format!("suffix:{}", suffix_match));
        }

        // Check regex patterns
        for (regex, pattern) in &self.regex_patterns {
            if regex.is_match(uri) {
                matches.push(format!("regex:{}", pattern));
            }
        }

        // Check hash match (compare bytes directly for efficiency)
        let uri_hash = crate::crypto::hash_sha256(uri.as_bytes());
        // SHA-256 always produces exactly 32 bytes
        let uri_hash_array: [u8; 32] = uri_hash
            .try_into()
            .expect("SHA-256 always produces 32 bytes");
        if let Some(pattern) = self.hash_patterns.get(&uri_hash_array) {
            matches.push(format!("hash:{}", pattern));
        }

        matches
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_prefix_trie_basic_operations() {
        let mut trie = PrefixTrie::new();

        trie.insert("hello", "greeting".to_string());
        trie.insert("help", "assistance".to_string());
        trie.insert("world", "earth".to_string());

        assert!(trie.contains_prefix("hello"));
        assert!(trie.contains_prefix("help"));
        assert!(!trie.contains_prefix("he"));

        let matches = trie.search_prefix("hello world");
        assert!(matches.contains(&"greeting"));
    }

    #[test]
    fn test_suffix_trie_basic_operations() {
        let mut trie = SuffixTrie::new();

        trie.insert(".com", "commercial".to_string());
        trie.insert(".org", "organization".to_string());
        trie.insert("ing", "gerund".to_string());

        assert!(trie.contains_suffix("example.com"));
        assert!(trie.contains_suffix("running"));
        assert!(!trie.contains_suffix("example"));

        let matches = trie.search_suffix("programming");
        assert!(matches.contains(&"gerund"));
    }

    #[test]
    fn test_uri_matcher() {
        let mut matcher = UriMatcher::new();

        matcher
            .add_pattern(crate::claims::UriPattern::Exact(
                "https://example.com".to_string(),
            ))
            .unwrap();
        matcher
            .add_pattern(crate::claims::UriPattern::Prefix(
                "https://api.".to_string(),
            ))
            .unwrap();
        matcher
            .add_pattern(crate::claims::UriPattern::Suffix(".json".to_string()))
            .unwrap();

        assert!(matcher.matches("https://example.com"));
        assert!(matcher.matches("https://api.service.com"));
        assert!(matcher.matches("/data/users.json"));
        assert!(!matcher.matches("http://unknown.com"));
    }
}
