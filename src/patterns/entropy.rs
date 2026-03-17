//! Entropy-based secret detection.
//!
//! Complements regex pattern matching by flagging strings with unusually high
//! Shannon entropy — a strong indicator of encoded secrets, tokens, or keys
//! that don't match any known pattern.

use crate::types::{SecretMatch, Severity};
use regex::Regex;
use std::sync::OnceLock;

static UUID_RE: OnceLock<Regex> = OnceLock::new();
static HEX_RE: OnceLock<Regex> = OnceLock::new();
static CONST_RE: OnceLock<Regex> = OnceLock::new();

fn uuid_re() -> &'static Regex {
    UUID_RE.get_or_init(|| Regex::new(r"^[0-9a-fA-F\-]{36}$").unwrap())
}

fn hex_re() -> &'static Regex {
    HEX_RE.get_or_init(|| Regex::new(r"^[0-9a-fA-F]+$").unwrap())
}

fn const_re() -> &'static Regex {
    CONST_RE.get_or_init(|| Regex::new(r"^[A-Z_]{10,}$").unwrap())
}

/// Compute Shannon entropy over the byte distribution of `s`.
pub fn shannon_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    for &b in s.as_bytes() {
        counts[b as usize] += 1;
    }
    let len = s.len() as f64;
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / len;
            -p * p.log2()
        })
        .sum()
}

// Symbol prefixes that appear in Mach-O string tables and are never secrets.
const SYMBOL_PREFIXES: &[&str] = &[
    "_T0", "_TFC", "_TtC", "_TtP", "_$s", "$S", "$s", "_OBJC_", "__OBJC_", "_objc_", "__swift_",
];

/// Return true if `s` is likely a false-positive and should NOT be flagged.
fn is_false_positive(s: &str) -> bool {
    // UUID pattern: 8-4-4-4-12
    if uuid_re().is_match(s) {
        return true;
    }

    let len = s.len();

    // Pure hex hash (MD5=32, SHA1=40, SHA256=64)
    if (len == 32 || len == 40 || len == 64) && hex_re().is_match(s) {
        return true;
    }

    // File path (starts with / ./ ../ and no = or :)
    if (s.starts_with('/') || s.starts_with("./") || s.starts_with("../"))
        && !s.contains('=')
        && !s.contains(':')
    {
        return true;
    }

    // All-uppercase constant name (e.g. SOME_CONFIG_KEY)
    if const_re().is_match(s) {
        return true;
    }

    // URLs — query parameters produce high entropy but carry no secret by themselves
    if s.contains("://") {
        return true;
    }

    // Dotted identifiers: bundle IDs (com.example.app), reverse-DNS class names,
    // or framework paths all score high on entropy and are never secrets
    if s.matches('.').count() >= 3 {
        return true;
    }

    // Swift / ObjC mangled symbol prefixes found in binary string tables
    if SYMBOL_PREFIXES.iter().any(|p| s.starts_with(p)) {
        return true;
    }

    // Require character class diversity: a real secret almost always contains
    // at least 3 of the 4 classes (uppercase, lowercase, digit, special).
    // Pure-lowercase identifiers, camelCase method names, and base64 padding
    // strings fail this check.
    let has_upper = s.bytes().any(|b| b.is_ascii_uppercase());
    let has_lower = s.bytes().any(|b| b.is_ascii_lowercase());
    let has_digit = s.bytes().any(|b| b.is_ascii_digit());
    let has_special = s
        .bytes()
        .any(|b| !b.is_ascii_alphanumeric() && b.is_ascii_graphic());
    let class_count = [has_upper, has_lower, has_digit, has_special]
        .iter()
        .filter(|&&x| x)
        .count();
    if class_count < 3 {
        return true;
    }

    false
}

/// Scan a slice of individual strings for high-entropy values.
///
/// Each element should be a single line or token — entropy is computed
/// per-string, not over a concatenated blob.
///
/// * `strings` — the strings to evaluate (e.g. lines from a file)
/// * `source_path` — file path used for evidence annotation
pub fn scan_for_high_entropy(strings: &[&str], source_path: &str) -> Vec<SecretMatch> {
    let mut results = Vec::new();
    for &s in strings {
        let trimmed = s.trim();
        let len = trimmed.len();
        if !(20..=128).contains(&len) {
            continue;
        }
        if is_false_positive(trimmed) {
            continue;
        }
        let entropy = shannon_entropy(trimmed);
        // Thresholds are intentionally conservative to reduce noise:
        //   5.0 is the Warning floor — normal identifiers and paths rarely exceed it.
        //   5.7 is the High floor — this is in the range of genuinely random 32-char tokens.
        let severity = if entropy > 5.7 {
            Severity::High
        } else if entropy > 5.0 {
            Severity::Warning
        } else {
            continue;
        };

        results.push(SecretMatch {
            rule_id: "QS-ENTROPY-001".to_string(),
            title: "High-Entropy String (Potential Secret)".to_string(),
            severity,
            matched_value: trimmed.to_string(),
            file_path: Some(source_path.to_string()),
        });
    }
    results
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Severity;

    #[test]
    fn test_shannon_entropy_uniform() {
        // All-same-char string has zero entropy.
        assert_eq!(shannon_entropy("aaaaaa"), 0.0);
    }

    #[test]
    fn test_shannon_entropy_known_value() {
        // "abcd": 4 distinct chars, each with p=0.25 → H = log2(4) = 2.0
        let h = shannon_entropy("abcd");
        assert!((h - 2.0).abs() < 1e-9, "expected ~2.0, got {h}");
    }

    #[test]
    fn test_high_entropy_detected() {
        // 60 distinct printable chars → entropy ≈ log2(60) = 5.91 > 5.7 → High
        // Has upper, lower, digit, special (+) → 4 character classes
        let token = "aB3cD4eF5gH6iJ7kL8mN9oP0qR1sT2uVwXyZ+AbCdEfGhIjKlMnOpQrStUvW";
        let results = scan_for_high_entropy(&[token], "test/file.json");
        assert_eq!(
            results.len(),
            1,
            "Expected exactly one High match, got: {results:?}"
        );
        assert_eq!(results[0].severity, Severity::High);
    }

    #[test]
    fn test_warning_entropy_detected() {
        // 36 distinct chars → entropy = log2(36) ≈ 5.17 → Warning (> 5.0, ≤ 5.7)
        // Has upper, lower, digit → 3 character classes; no special chars
        let token = "aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890";
        let results = scan_for_high_entropy(&[token], "test/config.json");
        assert_eq!(
            results.len(),
            1,
            "Expected exactly one Warning match, got: {results:?}"
        );
        assert_eq!(results[0].severity, Severity::Warning);
    }

    #[test]
    fn test_uuid_filtered() {
        // Standard UUID pattern — matched by uuid_re() and filtered out
        let uuid = "550e8400-e29b-41d4-a716-446655440000";
        let results = scan_for_high_entropy(&[uuid], "test");
        assert!(
            results.is_empty(),
            "UUID should be filtered, got: {results:?}"
        );
    }

    #[test]
    fn test_hex_hash_filtered() {
        // 32-char hex string (MD5 hash) — filtered by hex_re() length check
        let hex = "d41d8cd98f00b204e9800998ecf8427e";
        let results = scan_for_high_entropy(&[hex], "test");
        assert!(
            results.is_empty(),
            "Hex hash should be filtered, got: {results:?}"
        );
    }

    #[test]
    fn test_file_path_filtered() {
        // File path starting with '/' — filtered by path check
        let path = "/usr/lib/libsomething.dylib";
        let results = scan_for_high_entropy(&[path], "test");
        assert!(
            results.is_empty(),
            "File path should be filtered, got: {results:?}"
        );
    }

    #[test]
    fn test_allcaps_constant_filtered() {
        // All-uppercase constant — filtered by const_re()
        let constant = "SOME_ALLCAPS_CONSTANT_NAME";
        let results = scan_for_high_entropy(&[constant], "test");
        assert!(
            results.is_empty(),
            "ALLCAPS constant should be filtered, got: {results:?}"
        );
    }
}
