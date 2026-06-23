//! Secret detection is handled by PatternEngine in engine.rs.
//! This module provides helpers for deduplicating and filtering secret matches.

use crate::types::SecretMatch;
use std::collections::HashSet;

/// Deduplicate secret matches by (rule_id, matched_value) pair.
pub fn deduplicate(matches: Vec<SecretMatch>) -> Vec<SecretMatch> {
    let mut seen = HashSet::new();
    matches
        .into_iter()
        .filter(|m| seen.insert((m.rule_id.clone(), m.matched_value.clone())))
        .collect()
}

/// Filter out matches that are clearly false positives from binary weight files.
const BINARY_NOISE_EXTENSIONS: &[&str] = &[
    ".bin",
    ".mlmodelc",
    ".tflite",
    ".pb",
    ".weights",
    ".onnx",
    ".pt",
    ".pth",
    ".npy",
    ".npz",
    ".caffemodel",
    ".model",
    // Bundled reference datasets. These contain thousands of domains/IPs/strings
    // that are static library data, not the app's own endpoints or secrets.
    // Scanning them produced 773 spurious "domains" (Bitwarden's
    // public_suffix_list.dat) and ~2899 garbage "hardcoded IPs" (Orbot's GeoIP /
    // bridge lists).
    ".dat",
    ".mmdb", // MaxMind GeoIP2 binary database
];

/// Bundled reference-data files matched by name rather than extension.
const REFERENCE_DATA_NAMES: &[&str] = &[
    "public_suffix_list.dat",
    "effective_tld_names.dat",
    "publicsuffixlist",
    "geoip",
    "geolite",
    "geoip2",
    "geoipcity",
    "tlds-alpha-by-domain",
];

pub fn is_noise_file(path: &str) -> bool {
    let lower = path.to_lowercase();
    if BINARY_NOISE_EXTENSIONS
        .iter()
        .any(|ext| lower.ends_with(ext))
    {
        return true;
    }
    // Match the file name (last path component) against known reference datasets,
    // so e.g. "MaxMindDB/GeoLite2-City.mmdb" or "Resources/GeoIP.dat" are skipped.
    let name = lower.rsplit('/').next().unwrap_or(&lower);
    REFERENCE_DATA_NAMES.iter().any(|n| name.contains(n))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{SecretMatch, Severity};

    fn make_secret(rule_id: &str, value: &str) -> SecretMatch {
        SecretMatch {
            rule_id: rule_id.to_string(),
            title: "Test".to_string(),
            severity: Severity::High,
            matched_value: value.to_string(),
            file_path: None,
        }
    }

    #[test]
    fn test_dedup_exact() {
        let matches = vec![
            make_secret("QS-SEC-002", "AKIAIOSFODNN7EXAMPLE123"),
            make_secret("QS-SEC-002", "AKIAIOSFODNN7EXAMPLE123"),
        ];
        let result = deduplicate(matches);
        assert_eq!(
            result.len(),
            1,
            "Identical (rule_id, matched_value) should deduplicate to 1"
        );
    }

    #[test]
    fn test_dedup_keeps_distinct() {
        let matches = vec![
            make_secret("QS-SEC-002", "AKIAIOSFODNN7AAAAAAAAAAA"),
            make_secret("QS-SEC-002", "AKIAIOSFODNN7BBBBBBBBBBB"),
        ];
        let result = deduplicate(matches);
        assert_eq!(
            result.len(),
            2,
            "Different matched_values should both be kept"
        );
    }

    #[test]
    fn test_noise_file_tflite() {
        assert!(
            is_noise_file("models/classifier.tflite"),
            ".tflite should be noise"
        );
    }

    #[test]
    fn test_noise_file_swift() {
        assert!(
            !is_noise_file("Source/AppDelegate.swift"),
            ".swift should not be noise"
        );
    }

    #[test]
    fn test_noise_file_reference_datasets() {
        // Bundled reference data must be skipped — by name and by extension.
        assert!(is_noise_file("Payload/App.app/public_suffix_list.dat"));
        assert!(is_noise_file("Resources/MaxMindDB/GeoLite2-City.mmdb"));
        assert!(is_noise_file("Frameworks/X.framework/GeoIP.dat"));
        // A normal config file with real endpoints/secrets must NOT be skipped.
        assert!(!is_noise_file("App.app/config.json"));
        assert!(!is_noise_file("App.app/Settings.plist"));
    }
}
