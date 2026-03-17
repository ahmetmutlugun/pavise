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
];

pub fn is_noise_file(path: &str) -> bool {
    let lower = path.to_lowercase();
    BINARY_NOISE_EXTENSIONS
        .iter()
        .any(|ext| lower.ends_with(ext))
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
}
