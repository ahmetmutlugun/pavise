//! Secret detection is handled by PatternEngine in engine.rs.
//! This module provides helpers for deduplicating and filtering secret matches.

use crate::types::{SecretMatch, Severity};
use std::collections::{HashMap, HashSet};
use std::sync::OnceLock;

/// Deduplicate secret matches by (rule_id, matched_value) pair.
pub fn deduplicate(matches: Vec<SecretMatch>) -> Vec<SecretMatch> {
    let mut seen = HashSet::new();
    matches
        .into_iter()
        .filter(|m| seen.insert((m.rule_id.clone(), m.matched_value.clone())))
        .collect()
}

/// Published library test keys (`data/known_test_keys.txt`): first 40 base64
/// characters of the key body → where the key comes from.
fn known_test_keys() -> &'static HashMap<&'static str, &'static str> {
    static KEYS: OnceLock<HashMap<&'static str, &'static str>> = OnceLock::new();
    KEYS.get_or_init(|| {
        include_str!("../../data/known_test_keys.txt")
            .lines()
            .filter(|l| !l.starts_with('#'))
            .filter_map(|l| l.split_once('\t'))
            .collect()
    })
}

/// Lower private-key matches (QS-SEC-004) whose key is a published library
/// test key, such as mbedTLS's built-in test certificates, to Info. The key
/// protects nothing, but it shows test code compiled into the release build.
pub fn mark_known_test_keys(matches: &mut [SecretMatch]) {
    for m in matches.iter_mut().filter(|m| m.rule_id == "QS-SEC-004") {
        let Some((_, body)) = m.matched_value.split_once("PRIVATE KEY-----") else {
            continue;
        };
        let prefix: String = body
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || *c == '+' || *c == '/')
            .take(40)
            .collect();
        let Some(source) = known_test_keys().get(prefix.as_str()) else {
            continue;
        };
        m.severity = Severity::Info;
        m.title = "Library Test Private Key (public)".to_string();
        m.remediation = Some(format!(
            "This is the {}, published in the library's source code, so it protects \
            nothing. It means the library's test certificates are compiled in: disable them \
            in release builds (mbedTLS 2.x: MBEDTLS_CERTS_C).",
            source
        ));
    }
}

/// Rules that match a shape rather than a provider; a specific rule matching the
/// same value supersedes them.
const GENERIC_RULES: &[&str] = &["QS-ENTROPY-001", "QS-SEC-005", "QS-SEC-014"];

/// Drop generic matches whose value overlaps a specific rule's match, so a
/// Google API key is reported once as QS-SEC-001, not also as a generic API
/// key assignment and a high-entropy string.
/// Entropy hits (the weakest signal) also yield to generic regex matches.
pub fn drop_superseded(matches: Vec<SecretMatch>) -> Vec<SecretMatch> {
    let overlaps = |a: &str, b: &str| a.contains(b) || b.contains(a);
    let stronger = |m: &SecretMatch, other: &SecretMatch| -> bool {
        let rank = |id: &str| match id {
            "QS-ENTROPY-001" => 0,
            _ if GENERIC_RULES.contains(&id) => 1,
            _ => 2,
        };
        rank(&other.rule_id) > rank(&m.rule_id)
    };
    let keep: Vec<bool> = matches
        .iter()
        .map(|m| {
            !matches
                .iter()
                .any(|o| stronger(m, o) && overlaps(&m.matched_value, &o.matched_value))
        })
        .collect();
    matches
        .into_iter()
        .zip(keep)
        .filter_map(|(m, k)| k.then_some(m))
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
    // Flutter/Xcode symbol maps (`Symbols/<UUID>.symbols`) are debug data full
    // of mangled names that look like tokens (Skia `ghp_…`).
    if lower.ends_with(".symbols") {
        return true;
    }
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

    #[test]
    fn mbedtls_test_key_is_info_unknown_key_stays_high() {
        let key = |body: &str| SecretMatch {
            rule_id: "QS-SEC-004".into(),
            title: "Private Key Material".into(),
            severity: Severity::High,
            matched_value: format!("-----BEGIN EC PRIVATE KEY-----\n{}", body),
            file_path: Some("Payload/A.app/A".into()),
            cwe: None,
            owasp_mobile: None,
            owasp_masvs: None,
            remediation: None,
        };
        let mut m = vec![
            key("MHcCAQEEIPEqEyB2AnCoPL/9U/YDHvdqXYbIogTywwyp6/UfDw6noAoGCCqGSM49\nAwEH..."),
            key("MHcCAQEEIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAoAoGCCqGSM49\nAwEH..."),
        ];
        mark_known_test_keys(&mut m);
        assert_eq!(m[0].severity, Severity::Info);
        assert!(m[0]
            .remediation
            .as_deref()
            .unwrap()
            .contains("TEST_SRV_KEY_EC_PEM"));
        assert_eq!(m[1].severity, Severity::High);
    }

    fn make_secret(rule_id: &str, value: &str) -> SecretMatch {
        SecretMatch {
            rule_id: rule_id.to_string(),
            title: "Test".to_string(),
            severity: Severity::High,
            matched_value: value.to_string(),
            file_path: None,
            cwe: None,
            owasp_mobile: None,
            owasp_masvs: None,
            remediation: None,
        }
    }

    #[test]
    fn test_specific_rule_supersedes_generic() {
        let key = "AIzaSyDouM-1n5eyUckvkL9I5oOimDX23gi45_g";
        let matches = vec![
            make_secret("QS-SEC-001", key),
            make_secret("QS-SEC-005", &format!("API_KEY = \"{key}\"")),
            make_secret("QS-ENTROPY-001", key),
            make_secret("QS-ENTROPY-001", "q7Xk2PzR9vLm4TnW8sYb3HcJ"),
            make_secret(
                "QS-SEC-005",
                "APIKey = \"d0bb57a5e802f0e2c623dfb086ce3296dd6fd121\"",
            ),
            make_secret("QS-ENTROPY-001", "d0bb57a5e802f0e2c623dfb086ce3296dd6fd121"),
        ];
        let ids: Vec<String> = drop_superseded(matches)
            .into_iter()
            .map(|m| format!("{} {}", m.rule_id, m.matched_value))
            .collect();
        assert_eq!(
            ids,
            vec![
                format!("QS-SEC-001 {key}"),
                "QS-ENTROPY-001 q7Xk2PzR9vLm4TnW8sYb3HcJ".to_string(),
                "QS-SEC-005 APIKey = \"d0bb57a5e802f0e2c623dfb086ce3296dd6fd121\"".to_string(),
            ]
        );
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
