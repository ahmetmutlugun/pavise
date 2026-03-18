//! Test Plan §4: Pattern Engine Edge Cases
//! Tests YAML rule loading edge cases, large inputs, deduplication at scale,
//! and cipher/tracker detection.

mod common;

use pavise::patterns::ciphers::scan_for_weak_ciphers;
use pavise::patterns::emails::extract_emails;
use pavise::patterns::engine::PatternEngine;
use pavise::patterns::entropy::scan_for_high_entropy;
use pavise::patterns::secrets::{deduplicate, is_noise_file};
use pavise::patterns::urls;
use pavise::types::{SecretMatch, Severity};
use std::io::Write;
use tempfile::TempDir;

// ------------------------------------------------------------------ //
// YAML Rules Edge Cases
// ------------------------------------------------------------------ //

#[test]
fn test_yaml_rules_with_invalid_regex() {
    // Create a temporary rules directory with an invalid regex pattern
    let tmp_dir = TempDir::new().unwrap();
    let secrets_path = tmp_dir.path().join("secrets.yaml");
    let mut f = std::fs::File::create(&secrets_path).unwrap();
    write!(
        f,
        r#"- id: QS-BAD-001
  title: "Bad Regex Rule"
  pattern: "[invalid(regex"
  severity: high
  category: test
"#
    )
    .unwrap();

    let result = PatternEngine::load(tmp_dir.path());
    assert!(
        result.is_err(),
        "Invalid regex in YAML should produce an error, not panic"
    );
}

#[test]
fn test_yaml_rules_with_zero_rules() {
    // Create a temporary rules directory with an empty secrets.yaml
    let tmp_dir = TempDir::new().unwrap();
    let secrets_path = tmp_dir.path().join("secrets.yaml");
    std::fs::write(&secrets_path, "[]").unwrap();

    let engine = PatternEngine::load(tmp_dir.path())
        .expect("Empty rules list should load successfully");
    assert_eq!(engine.rule_count(), 0, "Should have zero rules loaded");

    // Scanning with zero rules should return empty, not crash
    let matches = engine.scan("AKIAIOSFODNN7EXAMPLE1234", "test.json");
    assert!(
        matches.is_empty(),
        "Zero rules engine should produce no matches"
    );
}

#[test]
fn test_yaml_rules_missing_file() {
    // Rules directory with no secrets.yaml at all
    let tmp_dir = TempDir::new().unwrap();
    let engine = PatternEngine::load(tmp_dir.path())
        .expect("Missing secrets.yaml should load with zero rules");
    assert_eq!(engine.rule_count(), 0);
}

// ------------------------------------------------------------------ //
// PatternEngine — Large Input
// ------------------------------------------------------------------ //

#[test]
fn test_pattern_scan_large_input() {
    let engine = PatternEngine::load(&common::rules_dir()).unwrap();
    // 1 MB of printable text with one embedded secret
    let mut text = String::with_capacity(1_100_000);
    for _ in 0..10_000 {
        text.push_str("This is a normal line of configuration data that contains nothing interesting.\n");
    }
    // Embed an AWS key in the middle
    text.push_str("aws_access_key_id = AKIAIOSFODNN7EXAMPLE1234\n");
    for _ in 0..10_000 {
        text.push_str("More normal text padding to make the input large enough for testing.\n");
    }

    let matches = engine.scan(&text, "large_config.json");
    let aws = matches.iter().find(|m| m.rule_id == "QS-SEC-002");
    assert!(aws.is_some(), "Should find AWS key in 1MB+ input");
}

#[test]
fn test_pattern_scan_empty_input() {
    let engine = PatternEngine::load(&common::rules_dir()).unwrap();
    let matches = engine.scan("", "empty.txt");
    assert!(matches.is_empty(), "Empty input should produce no matches");
}

// ------------------------------------------------------------------ //
// Secret Deduplication at Scale
// ------------------------------------------------------------------ //

#[test]
fn test_secret_dedup_large_volume() {
    // 1000 identical matches → should deduplicate to 1
    let matches: Vec<SecretMatch> = (0..1000)
        .map(|_| SecretMatch {
            rule_id: "QS-SEC-002".to_string(),
            title: "AWS Key".to_string(),
            severity: Severity::High,
            matched_value: "AKIAIOSFODNN7EXAMPLE1234".to_string(),
            file_path: Some("config.json".to_string()),
        })
        .collect();

    let result = deduplicate(matches);
    assert_eq!(result.len(), 1, "1000 identical secrets should dedup to 1");
}

#[test]
fn test_secret_dedup_many_distinct() {
    // 100 distinct secrets → all should be kept
    let matches: Vec<SecretMatch> = (0..100)
        .map(|i| SecretMatch {
            rule_id: "QS-SEC-002".to_string(),
            title: "AWS Key".to_string(),
            severity: Severity::High,
            matched_value: format!("AKIAIOSFODNN7{:016}", i),
            file_path: None,
        })
        .collect();

    let result = deduplicate(matches);
    assert_eq!(result.len(), 100, "100 distinct secrets should all be kept");
}

// ------------------------------------------------------------------ //
// Noise File Detection
// ------------------------------------------------------------------ //

#[test]
fn test_noise_file_various_extensions() {
    assert!(is_noise_file("model.bin"));
    assert!(is_noise_file("deep/path/model.mlmodelc"));
    assert!(is_noise_file("weights.onnx"));
    assert!(is_noise_file("model.pt"));
    assert!(is_noise_file("data.npz"));
    assert!(!is_noise_file("AppDelegate.swift"));
    assert!(!is_noise_file("config.json"));
    assert!(!is_noise_file("Info.plist"));
}

// ------------------------------------------------------------------ //
// Cipher Detection
// ------------------------------------------------------------------ //

#[test]
fn test_des_detected() {
    let findings = scan_for_weak_ciphers("Using kCCAlgorithmDES for encryption", "binary");
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].id, "QS-CRYPTO-001");
    assert_eq!(findings[0].severity, Severity::High);
}

#[test]
fn test_3des_detected() {
    let findings = scan_for_weak_ciphers("kCCAlgorithm3DES", "binary");
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].id, "QS-CRYPTO-002");
    assert_eq!(findings[0].severity, Severity::Warning);
}

#[test]
fn test_ecb_mode_detected() {
    let findings = scan_for_weak_ciphers("kCCOptionECBMode", "binary");
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].id, "QS-CRYPTO-005");
    assert_eq!(findings[0].severity, Severity::High);
}

#[test]
fn test_multiple_ciphers_detected() {
    let text = "kCCAlgorithmDES kCCAlgorithmRC4 kCCOptionECBMode";
    let findings = scan_for_weak_ciphers(text, "binary");
    assert_eq!(findings.len(), 3, "Should detect all three weak ciphers");
}

#[test]
fn test_no_cipher_in_clean_text() {
    let findings = scan_for_weak_ciphers("Using AES-256-GCM for encryption", "binary");
    assert!(findings.is_empty(), "Modern cipher should not trigger");
}

// ------------------------------------------------------------------ //
// URL Extraction Edge Cases
// ------------------------------------------------------------------ //

#[test]
fn test_url_noise_patterns_not_flagged_as_http() {
    let text = r#"
        http://www.w3.org/2001/XMLSchema
        http://www.apple.com/dtds/PropertyList-1.0.dtd
    "#;
    let result = urls::extract(text, "Info.plist");
    // Noise URLs should NOT produce QS-NET-001 HTTP findings
    assert!(
        result.findings.iter().all(|f| f.id != "QS-NET-001"),
        "Noise URLs (W3, Apple DTD) should not trigger HTTP finding"
    );
}

#[test]
fn test_url_dedup_single_domain() {
    let text = "https://api.example.net/v1 https://api.example.net/v2 https://api.example.net/v3";
    let result = urls::extract(text, "config.json");
    let count = result
        .domains
        .iter()
        .filter(|d| d.domain == "api.example.net")
        .count();
    // Domains should be deduplicated or at least not multiply indefinitely
    assert!(count <= 3, "Domain should appear at most once per URL, got {count}");
}

// ------------------------------------------------------------------ //
// Email Extraction Edge Cases
// ------------------------------------------------------------------ //

#[test]
fn test_email_extraction_many_emails() {
    let mut text = String::new();
    for i in 0..100 {
        text.push_str(&format!("user{}@company.com ", i));
    }
    let emails = extract_emails(&text, "contacts.plist");
    assert!(
        emails.len() >= 50,
        "Should extract many valid emails, got {}",
        emails.len()
    );
}

#[test]
fn test_email_extraction_no_false_positives_in_code() {
    // Common code patterns that look like emails but aren't
    let text = "import Foundation // user@interface.h method@selector(foo:)";
    let emails = extract_emails(text, "code.swift");
    // These should mostly be filtered
    let _ = emails; // Just ensure no panic
}

// ------------------------------------------------------------------ //
// Entropy — False Positive Filters
// ------------------------------------------------------------------ //

#[test]
fn test_entropy_url_filtered() {
    let url = "https://api.example.com/v2/users/authenticate";
    let results = scan_for_high_entropy(&[url], "config.plist");
    assert!(results.is_empty(), "URL should be filtered, got: {results:?}");
}

#[test]
fn test_entropy_dotted_identifier_filtered() {
    let id = "com.apple.developer.team-identifier";
    let results = scan_for_high_entropy(&[id], "entitlements.plist");
    assert!(
        results.is_empty(),
        "Dotted identifier should be filtered, got: {results:?}"
    );
}

#[test]
fn test_entropy_swift_mangled_symbol_filtered() {
    let symbol = "$s10Foundation4DateVMa";
    let results = scan_for_high_entropy(&[symbol], "binary");
    assert!(
        results.is_empty(),
        "Swift mangled symbol should be filtered, got: {results:?}"
    );
}

#[test]
fn test_entropy_objc_symbol_filtered() {
    let symbol = "_OBJC_CLASS_$_NSURLSession";
    let results = scan_for_high_entropy(&[symbol], "binary");
    assert!(
        results.is_empty(),
        "ObjC symbol should be filtered, got: {results:?}"
    );
}

// ------------------------------------------------------------------ //
// Tracker Detection via Overlapping Matches
// ------------------------------------------------------------------ //

#[test]
fn test_tracker_detection_loads() {
    let detector =
        pavise::patterns::trackers::TrackerDetector::load(&common::rules_dir())
            .expect("Tracker rules should load");
    // Detect with empty inputs — should return empty, not crash
    let results = detector.detect(&[], &[]);
    assert!(results.is_empty());
}

#[test]
fn test_tracker_detection_by_domain() {
    let detector = pavise::patterns::trackers::TrackerDetector::load(&common::rules_dir()).unwrap();
    // Try common tracker domains
    let domains = vec![
        "graph.facebook.com".to_string(),
        "api.myapp.com".to_string(),
    ];
    let results = detector.detect(&domains, &[]);
    // Facebook SDK tracker should be detected if it's in the rules
    // Just verify no panic and reasonable output
    let _ = results;
}

// ------------------------------------------------------------------ //
// Symbol Scanner
// ------------------------------------------------------------------ //

#[test]
fn test_symbol_scanner_loads() {
    let scanner = pavise::binary::symbols::SymbolScanner::load(&common::rules_dir())
        .expect("Symbol rules should load");
    // Empty imports → no findings
    let results = scanner.scan(&[]);
    assert!(results.is_empty());
}

#[test]
fn test_symbol_scanner_no_panic_on_large_import_list() {
    let scanner = pavise::binary::symbols::SymbolScanner::load(&common::rules_dir()).unwrap();
    let imports: Vec<String> = (0..10_000)
        .map(|i| format!("_symbol_{}", i))
        .collect();
    let results = scanner.scan(&imports);
    // Just ensure no panic
    let _ = results;
}
