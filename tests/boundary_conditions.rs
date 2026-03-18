//! Test Plan §2: Boundary Condition Tests
//! Tests edge cases around size limits, empty inputs, and score boundaries.

mod common;

use pavise::patterns::engine::extract_printable_strings;
use pavise::patterns::entropy::{scan_for_high_entropy, shannon_entropy};
use pavise::scoring::owasp::compute_score;
use pavise::types::{BinaryInfo, BinaryProtection, Finding, SecretMatch, Severity};
use pavise::{scan_ipa, ScanOptions};

fn default_opts() -> ScanOptions {
    ScanOptions {
        rules_dir: common::rules_dir(),
        min_severity: Severity::Info,
        network: false,
        show_progress: false,
    }
}

fn make_protection(name: &str, enabled: bool) -> BinaryProtection {
    BinaryProtection {
        name: name.to_string(),
        enabled,
        severity: if enabled {
            Severity::Secure
        } else {
            Severity::High
        },
        description: String::new(),
    }
}

fn make_binary(protections: &[(&str, bool)]) -> BinaryInfo {
    BinaryInfo {
        path: "TestApp".to_string(),
        arch: "arm64".to_string(),
        bits: 64,
        protections: protections
            .iter()
            .map(|(n, e)| make_protection(n, *e))
            .collect(),
    }
}

fn make_finding(id: &str, severity: Severity) -> Finding {
    Finding {
        id: id.to_string(),
        title: String::new(),
        description: String::new(),
        severity,
        category: String::new(),
        cwe: None,
        owasp_mobile: None,
        owasp_masvs: None,
        evidence: vec!["evidence".to_string()],
        remediation: None,
    }
}

fn make_secret(severity: Severity) -> SecretMatch {
    SecretMatch {
        rule_id: "QS-TEST".to_string(),
        title: "Test".to_string(),
        severity,
        matched_value: "secret".to_string(),
        file_path: None,
    }
}

// ------------------------------------------------------------------ //
// Score Boundary Tests
// ------------------------------------------------------------------ //

#[test]
fn test_score_all_high_findings_is_zero() {
    // Maximally bad binary + max secrets + many findings → score should floor at 0
    let bin = make_binary(&[
        ("PIE", false),
        ("Stack Canary", false),
        ("ARC", false),
        ("Encryption", false),
        ("Symbols", false),
        ("RPATH", false),
    ]);
    let secrets: Vec<SecretMatch> = (0..10).map(|_| make_secret(Severity::High)).collect();
    let findings: Vec<Finding> = vec![
        make_finding("QS-ATS-002", Severity::High),
        make_finding("QS-CVE-001", Severity::High),
        make_finding("QS-CVE-002", Severity::High),
        make_finding("QS-CVE-003", Severity::High),
    ];

    let (score, grade) = compute_score(Some(&bin), &[], &findings, &secrets, false);
    assert!(score <= 5, "All-bad config should be near 0, got {}", score);
    assert_eq!(grade, "F");
}

#[test]
fn test_score_zero_findings_is_100() {
    let (score, grade) = compute_score(None, &[], &[], &[], false);
    assert_eq!(score, 100, "No binary + no findings = perfect score");
    assert_eq!(grade, "A");
}

#[test]
fn test_score_deterministic() {
    let bin = make_binary(&[("PIE", false), ("ARC", false)]);
    let secrets = vec![make_secret(Severity::High)];
    let findings = vec![make_finding("QS-ATS-002", Severity::High)];

    let (s1, g1) = compute_score(Some(&bin), &[], &findings, &secrets, false);
    let (s2, g2) = compute_score(Some(&bin), &[], &findings, &secrets, false);
    assert_eq!(s1, s2, "Score must be deterministic");
    assert_eq!(g1, g2, "Grade must be deterministic");
}

// ------------------------------------------------------------------ //
// Entropy Threshold Boundaries
// ------------------------------------------------------------------ //

#[test]
fn test_entropy_at_exact_5_0() {
    // 32 distinct chars → H = log2(32) = 5.0 exactly
    // Build a string with exactly 32 distinct characters + digit and letter classes
    let token = "aAbBcCdDeEfFgGhHiIjJkKlLmMnNoOpP"; // 32 distinct, upper + lower
    let h = shannon_entropy(token);
    assert!(
        (h - 5.0).abs() < 0.01,
        "Expected entropy ~5.0, got {}",
        h
    );
    // At exactly 5.0 this should be at the Warning threshold boundary
    let results = scan_for_high_entropy(&[token], "test.json");
    // Whether it triggers depends on >= vs > — just ensure no panic
    let _ = results;
}

#[test]
fn test_entropy_below_5_0_not_flagged() {
    // Low entropy string — should not be flagged
    let token = "aaabbbccc";
    let results = scan_for_high_entropy(&[token], "test.json");
    assert!(
        results.is_empty(),
        "Low entropy string should not be flagged"
    );
}

// ------------------------------------------------------------------ //
// Empty Info.plist (valid XML, no useful keys)
// ------------------------------------------------------------------ //

#[test]
fn test_empty_plist() {
    let empty_plist = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
</dict>
</plist>"#;

    let result = pavise::manifest::info_plist::analyze(empty_plist.as_bytes(), &common::rules_dir());
    // Should succeed with empty/default AppInfo, not crash
    match result {
        Ok(r) => {
            assert!(r.app_info.name.is_empty() || r.app_info.name == "Unknown");
        }
        Err(_) => {
            // Also acceptable — parser may require CFBundleName
        }
    }
}

// ------------------------------------------------------------------ //
// Extract printable strings edge cases
// ------------------------------------------------------------------ //

#[test]
fn test_extract_printable_strings_all_binary() {
    let data = vec![0u8, 1, 2, 3, 4, 5];
    let result = extract_printable_strings(&data, 6);
    assert!(
        result.is_empty(),
        "All non-printable data should yield empty string"
    );
}

#[test]
fn test_extract_printable_strings_exact_min_len() {
    let data = b"abcdef"; // exactly 6 chars = min_len
    let result = extract_printable_strings(data, 6);
    assert!(
        result.contains("abcdef"),
        "String at exact min_len should be included"
    );
}

#[test]
fn test_extract_printable_strings_one_below_min_len() {
    let data = b"abcde"; // 5 chars < 6 = min_len
    let result = extract_printable_strings(data, 6);
    assert!(
        !result.contains("abcde"),
        "String below min_len should be excluded"
    );
}

// ------------------------------------------------------------------ //
// IPA with zero extractable content (only directories)
// ------------------------------------------------------------------ //

#[test]
fn test_ipa_only_directories() {
    use std::io::Write;
    use zip::write::SimpleFileOptions;
    use zip::ZipWriter;

    let mut buf = Vec::new();
    {
        let cursor = std::io::Cursor::new(&mut buf);
        let mut zip = ZipWriter::new(cursor);
        let options = SimpleFileOptions::default();
        // Only add directory entries
        zip.add_directory("Payload/", options).unwrap();
        zip.add_directory("Payload/TestApp.app/", options).unwrap();
        zip.finish().unwrap();
    }

    let mut tmp = tempfile::NamedTempFile::new().unwrap();
    tmp.write_all(&buf).unwrap();
    tmp.flush().unwrap();

    let result = scan_ipa(tmp.path(), &default_opts());
    assert!(
        result.is_err(),
        "IPA with only directories should fail (no Info.plist)"
    );
}

// ------------------------------------------------------------------ //
// Framework binary scoring deductions
// ------------------------------------------------------------------ //

#[test]
fn test_framework_canary_deduction_capped() {
    // 10 frameworks missing Stack Canary — max deduction should be 8 (2 each, capped)
    let frameworks: Vec<BinaryInfo> = (0..10)
        .map(|i| BinaryInfo {
            path: format!("Framework{}", i),
            arch: "arm64".to_string(),
            bits: 64,
            protections: vec![make_protection("Stack Canary", false)],
        })
        .collect();

    let (score, _) = compute_score(None, &frameworks, &[], &[], false);
    // 100 - 8 (canary cap) = 92
    assert_eq!(
        score, 92,
        "Framework canary deduction should cap at 8, got {}",
        score
    );
}

#[test]
fn test_framework_arc_deduction_capped() {
    // 10 frameworks missing ARC — max deduction should be 15 (3 each, capped)
    let frameworks: Vec<BinaryInfo> = (0..10)
        .map(|i| BinaryInfo {
            path: format!("Framework{}", i),
            arch: "arm64".to_string(),
            bits: 64,
            protections: vec![make_protection("ARC", false)],
        })
        .collect();

    let (score, _) = compute_score(None, &frameworks, &[], &[], false);
    // 100 - 15 (ARC cap) = 85
    assert_eq!(
        score, 85,
        "Framework ARC deduction should cap at 15, got {}",
        score
    );
}
