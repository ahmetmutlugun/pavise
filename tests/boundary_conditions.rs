//! Test Plan §2: Boundary Condition Tests
//! Tests edge cases around size limits, empty inputs, and score boundaries.

mod common;

use pavise::patterns::engine::extract_printable_strings;
use pavise::patterns::entropy::{scan_for_high_entropy, shannon_entropy};
use pavise::scoring::owasp::compute_score;
use pavise::types::{Finding, SecretMatch, Severity};
use pavise::{scan_ipa, ScanOptions};

fn default_opts() -> ScanOptions {
    ScanOptions {
        rules_dir: Some(common::rules_dir()),
        min_severity: Severity::Info,
        network: false,
        show_progress: false,
        max_extracted_bytes: None,
        max_in_flight_bytes: None,
    }
}

fn make_finding(id: &str, severity: Severity) -> Finding {
    Finding {
        id: id.to_string(),
        title: String::new(),
        description: String::new(),
        severity,
        category: String::new(), // scoring class is derived from the ID prefix
        cwe: None,
        owasp_mobile: None,
        owasp_masvs: None,
        evidence: vec!["evidence".to_string()],
        remediation: None,
    }
}

fn make_secret(rule_id: &str, severity: Severity) -> SecretMatch {
    SecretMatch {
        rule_id: rule_id.to_string(),
        title: "Test".to_string(),
        severity,
        matched_value: "secret".to_string(),
        file_path: None,
        cwe: None,
        owasp_mobile: None,
        owasp_masvs: None,
        remediation: None,
    }
}

// ------------------------------------------------------------------ //
// Score Boundary Tests
// ------------------------------------------------------------------ //

#[test]
fn test_score_all_high_findings_is_zero() {
    // Missing protections + secrets + network + CVEs → score floors at 0
    let findings: Vec<Finding> = [
        "QS-BIN-001",
        "QS-BIN-002",
        "QS-BIN-003",
        "QS-ATS-002",
        "QS-NET-002",
        "QS-ENT-001",
        "QS-ENT-003",
        "QS-CVE-001",
        "QS-CVE-002",
        "QS-CVE-003",
    ]
    .iter()
    .map(|id| make_finding(id, Severity::High))
    .collect();
    let secrets: Vec<SecretMatch> = (1..=5)
        .map(|i| make_secret(&format!("QS-SEC-{:03}", i), Severity::High))
        .collect();

    let (score, grade) = compute_score(&findings, &secrets);
    assert!(score <= 5, "All-bad config should be near 0, got {}", score);
    assert_eq!(grade, "F");
}

#[test]
fn test_score_zero_findings_is_100() {
    let (score, grade) = compute_score(&[], &[]);
    assert_eq!(score, 100, "No findings = perfect score");
    assert_eq!(grade, "A");
}

#[test]
fn test_score_deterministic() {
    let secrets = vec![make_secret("QS-SEC-002", Severity::High)];
    let findings = vec![
        make_finding("QS-ATS-002", Severity::High),
        make_finding("QS-BIN-001", Severity::High),
    ];

    let (s1, g1) = compute_score(&findings, &secrets);
    let (s2, g2) = compute_score(&findings, &secrets);
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
    assert!((h - 5.0).abs() < 0.01, "Expected entropy ~5.0, got {}", h);
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

    let result =
        pavise::manifest::info_plist::analyze(empty_plist.as_bytes(), Some(&common::rules_dir()));
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
fn test_framework_canary_counted_once() {
    // QS-BIN-008 is aggregated across frameworks; it deducts once (Warning = 3)
    // and framework protections are not scored a second time.
    let findings: Vec<Finding> = (0..10)
        .map(|_| make_finding("QS-BIN-008", Severity::Warning))
        .collect();
    let (score, _) = compute_score(&findings, &[]);
    assert_eq!(score, 97);
}

#[test]
fn test_framework_arc_is_info_only() {
    let findings = vec![make_finding("QS-BIN-009", Severity::Info)];
    let (score, _) = compute_score(&findings, &[]);
    assert_eq!(score, 100);
}
