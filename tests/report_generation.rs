//! Test Plan §5: Report Generation Tests
//! Validates JSON round-tripping, SARIF structure, and baseline diffing edge cases.

mod common;

use pavise::baseline::compare;
use pavise::report::sarif;
use pavise::types::{
    AppInfo, FileHashes, Finding, ScanReport, SecretMatch, Severity,
};
use std::collections::HashMap;

fn make_owasp_summary(findings: &[Finding]) -> HashMap<String, Vec<String>> {
    let mut summary: HashMap<String, Vec<String>> =
        ["M1", "M2", "M3", "M4", "M5", "M6", "M7", "M8", "M9", "M10"]
            .iter()
            .map(|k| (k.to_string(), Vec::new()))
            .collect();
    for f in findings {
        if let Some(ref m) = f.owasp_mobile {
            if let Some(list) = summary.get_mut(m.as_str()) {
                list.push(f.id.clone());
            }
        }
    }
    summary
}

fn make_report(
    findings: Vec<Finding>,
    secrets: Vec<SecretMatch>,
    score: u8,
    grade: &str,
) -> ScanReport {
    let owasp_summary = make_owasp_summary(&findings);
    ScanReport {
        app_info: AppInfo::default(),
        file_hashes: FileHashes {
            md5: "d41d8cd98f00b204e9800998ecf8427e".to_string(),
            sha1: "da39a3ee5e6b4b0d3255bfef95601890afd80709".to_string(),
            sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                .to_string(),
            size_bytes: 1024,
        },
        main_binary: None,
        framework_binaries: Vec::new(),
        findings,
        domains: Vec::new(),
        emails: Vec::new(),
        trackers: Vec::new(),
        secrets,
        firebase: None,
        scan_duration_ms: 42,
        security_score: score,
        grade: grade.to_string(),
        scan_log: Vec::new(),
        domain_intel: Vec::new(),
        framework_components: Vec::new(),
        provisioning: None,
        owasp_summary,
        baseline_diff: None,
    }
}

fn make_finding(id: &str, severity: Severity) -> Finding {
    Finding {
        id: id.to_string(),
        title: format!("Title for {}", id),
        description: format!("Description for {}", id),
        severity,
        category: "test".to_string(),
        cwe: Some("CWE-000".to_string()),
        owasp_mobile: Some("M1".to_string()),
        owasp_masvs: Some("MSTG-TEST-1".to_string()),
        evidence: vec![format!("evidence for {}", id)],
        remediation: Some(format!("Fix {}", id)),
    }
}

fn make_secret(rule_id: &str, value: &str) -> SecretMatch {
    SecretMatch {
        rule_id: rule_id.to_string(),
        title: "Test Secret".to_string(),
        severity: Severity::High,
        matched_value: value.to_string(),
        file_path: Some("Config.plist".to_string()),
    }
}

// ------------------------------------------------------------------ //
// JSON Round-Trip
// ------------------------------------------------------------------ //

#[test]
fn test_json_round_trip() {
    let findings = vec![
        make_finding("QS-TEST-001", Severity::High),
        make_finding("QS-TEST-002", Severity::Warning),
    ];
    let secrets = vec![make_secret("QS-SEC-001", "AKIAIOSFODNN7EXAMPLE1234")];
    let report = make_report(findings, secrets, 75, "C");

    // Serialize
    let json_str = serde_json::to_string_pretty(&report).expect("JSON serialize should work");

    // Deserialize back
    let deserialized: ScanReport =
        serde_json::from_str(&json_str).expect("JSON deserialize should work");

    assert_eq!(deserialized.security_score, 75);
    assert_eq!(deserialized.grade, "C");
    assert_eq!(deserialized.findings.len(), 2);
    assert_eq!(deserialized.secrets.len(), 1);
    assert_eq!(deserialized.findings[0].id, "QS-TEST-001");
    assert_eq!(deserialized.findings[0].severity, Severity::High);
    assert_eq!(
        deserialized.secrets[0].matched_value,
        "AKIAIOSFODNN7EXAMPLE1234"
    );
    assert_eq!(
        deserialized.file_hashes.sha256,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
}

// ------------------------------------------------------------------ //
// SARIF Output Structure
// ------------------------------------------------------------------ //

#[test]
fn test_sarif_valid_json() {
    let report = make_report(
        vec![make_finding("QS-TEST-001", Severity::High)],
        vec![make_secret("QS-SEC-002", "mysecret")],
        85,
        "B",
    );

    let sarif_str = sarif::to_string(&report).expect("SARIF generation should succeed");
    let parsed: serde_json::Value =
        serde_json::from_str(&sarif_str).expect("SARIF should be valid JSON");

    // Check required SARIF 2.1.0 fields
    assert_eq!(parsed["version"], "2.1.0");
    assert!(parsed["$schema"].as_str().unwrap().contains("sarif-schema"));

    let runs = parsed["runs"].as_array().expect("runs should be array");
    assert_eq!(runs.len(), 1);

    let run = &runs[0];
    assert_eq!(run["tool"]["driver"]["name"], "Pavise");

    // Check rules are present
    let rules = run["tool"]["driver"]["rules"]
        .as_array()
        .expect("rules should be array");
    assert!(
        rules.len() >= 2,
        "Should have rules for finding + secret"
    );

    // Check results include both findings and secrets
    let results = run["results"].as_array().expect("results should be array");
    assert!(
        results.len() >= 2,
        "Should have results for finding + secret"
    );
}

#[test]
fn test_sarif_contains_all_finding_ids() {
    let findings = vec![
        make_finding("QS-ATS-001", Severity::High),
        make_finding("QS-BIN-002", Severity::Warning),
        make_finding("QS-NET-001", Severity::Info),
    ];
    let report = make_report(findings, vec![], 70, "C");

    let sarif_str = sarif::to_string(&report).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&sarif_str).unwrap();

    let results = parsed["runs"][0]["results"].as_array().unwrap();
    let rule_ids: Vec<&str> = results
        .iter()
        .map(|r| r["ruleId"].as_str().unwrap())
        .collect();

    assert!(rule_ids.contains(&"QS-ATS-001"));
    assert!(rule_ids.contains(&"QS-BIN-002"));
    assert!(rule_ids.contains(&"QS-NET-001"));
}

#[test]
fn test_sarif_secret_truncation() {
    let long_secret = "A".repeat(100);
    let report = make_report(
        vec![],
        vec![make_secret("QS-SEC-001", &long_secret)],
        90,
        "A",
    );

    let sarif_str = sarif::to_string(&report).unwrap();
    // The full 100-char secret should NOT appear in SARIF (truncated to 40)
    assert!(
        !sarif_str.contains(&long_secret),
        "Full secret should be truncated in SARIF output"
    );
}

#[test]
fn test_sarif_cwe_relationships() {
    let report = make_report(
        vec![make_finding("QS-TEST-001", Severity::High)],
        vec![],
        90,
        "A",
    );

    let sarif_str = sarif::to_string(&report).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&sarif_str).unwrap();

    let rules = parsed["runs"][0]["tool"]["driver"]["rules"]
        .as_array()
        .unwrap();
    let rule = &rules[0];
    assert!(
        rule["relationships"].is_array(),
        "CWE relationship should be present"
    );
    assert_eq!(
        rule["relationships"][0]["target"]["id"], "CWE-000",
        "CWE ID should match"
    );
}

// ------------------------------------------------------------------ //
// HTML Output
// ------------------------------------------------------------------ //

#[test]
fn test_html_contains_all_finding_ids() {
    let findings = vec![
        make_finding("QS-ATS-001", Severity::High),
        make_finding("QS-BIN-002", Severity::Warning),
        make_finding("QS-NET-001", Severity::Info),
    ];
    let report = make_report(findings, vec![], 70, "C");

    let html = pavise::report::html::to_string(&report).expect("HTML generation should succeed");

    // All finding IDs should appear in the HTML output
    assert!(
        html.contains("QS-ATS-001"),
        "HTML should contain QS-ATS-001"
    );
    assert!(
        html.contains("QS-BIN-002"),
        "HTML should contain QS-BIN-002"
    );
    assert!(
        html.contains("QS-NET-001"),
        "HTML should contain QS-NET-001"
    );
}

#[test]
fn test_html_large_report() {
    // Generate a report with 100+ findings to test HTML rendering at scale
    let findings: Vec<Finding> = (0..120)
        .map(|i| {
            let severity = match i % 3 {
                0 => Severity::High,
                1 => Severity::Warning,
                _ => Severity::Info,
            };
            make_finding(&format!("QS-TEST-{:03}", i), severity)
        })
        .collect();

    let secrets: Vec<SecretMatch> = (0..10)
        .map(|i| make_secret(&format!("QS-SEC-{:03}", i), &format!("secret_value_{}", i)))
        .collect();

    let report = make_report(findings, secrets, 25, "F");

    let html = pavise::report::html::to_string(&report).expect("Large HTML report should render");
    assert!(
        html.len() > 1000,
        "HTML for 120 findings should be substantial"
    );
    // Spot-check a few finding IDs
    assert!(html.contains("QS-TEST-000"));
    assert!(html.contains("QS-TEST-119"));
}

// ------------------------------------------------------------------ //
// Baseline Diff Edge Cases
// ------------------------------------------------------------------ //

#[test]
fn test_baseline_identical_reports_zero_delta() {
    let f = make_finding("QS-ATS-001", Severity::High);
    let s = make_secret("QS-SEC-001", "value1");
    let r1 = make_report(vec![f.clone()], vec![s.clone()], 80, "B");
    let r2 = make_report(vec![f], vec![s], 80, "B");

    let diff = compare(&r1, &r2);
    assert!(diff.new_findings.is_empty());
    assert!(diff.fixed_findings.is_empty());
    assert_eq!(diff.new_secrets, 0);
    assert_eq!(diff.fixed_secrets, 0);
    assert_eq!(diff.score_delta, 0);
    assert!(!diff.grade_changed);
}

#[test]
fn test_baseline_completely_different_reports() {
    let r1 = make_report(
        vec![
            make_finding("QS-ATS-001", Severity::High),
            make_finding("QS-BIN-002", Severity::Warning),
        ],
        vec![make_secret("QS-SEC-001", "secret1")],
        60,
        "C",
    );

    let r2 = make_report(
        vec![
            make_finding("QS-NET-001", Severity::Info),
            make_finding("QS-CRYPTO-001", Severity::High),
        ],
        vec![make_secret("QS-SEC-002", "secret2")],
        90,
        "A",
    );

    let diff = compare(&r1, &r2);
    assert_eq!(
        diff.new_findings.len(),
        2,
        "All of r1's findings are new vs r2"
    );
    assert_eq!(
        diff.fixed_findings.len(),
        2,
        "All of r2's findings are fixed in r1"
    );
    assert_eq!(diff.new_secrets, 1);
    assert_eq!(diff.fixed_secrets, 1);
    assert_eq!(diff.score_delta, -30); // 60 - 90
    assert!(diff.grade_changed);
}

#[test]
fn test_baseline_empty_vs_findings() {
    let empty = make_report(vec![], vec![], 100, "A");
    let with_findings = make_report(
        vec![make_finding("QS-TEST-001", Severity::High)],
        vec![make_secret("QS-SEC-001", "val")],
        70,
        "C",
    );

    // Current has findings, baseline is empty → all are "new"
    let diff = compare(&with_findings, &empty);
    assert_eq!(diff.new_findings.len(), 1);
    assert!(diff.fixed_findings.is_empty());
    assert_eq!(diff.new_secrets, 1);

    // Reverse: current is clean, baseline had findings → all are "fixed"
    let diff2 = compare(&empty, &with_findings);
    assert!(diff2.new_findings.is_empty());
    assert_eq!(diff2.fixed_findings.len(), 1);
    assert_eq!(diff2.fixed_secrets, 1);
}
