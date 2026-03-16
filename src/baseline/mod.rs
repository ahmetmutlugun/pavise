//! Baseline / diff comparison for CI/CD workflows.
//!
//! Given a current `ScanReport` and a previously saved baseline report (JSON),
//! `compare` computes new vs fixed findings and secrets, a score delta, and
//! whether the letter grade changed.

use std::collections::HashSet;

use crate::types::{DiffResult, ScanReport};

/// Compare `current` against `baseline` and return a `DiffResult`.
///
/// Finding identity key: `(id, first_evidence)`.
/// Secret identity key:  `(rule_id, matched_value)`.
pub fn compare(current: &ScanReport, baseline: &ScanReport) -> DiffResult {
    // --- Findings ---
    let current_keys: HashSet<(String, String)> = current
        .findings
        .iter()
        .map(|f| (f.id.clone(), f.evidence.first().cloned().unwrap_or_default()))
        .collect();

    let baseline_keys: HashSet<(String, String)> = baseline
        .findings
        .iter()
        .map(|f| (f.id.clone(), f.evidence.first().cloned().unwrap_or_default()))
        .collect();

    // New: in current but not baseline
    let new_findings: Vec<String> = current
        .findings
        .iter()
        .filter(|f| {
            let key = (f.id.clone(), f.evidence.first().cloned().unwrap_or_default());
            !baseline_keys.contains(&key)
        })
        .map(|f| f.id.clone())
        .collect();

    // Fixed: in baseline but not current
    let fixed_findings: Vec<String> = baseline
        .findings
        .iter()
        .filter(|f| {
            let key = (f.id.clone(), f.evidence.first().cloned().unwrap_or_default());
            !current_keys.contains(&key)
        })
        .map(|f| f.id.clone())
        .collect();

    // --- Secrets ---
    let current_secret_keys: HashSet<(String, String)> = current
        .secrets
        .iter()
        .map(|s| (s.rule_id.clone(), s.matched_value.clone()))
        .collect();

    let baseline_secret_keys: HashSet<(String, String)> = baseline
        .secrets
        .iter()
        .map(|s| (s.rule_id.clone(), s.matched_value.clone()))
        .collect();

    let new_secrets = current
        .secrets
        .iter()
        .filter(|s| !baseline_secret_keys.contains(&(s.rule_id.clone(), s.matched_value.clone())))
        .count();

    let fixed_secrets = baseline
        .secrets
        .iter()
        .filter(|s| !current_secret_keys.contains(&(s.rule_id.clone(), s.matched_value.clone())))
        .count();

    // --- Score delta ---
    let score_delta =
        current.security_score as i16 - baseline.security_score as i16;

    let grade_changed = current.grade != baseline.grade;

    DiffResult {
        new_findings,
        fixed_findings,
        new_secrets,
        fixed_secrets,
        score_delta,
        grade_changed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use crate::types::{
        AppInfo, FileHashes, Finding, SecretMatch, Severity,
    };

    fn make_report(
        findings: Vec<Finding>,
        secrets: Vec<SecretMatch>,
        score: u8,
        grade: &str,
    ) -> ScanReport {
        ScanReport {
            app_info: AppInfo::default(),
            file_hashes: FileHashes {
                md5: String::new(),
                sha1: String::new(),
                sha256: String::new(),
                size_bytes: 0,
            },
            main_binary: None,
            framework_binaries: Vec::new(),
            findings,
            domains: Vec::new(),
            emails: Vec::new(),
            trackers: Vec::new(),
            secrets,
            firebase: None,
            scan_duration_ms: 0,
            security_score: score,
            grade: grade.to_string(),
            scan_log: Vec::new(),
            domain_intel: Vec::new(),
            framework_components: Vec::new(),
            provisioning: None,
            owasp_summary: HashMap::new(),
            baseline_diff: None,
        }
    }

    fn make_finding(id: &str) -> Finding {
        Finding {
            id: id.to_string(),
            title: String::new(),
            description: String::new(),
            severity: Severity::Warning,
            category: String::new(),
            cwe: None,
            owasp_mobile: None,
            owasp_masvs: None,
            evidence: vec!["test-evidence".to_string()],
            remediation: None,
        }
    }

    fn make_secret(rule_id: &str, value: &str) -> SecretMatch {
        SecretMatch {
            rule_id: rule_id.to_string(),
            title: String::new(),
            severity: Severity::High,
            matched_value: value.to_string(),
            file_path: None,
        }
    }

    #[test]
    fn test_identical_no_diff() {
        let f = make_finding("QS-API-001");
        let s = make_secret("QS-SEC-001", "myvalue");
        let current = make_report(vec![f.clone()], vec![s.clone()], 80, "B");
        let baseline = make_report(vec![f], vec![s], 80, "B");
        let diff = compare(&current, &baseline);
        assert!(diff.new_findings.is_empty());
        assert!(diff.fixed_findings.is_empty());
        assert_eq!(diff.new_secrets, 0);
        assert_eq!(diff.fixed_secrets, 0);
        assert_eq!(diff.score_delta, 0);
        assert!(!diff.grade_changed);
    }

    #[test]
    fn test_new_finding() {
        let baseline = make_report(vec![], vec![], 80, "B");
        let current = make_report(vec![make_finding("QS-API-001")], vec![], 80, "B");
        let diff = compare(&current, &baseline);
        assert_eq!(diff.new_findings, vec!["QS-API-001"]);
        assert!(diff.fixed_findings.is_empty());
    }

    #[test]
    fn test_fixed_finding() {
        let baseline = make_report(vec![make_finding("QS-API-001")], vec![], 80, "B");
        let current = make_report(vec![], vec![], 80, "B");
        let diff = compare(&current, &baseline);
        assert!(diff.new_findings.is_empty());
        assert_eq!(diff.fixed_findings, vec!["QS-API-001"]);
    }

    #[test]
    fn test_new_secret_counted() {
        let baseline = make_report(vec![], vec![], 80, "B");
        let current = make_report(
            vec![],
            vec![make_secret("QS-SEC-002", "AKIAIOSFODNN7EXAMPLE1234")],
            80,
            "B",
        );
        let diff = compare(&current, &baseline);
        assert_eq!(diff.new_secrets, 1);
        assert_eq!(diff.fixed_secrets, 0);
    }

    #[test]
    fn test_score_delta_and_grade_change() {
        let baseline = make_report(vec![], vec![], 65, "C");
        let current = make_report(vec![], vec![], 85, "B");
        let diff = compare(&current, &baseline);
        assert_eq!(diff.score_delta, 20);
        assert!(diff.grade_changed);
    }
}
