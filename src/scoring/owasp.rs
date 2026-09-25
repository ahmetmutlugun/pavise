use std::collections::HashMap;

use crate::types::{Finding, SecretMatch, Severity};

/// Scoring class: decides how much a High/Warning finding costs and caps the
/// total any one area can take off, so e.g. a pile of API-usage hints can't
/// outweigh a leaked private key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ScoreClass {
    /// Missing binary protections (PIE, canary, ARC, code signature, symbols).
    Hardening,
    /// Imported API usage (strcpy, rand, SHA1…) — weak signals, not proof.
    ApiUsage,
    /// Hardcoded secrets and bundled private keys.
    Secrets,
    /// ATS, cleartext URLs, pinning, sanctioned hosts.
    Network,
    /// Entitlements, provisioning, sandbox and IPC configuration.
    Platform,
    /// Known-vulnerable dependencies (OSV).
    Dependencies,
    Other,
}

impl ScoreClass {
    /// (High deduction, Warning deduction, class cap)
    fn weights(self) -> (i32, i32, i32) {
        match self {
            ScoreClass::Hardening => (15, 3, 30),
            ScoreClass::ApiUsage => (8, 2, 10),
            ScoreClass::Secrets => (20, 3, 40),
            ScoreClass::Network => (15, 4, 25),
            ScoreClass::Platform => (20, 4, 30),
            ScoreClass::Dependencies => (10, 4, 30),
            ScoreClass::Other => (10, 3, 15),
        }
    }

    fn of(id: &str, category: &str) -> Self {
        let prefix = id.splitn(3, '-').take(2).collect::<Vec<_>>().join("-");
        match prefix.as_str() {
            "QS-BIN" => ScoreClass::Hardening,
            "QS-API" => ScoreClass::ApiUsage,
            "QS-SEC" | "QS-ENTROPY" | "QS-CERT" => ScoreClass::Secrets,
            "QS-ATS" | "QS-NET" => ScoreClass::Network,
            "QS-ENT" | "QS-PROV" | "QS-SANDBOX" | "QS-IPC" | "QS-PERM" | "QS-PLIST" | "QS-PRIV"
            | "QS-FB" => ScoreClass::Platform,
            "QS-CVE" => ScoreClass::Dependencies,
            _ => match category {
                "secrets" => ScoreClass::Secrets,
                "network" => ScoreClass::Network,
                "binary" => ScoreClass::Hardening,
                "sca" => ScoreClass::Dependencies,
                _ => ScoreClass::Other,
            },
        }
    }
}

/// Rules that never affect the score:
/// - QS-BIN-005: FairPlay encryption is applied by Apple at download time, so
///   every sideloaded/CI build has cryptid = 0.
/// - QS-PROV-002/003: profile expiry depends on the scan date, not the app.
const UNSCORED: &[&str] = &["QS-BIN-005", "QS-PROV-002", "QS-PROV-003"];

/// Map a rule ID to its root cause so one issue is only deducted once.
fn root_cause(id: &str) -> &str {
    match id {
        // Same private key reported by file classification and secret regex.
        "QS-SEC-004" => "QS-CERT-001",
        _ => id,
    }
}

/// One scored root cause.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Deduction {
    pub rule_id: String,
    pub class: ScoreClass,
    pub points: i32,
}

/// Per-root-cause deductions before class caps are applied.
pub fn deductions(findings: &[Finding], secrets: &[SecretMatch]) -> Vec<Deduction> {
    let items = findings
        .iter()
        .map(|f| (f.id.as_str(), &f.severity, f.category.as_str()))
        .chain(
            secrets
                .iter()
                .map(|s| (s.rule_id.as_str(), &s.severity, "secrets")),
        );

    let mut by_root: HashMap<&str, Deduction> = HashMap::new();
    for (id, severity, category) in items {
        if UNSCORED.contains(&id) {
            continue;
        }
        let root = root_cause(id);
        let class = ScoreClass::of(root, category);
        let (high, warning, _) = class.weights();
        let points = match severity {
            Severity::High => high,
            Severity::Warning => warning,
            Severity::Info | Severity::Secure => continue,
        };
        let entry = by_root.entry(root).or_insert_with(|| Deduction {
            rule_id: root.to_string(),
            class,
            points: 0,
        });
        entry.points = entry.points.max(points);
    }

    let mut out: Vec<Deduction> = by_root.into_values().collect();
    out.sort_by(|a, b| b.points.cmp(&a.points).then(a.rule_id.cmp(&b.rule_id)));
    out
}

/// Compute a 0–100 security score and letter grade (higher is better).
///
/// Every High/Warning finding and secret deducts once per root cause, weighted
/// by its [`ScoreClass`]; each class's total is capped. Info findings never
/// deduct. Binary protections are scored through their QS-BIN findings, so
/// they are not counted a second time here.
pub fn compute_score(findings: &[Finding], secrets: &[SecretMatch]) -> (u8, String) {
    let mut per_class: HashMap<ScoreClass, i32> = HashMap::new();
    for d in deductions(findings, secrets) {
        *per_class.entry(d.class).or_default() += d.points;
    }
    let total: i32 = per_class
        .iter()
        .map(|(class, pts)| (*pts).min(class.weights().2))
        .sum();

    let score = (100 - total).clamp(0, 100) as u8;
    let grade = grade_from_score(score);
    (score, grade)
}

fn grade_from_score(score: u8) -> String {
    match score {
        90..=100 => "A".to_string(),
        80..=89 => "B".to_string(),
        60..=79 => "C".to_string(),
        40..=59 => "D".to_string(),
        _ => "F".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_finding(id: &str, severity: Severity, category: &str) -> Finding {
        Finding {
            id: id.to_string(),
            title: String::new(),
            description: String::new(),
            severity,
            category: category.to_string(),
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
            matched_value: "secret_value".to_string(),
            file_path: None,
            cwe: None,
            owasp_mobile: None,
            owasp_masvs: None,
            remediation: None,
        }
    }

    fn score(findings: &[Finding], secrets: &[SecretMatch]) -> u8 {
        compute_score(findings, secrets).0
    }

    #[test]
    fn perfect_score() {
        let secure = make_finding("QS-BIN-001", Severity::Secure, "binary");
        assert_eq!(compute_score(&[secure], &[]), (100, "A".to_string()));
    }

    #[test]
    fn info_never_deducts() {
        let findings = vec![
            make_finding("QS-API-002", Severity::Info, "binary"),
            make_finding("QS-API-023", Severity::Info, "network"),
            make_finding("QS-PERM-001", Severity::Info, "permissions"),
        ];
        assert_eq!(score(&findings, &[]), 100);
    }

    #[test]
    fn get_task_allow_is_not_an_a() {
        // Dev build: get-task-allow + development profile.
        let findings = vec![
            make_finding("QS-ENT-001", Severity::High, "entitlements"),
            make_finding("QS-PROV-001", Severity::Warning, "configuration"),
        ];
        assert_eq!(compute_score(&findings, &[]), (76, "C".to_string()));
    }

    #[test]
    fn previously_ignored_categories_now_deduct() {
        for (id, cat) in [
            ("QS-ENT-001", "entitlements"),
            ("QS-CERT-001", "secrets"),
            ("QS-NET-002", "network"),
            ("QS-CVE-2024-1", "sca"),
        ] {
            let f = make_finding(id, Severity::High, cat);
            assert!(score(&[f], &[]) < 100, "{} should deduct", id);
        }
    }

    #[test]
    fn fairplay_and_profile_expiry_unscored() {
        let findings = vec![
            make_finding("QS-BIN-005", Severity::Warning, "binary"),
            make_finding("QS-PROV-002", Severity::High, "configuration"),
            make_finding("QS-PROV-003", Severity::Warning, "configuration"),
        ];
        assert_eq!(score(&findings, &[]), 100);
    }

    #[test]
    fn one_deduction_per_root_cause() {
        // Private key via file classification and via secret regex.
        let findings = vec![
            make_finding("QS-CERT-001", Severity::High, "secrets"),
            make_finding("QS-CERT-001", Severity::High, "secrets"),
        ];
        let secrets = vec![
            make_secret("QS-SEC-004", Severity::High),
            make_secret("QS-SEC-004", Severity::High),
        ];
        assert_eq!(score(&findings, &secrets), 80);

        // Many instances of one secret rule count once.
        let secrets: Vec<_> = (0..50)
            .map(|_| make_secret("QS-ENTROPY-001", Severity::Warning))
            .collect();
        assert_eq!(score(&[], &secrets), 97);
    }

    #[test]
    fn class_caps_apply() {
        // Ten distinct API-usage warnings cap at 10.
        let findings: Vec<_> = (1..=10)
            .map(|i| make_finding(&format!("QS-API-{:03}", i), Severity::Warning, "binary"))
            .collect();
        assert_eq!(score(&findings, &[]), 90);
    }

    #[test]
    fn score_floors_at_zero_and_grades() {
        let mut findings = Vec::new();
        for (p, cat) in [
            ("QS-BIN", "binary"),
            ("QS-ATS", "network"),
            ("QS-ENT", "entitlements"),
            ("QS-CVE", "sca"),
            ("QS-API", "binary"),
            ("QS-OTHER", "misc"),
        ] {
            for i in 1..=5 {
                findings.push(make_finding(
                    &format!("{}-{:03}", p, i),
                    Severity::High,
                    cat,
                ));
            }
        }
        let secrets: Vec<_> = (1..=5)
            .map(|i| make_secret(&format!("QS-SEC-{:03}", i), Severity::High))
            .collect();
        assert_eq!(compute_score(&findings, &secrets), (0, "F".to_string()));

        assert_eq!(grade_from_score(90), "A");
        assert_eq!(grade_from_score(89), "B");
        assert_eq!(grade_from_score(60), "C");
        assert_eq!(grade_from_score(59), "D");
        assert_eq!(grade_from_score(39), "F");
    }
}
