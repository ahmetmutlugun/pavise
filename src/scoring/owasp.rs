use crate::types::{BinaryInfo, Finding, SecretMatch, Severity};

/// Compute a 0–100 security score and letter grade.
/// Higher is better.
///
/// `is_dev_build` — true when an `embedded.mobileprovision` is present in the
/// IPA. App Store binaries are encrypted by Apple at download time, so
/// `cryptid = 0` is expected in dev/ad-hoc/enterprise builds and should not
/// be penalised.
pub fn compute_score(
    main_binary: Option<&BinaryInfo>,
    framework_binaries: &[BinaryInfo],
    findings: &[Finding],
    secrets: &[SecretMatch],
    is_dev_build: bool,
) -> (u8, String) {
    let mut score: i32 = 100;

    // --- Main binary protections ---
    if let Some(bin) = main_binary {
        for prot in &bin.protections {
            if !prot.enabled {
                let deduction = match prot.name.as_str() {
                    n if n.contains("PIE") => 15,
                    n if n.contains("Stack Canary") => 8,
                    n if n.contains("ARC") => 10,
                    n if n.contains("Encryption") => if is_dev_build { 0 } else { 5 },
                    n if n.contains("Symbols") => 3,
                    n if n.contains("RPATH") => 0, // RPATH is flagged only when present
                    _ => 0,
                };
                score -= deduction;
            }
        }

        // RPATH present is a deduction
        for prot in &bin.protections {
            if prot.name.contains("RPATH") && !prot.enabled {
                // "enabled" = no rpath (secure). If rpath exists, enabled = false.
                score -= 3;
            }
        }
    }

    // --- Framework binary protections ---
    let mut fw_canary_deductions = 0i32;
    let mut fw_arc_deductions = 0i32;

    for fw in framework_binaries {
        for prot in &fw.protections {
            if !prot.enabled {
                if prot.name.contains("Stack Canary") && fw_canary_deductions < 8 {
                    score -= 2;
                    fw_canary_deductions += 2;
                } else if prot.name.contains("ARC") && fw_arc_deductions < 15 {
                    score -= 3;
                    fw_arc_deductions += 3;
                }
            }
        }
    }

    // --- Findings-based deductions ---
    let mut secret_high_deductions = 0i32;
    let mut secret_warn_deductions = 0i32;

    for secret in secrets {
        match secret.severity {
            Severity::High if secret_high_deductions < 20 => {
                score -= 10;
                secret_high_deductions += 10;
            }
            Severity::Warning if secret_warn_deductions < 10 => {
                score -= 5;
                secret_warn_deductions += 5;
            }
            _ => {}
        }
    }

    let mut insecure_api_deductions = 0i32;
    let mut http_url_deducted = false;
    let mut ats_deducted = false;
    let mut perm_deductions = 0i32;
    let mut cve_high_deductions = 0i32;
    let mut cve_warn_deductions = 0i32;

    for finding in findings {
        match finding.id.as_str() {
            "QS-BIN-008" => {
                score -= 3;
            }
            id if id.starts_with("QS-CVE-") => {
                match finding.severity {
                    Severity::High if cve_high_deductions < 20 => {
                        score -= 8;
                        cve_high_deductions += 8;
                    }
                    Severity::Warning if cve_warn_deductions < 10 => {
                        score -= 4;
                        cve_warn_deductions += 4;
                    }
                    _ => {}
                }
            }
            "QS-ATS-002" if !ats_deducted => {
                score -= 10;
                ats_deducted = true;
            }
            "QS-ATS-003" if !ats_deducted => {
                score -= 5;
                ats_deducted = true;
            }
            "QS-NET-001" | "QS-NET-003" if !http_url_deducted => {
                score -= 5;
                http_url_deducted = true;
            }
            id if id.starts_with("QS-API-") && insecure_api_deductions < 10 => {
                score -= 2;
                insecure_api_deductions += 2;
            }
            id if id.starts_with("QS-PERM-") && perm_deductions < 5 => {
                score -= 1;
                perm_deductions += 1;
            }
            _ => {}
        }
    }

    let score = score.max(0).min(100) as u8;
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
    use crate::types::{BinaryInfo, BinaryProtection, Finding, SecretMatch, Severity};

    fn make_protection(name: &str, enabled: bool) -> BinaryProtection {
        BinaryProtection {
            name: name.to_string(),
            enabled,
            severity: if enabled { Severity::Secure } else { Severity::High },
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
            matched_value: "secret_value".to_string(),
            file_path: None,
        }
    }

    #[test]
    fn test_perfect_score() {
        let bin = make_binary(&[
            ("PIE", true),
            ("Stack Canary", true),
            ("ARC", true),
            ("Encryption", true),
            ("Symbols", true),
        ]);
        let (score, grade) = compute_score(Some(&bin), &[], &[], &[], false);
        assert_eq!(score, 100);
        assert_eq!(grade, "A");
    }

    #[test]
    fn test_pie_missing() {
        // PIE disabled → -15
        let bin = make_binary(&[("PIE", false)]);
        let (score, _) = compute_score(Some(&bin), &[], &[], &[], false);
        assert_eq!(score, 85);
    }

    #[test]
    fn test_arc_missing() {
        // ARC disabled → -10
        let bin = make_binary(&[("ARC", false)]);
        let (score, _) = compute_score(Some(&bin), &[], &[], &[], false);
        assert_eq!(score, 90);
    }

    #[test]
    fn test_canary_missing() {
        // Stack Canary disabled → -8
        let bin = make_binary(&[("Stack Canary", false)]);
        let (score, _) = compute_score(Some(&bin), &[], &[], &[], false);
        assert_eq!(score, 92);
    }

    #[test]
    fn test_encryption_prod_deducts() {
        let bin = make_binary(&[("Encryption", false)]);
        // Production build (is_dev_build=false) → -5
        let (prod_score, _) = compute_score(Some(&bin), &[], &[], &[], false);
        assert_eq!(prod_score, 95);
        // Dev build (is_dev_build=true) → no deduction
        let (dev_score, _) = compute_score(Some(&bin), &[], &[], &[], true);
        assert_eq!(dev_score, 100);
    }

    #[test]
    fn test_high_secret_cap() {
        // 3 High secrets × 10 = 30, but cap is 20 → score = 80
        let secrets = vec![
            make_secret(Severity::High),
            make_secret(Severity::High),
            make_secret(Severity::High),
        ];
        let (score, _) = compute_score(None, &[], &[], &secrets, false);
        assert_eq!(score, 80, "3 High secrets should deduct at most 20 points");
    }

    #[test]
    fn test_ats_finding() {
        let findings = vec![make_finding("QS-ATS-002", Severity::High)];
        let (score, _) = compute_score(None, &[], &findings, &[], false);
        assert_eq!(score, 90);
    }

    #[test]
    fn test_grade_boundaries() {
        // A: 90–100 → perfect binary
        let bin = make_binary(&[("PIE", true), ("Stack Canary", true), ("ARC", true)]);
        let (s, g) = compute_score(Some(&bin), &[], &[], &[], false);
        assert_eq!(s, 100);
        assert_eq!(g, "A");

        // B: 80–89 → PIE missing (-15) → 85
        let bin_no_pie = make_binary(&[("PIE", false)]);
        let (s, g) = compute_score(Some(&bin_no_pie), &[], &[], &[], false);
        assert_eq!(s, 85);
        assert_eq!(g, "B");

        // C: 60–79 → PIE + ARC missing → 75
        let bin_no_pie_arc = make_binary(&[("PIE", false), ("ARC", false)]);
        let (s, g) = compute_score(Some(&bin_no_pie_arc), &[], &[], &[], false);
        assert_eq!(s, 75);
        assert_eq!(g, "C");

        // D: 40–59 → PIE + ARC + Canary + 2 High secrets → 100-15-10-8-20 = 47
        let bin_three_missing = make_binary(&[("PIE", false), ("ARC", false), ("Stack Canary", false)]);
        let secrets = vec![make_secret(Severity::High), make_secret(Severity::High)];
        let (s, g) = compute_score(Some(&bin_three_missing), &[], &[], &secrets, false);
        assert_eq!(s, 47);
        assert_eq!(g, "D");

        // F: below 40
        let bin_all_off = make_binary(&[
            ("PIE", false), ("ARC", false), ("Stack Canary", false),
            ("Encryption", false), ("Symbols", false),
        ]);
        let secrets3 = vec![
            make_secret(Severity::High), make_secret(Severity::High), make_secret(Severity::High),
        ];
        let findings = vec![make_finding("QS-ATS-002", Severity::High)];
        // 100-15-10-8-5-3-20-10 = 29
        let (s, g) = compute_score(Some(&bin_all_off), &[], &findings, &secrets3, false);
        assert_eq!(g, "F");
        assert!(s < 40, "Expected F-grade score < 40, got {s}");
    }

    #[test]
    fn test_score_floor() {
        // Pile on maximum deductions — score must not go below 0
        let bin = make_binary(&[
            ("PIE", false),
            ("Stack Canary", false),
            ("ARC", false),
            ("Encryption", false),
            ("Symbols", false),
            ("RPATH", false),
        ]);
        let secrets = vec![
            make_secret(Severity::High), make_secret(Severity::High), make_secret(Severity::High),
            make_secret(Severity::Warning), make_secret(Severity::Warning),
        ];
        let findings = vec![
            make_finding("QS-ATS-002", Severity::High),
            make_finding("QS-CVE-001", Severity::High),
            make_finding("QS-CVE-002", Severity::High),
            make_finding("QS-CVE-003", Severity::High),
            make_finding("QS-API-001", Severity::Warning),
            make_finding("QS-API-002", Severity::Warning),
            make_finding("QS-API-003", Severity::Warning),
            make_finding("QS-PERM-001", Severity::Info),
            make_finding("QS-PERM-002", Severity::Info),
            make_finding("QS-PERM-003", Severity::Info),
        ];
        let (score, _) = compute_score(Some(&bin), &[], &findings, &secrets, false);
        assert_eq!(score, 0, "Score must floor at 0, got {score}");
    }
}
