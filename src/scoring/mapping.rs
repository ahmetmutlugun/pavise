//! Single rule-ID → OWASP Mobile Top 10 (2024) / MASVS v2 table.
//!
//! Analyzers used to hard-code a mix of 2016 and 2024 categories and MASVS v1
//! `MSTG-*` IDs per call site. `scan_ipa` now stamps every finding and secret
//! from this table, so the mapping lives in one place.

/// OWASP Mobile Top 10 2024 category and MASVS v2 control for a rule ID.
pub fn owasp_for(rule_id: &str) -> Option<(&'static str, Option<&'static str>)> {
    let m = |cat: &'static str, masvs: &'static str| Some((cat, Some(masvs)));
    match rule_id {
        // M1 Improper Credential Usage — hardcoded secrets and keys
        "QS-CERT-001" | "QS-ENTROPY-001" => m("M1", "MASVS-CRYPTO-2"),
        id if id.starts_with("QS-SEC-") => m("M1", "MASVS-CRYPTO-2"),

        // M2 Inadequate Supply Chain Security
        id if id.starts_with("QS-CVE-") => m("M2", "MASVS-CODE-3"),

        // M4 Insufficient Input/Output Validation
        "QS-API-001" | "QS-API-003" => m("M4", "MASVS-CODE-4"),
        "QS-API-015" | "QS-API-021" => m("M4", "MASVS-PLATFORM-2"),
        id if id.starts_with("QS-IPC-") => m("M4", "MASVS-PLATFORM-1"),

        // M5 Insecure Communication
        "QS-API-023" | "QS-NET-004" | "QS-CERT-002" => m("M5", "MASVS-NETWORK-2"),
        "QS-API-020" => m("M5", "MASVS-NETWORK-1"),
        id if id.starts_with("QS-ATS-") || id.starts_with("QS-NET-") => m("M5", "MASVS-NETWORK-1"),

        // M6 Inadequate Privacy Controls
        "QS-ENT-003" | "QS-ENT-007" => m("M6", "MASVS-PRIVACY-1"),
        id if id.starts_with("QS-PERM-") || id.starts_with("QS-PRIV-") => {
            m("M6", "MASVS-PRIVACY-1")
        }
        "QS-PLIST-002" => m("M6", "MASVS-PRIVACY-1"),
        "QS-PLIST-001" => m("M8", "MASVS-CODE-1"),

        // M7 Insufficient Binary Protections
        "QS-BIN-005" => m("M7", "MASVS-RESILIENCE-2"),
        "QS-BIN-007" | "QS-BIN-010" => m("M7", "MASVS-RESILIENCE-3"),
        "QS-API-005" | "QS-API-012" => m("M7", "MASVS-RESILIENCE-4"),
        "QS-API-011" => m("M7", "MASVS-RESILIENCE-1"),
        "QS-API-006" | "QS-API-010" | "QS-API-013" => m("M7", "MASVS-RESILIENCE-2"),
        "QS-ENT-008" => m("M7", "MASVS-CODE-4"),
        id if id.starts_with("QS-BIN-") => m("M7", "MASVS-CODE-4"),

        // M8 Security Misconfiguration (shared keychain/app-group/iCloud
        // entitlements are storage exposure, M9)
        "QS-ENT-001" => m("M8", "MASVS-RESILIENCE-4"),
        "QS-ENT-004" | "QS-ENT-005" => m("M9", "MASVS-STORAGE-1"),
        "QS-ENT-011" => m("M9", "MASVS-STORAGE-2"),
        "QS-ENT-012" => m("M9", "MASVS-STORAGE-1"),
        id if id.starts_with("QS-ENT-") => m("M8", "MASVS-PLATFORM-1"),
        id if id.starts_with("QS-PROV-") || id.starts_with("QS-FB-") => Some(("M8", None)),

        // M9 Insecure Data Storage
        "QS-API-002" | "QS-API-008" => m("M9", "MASVS-STORAGE-2"),
        "QS-API-009" | "QS-API-014" | "QS-API-018" | "QS-API-019" | "QS-API-024" => {
            m("M9", "MASVS-STORAGE-1")
        }
        "QS-API-025" => m("M9", "MASVS-STORAGE-2"),
        id if id.starts_with("QS-SANDBOX-") => m("M9", "MASVS-STORAGE-2"),
        id if id.starts_with("QS-STORE-") => m("M9", "MASVS-STORAGE-1"),

        // M10 Insufficient Cryptography
        "QS-API-004" | "QS-API-007" | "QS-API-016" | "QS-API-017" => m("M10", "MASVS-CRYPTO-1"),
        id if id.starts_with("QS-CRYPTO-") => m("M10", "MASVS-CRYPTO-1"),

        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uses_2024_categories_and_masvs_v2() {
        assert_eq!(
            owasp_for("QS-SEC-002"),
            Some(("M1", Some("MASVS-CRYPTO-2")))
        );
        assert_eq!(
            owasp_for("QS-STORE-001"),
            Some(("M9", Some("MASVS-STORAGE-1")))
        );
        assert_eq!(
            owasp_for("QS-CVE-2024-1234"),
            Some(("M2", Some("MASVS-CODE-3")))
        );
        assert_eq!(
            owasp_for("QS-ENT-005"),
            Some(("M9", Some("MASVS-STORAGE-1")))
        );
        assert_eq!(
            owasp_for("QS-ENT-002"),
            Some(("M8", Some("MASVS-PLATFORM-1")))
        );
        assert_eq!(owasp_for("QS-UNKNOWN-1"), None);
    }

    #[test]
    fn every_emitted_rule_is_mapped() {
        // Rule IDs that analyzers emit; a new rule must be added to the table.
        let ids = [
            "QS-ATS-001",
            "QS-ATS-014",
            "QS-API-001",
            "QS-API-023",
            "QS-BIN-001",
            "QS-BIN-010",
            "QS-CERT-001",
            "QS-CERT-002",
            "QS-CRYPTO-001",
            "QS-ENT-001",
            "QS-ENT-011",
            "QS-ENT-012",
            "QS-ENTROPY-001",
            "QS-FB-001",
            "QS-IPC-001",
            "QS-IPC-002",
            "QS-NET-001",
            "QS-NET-004",
            "QS-PERM-001",
            "QS-PLIST-001",
            "QS-PLIST-002",
            "QS-PRIV-001",
            "QS-PRIV-002",
            "QS-PROV-001",
            "QS-SANDBOX-001",
            "QS-SEC-030",
            "QS-STORE-001",
        ];
        for id in ids {
            let (cat, masvs) = owasp_for(id).unwrap_or_else(|| panic!("{} unmapped", id));
            assert!(cat.starts_with('M'));
            assert!(masvs.map_or(true, |m| m.starts_with("MASVS-")), "{}", id);
        }
        // Every rule in the embedded YAML rule sets is mapped too.
        for (name, content) in crate::rules::RULE_FILES {
            if *name != "secrets.yaml" && *name != "ios_apis.yaml" {
                continue;
            }
            for line in content.lines() {
                if let Some(id) = line.strip_prefix("- id: ") {
                    assert!(
                        owasp_for(id.trim()).is_some(),
                        "{} from {} unmapped",
                        id,
                        name
                    );
                }
            }
        }
    }
}
