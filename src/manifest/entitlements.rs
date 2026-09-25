//! iOS entitlements analysis.
//!
//! Entitlements are embedded in the Mach-O code signature as an XML plist blob.
//! This module:
//!   1. Extracts the entitlements XML from the LC_CODE_SIGNATURE superblob
//!   2. Parses the plist and analyzes each key for security findings

use crate::types::{Finding, Severity};
use tracing::debug;

// SuperBlob and blob magic constants (big-endian values)
const CS_MAGIC_EMBEDDED_SIGNATURE: u32 = 0xFADE_0CC0;
const CSSLOT_ENTITLEMENTS: u32 = 0x0000_0005;
const CS_MAGIC_ENTITLEMENTS: u32 = 0xFADE_7171;

/// Extract the entitlements plist bytes from a Mach-O binary (thin or fat).
///
/// Returns the raw XML plist bytes if entitlements are present, or `None`
/// if the binary has no code signature / no entitlements blob.
pub fn extract_from_binary(data: &[u8]) -> Option<Vec<u8>> {
    use goblin::mach::Mach;

    match Mach::parse(data).ok()? {
        Mach::Binary(macho) => {
            let dataoff = codesig_offset(&macho)?;
            parse_entitlements_blob(data, dataoff)
        }
        Mach::Fat(fat) => {
            // Prefer ARM64; fall back to the first available arch.
            const ARM64_CPUTYPE: u32 = 0x0100_000c;
            let arches = fat.arches().ok()?;
            let arch = arches
                .iter()
                .find(|a| a.cputype == ARM64_CPUTYPE)
                .or_else(|| arches.first())?;

            let slice = data.get(arch.offset as usize..(arch.offset + arch.size) as usize)?;
            let inner = goblin::mach::MachO::parse(slice, 0).ok()?;
            let dataoff = codesig_offset(&inner)?;
            parse_entitlements_blob(slice, dataoff)
        }
    }
}

/// Analyze entitlements plist bytes and return security findings.
pub fn analyze(plist_data: &[u8]) -> Vec<Finding> {
    let value: plist::Value = match plist::from_bytes(plist_data) {
        Ok(v) => v,
        Err(e) => {
            debug!("Failed to parse entitlements plist: {}", e);
            return Vec::new();
        }
    };

    let dict = match value.as_dictionary() {
        Some(d) => d,
        None => return Vec::new(),
    };

    let mut findings: Vec<Finding> = Vec::new();

    // ------------------------------------------------------------------ //
    // get-task-allow: true  →  HIGH
    // This enables Xcode debugging and should NEVER be in production builds.
    // ------------------------------------------------------------------ //
    if dict.get("get-task-allow").and_then(|v| v.as_boolean()) == Some(true) {
        findings.push(Finding {
            id: "QS-ENT-001".to_string(),
            title: "get-task-allow Entitlement Enabled".to_string(),
            description: "The 'get-task-allow' entitlement is set to true. This allows other processes to attach a debugger to this app and is only valid for development builds. A production release with this flag allows runtime manipulation and memory inspection of the app.".to_string(),
            severity: Severity::High,
            category: "entitlements".to_string(),
            cwe: Some("CWE-264".to_string()),
            owasp_mobile: Some("M3".to_string()),
            owasp_masvs: Some("MSTG-RESILIENCE-2".to_string()),
            evidence: vec!["get-task-allow: true".to_string()],
            remediation: Some("Ensure 'get-task-allow' is false or absent in release/distribution builds. Xcode sets this automatically when using a Distribution provisioning profile.".to_string()),
        });
    }

    // ------------------------------------------------------------------ //
    // aps-environment: development  →  INFO
    // Production apps should use the production APN environment.
    // ------------------------------------------------------------------ //
    if let Some(env) = dict.get("aps-environment").and_then(|v| v.as_string()) {
        if env == "development" {
            findings.push(Finding {
                id: "QS-ENT-002".to_string(),
                title: "Push Notification Environment: Development".to_string(),
                description: "The 'aps-environment' entitlement is set to 'development'. Push notifications will only work with development APNs certificates. A production binary should use 'production'.".to_string(),
                severity: Severity::Info,
                category: "entitlements".to_string(),
                cwe: None,
                owasp_mobile: None,
                owasp_masvs: None,
                evidence: vec![format!("aps-environment: {}", env)],
                remediation: Some("Use a Distribution provisioning profile; Xcode will set aps-environment to 'production' automatically.".to_string()),
            });
        }
    }

    // ------------------------------------------------------------------ //
    // com.apple.developer.healthkit  →  INFO (WARNING with clinical records)
    // The capability marks the data as sensitive, not the app as weak; only
    // Health Records (FHIR clinical data) access is raised to a warning.
    // ------------------------------------------------------------------ //
    if dict.contains_key("com.apple.developer.healthkit") {
        let clinical = dict
            .get("com.apple.developer.healthkit.access")
            .and_then(|v| v.as_array())
            .is_some_and(|a| a.iter().any(|v| v.as_string() == Some("health-records")));
        let mut evidence = vec!["com.apple.developer.healthkit: present".to_string()];
        if clinical {
            evidence.push("com.apple.developer.healthkit.access: health-records".to_string());
        }
        findings.push(Finding {
            id: "QS-ENT-003".to_string(),
            title: if clinical {
                "HealthKit Clinical Records Entitlement".to_string()
            } else {
                "HealthKit Access Entitlement".to_string()
            },
            description: if clinical {
                "The app has the HealthKit entitlement with Health Records access. It can read the user's clinical records (FHIR data from healthcare providers), which carry the highest privacy and regulatory exposure. Ensure this data is handled in compliance with HIPAA/GDPR and Apple's HealthKit guidelines.".to_string()
            } else {
                "The app has the HealthKit entitlement. It can access sensitive health and fitness data from the user's Health app. Ensure HealthKit data is handled in compliance with HIPAA/GDPR and Apple's HealthKit guidelines.".to_string()
            },
            severity: if clinical { Severity::Warning } else { Severity::Info },
            category: "entitlements".to_string(),
            cwe: Some("CWE-359".to_string()),
            owasp_mobile: Some("M6".to_string()),
            owasp_masvs: Some("MSTG-STORAGE-1".to_string()),
            evidence,
            remediation: Some("Review HealthKit data usage. Store health data only in encrypted storage and never transmit it without user consent.".to_string()),
        });
    }

    // ------------------------------------------------------------------ //
    // keychain-access-groups  →  INFO
    // Broad keychain sharing can expose credentials across apps.
    // ------------------------------------------------------------------ //
    if let Some(groups) = dict
        .get("keychain-access-groups")
        .and_then(|v| v.as_array())
    {
        let group_list: Vec<String> = groups
            .iter()
            .filter_map(|v| v.as_string())
            .map(|s| s.to_string())
            .collect();

        if !group_list.is_empty() {
            findings.push(Finding {
                id: "QS-ENT-004".to_string(),
                title: "Keychain Access Groups Configured".to_string(),
                description: format!(
                    "The app shares keychain items with {} group(s): {}. Keychain access groups allow multiple apps to share credentials. Ensure each group contains only apps that legitimately need shared access.",
                    group_list.len(),
                    group_list.join(", ")
                ),
                severity: Severity::Info,
                category: "entitlements".to_string(),
                cwe: Some("CWE-200".to_string()),
                owasp_mobile: Some("M2".to_string()),
                owasp_masvs: Some("MSTG-STORAGE-1".to_string()),
                evidence: group_list.clone(),
                remediation: Some("Verify that all apps in each keychain access group are controlled by your team. Remove groups that are no longer needed.".to_string()),
            });
        }
    }

    // ------------------------------------------------------------------ //
    // com.apple.security.application-groups  →  INFO
    // Shared containers can expose data between apps.
    // ------------------------------------------------------------------ //
    if let Some(groups) = dict
        .get("com.apple.security.application-groups")
        .and_then(|v| v.as_array())
    {
        let group_list: Vec<String> = groups
            .iter()
            .filter_map(|v| v.as_string())
            .map(|s| s.to_string())
            .collect();

        if !group_list.is_empty() {
            findings.push(Finding {
                id: "QS-ENT-005".to_string(),
                title: "App Group Data Sharing Enabled".to_string(),
                description: format!(
                    "The app participates in {} app group(s): {}. App groups create a shared file container accessible by all apps in the group.",
                    group_list.len(),
                    group_list.join(", ")
                ),
                severity: Severity::Info,
                category: "entitlements".to_string(),
                cwe: Some("CWE-200".to_string()),
                owasp_mobile: Some("M2".to_string()),
                owasp_masvs: Some("MSTG-STORAGE-1".to_string()),
                evidence: group_list,
                remediation: Some("Ensure sensitive data written to the shared container is encrypted and access is restricted to trusted apps.".to_string()),
            });
        }
    }

    // ------------------------------------------------------------------ //
    // com.apple.developer.associated-domains  →  INFO (universal links)
    // ------------------------------------------------------------------ //
    if let Some(domains) = dict
        .get("com.apple.developer.associated-domains")
        .and_then(|v| v.as_array())
    {
        let domain_list: Vec<String> = domains
            .iter()
            .filter_map(|v| v.as_string())
            .map(|s| s.to_string())
            .collect();

        if !domain_list.is_empty() {
            findings.push(Finding {
                id: "QS-ENT-006".to_string(),
                title: "Associated Domains (Universal Links / Shared Credentials)".to_string(),
                description: format!(
                    "The app declares {} associated domain(s) for universal links or shared credentials: {}.",
                    domain_list.len(),
                    domain_list.join(", ")
                ),
                severity: Severity::Info,
                category: "entitlements".to_string(),
                cwe: Some("CWE-346".to_string()),
                owasp_mobile: Some("M1".to_string()),
                owasp_masvs: Some("MSTG-PLATFORM-3".to_string()),
                evidence: domain_list,
                remediation: Some("Ensure the apple-app-site-association file on each associated domain is correctly configured and served over HTTPS.".to_string()),
            });
        }
    }

    // ------------------------------------------------------------------ //
    // com.apple.developer.nfc.readersession.formats  →  INFO
    // ------------------------------------------------------------------ //
    if dict.contains_key("com.apple.developer.nfc.readersession.formats") {
        findings.push(Finding {
            id: "QS-ENT-007".to_string(),
            title: "NFC Reader Access Entitlement".to_string(),
            description: "The app has the NFC reader entitlement and can read NFC tags. Ensure NFC data is handled securely and the app does not read NFC data without user interaction.".to_string(),
            severity: Severity::Info,
            category: "entitlements".to_string(),
            cwe: None,
            owasp_mobile: None,
            owasp_masvs: None,
            evidence: vec!["com.apple.developer.nfc.readersession.formats: present".to_string()],
            remediation: None,
        });
    }

    // ------------------------------------------------------------------ //
    // dynamic-codesigning  →  WARNING
    // iOS's JIT entitlement: lets the process map writable+executable pages
    // (normally private to WebKit; seen in sideloaded emulators/VMs). The
    // macOS hardened-runtime keys (com.apple.security.cs.*) are ignored on
    // iOS; allow-jit is accepted only as an alias for Catalyst-style builds.
    // ------------------------------------------------------------------ //
    let jit_key = ["dynamic-codesigning", "com.apple.security.cs.allow-jit"]
        .into_iter()
        .find(|k| dict.get(k).and_then(|v| v.as_boolean()) == Some(true));
    if let Some(key) = jit_key {
        findings.push(Finding {
            id: "QS-ENT-008".to_string(),
            title: "JIT Compilation Entitlement Enabled".to_string(),
            description: format!(
                "The '{}' entitlement is enabled. This lets the app map pages as simultaneously \
                writable and executable, which JIT engines need. An attacker who achieves code \
                execution can use it to run arbitrary unsigned code.",
                key
            ),
            severity: Severity::Warning,
            category: "entitlements".to_string(),
            cwe: Some("CWE-119".to_string()),
            owasp_mobile: Some("M8".to_string()),
            owasp_masvs: Some("MSTG-CODE-2".to_string()),
            evidence: vec![format!("{}: true", key)],
            remediation: Some("Only enable this entitlement if the app includes a JIT-based runtime. Audit all code paths that generate executable code at runtime.".to_string()),
        });
    }

    // ------------------------------------------------------------------ //
    // com.apple.developer.icloud-container-identifiers  →  INFO
    // iCloud containers are accessible across the user's devices; storing
    // sensitive data here without encryption is a privacy risk.
    // ------------------------------------------------------------------ //
    if let Some(containers) = dict
        .get("com.apple.developer.icloud-container-identifiers")
        .and_then(|v| v.as_array())
    {
        let container_list: Vec<String> = containers
            .iter()
            .filter_map(|v| v.as_string())
            .map(|s| s.to_string())
            .collect();

        if !container_list.is_empty() {
            findings.push(Finding {
                id: "QS-ENT-011".to_string(),
                title: "iCloud Container Access".to_string(),
                description: format!(
                    "The app has access to {} iCloud container(s): {}. \
                    iCloud containers are synced across all of the user's devices and are \
                    accessible via iCloud.com. Any sensitive data stored here must be encrypted \
                    at the application layer before upload.",
                    container_list.len(),
                    container_list.join(", ")
                ),
                severity: Severity::Info,
                category: "entitlements".to_string(),
                cwe: Some("CWE-312".to_string()),
                owasp_mobile: Some("M2".to_string()),
                owasp_masvs: Some("MSTG-STORAGE-1".to_string()),
                evidence: container_list,
                remediation: Some("Encrypt sensitive data before writing it to iCloud containers. Do not store credentials, health data, or financial information in iCloud without application-layer encryption.".to_string()),
            });
        }
    }

    findings.extend(analyze_data_protection(dict));

    findings
}

/// com.apple.developer.default-data-protection sets the file protection class
/// for files the app creates. Without it (or with CompleteUntilFirstUserAuthentication,
/// the implicit default) files stay decryptable while the device is locked
/// once it has been unlocked after boot; NSFileProtectionNone never encrypts
/// them with a passcode-derived key.
fn analyze_data_protection(dict: &plist::Dictionary) -> Option<Finding> {
    const KEY: &str = "com.apple.developer.default-data-protection";
    let value = dict.get(KEY).and_then(|v| v.as_string());
    let (severity, evidence, description) = match value {
        Some("NSFileProtectionComplete") | Some("NSFileProtectionCompleteUnlessOpen") => {
            return None
        }
        Some("NSFileProtectionNone") => (
            Severity::Warning,
            format!("{}: NSFileProtectionNone", KEY),
            "The default data protection class is NSFileProtectionNone: files the app writes \
            are not protected by the device passcode and can be read from a locked device.",
        ),
        other => (
            Severity::Info,
            format!("{}: {}", KEY, other.unwrap_or("absent")),
            "Files the app writes default to NSFileProtectionCompleteUntilFirstUserAuthentication: \
            they stay readable while the device is locked, from the first unlock after boot.",
        ),
    };
    Some(Finding {
        id: "QS-ENT-012".to_string(),
        title: "Default Data Protection Weaker Than Complete".to_string(),
        description: description.to_string(),
        severity,
        category: "entitlements".to_string(),
        cwe: Some("CWE-311".to_string()),
        owasp_mobile: Some("M9".to_string()),
        owasp_masvs: Some("MASVS-STORAGE-1".to_string()),
        evidence: vec![evidence],
        remediation: Some(
            "Enable the Data Protection capability with NSFileProtectionComplete, or set \
            FileProtectionType.complete on files that hold sensitive data."
                .to_string(),
        ),
    })
}

// ------------------------------------------------------------------ //
// Private helpers
// ------------------------------------------------------------------ //

/// Return the byte offset within `data` where the code signature starts,
/// by inspecting the LC_CODE_SIGNATURE load command.
fn codesig_offset(macho: &goblin::mach::MachO) -> Option<usize> {
    use goblin::mach::load_command::CommandVariant;
    for lc in &macho.load_commands {
        if let CommandVariant::CodeSignature(cs) = &lc.command {
            return Some(cs.dataoff as usize);
        }
    }
    None
}

/// Parse the Apple code-signature SuperBlob starting at `offset` within `data`,
/// find the entitlements blob (type CSSLOT_ENTITLEMENTS), and return its payload bytes.
fn parse_entitlements_blob(data: &[u8], offset: usize) -> Option<Vec<u8>> {
    let blob = data.get(offset..)?;

    if blob.len() < 12 {
        return None;
    }

    let magic = u32::from_be_bytes(blob[0..4].try_into().ok()?);
    if magic != CS_MAGIC_EMBEDDED_SIGNATURE {
        debug!(
            "Unexpected code signature magic: {:#010x} (expected {:#010x})",
            magic, CS_MAGIC_EMBEDDED_SIGNATURE
        );
        return None;
    }

    let _total_len = u32::from_be_bytes(blob[4..8].try_into().ok()?);
    let count = u32::from_be_bytes(blob[8..12].try_into().ok()?) as usize;

    // Each index entry is 8 bytes: type (u32) + offset (u32), starting at byte 12
    for i in 0..count {
        let entry_start = 12 + i * 8;
        let entry = blob.get(entry_start..entry_start + 8)?;
        let slot_type = u32::from_be_bytes(entry[0..4].try_into().ok()?);
        let slot_offset = u32::from_be_bytes(entry[4..8].try_into().ok()?) as usize;

        if slot_type != CSSLOT_ENTITLEMENTS {
            continue;
        }

        // The slot offset is relative to the start of the superblob
        let ent_blob = blob.get(slot_offset..)?;
        if ent_blob.len() < 8 {
            return None;
        }

        let ent_magic = u32::from_be_bytes(ent_blob[0..4].try_into().ok()?);
        if ent_magic != CS_MAGIC_ENTITLEMENTS {
            debug!("Unexpected entitlements blob magic: {:#010x}", ent_magic);
            return None;
        }

        let ent_len = u32::from_be_bytes(ent_blob[4..8].try_into().ok()?) as usize;
        if ent_len < 8 || ent_len > ent_blob.len() {
            return None;
        }

        // The plist payload starts after the 8-byte blob header
        return Some(ent_blob[8..ent_len].to_vec());
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Finding IDs, without the data-protection finding every profile gets.
    fn ids(xml: &str) -> Vec<String> {
        analyze(xml.as_bytes())
            .into_iter()
            .map(|f| f.id)
            .filter(|id| id != "QS-ENT-012")
            .collect()
    }

    fn data_protection(value: Option<&str>) -> Option<Finding> {
        let entry = value.map_or(String::new(), |v| {
            format!("<key>com.apple.developer.default-data-protection</key><string>{v}</string>")
        });
        let xml = format!(r#"<plist version="1.0"><dict>{entry}</dict></plist>"#);
        analyze(xml.as_bytes())
            .into_iter()
            .find(|f| f.id == "QS-ENT-012")
    }

    #[test]
    fn data_protection_class_graded() {
        assert!(data_protection(Some("NSFileProtectionComplete")).is_none());
        let none = data_protection(Some("NSFileProtectionNone")).expect("finding");
        assert_eq!(none.severity, Severity::Warning);
        let absent = data_protection(None).expect("finding");
        assert_eq!(absent.severity, Severity::Info);
        assert_eq!(
            absent.evidence,
            vec!["com.apple.developer.default-data-protection: absent"]
        );
    }

    #[test]
    fn ios_jit_entitlement_detected() {
        let xml = r#"<plist version="1.0"><dict>
  <key>dynamic-codesigning</key><true/>
</dict></plist>"#;
        assert_eq!(ids(xml), vec!["QS-ENT-008"]);
    }

    #[test]
    fn healthkit_info_unless_clinical_records() {
        let sev = |extra: &str| {
            let xml = format!(
                r#"<plist version="1.0"><dict>
  <key>com.apple.developer.healthkit</key><true/>{extra}
</dict></plist>"#
            );
            analyze(xml.as_bytes())
                .into_iter()
                .find(|f| f.id == "QS-ENT-003")
                .expect("finding")
                .severity
        };
        assert_eq!(sev(""), Severity::Info);
        assert_eq!(
            sev("<key>com.apple.developer.healthkit.access</key><array></array>"),
            Severity::Info
        );
        assert_eq!(
            sev("<key>com.apple.developer.healthkit.access</key><array><string>health-records</string></array>"),
            Severity::Warning
        );
    }

    #[test]
    fn macos_only_keys_ignored() {
        let xml = r#"<plist version="1.0"><dict>
  <key>com.apple.security.cs.allow-unsigned-executable-memory</key><true/>
  <key>com.apple.security.cs.disable-library-validation</key><true/>
</dict></plist>"#;
        assert!(ids(xml).is_empty());
    }
}
