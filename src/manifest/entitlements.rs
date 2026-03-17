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
    // com.apple.developer.healthkit  →  WARNING (medical data access)
    // ------------------------------------------------------------------ //
    if dict.contains_key("com.apple.developer.healthkit") {
        findings.push(Finding {
            id: "QS-ENT-003".to_string(),
            title: "HealthKit Access Entitlement".to_string(),
            description: "The app has the HealthKit entitlement. It can read and write sensitive health and fitness data from the user's Health app. Ensure HealthKit data is handled in compliance with HIPAA/GDPR and Apple's HealthKit guidelines.".to_string(),
            severity: Severity::Warning,
            category: "entitlements".to_string(),
            cwe: Some("CWE-359".to_string()),
            owasp_mobile: Some("M6".to_string()),
            owasp_masvs: Some("MSTG-STORAGE-1".to_string()),
            evidence: vec!["com.apple.developer.healthkit: present".to_string()],
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
    // com.apple.security.cs.allow-jit  →  WARNING
    // Enables the dynamic-codesigning page permission; required for JIT
    // engines (JavaScript VMs) but widens the attack surface significantly.
    // ------------------------------------------------------------------ //
    if dict
        .get("com.apple.security.cs.allow-jit")
        .and_then(|v| v.as_boolean())
        == Some(true)
    {
        findings.push(Finding {
            id: "QS-ENT-008".to_string(),
            title: "JIT Compilation Entitlement Enabled".to_string(),
            description: "The 'com.apple.security.cs.allow-jit' entitlement is enabled. This grants the app permission to map pages as simultaneously writable and executable, which is required for JIT engines. An attacker who achieves code execution can use this to execute arbitrary unsigned code without bypassing the JIT compiler.".to_string(),
            severity: Severity::Warning,
            category: "entitlements".to_string(),
            cwe: Some("CWE-119".to_string()),
            owasp_mobile: Some("M8".to_string()),
            owasp_masvs: Some("MSTG-CODE-2".to_string()),
            evidence: vec!["com.apple.security.cs.allow-jit: true".to_string()],
            remediation: Some("Only enable this entitlement if the app includes a JIT-based runtime (e.g. JavaScriptCore, LuaJIT). Audit all code paths that generate executable code at runtime.".to_string()),
        });
    }

    // ------------------------------------------------------------------ //
    // com.apple.security.cs.allow-unsigned-executable-memory  →  HIGH
    // Allows mapping memory as executable without a code signature.
    // This is essentially opting out of code signing enforcement.
    // ------------------------------------------------------------------ //
    if dict
        .get("com.apple.security.cs.allow-unsigned-executable-memory")
        .and_then(|v| v.as_boolean())
        == Some(true)
    {
        findings.push(Finding {
            id: "QS-ENT-009".to_string(),
            title: "Unsigned Executable Memory Permitted".to_string(),
            description: "The 'com.apple.security.cs.allow-unsigned-executable-memory' entitlement is enabled. This allows the app to map memory as executable without a valid code signature, effectively disabling code signing enforcement for dynamically generated code. This is rarely necessary and significantly increases the risk of code-injection attacks.".to_string(),
            severity: Severity::High,
            category: "entitlements".to_string(),
            cwe: Some("CWE-284".to_string()),
            owasp_mobile: Some("M8".to_string()),
            owasp_masvs: Some("MSTG-CODE-2".to_string()),
            evidence: vec!["com.apple.security.cs.allow-unsigned-executable-memory: true".to_string()],
            remediation: Some("Remove this entitlement unless strictly required. If a scripting engine needs to execute dynamic code, use the allow-jit entitlement instead, which still enforces code signing constraints.".to_string()),
        });
    }

    // ------------------------------------------------------------------ //
    // com.apple.security.cs.disable-library-validation  →  WARNING
    // Allows loading dylibs that are not signed by Apple or the app's team.
    // ------------------------------------------------------------------ //
    if dict
        .get("com.apple.security.cs.disable-library-validation")
        .and_then(|v| v.as_boolean())
        == Some(true)
    {
        findings.push(Finding {
            id: "QS-ENT-010".to_string(),
            title: "Library Validation Disabled".to_string(),
            description: "The 'com.apple.security.cs.disable-library-validation' entitlement is enabled. Normally the OS verifies that all dynamically linked libraries are signed by Apple or by the same team as the app. Disabling this check allows the app to load unsigned or third-party-signed dylibs, which is a vector for dylib injection attacks.".to_string(),
            severity: Severity::Warning,
            category: "entitlements".to_string(),
            cwe: Some("CWE-426".to_string()),
            owasp_mobile: Some("M8".to_string()),
            owasp_masvs: Some("MSTG-CODE-2".to_string()),
            evidence: vec!["com.apple.security.cs.disable-library-validation: true".to_string()],
            remediation: Some("Remove this entitlement. Enable library validation to prevent dylib injection. If plug-in loading is required, use the hardened runtime plug-in host entitlement instead.".to_string()),
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

    findings
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
