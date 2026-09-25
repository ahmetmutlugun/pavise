//! Privacy manifest (`PrivacyInfo.xcprivacy`) and required-reason API checks.
//!
//! Since May 2024 App Store Connect rejects apps that call a "required reason"
//! API without declaring an approved reason in the app's privacy manifest.
//! The APIs are detected from the main binary's imported symbols.

use std::collections::BTreeSet;

use crate::types::{Finding, Severity};

/// (NSPrivacyAccessedAPIType, imported symbols that fall into it)
const REQUIRED_REASON_APIS: &[(&str, &[&str])] = &[
    (
        "NSPrivacyAccessedAPICategoryFileTimestamp",
        &[
            "_stat",
            "_fstat",
            "_lstat",
            "_fstatat",
            "_getattrlist",
            "_fgetattrlist",
            "_getattrlistat",
            "_getattrlistbulk",
            "_NSFileCreationDate",
            "_NSFileModificationDate",
            "_NSURLContentModificationDateKey",
            "_NSURLCreationDateKey",
        ],
    ),
    (
        "NSPrivacyAccessedAPICategorySystemBootTime",
        &["_mach_absolute_time"],
    ),
    (
        "NSPrivacyAccessedAPICategoryDiskSpace",
        &[
            "_statfs",
            "_fstatfs",
            "_statvfs",
            "_fstatvfs",
            "_NSFileSystemFreeSize",
            "_NSFileSystemSize",
            "_NSURLVolumeAvailableCapacityKey",
            "_NSURLVolumeAvailableCapacityForImportantUsageKey",
            "_NSURLVolumeAvailableCapacityForOpportunisticUsageKey",
            "_NSURLVolumeTotalCapacityKey",
        ],
    ),
    (
        "NSPrivacyAccessedAPICategoryActiveKeyboards",
        &["_OBJC_CLASS_$_UITextInputMode"],
    ),
    (
        "NSPrivacyAccessedAPICategoryUserDefaults",
        &["_OBJC_CLASS_$_NSUserDefaults"],
    ),
];

/// Check the main bundle's privacy manifest against the main binary's imports.
/// `manifest` is the raw `PrivacyInfo.xcprivacy`, if the bundle ships one.
pub fn analyze(manifest: Option<&[u8]>, imports: &[String]) -> Vec<Finding> {
    let used = used_categories(imports);
    let Some(data) = manifest else {
        return vec![missing_manifest(&used)];
    };
    let declared = declared_categories(data);
    let undeclared: Vec<&(&str, Vec<&str>)> = used
        .iter()
        .filter(|(cat, _)| !declared.contains(*cat))
        .collect();
    if undeclared.is_empty() {
        return Vec::new();
    }
    vec![Finding {
        id: "QS-PRIV-002".to_string(),
        title: "Required-Reason API Not Declared in Privacy Manifest".to_string(),
        description: format!(
            "The main binary uses {} required-reason API categor{} that PrivacyInfo.xcprivacy \
            does not declare. These APIs can fingerprint the device; App Store Connect rejects \
            builds that use them without an approved reason (ITMS-91053).",
            undeclared.len(),
            if undeclared.len() == 1 { "y" } else { "ies" }
        ),
        severity: Severity::Info,
        category: "privacy".to_string(),
        cwe: Some("CWE-359".to_string()),
        owasp_mobile: Some("M6".to_string()),
        owasp_masvs: Some("MASVS-PRIVACY-1".to_string()),
        evidence: undeclared
            .iter()
            .map(|(cat, syms)| format!("{}: {}", cat, syms.join(", ")))
            .collect(),
        remediation: Some(
            "Add an NSPrivacyAccessedAPITypes entry with an approved reason code for each \
            category, or stop calling the API."
                .to_string(),
        ),
    }]
}

fn missing_manifest(used: &[(&str, Vec<&str>)]) -> Finding {
    let mut evidence = vec!["PrivacyInfo.xcprivacy: absent from main bundle".to_string()];
    evidence.extend(
        used.iter()
            .map(|(cat, syms)| format!("{}: {}", cat, syms.join(", "))),
    );
    Finding {
        id: "QS-PRIV-001".to_string(),
        title: "No Privacy Manifest".to_string(),
        description: "The main bundle has no PrivacyInfo.xcprivacy. Apple requires a privacy \
            manifest that declares collected data types, tracking domains and the reasons for \
            using required-reason APIs; builds without one can be rejected."
            .to_string(),
        severity: Severity::Info,
        category: "privacy".to_string(),
        cwe: Some("CWE-359".to_string()),
        owasp_mobile: Some("M6".to_string()),
        owasp_masvs: Some("MASVS-PRIVACY-1".to_string()),
        evidence,
        remediation: Some(
            "Add PrivacyInfo.xcprivacy to the app target (Xcode: File > New > App Privacy) and \
            declare every required-reason API category the app uses."
                .to_string(),
        ),
    }
}

/// Required-reason categories used by the binary, with the matching symbols.
fn used_categories(imports: &[String]) -> Vec<(&'static str, Vec<&'static str>)> {
    let imports: BTreeSet<&str> = imports.iter().map(String::as_str).collect();
    REQUIRED_REASON_APIS
        .iter()
        .filter_map(|(cat, syms)| {
            let hits: Vec<&str> = syms
                .iter()
                .copied()
                .filter(|s| imports.contains(s))
                .collect();
            (!hits.is_empty()).then_some((*cat, hits))
        })
        .collect()
}

fn declared_categories(data: &[u8]) -> BTreeSet<String> {
    let Ok(value) = plist::from_bytes::<plist::Value>(data) else {
        return BTreeSet::new();
    };
    value
        .as_dictionary()
        .and_then(|d| d.get("NSPrivacyAccessedAPITypes"))
        .and_then(|v| v.as_array())
        .map(|entries| {
            entries
                .iter()
                .filter_map(|e| {
                    e.as_dictionary()?
                        .get("NSPrivacyAccessedAPIType")?
                        .as_string()
                })
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn imports(names: &[&str]) -> Vec<String> {
        names.iter().map(|s| s.to_string()).collect()
    }

    const MANIFEST: &str = r#"<plist version="1.0"><dict>
  <key>NSPrivacyAccessedAPITypes</key><array>
    <dict>
      <key>NSPrivacyAccessedAPIType</key><string>NSPrivacyAccessedAPICategoryUserDefaults</string>
      <key>NSPrivacyAccessedAPITypeReasons</key><array><string>CA92.1</string></array>
    </dict>
  </array>
</dict></plist>"#;

    #[test]
    fn missing_manifest_lists_used_apis() {
        let found = analyze(None, &imports(&["_stat", "_objc_msgSend"]));
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].id, "QS-PRIV-001");
        assert!(found[0]
            .evidence
            .contains(&"NSPrivacyAccessedAPICategoryFileTimestamp: _stat".to_string()));
    }

    #[test]
    fn undeclared_category_reported() {
        let found = analyze(
            Some(MANIFEST.as_bytes()),
            &imports(&["_OBJC_CLASS_$_NSUserDefaults", "_statfs"]),
        );
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].id, "QS-PRIV-002");
        assert_eq!(
            found[0].evidence,
            vec!["NSPrivacyAccessedAPICategoryDiskSpace: _statfs"]
        );
    }

    #[test]
    fn fully_declared_manifest_is_clean() {
        let found = analyze(
            Some(MANIFEST.as_bytes()),
            &imports(&["_OBJC_CLASS_$_NSUserDefaults"]),
        );
        assert!(found.is_empty());
    }
}
