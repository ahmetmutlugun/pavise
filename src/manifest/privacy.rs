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

/// Apple's list of commonly used SDKs that must ship their own privacy
/// manifest (`data/privacy_sdks.txt`), lowercase.
fn listed_sdks() -> &'static BTreeSet<String> {
    static SDKS: std::sync::OnceLock<BTreeSet<String>> = std::sync::OnceLock::new();
    SDKS.get_or_init(|| {
        include_str!("../../data/privacy_sdks.txt")
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .map(str::to_ascii_lowercase)
            .collect()
    })
}

/// Listed SDKs bundled as frameworks without a privacy manifest inside the
/// framework (ITMS-91061). `paths` are all archive entry paths; frameworks of
/// extensions and Watch apps count too. Statically linked SDKs are not checked:
/// their manifest lives in a resource bundle and their presence can't be
/// established from the archive layout alone.
pub fn sdk_manifests(paths: &[&str]) -> Option<Finding> {
    // ".../Frameworks/Name.framework/" prefix -> framework name
    let mut frameworks: BTreeSet<(&str, &str)> = BTreeSet::new();
    for path in paths {
        let Some(i) = path.find("/Frameworks/") else {
            continue;
        };
        let rest = &path[i + "/Frameworks/".len()..];
        let Some(end) = rest.find(".framework/") else {
            continue;
        };
        let name = &rest[..end];
        if !name.contains('/') && listed_sdks().contains(&name.to_ascii_lowercase()) {
            let prefix_len = i + "/Frameworks/".len() + end + ".framework/".len();
            frameworks.insert((&path[..prefix_len], name));
        }
    }
    let missing: Vec<String> = frameworks
        .iter()
        .filter(|(prefix, _)| {
            !paths
                .iter()
                .any(|p| p.starts_with(prefix) && p.ends_with("/PrivacyInfo.xcprivacy"))
        })
        .map(|(prefix, name)| format!("{}: no PrivacyInfo.xcprivacy in {}", name, prefix))
        .collect();
    if missing.is_empty() {
        return None;
    }
    Some(Finding {
        id: "QS-PRIV-003".to_string(),
        title: "Listed Third-Party SDK Without Privacy Manifest".to_string(),
        description: format!(
            "{} bundled SDK framework{} on Apple's list of commonly used third-party SDKs \
            ship{} no privacy manifest. App Store Connect rejects new apps, and updates that \
            add a listed SDK, unless the SDK includes its own manifest (ITMS-91061). Versions \
            released before 2024 usually predate the requirement.",
            missing.len(),
            if missing.len() == 1 { "" } else { "s" },
            if missing.len() == 1 { "s" } else { "" }
        ),
        severity: Severity::Warning,
        category: "privacy".to_string(),
        cwe: Some("CWE-359".to_string()),
        owasp_mobile: Some("M6".to_string()),
        owasp_masvs: Some("MASVS-PRIVACY-1".to_string()),
        evidence: missing,
        remediation: Some(
            "Update each SDK to a release that bundles PrivacyInfo.xcprivacy (see \
            developer.apple.com/support/third-party-SDK-requirements). An app's own manifest \
            does not cover a listed SDK."
                .to_string(),
        ),
    })
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

    #[test]
    fn listed_sdk_framework_without_manifest_flagged() {
        let paths = [
            "Payload/A.app/Frameworks/Alamofire.framework/Alamofire",
            "Payload/A.app/Frameworks/Alamofire.framework/Info.plist",
            // Manifest nested in a resource bundle inside the framework counts.
            "Payload/A.app/Frameworks/SDWebImage.framework/SDWebImage",
            "Payload/A.app/Frameworks/SDWebImage.framework/SDWebImage.bundle/PrivacyInfo.xcprivacy",
            // Not on Apple's list, and a name that merely contains a listed one.
            "Payload/A.app/Frameworks/MyKit.framework/MyKit",
            "Payload/A.app/Frameworks/AlamofireImage.framework/AlamofireImage",
            // Case-insensitive name; extension frameworks are checked too.
            "Payload/A.app/PlugIns/W.appex/Frameworks/hermes.framework/hermes",
        ];
        let f = sdk_manifests(&paths).expect("finding");
        assert_eq!(f.id, "QS-PRIV-003");
        assert_eq!(f.severity, Severity::Warning);
        assert_eq!(
            f.evidence,
            [
                "Alamofire: no PrivacyInfo.xcprivacy in Payload/A.app/Frameworks/Alamofire.framework/",
                "hermes: no PrivacyInfo.xcprivacy in Payload/A.app/PlugIns/W.appex/Frameworks/hermes.framework/",
            ]
        );
    }

    #[test]
    fn listed_sdks_with_manifests_pass() {
        let paths = [
            "Payload/A.app/Frameworks/Flutter.framework/Flutter",
            "Payload/A.app/Frameworks/Flutter.framework/PrivacyInfo.xcprivacy",
        ];
        assert!(sdk_manifests(&paths).is_none());
        assert!(listed_sdks().contains("openssl_grpc"));
        assert!(listed_sdks().contains("boringssl"));
    }

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
