use anyhow::{Context, Result};
use plist::Value;
use serde::Deserialize;
use std::collections::HashMap;
use tracing::debug;

use crate::types::{AppInfo, Finding, Permission, Platform, Severity};

#[derive(Debug, Deserialize)]
struct PermissionRule {
    key: String,
    reason: String,
    #[serde(default)]
    cwe: Option<String>,
    #[serde(default)]
    owasp_mobile: Option<String>,
}

#[derive(Debug, Deserialize)]
struct PermissionRules {
    ios: IosPermissions,
}

#[derive(Debug, Deserialize)]
struct IosPermissions {
    dangerous: Vec<PermissionRule>,
    #[serde(default)]
    #[allow(dead_code)]
    normal: Vec<PermissionRule>,
}

pub struct PlistAnalysisResult {
    pub app_info: AppInfo,
    pub findings: Vec<Finding>,
}

pub fn analyze(data: &[u8], rules_dir: &std::path::Path) -> Result<PlistAnalysisResult> {
    let value: Value = plist::from_bytes(data).context("Failed to parse Info.plist")?;

    let dict = value
        .as_dictionary()
        .context("Info.plist root is not a dictionary")?;

    // --- App metadata ---
    let name = get_str(dict, "CFBundleName")
        .or_else(|| get_str(dict, "CFBundleDisplayName"))
        .unwrap_or_default()
        .to_string();
    let identifier = get_str(dict, "CFBundleIdentifier")
        .unwrap_or_default()
        .to_string();
    let version = get_str(dict, "CFBundleShortVersionString")
        .unwrap_or_default()
        .to_string();
    let build = get_str(dict, "CFBundleVersion")
        .unwrap_or_default()
        .to_string();
    let min_os_version = get_str(dict, "MinimumOSVersion")
        .unwrap_or_default()
        .to_string();
    let sdk_name = get_str(dict, "DTSDKName").unwrap_or_default().to_string();

    let supported_platforms = dict
        .get("CFBundleSupportedPlatforms")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_string())
                .map(|s| s.to_string())
                .collect()
        })
        .unwrap_or_default();

    // Detect app type from plist hints
    let app_type = detect_app_type(dict);

    let mut findings: Vec<Finding> = Vec::new();

    // --- Permissions analysis ---
    let permission_rules = load_permission_rules(rules_dir).unwrap_or_else(|_| {
        debug!("Could not load permission rules, using empty set");
        PermissionRules {
            ios: IosPermissions {
                dangerous: Vec::new(),
                normal: Vec::new(),
            },
        }
    });

    let dangerous_keys: HashMap<&str, &PermissionRule> = permission_rules
        .ios
        .dangerous
        .iter()
        .map(|r| (r.key.as_str(), r))
        .collect();

    let mut permissions: Vec<Permission> = Vec::new();

    for (key, value) in dict {
        if key.ends_with("UsageDescription") || key.ends_with("UsagePrivacyPolicyURL") {
            let desc = value.as_string().unwrap_or("").to_string();

            if let Some(rule) = dangerous_keys.get(key.as_str()) {
                permissions.push(Permission {
                    key: key.clone(),
                    status: "sensitive".to_string(),
                    description: desc.clone(),
                    reason: rule.reason.clone(),
                });

                findings.push(Finding {
                    id: format!("QS-PERM-{}", sanitize_id(key)),
                    title: format!("Sensitive Permission: {}", key),
                    description: format!(
                        "App requests '{}' permission. Usage description: \"{}\"",
                        key, desc
                    ),
                    severity: Severity::Info,
                    category: "permissions".to_string(),
                    cwe: rule.cwe.clone(),
                    owasp_mobile: rule.owasp_mobile.clone(),
                    owasp_masvs: Some("MSTG-PLATFORM-1".to_string()),
                    evidence: vec![format!("{}: {}", key, desc)],
                    remediation: Some(rule.reason.clone()),
                });
            } else {
                permissions.push(Permission {
                    key: key.clone(),
                    status: "normal".to_string(),
                    description: desc,
                    reason: String::new(),
                });
            }
        }
    }

    // --- App Transport Security ---
    if let Some(ats_findings) = analyze_ats(dict) {
        findings.extend(ats_findings);
    }

    // --- Custom URL Schemes ---
    findings.extend(analyze_url_schemes(dict));

    // --- Sandbox / File Sharing ---
    findings.extend(analyze_sandbox(dict));

    let app_info = AppInfo {
        name,
        identifier,
        version,
        build,
        platform: Platform::IOS,
        min_os_version,
        sdk_name,
        app_type,
        supported_platforms,
        permissions,
    };

    Ok(PlistAnalysisResult { app_info, findings })
}

fn get_str<'a>(dict: &'a plist::Dictionary, key: &str) -> Option<&'a str> {
    dict.get(key)?.as_string()
}

fn detect_app_type(dict: &plist::Dictionary) -> String {
    // Heuristic: DTCompiler or presence of Swift hints in plist
    if let Some(compiler) = dict.get("DTCompiler").and_then(|v| v.as_string()) {
        if compiler.contains("swift") || compiler.contains("Swift") {
            return "Swift".to_string();
        }
    }
    // Default: check for Swift indicator key
    if dict.get("NSPrincipalClass").is_none() {
        "Swift".to_string()
    } else {
        "Objective-C".to_string()
    }
}

fn analyze_ats(dict: &plist::Dictionary) -> Option<Vec<Finding>> {
    let mut findings = Vec::new();

    let ats = match dict.get("NSAppTransportSecurity") {
        None => {
            // ATS absent means default security applies (iOS 9+), which is actually secure
            findings.push(Finding {
                id: "QS-ATS-001".to_string(),
                title: "App Transport Security Not Configured".to_string(),
                description: "NSAppTransportSecurity key is absent. Default ATS policy applies (HTTPS required). This is secure for iOS 9+ but verify all endpoints support TLS.".to_string(),
                severity: Severity::Info,
                category: "network".to_string(),
                cwe: Some("CWE-319".to_string()),
                owasp_mobile: Some("M5".to_string()),
                owasp_masvs: Some("MSTG-NETWORK-2".to_string()),
                evidence: vec!["NSAppTransportSecurity: absent".to_string()],
                remediation: None,
            });
            return Some(findings);
        }
        Some(v) => v,
    };

    let ats_dict = match ats.as_dictionary() {
        Some(d) => d,
        None => return Some(findings),
    };

    // ------------------------------------------------------------------ //
    // Top-level ATS flags
    // ------------------------------------------------------------------ //
    if ats_dict.get("NSAllowsArbitraryLoads").and_then(|v| v.as_boolean()) == Some(true) {
        findings.push(Finding {
            id: "QS-ATS-002".to_string(),
            title: "ATS: Arbitrary Loads Allowed".to_string(),
            description: "NSAllowsArbitraryLoads is true, disabling ATS protection for all network connections. The app can communicate over insecure HTTP.".to_string(),
            severity: Severity::High,
            category: "network".to_string(),
            cwe: Some("CWE-319".to_string()),
            owasp_mobile: Some("M5".to_string()),
            owasp_masvs: Some("MSTG-NETWORK-2".to_string()),
            evidence: vec!["NSAllowsArbitraryLoads: true".to_string()],
            remediation: Some("Remove NSAllowsArbitraryLoads or set it to false. Ensure all endpoints use HTTPS with valid TLS certificates.".to_string()),
        });
    }

    if ats_dict.get("NSAllowsArbitraryLoadsInWebContent").and_then(|v| v.as_boolean()) == Some(true) {
        findings.push(Finding {
            id: "QS-ATS-003".to_string(),
            title: "ATS: Arbitrary Loads Allowed in Web Content".to_string(),
            description: "NSAllowsArbitraryLoadsInWebContent is true, allowing WKWebView to load insecure HTTP content.".to_string(),
            severity: Severity::Warning,
            category: "network".to_string(),
            cwe: Some("CWE-319".to_string()),
            owasp_mobile: Some("M5".to_string()),
            owasp_masvs: Some("MSTG-NETWORK-2".to_string()),
            evidence: vec!["NSAllowsArbitraryLoadsInWebContent: true".to_string()],
            remediation: Some("Remove NSAllowsArbitraryLoadsInWebContent. Ensure all web content is loaded over HTTPS.".to_string()),
        });
    }

    if ats_dict.get("NSAllowsArbitraryLoadsForMedia").and_then(|v| v.as_boolean()) == Some(true) {
        findings.push(Finding {
            id: "QS-ATS-005".to_string(),
            title: "ATS: Arbitrary Loads Allowed for Media".to_string(),
            description: "NSAllowsArbitraryLoadsForMedia is true, allowing AV Foundation to load media over insecure HTTP. Streamed media is not encrypted in transit and is susceptible to MITM substitution.".to_string(),
            severity: Severity::Warning,
            category: "network".to_string(),
            cwe: Some("CWE-319".to_string()),
            owasp_mobile: Some("M5".to_string()),
            owasp_masvs: Some("MSTG-NETWORK-2".to_string()),
            evidence: vec!["NSAllowsArbitraryLoadsForMedia: true".to_string()],
            remediation: Some("Remove NSAllowsArbitraryLoadsForMedia. Serve media over HTTPS.".to_string()),
        });
    }

    if ats_dict.get("NSAllowsLocalNetworking").and_then(|v| v.as_boolean()) == Some(true) {
        findings.push(Finding {
            id: "QS-ATS-006".to_string(),
            title: "ATS: Local Networking Allowed".to_string(),
            description: "NSAllowsLocalNetworking is true, exempting local-network connections (unqualified hostnames, .local mDNS, link-local) from ATS. Legitimate for apps that talk to LAN devices, but verify the local protocol is itself authenticated and integrity-protected.".to_string(),
            severity: Severity::Info,
            category: "network".to_string(),
            cwe: Some("CWE-319".to_string()),
            owasp_mobile: Some("M5".to_string()),
            owasp_masvs: Some("MSTG-NETWORK-2".to_string()),
            evidence: vec!["NSAllowsLocalNetworking: true".to_string()],
            remediation: Some("Only set when communicating with local-network devices. Authenticate and integrity-check local traffic at the application layer.".to_string()),
        });
    }

    // Global Certificate Transparency disabled (top-level, not per-domain).
    // Distinct from QS-ATS-009, which covers CT disabled within a single
    // NSExceptionDomains entry.
    if ats_dict
        .get("NSRequiresCertificateTransparency")
        .and_then(|v| v.as_boolean())
        == Some(false)
    {
        findings.push(Finding {
            id: "QS-ATS-013".to_string(),
            title: "ATS: Certificate Transparency Not Required (global)".to_string(),
            description: "NSRequiresCertificateTransparency is false at the top level of NSAppTransportSecurity, disabling CT enforcement for all connections. CT logs are not consulted, weakening detection of mis-issued certificates.".to_string(),
            severity: Severity::Info,
            category: "network".to_string(),
            cwe: Some("CWE-295".to_string()),
            owasp_mobile: Some("M5".to_string()),
            owasp_masvs: Some("MSTG-NETWORK-3".to_string()),
            evidence: vec!["NSRequiresCertificateTransparency: false".to_string()],
            remediation: Some("Remove NSRequiresCertificateTransparency or set it to true (the iOS default). Ensure server certificates are CT-logged.".to_string()),
        });
    }

    // ------------------------------------------------------------------ //
    // Per-domain exception sub-flags. Each (rule, domain) tuple produces a
    // separate finding; rule IDs are stable across domains, so the global
    // dedup pass in lib.rs rolls multiple-domain matches into a single finding
    // whose evidence lists every affected domain.
    // ------------------------------------------------------------------ //
    if let Some(exceptions) = ats_dict
        .get("NSExceptionDomains")
        .and_then(|v| v.as_dictionary())
    {
        for (domain, config) in exceptions {
            let cfg = match config.as_dictionary() {
                Some(d) => d,
                None => continue,
            };

            // NSExceptionAllowsInsecureHTTPLoads
            if cfg.get("NSExceptionAllowsInsecureHTTPLoads").and_then(|v| v.as_boolean())
                == Some(true)
            {
                findings.push(Finding {
                    id: "QS-ATS-004".to_string(),
                    title: "ATS: Insecure HTTP Allowed for Exception Domain".to_string(),
                    description: "NSExceptionAllowsInsecureHTTPLoads is true for one or more domains in NSExceptionDomains. This permits unencrypted HTTP communication with the listed hosts.".to_string(),
                    severity: Severity::Warning,
                    category: "network".to_string(),
                    cwe: Some("CWE-319".to_string()),
                    owasp_mobile: Some("M5".to_string()),
                    owasp_masvs: Some("MSTG-NETWORK-2".to_string()),
                    evidence: vec![format!("{}: NSExceptionAllowsInsecureHTTPLoads = true", domain)],
                    remediation: Some("Remove the insecure HTTP exception for the listed domain(s). Update the upstream servers to support HTTPS with valid TLS certificates.".to_string()),
                });
            }

            // NSExceptionMinimumTLSVersion (anything below TLSv1.2)
            if let Some(ver) = cfg.get("NSExceptionMinimumTLSVersion").and_then(|v| v.as_string()) {
                if is_weak_tls_version(ver) {
                    findings.push(Finding {
                        id: "QS-ATS-007".to_string(),
                        title: "ATS: Weak Minimum TLS Version for Exception Domain".to_string(),
                        description: "NSExceptionMinimumTLSVersion is set below TLSv1.2 for one or more domains. TLS 1.0 and 1.1 are deprecated (RFC 8996) and vulnerable to known downgrade and chosen-plaintext attacks.".to_string(),
                        severity: Severity::Warning,
                        category: "network".to_string(),
                        cwe: Some("CWE-326".to_string()),
                        owasp_mobile: Some("M5".to_string()),
                        owasp_masvs: Some("MSTG-NETWORK-2".to_string()),
                        evidence: vec![format!("{}: NSExceptionMinimumTLSVersion = {}", domain, ver)],
                        remediation: Some("Remove the override or raise the minimum TLS version to TLSv1.2 (TLSv1.3 preferred). Upgrade the upstream server if it cannot negotiate modern TLS.".to_string()),
                    });
                }
            }

            // NSExceptionRequiresForwardSecrecy: false
            if cfg.get("NSExceptionRequiresForwardSecrecy").and_then(|v| v.as_boolean())
                == Some(false)
            {
                findings.push(Finding {
                    id: "QS-ATS-008".to_string(),
                    title: "ATS: Forward Secrecy Disabled for Exception Domain".to_string(),
                    description: "NSExceptionRequiresForwardSecrecy is false for one or more domains. This permits TLS cipher suites that do not provide perfect forward secrecy — past session traffic can be decrypted if the server's long-term key is later compromised.".to_string(),
                    severity: Severity::Info,
                    category: "network".to_string(),
                    cwe: Some("CWE-326".to_string()),
                    owasp_mobile: Some("M5".to_string()),
                    owasp_masvs: Some("MSTG-NETWORK-2".to_string()),
                    evidence: vec![format!("{}: NSExceptionRequiresForwardSecrecy = false", domain)],
                    remediation: Some("Re-enable forward secrecy. Configure the upstream server to offer ECDHE-based cipher suites.".to_string()),
                });
            }

            // NSRequiresCertificateTransparency: false
            if cfg.get("NSRequiresCertificateTransparency").and_then(|v| v.as_boolean())
                == Some(false)
            {
                findings.push(Finding {
                    id: "QS-ATS-009".to_string(),
                    title: "ATS: Certificate Transparency Not Required for Exception Domain".to_string(),
                    description: "NSRequiresCertificateTransparency is false for one or more domains. CT logs are not consulted for these hosts, weakening detection of mis-issued certificates.".to_string(),
                    severity: Severity::Info,
                    category: "network".to_string(),
                    cwe: Some("CWE-295".to_string()),
                    owasp_mobile: Some("M5".to_string()),
                    owasp_masvs: Some("MSTG-NETWORK-3".to_string()),
                    evidence: vec![format!("{}: NSRequiresCertificateTransparency = false", domain)],
                    remediation: Some("Enable CT enforcement (the iOS default). If the certificate cannot be CT-logged, replace it with one that can.".to_string()),
                });
            }

            // NSThirdPartyExceptionAllowsInsecureHTTPLoads
            if cfg.get("NSThirdPartyExceptionAllowsInsecureHTTPLoads").and_then(|v| v.as_boolean())
                == Some(true)
            {
                findings.push(Finding {
                    id: "QS-ATS-010".to_string(),
                    title: "ATS: Insecure HTTP Allowed for Third-Party Exception Domain".to_string(),
                    description: "NSThirdPartyExceptionAllowsInsecureHTTPLoads is true for one or more third-party domains. Third-party SDKs are pulling traffic in cleartext through this app.".to_string(),
                    severity: Severity::Warning,
                    category: "network".to_string(),
                    cwe: Some("CWE-319".to_string()),
                    owasp_mobile: Some("M5".to_string()),
                    owasp_masvs: Some("MSTG-NETWORK-2".to_string()),
                    evidence: vec![format!("{}: NSThirdPartyExceptionAllowsInsecureHTTPLoads = true", domain)],
                    remediation: Some("Pressure the upstream third party to enable HTTPS, or drop the dependency. Removing the override only forces failure — it does not encrypt the third party's endpoint.".to_string()),
                });
            }

            // NSThirdPartyExceptionMinimumTLSVersion (anything below TLSv1.2)
            if let Some(ver) = cfg
                .get("NSThirdPartyExceptionMinimumTLSVersion")
                .and_then(|v| v.as_string())
            {
                if is_weak_tls_version(ver) {
                    findings.push(Finding {
                        id: "QS-ATS-011".to_string(),
                        title: "ATS: Weak Minimum TLS Version for Third-Party Exception Domain".to_string(),
                        description: "NSThirdPartyExceptionMinimumTLSVersion is set below TLSv1.2 for one or more third-party domains.".to_string(),
                        severity: Severity::Warning,
                        category: "network".to_string(),
                        cwe: Some("CWE-326".to_string()),
                        owasp_mobile: Some("M5".to_string()),
                        owasp_masvs: Some("MSTG-NETWORK-2".to_string()),
                        evidence: vec![format!("{}: NSThirdPartyExceptionMinimumTLSVersion = {}", domain, ver)],
                        remediation: Some("Pressure the upstream third party to support modern TLS, or drop the dependency.".to_string()),
                    });
                }
            }

            // NSThirdPartyExceptionRequiresForwardSecrecy: false
            if cfg
                .get("NSThirdPartyExceptionRequiresForwardSecrecy")
                .and_then(|v| v.as_boolean())
                == Some(false)
            {
                findings.push(Finding {
                    id: "QS-ATS-012".to_string(),
                    title: "ATS: Forward Secrecy Disabled for Third-Party Exception Domain".to_string(),
                    description: "NSThirdPartyExceptionRequiresForwardSecrecy is false for one or more third-party domains.".to_string(),
                    severity: Severity::Info,
                    category: "network".to_string(),
                    cwe: Some("CWE-326".to_string()),
                    owasp_mobile: Some("M5".to_string()),
                    owasp_masvs: Some("MSTG-NETWORK-2".to_string()),
                    evidence: vec![format!("{}: NSThirdPartyExceptionRequiresForwardSecrecy = false", domain)],
                    remediation: Some("Push the upstream third party to enable forward-secrecy cipher suites.".to_string()),
                });
            }
        }
    }

    Some(findings)
}

/// True for "TLSv1.0" / "TLSv1.1" (Apple's NSExceptionMinimumTLSVersion strings).
/// Anything that parses to ≥ 1.2 is considered acceptable.
fn is_weak_tls_version(s: &str) -> bool {
    let trimmed = s.trim().trim_start_matches("TLSv").trim_start_matches("TLS");
    // Compare as (major, minor) tuple to avoid floating-point surprises.
    let mut parts = trimmed.split('.');
    let major = parts.next().and_then(|p| p.parse::<u32>().ok());
    let minor = parts.next().and_then(|p| p.parse::<u32>().ok()).unwrap_or(0);
    match major {
        Some(1) => minor < 2,
        Some(m) if m >= 1 => false,
        _ => false, // unparseable — don't flag
    }
}

fn analyze_sandbox(dict: &plist::Dictionary) -> Vec<Finding> {
    let mut findings = Vec::new();

    // UIFileSharingEnabled: true → Documents folder accessible via Files app / iTunes
    if dict
        .get("UIFileSharingEnabled")
        .and_then(|v| v.as_boolean())
        == Some(true)
    {
        findings.push(Finding {
            id: "QS-SANDBOX-001".to_string(),
            title: "File Sharing Enabled (UIFileSharingEnabled)".to_string(),
            description: "UIFileSharingEnabled is set to true. The app's Documents folder is \
                accessible through the Files app and iTunes File Sharing. Any sensitive files \
                stored there — credentials, exports, cached user data — can be read or replaced \
                by anyone with physical access to the device."
                .to_string(),
            severity: Severity::Warning,
            category: "storage".to_string(),
            cwe: Some("CWE-312".to_string()),
            owasp_mobile: Some("M2".to_string()),
            owasp_masvs: Some("MSTG-STORAGE-1".to_string()),
            evidence: vec!["UIFileSharingEnabled: true".to_string()],
            remediation: Some(
                "Set UIFileSharingEnabled to false unless users genuinely need to transfer files \
                via Files/iTunes. For user-facing document sharing, prefer UIDocumentPickerViewController \
                with scoped access rather than broad Documents folder exposure."
                    .to_string(),
            ),
        });
    }

    // LSSupportsOpeningDocumentsInPlace: true → cloud apps can edit files in-place
    if dict
        .get("LSSupportsOpeningDocumentsInPlace")
        .and_then(|v| v.as_boolean())
        == Some(true)
    {
        findings.push(Finding {
            id: "QS-SANDBOX-002".to_string(),
            title: "In-Place Document Editing Enabled (LSSupportsOpeningDocumentsInPlace)".to_string(),
            description: "LSSupportsOpeningDocumentsInPlace is set to true. Cloud storage providers \
                (iCloud Drive, Dropbox, Google Drive, etc.) can open and modify the app's documents \
                directly in their original location rather than copying them first. If the app's \
                documents contain sensitive data, the originals may be uploaded to cloud storage \
                without additional user confirmation."
                .to_string(),
            severity: Severity::Info,
            category: "storage".to_string(),
            cwe: Some("CWE-312".to_string()),
            owasp_mobile: Some("M2".to_string()),
            owasp_masvs: Some("MSTG-STORAGE-1".to_string()),
            evidence: vec!["LSSupportsOpeningDocumentsInPlace: true".to_string()],
            remediation: Some(
                "Only enable in-place editing if the app is designed as a document editor. \
                Sensitive files should be stored in the Application Support directory (not Documents) \
                and protected with NSFileProtectionComplete."
                    .to_string(),
            ),
        });
    }

    findings
}

fn load_permission_rules(rules_dir: &std::path::Path) -> Result<PermissionRules> {
    let path = rules_dir.join("permissions.yaml");
    let content = std::fs::read_to_string(&path)
        .with_context(|| format!("Failed to read {}", path.display()))?;
    serde_yaml::from_str(&content).context("Failed to parse permissions.yaml")
}

fn sanitize_id(key: &str) -> String {
    key.chars()
        .map(|c| if c.is_alphanumeric() { c } else { '_' })
        .collect()
}

fn analyze_url_schemes(dict: &plist::Dictionary) -> Vec<Finding> {
    let mut findings = Vec::new();

    let url_types = match dict.get("CFBundleURLTypes").and_then(|v| v.as_array()) {
        Some(arr) => arr,
        None => return findings,
    };

    // Schemes that look too generic and are prime hijacking targets
    const GENERIC_SCHEMES: &[&str] = &[
        "app", "open", "launch", "view", "share", "pay", "auth", "login", "oauth", "callback",
        "redirect", "link", "handle", "action",
    ];

    // Standard protocol schemes that are common in media players/file managers
    const STANDARD_SCHEMES: &[&str] = &[
        "ftp", "sftp", "ftps", "smb", "afp", "nfs", "rtsp", "rtmp", "mms", "udp", "tcp", "webdav",
        "dav", "vlc",
    ];

    for item in url_types {
        let type_dict = match item.as_dictionary() {
            Some(d) => d,
            None => continue,
        };

        let schemes = match type_dict
            .get("CFBundleURLSchemes")
            .and_then(|v| v.as_array())
        {
            Some(s) => s,
            None => continue,
        };

        for scheme_val in schemes {
            let scheme = match scheme_val.as_string() {
                Some(s) => s.to_lowercase(),
                None => continue,
            };

            // Skip http/https — those are Universal Links, not custom schemes
            if scheme == "http" || scheme == "https" {
                continue;
            }

            let is_standard = STANDARD_SCHEMES.iter().any(|s| scheme == *s);
            let is_generic = !is_standard
                && (GENERIC_SCHEMES.iter().any(|g| scheme == *g) || scheme.len() <= 3);

            let (severity, title, description) = if is_generic {
                (
                    Severity::Warning,
                    format!("Generic Custom URL Scheme: '{}'", scheme),
                    format!(
                        "The app registers a very short or generic URL scheme '{}://'. \
                        Generic schemes are easily guessed and can be registered by malicious apps \
                        to intercept deep links (URL scheme hijacking). Scheme names should be \
                        app-specific and ideally match the bundle identifier.",
                        scheme
                    ),
                )
            } else {
                (
                    Severity::Info,
                    format!("Custom URL Scheme Registered: '{}'", scheme),
                    format!(
                        "The app registers the custom URL scheme '{}://'. Any app on the device \
                        can invoke this scheme. Ensure the handler validates all incoming parameters \
                        and does not perform sensitive actions without additional authentication.",
                        scheme
                    ),
                )
            };

            findings.push(Finding {
                id: format!("QS-IPC-001-{}", sanitize_id(&scheme)),
                title,
                description,
                severity,
                category: "ipc".to_string(),
                cwe: Some("CWE-939".to_string()),
                owasp_mobile: Some("M1".to_string()),
                owasp_masvs: Some("MSTG-PLATFORM-3".to_string()),
                evidence: vec![format!("CFBundleURLSchemes: {}", scheme)],
                remediation: Some(
                    "Validate all URL scheme parameters before use. Use Universal Links (HTTPS) \
                    for deep linking where possible. Never perform sensitive actions (payments, \
                    auth state changes) solely based on URL scheme invocation."
                        .to_string(),
                ),
            });
        }
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;
    use plist::Value;

    fn ats_findings_from_plist(xml: &str) -> Vec<Finding> {
        let value: Value = plist::from_bytes(xml.as_bytes()).expect("parse plist");
        let dict = value.as_dictionary().expect("root dict");
        analyze_ats(dict).unwrap_or_default()
    }

    fn ids(findings: &[Finding]) -> Vec<&str> {
        findings.iter().map(|f| f.id.as_str()).collect()
    }

    #[test]
    fn test_weak_tls_version() {
        assert!(is_weak_tls_version("TLSv1.0"));
        assert!(is_weak_tls_version("TLSv1.1"));
        assert!(!is_weak_tls_version("TLSv1.2"));
        assert!(!is_weak_tls_version("TLSv1.3"));
        assert!(!is_weak_tls_version("garbage"));
    }

    #[test]
    fn test_arbitrary_loads_for_media() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>NSAppTransportSecurity</key>
  <dict>
    <key>NSAllowsArbitraryLoadsForMedia</key><true/>
  </dict>
</dict></plist>"#;
        let findings = ats_findings_from_plist(xml);
        assert!(ids(&findings).contains(&"QS-ATS-005"), "got: {:?}", ids(&findings));
    }

    #[test]
    fn test_allows_local_networking() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>NSAppTransportSecurity</key>
  <dict>
    <key>NSAllowsLocalNetworking</key><true/>
  </dict>
</dict></plist>"#;
        let findings = ats_findings_from_plist(xml);
        assert!(ids(&findings).contains(&"QS-ATS-006"));
    }

    #[test]
    fn test_per_domain_exception_subflags() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>NSAppTransportSecurity</key>
  <dict>
    <key>NSExceptionDomains</key>
    <dict>
      <key>legacy.example.com</key>
      <dict>
        <key>NSExceptionAllowsInsecureHTTPLoads</key><true/>
        <key>NSExceptionMinimumTLSVersion</key><string>TLSv1.0</string>
        <key>NSExceptionRequiresForwardSecrecy</key><false/>
        <key>NSRequiresCertificateTransparency</key><false/>
        <key>NSThirdPartyExceptionAllowsInsecureHTTPLoads</key><true/>
        <key>NSThirdPartyExceptionMinimumTLSVersion</key><string>TLSv1.1</string>
        <key>NSThirdPartyExceptionRequiresForwardSecrecy</key><false/>
      </dict>
    </dict>
  </dict>
</dict></plist>"#;
        let findings = ats_findings_from_plist(xml);
        let got = ids(&findings);
        for expected in &[
            "QS-ATS-004",
            "QS-ATS-007",
            "QS-ATS-008",
            "QS-ATS-009",
            "QS-ATS-010",
            "QS-ATS-011",
            "QS-ATS-012",
        ] {
            assert!(got.contains(expected), "missing {} in {:?}", expected, got);
        }
        // Domain must appear in evidence so dedup can roll up multi-domain hits.
        assert!(findings.iter().any(|f| f.id == "QS-ATS-004"
            && f.evidence.iter().any(|e| e.contains("legacy.example.com"))));
    }

    #[test]
    fn test_modern_tls_not_flagged() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>NSAppTransportSecurity</key>
  <dict>
    <key>NSExceptionDomains</key>
    <dict>
      <key>api.example.com</key>
      <dict>
        <key>NSExceptionMinimumTLSVersion</key><string>TLSv1.3</string>
      </dict>
    </dict>
  </dict>
</dict></plist>"#;
        let findings = ats_findings_from_plist(xml);
        assert!(!ids(&findings).contains(&"QS-ATS-007"));
    }
}
