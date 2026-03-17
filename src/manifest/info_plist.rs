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
                    status: "dangerous".to_string(),
                    description: desc.clone(),
                    reason: rule.reason.clone(),
                });

                findings.push(Finding {
                    id: format!("QS-PERM-{}", sanitize_id(key)),
                    title: format!("Dangerous Permission: {}", key),
                    description: format!(
                        "App requests '{}' permission. Usage description: \"{}\"",
                        key, desc
                    ),
                    severity: Severity::Warning,
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

    // Check NSAllowsArbitraryLoads
    if let Some(val) = ats_dict.get("NSAllowsArbitraryLoads") {
        if val.as_boolean() == Some(true) {
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
    }

    // Check NSAllowsArbitraryLoadsInWebContent
    if let Some(val) = ats_dict.get("NSAllowsArbitraryLoadsInWebContent") {
        if val.as_boolean() == Some(true) {
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
    }

    // Check exception domains
    if let Some(exceptions) = ats_dict
        .get("NSExceptionDomains")
        .and_then(|v| v.as_dictionary())
    {
        for (domain, config) in exceptions {
            if let Some(cfg_dict) = config.as_dictionary() {
                if cfg_dict
                    .get("NSExceptionAllowsInsecureHTTPLoads")
                    .and_then(|v| v.as_boolean())
                    == Some(true)
                {
                    findings.push(Finding {
                        id: "QS-ATS-004".to_string(),
                        title: format!("ATS: Insecure HTTP Allowed for Domain '{}'", domain),
                        description: format!(
                            "NSExceptionAllowsInsecureHTTPLoads is true for domain '{}'. This allows unencrypted HTTP communication with this host.",
                            domain
                        ),
                        severity: Severity::Warning,
                        category: "network".to_string(),
                        cwe: Some("CWE-319".to_string()),
                        owasp_mobile: Some("M5".to_string()),
                        owasp_masvs: Some("MSTG-NETWORK-2".to_string()),
                        evidence: vec![format!("NSExceptionDomains.{}.NSExceptionAllowsInsecureHTTPLoads: true", domain)],
                        remediation: Some(format!("Remove the insecure HTTP exception for '{}'. Update the server to support HTTPS.", domain)),
                    });
                }
            }
        }
    }

    Some(findings)
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

            let is_generic = GENERIC_SCHEMES.iter().any(|g| scheme == *g) || scheme.len() <= 3;

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
