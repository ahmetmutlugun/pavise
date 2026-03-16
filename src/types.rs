use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A single timestamped entry in the scan audit log.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    /// Milliseconds elapsed from scan start when this step completed.
    pub elapsed_ms: u64,
    /// Human-readable description of the step and its outcome.
    pub step: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    High,
    Warning,
    Info,
    Secure,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Severity::High => write!(f, "HIGH"),
            Severity::Warning => write!(f, "WARNING"),
            Severity::Info => write!(f, "INFO"),
            Severity::Secure => write!(f, "SECURE"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Platform {
    IOS,
    Android,
}

impl std::fmt::Display for Platform {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Platform::IOS => write!(f, "iOS"),
            Platform::Android => write!(f, "Android"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    pub title: String,
    pub description: String,
    pub severity: Severity,
    pub category: String,
    pub cwe: Option<String>,
    pub owasp_mobile: Option<String>,
    pub owasp_masvs: Option<String>,
    pub evidence: Vec<String>,
    pub remediation: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Permission {
    pub key: String,
    pub status: String,
    pub description: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppInfo {
    pub name: String,
    pub identifier: String,
    pub version: String,
    pub build: String,
    pub platform: Platform,
    pub min_os_version: String,
    pub sdk_name: String,
    pub app_type: String,
    pub supported_platforms: Vec<String>,
    pub permissions: Vec<Permission>,
}

impl Default for AppInfo {
    fn default() -> Self {
        AppInfo {
            name: String::new(),
            identifier: String::new(),
            version: String::new(),
            build: String::new(),
            platform: Platform::IOS,
            min_os_version: String::new(),
            sdk_name: String::new(),
            app_type: String::new(),
            supported_platforms: Vec::new(),
            permissions: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BinaryProtection {
    pub name: String,
    pub enabled: bool,
    pub severity: Severity,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BinaryInfo {
    pub path: String,
    pub arch: String,
    pub bits: u8,
    pub protections: Vec<BinaryProtection>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainInfo {
    pub domain: String,
    pub context: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileHashes {
    pub md5: String,
    pub sha1: String,
    pub sha256: String,
    pub size_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretMatch {
    pub rule_id: String,
    pub title: String,
    pub severity: Severity,
    pub matched_value: String,
    pub file_path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrackerMatch {
    pub name: String,
    pub website: Option<String>,
    pub categories: Vec<String>,
    pub detection_evidence: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirebaseInfo {
    pub project_id: Option<String>,
    pub database_url: Option<String>,
    pub api_key: Option<String>,
    pub bundle_id: Option<String>,
    pub google_app_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanReport {
    pub app_info: AppInfo,
    pub file_hashes: FileHashes,
    pub main_binary: Option<BinaryInfo>,
    pub framework_binaries: Vec<BinaryInfo>,
    pub findings: Vec<Finding>,
    pub domains: Vec<DomainInfo>,
    pub emails: Vec<String>,
    pub trackers: Vec<TrackerMatch>,
    pub secrets: Vec<SecretMatch>,
    pub firebase: Option<FirebaseInfo>,
    pub scan_duration_ms: u64,
    pub security_score: u8,
    pub grade: String,
    /// Timestamped audit log of analysis steps. Always populated.
    pub scan_log: Vec<AuditEntry>,
    /// Per-domain geolocation and threat intel. Populated only when --network is used.
    pub domain_intel: Vec<DomainGeoInfo>,
    /// Third-party framework components with version info (software composition analysis).
    pub framework_components: Vec<FrameworkComponent>,
    /// Parsed provisioning profile. Present only in dev/ad-hoc/enterprise builds.
    pub provisioning: Option<ProvisioningInfo>,
    /// OWASP Mobile Top 10 summary: maps M1..M10 → list of finding IDs.
    #[serde(default)]
    pub owasp_summary: HashMap<String, Vec<String>>,
    /// Diff against a saved baseline report. Populated only when `--baseline` is used.
    pub baseline_diff: Option<DiffResult>,
}

/// A third-party framework component with version information extracted from
/// its embedded Info.plist. Used for software composition analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FrameworkComponent {
    /// Name of the framework (e.g. "Alamofire").
    pub name: String,
    /// Bundle identifier (e.g. "org.alamofire.Alamofire").
    pub bundle_id: Option<String>,
    /// Version string from CFBundleShortVersionString.
    pub version: Option<String>,
    /// Full path inside the IPA archive.
    pub path: String,
}

/// Parsed content of embedded.mobileprovision.
/// Present only in development, ad-hoc, and enterprise builds.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProvisioningInfo {
    /// Human-readable profile name.
    pub name: Option<String>,
    /// Developer team name.
    pub team_name: Option<String>,
    /// Team identifier (10-char Apple ID).
    pub team_id: Option<String>,
    /// Profile type: "development", "ad-hoc", "enterprise", or "app-store".
    pub profile_type: String,
    /// ISO-8601 expiration date string.
    pub expiration_date: Option<String>,
    /// Number of provisioned device UDIDs (ad-hoc only).
    pub provisioned_device_count: usize,
}

/// Comparison result between the current scan and a saved baseline report.
/// Populated when `--baseline` is supplied.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiffResult {
    /// Finding IDs that appear in the current scan but not in the baseline.
    pub new_findings: Vec<String>,
    /// Finding IDs that were present in the baseline but are gone now.
    pub fixed_findings: Vec<String>,
    /// Number of secrets new vs baseline.
    pub new_secrets: usize,
    /// Number of secrets resolved vs baseline.
    pub fixed_secrets: usize,
    /// current score − baseline score (positive = improvement).
    pub score_delta: i16,
    /// True if the letter grade changed between baseline and current.
    pub grade_changed: bool,
}

/// Geolocation and threat intelligence for a single domain/IP.
/// Populated when `--network` is supplied.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainGeoInfo {
    pub domain: String,
    pub ip: Option<String>,
    pub country: Option<String>,
    pub country_code: Option<String>,
    pub city: Option<String>,
    pub lat: Option<f64>,
    pub lon: Option<f64>,
    pub isp: Option<String>,
    /// True if the server's country appears on the OFAC sanctions list.
    pub is_ofac_sanctioned: bool,
}
