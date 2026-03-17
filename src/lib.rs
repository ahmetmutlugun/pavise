#![forbid(unsafe_code)]

pub mod baseline;
pub mod binary;
pub mod manifest;
pub mod network;
pub mod patterns;
pub mod report;
pub mod resources;
pub mod scoring;
pub mod types;
pub mod unpacker;

use anyhow::{Context, Result};
use rayon::prelude::*;
use std::path::{Path, PathBuf};
use std::time::Instant;
use tracing::{debug, info, span, Level};

use crate::binary::macho;
use crate::binary::symbols::SymbolScanner;
use crate::manifest::{entitlements, info_plist, provisioning};
use crate::patterns::{
    ciphers,
    emails::extract_emails,
    engine::{extract_printable_strings, PatternEngine},
    secrets::deduplicate,
    trackers::TrackerDetector,
    urls,
};
use crate::resources::{firebase, sca, vulns::VulnDatabase};
use crate::scoring::owasp::compute_score;
use crate::types::{
    AuditEntry, BinaryInfo, DomainGeoInfo, DomainInfo, Finding, ScanReport, SecretMatch, Severity,
};
use crate::unpacker::ipa::unpack as unpack_ipa;
use regex::Regex;
use std::collections::HashMap;
use std::sync::OnceLock;

static BARE_IP_RE: OnceLock<Regex> = OnceLock::new();

fn bare_ip_re() -> &'static Regex {
    BARE_IP_RE.get_or_init(|| {
        Regex::new(r"(?:^|[^0-9.])(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?:[^0-9.]|$)")
            .expect("bare IP regex")
    })
}

/// Extract bare IPv4 addresses from text (not already wrapped in a URL scheme).
fn scan_for_bare_ips(text: &str) -> Vec<String> {
    let mut ips = Vec::new();
    for cap in bare_ip_re().captures_iter(text) {
        if let Some(m) = cap.get(1) {
            let s = m.as_str();
            if is_ip_literal(s) {
                ips.push(s.to_string());
            }
        }
    }
    ips.sort();
    ips.dedup();
    ips
}

/// Parse a YYYY-MM-DD date string into days since Unix epoch.
fn date_str_to_days(date: &str) -> Option<i64> {
    let parts: Vec<&str> = date.split('-').collect();
    if parts.len() != 3 {
        return None;
    }
    let y: i64 = parts[0].parse().ok()?;
    let m: i64 = parts[1].parse().ok()?;
    let d: i64 = parts[2].parse().ok()?;
    if !(1..=12).contains(&m) || !(1..=31).contains(&d) {
        return None;
    }
    // Civil calendar algorithm (Howard Hinnant)
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let doy = (153 * (m + if m > 2 { -3 } else { 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    Some(era * 146097 + doe - 719468)
}

/// Resolve the rules directory: use user-supplied path, or fall back to
/// a `rules/` directory alongside the binary.
pub fn resolve_rules_dir(custom: Option<&Path>) -> PathBuf {
    if let Some(p) = custom {
        return p.to_path_buf();
    }

    // Try next to binary
    if let Ok(exe) = std::env::current_exe() {
        let candidate = exe.parent().unwrap_or(Path::new(".")).join("rules");
        if candidate.is_dir() {
            return candidate;
        }
    }

    // Try relative to CWD (useful in development)
    std::env::current_dir()
        .unwrap_or_else(|_| PathBuf::from("."))
        .join("rules")
}

/// Resolve the `data/` directory alongside the binary, then alongside CWD.
pub fn resolve_data_dir() -> PathBuf {
    if let Ok(exe) = std::env::current_exe() {
        let candidate = exe.parent().unwrap_or(Path::new(".")).join("data");
        if candidate.is_dir() {
            return candidate;
        }
    }
    std::env::current_dir()
        .unwrap_or_else(|_| PathBuf::from("."))
        .join("data")
}

pub struct ScanOptions {
    pub rules_dir: PathBuf,
    pub min_severity: Severity,
    /// Perform DNS resolution and IP geolocation lookups (requires network access).
    pub network: bool,
    /// Print phase progress lines to stderr during the scan.
    pub show_progress: bool,
}

/// Lightweight audit log accumulator used during a scan.
struct AuditLog {
    start: Instant,
    entries: Vec<AuditEntry>,
}

impl AuditLog {
    fn new(start: Instant) -> Self {
        AuditLog {
            start,
            entries: Vec::new(),
        }
    }

    fn record(&mut self, step: impl Into<String>) {
        self.entries.push(AuditEntry {
            elapsed_ms: self.start.elapsed().as_millis() as u64,
            step: step.into(),
        });
    }
}

/// Main entry point for scanning an IPA file.
pub fn scan_ipa(path: &Path, opts: &ScanOptions) -> Result<ScanReport> {
    let start = Instant::now();
    let _span = span!(Level::INFO, "scan_ipa", path = %path.display()).entered();

    info!("Scanning IPA: {}", path.display());
    let mut log = AuditLog::new(start);

    macro_rules! progress {
        ($msg:expr) => {
            if opts.show_progress {
                eprintln!("  → {}", $msg);
            }
        };
    }

    // ------------------------------------------------------------------ //
    // 1. Unpack
    // ------------------------------------------------------------------ //
    progress!("Unpacking IPA…");
    let unpacked = unpack_ipa(path).context("Failed to unpack IPA")?;
    log.record(format!(
        "Unpacked IPA: {} files extracted, {:.1} MB ({} frameworks)",
        unpacked.archive.files.len(),
        unpacked.hashes.size_bytes as f64 / 1_048_576.0,
        unpacked.framework_binary_paths.len()
    ));

    // ------------------------------------------------------------------ //
    // 2. Parse Info.plist (sequential — other steps depend on app info)
    // ------------------------------------------------------------------ //
    progress!("Parsing Info.plist…");
    let plist_result = {
        // Use the bundle prefix to find exactly Payload/<App>.app/Info.plist,
        // not any framework's Info.plist (which appear at deeper paths).
        let plist_path = unpacked
            .bundle_prefix
            .as_deref()
            .map(|p| format!("{}/Info.plist", p));

        let plist_file = plist_path
            .as_deref()
            .and_then(|p| unpacked.archive.files.iter().find(|f| f.path == p))
            .or_else(|| {
                // Fallback: first file at exactly depth Payload/<X>/Info.plist
                unpacked.archive.files.iter().find(|f| {
                    let parts: Vec<&str> = f.path.split('/').collect();
                    parts.len() == 3 && parts[0] == "Payload" && parts[2] == "Info.plist"
                })
            })
            .context("Info.plist not found in IPA")?;

        info_plist::analyze(&plist_file.data, &opts.rules_dir)
            .context("Failed to analyze Info.plist")?
    };

    let app_info = plist_result.app_info;
    let mut all_findings: Vec<Finding> = plist_result.findings;
    let ats_finding_count = all_findings
        .iter()
        .filter(|f| f.id.starts_with("QS-ATS-"))
        .count();
    log.record(format!(
        "Parsed Info.plist: {} v{} ({}) — {} permissions, {} ATS findings",
        app_info.name,
        app_info.version,
        app_info.identifier,
        app_info.permissions.len(),
        ats_finding_count,
    ));

    // ------------------------------------------------------------------ //
    // 3. Parallel analysis tasks
    // ------------------------------------------------------------------ //

    // Load shared analyzers (cheap — just loads YAML once)
    let symbol_scanner = SymbolScanner::load(&opts.rules_dir)?;
    let pattern_engine = PatternEngine::load(&opts.rules_dir)?;
    let tracker_detector = TrackerDetector::load(&opts.rules_dir)?;

    progress!("Analyzing main binary…");
    // 3a. Main binary analysis
    let (main_binary_result, main_binary_findings) =
        if let Some(ref bin_path) = unpacked.main_binary_path {
            if let Some(bin_file) = unpacked.archive.files.iter().find(|f| &f.path == bin_path) {
                match macho::analyze(&bin_file.data, &bin_file.path) {
                    Ok(result) => {
                        let sym_findings = symbol_scanner.scan(&result.imports);
                        let mut findings = result.findings;
                        findings.extend(sym_findings);
                        (Some(result.binary_info), findings)
                    }
                    Err(e) => {
                        debug!("Failed to analyze main binary: {}", e);
                        (None, Vec::new())
                    }
                }
            } else {
                (None, Vec::new())
            }
        } else {
            (None, Vec::new())
        };

    all_findings.extend(main_binary_findings);
    log.record(format!(
        "Main binary analysis: {} ({}) — {} findings",
        main_binary_result
            .as_ref()
            .map(|b| b.arch.as_str())
            .unwrap_or("unknown"),
        unpacked.main_binary_path.as_deref().unwrap_or("not found"),
        all_findings.len()
    ));

    // 3a-ii. Entitlements (extracted from main binary's code signature)
    let ent_count_before = all_findings.len();
    if let Some(ref bin_path) = unpacked.main_binary_path {
        if let Some(bin_file) = unpacked.archive.files.iter().find(|f| &f.path == bin_path) {
            if let Some(ent_bytes) = entitlements::extract_from_binary(&bin_file.data) {
                debug!("Extracted {} bytes of entitlements", ent_bytes.len());
                let ent_findings = entitlements::analyze(&ent_bytes);
                all_findings.extend(ent_findings);
            }
        }
    }
    log.record(format!(
        "Entitlements: {} security findings",
        all_findings.len() - ent_count_before
    ));

    progress!(format!(
        "Analyzing {} framework binaries…",
        unpacked.framework_binary_paths.len()
    ));
    // 3b. Framework binaries (parallel)
    let framework_results: Vec<(BinaryInfo, Vec<Finding>)> = unpacked
        .framework_binary_paths
        .par_iter()
        .filter_map(|fw_path| {
            let fw_file = unpacked.archive.files.iter().find(|f| &f.path == fw_path)?;
            match macho::analyze(&fw_file.data, &fw_file.path) {
                Ok(result) => {
                    let sym_findings = symbol_scanner.scan(&result.imports);
                    let mut findings = result.findings;
                    findings.extend(sym_findings);
                    Some((result.binary_info, findings))
                }
                Err(e) => {
                    debug!("Failed to analyze framework {}: {}", fw_path, e);
                    None
                }
            }
        })
        .collect();

    let mut framework_binaries: Vec<BinaryInfo> = Vec::new();
    let mut fw_finding_groups: HashMap<String, Vec<Finding>> = HashMap::new();
    for (bi, fw_findings) in framework_results {
        for f in fw_findings {
            fw_finding_groups.entry(f.id.clone()).or_default().push(f);
        }
        framework_binaries.push(bi);
    }
    // Aggregate framework findings: instead of N separate identical findings,
    // emit one summary finding per rule ID with all affected frameworks listed.
    let fw_count = framework_binaries.len();
    for (rule_id, group) in fw_finding_groups {
        if group.len() <= 2 || fw_count <= 3 {
            // Few findings — keep individual entries
            all_findings.extend(group);
        } else {
            // Aggregate: take the first finding as template, merge evidence
            let first = &group[0];
            let affected: Vec<String> = group
                .iter()
                .filter_map(|f| f.evidence.first())
                .map(|e| {
                    // Extract short framework name from evidence path
                    e.split('/')
                        .find(|s| s.ends_with(".framework") || s.ends_with(".dylib"))
                        .unwrap_or(e.as_str())
                        .to_string()
                })
                .collect();
            all_findings.push(Finding {
                id: rule_id,
                title: first.title.clone(),
                description: format!(
                    "{} — affects {} of {} framework binaries.",
                    first.description.split('\'').next().unwrap_or(&first.description).trim(),
                    group.len(),
                    fw_count
                ),
                severity: first.severity.clone(),
                category: first.category.clone(),
                cwe: first.cwe.clone(),
                owasp_mobile: first.owasp_mobile.clone(),
                owasp_masvs: first.owasp_masvs.clone(),
                evidence: affected,
                remediation: first.remediation.clone(),
            });
        }
    }
    log.record(format!(
        "Framework binaries: {} analyzed in parallel",
        framework_binaries.len()
    ));

    progress!("Scanning strings for secrets, URLs, ciphers, and emails…");
    // 3c. String scanning (parallel over all files)
    #[allow(clippy::type_complexity)]
    let string_results: Vec<(
        Vec<SecretMatch>,
        Vec<String>,
        Vec<DomainInfo>,
        Vec<Finding>,
        Vec<String>, // bare IPv4 addresses
    )> = unpacked
        .archive
        .files
        .par_iter()
        .filter(|f| !patterns::secrets::is_noise_file(&f.path))
        .map(|f| {
            let text = extract_printable_strings(&f.data, 6);
            let mut secrets = pattern_engine.scan(&text, &f.path);

            // Entropy-based detection only on text-like files.
            // Running on binary files (dylibs, Mach-O frameworks) produces extreme noise:
            // ObjC selectors, Swift mangled symbols, and path strings all score above 4.5
            // despite being completely harmless.
            if is_text_like(&f.path) {
                let lines: Vec<&str> = text.lines().collect();
                let entropy_hits =
                    crate::patterns::entropy::scan_for_high_entropy(&lines, &f.path);
                secrets.extend(entropy_hits);
            }

            // Email extraction on text files only (skip large binary files)
            let emails = if is_text_like(&f.path) {
                extract_emails(&text, &f.path)
            } else {
                Vec::new()
            };

            let url_result = urls::extract(&text, &f.path);

            // Weak cipher scan — runs on all file types; CommonCrypto constants
            // appear as C string literals in Mach-O __TEXT,__cstring sections.
            let cipher_findings = ciphers::scan_for_weak_ciphers(&text, &f.path);

            // Bare IPv4 addresses not already inside a URL scheme
            let bare_ips = scan_for_bare_ips(&text);

            let mut file_findings = url_result.findings;
            file_findings.extend(cipher_findings);

            (secrets, emails, url_result.domains, file_findings, bare_ips)
        })
        .collect();

    let mut all_secrets: Vec<SecretMatch> = Vec::new();
    let mut all_emails: Vec<String> = Vec::new();
    let mut all_domains: Vec<DomainInfo> = Vec::new();
    let mut all_bare_ips: Vec<String> = Vec::new();

    for (secrets, emails, domains, file_findings, bare_ips) in string_results {
        all_secrets.extend(secrets);
        all_emails.extend(emails);
        all_domains.extend(domains);
        all_findings.extend(file_findings);
        all_bare_ips.extend(bare_ips);
    }

    // Deduplicate
    all_secrets = deduplicate(all_secrets);
    all_emails.sort();
    all_emails.dedup();
    all_domains.sort_by(|a, b| a.domain.cmp(&b.domain));
    all_domains.dedup_by(|a, b| a.domain == b.domain);
    all_bare_ips.sort();
    all_bare_ips.dedup();

    // Deduplicate findings: group by rule ID and merge evidence
    all_findings = deduplicate_findings(all_findings);

    log.record(format!(
        "String scan: {} secrets, {} unique domains, {} emails extracted",
        all_secrets.len(),
        all_domains.len(),
        all_emails.len()
    ));

    // Flag hardcoded IP address literals (unusual for legitimate backend communication).
    // Skip loopback/unspecified addresses — these are used for local development.
    const BENIGN_IPS: &[&str] = &["127.0.0.1", "0.0.0.0", "255.255.255.255"];

    // 1. URL-embedded IPs (http://x.x.x.x/...)
    for d in &all_domains {
        if is_ip_literal(&d.domain) && !BENIGN_IPS.contains(&d.domain.as_str()) {
            all_findings.push(Finding {
                id: "QS-NET-003".to_string(),
                title: "Hardcoded IP Address".to_string(),
                description: format!(
                    "A hardcoded IP address '{}' was found in the app. Legitimate backend \
                    servers should be addressed by hostname. Hardcoded IPs bypass certificate \
                    pinning and may indicate a misconfiguration.",
                    d.domain
                ),
                severity: Severity::Warning,
                category: "network".to_string(),
                cwe: Some("CWE-319".to_string()),
                owasp_mobile: Some("M5".to_string()),
                owasp_masvs: Some("MSTG-NETWORK-1".to_string()),
                evidence: vec![format!("IP literal: {} (found in {})", d.domain, d.context)],
                remediation: Some("Replace hardcoded IP addresses with domain names and implement certificate pinning.".to_string()),
            });
        }
    }

    // 2. Bare IPs found in strings (not wrapped in a URL scheme)
    let url_ips: std::collections::HashSet<&str> = all_domains
        .iter()
        .filter(|d| is_ip_literal(&d.domain))
        .map(|d| d.domain.as_str())
        .collect();
    for ip in &all_bare_ips {
        if !BENIGN_IPS.contains(&ip.as_str()) && !url_ips.contains(ip.as_str()) {
            all_findings.push(Finding {
                id: "QS-NET-003".to_string(),
                title: "Hardcoded IP Address".to_string(),
                description: format!(
                    "A hardcoded IP address '{}' was found in extracted strings. Legitimate \
                    backend servers should be addressed by hostname. Hardcoded IPs bypass \
                    certificate pinning and may indicate a misconfiguration.",
                    ip
                ),
                severity: Severity::Warning,
                category: "network".to_string(),
                cwe: Some("CWE-319".to_string()),
                owasp_mobile: Some("M5".to_string()),
                owasp_masvs: Some("MSTG-NETWORK-1".to_string()),
                evidence: vec![format!("Bare IP literal: {}", ip)],
                remediation: Some("Replace hardcoded IP addresses with domain names and implement certificate pinning.".to_string()),
            });
        }
    }

    // 3d. Firebase detection
    let firebase_info = unpacked
        .archive
        .find("GoogleService-Info.plist")
        .and_then(|f| firebase::parse_google_service_info(&f.data));

    // 3d-ii. Scan all non-main .plist files for secrets (config plists can contain credentials)
    let plist_secret_results: Vec<Vec<SecretMatch>> = unpacked
        .archive
        .files
        .par_iter()
        .filter(|f| {
            f.path.ends_with(".plist")
                && !f.path.ends_with("Info.plist")
                && !patterns::secrets::is_noise_file(&f.path)
        })
        .map(|f| {
            let text = extract_printable_strings(&f.data, 6);
            pattern_engine.scan(&text, &f.path)
        })
        .collect();
    for matches in plist_secret_results {
        all_secrets.extend(matches);
    }
    all_secrets = deduplicate(all_secrets);

    // 3d-iii. Embedded certificate / private key file detection
    const CERT_EXTENSIONS: &[&str] = &[".p12", ".pfx", ".pem", ".cer", ".der", ".key"];
    for f in &unpacked.archive.files {
        let lower = f.path.to_lowercase();
        if let Some(ext) = CERT_EXTENSIONS.iter().find(|e| lower.ends_with(*e)) {
            all_findings.push(Finding {
                id: "QS-CERT-001".to_string(),
                title: "Embedded Certificate or Private Key File".to_string(),
                description: format!(
                    "A certificate or key file ('{}') was found inside the IPA bundle. \
                    Shipping private keys or PKCS#12 keystores in the app bundle exposes \
                    them to extraction and misuse by anyone who unpacks the IPA.",
                    f.path
                ),
                severity: Severity::High,
                category: "secrets".to_string(),
                cwe: Some("CWE-321".to_string()),
                owasp_mobile: Some("M9".to_string()),
                owasp_masvs: Some("MSTG-CRYPTO-1".to_string()),
                evidence: vec![format!("{} file: {}", ext, f.path)],
                remediation: Some(
                    "Remove certificate and key files from the app bundle. \
                    Use the iOS Keychain or server-side PKI. If mutual TLS is required, \
                    provision certificates at runtime via MDM or a secure enrolment flow."
                        .to_string(),
                ),
            });
        }
    }

    // 3d-iv. Bundled database file detection
    const DB_EXTENSIONS: &[&str] = &[".sqlite", ".sqlite3", ".db", ".realm"];
    for f in &unpacked.archive.files {
        let lower = f.path.to_lowercase();
        if DB_EXTENSIONS.iter().any(|e| lower.ends_with(*e)) {
            all_findings.push(Finding {
                id: "QS-STORE-001".to_string(),
                title: "Bundled Database File".to_string(),
                description: format!(
                    "A pre-populated database file ('{}') is shipped inside the IPA. \
                    Bundled databases may contain sensitive data (PII, credentials, internal \
                    schema) that is accessible to anyone who unpacks the IPA.",
                    f.path
                ),
                severity: Severity::Info,
                category: "storage".to_string(),
                cwe: Some("CWE-312".to_string()),
                owasp_mobile: Some("M9".to_string()),
                owasp_masvs: Some("MSTG-STORAGE-1".to_string()),
                evidence: vec![format!("Database: {}", f.path)],
                remediation: Some(
                    "Audit the bundled database for sensitive content. \
                    Pre-populated databases are acceptable for reference data \
                    but must never contain credentials, PII, or internal infrastructure details."
                        .to_string(),
                ),
            });
        }
    }
    log.record(format!(
        "Archive scan: {} cert/key files flagged, {} database files detected",
        all_findings
            .iter()
            .filter(|f| f.id == "QS-CERT-001")
            .count(),
        all_findings
            .iter()
            .filter(|f| f.id == "QS-STORE-001")
            .count(),
    ));

    progress!("Detecting trackers and performing SCA…");
    // 3e. Tracker detection — collect framework names from paths
    let framework_names: Vec<String> = unpacked
        .framework_binary_paths
        .iter()
        .filter_map(|p| {
            p.split('/')
                .find(|seg| seg.ends_with(".framework"))
                .map(|seg| seg.trim_end_matches(".framework").to_string())
        })
        .collect();

    let domain_strings: Vec<String> = all_domains.iter().map(|d| d.domain.clone()).collect();
    let trackers = tracker_detector.detect(&domain_strings, &framework_names);
    log.record(format!(
        "Tracker detection: {} trackers identified from {} domains and {} frameworks",
        trackers.len(),
        all_domains.len(),
        framework_names.len()
    ));

    // 3e-ii. Certificate pinning check
    // Flag apps with external network activity but no detectable pinning mechanism.
    // We check for known pinning signals in extracted strings and framework names.
    {
        const PINNING_SIGNALS: &[&str] = &[
            "pinnedCertificates",
            "pinnedPublicKeys",
            "pinnedKeys",
            "TrustKit",
            "SSLPinning",
            "certificate_pinning",
            "public_key_hash",
            "kCFStreamSSLPeerTrust",
            "SecTrustEvaluateWithError",
            "SecTrustEvaluate",
            "challengeCompletionHandler",
            "didReceiveAuthenticationChallenge",
            "URLAuthenticationChallenge",
        ];

        let has_pinning_signal = unpacked.archive.files.iter().any(|f| {
            if let Ok(text) = std::str::from_utf8(&f.data) {
                PINNING_SIGNALS.iter().any(|sig| text.contains(sig))
            } else {
                false
            }
        }) || framework_names.iter().any(|n| {
            let lower = n.to_lowercase();
            lower.contains("trustkit") || lower.contains("pinning")
        });

        // Count external non-Apple domains
        let external_domain_count = all_domains
            .iter()
            .filter(|d| {
                !d.domain.ends_with(".apple.com")
                    && !d.domain.contains("apple.com")
                    && !d.domain.ends_with(".icloud.com")
                    && !d.domain.ends_with(".googleapis.com")
                    && !d.domain.starts_with("localhost")
            })
            .count();

        if !has_pinning_signal && external_domain_count >= 2 {
            all_findings.push(Finding {
                id: "QS-NET-004".to_string(),
                title: "No Certificate Pinning Detected".to_string(),
                description: format!(
                    "The app communicates with {} external domain(s) but no certificate pinning \
                    mechanism was detected. Without pinning, the app is vulnerable to \
                    man-in-the-middle attacks by any trusted CA in the device's certificate store.",
                    external_domain_count
                ),
                severity: Severity::Warning,
                category: "network".to_string(),
                cwe: Some("CWE-295".to_string()),
                owasp_mobile: Some("M5".to_string()),
                owasp_masvs: Some("MSTG-NETWORK-4".to_string()),
                evidence: all_domains
                    .iter()
                    .filter(|d| {
                        !d.domain.ends_with(".apple.com")
                            && !d.domain.contains("apple.com")
                            && !d.domain.ends_with(".icloud.com")
                    })
                    .take(5)
                    .map(|d| d.domain.clone())
                    .collect(),
                remediation: Some(
                    "Implement certificate pinning using TrustKit, URLSession \
                    authentication challenges (didReceiveChallenge), or Apple's \
                    App Transport Security pinning. Pin to public key hashes rather \
                    than leaf certificates for rotation flexibility."
                        .to_string(),
                ),
            });
        }
        log.record(format!(
            "Pinning check: {} (signal={}, external_domains={})",
            if has_pinning_signal { "detected" } else { "not detected" },
            has_pinning_signal,
            external_domain_count
        ));
    }

    // 3f. Software Composition Analysis — extract framework versions
    let mut framework_components =
        sca::extract_components(&unpacked.framework_binary_paths, &unpacked.archive.files);

    // 3f-i. Lock file SCA — CocoaPods Podfile.lock and SPM Package.resolved
    // These files are not normally shipped in production IPAs, but developer
    // or CI archives sometimes include them.  Parsing them adds transitive
    // dependency coverage beyond bundled framework binaries.
    let lockfile_components = sca::extract_lockfile_deps(&unpacked.archive.files);
    let lockfile_count = lockfile_components.len();
    framework_components.extend(lockfile_components);

    let versioned_count = framework_components
        .iter()
        .filter(|c| c.version.is_some())
        .count();
    log.record(format!(
        "SCA: {} framework components identified ({} with version info, {} from lock files)",
        framework_components.len(),
        versioned_count,
        lockfile_count
    ));

    // 3f-ii. CVE matching against detected framework versions
    let data_dir = resolve_data_dir();
    match VulnDatabase::load(&data_dir) {
        Ok(vuln_db) => {
            let cve_findings = vuln_db.check(&framework_components);
            let cve_count = cve_findings.len();
            all_findings.extend(cve_findings);
            log.record(format!(
                "CVE scan: {} vulnerable framework versions found",
                cve_count
            ));
        }
        Err(e) => {
            debug!("CVE database unavailable: {}", e);
            log.record(format!("CVE scan: skipped ({})", e));
        }
    }

    // 3g. Provisioning profile
    let provisioning_info = unpacked
        .archive
        .files
        .iter()
        .find(|f| f.path.ends_with("embedded.mobileprovision"))
        .and_then(|f| provisioning::parse(&f.data));

    if let Some(ref prov) = provisioning_info {
        let profile_type = &prov.profile_type;
        if profile_type == "development" || profile_type == "ad-hoc" {
            all_findings.push(Finding {
                id: "QS-PROV-001".to_string(),
                title: format!("Non-Production Provisioning Profile ({})", profile_type),
                description: format!(
                    "The IPA contains an embedded.mobileprovision with profile type '{}'. \
                    {} \
                    Distribution builds submitted to the App Store should not include a \
                    mobileprovision file.",
                    profile_type,
                    if prov.provisioned_device_count > 0 {
                        format!(
                            "{} specific device UDIDs are provisioned. ",
                            prov.provisioned_device_count
                        )
                    } else {
                        String::new()
                    }
                ),
                severity: Severity::Warning,
                category: "configuration".to_string(),
                cwe: Some("CWE-489".to_string()),
                owasp_mobile: Some("M8".to_string()),
                owasp_masvs: Some("MSTG-CODE-1".to_string()),
                evidence: vec![format!(
                    "Profile: {} | Team: {} | Type: {}",
                    prov.name.as_deref().unwrap_or("unknown"),
                    prov.team_name.as_deref().unwrap_or("unknown"),
                    profile_type
                )],
                remediation: Some(
                    "Use App Store distribution signing for production releases. \
                    Development and ad-hoc builds should not be submitted to end users."
                        .to_string(),
                ),
            });
        }
        // Expiration check
        if let Some(ref exp_date) = prov.expiration_date {
            let today_days = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| (d.as_secs() / 86400) as i64)
                .unwrap_or(0);

            if let Some(exp_days) = date_str_to_days(exp_date) {
                let days_remaining = exp_days - today_days;
                if days_remaining < 0 {
                    all_findings.push(Finding {
                        id: "QS-PROV-002".to_string(),
                        title: "Provisioning Profile Expired".to_string(),
                        description: format!(
                            "The embedded.mobileprovision expired on {}. Apps signed with an \
                            expired profile will no longer launch on non-development devices and \
                            may be rejected by MDM systems.",
                            exp_date
                        ),
                        severity: Severity::High,
                        category: "configuration".to_string(),
                        cwe: Some("CWE-298".to_string()),
                        owasp_mobile: Some("M8".to_string()),
                        owasp_masvs: Some("MSTG-CODE-1".to_string()),
                        evidence: vec![format!("ExpirationDate: {} (expired {} days ago)", exp_date, -days_remaining)],
                        remediation: Some("Renew the provisioning profile in the Apple Developer Portal and re-sign the app.".to_string()),
                    });
                } else if days_remaining <= 30 {
                    all_findings.push(Finding {
                        id: "QS-PROV-003".to_string(),
                        title: format!("Provisioning Profile Expires in {} Days", days_remaining),
                        description: format!(
                            "The embedded.mobileprovision will expire on {} ({} days remaining). \
                            Renew the profile before expiry to prevent signing failures and \
                            prevent the app from launching on managed devices.",
                            exp_date, days_remaining
                        ),
                        severity: Severity::Warning,
                        category: "configuration".to_string(),
                        cwe: Some("CWE-298".to_string()),
                        owasp_mobile: Some("M8".to_string()),
                        owasp_masvs: Some("MSTG-CODE-1".to_string()),
                        evidence: vec![format!("ExpirationDate: {} ({} days remaining)", exp_date, days_remaining)],
                        remediation: Some("Renew the provisioning profile in the Apple Developer Portal before it expires.".to_string()),
                    });
                }
            }
        }

        log.record(format!(
            "Provisioning profile: type={}, team={}, devices={}, expires={}",
            prov.profile_type,
            prov.team_name.as_deref().unwrap_or("unknown"),
            prov.provisioned_device_count,
            prov.expiration_date.as_deref().unwrap_or("unknown")
        ));
    }

    // ------------------------------------------------------------------ //
    // 4. Score
    // ------------------------------------------------------------------ //
    progress!("Computing security score…");

    // embedded.mobileprovision is present in dev/ad-hoc/enterprise builds.
    // App Store binaries are encrypted by Apple at download time, so cryptid=0
    // is normal here and should not count against the score.
    let is_dev_build = unpacked
        .archive
        .files
        .iter()
        .any(|f| f.path.ends_with("embedded.mobileprovision"));

    let (security_score, grade) = compute_score(
        main_binary_result.as_ref(),
        &framework_binaries,
        &all_findings,
        &all_secrets,
        is_dev_build,
    );
    log.record(format!(
        "Scoring: {}/100 ({}) — {} high, {} warning, {} info findings total",
        security_score,
        grade,
        all_findings
            .iter()
            .filter(|f| f.severity == Severity::High)
            .count(),
        all_findings
            .iter()
            .filter(|f| f.severity == Severity::Warning)
            .count(),
        all_findings
            .iter()
            .filter(|f| f.severity == Severity::Info)
            .count(),
    ));

    // ------------------------------------------------------------------ //
    // 5. Network domain intelligence (optional — requires --network flag)
    // ------------------------------------------------------------------ //
    let domain_intel: Vec<DomainGeoInfo> = if opts.network {
        match network::domain_intel::analyze_domains(&domain_strings) {
            Ok(intel) => {
                let ofac_count = intel.iter().filter(|d| d.is_ofac_sanctioned).count();
                log.record(format!(
                    "Network intel: {} domains geolocated, {} OFAC-sanctioned servers",
                    intel.len(),
                    ofac_count
                ));
                // Generate findings for OFAC-sanctioned domains
                for entry in &intel {
                    if entry.is_ofac_sanctioned {
                        all_findings.push(Finding {
                            id: "QS-NET-002".to_string(),
                            title: "Server in OFAC-Sanctioned Country".to_string(),
                            description: format!(
                                "Domain '{}' resolves to {} ({}), which is in {} — an OFAC-sanctioned country. \
                                Communicating with servers in sanctioned countries may create regulatory and compliance risk.",
                                entry.domain,
                                entry.ip.as_deref().unwrap_or("unknown IP"),
                                entry.city.as_deref().unwrap_or("unknown city"),
                                entry.country.as_deref().unwrap_or("unknown country")
                            ),
                            severity: Severity::High,
                            category: "network".to_string(),
                            cwe: Some("CWE-918".to_string()),
                            owasp_mobile: Some("M5".to_string()),
                            owasp_masvs: None,
                            evidence: vec![format!(
                                "{} → {} ({}, {})",
                                entry.domain,
                                entry.ip.as_deref().unwrap_or("?"),
                                entry.city.as_deref().unwrap_or("?"),
                                entry.country_code.as_deref().unwrap_or("?")
                            )],
                            remediation: Some("Review why the app communicates with servers in this country. Consider whether this traffic is necessary and compliant with applicable regulations.".to_string()),
                        });
                    }
                }
                intel
            }
            Err(e) => {
                debug!("Network domain intel failed: {}", e);
                log.record(format!("Network intel: failed ({})", e));
                Vec::new()
            }
        }
    } else {
        log.record(
            "Network intel: skipped (use --network to enable DNS/GeoIP lookups)".to_string(),
        );
        Vec::new()
    };

    // ------------------------------------------------------------------ //
    // 6. Filter by minimum severity
    // ------------------------------------------------------------------ //
    let all_findings = filter_by_severity(all_findings, &opts.min_severity);

    // OWASP Mobile Top 10 summary (computed after filtering so counts match report)
    let owasp_summary = compute_owasp_summary(&all_findings);

    let scan_duration_ms = start.elapsed().as_millis() as u64;
    log.record(format!("Scan complete: {}ms total", scan_duration_ms));
    info!(
        "Scan completed in {}ms — score: {}/100 ({})",
        scan_duration_ms, security_score, grade
    );

    Ok(ScanReport {
        app_info,
        file_hashes: unpacked.hashes,
        main_binary: main_binary_result,
        framework_binaries,
        findings: all_findings,
        domains: all_domains,
        emails: all_emails,
        trackers,
        secrets: all_secrets,
        firebase: firebase_info,
        scan_duration_ms,
        security_score,
        grade,
        scan_log: log.entries,
        domain_intel,
        framework_components,
        provisioning: provisioning_info,
        owasp_summary,
        baseline_diff: None,
    })
}

/// Build OWASP Mobile Top 10 summary: M1..M10 → list of finding IDs with that category.
fn compute_owasp_summary(findings: &[Finding]) -> HashMap<String, Vec<String>> {
    let mut summary: HashMap<String, Vec<String>> =
        ["M1", "M2", "M3", "M4", "M5", "M6", "M7", "M8", "M9", "M10"]
            .iter()
            .map(|k| (k.to_string(), Vec::new()))
            .collect();
    for f in findings {
        if let Some(m) = &f.owasp_mobile {
            if let Some(list) = summary.get_mut(m.as_str()) {
                list.push(f.id.clone());
            }
        }
    }
    summary
}

/// Deduplicate and group findings by rule ID.
///
/// Multiple firings of the same rule (e.g. strcpy in 5 different files) are
/// collapsed into a single finding with all evidence items listed and a
/// count appended to the description.  This keeps the report focused while
/// preserving full forensic detail in the evidence array.
fn deduplicate_findings(findings: Vec<Finding>) -> Vec<Finding> {
    let mut by_id: HashMap<String, Vec<Finding>> = HashMap::new();
    let mut order: Vec<String> = Vec::new();

    for f in findings {
        if !by_id.contains_key(&f.id) {
            order.push(f.id.clone());
        }
        by_id.entry(f.id.clone()).or_default().push(f);
    }

    let mut result = Vec::with_capacity(order.len());
    for id in order {
        let mut group = by_id.remove(&id).unwrap_or_default();
        if group.len() == 1 {
            result.push(group.remove(0));
        } else {
            let n = group.len();
            // Use the highest-severity (lowest enum discriminant) finding as the template
            let template_idx = group
                .iter()
                .enumerate()
                .min_by_key(|(_, f)| &f.severity)
                .map(|(i, _)| i)
                .unwrap_or(0);
            let template = group.remove(template_idx);

            // Collect all evidence, deduplicate, cap at 20 items
            let mut all_evidence: Vec<String> = std::iter::once(template.evidence.clone())
                .chain(group.iter().map(|f| f.evidence.clone()))
                .flatten()
                .collect();
            all_evidence.dedup();
            all_evidence.truncate(20);

            let description = format!(
                "{} ({} instances detected.)",
                template.description.trim_end_matches('.'),
                n
            );

            result.push(Finding {
                id,
                title: template.title,
                description,
                severity: template.severity,
                category: template.category,
                cwe: template.cwe,
                owasp_mobile: template.owasp_mobile,
                owasp_masvs: template.owasp_masvs,
                evidence: all_evidence,
                remediation: template.remediation,
            });
        }
    }
    result
}

fn filter_by_severity(findings: Vec<Finding>, min: &Severity) -> Vec<Finding> {
    findings
        .into_iter()
        .filter(|f| &f.severity <= min)
        .collect()
}

/// True if the string looks like a bare IPv4 address (e.g. "192.168.1.1").
fn is_ip_literal(s: &str) -> bool {
    let parts: Vec<&str> = s.split('.').collect();
    parts.len() == 4 && parts.iter().all(|p| p.parse::<u8>().is_ok())
}

fn is_text_like(path: &str) -> bool {
    let lower = path.to_lowercase();
    // Include source, config, and script files; exclude known binary formats
    const TEXT_EXTENSIONS: &[&str] = &[
        ".plist",
        ".json",
        ".xml",
        ".yaml",
        ".yml",
        ".txt",
        ".md",
        ".swift",
        ".m",
        ".mm",
        ".h",
        ".c",
        ".cpp",
        ".js",
        ".ts",
        ".py",
        ".sh",
        ".html",
        ".css",
        ".strings",
        ".stringsdict",
    ];
    const BINARY_EXTENSIONS: &[&str] = &[
        ".bin",
        ".mlmodelc",
        ".nib",
        ".car",
        ".dylib",
        ".a",
        ".o",
        ".png",
        ".jpg",
        ".jpeg",
        ".gif",
        ".pdf",
        ".mp4",
        ".mov",
        ".tflite",
        ".pb",
        ".onnx",
        ".pt",
        ".weights",
    ];

    if BINARY_EXTENSIONS.iter().any(|ext| lower.ends_with(ext)) {
        return false;
    }
    // Allow files with text-like extensions, or no extension (could be source)
    TEXT_EXTENSIONS.iter().any(|ext| lower.ends_with(ext)) || !lower.contains('.')
}
