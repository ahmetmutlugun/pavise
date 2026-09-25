#![forbid(unsafe_code)]

pub mod baseline;
pub mod binary;
pub mod manifest;
pub mod network;
pub mod patterns;
pub mod report;
pub mod resources;
pub mod rules;
pub mod scoring;
pub mod server;
pub mod types;
pub mod unpacker;

use anyhow::{Context, Result};
use rayon::prelude::*;
use std::path::{Path, PathBuf};
use std::time::Instant;
use tracing::{debug, info, span, Level};

use crate::binary::macho;
use crate::binary::symbols::{Origin, SymbolScanner};
use crate::manifest::{entitlements, info_plist, provisioning};
use crate::patterns::{
    ciphers,
    emails::extract_emails,
    engine::{extract_printable_strings, PatternEngine},
    secrets::deduplicate,
    trackers::TrackerDetector,
    urls,
};
use crate::resources::{eol, firebase, sca};
use crate::scoring::owasp::compute_score;
use crate::types::{
    AuditEntry, BinaryInfo, DomainGeoInfo, DomainInfo, Finding, ScanReport, SecretMatch, Severity,
};
use crate::unpacker::ipa::{unpack_with_limit, MAX_TOTAL_EXTRACTED};
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

static IP_CONTEXT_RE: OnceLock<Regex> = OnceLock::new();

/// Words that mark a dotted quad on the same line as a network address.
fn ip_context_re() -> &'static Regex {
    IP_CONTEXT_RE.get_or_init(|| {
        Regex::new(
            r"(?i)host|server|addr|dns|proxy|endpoint|resolver|gateway|\bip\b|_ip\b|\bip_|ipv4",
        )
        .expect("IP context regex")
    })
}

/// Extract bare IPv4 addresses from text (not already wrapped in a URL scheme).
///
/// A dotted quad inside arbitrary text is usually a version or OID, so a match
/// needs context: the string is just the address (optionally `:port` or
/// `/prefix`), the line lists several addresses, or it names a host/server/DNS.
fn scan_for_bare_ips(text: &str) -> Vec<String> {
    let mut ips = Vec::new();
    for line in text.lines() {
        let found: Vec<&str> = bare_ip_re()
            .captures_iter(line)
            .filter_map(|c| c.get(1).map(|m| m.as_str()))
            .filter(|s| is_ip_literal(s))
            .collect();
        let Some(first) = found.first() else {
            continue;
        };
        let trimmed = line
            .trim()
            .trim_matches(|c| c == '"' || c == '\'' || c == ',');
        let standalone = trimmed.strip_prefix(first).is_some_and(|rest| {
            rest.is_empty()
                || rest
                    .strip_prefix([':', '/'])
                    .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
        });
        if standalone || found.len() >= 2 || ip_context_re().is_match(line) {
            ips.extend(found.iter().map(|s| s.to_string()));
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

/// Configuration for a single IPA scan invocation.
pub struct ScanOptions {
    /// Custom rules directory replacing the embedded rule set (`--rules`).
    pub rules_dir: Option<PathBuf>,
    /// Minimum severity threshold — findings below this level are excluded from results.
    pub min_severity: Severity,
    /// Perform DNS resolution and IP geolocation lookups (requires network access).
    pub network: bool,
    /// Print phase progress lines to stderr during the scan.
    pub show_progress: bool,
    /// Zip-bomb cap on total decompressed bytes, by declared size (default 4 GB).
    pub max_extracted_bytes: Option<u64>,
    /// Cap on bytes of inflated files held at once during the parallel
    /// per-file pass (default 512 MiB). Bounds peak memory of a scan.
    pub max_in_flight_bytes: Option<u64>,
}

/// Default for [`ScanOptions::max_in_flight_bytes`].
pub const MAX_IN_FLIGHT_BYTES: u64 = 512 * 1024 * 1024;

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
    let max_total = opts.max_extracted_bytes.unwrap_or(MAX_TOTAL_EXTRACTED);
    let unpacked = unpack_with_limit(path, max_total).context("Failed to unpack IPA")?;
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

        info_plist::analyze(
            &unpacked.archive.read(plist_file)?,
            opts.rules_dir.as_deref(),
        )
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
    let symbol_scanner = SymbolScanner::load(opts.rules_dir.as_deref())?;
    let pattern_engine = PatternEngine::load(opts.rules_dir.as_deref())?;
    let tracker_detector = TrackerDetector::load(opts.rules_dir.as_deref())?;

    progress!("Analyzing main binary…");
    // 3a. Main binary analysis
    let main_binary = unpacked
        .main_binary_path
        .as_deref()
        .and_then(|p| unpacked.archive.files.iter().find(|f| f.path == p));
    let main_data = main_binary.map(|f| unpacked.archive.read(f)).transpose()?;
    let (main_binary_result, main_binary_findings, main_imports) = if let Some(ref bin_path) =
        unpacked.main_binary_path
    {
        if let (Some(bin_file), Some(bin_data)) = (main_binary, main_data.as_deref()) {
            match macho::analyze(bin_data, &bin_file.path) {
                Ok(result) => {
                    let sym_findings = symbol_scanner.scan(&result.imports, bin_path, Origin::App);
                    let mut findings = result.findings;
                    findings.extend(sym_findings);
                    (Some(result.binary_info), findings, result.imports)
                }
                // Without the main binary every protection check is
                // skipped and the score would be inflated — fail instead.
                Err(e) => {
                    return Err(e).with_context(|| {
                        format!("Failed to analyze main binary {}", bin_file.path)
                    });
                }
            }
        } else {
            anyhow::bail!("Main binary {} missing from archive", bin_path);
        }
    } else {
        anyhow::bail!("Main binary not found (CFBundleExecutable unresolved)");
    };

    all_findings.extend(main_binary_findings);

    // Privacy manifest vs. required-reason APIs the main binary imports.
    let privacy_manifest = unpacked
        .bundle_prefix
        .as_deref()
        .map(|p| format!("{}/PrivacyInfo.xcprivacy", p))
        .and_then(|path| unpacked.archive.files.iter().find(|f| f.path == path))
        .map(|f| unpacked.archive.read(f))
        .transpose()?;
    all_findings.extend(manifest::privacy::analyze(
        privacy_manifest.as_deref(),
        &main_imports,
    ));
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
    if let Some(bin_data) = main_data.as_deref() {
        if let Some(ent_bytes) = entitlements::extract_from_binary(bin_data) {
            debug!("Extracted {} bytes of entitlements", ent_bytes.len());
            let ent_findings = entitlements::analyze(&ent_bytes);
            all_findings.extend(ent_findings);
        }
    }
    log.record(format!(
        "Entitlements: {} security findings",
        all_findings.len() - ent_count_before
    ));

    // 3a-iii. App extensions (.appex): own executable and entitlements, run
    // in their own process but ship with — and share data with — the app.
    let extension_results: Vec<Option<(BinaryInfo, Vec<Finding>)>> = unpacked
        .extension_binary_paths
        .par_iter()
        .filter_map(|ext_path| unpacked.archive.files.iter().find(|f| &f.path == ext_path))
        .map(|ext_file| {
            let data = unpacked.archive.read(ext_file)?;
            Ok(analyze_extension(&ext_file.path, &data, &symbol_scanner))
        })
        .collect::<Result<_>>()?;
    let mut extension_binaries: Vec<BinaryInfo> = Vec::new();
    for (bi, findings) in extension_results.into_iter().flatten() {
        all_findings.extend(findings);
        extension_binaries.push(bi);
    }
    log.record(format!(
        "App extensions: {} of {} analyzed",
        extension_binaries.len(),
        unpacked.extension_binary_paths.len()
    ));

    progress!(format!(
        "Analyzing {} framework binaries and scanning strings…",
        unpacked.framework_binary_paths.len()
    ));
    // 3b/3c. One parallel pass over every file: framework Mach-O analysis,
    // string scanning (secrets, URLs, ciphers, emails) and pinning signals.
    // Each non-retained file is inflated once here and dropped afterwards, so
    // peak memory tracks the files in flight, not the whole archive.
    let framework_paths: std::collections::HashSet<&str> = unpacked
        .framework_binary_paths
        .iter()
        .map(String::as_str)
        .collect();
    // Symbol-based pinning (QS-API-023) in the app's own binaries settles the
    // pinning check, so skipped (noise) files needn't be inflated for signals.
    // A framework importing a pinning API only shows the library can pin.
    let pinning_settled = all_findings.iter().any(|f| f.id == "QS-API-023");
    let budget = unpacker::ByteBudget::new(opts.max_in_flight_bytes.unwrap_or(MAX_IN_FLIGHT_BYTES));
    let mut file_scans: Vec<FileScan> = unpacked
        .archive
        .files
        .par_iter()
        .map(|f| -> Result<Option<FileScan>> {
            let noise = patterns::secrets::is_noise_file(&f.path);
            if noise && pinning_settled {
                return Ok(None);
            }
            // Held until the file's results are built: covers the inflated
            // bytes and the extracted text derived from them.
            let _permit = budget.acquire(f.size);
            let data = unpacked.archive.read(f)?;
            let mut scan = FileScan {
                pinning_signal: has_pinning_signal(&f.path, &data),
                ..FileScan::default()
            };
            if noise {
                return Ok(Some(scan));
            }
            if framework_paths.contains(f.path.as_str()) {
                scan.framework = match macho::analyze(&data, &f.path) {
                    Ok(result) => {
                        let mut findings = result.findings;
                        findings.extend(symbol_scanner.scan(
                            &result.imports,
                            &f.path,
                            Origin::Library,
                        ));
                        Some((result.binary_info, findings))
                    }
                    Err(e) => {
                        debug!("Failed to analyze framework {}: {}", f.path, e);
                        None
                    }
                };
            }
            scan_strings(f, &data, &pattern_engine, &mut scan);
            Ok(Some(scan))
        })
        .filter_map(Result::transpose)
        .collect::<Result<_>>()?;

    let mut framework_binaries: Vec<BinaryInfo> = Vec::new();
    let mut fw_finding_groups: HashMap<String, Vec<Finding>> = HashMap::new();
    for (bi, fw_findings) in file_scans.iter_mut().filter_map(|s| s.framework.take()) {
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
                // Per-binary descriptions name one framework; state the rule.
                description: format!(
                    "{} — affects {} of {} bundled framework binaries (third-party code).",
                    first.title,
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
    let mut all_secrets: Vec<SecretMatch> = Vec::new();
    let mut all_emails: Vec<String> = Vec::new();
    let mut all_domains: Vec<DomainInfo> = Vec::new();
    let mut all_bare_ips: Vec<String> = Vec::new();

    let mut file_pinning_signal = false;
    let mut library_versions: Vec<eol::LibraryVersion> = Vec::new();
    for scan in file_scans {
        library_versions.extend(scan.libraries);
        all_secrets.extend(scan.secrets);
        all_emails.extend(scan.emails);
        all_domains.extend(scan.domains);
        all_findings.extend(scan.findings);
        all_bare_ips.extend(scan.bare_ips);
        file_pinning_signal |= scan.pinning_signal;
    }

    // Secrets are deduplicated after the private-key-file filter below.
    all_emails.sort();
    all_emails.dedup();
    // Where a domain appears in several files, keep an endpoint source (see
    // `is_endpoint_source`) as its context.
    let binary_paths: std::collections::HashSet<&str> = framework_paths
        .iter()
        .copied()
        .chain(unpacked.main_binary_path.as_deref())
        .chain(unpacked.extension_binary_paths.iter().map(String::as_str))
        .collect();
    let is_endpoint =
        |d: &DomainInfo| is_endpoint_source(&d.context, binary_paths.contains(d.context.as_str()));
    all_domains.sort_by(|a, b| {
        a.domain
            .cmp(&b.domain)
            .then(is_endpoint(b).cmp(&is_endpoint(a)))
    });
    all_domains.dedup_by(|a, b| a.domain == b.domain);
    all_bare_ips.sort();
    all_bare_ips.dedup();

    // Deduplicate findings: group by rule ID and merge evidence
    all_findings = deduplicate_findings(all_findings);

    log.record(format!(
        "String scan: {} raw secret matches, {} unique domains, {} emails extracted",
        all_secrets.len(),
        all_domains.len(),
        all_emails.len()
    ));

    // 1. URL-embedded IPs (http://x.x.x.x/...)
    for d in &all_domains {
        if is_ip_literal(&d.domain) && !is_benign_ip(&d.domain) {
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
        if !is_benign_ip(ip) && !url_ips.contains(ip.as_str()) {
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
        .map(|f| unpacked.archive.read(f))
        .transpose()?
        .and_then(|data| firebase::parse_google_service_info(&data));

    // 3d-ii. Scan parsed plists as `Key = "Value"` lines. The raw string scan
    // above can't match key/value rules: XML puts key and value in separate
    // elements and binary plists store them as unrelated byte runs.
    let plist_secret_results: Vec<Option<Vec<SecretMatch>>> = unpacked
        .archive
        .files
        .par_iter()
        .filter(|f| f.path.ends_with(".plist") && !patterns::secrets::is_noise_file(&f.path))
        .map(|f| {
            let data = unpacked.archive.read(f)?;
            Ok(patterns::engine::plist_key_values(&data)
                .map(|text| pattern_engine.scan(&text, &f.path)))
        })
        .collect::<Result<_>>()?;
    for matches in plist_secret_results.into_iter().flatten() {
        all_secrets.extend(matches);
    }

    // 3d-iii. Embedded certificate / private key file detection.
    // Classify by *content*, not just extension: a bundled public certificate
    // (`.der`/`.cer`, or a PEM `CERTIFICATE`) is usually a legitimate pinning
    // anchor and is reported as an informational hotspot, while genuine private
    // keys and PKCS#12 keystores are high-severity key exposure.
    const CERT_EXTENSIONS: &[&str] = &[
        ".p12",
        ".pfx",
        ".pem",
        ".cer",
        ".der",
        ".key",
        ".crt",
        ".p8",
        ".jks",
        ".keystore",
        ".bks",
    ];
    let mut private_key_paths: std::collections::HashSet<&str> = Default::default();
    for f in &unpacked.archive.files {
        let lower = f.path.to_lowercase();
        if !CERT_EXTENSIONS.iter().any(|e| lower.ends_with(*e)) {
            continue;
        }
        let Some(kind) = resources::certs::classify(&f.path, &unpacked.archive.read(f)?) else {
            continue;
        };
        if kind.is_private() {
            private_key_paths.insert(f.path.as_str());
            let keystore = kind == resources::certs::CertKind::EncryptedKeystore;
            all_findings.push(Finding {
                id: "QS-CERT-001".to_string(),
                title: if keystore {
                    "Embedded Private Key Keystore".to_string()
                } else {
                    "Embedded Private Key File".to_string()
                },
                description: format!(
                    "A {} ('{}') was found inside the IPA bundle. {} Anyone who unpacks the \
                    IPA can extract this key material and impersonate the app or its backend.",
                    if keystore {
                        "PKCS#12 keystore"
                    } else {
                        "private key file"
                    },
                    f.path,
                    if keystore {
                        "PKCS#12 containers are password-protected, but the passphrase is \
                        typically weak or shipped alongside, leaving the private key recoverable."
                    } else {
                        "The key is stored unencrypted."
                    },
                ),
                severity: Severity::High,
                category: "secrets".to_string(),
                cwe: Some("CWE-321".to_string()),
                owasp_mobile: Some("M9".to_string()),
                owasp_masvs: Some("MSTG-CRYPTO-1".to_string()),
                evidence: vec![format!(
                    "{}: {}",
                    if keystore { "keystore" } else { "private key" },
                    f.path
                )],
                remediation: Some(
                    "Remove private key and keystore files from the app bundle. \
                    Use the iOS Keychain or server-side PKI. If mutual TLS is required, \
                    provision client certificates at runtime via MDM or a secure enrolment flow."
                        .to_string(),
                ),
            });
        } else {
            // Public certificate: informational inventory hotspot. Often a
            // legitimate certificate-pinning anchor rather than a vulnerability.
            all_findings.push(Finding {
                id: "QS-CERT-002".to_string(),
                title: "Embedded Public Certificate".to_string(),
                description: format!(
                    "A public X.509 certificate ('{}') is bundled in the IPA. This is commonly a \
                    certificate-pinning anchor and is not a secret, but it is listed for inventory: \
                    confirm it is an intended pinning/trust anchor and not a stale or unexpected CA.",
                    f.path
                ),
                severity: Severity::Info,
                category: "network".to_string(),
                cwe: None,
                owasp_mobile: Some("M5".to_string()),
                owasp_masvs: Some("MSTG-NETWORK-4".to_string()),
                evidence: vec![format!("certificate: {}", f.path)],
                remediation: Some(
                    "No action needed if this is an intended pinning anchor. Remove unused or \
                    stale certificates, and prefer pinning to public key hashes for rotation flexibility."
                        .to_string(),
                ),
            });
        }
    }

    // A private key file is reported once, as QS-CERT-001; drop the regex hit
    // (QS-SEC-004) on the same file, and generic matches a specific rule covers.
    all_secrets.retain(|s| {
        s.rule_id != "QS-SEC-004"
            || !s
                .file_path
                .as_deref()
                .is_some_and(|p| private_key_paths.contains(p))
    });
    // Deduplicate only now: an earlier (rule, value) pass could keep the key
    // file's copy of an inline key, which the filter above then drops.
    all_secrets = deduplicate(all_secrets);
    all_secrets = patterns::secrets::drop_superseded(all_secrets);

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
        "Archive scan: {} private key/keystore files, {} public certs, {} database files detected",
        all_findings
            .iter()
            .filter(|f| f.id == "QS-CERT-001")
            .count(),
        all_findings
            .iter()
            .filter(|f| f.id == "QS-CERT-002")
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
    let main_classes: Vec<String> = main_data
        .as_deref()
        .map(macho::objc_class_names)
        .unwrap_or_default();
    let trackers = tracker_detector.detect(&domain_strings, &framework_names, &main_classes);
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
        // Symbol-based pinning detection (QS-API-023 in app binaries, see
        // `pinning_settled`) is a stronger signal than the per-file text scan
        // (`has_pinning_signal`), which can't see symbols in Mach-O binaries
        // (from_utf8 fails on them). A bundled public certificate
        // (QS-CERT-002) is not evidence of pinning on its own.
        let has_pinning_signal = pinning_settled
            || file_pinning_signal
            || framework_names.iter().any(|n| {
                let lower = n.to_lowercase();
                lower.contains("trustkit") || lower.contains("pinning")
            });

        // External non-Apple domains in endpoint sources: links in bundled
        // JS libraries' comments or docs are not hosts the app talks to.
        let external_domains: Vec<&str> = all_domains
            .iter()
            .filter(|d| is_endpoint(d))
            .map(|d| d.domain.as_str())
            .filter(|d| {
                !d.ends_with(".apple.com")
                    && !d.contains("apple.com")
                    && !d.ends_with(".icloud.com")
                    && !d.ends_with(".googleapis.com")
                    && !d.starts_with("localhost")
            })
            .collect();
        let external_domain_count = external_domains.len();

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
                evidence: external_domains
                    .iter()
                    .take(5)
                    .map(|d| d.to_string())
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
            if has_pinning_signal {
                "detected"
            } else {
                "not detected"
            },
            has_pinning_signal,
            external_domain_count
        ));
    }

    // 3f. Software Composition Analysis — extract framework versions
    let mut framework_components =
        sca::extract_components(&unpacked.framework_binary_paths, &unpacked.archive)?;

    // 3f-i. Lock file SCA — CocoaPods Podfile.lock and SPM Package.resolved
    // These files are not normally shipped in production IPAs, but developer
    // or CI archives sometimes include them.  Parsing them adds transitive
    // dependency coverage beyond bundled framework binaries.
    let lockfile_components = sca::extract_lockfile_deps(&unpacked.archive)?;
    let lockfile_count = lockfile_components.len();
    framework_components.extend(lockfile_components);

    // 3f-ii. SDKs linked statically into the main binary have no framework
    // bundle; list them from their ObjC class signatures (version unknown).
    let static_sdks = tracker_detector.statically_linked(&main_classes, &framework_names);
    let main_path = unpacked.main_binary_path.as_deref().unwrap_or_default();
    framework_components.extend(
        static_sdks
            .into_iter()
            .map(|name| resources::sca::static_component(name, main_path)),
    );

    // 3f-iii. Versions from library banners (bundled frameworks' plists often
    // carry a template `1.0`) and embedded Python, then end-of-life lines.
    let archive_paths: Vec<&str> = unpacked
        .archive
        .files
        .iter()
        .map(|f| f.path.as_str())
        .collect();
    library_versions.extend(eol::detect_python(&archive_paths));
    library_versions.sort();
    library_versions.dedup();
    sca::apply_library_versions(&mut framework_components, &library_versions);
    all_findings.extend(eol::findings(&library_versions));

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

    // 3g. Provisioning profile
    // The main app's profile sits at the bundle root; extensions carry their
    // own under PlugIns/, which `ends_with` would pick up first.
    let provisioning_info = unpacked
        .bundle_prefix
        .as_deref()
        .map(|p| format!("{}/embedded.mobileprovision", p))
        .and_then(|path| unpacked.archive.files.iter().find(|f| f.path == path))
        .map(|f| unpacked.archive.read(f))
        .transpose()?
        .and_then(|data| provisioning::parse(&data));

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
                        // Info: expiry depends on the scan date, not the app, and
                        // must not flip the exit code for an unchanged IPA.
                        severity: Severity::Info,
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
                        severity: Severity::Info,
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
    // 4. Network domain intelligence (optional — requires --network flag)
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

    // 4b. Firebase open-backend probes (optional — requires --network flag)
    if opts.network {
        if let Some(ref fb) = firebase_info {
            let fb_findings = network::firebase_probe::probe(fb);
            log.record(format!(
                "Firebase probes: {} publicly readable backends",
                fb_findings.len()
            ));
            all_findings.extend(fb_findings);
        }
    }

    // 5. OSV.dev CVE lookup (optional — requires --network flag)
    if opts.network {
        let osv_findings = network::osv::query_components(&framework_components);
        let osv_count = osv_findings.len();
        all_findings.extend(osv_findings);
        log.record(format!(
            "OSV.dev CVE lookup: {} CVE-backed findings",
            osv_count
        ));
    } else {
        log.record("OSV.dev CVE lookup: skipped (use --network to enable)".to_string());
    }

    // Final dedup pass — merges findings emitted after the mid-scan pass at
    // line 431 (hardcoded IPs, OFAC, OSV, etc.). Without this, QS-NET-003
    // produces one finding per IP and dominates the warning count on apps
    // like Orbot/OnionBrowser. Idempotent for already-merged ids.
    all_findings = deduplicate_findings(all_findings);

    // ------------------------------------------------------------------ //
    // 6. Score (last, so network/CVE findings count)
    // ------------------------------------------------------------------ //
    progress!("Computing security score…");

    let (security_score, grade) = compute_score(&all_findings, &all_secrets);
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

    // OWASP Mobile Top 10 (2024) / MASVS v2 from the single rule-ID table;
    // it overrides whatever analyzers set at their call sites.
    for f in &mut all_findings {
        if let Some((cat, masvs)) = scoring::mapping::owasp_for(&f.id) {
            f.owasp_mobile = Some(cat.to_string());
            f.owasp_masvs = masvs.map(str::to_string);
        }
    }
    for s in &mut all_secrets {
        if let Some((cat, masvs)) = scoring::mapping::owasp_for(&s.rule_id) {
            s.owasp_mobile = Some(cat.to_string());
            s.owasp_masvs = masvs.map(str::to_string);
        }
    }

    // ------------------------------------------------------------------ //
    // 7. Filter by minimum severity
    // ------------------------------------------------------------------ //
    let all_findings = filter_by_severity(all_findings, &opts.min_severity);

    // OWASP Mobile Top 10 summary (computed after filtering so counts match report)
    let owasp_summary = compute_owasp_summary(&all_findings, &all_secrets, &opts.min_severity);

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
        extension_binaries,
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

/// Per-file results of the parallel pass in `scan_ipa`.
#[derive(Default)]
struct FileScan {
    framework: Option<(BinaryInfo, Vec<Finding>)>,
    secrets: Vec<SecretMatch>,
    emails: Vec<String>,
    domains: Vec<DomainInfo>,
    findings: Vec<Finding>,
    /// Bare IPv4 addresses
    bare_ips: Vec<String>,
    /// Library versions from banners in binaries and web assets
    libraries: Vec<eol::LibraryVersion>,
    pinning_signal: bool,
}

/// String-level checks on one file: secrets, entropy, emails, URLs, weak
/// ciphers and bare IPs.
fn scan_strings(
    f: &unpacker::ExtractedFile,
    data: &[u8],
    pattern_engine: &PatternEngine,
    out: &mut FileScan,
) {
    let mut text = extract_printable_strings(data, 6);
    if is_macho(data) {
        for s in macho::ustrings(data) {
            text.push('\n');
            text.push_str(&s);
        }
    }
    if let Some(scope) = eol::scope_of(&f.path, is_macho(data)) {
        out.libraries = eol::detect(&text, &f.path, scope);
    }
    let mut secrets = pattern_engine.scan(&text, &f.path);

    // Entropy-based detection only on text-like files.
    // Running on binary files (dylibs, Mach-O frameworks) produces extreme noise:
    // ObjC selectors, Swift mangled symbols, and path strings all score above 4.5
    // despite being completely harmless.
    // Config files only: minified JS/HTML/CSS bundles are dominated by
    // embedded base64 assets. Plists are scanned as parsed values, since
    // raw binary-plist bytes glue keys and offsets into fake tokens.
    if is_config_like(&f.path) && !patterns::entropy::is_lottie_json(data) {
        let parsed = f
            .path
            .ends_with(".plist")
            .then(|| patterns::engine::plist_key_values(data))
            .flatten();
        let source = parsed.as_deref().unwrap_or(&text);
        let lines: Vec<&str> = source.lines().collect();
        let entropy_hits = crate::patterns::entropy::scan_for_high_entropy(&lines, &f.path);
        secrets.extend(entropy_hits);
    }

    // Email extraction on text files and Mach-O binaries. The main
    // executable and embedded frameworks have no text-like extension but
    // routinely embed support/developer addresses in __cstring; MobSF
    // surfaces these. emails::extract_emails applies its own entropy and
    // fake-TLD filtering, so binary noise is rejected without the
    // false-positive blowup that entropy secret scanning suffers from.
    let emails = if is_text_like(&f.path) || is_macho(data) {
        extract_emails(&text, &f.path)
    } else {
        Vec::new()
    };

    let mut url_result = if urls::is_reference_file(&f.path) {
        urls::UrlExtractResult {
            domains: Vec::new(),
            findings: Vec::new(),
        }
    } else {
        urls::extract(&text, &f.path)
    };
    // HTTP links in bundled library JS/HTML are mostly comments and docs.
    if !is_endpoint_source(&f.path, is_macho(data)) {
        for finding in &mut url_result.findings {
            finding.severity = Severity::Info;
            finding.description.push_str(
                " The file is a bundled asset, not app code or config, so the URL may be a comment or documentation link.",
            );
        }
    }

    // Weak cipher scan — runs on all file types; CommonCrypto constants
    // appear as C string literals in Mach-O __TEXT,__cstring sections.
    let cipher_findings = ciphers::scan_for_weak_ciphers(&text, &f.path);

    // Bare IPv4 addresses not already inside a URL scheme
    let bare_ips = scan_for_bare_ips(&text);

    let mut file_findings = url_result.findings;
    file_findings.extend(cipher_findings);

    out.secrets = secrets;
    out.emails = emails;
    out.domains = url_result.domains;
    out.findings = file_findings;
    out.bare_ips = bare_ips;
}

/// Strings that only appear when pinning is configured. Generic trust handling
/// (SecTrustEvaluate, didReceiveAuthenticationChallenge) is used by every
/// URLSession client and says nothing about pinning.
const PINNING_SIGNALS: &[&str] = &[
    "pinnedCertificates",
    "pinnedPublicKeys",
    "pinnedKeys",
    "TrustKit",
    "SSLPinning",
    "certificate_pinning",
    "public_key_hash",
    "NSPinnedDomains", // ATS-native pinning (iOS 14+)
];

/// Text scan for pinning configuration. It can't see symbols in Mach-O
/// binaries (`from_utf8` fails on them); `QS-API-023` covers those.
fn has_pinning_signal(path: &str, data: &[u8]) -> bool {
    if let Ok(text) = std::str::from_utf8(data) {
        PINNING_SIGNALS.iter().any(|sig| text.contains(sig))
    } else {
        // Binary plists (Info.plist) keep keys as raw ASCII.
        path.ends_with("Info.plist") && data.windows(15).any(|w| w == b"NSPinnedDomains")
    }
}

/// Analyze one app-extension executable: Mach-O protections, imported APIs
/// and its own entitlements. Entitlement evidence names the extension.
fn analyze_extension(
    path: &str,
    data: &[u8],
    scanner: &SymbolScanner,
) -> Option<(BinaryInfo, Vec<Finding>)> {
    let result = match macho::analyze(data, path) {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!("Failed to analyze extension {}: {}", path, e);
            return None;
        }
    };
    let mut findings = result.findings;
    findings.extend(scanner.scan(&result.imports, path, Origin::App));
    if let Some(ent) = entitlements::extract_from_binary(data) {
        let name = path
            .split('/')
            .find(|s| s.ends_with(".appex"))
            .unwrap_or(path);
        for mut f in entitlements::analyze(&ent) {
            for e in &mut f.evidence {
                *e = format!("{}: {}", name, e);
            }
            findings.push(f);
        }
    }
    Some((result.binary_info, findings))
}

/// Build OWASP Mobile Top 10 summary: M1..M10 → list of finding and secret
/// rule IDs with that category (secrets filtered by the same minimum severity).
fn compute_owasp_summary(
    findings: &[Finding],
    secrets: &[SecretMatch],
    min_severity: &Severity,
) -> HashMap<String, Vec<String>> {
    let mut summary: HashMap<String, Vec<String>> =
        ["M1", "M2", "M3", "M4", "M5", "M6", "M7", "M8", "M9", "M10"]
            .iter()
            .map(|k| (k.to_string(), Vec::new()))
            .collect();
    let entries = findings.iter().map(|f| (&f.id, &f.owasp_mobile)).chain(
        secrets
            .iter()
            .filter(|s| &s.severity <= min_severity)
            .map(|s| (&s.rule_id, &s.owasp_mobile)),
    );
    for (id, category) in entries {
        if let Some(list) = category.as_deref().and_then(|m| summary.get_mut(m)) {
            // Per-instance rules (e.g. QS-CERT-001) fire once per file and
            // share a ruleId; record each ruleId only once per category.
            if !list.contains(id) {
                list.push(id.clone());
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
    // Rules whose every firing is a distinct real-world artifact (one embedded
    // file each) and must stay as separate per-file hotspots rather than being
    // collapsed into one merged finding. Mirrors how MobSF lists each cert/key
    // file individually. These share a ruleId (one SARIF rule, many results);
    // the instance key (file, permission, URL scheme) lives in the evidence.
    const PER_INSTANCE_RULES: &[&str] = &[
        "QS-CERT-001",
        "QS-CERT-002",
        "QS-PERM-001",
        "QS-IPC-001",
        "QS-IPC-002",
        // One per end-of-life library, each with its own title.
        "QS-SCA-001",
    ];

    let mut per_instance: Vec<Finding> = Vec::new();
    // Group key is (rule_id, is_secure). A "Secure" finding ("protection X is
    // present") must never be merged into the same group as a non-secure
    // ("protection X is absent") firing of the same rule id — that previously
    // produced a HIGH finding titled "Not Found" whose evidence read "present".
    let mut by_id: HashMap<(String, bool), Vec<Finding>> = HashMap::new();
    let mut order: Vec<(String, bool)> = Vec::new();

    for f in findings {
        if PER_INSTANCE_RULES.contains(&f.id.as_str()) {
            per_instance.push(f);
            continue;
        }
        let key = (f.id.clone(), f.severity == Severity::Secure);
        if !by_id.contains_key(&key) {
            order.push(key.clone());
        }
        by_id.entry(key).or_default().push(f);
    }

    let mut result = Vec::with_capacity(order.len());
    for key in order {
        let id = key.0.clone();
        let mut group = by_id.remove(&key).unwrap_or_default();
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

            // Collect all evidence, deduplicate, cap at 25 items per rule.
            const EVIDENCE_CAP: usize = 25;
            let mut all_evidence: Vec<String> = std::iter::once(template.evidence.clone())
                .chain(group.iter().map(|f| f.evidence.clone()))
                .flatten()
                .collect();
            // dedup() only removes adjacent duplicates; sort first so identical
            // evidence strings collapse regardless of source order.
            all_evidence.sort();
            all_evidence.dedup();
            let unique_evidence_count = all_evidence.len();
            let truncated = unique_evidence_count > EVIDENCE_CAP;
            if truncated {
                all_evidence.truncate(EVIDENCE_CAP);
            }

            let description = if truncated {
                format!(
                    "{} ({} instances detected; showing {} of {} unique.)",
                    template.description.trim_end_matches('.'),
                    n,
                    EVIDENCE_CAP,
                    unique_evidence_count,
                )
            } else {
                format!(
                    "{} ({} instances detected.)",
                    template.description.trim_end_matches('.'),
                    n
                )
            };

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

    // Per-instance findings are appended unmerged so each embedded file remains
    // its own hotspot in the report.
    result.extend(per_instance);
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
    // Leading zeros (`1.00.02.28`) mean a version string, not an address.
    parts.len() == 4
        && parts
            .iter()
            .all(|p| p.parse::<u8>().is_ok() && (p.len() == 1 || !p.starts_with('0')))
}

/// Public DNS resolvers: look like version tuples but are real addresses.
const PUBLIC_RESOLVERS: &[&str] = &[
    "1.1.1.1", "1.0.0.1", "1.1.1.2", "1.0.0.2", "1.1.1.3", "1.0.0.3", "8.8.8.8", "8.8.4.4",
    "9.9.9.9",
];

/// True when a dotted-quad should NOT be flagged as a hardcoded server IP.
///
/// Besides loopback/RFC-1918, this rejects reserved and non-routable ranges
/// that real backends never use but which the bare-IP regex matches against
/// string noise — e.g. OID fragments (`1.3.101.112`), version tuples
/// (`0.1.2.17`), and link-local addresses. A public backend address still
/// returns false and is reported.
fn is_benign_ip(ip: &str) -> bool {
    let octets: Vec<u8> = ip.split('.').filter_map(|p| p.parse::<u8>().ok()).collect();
    if octets.len() != 4 {
        // Not a well-formed IPv4 literal — don't flag.
        return true;
    }
    let (a, b) = (octets[0], octets[1]);
    // X.509 / SNMP OID arcs (`2.5.29.14`, `1.3.101.112`, `1.2.840.x`).
    if matches!((a, b), (1, 2) | (1, 3) | (2, 5) | (2, 16)) {
        return true;
    }
    // Version tuples (`3.1.1.10`, `2.6.29.4`): tiny first octet, all small.
    if a <= 9 && octets.iter().all(|&o| o <= 30) && !PUBLIC_RESOLVERS.contains(&ip) {
        return true;
    }
    // x.x.x.0 is a network address (`1.24.4.0`, `134.0.0.0`), not a host.
    if octets[3] == 0 {
        return true;
    }
    match a {
        // 0.0.0.0/8 "this network" — never a real host. Catches version
        // tuples and OID prefixes like 0.1.2.17.
        0 => true,
        // 10.0.0.0/8 (RFC 1918 private)
        10 => true,
        // 127.0.0.0/8 loopback
        127 => true,
        // 169.254.0.0/16 link-local
        169 if b == 254 => true,
        // 172.16.0.0/12 (RFC 1918 private)
        172 if (16..=31).contains(&b) => true,
        // 192.168.0.0/16 (RFC 1918 private)
        192 if b == 168 => true,
        // 224.0.0.0/4 multicast, 240.0.0.0/4 reserved, 255.x broadcast.
        224..=255 => true,
        _ => false,
    }
}

/// True if `data` begins with a Mach-O thin or universal (fat) binary magic
/// number. Used to opt binary executables and frameworks into string-based
/// email extraction even though they have no text-like file extension.
fn is_macho(data: &[u8]) -> bool {
    if data.len() < 4 {
        return false;
    }
    matches!(
        [data[0], data[1], data[2], data[3]],
        [0xfe, 0xed, 0xfa, 0xce]   // MH_MAGIC (32-bit)
            | [0xce, 0xfa, 0xed, 0xfe]   // MH_CIGAM (32-bit, swapped)
            | [0xfe, 0xed, 0xfa, 0xcf]   // MH_MAGIC_64
            | [0xcf, 0xfa, 0xed, 0xfe]   // MH_CIGAM_64 (swapped)
            | [0xca, 0xfe, 0xba, 0xbe]   // FAT_MAGIC (universal)
            | [0xbe, 0xba, 0xfe, 0xca] // FAT_CIGAM (universal, swapped)
    )
}

/// Files whose URLs are endpoints the app may contact: its Mach-O binaries,
/// config files, and JS app code (React Native `.jsbundle`, Cordova `www/`,
/// Capacitor `public/`). Other bundled JS/HTML is usually a library.
fn is_endpoint_source(path: &str, is_binary: bool) -> bool {
    let lower = path.to_lowercase();
    is_binary
        || is_config_like(path)
        || lower.ends_with(".jsbundle")
        || ((lower.ends_with(".js") || lower.ends_with(".html"))
            && (lower.contains(".app/www/") || lower.contains(".app/public/")))
}

/// Configuration-style files where a high-entropy token is plausibly a credential.
fn is_config_like(path: &str) -> bool {
    const CONFIG_EXTENSIONS: &[&str] = &[
        ".plist",
        ".json",
        ".xml",
        ".yaml",
        ".yml",
        ".txt",
        ".strings",
        ".env",
        ".cfg",
        ".conf",
        ".config",
        ".ini",
        ".properties",
    ];
    let lower = path.to_lowercase();
    CONFIG_EXTENSIONS.iter().any(|e| lower.ends_with(e))
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

#[cfg(test)]
mod tests {
    use super::*;

    fn finding(id: &str, owasp: &str, evidence: &str) -> Finding {
        Finding {
            id: id.to_string(),
            title: "t".to_string(),
            description: "d".to_string(),
            severity: Severity::High,
            category: "secrets".to_string(),
            cwe: None,
            owasp_mobile: Some(owasp.to_string()),
            owasp_masvs: None,
            evidence: vec![evidence.to_string()],
            remediation: None,
        }
    }

    #[test]
    fn test_is_macho_magics() {
        // 64-bit thin Mach-O and universal/fat headers are recognized.
        assert!(is_macho(&[0xcf, 0xfa, 0xed, 0xfe, 0x00]));
        assert!(is_macho(&[0xfe, 0xed, 0xfa, 0xce]));
        assert!(is_macho(&[0xca, 0xfe, 0xba, 0xbe, 0x00, 0x00]));
        // Non-Mach-O / too short are rejected.
        assert!(!is_macho(b"PK\x03\x04")); // zip
        assert!(!is_macho(b"<?xml"));
        assert!(!is_macho(&[0xfe, 0xed]));
        assert!(!is_macho(&[]));
    }

    #[test]
    fn test_is_benign_ip_rejects_reserved() {
        // Reserved / non-routable — must be treated as benign (not flagged).
        for ip in [
            "0.1.2.17",        // 0.0.0.0/8 — OID/version-tuple noise
            "1.3.101.112",     // OID arc 1.3
            "2.5.29.14",       // OID arc 2.5 (X.509 extensions)
            "3.1.1.10",        // version tuple
            "1.24.4.0",        // network address
            "127.0.0.2",       // loopback /8
            "169.254.1.1",     // link-local
            "10.0.0.5",        // RFC1918
            "172.16.0.1",      // RFC1918
            "192.168.1.1",     // RFC1918
            "224.0.0.1",       // multicast
            "255.255.255.255", // broadcast
        ] {
            assert!(is_benign_ip(ip), "{ip} should be benign/non-routable");
        }
        // A real public backend IP is still flagged (not benign).
        assert!(!is_benign_ip("13.107.42.14"));
        assert!(!is_benign_ip("8.8.8.8"));
        assert!(!is_benign_ip("1.1.1.1"));
        assert!(!is_benign_ip("149.154.167.50"));
        assert!(!is_ip_literal("1.00.02.28"));
        assert!(!is_ip_literal("4.091.008.004"));
    }

    #[test]
    fn test_bare_ips_need_context() {
        let text = "149.154.167.50\n\
                    Version 5.4.1.22 build\n\
                    proxy_host=51.15.20.19\n\
                    1.2.3.4 build 5.6.7.8 notes\n\
                    185.76.9.1:443";
        assert_eq!(
            scan_for_bare_ips(text),
            vec![
                "1.2.3.4",
                "149.154.167.50",
                "185.76.9.1",
                "5.6.7.8",
                "51.15.20.19"
            ]
        );
    }

    #[test]
    fn test_dedup_keeps_secure_separate_from_high() {
        // A SECURE "present" finding must never merge into a HIGH "absent" group
        // of the same rule id — that produced a HIGH titled "Not Found" whose
        // evidence said "present".
        let mut secure = finding("QS-BIN-002", "M7", "___stack_chk_fail present in App");
        secure.severity = Severity::Secure;
        secure.title = "Stack Canary Protection Present".to_string();
        let mut high = finding("QS-BIN-002", "M7", "___stack_chk_fail absent in Foo.dylib");
        high.title = "Stack Canary Not Found".to_string();

        let deduped = deduplicate_findings(vec![secure, high]);
        assert_eq!(deduped.len(), 2, "secure and high must stay separate");
        let secure_f = deduped
            .iter()
            .find(|f| f.severity == Severity::Secure)
            .expect("secure finding present");
        assert!(secure_f.evidence.iter().all(|e| e.contains("present")));
        let high_f = deduped
            .iter()
            .find(|f| f.severity == Severity::High)
            .expect("high finding present");
        assert!(high_f.evidence.iter().all(|e| e.contains("absent")));
    }

    #[test]
    fn test_cert_findings_stay_per_file() {
        // Two embedded cert files must remain two separate hotspots, not be
        // collapsed into a single merged QS-CERT-001 finding.
        let findings = vec![
            finding("QS-CERT-001", "M9", ".der file: Payload/A.app/a.der"),
            finding("QS-CERT-001", "M9", ".p12 file: Payload/A.app/b.p12"),
        ];
        let deduped = deduplicate_findings(findings);
        assert_eq!(deduped.len(), 2);
        assert!(deduped.iter().all(|f| f.id == "QS-CERT-001"));
        // Descriptions are not rewritten with an "(N instances detected)" suffix.
        assert!(deduped.iter().all(|f| !f.description.contains("instances")));
    }

    #[test]
    fn test_non_per_instance_findings_still_merge() {
        let findings = vec![
            finding("QS-NET-003", "M5", "http://a.com"),
            finding("QS-NET-003", "M5", "http://b.com"),
        ];
        let deduped = deduplicate_findings(findings);
        assert_eq!(deduped.len(), 1);
        assert!(deduped[0].description.contains("instances"));
    }

    #[test]
    fn test_owasp_summary_dedups_shared_ruleids() {
        // Repeated per-instance ruleIds appear only once per OWASP category.
        let findings = vec![
            finding("QS-CERT-001", "M9", "a"),
            finding("QS-CERT-001", "M9", "b"),
        ];
        let summary = compute_owasp_summary(&findings, &[], &Severity::Info);
        assert_eq!(summary["M9"], vec!["QS-CERT-001".to_string()]);
    }
}
