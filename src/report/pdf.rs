//! PDF report generation.
//!
//! The PDF is a brief, human-oriented summary — not a dump of the scan. It has
//! its own template (`templates/report.pdf.tera`) in the Pavise design system
//! (cream / navy / mint, Bricolage Grotesque, DM Sans, JetBrains Mono — fonts
//! embedded from `assets/fonts/`, so rendering never touches the network).
//!
//! Everything the template shows is pre-shaped here into a small view model:
//! findings are grouped by rule, evidence is capped, and every untrusted
//! string is cleaned and length-bounded so long names/paths cannot break the
//! layout. Headless Chrome then prints the HTML to A4. It needs a
//! Chrome/Chromium binary on the host (`$CHROME` overrides auto-detection).

use std::collections::{BTreeMap, HashMap};
use std::sync::OnceLock;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use base64::Engine;
use headless_chrome::types::PrintToPdfOptions;
use headless_chrome::{Browser, LaunchOptions};
use serde::Serialize;
use tera::{Context as TeraContext, Tera};

use crate::types::{Finding, ScanReport, SecretMatch, Severity};

const TEMPLATE: &str = include_str!("../../templates/report.pdf.tera");
const FONT_DISPLAY: &[u8] = include_bytes!("../../assets/fonts/bricolage-grotesque.woff2");
const FONT_BODY: &[u8] = include_bytes!("../../assets/fonts/dm-sans.woff2");
const FONT_MONO: &[u8] = include_bytes!("../../assets/fonts/jetbrains-mono.woff2");

// A4 in inches — a fallback only; the template's `@page` rule wins.
const A4_WIDTH_IN: f64 = 8.27;
const A4_HEIGHT_IN: f64 = 11.69;

/// Default render budget for `to_bytes`.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(60);

// Brevity limits: the PDF summarises, JSON/HTML carry the full data.
const MAX_PRIORITY_ROWS: usize = 8;
const MAX_DETAIL_CARDS: usize = 25;
const MAX_INFO_ROWS: usize = 20;
const MAX_EVIDENCE: usize = 4;
const MAX_TRACKERS: usize = 16;

// Character limits for untrusted strings.
const LEN_APP_NAME: usize = 80;
const LEN_IDENT: usize = 96;
const LEN_SHORT: usize = 40;
const LEN_TITLE: usize = 120;
const LEN_PARAGRAPH: usize = 420;
const LEN_EVIDENCE: usize = 150;
const LEN_PATH: usize = 64;
const LEN_PREVIEW: usize = 110;

const OWASP_LABELS: [(&str, &str); 10] = [
    ("M1", "Credential Usage"),
    ("M2", "Supply Chain"),
    ("M3", "Auth / Authorization"),
    ("M4", "Input / Output Validation"),
    ("M5", "Insecure Communication"),
    ("M6", "Privacy Controls"),
    ("M7", "Binary Protections"),
    ("M8", "Misconfiguration"),
    ("M9", "Data Storage"),
    ("M10", "Cryptography"),
];

/// Compile a `ScanReport` to a PDF and return the raw bytes.
pub fn to_bytes(report: &ScanReport) -> Result<Vec<u8>> {
    to_bytes_with_timeout(report, DEFAULT_TIMEOUT)
}

/// Like `to_bytes`, but every Chrome call is bounded by what is left of
/// `timeout`, so the function itself returns — and Chrome is killed when the
/// `Browser` drops — within roughly that budget. A caller-side timeout alone
/// would abandon the thread and leave Chrome running.
pub fn to_bytes_with_timeout(report: &ScanReport, timeout: Duration) -> Result<Vec<u8>> {
    let deadline = Instant::now() + timeout;
    let remaining = || {
        deadline
            .checked_duration_since(Instant::now())
            .filter(|d| !d.is_zero())
            .context("PDF generation timed out")
    };

    let html = render_html(report)?;

    // Chrome loads the document from disk via a file:// URL. A temp dir keeps
    // the file isolated and auto-removed when it drops.
    let tmp = tempfile::tempdir().context("Failed to create temp directory")?;
    let html_path = tmp.path().join("report.html");
    std::fs::write(&html_path, html.as_bytes()).context("Failed to write temp HTML for PDF")?;
    let url = format!("file://{}", html_path.display());

    let options = LaunchOptions::default_builder()
        .headless(true)
        // Disable the sandbox so generation also works as root / in containers
        // (common on servers); the page is our own template with escaped data.
        .sandbox(false)
        .idle_browser_timeout(timeout)
        .build()
        .context("Failed to build Chrome launch options")?;

    let browser = Browser::new(options).context(
        "Failed to launch headless Chrome for PDF generation. \
         A Chrome or Chromium binary must be installed on the host.",
    )?;

    let tab = browser.new_tab().context("Failed to open a browser tab")?;
    tab.set_default_timeout(remaining()?);
    tab.navigate_to(&url)
        .context("Failed to load the report into the browser")?;
    tab.set_default_timeout(remaining()?);
    tab.wait_until_navigated()
        .context("Report page did not finish loading")?;
    // Embedded fonts decode asynchronously; printing before they are ready
    // would fall back to system fonts.
    tab.set_default_timeout(remaining()?);
    tab.evaluate("document.fonts.ready.then(() => true)", true)
        .context("Report fonts did not finish loading")?;

    tab.set_default_timeout(remaining()?);
    let pdf = tab
        .print_to_pdf(Some(pdf_options()))
        .context("Chrome failed to print the report to PDF")?;

    Ok(pdf)
}

/// Render the print-ready HTML that Chrome turns into the PDF.
pub fn render_html(report: &ScanReport) -> Result<String> {
    let mut tera = Tera::default();
    // The `.html` suffix turns on Tera's autoescaping — every value in the
    // view model comes from the scanned app and must be treated as untrusted.
    tera.add_raw_template("report.pdf.html", TEMPLATE)
        .context("Failed to load PDF report template")?;

    let mut ctx = TeraContext::new();
    ctx.insert("r", &build_view(report));
    ctx.insert("fonts_css", fonts_css());
    ctx.insert("footer_css", &footer_css(report));
    tera.render("report.pdf.html", &ctx)
        .context("Failed to render PDF report template")
}

// ─── View model ──────────────────────────────────────────────────────────────

#[derive(Serialize)]
struct View {
    version: &'static str,
    generated: String,
    app: AppView,
    grade: String,
    grade_class: &'static str,
    score: u8,
    counts: Counts,
    verdict: String,
    verdict_detail: String,
    diff: Option<DiffView>,
    priority: Vec<Group>,
    priority_more: usize,
    details: Vec<Group>,
    details_more: usize,
    info: Vec<InfoRow>,
    info_more: usize,
    binary: Option<BinaryView>,
    owasp: Vec<OwaspCell>,
    trackers: Vec<TrackerView>,
    trackers_more: usize,
    facts: Vec<Fact>,
}

#[derive(Serialize)]
struct AppView {
    name: String,
    /// Long names get a smaller masthead size.
    long_name: bool,
    identifier: String,
    /// "v1.2 (build 34) · iOS 13.0+ · iphoneos17.2"
    meta: String,
}

#[derive(Serialize)]
struct Counts {
    high: usize,
    warning: usize,
    info: usize,
    secrets: usize,
    trackers: usize,
}

#[derive(Serialize)]
struct DiffView {
    score_delta: i16,
    new_findings: usize,
    fixed_findings: usize,
    new_secrets: usize,
    fixed_secrets: usize,
}

/// One rule's findings (or one secret rule's matches) rolled into a card.
#[derive(Serialize)]
struct Group {
    sev: &'static str,
    sev_label: &'static str,
    id: String,
    title: String,
    count: usize,
    /// "network · CWE-319 · M5 · MASVS-NETWORK-1"
    tags: String,
    description: Option<String>,
    remediation: Option<String>,
    evidence: Vec<String>,
    evidence_more: usize,
    /// All evidence items are short tokens (symbols, keys): render on one line.
    evidence_inline: bool,
    /// One-line evidence summary for compact rows.
    preview: String,
}

#[derive(Serialize)]
struct InfoRow {
    id: String,
    title: String,
    count: usize,
    preview: String,
}

#[derive(Serialize)]
struct BinaryView {
    path: String,
    arch: String,
    checks: Vec<Check>,
    failed: usize,
}

#[derive(Serialize)]
struct Check {
    name: String,
    /// "ok" | "fail" | "warn"
    state: &'static str,
}

#[derive(Serialize)]
struct OwaspCell {
    code: &'static str,
    label: &'static str,
    count: usize,
    /// Worst severity mapped here: "high" | "warn" | "info" | "none".
    worst: &'static str,
}

#[derive(Serialize)]
struct TrackerView {
    name: String,
    categories: String,
}

#[derive(Serialize)]
struct Fact {
    label: &'static str,
    value: String,
    mono: bool,
}

fn build_view(r: &ScanReport) -> View {
    let (high, warning, info) = severity_counts(r);
    let counts = Counts {
        high,
        warning,
        info,
        secrets: r.secrets.len(),
        trackers: r.trackers.len(),
    };

    let mut actionable: Vec<Group> = group_findings(
        r.findings
            .iter()
            .filter(|f| matches!(f.severity, Severity::High | Severity::Warning)),
    );
    actionable.extend(group_secrets(&r.secrets));
    actionable.sort_by_key(|g| g.sev_rank());
    let info_groups = group_findings(r.findings.iter().filter(|f| f.severity == Severity::Info));

    let (verdict, verdict_detail) = verdict(&counts, info_groups.len());

    let priority_more = actionable.len().saturating_sub(MAX_PRIORITY_ROWS);
    let details_more = actionable.len().saturating_sub(MAX_DETAIL_CARDS);
    let priority = actionable
        .iter()
        .take(MAX_PRIORITY_ROWS)
        .map(Group::summary_row)
        .collect();
    let details: Vec<Group> = actionable.into_iter().take(MAX_DETAIL_CARDS).collect();

    let info_more = info_groups.len().saturating_sub(MAX_INFO_ROWS);
    let info = info_groups
        .into_iter()
        .take(MAX_INFO_ROWS)
        .map(|g| InfoRow {
            id: g.id,
            title: g.title,
            count: g.count,
            preview: g.preview,
        })
        .collect();

    let trackers_more = r.trackers.len().saturating_sub(MAX_TRACKERS);
    let trackers = r
        .trackers
        .iter()
        .take(MAX_TRACKERS)
        .map(|t| TrackerView {
            name: clip(&t.name, LEN_SHORT),
            categories: clip(&t.categories.join(", "), LEN_SHORT),
        })
        .collect();

    View {
        version: env!("CARGO_PKG_VERSION"),
        generated: utc_date(SystemTime::now()),
        app: app_view(r),
        grade: clip(&r.grade, 2),
        grade_class: grade_class(&r.grade),
        score: r.security_score,
        counts,
        verdict,
        verdict_detail,
        diff: r.baseline_diff.as_ref().map(|d| DiffView {
            score_delta: d.score_delta,
            new_findings: d.new_findings.len(),
            fixed_findings: d.fixed_findings.len(),
            new_secrets: d.new_secrets,
            fixed_secrets: d.fixed_secrets,
        }),
        priority,
        priority_more,
        details,
        details_more,
        info,
        info_more,
        binary: binary_view(r),
        owasp: owasp_cells(r),
        trackers,
        trackers_more,
        facts: facts(r),
    }
}

/// Severity totals across findings and secrets (matches the HTML report).
fn severity_counts(r: &ScanReport) -> (usize, usize, usize) {
    let sevs = r
        .findings
        .iter()
        .map(|f| &f.severity)
        .chain(r.secrets.iter().map(|s| &s.severity));
    let (mut high, mut warning, mut info) = (0, 0, 0);
    for s in sevs {
        match s {
            Severity::High => high += 1,
            Severity::Warning => warning += 1,
            Severity::Info => info += 1,
            Severity::Secure => {}
        }
    }
    (high, warning, info)
}

fn verdict(c: &Counts, info_groups: usize) -> (String, String) {
    let headline = match (c.high, c.warning) {
        (0, 0) => "No high or warning-level issues found.".to_string(),
        (0, w) => format!(
            "No high-severity issues. {} worth reviewing.",
            plural(w, "warning", "warnings")
        ),
        (h, _) => format!(
            "{} should be fixed before release.",
            plural(h, "high-severity issue", "high-severity issues")
        ),
    };
    let mut detail = Vec::new();
    if c.high > 0 && c.warning > 0 {
        detail.push(format!(
            "{} also worth reviewing.",
            plural(c.warning, "warning is", "warnings are")
        ));
    }
    if info_groups > 0 {
        detail.push(format!(
            "{} listed at the end for context.",
            plural(
                info_groups,
                "informational observation is",
                "informational observations are"
            )
        ));
    }
    (headline, detail.join(" "))
}

fn plural(n: usize, one: &str, many: &str) -> String {
    format!("{n} {}", if n == 1 { one } else { many })
}

fn app_view(r: &ScanReport) -> AppView {
    let a = &r.app_info;
    let name = if a.name.trim().is_empty() {
        "Unnamed app".to_string()
    } else {
        clip(&a.name, LEN_APP_NAME)
    };
    let mut meta = Vec::new();
    if !a.version.trim().is_empty() {
        let mut v = format!("v{}", version_label(&a.version));
        if !a.build.trim().is_empty() && a.build != a.version {
            v.push_str(&format!(" (build {})", clip(&a.build, LEN_SHORT)));
        }
        meta.push(v);
    }
    if !a.min_os_version.trim().is_empty() {
        meta.push(format!("iOS {}+", clip(&a.min_os_version, LEN_SHORT)));
    }
    if !a.sdk_name.trim().is_empty() {
        meta.push(clip(&a.sdk_name, LEN_SHORT));
    }
    AppView {
        long_name: name.chars().count() > 34,
        name,
        identifier: clip(&a.identifier, LEN_IDENT),
        meta: meta.join(" · "),
    }
}

impl Group {
    fn sev_rank(&self) -> u8 {
        match self.sev {
            "high" => 0,
            "warn" => 1,
            _ => 2,
        }
    }

    /// A lightweight copy for the page-one priority list.
    fn summary_row(&self) -> Group {
        Group {
            sev: self.sev,
            sev_label: self.sev_label,
            id: self.id.clone(),
            title: self.title.clone(),
            count: self.count,
            tags: String::new(),
            description: None,
            remediation: None,
            evidence: Vec::new(),
            evidence_more: 0,
            evidence_inline: false,
            preview: self.preview.clone(),
        }
    }
}

fn sev_key(s: &Severity) -> (&'static str, &'static str) {
    match s {
        Severity::High => ("high", "High"),
        Severity::Warning => ("warn", "Warning"),
        Severity::Info => ("info", "Info"),
        Severity::Secure => ("secure", "Secure"),
    }
}

/// Roll findings sharing a rule ID and severity into one group, keeping the
/// order of first appearance (callers sort by severity afterwards).
fn group_findings<'a>(findings: impl Iterator<Item = &'a Finding>) -> Vec<Group> {
    let mut order: Vec<(&str, &Severity)> = Vec::new();
    let mut buckets: BTreeMap<(&str, &Severity), Vec<&Finding>> = BTreeMap::new();
    for f in findings {
        let key = (f.id.as_str(), &f.severity);
        buckets
            .entry(key)
            .or_insert_with(|| {
                order.push(key);
                Vec::new()
            })
            .push(f);
    }

    order
        .into_iter()
        .map(|key| {
            let items = &buckets[&key];
            let first = items[0];
            let (sev, sev_label) = sev_key(&first.severity);
            let titles: Vec<&str> = items.iter().map(|f| f.title.as_str()).collect();
            let evidence: Vec<&str> = dedup(items.iter().flat_map(|f| f.evidence.iter()));
            let tags = [
                Some(first.category.as_str()),
                first.cwe.as_deref(),
                first.owasp_mobile.as_deref(),
                first.owasp_masvs.as_deref(),
            ];
            Group {
                sev,
                sev_label,
                id: clip(&first.id, LEN_SHORT),
                title: clip(&group_title(&titles), LEN_TITLE),
                count: items.len(),
                tags: join_tags(&tags),
                description: shared(items.iter().map(|f| Some(f.description.as_str())))
                    .map(|d| clip(d, LEN_PARAGRAPH)),
                remediation: shared(items.iter().map(|f| f.remediation.as_deref()))
                    .map(|d| clip(d, LEN_PARAGRAPH)),
                evidence: evidence
                    .iter()
                    .take(MAX_EVIDENCE)
                    .map(|e| clip_middle(e, LEN_EVIDENCE))
                    .collect(),
                evidence_more: evidence.len().saturating_sub(MAX_EVIDENCE),
                evidence_inline: evidence
                    .iter()
                    .take(MAX_EVIDENCE)
                    .all(|e| e.chars().count() <= 36),
                preview: preview(&evidence),
            }
        })
        .collect()
}

/// Secrets are grouped per rule; values are masked since PDFs get forwarded.
fn group_secrets(secrets: &[SecretMatch]) -> Vec<Group> {
    let mut by_rule: BTreeMap<(&Severity, &str), Vec<&SecretMatch>> = BTreeMap::new();
    for s in secrets {
        by_rule
            .entry((&s.severity, s.rule_id.as_str()))
            .or_default()
            .push(s);
    }
    by_rule
        .into_values()
        .map(|items| {
            let first = items[0];
            let (sev, sev_label) = sev_key(&first.severity);
            let lines: Vec<String> = items
                .iter()
                .map(|s| match &s.file_path {
                    Some(p) => format!(
                        "{}  in  {}",
                        mask(&s.matched_value),
                        clip_middle(p, LEN_PATH)
                    ),
                    None => mask(&s.matched_value),
                })
                .collect();
            let tags = [
                Some("secret"),
                first.cwe.as_deref(),
                first.owasp_mobile.as_deref(),
                first.owasp_masvs.as_deref(),
            ];
            let refs: Vec<&str> = lines.iter().map(String::as_str).collect();
            Group {
                sev,
                sev_label,
                id: clip(&first.rule_id, LEN_SHORT),
                title: clip(&first.title, LEN_TITLE),
                count: items.len(),
                tags: join_tags(&tags),
                description: Some(format!(
                    "{} hardcoded in the app bundle. Anyone who downloads the app can extract {}.",
                    plural(
                        items.len(),
                        "value matching this pattern is",
                        "values matching this pattern are"
                    ),
                    if items.len() == 1 { "it" } else { "them" },
                )),
                remediation: first.remediation.as_deref().map(|d| clip(d, LEN_PARAGRAPH)),
                evidence: lines.iter().take(MAX_EVIDENCE).cloned().collect(),
                evidence_more: lines.len().saturating_sub(MAX_EVIDENCE),
                evidence_inline: false,
                preview: clip(&refs.join(", "), LEN_PREVIEW),
            }
        })
        .collect()
}

/// For a group, "Custom URL Scheme Registered: 'rtsp'" + "…: 'mms'" becomes
/// "Custom URL Scheme Registered" — the per-instance part moves to evidence.
fn group_title(titles: &[&str]) -> String {
    if titles.len() > 1 {
        let heads: Vec<&str> = titles
            .iter()
            .map(|t| t.split_once(": ").map_or(*t, |(h, _)| h))
            .collect();
        if heads.iter().all(|h| *h == heads[0]) {
            return heads[0].to_string();
        }
    }
    titles[0].to_string()
}

/// The value every item shares, or `None` if they differ or are all empty.
fn shared<'a>(mut values: impl Iterator<Item = Option<&'a str>>) -> Option<&'a str> {
    let first = values.next()??;
    if first.trim().is_empty() {
        return None;
    }
    values.all(|v| v == Some(first)).then_some(first)
}

fn dedup<'a>(items: impl Iterator<Item = &'a String>) -> Vec<&'a str> {
    let mut out: Vec<&str> = Vec::new();
    for s in items {
        if !s.trim().is_empty() && !out.contains(&s.as_str()) {
            out.push(s);
        }
    }
    out
}

/// One-line evidence summary. When every item is "Key: value" with the same
/// key, show "Key: v1, v2, …" rather than repeating the key.
fn preview(evidence: &[&str]) -> String {
    let Some(first) = evidence.first() else {
        return String::new();
    };
    let key = first.split_once(": ").map(|(k, _)| k);
    let joined = match key {
        Some(k)
            if evidence.len() > 1 && evidence.iter().all(|e| e.starts_with(&format!("{k}: "))) =>
        {
            let vals: Vec<&str> = evidence.iter().map(|e| &e[k.len() + 2..]).collect();
            format!("{k}: {}", vals.join(", "))
        }
        _ => evidence.join(", "),
    };
    clip(&joined, LEN_PREVIEW)
}

fn join_tags(tags: &[Option<&str>]) -> String {
    tags.iter()
        .flatten()
        .filter(|t| !t.trim().is_empty())
        .map(|t| clip(t, LEN_SHORT))
        .collect::<Vec<_>>()
        .join(" · ")
}

fn binary_view(r: &ScanReport) -> Option<BinaryView> {
    let b = r.main_binary.as_ref()?;
    let checks: Vec<Check> = b
        .protections
        .iter()
        .map(|p| Check {
            name: clip(&p.name, LEN_SHORT),
            state: match (p.enabled, &p.severity) {
                (true, _) => "ok",
                (false, Severity::High) => "fail",
                (false, _) => "warn",
            },
        })
        .collect();
    Some(BinaryView {
        path: clip_middle(&b.path, LEN_PATH),
        arch: clip(&format!("{} · {}-bit", b.arch, b.bits), LEN_SHORT),
        failed: checks.iter().filter(|c| c.state != "ok").count(),
        checks,
    })
}

fn owasp_cells(r: &ScanReport) -> Vec<OwaspCell> {
    let mut worst_by_id: HashMap<&str, &Severity> = HashMap::new();
    let all = r
        .findings
        .iter()
        .map(|f| (f.id.as_str(), &f.severity))
        .chain(r.secrets.iter().map(|s| (s.rule_id.as_str(), &s.severity)));
    for (id, sev) in all {
        let e = worst_by_id.entry(id).or_insert(sev);
        if sev < *e {
            *e = sev;
        }
    }

    OWASP_LABELS
        .iter()
        .map(|&(code, label)| {
            let ids = r.owasp_summary.get(code).map(Vec::as_slice).unwrap_or(&[]);
            let mut unique: Vec<&str> = ids.iter().map(String::as_str).collect();
            unique.sort_unstable();
            unique.dedup();
            let worst = unique
                .iter()
                .filter_map(|id| worst_by_id.get(id).copied())
                .min();
            OwaspCell {
                code,
                label,
                count: unique.len(),
                worst: match worst {
                    Some(Severity::High) => "high",
                    Some(Severity::Warning) => "warn",
                    Some(Severity::Info) => "info",
                    _ => "none",
                },
            }
        })
        .collect()
}

fn facts(r: &ScanReport) -> Vec<Fact> {
    let h = &r.file_hashes;
    let mut out = vec![
        Fact {
            label: "SHA-256",
            value: clip(&h.sha256, 64),
            mono: true,
        },
        Fact {
            label: "File size",
            value: human_size(h.size_bytes),
            mono: false,
        },
        Fact {
            label: "Binaries analysed",
            value: format!(
                "{} main · {} frameworks · {} extensions",
                usize::from(r.main_binary.is_some()),
                r.framework_binaries.len(),
                r.extension_binaries.len()
            ),
            mono: false,
        },
        Fact {
            label: "Extracted",
            value: format!(
                "{} · {} · {}",
                plural(r.domains.len(), "domain", "domains"),
                plural(r.emails.len(), "email address", "email addresses"),
                plural(
                    r.framework_components.len(),
                    "versioned component",
                    "versioned components"
                ),
            ),
            mono: false,
        },
    ];
    if let Some(p) = &r.provisioning {
        out.push(Fact {
            label: "Provisioning",
            value: clip(
                &match &p.expiration_date {
                    Some(exp) => format!("{} · expires {exp}", p.profile_type),
                    None => p.profile_type.clone(),
                },
                LEN_SHORT * 2,
            ),
            mono: false,
        });
    }
    out.push(Fact {
        label: "Scan",
        value: format!(
            "{} ms · Pavise {}",
            r.scan_duration_ms,
            env!("CARGO_PKG_VERSION")
        ),
        mono: false,
    });
    out
}

/// Version without a leading "v" (the templates add their own), clipped.
fn version_label(v: &str) -> String {
    let v = v.trim();
    let v = v.strip_prefix(['v', 'V']).unwrap_or(v);
    clip(v, 20)
}

fn grade_class(grade: &str) -> &'static str {
    match grade.chars().next().map(|c| c.to_ascii_uppercase()) {
        Some('A') => "a",
        Some('B') => "b",
        Some('C') => "c",
        Some('D') => "d",
        _ => "f",
    }
}

// ─── String hygiene ──────────────────────────────────────────────────────────

/// Normalise an untrusted string for display: control and bidi-override
/// characters are dropped, whitespace runs collapse to one space.
fn clean(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut space = false;
    for c in s.chars() {
        if c.is_whitespace() {
            space = !out.is_empty();
            continue;
        }
        if c.is_control()
            || matches!(c, '\u{200B}'..='\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}' | '\u{FEFF}')
        {
            continue;
        }
        if space {
            out.push(' ');
            space = false;
        }
        out.push(c);
    }
    out
}

/// Clean and cut to at most `max` characters, ending with "…" if cut
/// (preferring a word boundary when one is close).
fn clip(s: &str, max: usize) -> String {
    let s = clean(s);
    if s.chars().count() <= max {
        return s;
    }
    let cut: String = s.chars().take(max.saturating_sub(1)).collect();
    let cut = match cut.rfind(' ') {
        Some(i) if cut[..i].chars().count() * 5 >= max * 4 => &cut[..i],
        _ => cut.as_str(),
    };
    format!("{}…", cut.trim_end_matches([' ', ',', '.', ';', ':']))
}

/// Clean and cut from the middle, keeping the tail (file names live there).
fn clip_middle(s: &str, max: usize) -> String {
    let s = clean(s);
    let chars: Vec<char> = s.chars().collect();
    if chars.len() <= max {
        return s;
    }
    let tail = (max - 1) * 3 / 5;
    let head = max - 1 - tail;
    let mut out: String = chars[..head].iter().collect();
    out.push('…');
    out.extend(&chars[chars.len() - tail..]);
    out
}

/// Keep enough of a secret to recognise it, never enough to use it.
fn mask(value: &str) -> String {
    let chars: Vec<char> = clean(value).chars().collect();
    let n = chars.len();
    let (head, tail) = match n {
        0..=8 => (n.min(2), 0),
        9..=20 => (3, 2),
        _ => (6, 4),
    };
    let mut out: String = chars[..head].iter().collect();
    out.push_str("••••••");
    out.extend(&chars[n - tail..]);
    out
}

fn human_size(bytes: u64) -> String {
    const MB: f64 = 1024.0 * 1024.0;
    if bytes as f64 >= MB {
        format!("{:.1} MB", bytes as f64 / MB)
    } else {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    }
}

/// `YYYY-MM-DD` (UTC) without pulling in a date crate.
fn utc_date(t: SystemTime) -> String {
    let days = t
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() / 86_400) as i64;
    // Howard Hinnant's civil_from_days.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!("{year:04}-{month:02}-{day:02}")
}

fn fonts_css() -> &'static str {
    static CSS: OnceLock<String> = OnceLock::new();
    CSS.get_or_init(|| {
        let b64 = |b: &[u8]| base64::engine::general_purpose::STANDARD.encode(b);
        [
            ("Bricolage Grotesque", "600 800", FONT_DISPLAY),
            ("DM Sans", "400 700", FONT_BODY),
            ("JetBrains Mono", "400 600", FONT_MONO),
        ]
        .iter()
        .map(|(family, weight, data)| {
            format!(
                "@font-face{{font-family:'{family}';font-weight:{weight};font-style:normal;\
                 src:url(data:font/woff2;base64,{}) format('woff2')}}",
                b64(data)
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
    })
}

// ─── Chrome print settings ───────────────────────────────────────────────────

fn pdf_options() -> PrintToPdfOptions {
    // Page size, margins, background and the running footer all come from the
    // template's `@page` rules (margin boxes), so the page reads as full-bleed
    // cream and the footer uses the embedded fonts.
    PrintToPdfOptions {
        landscape: Some(false),
        display_header_footer: Some(false),
        print_background: Some(true),
        scale: Some(1.0),
        paper_width: Some(A4_WIDTH_IN),
        paper_height: Some(A4_HEIGHT_IN),
        margin_top: Some(0.0),
        margin_bottom: Some(0.0),
        margin_left: Some(0.0),
        margin_right: Some(0.0),
        prefer_css_page_size: Some(true),
        ..Default::default()
    }
}

/// The running footer's left text, as a CSS string literal.
fn footer_css(r: &ScanReport) -> String {
    let name = match clip(&r.app_info.name, 48) {
        n if n.is_empty() => "Unnamed app".to_string(),
        n => n,
    };
    let mut text = format!("Pavise  /  {name}");
    let ver = version_label(&r.app_info.version);
    if !ver.is_empty() {
        text.push_str(&format!(" v{ver}"));
    }
    text.push_str(&format!("  /  Grade {}", clip(&r.grade, 2)));
    css_string(&text)
}

/// Quote an untrusted string as a CSS string literal for the `@page` footer.
/// Everything outside a small safe set is hex-escaped, so it can neither end
/// the string nor the enclosing `<style>` element.
fn css_string(s: &str) -> String {
    let mut out = String::from("\"");
    for c in s.chars() {
        if c.is_ascii_alphanumeric() || matches!(c, ' ' | '.' | '-' | '_' | ',' | '(' | ')') {
            out.push(c);
        } else {
            out.push_str(&format!("\\{:x} ", c as u32));
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clip_bounds_length_and_marks_cut() {
        let long = "word ".repeat(100);
        let c = clip(&long, 50);
        assert!(c.chars().count() <= 50);
        assert!(c.ends_with('…'));
        assert_eq!(clip("short", 50), "short");
        // Unbroken strings are cut mid-token, never overflow.
        let token = "x".repeat(500);
        assert_eq!(clip(&token, 20).chars().count(), 20);
    }

    #[test]
    fn clip_handles_multibyte() {
        let s = "日本語のアプリ名".repeat(20);
        let c = clip(&s, 10);
        assert_eq!(c.chars().count(), 10);
    }

    #[test]
    fn clean_strips_controls_and_bidi() {
        assert_eq!(clean("a\u{202E}b\u{0000}c\n\n  d"), "abc d");
        assert_eq!(clean("  lead"), "lead");
    }

    #[test]
    fn clip_middle_keeps_tail() {
        let p = format!(
            "Payload/{}/Frameworks/Thing.framework/Thing",
            "Deep".repeat(40)
        );
        let c = clip_middle(&p, 40);
        assert_eq!(c.chars().count(), 40);
        assert!(c.ends_with("Thing.framework/Thing"));
        assert!(c.starts_with("Payload/"));
    }

    #[test]
    fn mask_never_reveals_full_secret() {
        let secret = "AIzaSyD-abcdefghijklmnopqrstuvwxyz012345";
        let m = mask(secret);
        assert!(m.starts_with("AIzaSy"));
        assert!(m.ends_with("2345"));
        assert!(!m.contains("abcdefghijklmnop"));
        assert_eq!(mask("abc"), "ab••••••");
        assert_eq!(mask(""), "••••••");
    }

    #[test]
    fn group_title_uses_shared_prefix() {
        assert_eq!(
            group_title(&["Custom URL Scheme: 'a'", "Custom URL Scheme: 'b'"]),
            "Custom URL Scheme"
        );
        assert_eq!(group_title(&["Alpha: x", "Beta: y"]), "Alpha: x");
        assert_eq!(group_title(&["Solo: x"]), "Solo: x");
    }

    #[test]
    fn preview_factors_out_common_key() {
        assert_eq!(
            preview(&["CFBundleURLSchemes: rtsp", "CFBundleURLSchemes: mms"]),
            "CFBundleURLSchemes: rtsp, mms"
        );
        assert_eq!(preview(&["_strcpy", "_strcat"]), "_strcpy, _strcat");
        assert_eq!(preview(&[]), "");
    }

    #[test]
    fn utc_date_known_values() {
        assert_eq!(utc_date(UNIX_EPOCH), "1970-01-01");
        let t = UNIX_EPOCH + Duration::from_secs(1_790_208_000); // 2026-09-24
        assert_eq!(utc_date(t), "2026-09-24");
        let leap = UNIX_EPOCH + Duration::from_secs(951_782_400); // 2000-02-29
        assert_eq!(utc_date(leap), "2000-02-29");
    }

    #[test]
    fn css_string_cannot_escape_style() {
        let q = css_string("a\"</style><script>x'\\");
        assert!(q.starts_with('"') && q.ends_with('"'));
        let inner = &q[1..q.len() - 1];
        assert!(!inner.contains(['"', '<', '>', '\'']));
    }

    #[test]
    fn grade_class_defaults_to_f() {
        assert_eq!(grade_class("A"), "a");
        assert_eq!(grade_class("b+"), "b");
        assert_eq!(grade_class(""), "f");
    }
}
