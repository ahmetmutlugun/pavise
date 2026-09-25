//! Report view model shared by the PDF summary and the web result fragment.
//!
//! Findings are grouped by rule, evidence is capped, secrets are masked, and
//! every untrusted string is cleaned and length-bounded, so neither the PDF
//! nor the page can be broken by a hostile app name or path. The two outputs
//! differ only in their `Limits`.

use std::collections::{BTreeMap, HashMap};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;

use crate::types::{Finding, ScanReport, SecretMatch, Severity};

/// How much of the scan a view carries. JSON/SARIF/HTML keep the full data.
pub struct Limits {
    /// Rows in the page-one "Fix first" list.
    pub priority_rows: usize,
    /// High/Warning groups rendered as cards.
    pub detail_cards: usize,
    /// Informational groups.
    pub info_rows: usize,
    /// Evidence lines per group.
    pub evidence: usize,
    pub trackers: usize,
}

/// The PDF is a brief summary that has to fit on paper.
pub const PDF_LIMITS: Limits = Limits {
    priority_rows: 8,
    detail_cards: 25,
    info_rows: 20,
    evidence: 4,
    trackers: 16,
};

/// The web page lists every group (collapsed) and more evidence per group.
pub const WEB_LIMITS: Limits = Limits {
    priority_rows: 8,
    detail_cards: 200,
    info_rows: 200,
    evidence: 12,
    trackers: 100,
};

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

// ─── View model ──────────────────────────────────────────────────────────────

#[derive(Serialize)]
pub struct View {
    version: &'static str,
    generated: String,
    app: AppView,
    grade: String,
    grade_class: &'static str,
    score: u8,
    duration_ms: u64,
    counts: Counts,
    verdict: String,
    verdict_detail: String,
    diff: Option<DiffView>,
    priority: Vec<Group>,
    priority_more: usize,
    details: Vec<Group>,
    details_more: usize,
    info: Vec<Group>,
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

pub fn build(r: &ScanReport, limits: &Limits) -> View {
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
        limits.evidence,
    );
    actionable.extend(group_secrets(&r.secrets, limits.evidence));
    actionable.sort_by_key(|g| g.sev_rank());
    let info_groups = group_findings(
        r.findings.iter().filter(|f| f.severity == Severity::Info),
        limits.evidence,
    );

    let (verdict, verdict_detail) = verdict(&counts, info_groups.len());

    let priority_more = actionable.len().saturating_sub(limits.priority_rows);
    let details_more = actionable.len().saturating_sub(limits.detail_cards);
    let priority = actionable
        .iter()
        .take(limits.priority_rows)
        .map(Group::summary_row)
        .collect();
    let details: Vec<Group> = actionable.into_iter().take(limits.detail_cards).collect();

    let info_more = info_groups.len().saturating_sub(limits.info_rows);
    let info = info_groups.into_iter().take(limits.info_rows).collect();

    let trackers_more = r.trackers.len().saturating_sub(limits.trackers);
    let trackers = r
        .trackers
        .iter()
        .take(limits.trackers)
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
        duration_ms: r.scan_duration_ms,
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
            "{} included for context.",
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
fn group_findings<'a>(
    findings: impl Iterator<Item = &'a Finding>,
    max_evidence: usize,
) -> Vec<Group> {
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
                    .take(max_evidence)
                    .map(|e| clip_middle(e, LEN_EVIDENCE))
                    .collect(),
                evidence_more: evidence.len().saturating_sub(max_evidence),
                evidence_inline: evidence
                    .iter()
                    .take(max_evidence)
                    .all(|e| e.chars().count() <= 36),
                preview: preview(&evidence),
            }
        })
        .collect()
}

/// Secrets are grouped per rule; values are masked since PDFs get forwarded.
fn group_secrets(secrets: &[SecretMatch], max_evidence: usize) -> Vec<Group> {
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
                evidence: lines.iter().take(max_evidence).cloned().collect(),
                evidence_more: lines.len().saturating_sub(max_evidence),
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
pub(super) fn version_label(v: &str) -> String {
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
pub(super) fn clip(s: &str, max: usize) -> String {
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

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
    fn grade_class_defaults_to_f() {
        assert_eq!(grade_class("A"), "a");
        assert_eq!(grade_class("b+"), "b");
        assert_eq!(grade_class(""), "f");
    }
}
