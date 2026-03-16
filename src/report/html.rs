//! HTML report generation using Tera templates.
//!
//! The template is embedded at compile time — no external file needed at runtime.

use crate::types::{ScanReport, Severity};
use anyhow::{Context, Result};
use tera::{Context as TeraContext, Tera};

const TEMPLATE: &str = include_str!("../../templates/report.html.tera");

pub fn to_string(report: &ScanReport) -> Result<String> {
    let mut tera = Tera::default();
    tera.add_raw_template("report.html", TEMPLATE)
        .context("Failed to load HTML report template")?;

    let mut ctx = TeraContext::new();
    ctx.insert("report", report);
    ctx.insert("version", env!("CARGO_PKG_VERSION"));

    // Pre-compute severity counts so the template doesn't need filtering logic
    let high_count = count_severity(&report.findings, &Severity::High)
        + report
            .secrets
            .iter()
            .filter(|s| s.severity == Severity::High)
            .count();
    let warn_count = count_severity(&report.findings, &Severity::Warning)
        + report
            .secrets
            .iter()
            .filter(|s| s.severity == Severity::Warning)
            .count();
    let info_count = count_severity(&report.findings, &Severity::Info);

    ctx.insert("high_count", &high_count);
    ctx.insert("warn_count", &warn_count);
    ctx.insert("info_count", &info_count);

    let owasp_labels: Vec<(&str, &str)> = vec![
        ("M1", "Improper Credential Usage"),
        ("M2", "Inadequate Supply Chain Security"),
        ("M3", "Insecure Authentication/Authorization"),
        ("M4", "Insufficient Input/Output Validation"),
        ("M5", "Insecure Communication"),
        ("M6", "Inadequate Privacy Controls"),
        ("M7", "Insufficient Binary Protections"),
        ("M8", "Security Misconfiguration"),
        ("M9", "Insecure Data Storage"),
        ("M10", "Insufficient Cryptography"),
    ];
    ctx.insert("owasp_labels", &owasp_labels);

    let cve_findings: Vec<&crate::types::Finding> = report
        .findings
        .iter()
        .filter(|f| f.id.starts_with("QS-CVE-"))
        .collect();
    ctx.insert("cve_findings", &cve_findings);

    tera.render("report.html", &ctx)
        .context("Failed to render HTML report")
}

fn count_severity(findings: &[crate::types::Finding], sev: &Severity) -> usize {
    findings.iter().filter(|f| &f.severity == sev).count()
}
