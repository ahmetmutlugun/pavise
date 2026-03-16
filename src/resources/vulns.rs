//! Framework CVE database loader and matcher.
//!
//! Loads `data/framework_vulns.yaml` and checks detected framework components
//! against known vulnerable version ranges, emitting `QS-CVE-*` findings.

use anyhow::{Context, Result};
use serde::Deserialize;
use std::path::Path;

use crate::types::{Finding, FrameworkComponent, Severity};

#[derive(Debug, Deserialize)]
struct VulnEntry {
    framework: String,
    name_patterns: Vec<String>,
    affected_below: String,
    cve: String,
    title: String,
    severity: String,
    description: String,
    cwe: String,
    owasp_mobile: String,
}

pub struct VulnDatabase {
    entries: Vec<VulnEntry>,
}

impl VulnDatabase {
    /// Load the vulnerability database from `data/framework_vulns.yaml` relative to `data_dir`.
    pub fn load(data_dir: &Path) -> Result<Self> {
        let path = data_dir.join("framework_vulns.yaml");
        let content = std::fs::read_to_string(&path)
            .with_context(|| format!("Failed to read {}", path.display()))?;
        let entries: Vec<VulnEntry> =
            serde_yaml::from_str(&content).context("Failed to parse framework_vulns.yaml")?;
        Ok(VulnDatabase { entries })
    }

    /// Check a list of detected framework components against the database.
    /// Returns one `Finding` per (component, CVE) pair where the component version is
    /// below the fixed threshold.
    pub fn check(&self, components: &[FrameworkComponent]) -> Vec<Finding> {
        let mut findings = Vec::new();

        for component in components {
            let comp_version = match &component.version {
                Some(v) if !v.is_empty() => v,
                _ => continue, // no version info — cannot compare
            };

            let parsed_comp = match parse_loose_semver(comp_version) {
                Some(v) => v,
                None => continue,
            };

            for entry in &self.entries {
                // Name matching: any pattern is a case-insensitive substring of the component name
                let name_matches = entry
                    .name_patterns
                    .iter()
                    .any(|p| component.name.to_lowercase().contains(&p.to_lowercase()));
                if !name_matches {
                    continue;
                }

                let threshold = match parse_loose_semver(&entry.affected_below) {
                    Some(v) => v,
                    None => continue,
                };

                if parsed_comp < threshold {
                    let severity = match entry.severity.as_str() {
                        "high" => Severity::High,
                        _ => Severity::Warning,
                    };

                    // Sanitize CVE ID for use in finding ID (replace non-alphanumeric with -)
                    let cve_id = entry
                        .cve
                        .chars()
                        .map(|c| if c.is_alphanumeric() || c == '-' { c } else { '-' })
                        .collect::<String>();

                    findings.push(Finding {
                        id: format!("QS-CVE-{}", cve_id),
                        title: format!("{}: {}", entry.cve, entry.title),
                        description: format!(
                            "{} (detected version: {}, fixed in: {})",
                            entry.description, comp_version, entry.affected_below
                        ),
                        severity,
                        category: "sca".to_string(),
                        cwe: Some(entry.cwe.clone()),
                        owasp_mobile: Some(entry.owasp_mobile.clone()),
                        owasp_masvs: None,
                        evidence: vec![format!(
                            "{} v{} in {}",
                            component.name, comp_version, component.path
                        )],
                        remediation: Some(format!(
                            "Update {} to version {} or later.",
                            entry.framework, entry.affected_below
                        )),
                    });
                }
            }
        }

        findings
    }
}

/// Parse a version string leniently: tries "x.y.z", then "x.y.z.0" (4-part iOS versions),
/// then "x.y.0.0". Returns None if no parse succeeds.
fn parse_loose_semver(s: &str) -> Option<semver::Version> {
    // Strip any leading 'v'
    let s = s.trim_start_matches('v');

    // Direct parse
    if let Ok(v) = semver::Version::parse(s) {
        return Some(v);
    }

    // Split on dots and try to build a 3-part version from the first 3 components
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() >= 3 {
        let trimmed = format!("{}.{}.{}", parts[0], parts[1], parts[2]);
        if let Ok(v) = semver::Version::parse(&trimmed) {
            return Some(v);
        }
    }
    if parts.len() == 2 {
        let trimmed = format!("{}.{}.0", parts[0], parts[1]);
        if let Ok(v) = semver::Version::parse(&trimmed) {
            return Some(v);
        }
    }
    if parts.len() == 1 {
        let trimmed = format!("{}.0.0", parts[0]);
        if let Ok(v) = semver::Version::parse(&trimmed) {
            return Some(v);
        }
    }

    None
}
