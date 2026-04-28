//! OSV.dev CVE lookup for detected framework components.
//!
//! Queries <https://api.osv.dev/v1/query> with each component's name and version
//! across relevant ecosystems (CocoaPods, SwiftPM). Returns `Finding` objects
//! containing only CVE IDs that exist in the OSV database.
//!
//! Only called when `--network` is supplied.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use tracing::debug;

use crate::types::{Finding, FrameworkComponent, Severity};

// ------------------------------------------------------------------ //
// OSV API types
// ------------------------------------------------------------------ //

#[derive(Debug, Serialize)]
struct OsvQuery {
    version: String,
    package: OsvPackage,
}

#[derive(Debug, Serialize)]
struct OsvPackage {
    name: String,
    ecosystem: String,
}

#[derive(Debug, Deserialize)]
struct OsvResponse {
    #[serde(default)]
    vulns: Vec<OsvVuln>,
}

#[derive(Debug, Deserialize)]
struct OsvVuln {
    id: String,
    #[serde(default)]
    aliases: Vec<String>,
    #[serde(default)]
    summary: Option<String>,
    #[serde(default)]
    severity: Vec<OsvSeverity>,
    #[serde(default)]
    affected: Vec<OsvAffected>,
}

#[derive(Debug, Deserialize)]
struct OsvSeverity {
    #[allow(dead_code)]
    r#type: String,
    score: String,
}

#[derive(Debug, Deserialize)]
struct OsvAffected {
    #[serde(default)]
    ranges: Vec<OsvRange>,
}

#[derive(Debug, Deserialize)]
struct OsvRange {
    #[serde(default)]
    events: Vec<OsvEvent>,
}

#[derive(Debug, Deserialize)]
struct OsvEvent {
    fixed: Option<String>,
}

// ------------------------------------------------------------------ //
// Public API
// ------------------------------------------------------------------ //

/// Query OSV.dev for each component and return CVE-backed `Finding` objects.
pub fn query_components(components: &[FrameworkComponent]) -> Vec<Finding> {
    let agent = ureq::AgentBuilder::new()
        .timeout(std::time::Duration::from_secs(10))
        .user_agent("pavise-security-scanner/1.0")
        .build();

    let mut findings = Vec::new();
    let mut seen_vuln_ids: HashSet<String> = HashSet::new();

    for component in components {
        let version = match &component.version {
            Some(v) if !v.is_empty() => v.clone(),
            _ => continue,
        };

        let candidate_queries = package_candidates(&component.name);
        for (pkg_name, ecosystem) in candidate_queries {
            match query_one(&agent, &pkg_name, &version, &ecosystem) {
                Ok(vulns) => {
                    for vuln in vulns {
                        // Deduplicate across ecosystem variants
                        if !seen_vuln_ids.insert(vuln.id.clone()) {
                            continue;
                        }
                        if let Some(finding) =
                            vuln_to_finding(&vuln, &component.name, &version, &component.path)
                        {
                            findings.push(finding);
                        }
                    }
                }
                Err(e) => {
                    debug!("OSV query failed for {} ({}): {}", pkg_name, ecosystem, e);
                }
            }
        }
    }

    findings
}

// ------------------------------------------------------------------ //
// Internal helpers
// ------------------------------------------------------------------ //

/// Return (package_name, ecosystem) pairs to try for a given component name.
/// Tries CocoaPods with the original name, then SwiftPM with a lowercased
/// hyphenated variant.
fn package_candidates(name: &str) -> Vec<(String, String)> {
    let mut candidates = vec![(name.to_string(), "CocoaPods".to_string())];

    // SwiftPM packages are typically lowercase-hyphenated
    let swiftpm_name = name
        .chars()
        .enumerate()
        .flat_map(|(i, c)| {
            if c.is_uppercase() && i > 0 {
                vec!['-', c.to_lowercase().next().unwrap_or(c)]
            } else {
                vec![c.to_lowercase().next().unwrap_or(c)]
            }
        })
        .collect::<String>();

    if swiftpm_name != name.to_lowercase() {
        candidates.push((swiftpm_name, "SwiftPM".to_string()));
    }
    // Also try plain lowercase for SwiftPM
    let lower = name.to_lowercase();
    if lower != name && lower != candidates.last().map(|(n, _)| n.clone()).unwrap_or_default() {
        candidates.push((lower, "SwiftPM".to_string()));
    }

    candidates
}

/// POST a single OSV query and return the list of vulnerabilities.
fn query_one(
    agent: &ureq::Agent,
    name: &str,
    version: &str,
    ecosystem: &str,
) -> Result<Vec<OsvVuln>> {
    let body = OsvQuery {
        version: version.to_string(),
        package: OsvPackage {
            name: name.to_string(),
            ecosystem: ecosystem.to_string(),
        },
    };

    let response = agent
        .post("https://api.osv.dev/v1/query")
        .set("Content-Type", "application/json")
        .send_json(serde_json::to_value(&body)?)?;

    if response.status() != 200 {
        return Ok(Vec::new());
    }

    let parsed: OsvResponse = response.into_json()?;
    Ok(parsed.vulns)
}

/// Convert an OSV vulnerability to a Pavise `Finding`.
fn vuln_to_finding(
    vuln: &OsvVuln,
    component_name: &str,
    component_version: &str,
    component_path: &str,
) -> Option<Finding> {
    // Prefer a CVE alias; fall back to the OSV ID (e.g., GHSA-*)
    let display_id = vuln
        .aliases
        .iter()
        .find(|a| a.starts_with("CVE-"))
        .cloned()
        .unwrap_or_else(|| vuln.id.clone());

    let summary = vuln
        .summary
        .as_deref()
        .unwrap_or("No summary available")
        .to_string();

    let severity = infer_severity(&vuln.severity);

    let fixed_version = vuln
        .affected
        .iter()
        .flat_map(|a| &a.ranges)
        .flat_map(|r| &r.events)
        .find_map(|e| e.fixed.clone());

    let remediation = fixed_version
        .as_ref()
        .map(|v| format!("Update {} to version {} or later.", component_name, v));

    let id_slug = display_id
        .chars()
        .map(|c| if c.is_alphanumeric() || c == '-' { c } else { '-' })
        .collect::<String>();

    Some(Finding {
        id: format!("QS-CVE-{}", id_slug),
        title: format!("{}: {}", display_id, summary),
        description: format!(
            "{} (detected: v{}, OSV ID: {})",
            summary, component_version, vuln.id
        ),
        severity,
        category: "sca".to_string(),
        cwe: None,
        owasp_mobile: Some("M8".to_string()),
        owasp_masvs: None,
        evidence: vec![format!(
            "{} v{} in {}",
            component_name, component_version, component_path
        )],
        remediation,
    })
}

/// Map OSV severity entries to Pavise severity. Uses CVSS v3 impact metrics
/// as a heuristic: high confidentiality/integrity/availability impact → High.
fn infer_severity(entries: &[OsvSeverity]) -> Severity {
    for entry in entries {
        let score = &entry.score;
        // CVSS v3 vector: ...C:H... or ...I:H... or ...A:H... → High
        if score.contains("/C:H") || score.contains("/I:H") || score.contains("/A:H") {
            return Severity::High;
        }
    }
    Severity::Warning
}
