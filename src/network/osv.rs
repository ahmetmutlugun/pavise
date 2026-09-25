//! OSV.dev CVE lookup for detected framework components.
//!
//! Queries <https://api.osv.dev/v1/query> for each component that has a source
//! repository URL, using OSV's `SwiftURL` ecosystem (package name = repo URL
//! without scheme, e.g. `github.com/apple/swift-nio`). OSV has no CocoaPods
//! ecosystem, so bundled frameworks without a known repo URL are skipped.
//!
//! Only called when `--network` is supplied.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use tracing::{debug, warn};

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

    let mut skipped = 0usize;
    for component in components {
        let version = match &component.version {
            Some(v) if !v.is_empty() => v.clone(),
            _ => continue,
        };
        let Some(pkg_name) = component.source_url.as_deref().and_then(swift_url_name) else {
            skipped += 1;
            continue;
        };

        match query_one(&agent, &pkg_name, &version, "SwiftURL") {
            Ok(vulns) => {
                for vuln in vulns {
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
                warn!("OSV query failed for {} (SwiftURL): {}", pkg_name, e);
            }
        }
    }
    if skipped > 0 {
        debug!(
            "OSV: skipped {} versioned components without a repo URL",
            skipped
        );
    }

    findings
}

// ------------------------------------------------------------------ //
// Internal helpers
// ------------------------------------------------------------------ //

/// Normalise a repository URL to OSV's `SwiftURL` package name: scheme,
/// credentials and `.git` stripped (`https://github.com/a/b.git` → `github.com/a/b`).
fn swift_url_name(url: &str) -> Option<String> {
    let url = url.trim();
    let rest = if let Some(scp) = url.strip_prefix("git@") {
        // scp-style: git@github.com:owner/repo.git
        scp.replacen(':', "/", 1)
    } else {
        let no_scheme = url.split_once("://").map(|(_, r)| r).unwrap_or(url);
        no_scheme
            .rsplit_once('@')
            .map(|(_, r)| r)
            .unwrap_or(no_scheme)
            .to_string()
    };
    let name = rest.trim_end_matches('/').trim_end_matches(".git");
    // Require host/path so bare names never become queries.
    if name.contains('/') && name.split('/').next().is_some_and(|h| h.contains('.')) {
        Some(name.to_string())
    } else {
        None
    }
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
        .map(|c| {
            if c.is_alphanumeric() || c == '-' {
                c
            } else {
                '-'
            }
        })
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

#[cfg(test)]
mod tests {
    use super::swift_url_name;

    #[test]
    fn normalises_repo_urls() {
        assert_eq!(
            swift_url_name("https://github.com/Alamofire/Alamofire.git").as_deref(),
            Some("github.com/Alamofire/Alamofire")
        );
        assert_eq!(
            swift_url_name("git@github.com:apple/swift-nio.git").as_deref(),
            Some("github.com/apple/swift-nio")
        );
        assert_eq!(
            swift_url_name("https://user:tok@gitlab.com/o/r/").as_deref(),
            Some("gitlab.com/o/r")
        );
        assert_eq!(swift_url_name("Alamofire"), None);
    }
}
