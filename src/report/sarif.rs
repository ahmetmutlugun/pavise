//! SARIF 2.1.0 output for CI/CD integration (GitHub Code Scanning, VS Code, etc.)

use crate::types::{ScanReport, Severity};
use anyhow::Result;
use serde_json::{json, Value};
use std::collections::HashSet;

pub fn to_string(report: &ScanReport) -> Result<String> {
    let mut rules: Vec<Value> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();

    // Rules from findings
    for f in &report.findings {
        if seen.insert(f.id.clone()) {
            let mut rule = json!({
                "id": f.id,
                "name": f.id.replace('-', ""),
                "shortDescription": { "text": f.title },
                "fullDescription": { "text": f.description },
                "defaultConfiguration": { "level": level(&f.severity) },
                "properties": {
                    "tags": ["security", f.category],
                    "owasp-mobile": f.owasp_mobile,
                    "owasp-masvs": f.owasp_masvs
                }
            });

            if let Some(ref cwe) = f.cwe {
                rule["relationships"] = json!([{
                    "target": {
                        "id": cwe,
                        "toolComponent": { "name": "CWE" }
                    },
                    "kinds": ["superset"]
                }]);
            }

            if let Some(ref rem) = f.remediation {
                rule["help"] = json!({ "text": rem, "markdown": rem });
            }

            rules.push(rule);
        }
    }

    // Rules from secrets
    for s in &report.secrets {
        if seen.insert(s.rule_id.clone()) {
            rules.push(json!({
                "id": s.rule_id,
                "name": s.rule_id.replace('-', ""),
                "shortDescription": { "text": s.title },
                "defaultConfiguration": { "level": level(&s.severity) },
                "properties": { "tags": ["security", "secrets"] }
            }));
        }
    }

    // Results from findings
    let mut results: Vec<Value> = report
        .findings
        .iter()
        .map(|f| {
            let uri = f.evidence.first().map(String::as_str).unwrap_or("app");
            let mut msg = f.description.clone();
            if let Some(ref rem) = f.remediation {
                msg.push_str("\n\nRemediation: ");
                msg.push_str(rem);
            }

            json!({
                "ruleId": f.id,
                "level": level(&f.severity),
                "message": { "text": msg },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": uri,
                            "uriBaseId": "%SRCROOT%"
                        }
                    }
                }],
                "properties": {
                    "category": f.category,
                    "cwe": f.cwe,
                    "owasp-mobile": f.owasp_mobile,
                    "owasp-masvs": f.owasp_masvs
                }
            })
        })
        .collect();

    // Results from secrets
    for s in &report.secrets {
        let uri = s.file_path.as_deref().unwrap_or("app");
        // Truncate matched value to avoid leaking full secrets in SARIF
        let preview = if s.matched_value.len() > 40 {
            format!("{}…", truncate_str(&s.matched_value, 40))
        } else {
            s.matched_value.clone()
        };

        results.push(json!({
            "ruleId": s.rule_id,
            "level": level(&s.severity),
            "message": {
                "text": format!("Potential secret detected: {} — {}", s.title, preview)
            },
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": uri,
                        "uriBaseId": "%SRCROOT%"
                    }
                }
            }],
            "properties": { "category": "secrets" }
        }));
    }

    let sarif = json!({
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "Pavise",
                    "version": env!("CARGO_PKG_VERSION"),
                    "informationUri": "https://github.com/pavise/pavise",
                    "rules": rules
                }
            },
            "results": results,
            "properties": {
                "appName": report.app_info.name,
                "appVersion": report.app_info.version,
                "bundleId": report.app_info.identifier,
                "platform": report.app_info.platform,
                "securityScore": report.security_score,
                "grade": report.grade,
                "scanDurationMs": report.scan_duration_ms,
                "md5": report.file_hashes.md5,
                "sha256": report.file_hashes.sha256
            }
        }]
    });

    serde_json::to_string_pretty(&sarif).map_err(Into::into)
}

fn truncate_str(s: &str, max_bytes: usize) -> &str {
    if s.len() <= max_bytes {
        return s;
    }
    let mut end = max_bytes;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

fn level(severity: &Severity) -> &'static str {
    match severity {
        Severity::High => "error",
        Severity::Warning => "warning",
        Severity::Info => "note",
        Severity::Secure => "none",
    }
}
