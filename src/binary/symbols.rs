use anyhow::{Context, Result};
use serde::Deserialize;
use std::collections::{HashMap, HashSet};
use std::path::Path;

use crate::types::{Finding, Severity};

#[derive(Debug, Deserialize)]
pub struct ApiRule {
    pub id: String,
    pub title: String,
    pub symbols: Vec<String>,
    pub severity: SeverityDef,
    #[serde(default)]
    pub cwe: Option<String>,
    #[serde(default)]
    pub owasp_mobile: Option<String>,
    #[serde(default)]
    pub owasp_masvs: Option<String>,
    #[serde(default)]
    pub remediation: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SeverityDef {
    High,
    Warning,
    Info,
    Secure,
}

impl From<&SeverityDef> for Severity {
    fn from(s: &SeverityDef) -> Self {
        match s {
            SeverityDef::High => Severity::High,
            SeverityDef::Warning => Severity::Warning,
            SeverityDef::Info => Severity::Info,
            SeverityDef::Secure => Severity::Secure,
        }
    }
}

pub struct SymbolScanner {
    /// Maps symbol name → rule index
    symbol_map: HashMap<String, usize>,
    rules: Vec<ApiRule>,
}

impl SymbolScanner {
    pub fn load(rules_dir: Option<&Path>) -> Result<Self> {
        let content = crate::rules::load(rules_dir, "ios_apis.yaml")?;
        let rules: Vec<ApiRule> =
            serde_yaml::from_str(&content).context("Failed to parse ios_apis.yaml")?;

        let mut symbol_map = HashMap::new();
        for (idx, rule) in rules.iter().enumerate() {
            for sym in &rule.symbols {
                symbol_map.insert(sym.clone(), idx);
            }
        }

        Ok(SymbolScanner { symbol_map, rules })
    }

    /// Findings for the rules `imports` match, attributed to `binary` (its
    /// archive path). Imports of a bundled framework are third-party code the
    /// app may never reach, so their severity drops one level.
    pub fn scan(&self, imports: &[String], binary: &str, origin: Origin) -> Vec<Finding> {
        let import_set: HashSet<&str> = imports.iter().map(|s| s.as_str()).collect();

        // Track which rules fired and which symbols matched
        let mut rule_hits: HashMap<usize, Vec<&str>> = HashMap::new();
        for sym in &import_set {
            if let Some(&rule_idx) = self.symbol_map.get(*sym) {
                rule_hits.entry(rule_idx).or_default().push(sym);
            }
        }

        let name = binary_name(binary);
        rule_hits
            .into_iter()
            .map(|(idx, mut matched_syms)| {
                matched_syms.sort_unstable();
                let rule = &self.rules[idx];
                let severity = Severity::from(&rule.severity);
                let (severity, description) = match origin {
                    Origin::App => (
                        severity,
                        format!("Binary {} imports: {}.", name, matched_syms.join(", ")),
                    ),
                    Origin::Library => (
                        demote(severity),
                        format!(
                            "Bundled library {} imports: {}. The app's own code may never \
                            call them, so severity is lowered.",
                            name,
                            matched_syms.join(", ")
                        ),
                    ),
                };
                Finding {
                    id: rule.id.clone(),
                    title: rule.title.clone(),
                    description,
                    severity,
                    category: "binary".to_string(),
                    cwe: rule.cwe.clone(),
                    owasp_mobile: rule.owasp_mobile.clone(),
                    owasp_masvs: rule.owasp_masvs.clone(),
                    evidence: matched_syms
                        .iter()
                        .map(|s| format!("{}: {}", name, s))
                        .collect(),
                    remediation: rule.remediation.clone(),
                }
            })
            .collect()
    }
}

/// Name the modules that call each import in `findings` (from [`scan`] on
/// the app's own executable `data`; see [`callsites`]). When every call site
/// of every matched import is in a dependency (a pod, SwiftPM target or static
/// library linked into the binary), severity drops one level, as for a
/// bundled framework. Does nothing without a debug map.
///
/// [`scan`]: SymbolScanner::scan
/// [`callsites`]: crate::binary::callsites
pub fn attribute_callers(findings: &mut [Finding], data: &[u8]) {
    let symbol_of = |e: &str| e.rsplit(": ").next().unwrap_or(e).to_string();
    let wanted: Vec<String> = findings
        .iter()
        .flat_map(|f| f.evidence.iter().map(|e| symbol_of(e)))
        .collect();
    let wanted: Vec<&str> = wanted.iter().map(String::as_str).collect();
    let Some(callers) = crate::binary::callsites::callers(data, &wanted) else {
        return;
    };
    let app = callers.app_module.as_deref();
    for f in findings {
        let mut dependencies: Vec<&str> = Vec::new();
        let mut only_dependencies = app.is_some();
        for e in &mut f.evidence {
            let Some(modules) = callers.by_symbol.get(&symbol_of(e)) else {
                // No direct call found (function pointer, inlined thunk…).
                only_dependencies = false;
                continue;
            };
            let list: Vec<String> = modules
                .iter()
                .map(|(m, n)| {
                    if Some(m.as_str()) == app {
                        only_dependencies = false;
                        format!("{} (app code) ×{}", m, n)
                    } else {
                        dependencies.push(m);
                        format!("{} ×{}", m, n)
                    }
                })
                .collect();
            e.push_str(&format!(" — called from {}", list.join(", ")));
        }
        if only_dependencies && !dependencies.is_empty() {
            dependencies.sort_unstable();
            dependencies.dedup();
            f.severity = demote(f.severity.clone());
            f.description.push_str(&format!(
                " Every call site is in statically linked dependency code ({}), not the \
                app's own code, so severity is lowered. Update or replace the dependency \
                rather than changing app code.",
                dependencies.join(", ")
            ));
        }
    }
}

/// Who wrote the binary whose imports are scanned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Origin {
    /// Main executable or app extension.
    App,
    /// Embedded framework or dylib.
    Library,
}

fn demote(severity: Severity) -> Severity {
    match severity {
        Severity::High => Severity::Warning,
        Severity::Warning => Severity::Info,
        other => other,
    }
}

/// `Payload/A.app/Frameworks/ssl.framework/ssl` → `ssl.framework`;
/// the main executable keeps its file name.
pub fn binary_name(path: &str) -> &str {
    path.split('/')
        .find(|s| s.ends_with(".framework") || s.ends_with(".appex") || s.ends_with(".dylib"))
        .unwrap_or_else(|| path.rsplit('/').next().unwrap_or(path))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn library_imports_are_attributed_and_demoted() {
        let scanner = SymbolScanner::load(None).unwrap();
        let imports = vec!["_DES_set_key".to_string()];
        let lib = scanner.scan(
            &imports,
            "Payload/UTM.app/Frameworks/ssl.1.1.framework/ssl.1.1",
            Origin::Library,
        );
        assert_eq!(lib[0].severity, Severity::Warning);
        assert_eq!(lib[0].evidence, ["ssl.1.1.framework: _DES_set_key"]);
        let app = scanner.scan(&imports, "Payload/UTM.app/UTM", Origin::App);
        assert_eq!(app[0].severity, Severity::High);
        assert_eq!(app[0].evidence, ["UTM: _DES_set_key"]);
    }

    #[test]
    fn dependency_only_calls_lower_severity() {
        let f = |evidence: &[&str]| Finding {
            id: "QS-API-001".into(),
            title: String::new(),
            description: "Binary App imports.".into(),
            severity: Severity::Warning,
            category: "binary".into(),
            cwe: None,
            owasp_mobile: None,
            owasp_masvs: None,
            evidence: evidence.iter().map(|e| e.to_string()).collect(),
            remediation: None,
        };
        let data = crate::binary::callsites::tests_support::macho_with_calls();
        // _rand is only called from Dep; _strcpy also from the app's code.
        let mut findings = vec![f(&["App: _rand"]), f(&["App: _rand", "App: _strcpy"])];
        attribute_callers(&mut findings, &data);
        assert_eq!(findings[0].severity, Severity::Info);
        assert_eq!(findings[0].evidence, ["App: _rand — called from Dep ×1"]);
        assert!(findings[0].description.contains("(Dep)"));
        assert_eq!(findings[1].severity, Severity::Warning);
        assert_eq!(
            findings[1].evidence[1],
            "App: _strcpy — called from App (app code) ×1, Dep ×1"
        );
    }
}
