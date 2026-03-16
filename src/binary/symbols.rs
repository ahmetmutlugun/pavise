use anyhow::Result;
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
    pub fn load(rules_dir: &Path) -> Result<Self> {
        let path = rules_dir.join("ios_apis.yaml");
        let content = std::fs::read_to_string(&path)
            .unwrap_or_default();

        let rules: Vec<ApiRule> = if content.is_empty() {
            Vec::new()
        } else {
            serde_yaml::from_str(&content)?
        };

        let mut symbol_map = HashMap::new();
        for (idx, rule) in rules.iter().enumerate() {
            for sym in &rule.symbols {
                symbol_map.insert(sym.clone(), idx);
            }
        }

        Ok(SymbolScanner { symbol_map, rules })
    }

    /// Given a list of imported symbol names, return findings for matched rules.
    pub fn scan(&self, imports: &[String]) -> Vec<Finding> {
        let import_set: HashSet<&str> = imports.iter().map(|s| s.as_str()).collect();

        // Track which rules fired and which symbols matched
        let mut rule_hits: HashMap<usize, Vec<String>> = HashMap::new();
        for sym in &import_set {
            if let Some(&rule_idx) = self.symbol_map.get(*sym) {
                rule_hits.entry(rule_idx).or_default().push(sym.to_string());
            }
        }

        rule_hits
            .into_iter()
            .map(|(idx, matched_syms)| {
                let rule = &self.rules[idx];
                Finding {
                    id: rule.id.clone(),
                    title: rule.title.clone(),
                    description: format!(
                        "Binary imports potentially dangerous symbol(s): {}",
                        matched_syms.join(", ")
                    ),
                    severity: Severity::from(&rule.severity),
                    category: "binary".to_string(),
                    cwe: rule.cwe.clone(),
                    owasp_mobile: rule.owasp_mobile.clone(),
                    owasp_masvs: rule.owasp_masvs.clone(),
                    evidence: matched_syms,
                    remediation: rule.remediation.clone(),
                }
            })
            .collect()
    }
}
