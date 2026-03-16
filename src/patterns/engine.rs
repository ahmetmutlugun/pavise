use anyhow::Result;
use regex::{Regex, RegexSet};
use serde::Deserialize;
use std::path::Path;
use tracing::debug;

use crate::types::{SecretMatch, Severity};

#[derive(Debug, Deserialize, Clone)]
pub struct SecretRule {
    pub id: String,
    pub title: String,
    pub pattern: String,
    pub severity: SeverityDef,
    pub category: String,
    #[serde(default)]
    pub cwe: Option<String>,
    #[serde(default)]
    pub owasp_mobile: Option<String>,
    #[serde(default)]
    pub remediation: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
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

pub struct PatternEngine {
    rules: Vec<SecretRule>,
    set: RegexSet,
    compiled: Vec<Regex>,
}

impl PatternEngine {
    pub fn load(rules_dir: &Path) -> Result<Self> {
        let path = rules_dir.join("secrets.yaml");
        let content = match std::fs::read_to_string(&path) {
            Ok(s) => s,
            Err(e) => {
                debug!("Could not read secrets.yaml at {}: {}", path.display(), e);
                String::new()
            }
        };

        let rules: Vec<SecretRule> = if content.is_empty() {
            Vec::new()
        } else {
            serde_yaml::from_str(&content)?
        };

        let patterns: Vec<&str> = rules.iter().map(|r| r.pattern.as_str()).collect();
        let set = RegexSet::new(&patterns)?;
        let compiled: Vec<Regex> = patterns
            .iter()
            .map(|p| Regex::new(p))
            .collect::<Result<Vec<_>, _>>()?;

        debug!("PatternEngine loaded {} secret rules", rules.len());

        Ok(PatternEngine { rules, set, compiled })
    }

    /// Scan a text buffer and return all secret matches.
    /// `source_path` is used for evidence labeling only.
    pub fn scan(&self, text: &str, source_path: &str) -> Vec<SecretMatch> {
        if text.is_empty() || self.rules.is_empty() {
            return Vec::new();
        }

        let mut matches: Vec<SecretMatch> = Vec::new();

        // Single-pass set match to find which patterns have hits
        let matched_indices: Vec<usize> = self.set.matches(text).into_iter().collect();

        for idx in matched_indices {
            let rule = &self.rules[idx];
            let re = &self.compiled[idx];

            for m in re.find_iter(text) {
                let matched_value = m.as_str();
                // Truncate very long matches for display (e.g., private keys)
                let display_value = if matched_value.len() > 120 {
                    format!("{}...", truncate_str(matched_value, 120))
                } else {
                    matched_value.to_string()
                };

                matches.push(SecretMatch {
                    rule_id: rule.id.clone(),
                    title: rule.title.clone(),
                    severity: Severity::from(&rule.severity),
                    matched_value: display_value,
                    file_path: Some(source_path.to_string()),
                });
            }
        }

        matches
    }

    /// Number of rules loaded from the YAML file.
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    /// Scan raw bytes by converting printable runs to UTF-8 strings first.
    pub fn scan_bytes(&self, data: &[u8], source_path: &str) -> Vec<SecretMatch> {
        // Extract printable ASCII runs (length >= 6)
        let text = extract_printable_strings(data, 6);
        self.scan(&text, source_path)
    }
}

/// Truncate `s` to at most `max_bytes` bytes, respecting UTF-8 char boundaries.
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

/// Extract printable ASCII strings from binary data, joined by newlines.
/// Minimum string length is configurable.
pub fn extract_printable_strings(data: &[u8], min_len: usize) -> String {
    let mut result = String::with_capacity(data.len() / 4);
    let mut current = Vec::new();

    for &byte in data {
        if byte >= 0x20 && byte < 0x7f {
            current.push(byte);
        } else {
            if current.len() >= min_len {
                if let Ok(s) = std::str::from_utf8(&current) {
                    result.push_str(s);
                    result.push('\n');
                }
            }
            current.clear();
        }
    }

    // Flush last run
    if current.len() >= min_len {
        if let Ok(s) = std::str::from_utf8(&current) {
            result.push_str(s);
            result.push('\n');
        }
    }

    result
}
