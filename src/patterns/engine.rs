use anyhow::{Context, Result};
use regex::Regex;
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

// No RegexSet pre-pass: once the haystack holds non-ASCII text (`__ustring`
// UTF-16 runs), the Unicode `.{0,20}` / `(?i)` rules thrash the combined
// lazy DFA and it falls back to the PikeVM — 20 s instead of 0.2 s on a
// 357 MB binary. Individual regexes keep their literal prefilters.
pub struct PatternEngine {
    rules: Vec<SecretRule>,
    compiled: Vec<Regex>,
}

impl PatternEngine {
    pub fn load(rules_dir: Option<&Path>) -> Result<Self> {
        let content = crate::rules::load(rules_dir, "secrets.yaml")?;
        let rules: Vec<SecretRule> =
            serde_yaml::from_str(&content).context("Failed to parse secrets.yaml")?;

        let patterns: Vec<&str> = rules.iter().map(|r| r.pattern.as_str()).collect();
        let compiled: Vec<Regex> = patterns
            .iter()
            .map(|p| Regex::new(p))
            .collect::<Result<Vec<_>, _>>()?;

        debug!("PatternEngine loaded {} secret rules", rules.len());

        Ok(PatternEngine { rules, compiled })
    }

    /// Scan a text buffer and return all secret matches.
    /// `source_path` is used for evidence labeling only.
    pub fn scan(&self, text: &str, source_path: &str) -> Vec<SecretMatch> {
        if text.is_empty() || self.rules.is_empty() {
            return Vec::new();
        }

        let mut matches: Vec<SecretMatch> = Vec::new();

        for (rule, re) in self.rules.iter().zip(&self.compiled) {
            for m in re.find_iter(text) {
                let matched_value = m.as_str();
                if !is_plausible(&rule.id, matched_value) {
                    continue;
                }
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
                    cwe: Some(rule.cwe.clone().unwrap_or_else(|| "CWE-798".to_string())),
                    owasp_mobile: None,
                    owasp_masvs: None,
                    remediation: rule.remediation.clone(),
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

/// Post-regex checks for rules whose pattern alone is too loose.
fn is_plausible(rule_id: &str, value: &str) -> bool {
    // Legacy Rust symbol hash suffix (`17h<16 hex>E`): mangled names such as
    // `hf_shared8displace17h4b553b516e2f71e7E` are not tokens.
    static RUST_HASH: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
    let rust_hash = RUST_HASH.get_or_init(|| Regex::new(r"17h[0-9a-f]{16}E").expect("valid regex"));
    if rust_hash.is_match(value) {
        return false;
    }
    match rule_id {
        // Real bearer tokens contain digits; words from string tables don't.
        "QS-SEC-014" => value
            .split_whitespace()
            .nth(1)
            .is_some_and(|t| t.bytes().any(|b| b.is_ascii_digit())),
        // Generic `api_key = value`: real values contain digits; ObjC selectors
        // (`initWithAPIKey:kitVersionsByKitBundleIdentifier`) don't.
        "QS-SEC-005" => value
            .split_once([':', '='])
            .is_some_and(|(_, v)| v.bytes().any(|b| b.is_ascii_digit())),
        // The anon key has the same shape; only a service_role key is a finding.
        "QS-SEC-024" => jwt_role(value).as_deref() == Some("service_role"),
        _ => true,
    }
}

/// Decode a JWT's payload and return its `role` claim.
fn jwt_role(token: &str) -> Option<String> {
    use base64::Engine as _;
    let payload = token.split('.').nth(1)?;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload.trim_end_matches('='))
        .ok()?;
    let claims: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    claims.get("role")?.as_str().map(str::to_string)
}

/// Flatten a plist (XML or binary) into `Key = "Value"` lines, one per string
/// leaf, so rules written for `key = "value"` assignments match config plists.
/// Array elements inherit the enclosing key. Returns `None` if unparseable.
pub fn plist_key_values(data: &[u8]) -> Option<String> {
    fn walk(key: &str, value: &plist::Value, out: &mut String) {
        match value {
            plist::Value::Dictionary(d) => {
                for (k, v) in d {
                    walk(k, v, out);
                }
            }
            plist::Value::Array(items) => {
                for v in items {
                    walk(key, v, out);
                }
            }
            plist::Value::String(s) if !key.is_empty() && !s.contains('\n') => {
                out.push_str(key);
                out.push_str(" = \"");
                out.push_str(s);
                out.push_str("\"\n");
            }
            _ => {}
        }
    }
    let value = plist::Value::from_reader(std::io::Cursor::new(data)).ok()?;
    let mut out = String::new();
    walk("", &value, &mut out);
    Some(out)
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
        if (0x20..0x7f).contains(&byte) {
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
