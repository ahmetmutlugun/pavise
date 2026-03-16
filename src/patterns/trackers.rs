use anyhow::Result;
use serde::Deserialize;
use std::collections::{HashMap, HashSet};
use std::path::Path;

use crate::types::TrackerMatch;

#[derive(Debug, Deserialize)]
struct TrackerRule {
    name: String,
    #[serde(default)]
    categories: Vec<String>,
    #[serde(default)]
    domains: Vec<String>,
    #[serde(default)]
    framework_names: Vec<String>,
    /// Prefix patterns: any framework whose name starts with one of these strings matches.
    /// e.g. "Firebase" matches FirebaseCore, FirebaseFirestoreInternal, etc.
    #[serde(default)]
    framework_prefixes: Vec<String>,
    #[serde(default)]
    website: Option<String>,
}

pub struct TrackerDetector {
    rules: Vec<TrackerRule>,
    /// Maps lowercase domain suffix → rule index
    domain_map: HashMap<String, usize>,
    /// Maps lowercase exact framework name → rule index
    framework_map: HashMap<String, usize>,
    /// (lowercase prefix, rule index) pairs for prefix matching
    framework_prefixes: Vec<(String, usize)>,
}

impl TrackerDetector {
    pub fn load(rules_dir: &Path) -> Result<Self> {
        let path = rules_dir.join("trackers.yaml");
        let content = std::fs::read_to_string(&path).unwrap_or_default();

        let rules: Vec<TrackerRule> = if content.is_empty() {
            Vec::new()
        } else {
            serde_yaml::from_str(&content).unwrap_or_default()
        };

        let mut domain_map = HashMap::new();
        let mut framework_map = HashMap::new();
        let mut framework_prefixes = Vec::new();

        for (idx, rule) in rules.iter().enumerate() {
            for domain in &rule.domains {
                domain_map.insert(domain.to_lowercase(), idx);
            }
            for fw in &rule.framework_names {
                framework_map.insert(fw.to_lowercase(), idx);
            }
            for prefix in &rule.framework_prefixes {
                framework_prefixes.push((prefix.to_lowercase(), idx));
            }
        }

        Ok(TrackerDetector {
            rules,
            domain_map,
            framework_map,
            framework_prefixes,
        })
    }

    /// Detect trackers from a list of domains and framework names.
    pub fn detect(
        &self,
        domains: &[String],
        framework_names: &[String],
    ) -> Vec<TrackerMatch> {
        let mut matched_indices: HashSet<usize> = HashSet::new();
        let mut evidence_map: HashMap<usize, String> = HashMap::new();

        for domain in domains {
            let lower = domain.to_lowercase();

            // Exact match
            if let Some(&idx) = self.domain_map.get(&lower) {
                if matched_indices.insert(idx) {
                    evidence_map.insert(idx, format!("Domain: {}", domain));
                }
                continue;
            }

            // Suffix match: domain ends with .<tracker_domain>
            for (tracker_domain, &idx) in &self.domain_map {
                if lower.ends_with(&format!(".{}", tracker_domain)) {
                    if matched_indices.insert(idx) {
                        evidence_map.insert(idx, format!("Domain: {}", domain));
                    }
                    break;
                }
            }
        }

        for fw in framework_names {
            let lower = fw.to_lowercase();

            // Exact match
            if let Some(&idx) = self.framework_map.get(&lower) {
                if matched_indices.insert(idx) {
                    evidence_map.insert(idx, format!("Framework: {}", fw));
                }
                continue;
            }

            // Prefix match: framework name starts with a known prefix
            for (prefix, idx) in &self.framework_prefixes {
                if lower.starts_with(prefix.as_str()) {
                    if matched_indices.insert(*idx) {
                        evidence_map.insert(*idx, format!("Framework: {}", fw));
                    }
                    break;
                }
            }
        }

        matched_indices
            .into_iter()
            .map(|idx| {
                let rule = &self.rules[idx];
                TrackerMatch {
                    name: rule.name.clone(),
                    website: rule.website.clone(),
                    categories: rule.categories.clone(),
                    detection_evidence: evidence_map
                        .get(&idx)
                        .cloned()
                        .unwrap_or_default(),
                }
            })
            .collect()
    }
}
