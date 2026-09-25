use anyhow::{Context, Result};
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
    /// Objective-C class names that only this SDK defines. They survive
    /// stripping, so they identify SDKs linked statically into the app.
    #[serde(default)]
    objc_classes: Vec<String>,
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
    /// Exact (case-sensitive) ObjC class name → rule index
    class_map: HashMap<String, usize>,
}

impl TrackerDetector {
    pub fn load(rules_dir: Option<&Path>) -> Result<Self> {
        let content = crate::rules::load(rules_dir, "trackers.yaml")?;
        let rules: Vec<TrackerRule> =
            serde_yaml::from_str(&content).context("Failed to parse trackers.yaml")?;

        let mut domain_map = HashMap::new();
        let mut framework_map = HashMap::new();
        let mut framework_prefixes = Vec::new();
        let mut class_map = HashMap::new();

        for (idx, rule) in rules.iter().enumerate() {
            for class in &rule.objc_classes {
                class_map.insert(class.clone(), idx);
            }
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
            class_map,
        })
    }

    /// Rule indices whose ObjC class signatures appear in `class_names`, with
    /// the first matching class.
    fn match_classes(&self, class_names: &[String]) -> Vec<(usize, String)> {
        let mut hits: Vec<(usize, String)> = Vec::new();
        for class in class_names {
            if let Some(&idx) = self.class_map.get(class) {
                if !hits.iter().any(|(i, _)| *i == idx) {
                    hits.push((idx, class.clone()));
                }
            }
        }
        hits.sort();
        hits
    }

    /// SDK names detected from class signatures in the main binary, i.e.
    /// linked statically rather than shipped as a framework.
    pub fn statically_linked(
        &self,
        class_names: &[String],
        framework_names: &[String],
    ) -> Vec<String> {
        let shipped = self.detect(&[], framework_names, &[]);
        self.match_classes(class_names)
            .into_iter()
            .map(|(idx, _)| self.rules[idx].name.clone())
            .filter(|name| !shipped.iter().any(|t| &t.name == name))
            .collect()
    }

    /// Detect trackers from domains, framework names and the main binary's
    /// ObjC class names.
    pub fn detect(
        &self,
        domains: &[String],
        framework_names: &[String],
        class_names: &[String],
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

        for (idx, class) in self.match_classes(class_names) {
            if matched_indices.insert(idx) {
                evidence_map.insert(idx, format!("ObjC class: {} (main binary)", class));
            }
        }

        let mut matched: Vec<usize> = matched_indices.into_iter().collect();
        matched.sort();
        matched
            .into_iter()
            .map(|idx| {
                let rule = &self.rules[idx];
                TrackerMatch {
                    name: rule.name.clone(),
                    website: rule.website.clone(),
                    categories: rule.categories.clone(),
                    detection_evidence: evidence_map.get(&idx).cloned().unwrap_or_default(),
                }
            })
            .collect()
    }
}
