//! Rule-file loading.
//!
//! The default rule set is compiled into the binary so release tarballs,
//! `cargo install` and the GitHub Action scan with the same rules as Docker.
//! `--rules DIR` replaces the whole set; every file must then exist and parse.

use anyhow::{bail, Context, Result};
use std::borrow::Cow;
use std::path::Path;

/// Every rule file the scanner loads, with its embedded default contents.
pub const RULE_FILES: &[(&str, &str)] = &[
    ("secrets.yaml", include_str!("../rules/secrets.yaml")),
    ("ios_apis.yaml", include_str!("../rules/ios_apis.yaml")),
    ("trackers.yaml", include_str!("../rules/trackers.yaml")),
    (
        "permissions.yaml",
        include_str!("../rules/permissions.yaml"),
    ),
];

/// Load a rule file from `rules_dir` if given, otherwise from the embedded defaults.
pub fn load(rules_dir: Option<&Path>, name: &str) -> Result<Cow<'static, str>> {
    match rules_dir {
        Some(dir) => {
            let path = dir.join(name);
            std::fs::read_to_string(&path)
                .map(Cow::Owned)
                .with_context(|| format!("Failed to read rule file {}", path.display()))
        }
        None => RULE_FILES
            .iter()
            .find(|(n, _)| *n == name)
            .map(|(_, content)| Cow::Borrowed(*content))
            .with_context(|| format!("Unknown rule file {}", name)),
    }
}

/// Check that a custom rules directory contains every rule file.
pub fn validate_dir(dir: &Path) -> Result<()> {
    if !dir.is_dir() {
        bail!("Rules directory not found: {}", dir.display());
    }
    let missing: Vec<&str> = RULE_FILES
        .iter()
        .map(|(n, _)| *n)
        .filter(|n| !dir.join(n).is_file())
        .collect();
    if !missing.is_empty() {
        bail!(
            "Rules directory {} is missing: {}",
            dir.display(),
            missing.join(", ")
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_rules_are_non_empty() {
        for (name, content) in RULE_FILES {
            assert!(!content.trim().is_empty(), "{} is empty", name);
            assert_eq!(load(None, name).unwrap(), *content);
        }
    }

    #[test]
    fn incomplete_dir_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("secrets.yaml"), "[]").unwrap();
        let err = validate_dir(dir.path()).unwrap_err().to_string();
        assert!(err.contains("ios_apis.yaml"), "{}", err);
        assert!(load(Some(dir.path()), "trackers.yaml").is_err());
    }
}
