//! Golden grade bands for known apps in the benchmark corpus.
//!
//! The corpus is gitignored (`benchmarks/fetch_corpus.sh` downloads it), so
//! this is opt-in: `cargo test --release --test corpus_grades -- --ignored`.
//! Bands are deliberately loose; a failure means a scoring or detection change
//! moved a well-understood app across a grade boundary — check it was intended.

use std::path::{Path, PathBuf};

use pavise::types::Severity;
use pavise::{scan_ipa, ScanOptions};

/// (IPA file-name prefix, allowed grades, why)
const BANDS: &[(&str, &[&str], &str)] = &[
    ("bitwarden__", &["A", "B"], "hardened password manager"),
    ("SwissCovid__", &["A", "B"], "audited government app"),
    (
        "zydeco__minivmac4ios",
        &["C", "D"],
        "dev build with get-task-allow",
    ),
    (
        "Provenance-Emu__",
        &["F"],
        "bundles private keys, get-task-allow, ATS off",
    ),
    (
        "hadobedo__FunkiniOS",
        &["F"],
        "private keys in binary, get-task-allow, no canary",
    ),
];

fn corpus_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("benchmarks/corpus")
}

fn find_ipa(prefix: &str) -> Option<PathBuf> {
    std::fs::read_dir(corpus_dir())
        .ok()?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .find(|p| {
            let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
            name.starts_with(prefix) && name.ends_with(".ipa")
        })
}

#[test]
#[ignore = "needs benchmarks/corpus (run benchmarks/fetch_corpus.sh)"]
fn corpus_grade_bands() {
    assert!(
        corpus_dir().is_dir(),
        "corpus missing: run benchmarks/fetch_corpus.sh"
    );
    let opts = ScanOptions {
        rules_dir: None,
        min_severity: Severity::Info,
        network: false,
        show_progress: false,
        max_extracted_bytes: None,
        max_in_flight_bytes: None,
    };
    let mut failures = Vec::new();
    for (prefix, grades, why) in BANDS {
        let ipa = find_ipa(prefix).unwrap_or_else(|| panic!("{} not in corpus", prefix));
        let report = scan_ipa(&ipa, &opts).expect("scan should succeed");
        if !grades.contains(&report.grade.as_str()) {
            failures.push(format!(
                "{}: {}/{} not in {:?} ({})",
                prefix, report.security_score, report.grade, grades, why
            ));
        }
    }
    assert!(
        failures.is_empty(),
        "grade bands violated:\n{}",
        failures.join("\n")
    );
}
