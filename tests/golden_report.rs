//! Golden-file regression: scan a fixed fixture IPA and compare the JSON report
//! with `tests/golden/fixture_report.json`.
//!
//! Volatile fields (timings) are zeroed and unordered collections sorted, so
//! any remaining diff is a real change in detection, scoring or report shape.
//! After an intended change, regenerate with
//! `PAVISE_UPDATE_GOLDEN=1 cargo test --test golden_report` and review the diff.

mod common;

use std::path::Path;

use pavise::types::Severity;
use pavise::{scan_ipa, ScanOptions};
use serde_json::Value;

const GOLDEN: &str = "tests/golden/fixture_report.json";

fn fixture() -> tempfile::NamedTempFile {
    let config = r#"<plist version="1.0"><dict>
  <key>AWSKey</key><string>AKIAIOSFODNN7EXAMPLE</string>
  <key>ApiBase</key><string>http://api.example-backend.com/v1</string>
</dict></plist>"#;
    let ext_plist = r#"<plist version="1.0"><dict>
  <key>CFBundleExecutable</key><string>Widget</string>
</dict></plist>"#;
    let key = "-----BEGIN RSA PRIVATE KEY-----\n\
               MIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Qu\n\
               -----END RSA PRIVATE KEY-----\n";
    common::IpaBuilder::new("Golden")
        .add_bundle_file("Config.plist", config)
        .add_bundle_file("server.pem", key)
        .add_bundle_file("seed.sqlite", b"SQLite format 3\0".to_vec())
        .add_bundle_file("PlugIns/Widget.appex/Info.plist", ext_plist)
        .add_bundle_file("PlugIns/Widget.appex/Widget", common::minimal_macho())
        .build()
}

/// Zero timings and sort collections whose order is not meaningful.
fn normalize(v: &mut Value) {
    v["scan_duration_ms"] = Value::from(0);
    if let Some(log) = v["scan_log"].as_array_mut() {
        for entry in log {
            entry["elapsed_ms"] = Value::from(0);
            if let Some(step) = entry["step"].as_str() {
                if step.starts_with("Scan complete:") {
                    entry["step"] = Value::from("Scan complete");
                }
            }
        }
    }
    for key in ["findings", "secrets", "trackers", "framework_components"] {
        if let Some(arr) = v[key].as_array_mut() {
            arr.sort_by_key(|x| x.to_string());
        }
    }
    if let Some(summary) = v["owasp_summary"].as_object_mut() {
        for ids in summary.values_mut() {
            if let Some(arr) = ids.as_array_mut() {
                arr.sort_by_key(|x| x.to_string());
            }
        }
    }
}

#[test]
fn fixture_report_matches_golden() {
    let ipa = fixture();
    let opts = ScanOptions {
        rules_dir: None,
        min_severity: Severity::Info,
        network: false,
        show_progress: false,
        max_extracted_bytes: None,
        max_in_flight_bytes: None,
    };
    let report = scan_ipa(ipa.path(), &opts).expect("scan fixture");
    let mut actual = serde_json::to_value(&report).expect("serialize report");
    normalize(&mut actual);
    let rendered = serde_json::to_string_pretty(&actual).unwrap() + "\n";

    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(GOLDEN);
    if std::env::var_os("PAVISE_UPDATE_GOLDEN").is_some() {
        std::fs::write(&path, &rendered).expect("write golden file");
        return;
    }
    let expected = std::fs::read_to_string(&path).unwrap_or_else(|_| {
        panic!("{GOLDEN} missing; run with PAVISE_UPDATE_GOLDEN=1 to create it")
    });
    if expected != rendered {
        let first_diff = expected
            .lines()
            .zip(rendered.lines())
            .position(|(a, b)| a != b)
            .unwrap_or(expected.lines().count().min(rendered.lines().count()));
        panic!(
            "report differs from {GOLDEN} at line {}:\n  expected: {}\n  actual:   {}\n\
             Regenerate with PAVISE_UPDATE_GOLDEN=1 if the change is intended.",
            first_diff + 1,
            expected.lines().nth(first_diff).unwrap_or("<eof>"),
            rendered.lines().nth(first_diff).unwrap_or("<eof>"),
        );
    }
}
