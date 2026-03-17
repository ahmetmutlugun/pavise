mod common;

use pavise::types::Severity;
use pavise::{scan_ipa, ScanOptions};

fn default_opts() -> ScanOptions {
    ScanOptions {
        rules_dir: common::rules_dir(),
        min_severity: Severity::Info,
        network: false,
        show_progress: false,
    }
}

#[test]
fn test_minimal_scan_succeeds() {
    let ipa = common::IpaBuilder::new("TestApp").build();
    let report = scan_ipa(ipa.path(), &default_opts()).expect("scan_ipa should succeed");
    assert_eq!(report.app_info.name, "TestApp");
}

#[test]
fn test_secret_in_plist_detected() {
    // AWS key pattern: AKIA[0-9A-Z]{16}
    let plist_content = r#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
  <key>AWSKey</key><string>AKIAIOSFODNN7EXAMPLE1234</string>
</dict></plist>"#;

    let ipa = common::IpaBuilder::new("TestApp")
        .add_bundle_file("Config.plist", plist_content)
        .build();

    let report = scan_ipa(ipa.path(), &default_opts()).expect("scan_ipa should succeed");
    let aws_secret = report.secrets.iter().find(|s| s.rule_id == "QS-SEC-002");
    assert!(
        aws_secret.is_some(),
        "Expected QS-SEC-002 secret from Config.plist, secrets found: {:?}",
        report
            .secrets
            .iter()
            .map(|s| &s.rule_id)
            .collect::<Vec<_>>()
    );
}

#[test]
fn test_cert_file_triggers_finding() {
    let ipa = common::IpaBuilder::new("TestApp")
        .add_bundle_file("certs/server.p12", b"fake pkcs12 data")
        .build();

    let report = scan_ipa(ipa.path(), &default_opts()).expect("scan_ipa should succeed");
    let cert_finding = report.findings.iter().find(|f| f.id == "QS-CERT-001");
    assert!(
        cert_finding.is_some(),
        "Expected QS-CERT-001 finding for .p12 file, findings: {:?}",
        report.findings.iter().map(|f| &f.id).collect::<Vec<_>>()
    );
}

#[test]
fn test_sqlite_triggers_finding() {
    let ipa = common::IpaBuilder::new("TestApp")
        .add_bundle_file("data/app.sqlite", b"SQLite format 3\x00")
        .build();

    let report = scan_ipa(ipa.path(), &default_opts()).expect("scan_ipa should succeed");
    let db_finding = report.findings.iter().find(|f| f.id == "QS-STORE-001");
    assert!(
        db_finding.is_some(),
        "Expected QS-STORE-001 finding for .sqlite file, findings: {:?}",
        report.findings.iter().map(|f| &f.id).collect::<Vec<_>>()
    );
}

#[test]
fn test_http_in_plist_triggers_finding() {
    let plist_content = r#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
  <key>APIBaseURL</key><string>http://api.mycompany.com/v1</string>
</dict></plist>"#;

    let ipa = common::IpaBuilder::new("TestApp")
        .add_bundle_file("Settings.plist", plist_content)
        .build();

    let report = scan_ipa(ipa.path(), &default_opts()).expect("scan_ipa should succeed");
    let http_finding = report.findings.iter().find(|f| f.id == "QS-NET-001");
    assert!(
        http_finding.is_some(),
        "Expected QS-NET-001 finding for HTTP URL in plist, findings: {:?}",
        report.findings.iter().map(|f| &f.id).collect::<Vec<_>>()
    );
}
