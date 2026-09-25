mod common;

use pavise::types::Severity;
use pavise::{scan_ipa, ScanOptions};

fn default_opts() -> ScanOptions {
    ScanOptions {
        rules_dir: Some(common::rules_dir()),
        min_severity: Severity::Info,
        network: false,
        show_progress: false,
        max_extracted_bytes: None,
        max_in_flight_bytes: None,
    }
}

#[test]
fn test_minimal_scan_succeeds() {
    let ipa = common::IpaBuilder::new("TestApp").build();
    let report = scan_ipa(ipa.path(), &default_opts()).expect("scan_ipa should succeed");
    assert_eq!(report.app_info.name, "TestApp");
}

#[test]
fn test_unparseable_main_binary_fails_scan() {
    // A garbage main executable must not yield a (score-inflated) report.
    let ipa = common::IpaBuilder::new("TestApp")
        .main_binary(vec![0u8; 4])
        .build();
    let err = scan_ipa(ipa.path(), &default_opts()).unwrap_err();
    assert!(format!("{:#}", err).contains("main binary"), "{:#}", err);
}

#[test]
fn test_embedded_rules_used_by_default() {
    let plist_content = r#"<plist version="1.0"><dict>
  <key>AWSKey</key><string>AKIAIOSFODNN7EXAMPLE</string>
</dict></plist>"#;
    let ipa = common::IpaBuilder::new("TestApp")
        .add_bundle_file("Config.plist", plist_content)
        .build();
    let opts = ScanOptions {
        rules_dir: None,
        ..default_opts()
    };
    let report = scan_ipa(ipa.path(), &opts).expect("scan_ipa should succeed");
    let aws = report
        .secrets
        .iter()
        .find(|s| s.rule_id == "QS-SEC-002")
        .expect("AWS key");
    // Secrets carry the rule's CWE and the OWASP 2024 mapping, and appear in
    // the OWASP summary.
    assert_eq!(aws.cwe.as_deref(), Some("CWE-798"));
    assert_eq!(aws.owasp_mobile.as_deref(), Some("M1"));
    assert!(report.owasp_summary["M1"].contains(&"QS-SEC-002".to_string()));
}

#[test]
fn test_secret_in_plist_detected() {
    // AWS key pattern: AKIA[0-9A-Z]{16}
    let plist_content = r#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
  <key>AWSKey</key><string>AKIAIOSFODNN7EXAMPLE</string>
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
fn test_public_cert_is_info_not_high() {
    // A bundled public certificate (common pinning anchor) must be reported as
    // an informational QS-CERT-002 hotspot, not a high-severity QS-CERT-001
    // private-key exposure.
    let pem = b"-----BEGIN CERTIFICATE-----\nMIIBfakecertdata==\n-----END CERTIFICATE-----\n";
    let ipa = common::IpaBuilder::new("TestApp")
        .add_bundle_file("certs/pinned.pem", pem)
        .build();

    let report = scan_ipa(ipa.path(), &default_opts()).expect("scan_ipa should succeed");
    assert!(
        report.findings.iter().any(|f| f.id == "QS-CERT-002"),
        "Expected QS-CERT-002 for a public certificate, findings: {:?}",
        report.findings.iter().map(|f| &f.id).collect::<Vec<_>>()
    );
    assert!(
        !report.findings.iter().any(|f| f.id == "QS-CERT-001"),
        "Public certificate must not raise a high-severity QS-CERT-001 finding"
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
fn test_doc_urls_are_not_endpoints() {
    // License text and library JS comments name hosts the app never contacts.
    let license = "See http://www.gnu.org-mirror.net/COPYING-ish and https://lists.example-lib.io/";
    let js = "// docs: http://unixpapa.example-docs.io/js/key.html\n\
              // see https://developer.example-docs.io/x";
    let ipa = common::IpaBuilder::new("TestApp")
        .add_bundle_file("License.plist", license)
        .add_bundle_file("hterm/hterm_all.js", js)
        .add_bundle_file(
            "Settings.plist",
            "<string>https://api.mycompany.com/v1</string>",
        )
        .build();

    let report = scan_ipa(ipa.path(), &default_opts()).expect("scan_ipa should succeed");
    let domains: Vec<&str> = report.domains.iter().map(|d| d.domain.as_str()).collect();
    assert!(!domains.contains(&"lists.example-lib.io"), "{domains:?}");
    // Library JS URLs stay in the inventory but are not scored or counted.
    let http = report
        .findings
        .iter()
        .find(|f| f.id == "QS-NET-001")
        .expect("QS-NET-001");
    assert_eq!(http.severity, pavise::types::Severity::Info);
    assert!(
        report.findings.iter().all(|f| f.id != "QS-NET-004"),
        "one endpoint domain must not trigger the pinning check"
    );
}

#[test]
fn test_end_of_life_libraries_detected() {
    // jQuery 1.x and Python 3.8 ended years ago; Bootstrap 5 is supported.
    let js = "/*! jQuery v1.12.4 | (c) jQuery Foundation | jquery.org/license */";
    let css = "/*! Bootstrap v5.3.2 (https://getbootstrap.com/) */";
    let ipa = common::IpaBuilder::new("TestApp")
        .add_bundle_file("www/js/jquery.min.js", js)
        .add_bundle_file("www/css/bootstrap.min.css", css)
        .add_bundle_file(
            "Frameworks/Python.framework/lib/python3.8/os.py",
            "import abc",
        )
        .build();

    let report = scan_ipa(ipa.path(), &default_opts()).expect("scan_ipa should succeed");
    let versions: Vec<(&str, &str)> = report
        .framework_components
        .iter()
        .filter_map(|c| Some((c.name.as_str(), c.version.as_deref()?)))
        .collect();
    for want in [
        ("jQuery", "1.12.4"),
        ("Bootstrap", "5.3.2"),
        ("Python", "3.8"),
    ] {
        assert!(
            versions.contains(&want),
            "{want:?} missing from {versions:?}"
        );
    }
    let eol: Vec<&str> = report
        .findings
        .iter()
        .filter(|f| f.id == "QS-SCA-001")
        .map(|f| f.title.as_str())
        .collect();
    assert_eq!(
        eol.len(),
        2,
        "one finding per end-of-life library, no Bootstrap: {eol:?}"
    );
    assert!(eol.contains(&"End-of-Life jQuery Bundled"), "{eol:?}");
    assert!(eol.contains(&"End-of-Life Python Bundled"), "{eol:?}");
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

#[test]
fn test_non_ascii_bundle_without_utf8_flag() {
    // Some IPAs store UTF-8 names without the ZIP UTF-8 flag (bit 11); the zip
    // crate then decodes them as CP437 and the main binary is never found.
    let ipa = common::IpaBuilder::new("המגן").build();
    let mut buf = std::fs::read(ipa.path()).unwrap();
    for i in 0..buf.len().saturating_sub(10) {
        let off = match &buf[i..i + 4] {
            b"PK\x03\x04" => 6, // local file header: general purpose flags
            b"PK\x01\x02" => 8, // central directory header
            _ => continue,
        };
        buf[i + off + 1] &= !0x08;
    }
    let tmp = tempfile::Builder::new().suffix(".ipa").tempfile().unwrap();
    std::fs::write(tmp.path(), &buf).unwrap();

    let report = scan_ipa(tmp.path(), &default_opts()).expect("scan_ipa should succeed");
    assert!(report.main_binary.is_some());
}

#[test]
fn test_plist_key_value_secret_detected() {
    // Key and value live in separate XML elements; only the parsed pass sees
    // them as an assignment.
    let plist_content = r#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
  <key>api_key</key><string>a1b2c3d4e5f6g7h8i9j0k1l2</string>
  <key>ServerPassword</key><string>Tr0ub4dor3xyz</string>
</dict></plist>"#;
    let ipa = common::IpaBuilder::new("TestApp")
        .add_bundle_file("Config.plist", plist_content)
        .build();
    let report = scan_ipa(ipa.path(), &default_opts()).expect("scan_ipa should succeed");
    let ids: Vec<&str> = report.secrets.iter().map(|s| s.rule_id.as_str()).collect();
    assert!(ids.contains(&"QS-SEC-005"), "secrets: {:?}", ids);
    assert!(ids.contains(&"QS-SEC-006"), "secrets: {:?}", ids);
}

fn profile(name: &str, get_task_allow: bool) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
  <key>Name</key><string>{name}</string>
  <key>Entitlements</key><dict>
    <key>get-task-allow</key><{get_task_allow}/>
  </dict>
</dict></plist>"#
    )
}

#[test]
fn test_app_extension_analyzed_and_main_profile_used() {
    let ext_plist = r#"<plist version="1.0"><dict>
  <key>CFBundleExecutable</key><string>ShareExt</string>
</dict></plist>"#;
    let ipa = common::IpaBuilder::new("TestApp")
        // Sorts before the main bundle's profile, so `ends_with` would pick it.
        .add_bundle_file(
            "PlugIns/Share.appex/embedded.mobileprovision",
            profile("Extension Profile", true),
        )
        .add_bundle_file("PlugIns/Share.appex/Info.plist", ext_plist)
        .add_bundle_file("PlugIns/Share.appex/ShareExt", common::minimal_macho())
        .add_bundle_file("embedded.mobileprovision", profile("Main Profile", false))
        .build();
    let report = scan_ipa(ipa.path(), &default_opts()).expect("scan");

    let paths: Vec<&str> = report
        .extension_binaries
        .iter()
        .map(|b| b.path.as_str())
        .collect();
    assert_eq!(
        paths,
        vec!["Payload/TestApp.app/PlugIns/Share.appex/ShareExt"]
    );
    let prov = report.provisioning.expect("provisioning parsed");
    assert_eq!(prov.name.as_deref(), Some("Main Profile"));
}

#[test]
fn test_privacy_manifest_and_plist_platform_checks() {
    let ipa = common::IpaBuilder::new("TestApp").build();
    let report = scan_ipa(ipa.path(), &default_opts()).expect("scan");
    let ids: Vec<&str> = report.findings.iter().map(|f| f.id.as_str()).collect();
    // Fixture has no PrivacyInfo.xcprivacy and MinimumOSVersion 14.0.
    assert!(ids.contains(&"QS-PRIV-001"), "{:?}", ids);
    assert!(ids.contains(&"QS-PLIST-001"), "{:?}", ids);

    let manifest = r#"<plist version="1.0"><dict>
  <key>NSPrivacyAccessedAPITypes</key><array/>
</dict></plist>"#;
    let ipa = common::IpaBuilder::new("TestApp")
        .add_bundle_file("PrivacyInfo.xcprivacy", manifest)
        .build();
    let report = scan_ipa(ipa.path(), &default_opts()).expect("scan");
    assert!(report.findings.iter().all(|f| f.id != "QS-PRIV-001"));
}
