mod common;

use pavise::patterns::engine::{extract_printable_strings, PatternEngine};
use pavise::types::Severity;

#[test]
fn test_load_real_rules() {
    let engine = PatternEngine::load(Some(&common::rules_dir()))
        .expect("PatternEngine::load should succeed");
    assert!(
        engine.rule_count() > 0,
        "Expected > 0 rules loaded from secrets.yaml"
    );
}

#[test]
fn test_aws_key_detected() {
    let engine = PatternEngine::load(Some(&common::rules_dir())).unwrap();
    // AWS access key ID pattern: AKIA[0-9A-Z]{16}
    let text = "aws_key=AKIAIOSFODNN7EXAMPLE";
    let matches = engine.scan(text, "config.json");
    let aws_match = matches.iter().find(|m| m.rule_id == "QS-SEC-002");
    assert!(
        aws_match.is_some(),
        "Expected QS-SEC-002 match for AWS key, got: {matches:?}"
    );
    assert_eq!(aws_match.unwrap().severity, Severity::High);
}

#[test]
fn test_private_key_detected() {
    let engine = PatternEngine::load(Some(&common::rules_dir())).unwrap();
    // A real PEM key: banner followed by a base64 body. QS-SEC-004 now requires
    // the body, not just the banner.
    let text = "-----BEGIN RSA PRIVATE KEY-----\n\
        MIIEowIBAAKCAQEAq7BFUpkGp3+LQmlQYx2eqzDV+xeG8kx/sQFV18S5JCMe\n\
        Vu0XAVdAOr4QFx4uF6t8qGYwLPpYz0bYzVqQ1mF6sJrZ4Hn8K9vN2pQ==\n\
        -----END RSA PRIVATE KEY-----";
    let matches = engine.scan(text, "keys/server.pem");
    let key_match = matches.iter().find(|m| m.rule_id == "QS-SEC-004");
    assert!(
        key_match.is_some(),
        "Expected QS-SEC-004 match for private key, got: {matches:?}"
    );
    assert_eq!(key_match.unwrap().severity, Severity::High);
}

#[test]
fn test_private_key_banner_only_not_flagged() {
    // The bare PEM banner appears as a string constant in crypto libraries that
    // ship no key. It must NOT trigger QS-SEC-004 (false-positive fix).
    let engine = PatternEngine::load(Some(&common::rules_dir())).unwrap();
    let text = "log: failed to parse -----BEGIN RSA PRIVATE KEY----- header";
    let matches = engine.scan(text, "Frameworks/libcrypto.dylib");
    assert!(
        !matches.iter().any(|m| m.rule_id == "QS-SEC-004"),
        "Banner without a key body must not match QS-SEC-004, got: {matches:?}"
    );
}

#[test]
fn test_extract_printable_strings() {
    // Binary data with two embedded ASCII runs separated by non-printable bytes
    let mut data = Vec::new();
    data.extend_from_slice(b"\x00\x01\x02");
    data.extend_from_slice(b"hello world"); // 11 chars >= 6
    data.extend_from_slice(b"\x00\x01");
    data.extend_from_slice(b"short"); // 5 chars < 6, should be excluded
    data.extend_from_slice(b"\x00");
    data.extend_from_slice(b"another string here"); // 19 chars >= 6
    data.push(b'\x00');

    let result = extract_printable_strings(&data, 6);
    assert!(
        result.contains("hello world"),
        "Expected 'hello world' in output"
    );
    assert!(
        result.contains("another string here"),
        "Expected 'another string here' in output"
    );
    assert!(
        !result.contains("short"),
        "'short' is < min_len and should be excluded"
    );
}

fn rule_hits(text: &str, rule_id: &str) -> Vec<String> {
    let engine = PatternEngine::load(None).unwrap();
    engine
        .scan(text, "Payload/App.app/App")
        .into_iter()
        .filter(|m| m.rule_id == rule_id)
        .map(|m| m.matched_value)
        .collect()
}

#[test]
fn test_matches_never_span_extracted_strings() {
    // extract_printable_strings joins runs with '\n'; a match must not glue
    // two unrelated strings together.
    assert!(rule_hits("password: \"\n_pageController@941137974\"", "QS-SEC-006").is_empty());
    assert!(rule_hits(
        "Bearer\nMSALAuthenticationSchemeProtocolInternal",
        "QS-SEC-014"
    )
    .is_empty());
    assert_eq!(
        rule_hits("password = \"hunter2hunter2\"", "QS-SEC-006").len(),
        1
    );
}

#[test]
fn test_minified_js_password_not_flagged() {
    let js = r#"password: "+t.hex;e=t.hex}if(void 0!==t.utf8&&(e=Rt(t.utf8)),void 0!=="#;
    assert!(rule_hits(js, "QS-SEC-006").is_empty());
}

#[test]
fn test_rust_mangled_symbol_not_a_token() {
    assert!(rule_hits(
        "_ZN3std10hf_shared8displace17h4b553b516e2f71e7E",
        "QS-SEC-021"
    )
    .is_empty());
    assert!(rule_hits("hf_shared8displace17h4b553b516e2f71e7E", "QS-SEC-021").is_empty());
    assert_eq!(
        rule_hits("hf_AbCdEfGhIjKlMnOpQrStUvWxYz01234567", "QS-SEC-021").len(),
        1
    );
}

#[test]
fn test_bearer_requires_token_like_value() {
    assert!(rule_hits("Bearer Acehnese-Latn-BOUQUETahititidAcerca", "QS-SEC-014").is_empty());
    assert_eq!(
        rule_hits("Bearer 8f3a9c2e7b1d4f6a0c5e9b2d7a", "QS-SEC-014").len(),
        1
    );
}

#[test]
fn test_supabase_requires_service_role() {
    let header = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";
    let sig = "dGhpc19pc19hX2Zha2Vfc2lnbmF0dXJlX2Zvcl90ZXN0cw";
    let service = "eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImFiY2RlZmdoaWprbG1ub3BxcnN0Iiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImlhdCI6MTcwMDAwMDAwMCwiZXhwIjoyMDAwMDAwMDAwfQ";
    let anon = "eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImFiY2RlZmdoaWprbG1ub3BxcnN0Iiwicm9sZSI6ImFub24iLCJpYXQiOjE3MDAwMDAwMDAsImV4cCI6MjAwMDAwMDAwMH0";
    assert_eq!(
        rule_hits(&format!("{header}.{service}.{sig}"), "QS-SEC-024").len(),
        1
    );
    assert!(rule_hits(&format!("{header}.{anon}.{sig}"), "QS-SEC-024").is_empty());
}

#[test]
fn test_new_token_formats() {
    let proj = format!("sk-proj-{}", "Ab1_".repeat(20));
    assert_eq!(rule_hits(&proj, "QS-SEC-023").len(), 1);
    let pat = format!("github_pat_{}", "a1B2".repeat(20) + "xy");
    assert_eq!(rule_hits(&pat, "QS-SEC-010").len(), 1);
    assert_eq!(
        rule_hits("gho_abcdefghijklmnopqrstuvwxyz0123456789", "QS-SEC-010").len(),
        1
    );
}

#[test]
fn test_slack_tokens() {
    // Assembled at runtime so push-protection secret scanners don't flag the fixture.
    let bot = format!(
        "xox{}-2718281828-3141592653589-Zq8Rw3LkTp9Vn2Hs6Yc4Ub7M",
        "b"
    );
    assert_eq!(rule_hits(&bot, "QS-SEC-031").len(), 1);
    let user = format!(
        "xox{}-2718281828-1618033988-3141592653589-9f2c4a7e1b8d3f6a0c5e2b9d7a4f1c8e",
        "p"
    );
    assert_eq!(rule_hits(&user, "QS-SEC-031").len(), 1);
    // Prefix alone, or a short suffix, is not a token.
    assert!(rule_hits("xoxb-", "QS-SEC-031").is_empty());
    assert!(rule_hits("xoxb-1234-abcdef", "QS-SEC-031").is_empty());
}

#[test]
fn test_connection_string_requires_credentials() {
    assert!(rule_hits("mongodb://localhost:27017/test", "QS-SEC-027").is_empty());
    assert!(rule_hits("redis://cache.internal:6379", "QS-SEC-027").is_empty());
    assert_eq!(
        rule_hits("postgres://admin:s3cret@db.example.com/prod", "QS-SEC-027").len(),
        1
    );
}

#[test]
fn test_stripe_publishable_key_is_info() {
    let engine = PatternEngine::load(None).unwrap();
    let m = engine.scan("pk_live_abcdefghijklmnopqrstuvwx", "a");
    assert_eq!(m.len(), 1);
    assert_eq!(
        (m[0].rule_id.as_str(), &m[0].severity),
        ("QS-SEC-029", &Severity::Info)
    );
}
