mod common;

use pavise::patterns::engine::{extract_printable_strings, PatternEngine};
use pavise::types::Severity;

#[test]
fn test_load_real_rules() {
    let engine = PatternEngine::load(&common::rules_dir()).expect("PatternEngine::load should succeed");
    assert!(engine.rule_count() > 0, "Expected > 0 rules loaded from secrets.yaml");
}

#[test]
fn test_aws_key_detected() {
    let engine = PatternEngine::load(&common::rules_dir()).unwrap();
    // AWS access key ID pattern: AKIA[0-9A-Z]{16}
    let text = "aws_key=AKIAIOSFODNN7EXAMPLE1234";
    let matches = engine.scan(text, "config.json");
    let aws_match = matches.iter().find(|m| m.rule_id == "QS-SEC-002");
    assert!(aws_match.is_some(), "Expected QS-SEC-002 match for AWS key, got: {matches:?}");
    assert_eq!(aws_match.unwrap().severity, Severity::High);
}

#[test]
fn test_private_key_detected() {
    let engine = PatternEngine::load(&common::rules_dir()).unwrap();
    let text = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQ...\n-----END RSA PRIVATE KEY-----";
    let matches = engine.scan(text, "keys/server.pem");
    let key_match = matches.iter().find(|m| m.rule_id == "QS-SEC-004");
    assert!(key_match.is_some(), "Expected QS-SEC-004 match for private key, got: {matches:?}");
    assert_eq!(key_match.unwrap().severity, Severity::High);
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
    assert!(result.contains("hello world"), "Expected 'hello world' in output");
    assert!(result.contains("another string here"), "Expected 'another string here' in output");
    assert!(!result.contains("short"), "'short' is < min_len and should be excluded");
}
