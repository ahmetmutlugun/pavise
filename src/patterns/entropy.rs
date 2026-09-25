//! Entropy-based secret detection.
//!
//! Complements regex pattern matching by flagging strings with unusually high
//! Shannon entropy — a strong indicator of encoded secrets, tokens, or keys
//! that don't match any known pattern.

use crate::types::{SecretMatch, Severity};
use regex::Regex;
use std::sync::OnceLock;

static UUID_RE: OnceLock<Regex> = OnceLock::new();
static HEX_RE: OnceLock<Regex> = OnceLock::new();
static CONST_RE: OnceLock<Regex> = OnceLock::new();

fn uuid_re() -> &'static Regex {
    UUID_RE.get_or_init(|| {
        Regex::new(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
            .unwrap()
    })
}

fn hex_re() -> &'static Regex {
    HEX_RE.get_or_init(|| Regex::new(r"^[0-9a-fA-F]+$").unwrap())
}

fn const_re() -> &'static Regex {
    CONST_RE.get_or_init(|| Regex::new(r"^[A-Z_]{10,}$").unwrap())
}

/// Compute Shannon entropy over the byte distribution of `s`.
pub fn shannon_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    for &b in s.as_bytes() {
        counts[b as usize] += 1;
    }
    let len = s.len() as f64;
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / len;
            -p * p.log2()
        })
        .sum()
}

// Symbol prefixes that appear in Mach-O string tables and are never secrets.
const SYMBOL_PREFIXES: &[&str] = &[
    "_T0", "_TFC", "_TtC", "_TtP", "_$s", "$S", "$s", "_OBJC_", "__OBJC_", "_objc_", "__swift_",
];

/// Return true if the whole line is noise and none of its tokens should be flagged.
fn is_noise_line(line: &str, source_path: &str) -> bool {
    // Copyright strings often have high entropy due to names, years, and symbols (c) (r)
    let lower = line.to_lowercase();
    if lower.contains("copyright") || lower.contains("(c)") || lower.contains("©") {
        return true;
    }

    // Build artifacts and public config: Core Data model hashes, compiled
    // storyboards/nibs (Xcode object IDs like `I1M-u0-SdJ`), and Firebase's
    // GoogleService-Info.plist (public app/sender IDs; its API key is a regex rule).
    if source_path.contains(".momd/")
        || source_path.ends_with("VersionInfo.plist")
        || source_path.contains(".storyboardc/")
        || source_path.contains(".nib/")
        || source_path.ends_with("GoogleService-Info.plist")
    {
        return true;
    }

    // Swift / ObjC mangled symbols; checked on the line because tokenizing
    // strips the leading `$`.
    let trimmed = line.trim();
    if SYMBOL_PREFIXES.iter().any(|p| trimmed.starts_with(p)) {
        return true;
    }

    // Vendored JS/HTML template noise: template literals (`${...}`, backticks)
    // and inline HTML fragments score high but are code, not secrets.
    line.contains("${") || line.contains('`') || line.contains("<div")
}

/// Line words that mark a hex value as a digest rather than a credential.
const HASH_CONTEXT: &[&str] = &[
    "sha", "md5", "hash", "checksum", "crc", "digest", "uuid", "guid", "etag",
];
/// Line words that make a hash-length hex value worth flagging.
const SECRET_CONTEXT: &[&str] = &["key", "secret", "token", "password", "auth"];
/// Line words marking public key material (Tor bridge certs, pins, fingerprints).
const PUBLIC_CONTEXT: &[&str] = &["cert", "fingerprint", "pubkey", "public", "pin-sha256"];

/// Share of adjacent characters that switch class (upper/lower/digit/other).
/// Random base64 switches ~64% of the time; identifiers built from words and
/// numbers (`LaunchImage-1100-Portrait`, `qemu-aarch64-softmmu`) stay far lower.
fn class_switch_rate(s: &str) -> f64 {
    fn class(b: u8) -> u8 {
        match b {
            b'A'..=b'Z' => 0,
            b'a'..=b'z' => 1,
            b'0'..=b'9' => 2,
            _ => 3,
        }
    }
    // Separators don't count: `Name_3_10_` would otherwise look random.
    let b: Vec<u8> = s.bytes().filter(|c| !b"_-".contains(c)).collect();
    let switches = b.windows(2).filter(|w| class(w[0]) != class(w[1])).count();
    switches as f64 / (b.len().saturating_sub(1).max(1)) as f64
}

/// Return true if the token `s` is likely a false-positive and should NOT be flagged.
fn is_false_positive(s: &str, source_path: &str) -> bool {
    // UUID pattern: 8-4-4-4-12
    if uuid_re().is_match(s) {
        return true;
    }

    // Ignore high entropy in CSS/HTML/JS if it looks like Base64 (common for
    // embedded icons/images/fonts and inlined data blobs in vendored JS bundles).
    if (source_path.ends_with(".css")
        || source_path.ends_with(".html")
        || source_path.ends_with(".js"))
        && (s.contains("data:image/") || (s.len() > 32 && s.contains('=')))
    {
        return true;
    }

    // File path (starts with / ./ ../ and no = or :)
    if (s.starts_with('/') || s.starts_with("./") || s.starts_with("../"))
        && !s.contains('=')
        && !s.contains(':')
    {
        return true;
    }

    // All-uppercase constant name (e.g. SOME_CONFIG_KEY)
    if const_re().is_match(s) {
        return true;
    }

    // URLs — query parameters produce high entropy but carry no secret by themselves
    if s.contains("://") {
        return true;
    }

    // Dotted identifiers: bundle IDs (com.example.app), reverse-DNS class names,
    // or framework paths all score high on entropy and are never secrets
    if s.matches('.').count() >= 3 {
        return true;
    }

    // Swift / ObjC mangled symbol prefixes found in binary string tables
    if SYMBOL_PREFIXES.iter().any(|p| s.starts_with(p)) {
        return true;
    }

    // Hex tokens have their own checks in `scan_for_high_entropy`.
    if hex_re().is_match(s) {
        return !(s.bytes().any(|b| b.is_ascii_digit())
            && s.bytes().any(|b| b.is_ascii_alphabetic()));
    }

    // Require character class diversity: a real secret almost always contains
    // at least 3 of the 4 classes (uppercase, lowercase, digit, special), and
    // random tokens nearly always contain several digits where camelCase
    // identifiers have at most one or two.
    if s.bytes().filter(|b| b.is_ascii_digit()).count() < 2 {
        return true;
    }
    let has_upper = s.bytes().any(|b| b.is_ascii_uppercase());
    let has_lower = s.bytes().any(|b| b.is_ascii_lowercase());
    let has_digit = s.bytes().any(|b| b.is_ascii_digit());
    let has_special = s
        .bytes()
        .any(|b| !b.is_ascii_alphanumeric() && b.is_ascii_graphic());
    let class_count = [has_upper, has_lower, has_digit, has_special]
        .iter()
        .filter(|&&x| x)
        .count();
    if class_count < 3 {
        return true;
    }

    // Sequential ASCII runs: character encoding tables, charset strings, and
    // printable-ASCII ranges produce high entropy but are never secrets.
    // If >40% of adjacent characters differ by exactly 1 codepoint, skip.
    if s.len() >= 20 {
        let bytes = s.as_bytes();
        let sequential_count = bytes
            .windows(2)
            .filter(|w| {
                let diff = (w[0] as i16 - w[1] as i16).unsigned_abs();
                diff == 1
            })
            .count();
        if sequential_count * 100 / (bytes.len() - 1) > 40 {
            return true;
        }
    }

    false
}

/// Entropy of `s` relative to the most a string of its length and alphabet
/// could reach (log2 of min(len, alphabet size)). Raw Shannon entropy is capped
/// at log2(len), so a fixed threshold can never fire on 20–32 char tokens.
fn normalized_entropy(s: &str) -> f64 {
    let alphabet: f64 = if hex_re().is_match(s) {
        16.0
    } else if s
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b"+/=_-".contains(&b))
    {
        64.0
    } else {
        94.0
    };
    shannon_entropy(s) / (s.len() as f64).min(alphabet).log2()
}

/// Minimum normalized entropy for a token to look random. Expected entropy of
/// a random string falls slightly with length (repeated symbols), so the bar
/// does too; values sit near the 5th percentile of random base64/hex strings.
fn threshold(token: &str) -> f64 {
    if hex_re().is_match(token) {
        0.80
    } else {
        0.87 - 0.0009 * (token.len().saturating_sub(20)) as f64
    }
}

const MIN_TOKEN_LEN: usize = 20;
const MAX_TOKEN_LEN: usize = 128;
/// A file with more hits than this is a dataset (ROM/CRC tables, embedded
/// blobs), not a config file with a leaked credential.
const MAX_HITS_PER_FILE: usize = 20;

/// Scan lines of a text file for high-entropy tokens.
///
/// Each line is split into candidate tokens (runs of base64/identifier
/// characters); entropy is judged per token, never over a whole line.
/// Hits are Warning-only: entropy alone is a lead, not proof.
/// Lottie animation JSON (bodymovin export): the header keys sit at the top of
/// the file. Its path data and embedded image base64 are pure entropy noise;
/// regex secret rules still run on it.
pub fn is_lottie_json(data: &[u8]) -> bool {
    let head = &data[..data.len().min(512)];
    let head = String::from_utf8_lossy(head);
    head.trim_start().starts_with('{')
        && ["\"v\":", "\"fr\":", "\"ip\":", "\"op\":"]
            .iter()
            .all(|k| head.contains(k))
}

pub fn scan_for_high_entropy(strings: &[&str], source_path: &str) -> Vec<SecretMatch> {
    let mut results = Vec::new();
    for &line in strings {
        if is_noise_line(line, source_path) {
            continue;
        }
        let lower_line = line.to_lowercase();
        let has_secret_context = SECRET_CONTEXT.iter().any(|w| lower_line.contains(w));
        if !has_secret_context && PUBLIC_CONTEXT.iter().any(|w| lower_line.contains(w)) {
            continue;
        }
        // '.' and '=' split tokens: dotted names and `key=value` pairs are never
        // one secret (JWTs are covered by regex rules).
        let tokens = line
            .split(|c: char| !(c.is_ascii_alphanumeric() || "+/_-".contains(c)))
            .map(|t| t.trim_matches('-'));
        for token in tokens {
            if !(MIN_TOKEN_LEN..=MAX_TOKEN_LEN).contains(&token.len())
                || is_false_positive(token, source_path)
            {
                continue;
            }
            if hex_re().is_match(token) {
                if HASH_CONTEXT.iter().any(|w| lower_line.contains(w)) {
                    continue;
                }
                // MD5/SHA1/SHA256-length hex needs credential context.
                let hash_len = matches!(token.len(), 32 | 40 | 64);
                if hash_len && !has_secret_context {
                    continue;
                }
            } else if class_switch_rate(token) < 0.5 {
                continue;
            }
            if normalized_entropy(token) < threshold(token) {
                continue;
            }
            results.push(SecretMatch {
                rule_id: "QS-ENTROPY-001".to_string(),
                title: "High-Entropy String (Potential Secret)".to_string(),
                severity: Severity::Warning,
                matched_value: token.to_string(),
                file_path: Some(source_path.to_string()),
                cwe: Some("CWE-798".to_string()),
                owasp_mobile: None,
                owasp_masvs: None,
                remediation: Some(
                    "Verify whether this value is a credential. If so, remove it from the \
                    bundle and fetch it at runtime from an authenticated backend."
                        .to_string(),
                ),
            });
        }
    }
    if results.len() > MAX_HITS_PER_FILE {
        return Vec::new();
    }
    results
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Severity;

    #[test]
    fn test_shannon_entropy_uniform() {
        // All-same-char string has zero entropy.
        assert_eq!(shannon_entropy("aaaaaa"), 0.0);
    }

    #[test]
    fn test_shannon_entropy_known_value() {
        // "abcd": 4 distinct chars, each with p=0.25 → H = log2(4) = 2.0
        let h = shannon_entropy("abcd");
        assert!((h - 2.0).abs() < 1e-9, "expected ~2.0, got {h}");
    }

    #[test]
    fn test_high_entropy_detected() {
        // Upper, lower, digit, special (+); entropy hits are Warning-only.
        let token = "aB3cD4eF5gH6iJ7kL8mN9oP0qR1sT2uVwXyZ+AbCdEfGhIjKlMnOpQrStUvW";
        let results = scan_for_high_entropy(&[token], "test/file.json");
        assert_eq!(results.len(), 1, "Expected one match, got: {results:?}");
        assert_eq!(results[0].severity, Severity::Warning);
    }

    #[test]
    fn test_short_random_token_detected() {
        // 24 chars can never exceed raw entropy 4.6; the old 5.0 floor missed it.
        let line = r#"  "client_secret": "q7Xk2PzR9vLm4TnW8sYb3HcJ""#;
        let results = scan_for_high_entropy(&[line], "Config.json");
        assert_eq!(results.len(), 1, "got: {results:?}");
        assert_eq!(results[0].matched_value, "q7Xk2PzR9vLm4TnW8sYb3HcJ");
    }

    #[test]
    fn test_hex_secret_needs_context() {
        let key = "e3b0c44298fc1c149afbf4c8996fb924";
        let hit = scan_for_high_entropy(&[&format!("api_key = \"{key}\"")], "a.plist");
        assert_eq!(hit.len(), 1, "got: {hit:?}");
        assert!(scan_for_high_entropy(&[&format!("md5 = \"{key}\"")], "a.plist").is_empty());
        // Non-hash-length hex is flagged without context.
        let hit = scan_for_high_entropy(&["value: 9f86d081884c7d659a2feaa0c55ad015a3bf"], "a.yaml");
        assert_eq!(hit.len(), 1, "got: {hit:?}");
    }

    #[test]
    fn test_identifiers_not_flagged() {
        for s in [
            "CFBundleNameYDTSDKNameWDTXcode_",
            "UIApplicationSceneManifest_v2",
            "NSLocationWhenInUseUsageDescription",
            "GoogleService_Info_plist_v2_2024",
            "LaunchImage-1100-Portrait-2436h",
            "UITableViewController-yXS-6u-1AN",
            "PVHashing_1EA814DD982E971_PackageProduct",
            "fullscreenHeight=480",
            "G7YU7X7KRJ.SworIM.shareSheet",
            "issuecomment-1304826656",
            "RemoveMaskCount_3_10_",
        ] {
            assert!(scan_for_high_entropy(&[s], "Info.plist").is_empty(), "{s}");
        }
    }

    #[test]
    fn test_public_key_material_not_flagged() {
        let line = "obfs4 192.0.2.1:443 cert=bjRaMrr1BRiAW8IE9U5z27fQaYgOhX1UCmOpg2pFpoMvo6ZgQMzLsaTzzQNTlm7hN";
        assert!(scan_for_high_entropy(&[line], "builtin-bridges.json").is_empty());
    }

    #[test]
    fn test_dataset_file_dropped() {
        let lines: Vec<String> = (0..30)
            .map(|i| format!("<rom id=\"{i}\" data=\"q7Xk2PzR9vLm4TnW8sYb3Hc{i:02}\"/>"))
            .collect();
        let refs: Vec<&str> = lines.iter().map(String::as_str).collect();
        assert!(scan_for_high_entropy(&refs, "Database.xml").is_empty());
    }

    #[test]
    fn test_warning_entropy_detected() {
        // 36 distinct chars → maximal entropy for its length; upper, lower, digit
        let token = "aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890";
        let results = scan_for_high_entropy(&[token], "test/config.json");
        assert_eq!(
            results.len(),
            1,
            "Expected exactly one Warning match, got: {results:?}"
        );
        assert_eq!(results[0].severity, Severity::Warning);
    }

    #[test]
    fn test_uuid_filtered() {
        // Standard UUID pattern — matched by uuid_re() and filtered out
        let uuid = "550e8400-e29b-41d4-a716-446655440000";
        let results = scan_for_high_entropy(&[uuid], "test");
        assert!(
            results.is_empty(),
            "UUID should be filtered, got: {results:?}"
        );
    }

    #[test]
    fn test_hex_hash_filtered() {
        // 32-char hex string (MD5 hash) without credential context
        let hex = "d41d8cd98f00b204e9800998ecf8427e";
        let results = scan_for_high_entropy(&[hex], "test");
        assert!(
            results.is_empty(),
            "Hex hash should be filtered, got: {results:?}"
        );
    }

    #[test]
    fn test_file_path_filtered() {
        // File path starting with '/' — filtered by path check
        let path = "/usr/lib/libsomething.dylib";
        let results = scan_for_high_entropy(&[path], "test");
        assert!(
            results.is_empty(),
            "File path should be filtered, got: {results:?}"
        );
    }

    #[test]
    fn test_allcaps_constant_filtered() {
        // All-uppercase constant — filtered by const_re()
        let constant = "SOME_ALLCAPS_CONSTANT_NAME";
        let results = scan_for_high_entropy(&[constant], "test");
        assert!(
            results.is_empty(),
            "ALLCAPS constant should be filtered, got: {results:?}"
        );
    }

    #[test]
    fn test_sequential_ascii_charset_filtered() {
        // Character set / encoding table with sequential ASCII runs — not a secret
        let charset = r##"!"#$%&'()*+,-/015689ABOPS8[\^8`acfh^i0jk`lp{Q|}"##;
        let results = scan_for_high_entropy(&[charset], "Info.plist");
        assert!(
            results.is_empty(),
            "Sequential ASCII charset should be filtered, got: {results:?}"
        );
    }

    #[test]
    fn test_copyright_filtered() {
        let copyright = "Copyright © 1996-2017 VideoLAN and VLC Authors";
        let results = scan_for_high_entropy(&[copyright], "About.html");
        assert!(
            results.is_empty(),
            "Copyright string should be filtered, got: {results:?}"
        );
    }

    #[test]
    fn test_css_base64_filtered() {
        let base64_asset = "7Awh4rh28ygQCR6ISg8Awh4rh28ygQCR6ISg==";
        let results = scan_for_high_entropy(&[base64_asset], "style.css");
        assert!(
            results.is_empty(),
            "Base64 asset in CSS should be filtered, got: {results:?}"
        );
    }

    #[test]
    fn test_js_base64_filtered() {
        // Base64 data blobs in vendored JS bundles (e.g. hterm_all.js) are noise.
        let blob = "7Awh4rh28ygQCR6ISg8Awh4rh28ygQCR6ISg==";
        let results = scan_for_high_entropy(&[blob], "Payload/App.app/hterm_all.js");
        assert!(
            results.is_empty(),
            "Base64 blob in JS should be filtered, got: {results:?}"
        );
    }

    #[test]
    fn test_template_literal_filtered() {
        // Template-literal / HTML fragments from vendored JS must be filtered.
        let tmpl = "${copyImage}<div>${hterm.msg('NOTIFY_COPY')}</div>X9zQ";
        let results = scan_for_high_entropy(&[tmpl], "Payload/App.app/hterm_all.js");
        assert!(
            results.is_empty(),
            "Template literal should be filtered, got: {results:?}"
        );
    }

    #[test]
    fn test_lottie_detected() {
        let lottie = br#"{"v":"5.10.1","fr":60,"ip":0,"op":60,"w":90,"h":90,"layers":[]}"#;
        assert!(is_lottie_json(lottie));
        assert!(is_lottie_json(
            b"\n  { \"nm\": \"x\", \"v\": \"5.7\", \"ip\": 0, \"op\": 1, \"fr\": 30 }"
        ));
        assert!(!is_lottie_json(br#"{"api_key":"abc","v":"1"}"#));
        assert!(!is_lottie_json(b"[1,2,3]"));
    }

    #[test]
    fn test_coredata_versioninfo_filtered() {
        // Core Data .momd/VersionInfo.plist holds high-entropy model hashes.
        let hash = ",7U9u4XCfiZxqLPZXkAnaDWbKXabc123DEF456==";
        let results = scan_for_high_entropy(&[hash], "App.app/Model.momd/VersionInfo.plist");
        assert!(
            results.is_empty(),
            "Core Data version hash should be filtered, got: {results:?}"
        );
    }
}
