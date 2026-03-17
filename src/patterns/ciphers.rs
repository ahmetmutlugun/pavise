//! Weak cipher and insecure cryptography pattern detection.
//!
//! Scans extracted strings for iOS CommonCrypto constants that indicate the use
//! of deprecated or broken algorithms and modes.  These constants appear as C
//! string literals in `__TEXT,__cstring`, so the scan runs on all file types
//! including Mach-O binaries.

use crate::types::{Finding, Severity};

/// One pattern entry: (needle, rule_id, title, severity, description, cwe, owasp_mobile, owasp_masvs, remediation)
type Entry = (
    &'static str,
    &'static str,
    &'static str,
    Severity,
    &'static str,
    Option<&'static str>,
    Option<&'static str>,
    Option<&'static str>,
    &'static str,
);

fn patterns() -> Vec<Entry> {
    vec![
        (
            "kCCAlgorithmDES",
            "QS-CRYPTO-001",
            "Weak Cipher: DES Algorithm Detected",
            Severity::High,
            "The constant 'kCCAlgorithmDES' was found in extracted strings. DES uses a 56-bit \
            key that modern hardware can brute-force in hours. It is cryptographically broken \
            and must not be used to protect sensitive data.",
            Some("CWE-327"),
            Some("M5"),
            Some("MSTG-CRYPTO-4"),
            "Replace DES with AES-256 in GCM mode (kCCAlgorithmAES + kCCKeySizeAES256). \
            Generate a fresh random IV for every encryption operation.",
        ),
        (
            "kCCAlgorithm3DES",
            "QS-CRYPTO-002",
            "Weak Cipher: Triple-DES (3DES) Detected",
            Severity::Warning,
            "The constant 'kCCAlgorithm3DES' was found. Triple-DES provides ~112 bits of \
            effective security and is vulnerable to Sweet32 birthday attacks on long sessions. \
            NIST deprecated 3DES in 2023.",
            Some("CWE-327"),
            Some("M5"),
            Some("MSTG-CRYPTO-4"),
            "Migrate to AES-256-GCM. If legacy compatibility is required, prefer AES-128 at minimum.",
        ),
        (
            "kCCAlgorithmRC4",
            "QS-CRYPTO-003",
            "Weak Cipher: RC4 Stream Cipher Detected",
            Severity::High,
            "The constant 'kCCAlgorithmRC4' was found. RC4 has multiple practical cryptographic \
            weaknesses (biased key bytes, BEAST/NOMORE attacks) and was prohibited by RFC 7465 \
            for TLS use. It must not be used to protect confidentiality.",
            Some("CWE-327"),
            Some("M5"),
            Some("MSTG-CRYPTO-4"),
            "Replace RC4 with AES-256-GCM or ChaCha20-Poly1305.",
        ),
        (
            "kCCAlgorithmRC2",
            "QS-CRYPTO-004",
            "Weak Cipher: RC2 Algorithm Detected",
            Severity::High,
            "The constant 'kCCAlgorithmRC2' was found. RC2 is a 1987-vintage variable-key-size \
            cipher with known related-key weaknesses. It should not be used in new code.",
            Some("CWE-327"),
            Some("M5"),
            Some("MSTG-CRYPTO-4"),
            "Replace RC2 with AES-256-GCM.",
        ),
        (
            "kCCOptionECBMode",
            "QS-CRYPTO-005",
            "Insecure Block Cipher Mode: ECB Detected",
            Severity::High,
            "The constant 'kCCOptionECBMode' was found. ECB (Electronic Codebook) encrypts each \
            block independently under the same key. Identical plaintext blocks produce identical \
            ciphertext blocks, leaking data patterns (the 'ECB penguin' attack). ECB must not be \
            used for general data encryption.",
            Some("CWE-327"),
            Some("M5"),
            Some("MSTG-CRYPTO-3"),
            "Use GCM mode (CCCryptorGCM or kCCAlgorithmAES with a random IV and authentication tag). \
            Never reuse an IV under the same key.",
        ),
        (
            "kCCAlgorithmBlowfish",
            "QS-CRYPTO-006",
            "Outdated Cipher: Blowfish Algorithm Detected",
            Severity::Warning,
            "The constant 'kCCAlgorithmBlowfish' was found. Blowfish uses a 64-bit block size, \
            making it vulnerable to birthday attacks (Sweet32) when large volumes of data are \
            encrypted under the same key. It is not recommended for new implementations.",
            Some("CWE-327"),
            Some("M5"),
            Some("MSTG-CRYPTO-4"),
            "Replace Blowfish with AES-256-GCM.",
        ),
    ]
}

/// Scan extracted text for weak cipher algorithm constants.
///
/// Runs on all file types — CommonCrypto constants appear as C string literals
/// in Mach-O `__TEXT,__cstring` and are extracted by `extract_printable_strings`.
pub fn scan_for_weak_ciphers(text: &str, source_path: &str) -> Vec<Finding> {
    let mut findings = Vec::new();

    for (needle, id, title, severity, description, cwe, owasp_mobile, owasp_masvs, remediation) in
        patterns()
    {
        if text.contains(needle) {
            findings.push(Finding {
                id: id.to_string(),
                title: title.to_string(),
                description: description.to_string(),
                severity,
                category: "cryptography".to_string(),
                cwe: cwe.map(|s| s.to_string()),
                owasp_mobile: owasp_mobile.map(|s| s.to_string()),
                owasp_masvs: owasp_masvs.map(|s| s.to_string()),
                evidence: vec![format!("'{}' detected in {}", needle, source_path)],
                remediation: Some(remediation.to_string()),
            });
        }
    }

    findings
}
