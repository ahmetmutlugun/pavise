//! Content-aware classification of embedded certificate and key files.
//!
//! Flagging every `.der`/`.pem`/`.p12` file inside an IPA as a "private key
//! exposure" produces false positives: a bundled `.der`/`.cer` is almost
//! always a *public* X.509 certificate used for certificate pinning — a good
//! practice, not a leaked secret. Only private keys and PKCS#12 keystores
//! carry extractable key material.
//!
//! This module inspects each file's bytes (PEM markers, PKCS#12 magic) so the
//! scanner can emit a high-severity finding for genuine private-key exposure
//! and a low-severity inventory hotspot for public certificates.

/// What a bundled certificate/key file actually contains.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertKind {
    /// Unencrypted private key material (PEM `PRIVATE KEY`, raw `.key`). High risk.
    PrivateKey,
    /// Password-protected key container: PKCS#12 (`.p12`/`.pfx`) or PEM
    /// `ENCRYPTED PRIVATE KEY`. The key is present but wrapped — still a leak,
    /// as the passphrase is typically weak or shipped alongside.
    EncryptedKeystore,
    /// A public X.509 certificate (PEM `CERTIFICATE`, binary DER). Commonly a
    /// legitimate pinning anchor; informational rather than a vulnerability.
    PublicCertificate,
}

impl CertKind {
    /// True if this kind carries private (secret) key material.
    pub fn is_private(self) -> bool {
        matches!(self, CertKind::PrivateKey | CertKind::EncryptedKeystore)
    }
}

/// Classify a bundled cert/key file from its path and contents.
///
/// Returns `None` for files that match a cert/key extension but whose contents
/// don't look like any recognized certificate or key format (e.g. an empty
/// placeholder or an unrelated `.key` text file) — the caller skips those to
/// avoid noise.
pub fn classify(path: &str, data: &[u8]) -> Option<CertKind> {
    let lower = path.to_lowercase();

    // PKCS#12 keystores are binary; the extension is the reliable signal and the
    // container always embeds a private key.
    if lower.ends_with(".p12") || lower.ends_with(".pfx") {
        return Some(CertKind::EncryptedKeystore);
    }

    // PEM (and most `.key`/`.pem`/`.crt`) files are ASCII-armored: inspect the
    // BEGIN markers, which unambiguously state the payload type.
    if let Some(kind) = classify_pem(data) {
        return Some(kind);
    }

    // Binary DER: `.der`/`.cer` are conventionally public certificates. A
    // DER-encoded private key is possible but rare and indistinguishable from a
    // cert by a cheap byte check, so we classify by the (strong) convention and
    // let the filename override when it explicitly names a key.
    if lower.ends_with(".der") || lower.ends_with(".cer") || lower.ends_with(".crt") {
        if looks_like_der(data) {
            return Some(CertKind::PublicCertificate);
        }
        return None;
    }

    // A `.key` file with no recognizable PEM marker: treat as a raw private key
    // only if it has non-trivial content (avoids flagging empty stubs).
    if lower.ends_with(".key") && data.len() > 32 {
        return Some(CertKind::PrivateKey);
    }

    None
}

/// Scan PEM `-----BEGIN ...-----` markers. A file containing any private-key
/// marker is treated as a private key even if it also bundles the public chain.
fn classify_pem(data: &[u8]) -> Option<CertKind> {
    // PEM is ASCII; bound the scan so we never stringify a large binary blob.
    let head = &data[..data.len().min(64 * 1024)];
    let text = match std::str::from_utf8(head) {
        Ok(t) => t,
        // Lossy is fine for marker matching — markers are pure ASCII.
        Err(_) => return classify_pem_bytes(head),
    };

    if text.contains("-----BEGIN ENCRYPTED PRIVATE KEY-----") {
        return Some(CertKind::EncryptedKeystore);
    }
    if text.contains("PRIVATE KEY-----") {
        // Covers "BEGIN PRIVATE KEY", "BEGIN RSA PRIVATE KEY",
        // "BEGIN EC PRIVATE KEY", "BEGIN OPENSSH PRIVATE KEY", etc.
        return Some(CertKind::PrivateKey);
    }
    if text.contains("-----BEGIN CERTIFICATE-----")
        || text.contains("-----BEGIN PUBLIC KEY-----")
        || text.contains("-----BEGIN CERTIFICATE REQUEST-----")
    {
        return Some(CertKind::PublicCertificate);
    }
    None
}

/// Fallback marker scan over raw bytes when the head isn't valid UTF-8.
fn classify_pem_bytes(head: &[u8]) -> Option<CertKind> {
    let contains = |needle: &[u8]| head.windows(needle.len()).any(|w| w == needle);
    if contains(b"ENCRYPTED PRIVATE KEY-----") {
        return Some(CertKind::EncryptedKeystore);
    }
    if contains(b"PRIVATE KEY-----") {
        return Some(CertKind::PrivateKey);
    }
    if contains(b"BEGIN CERTIFICATE-----") {
        return Some(CertKind::PublicCertificate);
    }
    None
}

/// Cheap sanity check that a blob is DER: starts with a SEQUENCE tag (0x30) and
/// a plausible length encoding. Rejects PNGs, plists, etc. that share a `.cer`
/// extension by mistake.
fn looks_like_der(data: &[u8]) -> bool {
    data.len() > 16 && data[0] == 0x30 && (data[1] == 0x82 || data[1] == 0x81 || data[1] < 0x80)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pem_private_key_is_private() {
        let pem = b"-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n-----END RSA PRIVATE KEY-----\n";
        assert_eq!(classify("k.pem", pem), Some(CertKind::PrivateKey));
        assert!(classify("k.pem", pem).unwrap().is_private());
    }

    #[test]
    fn pem_encrypted_key_is_keystore() {
        let pem = b"-----BEGIN ENCRYPTED PRIVATE KEY-----\nMIIF...\n-----END ENCRYPTED PRIVATE KEY-----";
        assert_eq!(classify("k.pem", pem), Some(CertKind::EncryptedKeystore));
    }

    #[test]
    fn pem_certificate_is_public() {
        let pem = b"-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----\n";
        assert_eq!(classify("server.pem", pem), Some(CertKind::PublicCertificate));
        assert!(!classify("server.pem", pem).unwrap().is_private());
    }

    #[test]
    fn full_chain_with_key_is_private() {
        // A bundle holding both the chain and the private key is a key leak.
        let pem = b"-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n\
                    -----BEGIN PRIVATE KEY-----\nMIIE\n-----END PRIVATE KEY-----\n";
        assert_eq!(classify("bundle.pem", pem), Some(CertKind::PrivateKey));
    }

    #[test]
    fn p12_is_keystore_regardless_of_content() {
        assert_eq!(classify("id.p12", b"\x30\x82binarygarbage"), Some(CertKind::EncryptedKeystore));
        assert_eq!(classify("id.pfx", &[0u8; 8]), Some(CertKind::EncryptedKeystore));
    }

    #[test]
    fn binary_der_is_public_cert() {
        // DER SEQUENCE header (0x30 0x82 len len ...).
        let mut der = vec![0x30, 0x82, 0x01, 0x00];
        der.extend(std::iter::repeat(0xAB).take(64));
        assert_eq!(classify("anchor.der", &der), Some(CertKind::PublicCertificate));
        assert_eq!(classify("anchor.cer", &der), Some(CertKind::PublicCertificate));
    }

    #[test]
    fn der_extension_on_non_der_is_skipped() {
        // A PNG mistakenly named .cer must not be reported as a certificate.
        let png = b"\x89PNG\r\n\x1a\n\x00\x00\x00\x0dIHDR....................";
        assert_eq!(classify("logo.cer", png), None);
    }

    #[test]
    fn bare_key_file_is_private_when_substantial() {
        let key = vec![0x42u8; 64];
        assert_eq!(classify("priv.key", &key), Some(CertKind::PrivateKey));
        // Tiny stub is ignored.
        assert_eq!(classify("priv.key", b"x"), None);
    }
}
