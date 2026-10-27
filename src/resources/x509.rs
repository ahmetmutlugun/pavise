//! Just enough DER/PEM reading to pull public keys out of bundled certificates.
//!
//! Trust-store checks match a certificate by its SubjectPublicKeyInfo, so this
//! module only walks the TBSCertificate far enough to reach the subject and
//! SPKI. Nothing is validated: a malformed or truncated blob yields `None`.

use base64::Engine as _;
use memchr::memmem;

/// A public key found in a bundled certificate, PEM `PUBLIC KEY` or DER file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BundledKey {
    /// DER SubjectPublicKeyInfo (the bytes SPKI pins hash).
    pub spki: Vec<u8>,
    /// Subject common name, when the key came from a certificate.
    pub subject_cn: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Curve {
    P256,
    P384,
}

impl std::fmt::Display for Curve {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Curve::P256 => "P-256",
            Curve::P384 => "P-384",
        })
    }
}

const OID_EC_PUBLIC_KEY: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01];
const OID_P256: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];
const OID_P384: &[u8] = &[0x2B, 0x81, 0x04, 0x00, 0x22];
const OID_COMMON_NAME: &[u8] = &[0x55, 0x04, 0x03];
const OID_RSA_ENCRYPTION: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01];
/// Leading modulus bytes that identify an RSA key (512 bits: no collisions).
const RSA_MODULUS_PREFIX: usize = 64;

/// Distinct keys per file; a full public root store is ~150.
const MAX_KEYS_PER_FILE: usize = 2_000;
/// Longest PEM body accepted; real certificates are a few KB.
const MAX_PEM_BODY: usize = 64 * 1024;

/// Split one DER TLV off `input`: `(tag, content, rest)`.
fn tlv(input: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (&tag, after_tag) = input.split_first()?;
    let (&first, after_len) = after_tag.split_first()?;
    let (len, body) = if first < 0x80 {
        (first as usize, after_len)
    } else {
        let n = (first & 0x7F) as usize;
        if n == 0 || n > 4 || after_len.len() < n {
            return None;
        }
        let len = after_len[..n]
            .iter()
            .fold(0usize, |acc, &b| (acc << 8) | b as usize);
        (len, &after_len[n..])
    };
    (body.len() >= len).then(|| (tag, &body[..len], &body[len..]))
}

/// Like [`tlv`] but returns the whole encoded element instead of its content.
fn tlv_whole(input: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (tag, _, rest) = tlv(input)?;
    Some((tag, &input[..input.len() - rest.len()], rest))
}

/// SPKI and subject CN of a DER X.509 certificate.
pub fn cert_key(der: &[u8]) -> Option<BundledKey> {
    let (0x30, cert, _) = tlv(der)? else {
        return None;
    };
    let (0x30, tbs, _) = tlv(cert)? else {
        return None;
    };
    let mut rest = tbs;
    // Optional explicit [0] version.
    if rest.first() == Some(&0xA0) {
        rest = tlv(rest)?.2;
    }
    // serialNumber, signature, issuer, validity
    for expected in [0x02, 0x30, 0x30, 0x30] {
        let (tag, _, r) = tlv(rest)?;
        if tag != expected {
            return None;
        }
        rest = r;
    }
    let (0x30, subject, rest) = tlv(rest)? else {
        return None;
    };
    let (0x30, spki, _) = tlv_whole(rest)? else {
        return None;
    };
    if !is_spki(spki) {
        return None;
    }
    Some(BundledKey {
        spki: spki.to_vec(),
        subject_cn: common_name(subject),
    })
}

/// Whether `spki` is SEQUENCE { AlgorithmIdentifier, BIT STRING }.
fn is_spki(spki: &[u8]) -> bool {
    let Some((0x30, body, _)) = tlv(spki) else {
        return false;
    };
    let Some((0x30, _, rest)) = tlv(body) else {
        return false;
    };
    matches!(tlv(rest), Some((0x03, _, _)))
}

/// First CN attribute of an X.501 Name (the content of its SEQUENCE).
fn common_name(mut name: &[u8]) -> Option<String> {
    while let Some((0x31, set, rest)) = tlv(name) {
        let mut atvs = set;
        while let Some((0x30, atv, next)) = tlv(atvs) {
            if let Some((0x06, oid, value)) = tlv(atv) {
                if oid == OID_COMMON_NAME {
                    let (_, s, _) = tlv(value)?;
                    return Some(String::from_utf8_lossy(s).into_owned());
                }
            }
            atvs = next;
        }
        name = rest;
    }
    None
}

/// The curve and SEC1-encoded point of a P-256/P-384 SPKI.
pub fn ec_point(spki: &[u8]) -> Option<(Curve, &[u8])> {
    let (0x30, body, _) = tlv(spki)? else {
        return None;
    };
    let (0x30, alg, rest) = tlv(body)? else {
        return None;
    };
    let (0x06, oid, params) = tlv(alg)? else {
        return None;
    };
    if oid != OID_EC_PUBLIC_KEY {
        return None;
    }
    let curve = match tlv(params)? {
        (0x06, OID_P256, _) => Curve::P256,
        (0x06, OID_P384, _) => Curve::P384,
        _ => return None,
    };
    let (0x03, bits, _) = tlv(rest)? else {
        return None;
    };
    let (&0, point) = bits.split_first()? else {
        return None;
    };
    Some((curve, point))
}

/// Bytes that identify `spki`'s key however it is stored: the EC point's
/// coordinates (without the SEC1 tag byte, which is too common a byte to lead
/// a search pattern), or the start of the RSA modulus. DER certificates, bare
/// SPKI arrays and BearSSL trust anchors (raw modulus or point) all contain
/// them verbatim.
pub fn key_material(spki: &[u8]) -> Option<&[u8]> {
    if let Some((_, point)) = ec_point(spki) {
        return point.strip_prefix(&[0x04]);
    }
    let (0x30, body, _) = tlv(spki)? else {
        return None;
    };
    let (0x30, alg, rest) = tlv(body)? else {
        return None;
    };
    let (0x06, OID_RSA_ENCRYPTION, _) = tlv(alg)? else {
        return None;
    };
    let (0x03, bits, _) = tlv(rest)? else {
        return None;
    };
    let (&0, rsa_key) = bits.split_first()? else {
        return None;
    };
    let (0x30, rsa, _) = tlv(rsa_key)? else {
        return None;
    };
    let (0x02, n, _) = tlv(rsa)? else {
        return None;
    };
    n.strip_prefix(&[0]).unwrap_or(n).get(..RSA_MODULUS_PREFIX)
}

/// Decode a PEM body, tolerating line breaks, indentation and the `\n`
/// escapes left when a PEM sits in a JSON or source string.
fn decode_pem_body(body: &[u8]) -> Option<Vec<u8>> {
    let mut b64 = Vec::with_capacity(body.len());
    let mut bytes = body.iter();
    while let Some(&c) = bytes.next() {
        match c {
            b'\\' => {
                bytes.next();
            }
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'+' | b'/' | b'=' => b64.push(c),
            _ => {}
        }
    }
    base64::engine::general_purpose::STANDARD.decode(b64).ok()
}

/// Every certificate and public key in `data`: PEM blocks anywhere in the file
/// (including C string literals in a Mach-O), or the whole file when it is a
/// DER certificate. Duplicate keys are collapsed.
pub fn bundled_keys(path: &str, data: &[u8]) -> Vec<BundledKey> {
    let mut keys: Vec<BundledKey> = Vec::new();
    let push = |key: BundledKey, keys: &mut Vec<BundledKey>| {
        if keys.len() < MAX_KEYS_PER_FILE && !keys.iter().any(|k| k.spki == key.spki) {
            keys.push(key);
        }
    };

    let lower = path.to_lowercase();
    if [".der", ".cer", ".crt"].iter().any(|e| lower.ends_with(e)) {
        if let Some(key) = cert_key(data) {
            push(key, &mut keys);
        }
    }

    let end_marker = memmem::Finder::new(b"-----END ");
    for start in memmem::find_iter(data, b"-----BEGIN ") {
        let after = &data[start + 11..];
        let Some(label_len) = memmem::find(&after[..after.len().min(40)], b"-----") else {
            continue;
        };
        let label = &after[..label_len];
        let body = &after[label_len + 5..];
        let Some(end) = end_marker.find(&body[..body.len().min(MAX_PEM_BODY)]) else {
            continue;
        };
        let Some(der) = decode_pem_body(&body[..end]) else {
            continue;
        };
        let key = match label {
            b"CERTIFICATE" | b"TRUSTED CERTIFICATE" | b"X509 CERTIFICATE" => cert_key(&der),
            b"PUBLIC KEY" => is_spki(&der).then_some(BundledKey {
                spki: der,
                subject_cn: None,
            }),
            _ => None,
        };
        if let Some(key) = key {
            push(key, &mut keys);
        }
    }
    keys
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// Self-signed P-256 test certificate (CN=pavise-test), generated with
    /// `openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256`.
    pub const TEST_CERT_PEM: &str = "-----BEGIN CERTIFICATE-----
MIIBgDCCASegAwIBAgIUFdnSH+HoLKsA/Gqj3RcNZS3UBd8wCgYIKoZIzj0EAwIw
FjEUMBIGA1UEAwwLcGF2aXNlLXRlc3QwHhcNMjYxMDI2MjMwODE2WhcNMzYxMDIz
MjMwODE2WjAWMRQwEgYDVQQDDAtwYXZpc2UtdGVzdDBZMBMGByqGSM49AgEGCCqG
SM49AwEHA0IABO5f3eFo8pCwijGc0d0UxTAM0j1H9KoFST/uic7Irh9C47OULILB
X4ud3CeaX9GFfQGcO1X5FWFfUWHro3SGAPWjUzBRMB0GA1UdDgQWBBT0czGktl4A
mR0zNm8BP4N0gvOGvjAfBgNVHSMEGDAWgBT0czGktl4AmR0zNm8BP4N0gvOGvjAP
BgNVHRMBAf8EBTADAQH/MAoGCCqGSM49BAMCA0cAMEQCICu8SFeWYBG0Fh+nC6Pm
Byc3KbzHzyCKXEh0VBCK2ehYAiALmiYP805rn7/cPWPBvJF8lpwSP3CGVzDw3gXS
34sYCA==
-----END CERTIFICATE-----
";

    #[test]
    fn reads_cn_and_p256_point_from_pem_certificate() {
        let keys = bundled_keys("roots.pem", TEST_CERT_PEM.as_bytes());
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].subject_cn.as_deref(), Some("pavise-test"));
        let (curve, point) = ec_point(&keys[0].spki).unwrap();
        assert_eq!(curve, Curve::P256);
        assert_eq!((point.len(), point[0]), (65, 0x04));
    }

    #[test]
    fn pem_in_c_string_literal_with_escapes_and_duplicates() {
        // How a store looks in __cstring when written with "\r\n" escapes in
        // JSON, plus the same certificate twice.
        let escaped = TEST_CERT_PEM.replace('\n', "\\r\\n");
        let blob = format!("\0junk\0{}\0{}\0", escaped, TEST_CERT_PEM);
        let keys = bundled_keys("Frameworks/X.framework/X", blob.as_bytes());
        assert_eq!(keys.len(), 1);
    }

    #[test]
    fn der_certificate_file() {
        let der = decode_pem_body(
            TEST_CERT_PEM
                .trim_start_matches("-----BEGIN CERTIFICATE-----")
                .trim_end()
                .trim_end_matches("-----END CERTIFICATE-----")
                .as_bytes(),
        )
        .unwrap();
        assert_eq!(bundled_keys("pin.cer", &der).len(), 1);
        // The same bytes under a non-certificate name are not parsed as DER.
        assert!(bundled_keys("blob.bin", &der).is_empty());
    }

    #[test]
    fn malformed_input_yields_nothing() {
        for blob in [
            &b"-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----"[..],
            b"-----BEGIN CERTIFICATE-----",
            b"-----BEGIN ",
            b"\x30\x82\xff\xff\x30",
        ] {
            assert!(bundled_keys("x.pem", blob).is_empty());
            assert!(cert_key(blob).is_none());
        }
    }
}
