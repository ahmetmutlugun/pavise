//! Bundled trust anchors and pins checked against known-bad CA keys.
//!
//! An app that ships its own root store (curl's `cacert.pem`, gRPC's
//! `roots.pem`, a PEM list compiled into a networking library) never gets the
//! OS root program's removals or revocation blocklists, so a CA Apple and
//! Mozilla have distrusted stays trusted inside the app. Keys are matched by
//! SPKI SHA-256 against `data/distrusted_cas.tsv`, and by their raw key bytes
//! so DER arrays compiled into a binary match too; every EC key is also
//! tested for a trivially small private scalar (`weak_ec`).

use std::collections::HashMap;
use std::sync::OnceLock;

use aho_corasick::{packed, AhoCorasick};
use base64::Engine as _;
use sha2::{Digest, Sha256};

use super::{weak_ec, x509};
use crate::types::{Finding, Severity};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// The private key is public: anyone can sign certificates with it.
    Compromised,
    /// A CA that issued compromised intermediates.
    Issuer,
    /// A still-trusted root whose cross-signs chain to compromised intermediates.
    CrossSigner,
    /// Removed from Mozilla's root store for CA compliance failures.
    Distrusted,
}

#[derive(Debug)]
pub struct BadKey {
    pub kind: Kind,
    pub name: &'static str,
    /// Space-separated primary sources (Mozilla bugs, crt.sh).
    pub sources: &'static str,
    /// [`x509::key_material`] of the listed SPKI.
    pub material: Vec<u8>,
}

/// A file with this many distinct certificates is a root store, not a pin set.
const TRUST_STORE_MIN_CERTS: usize = 10;

fn bad_keys() -> &'static HashMap<[u8; 32], BadKey> {
    static KEYS: OnceLock<HashMap<[u8; 32], BadKey>> = OnceLock::new();
    KEYS.get_or_init(|| {
        include_str!("../../data/distrusted_cas.tsv")
            .lines()
            .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
            .map(|line| {
                let cols: Vec<&str> = line.split('\t').collect();
                let hash = base64::engine::general_purpose::STANDARD
                    .decode(cols[0])
                    .ok()
                    .and_then(|h| <[u8; 32]>::try_from(h).ok())
                    .unwrap_or_else(|| panic!("bad SPKI hash in distrusted_cas.tsv: {}", line));
                let kind = match cols[1] {
                    "compromised" => Kind::Compromised,
                    "issuer" => Kind::Issuer,
                    "cross-signer" => Kind::CrossSigner,
                    "distrusted" => Kind::Distrusted,
                    other => panic!("unknown kind in distrusted_cas.tsv: {}", other),
                };
                let spki = base64::engine::general_purpose::STANDARD
                    .decode(cols[5])
                    .unwrap_or_else(|_| panic!("bad SPKI DER in distrusted_cas.tsv: {}", line));
                assert_eq!(
                    <[u8; 32]>::from(Sha256::digest(&spki)),
                    hash,
                    "SPKI DER does not match its hash: {}",
                    cols[2]
                );
                let key = BadKey {
                    kind,
                    name: cols[2],
                    sources: cols[4],
                    material: x509::key_material(&spki)
                        .unwrap_or_else(|| panic!("unsupported key type: {}", cols[2]))
                        .to_vec(),
                };
                (hash, key)
            })
            .collect()
    })
}

pub fn lookup(spki: &[u8]) -> Option<&'static BadKey> {
    bad_keys().get(&<[u8; 32]>::from(Sha256::digest(spki)))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Needle {
    /// An SPKI SHA-256 pin string naming this key.
    Pin([u8; 32]),
    /// The key's raw bytes (EC point or RSA modulus prefix).
    Key([u8; 32]),
}

/// The TBSCertificate opening that follows `30 82 xx xx` in every DER v3 cert.
const DER_V3_TBS: &[u8] = &[0xA0, 0x03, 0x02, 0x01, 0x02];

/// DER v3 certificates stored as raw bytes in `data`.
fn der_certificates(data: &[u8]) -> usize {
    memchr::memmem::find_iter(data, DER_V3_TBS)
        .filter(|&i| i >= 4 && data[i - 4] == 0x30 && data[i - 3] == 0x82)
        .count()
}

/// Compressed or media containers (ZIP, PNG, JPEG, GIF, asset catalogs),
/// where neither pin strings nor raw key bytes can appear verbatim.
const OPAQUE_MAGIC: &[&[u8]] = &[
    b"PK\x03\x04",
    b"\x89PNG",
    b"\xFF\xD8\xFF",
    b"GIF8",
    b"BOMStore",
];

/// Every pattern in one searcher, so each file is scanned once. Pins are the
/// base64 and hex SPKI SHA-256 forms NSPinnedDomains, TrustKit and `sha256/…`
/// pin strings use. The cross-signer's pins are left out: pinning a widely
/// used root is not itself wrong.
struct Needles {
    /// SIMD Teddy (≤ 64 patterns): ~15× faster than `AhoCorasick` on arm64,
    /// which doesn't use it as a prefilter there.
    packed: Option<packed::Searcher>,
    automaton: AhoCorasick,
    ids: Vec<Needle>,
}

impl Needles {
    /// Pattern indexes of every match in `data`.
    fn find(&self, data: &[u8]) -> Vec<usize> {
        match &self.packed {
            Some(p) => p.find_iter(data).map(|m| m.pattern().as_usize()).collect(),
            None => self
                .automaton
                .find_iter(data)
                .map(|m| m.pattern().as_usize())
                .collect(),
        }
    }
}

fn needles() -> &'static Needles {
    static NEEDLES: OnceLock<Needles> = OnceLock::new();
    NEEDLES.get_or_init(|| {
        let mut patterns: Vec<Vec<u8>> = Vec::new();
        let mut ids = Vec::new();
        for (hash, key) in bad_keys() {
            patterns.push(key.material.clone());
            ids.push(Needle::Key(*hash));
            if key.kind != Kind::CrossSigner {
                let b64 = base64::engine::general_purpose::STANDARD.encode(hash);
                for form in [b64, hex::encode(hash)] {
                    patterns.push(form.into_bytes());
                    ids.push(Needle::Pin(*hash));
                }
            }
        }
        Needles {
            packed: packed::Config::new().builder().extend(&patterns).build(),
            automaton: AhoCorasick::new(&patterns).unwrap(),
            ids,
        }
    })
}

fn first_source(key: &BadKey) -> &str {
    key.sources.split(' ').next().unwrap_or("")
}

fn file_name(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

fn finding(
    id: &str,
    title: &str,
    severity: Severity,
    cwe: &str,
    description: &str,
    remediation: &str,
    evidence: Vec<String>,
) -> Finding {
    Finding {
        id: id.to_string(),
        title: title.to_string(),
        description: description.to_string(),
        severity,
        category: "network".to_string(),
        cwe: Some(cwe.to_string()),
        owasp_mobile: None,
        owasp_masvs: None,
        evidence,
        remediation: Some(remediation.to_string()),
    }
}

const REMEDIATE_STORE: &str = "If the root list ships inside a third-party library, update \
    that library to a release whose bundled roots postdate the CA's removal (WebRTC, for \
    example, regenerated rtc_base/ssl_roots.h without these CAs on 2026-10-20). Otherwise \
    validate TLS with the system trust store (URLSession, or SecTrustEvaluateWithError on the \
    library's chain) so OS root-program removals and revocations apply. If a bundled root list \
    is unavoidable, regenerate it from a current Mozilla extract, ship updates promptly, and \
    enable revocation checking.";

/// Trust-store, pin and weak-key findings for one file.
pub fn scan(path: &str, data: &[u8]) -> Vec<Finding> {
    let mut findings = Vec::new();
    let keys = x509::bundled_keys(path, data);
    let name = file_name(path);

    let needles = needles();
    let mut pins: Vec<[u8; 32]> = Vec::new();
    let mut raw_keys: Vec<[u8; 32]> = Vec::new();
    let opaque = OPAQUE_MAGIC.iter().any(|m| data.starts_with(m));
    for id in if opaque {
        Vec::new()
    } else {
        needles.find(data)
    } {
        match needles.ids[id] {
            Needle::Pin(hash) if !pins.contains(&hash) => pins.push(hash),
            Needle::Key(hash) if !raw_keys.contains(&hash) => raw_keys.push(hash),
            _ => {}
        }
    }
    // Keys parsed from PEM/DER files are reported by name; raw key bytes add
    // the ones stored some other way (DER arrays, BearSSL trust anchors).
    let parsed: Vec<[u8; 32]> = keys
        .iter()
        .map(|k| <[u8; 32]>::from(Sha256::digest(&k.spki)))
        .collect();
    raw_keys.retain(|h| !parsed.contains(h));

    let mut compromised = Vec::new();
    let mut cross_signed = Vec::new();
    let mut distrusted = Vec::new();
    let mut weak = Vec::new();
    let listed = parsed
        .iter()
        .map(|h| (h, ""))
        .chain(raw_keys.iter().map(|h| (h, ", embedded key bytes")));
    for (hash, how) in listed {
        let Some(bad) = bad_keys().get(hash) else {
            continue;
        };
        let entry = format!("{}: {} ({}{})", name, bad.name, first_source(bad), how);
        match bad.kind {
            Kind::Compromised | Kind::Issuer => compromised.push(entry),
            Kind::CrossSigner => cross_signed.push(entry),
            Kind::Distrusted => distrusted.push(entry),
        }
    }
    for key in &keys {
        // Listed keys are reported for their hierarchy (a weak key is the reason).
        if lookup(&key.spki).is_some() {
            continue;
        }
        if let Some((curve, point)) = x509::ec_point(&key.spki) {
            if let Some(d) = weak_ec::recover_small_key(curve, point) {
                weak.push(format!(
                    "{}: {} — {} private key is {}",
                    name,
                    key.subject_cn.as_deref().unwrap_or("public key"),
                    curve,
                    d
                ));
            }
        }
    }

    if !compromised.is_empty() {
        findings.push(finding(
            "QS-CERT-003",
            "Bundled Trust Anchor With Compromised Key",
            Severity::High,
            "CWE-295",
            "A certificate bundled in the app belongs to the eMudhra CA hierarchy whose \
            intermediate private keys were recovered from the public certificates in \
            October 2026 (they were integers below 256). Browsers and Apple block these \
            CAs, but a root list or pin set shipped inside the app keeps trusting them: \
            anyone can sign a certificate for any domain that chains to it and intercept \
            the app's TLS traffic if this list is used to validate connections.",
            REMEDIATE_STORE,
            compromised,
        ));
    }
    if !cross_signed.is_empty() && keys.len().max(der_certificates(data)) >= TRUST_STORE_MIN_CERTS {
        findings.push(finding(
            "QS-CERT-005",
            "Bundled Root Store Accepts Compromised Cross-Signed CAs",
            Severity::Warning,
            "CWE-295",
            "A root store bundled in the app trusts Sectigo's AAA Certificate Services, \
            which cross-signed the eight eMudhra intermediates whose private keys became \
            public in October 2026. Those cross-signs are valid until 2028-12-31 and are \
            only revoked, so a TLS stack that validates against this bundled list without \
            checking revocation accepts certificates anyone can forge for any domain.",
            REMEDIATE_STORE,
            cross_signed,
        ));
    }
    if !distrusted.is_empty() {
        findings.push(finding(
            "QS-CERT-006",
            "Bundled Trust Store Includes Distrusted Root CAs",
            Severity::Warning,
            "CWE-295",
            "The app bundles root certificates that Mozilla removed from its root store \
            after CA compliance failures, so its own root list is stale: the app trusts \
            CAs that browsers and operating systems no longer do.",
            REMEDIATE_STORE,
            distrusted,
        ));
    }
    if !weak.is_empty() {
        findings.push(finding(
            "QS-CERT-004",
            "Certificate With Trivially Weak EC Key",
            Severity::High,
            "CWE-331",
            "A bundled certificate or public key has an elliptic-curve private key below \
            2^16, recovered here in milliseconds from the public key alone. Anything \
            signed or encrypted with that key — certificates, TLS sessions, tokens — can \
            be forged or decrypted by anyone.",
            "Treat the key as compromised: revoke its certificates, generate a new key with \
            a vetted CSPRNG (or an HSM), and stop trusting or pinning the weak key.",
            weak,
        ));
    }

    let pins: Vec<&BadKey> = pins.iter().filter_map(|h| bad_keys().get(h)).collect();
    if !pins.is_empty() {
        let compromised_pin = pins.iter().any(|k| k.kind != Kind::Distrusted);
        findings.push(finding(
            "QS-CERT-007",
            "Certificate Pin on a Compromised or Distrusted CA Key",
            if compromised_pin {
                Severity::Warning
            } else {
                Severity::Info
            },
            "CWE-295",
            "The app pins (SPKI SHA-256) a CA key that is compromised or distrusted. \
            Connections pinned to it break once servers move off that CA; where the pin \
            replaces system trust evaluation, certificates signed with a compromised key \
            also pass the pin.",
            "Remove the pin and pin a key the app controls (its own leaf or an intermediate \
            from a CA in good standing), with a backup pin, and ship the update before the \
            servers migrate.",
            pins.iter()
                .map(|k| format!("{}: pin for {} ({})", name, k.name, first_source(k)))
                .collect(),
        ));
    }
    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn data_file_parses_with_sources() {
        let keys = bad_keys();
        assert_eq!(keys.len(), 20);
        assert_eq!(
            keys.values()
                .filter(|k| k.kind == Kind::Compromised)
                .count(),
            8
        );
        for key in keys.values() {
            assert!(key.sources.starts_with("https://"), "{}", key.name);
            // P-384 coordinates, or the RSA modulus prefix.
            assert!([96, 64].contains(&key.material.len()), "{}", key.name);
        }
    }

    #[test]
    fn pin_strings_in_info_plist_and_binary() {
        let g3 = "jUF9st2L9eMITR4/GW1YOEnYG91MAMcLnTk2npa4x4I=";
        let plist = format!(
            "<key>NSPinnedCAIdentities</key><array><dict><key>SPKI-SHA256-BASE64</key>\
             <string>{}</string></dict></array>",
            g3
        );
        let f = scan("Payload/A.app/Info.plist", plist.as_bytes());
        assert_eq!(f.len(), 1);
        assert_eq!(
            (f[0].id.as_str(), &f[0].severity),
            ("QS-CERT-007", &Severity::Warning)
        );
        assert!(f[0].evidence[0].contains("emSign ECC Root CA - G3"));

        // Hex form of a distrusted (not compromised) key in a Mach-O string.
        let trustcor = "d40e9c86cd8fe468c1776959f49ea774fa548684b6c406f3909261f4dce2575c";
        let spki_hex = hex::encode(
            base64::engine::general_purpose::STANDARD
                .decode("6of0Yt7v/713daoqS34Py5HCLu5t9p7ZAQDMxzsxFHY=")
                .unwrap(),
        );
        let bin = format!("\0{}\0{}\0", trustcor, spki_hex);
        let f = scan("Payload/A.app/A", bin.as_bytes());
        // The certificate hash is not a pin; the SPKI hash is.
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].severity, Severity::Info);
        assert!(f[0].evidence[0].contains("TrustCor RootCert CA-1"));
    }

    #[test]
    fn packed_searcher_matches_the_automaton() {
        let n = needles();
        assert!(n.packed.is_some(), "{} patterns exceed Teddy", n.ids.len());
        let mut blob = vec![0u8; 1000];
        let key = bad_keys().values().next().unwrap();
        blob.extend_from_slice(&key.material);
        blob.extend(b"..jUF9st2L9eMITR4/GW1YOEnYG91MAMcLnTk2npa4x4I=..");
        let found = n.find(&blob);
        let expected: Vec<usize> = n
            .automaton
            .find_iter(&blob)
            .map(|m| m.pattern().as_usize())
            .collect();
        assert_eq!(found.len(), 2);
        assert_eq!(found, expected);
    }

    #[test]
    fn unrelated_certificate_raises_nothing() {
        assert!(scan("roots.pem", x509::tests::TEST_CERT_PEM.as_bytes()).is_empty());
    }
}
