//! Bundled root stores, pins and weak EC keys (QS-CERT-003…007).
//!
//! Fixtures in `tests/fixtures/trust/`: the real emSign ECC Root CA - G3 and
//! AAA Certificate Services roots (from curl's Mozilla extract and crt.sh),
//! nine throwaway self-signed roots, and a self-signed P-256 certificate whose
//! private key is 7.

mod common;

use pavise::types::{Finding, Severity};
use pavise::{scan_ipa, ScanOptions};

const G3_ROOT: &str = include_str!("fixtures/trust/g3_root.pem");
const AAA_ROOT: &str = include_str!("fixtures/trust/aaa_root.pem");
const FILLER_ROOTS: &str = include_str!("fixtures/trust/filler.pem");
const WEAK_P256: &str = include_str!("fixtures/trust/weak_p256_d7.pem");

fn scan(builder: common::IpaBuilder) -> Vec<Finding> {
    let ipa = builder.build();
    let opts = ScanOptions {
        rules_dir: Some(common::rules_dir()),
        min_severity: Severity::Info,
        network: false,
        show_progress: false,
        max_extracted_bytes: None,
        max_in_flight_bytes: None,
    };
    scan_ipa(ipa.path(), &opts).expect("scan").findings
}

fn by_id<'a>(findings: &'a [Finding], id: &str) -> Option<&'a Finding> {
    findings.iter().find(|f| f.id == id)
}

#[test]
fn root_store_with_emudhra_root_is_high() {
    let store = format!("{}{}", FILLER_ROOTS, G3_ROOT);
    let findings = scan(common::IpaBuilder::new("App").add_bundle_file(
        "Frameworks/gRPC.framework/gRPCCertificates.bundle/roots.pem",
        store,
    ));
    let f = by_id(&findings, "QS-CERT-003").expect("QS-CERT-003");
    assert_eq!(f.severity, Severity::High);
    assert!(
        f.evidence[0].starts_with("roots.pem: emSign ECC Root CA - G3"),
        "{:?}",
        f.evidence
    );
    assert!(f.evidence[0].contains("bugzilla.mozilla.org"));
    // Its key is not small: listed for the hierarchy, not as a weak key.
    assert!(by_id(&findings, "QS-CERT-004").is_none());
}

#[test]
fn pem_store_compiled_into_a_framework_binary() {
    // How networking libraries compile in root stores: PEM C strings in a Mach-O.
    let mut binary = common::minimal_macho();
    binary.extend_from_slice(b"\0");
    binary.extend_from_slice(G3_ROOT.replace('\n', "\r\n").as_bytes());
    binary.push(0);
    let findings = scan(
        common::IpaBuilder::new("App").add_bundle_file("Frameworks/Net.framework/Net", binary),
    );
    let f = by_id(&findings, "QS-CERT-003").expect("QS-CERT-003");
    assert!(f.evidence[0].starts_with("Net: "), "{:?}", f.evidence);
}

#[test]
fn cross_signer_only_flagged_in_a_root_store() {
    let store = format!("{}{}", FILLER_ROOTS, AAA_ROOT);
    let findings = scan(common::IpaBuilder::new("App").add_bundle_file("cacert.pem", store));
    let f = by_id(&findings, "QS-CERT-005").expect("QS-CERT-005");
    assert_eq!(f.severity, Severity::Warning);
    assert!(f.evidence[0].contains("AAA Certificate Services"));

    // Pinning Sectigo's root on its own is not a root store.
    let findings = scan(common::IpaBuilder::new("App").add_bundle_file("sectigo.pem", AAA_ROOT));
    assert!(by_id(&findings, "QS-CERT-005").is_none());
    assert!(by_id(&findings, "QS-CERT-002").is_some());
}

#[test]
fn weak_ec_key_is_recovered() {
    let findings = scan(common::IpaBuilder::new("App").add_bundle_file("certs/ca.pem", WEAK_P256));
    let f = by_id(&findings, "QS-CERT-004").expect("QS-CERT-004");
    assert_eq!(f.severity, Severity::High);
    assert_eq!(
        f.evidence,
        ["ca.pem: Weak Key Test CA — P-256 private key is 7"]
    );
}

#[test]
fn ordinary_roots_raise_nothing_new() {
    let findings = scan(common::IpaBuilder::new("App").add_bundle_file("roots.pem", FILLER_ROOTS));
    for id in [
        "QS-CERT-003",
        "QS-CERT-004",
        "QS-CERT-005",
        "QS-CERT-006",
        "QS-CERT-007",
    ] {
        assert!(by_id(&findings, id).is_none(), "{} on ordinary roots", id);
    }
}

/// DER bytes of every certificate in a PEM string.
fn ders(pem: &str) -> Vec<Vec<u8>> {
    use base64::Engine as _;
    pem.split("-----BEGIN CERTIFICATE-----")
        .skip(1)
        .map(|b| {
            let body: String = b
                .split("-----END CERTIFICATE-----")
                .next()
                .unwrap()
                .split_whitespace()
                .collect();
            base64::engine::general_purpose::STANDARD
                .decode(body)
                .unwrap()
        })
        .collect()
}

/// A framework binary: Mach-O header, then each blob between filler bytes.
fn binary_with(blobs: &[&[u8]]) -> Vec<u8> {
    let mut bin = common::minimal_macho();
    for (i, blob) in blobs.iter().enumerate() {
        bin.extend((0..257u32).map(|j| (j * 31 + i as u32 * 7) as u8));
        bin.extend_from_slice(blob);
    }
    bin.extend([0u8; 64]);
    bin
}

#[test]
fn der_certificate_array_in_a_binary() {
    // `static const unsigned char cert[] = {0x30, 0x82, …}` — no PEM text.
    let g3 = &ders(G3_ROOT)[0];
    let findings = scan(
        common::IpaBuilder::new("App")
            .add_bundle_file("Frameworks/Net.framework/Net", binary_with(&[g3])),
    );
    let f = by_id(&findings, "QS-CERT-003").expect("QS-CERT-003");
    assert_eq!(f.evidence.len(), 1, "{:?}", f.evidence);
    assert!(
        f.evidence[0].contains("emSign ECC Root CA - G3")
            && f.evidence[0].contains("embedded key bytes"),
        "{:?}",
        f.evidence
    );
}

#[test]
fn bare_ec_point_like_a_bearssl_trust_anchor() {
    // BearSSL stores the subject DN and the raw public point, not a certificate.
    let key = pavise::resources::x509::cert_key(&ders(G3_ROOT)[0]).unwrap();
    let point = pavise::resources::x509::key_material(&key.spki).unwrap();
    assert_eq!(point.len(), 96);
    let findings = scan(
        common::IpaBuilder::new("App")
            .add_bundle_file("Frameworks/Net.framework/Net", binary_with(&[point])),
    );
    assert!(by_id(&findings, "QS-CERT-003").is_some());
}

#[test]
fn der_root_store_with_cross_signer() {
    let aaa = ders(AAA_ROOT).remove(0);
    let filler = ders(FILLER_ROOTS);
    let mut blobs: Vec<&[u8]> = filler.iter().map(Vec::as_slice).collect();
    blobs.push(&aaa);
    let findings = scan(
        common::IpaBuilder::new("App")
            .add_bundle_file("Frameworks/Net.framework/Net", binary_with(&blobs)),
    );
    let f = by_id(&findings, "QS-CERT-005").expect("QS-CERT-005");
    assert!(
        f.evidence[0].contains("embedded key bytes"),
        "{:?}",
        f.evidence
    );

    // One compiled-in AAA certificate is a pin anchor, not a root store.
    let findings = scan(
        common::IpaBuilder::new("App")
            .add_bundle_file("Frameworks/Net.framework/Net", binary_with(&[&aaa])),
    );
    assert!(by_id(&findings, "QS-CERT-005").is_none());
}

#[test]
fn der_file_is_reported_once() {
    let findings = scan(
        common::IpaBuilder::new("App").add_bundle_file("pins/g3.cer", ders(G3_ROOT).remove(0)),
    );
    let f = by_id(&findings, "QS-CERT-003").expect("QS-CERT-003");
    assert_eq!(f.evidence.len(), 1, "{:?}", f.evidence);
    assert!(
        !f.evidence[0].contains("embedded key bytes"),
        "{:?}",
        f.evidence
    );
}
