use regex::Regex;
use std::collections::HashSet;
use std::sync::OnceLock;

use crate::types::{DomainInfo, Finding, Severity};

static URL_RE: OnceLock<Regex> = OnceLock::new();

fn url_re() -> &'static Regex {
    URL_RE.get_or_init(|| {
        Regex::new(r"https?://[a-zA-Z0-9\-._~:/?#\[\]@!$&'()*+,;=%]+").expect("url regex")
    })
}

/// Hosts (and their subdomains) whose URLs are identifiers, documentation or
/// test fixtures rather than runtime endpoints.
const NOISE_HOSTS: &[&str] = &[
    // XML / RDF / metadata namespaces
    "w3.org",
    "xmlpull.org",
    "schemas.android.com",
    "schemas.microsoft.com",
    "schemas.xmlsoap.org",
    "schemas.openxmlformats.org",
    "ns.adobe.com",
    "iec.ch",
    "color.org",
    "purl.org",
    "ogp.me",
    "rdfs.org",
    "dashif.org",
    "cipa.jp",  // EXIF namespace
    "iptc.org", // IPTC photo-metadata XMP namespaces
    "ifpi.org", // ISRC tag identifier (GStreamer)
    "json-schema.org",
    "standards.iso.org",
    "xml.org",
    // XMPP protocol namespaces (`http://jabber.org/protocol/caps`)
    "jabber.org",
    "xmpp.org",
    // Licenses, specs and bug/docs links embedded in third-party code
    "apache.org",
    "gnu.org",
    "opensource.org",
    "creativecommons.org",
    "ietf.org",
    "scripts.sil.org",
    "anglebug.com",
    "crbug.com",
    "fb.me",
    "momentjs.com",
    "jquery.com",
    "jquery.org",
    "jqueryui.com",
    "vt100.net",
    "videolan.org",
    "openssl.org",
    "cairographics.org",
    "freedesktop.org",
    "tianocore.org",
    "sqlite.org",
    "unicode.org",
    "zlib.net",
    // RFC 2606 / test fixtures
    "example.com",
    "example.org",
    "example.net",
    "example.invalid",
    "localhost",
    "www.google.com",
];

/// (host suffix, path prefix) pairs for hosts that also serve real endpoints.
const NOISE_HOST_PATHS: &[(&str, &str)] = &[
    ("apple.com", "/dtds/"),
    ("captive.apple.com", ""), // captive-portal probe, plain HTTP by design
    ("apple.com", "/xmlschemas/"),
    ("mozilla.org", "/mpl"),
    ("webrtc.org", "/experiments/"), // RTP header-extension URIs
    ("gultsch.de", "/xmpp/"),        // XMPP extension namespaces
];

/// Host suffix match: `host` is `suffix` or a subdomain of it.
fn host_matches(host: &str, suffix: &str) -> bool {
    host == suffix
        || host
            .strip_suffix(suffix)
            .is_some_and(|rest| rest.ends_with('.'))
}

/// True for a syntactically valid DNS name or IPv4 literal. Rejects fragments
/// from minified JS (`www.`, `.css`) and run-on strings (`169.254.170.2EnvConfig`).
fn is_valid_host(host: &str) -> bool {
    if host.split('.').count() == 4 && host.split('.').all(|p| p.parse::<u8>().is_ok()) {
        return true;
    }
    let labels: Vec<&str> = host.split('.').collect();
    let tld = labels.last().copied().unwrap_or("");
    labels.len() >= 2
        && labels.iter().all(|l| {
            !l.is_empty()
                && !l.starts_with('-')
                && !l.ends_with('-')
                && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
        && (2..=24).contains(&tld.len())
        && tld.bytes().all(|b| b.is_ascii_alphabetic())
        // `http://www.` + concatenated word: `www.css`, `www.icon`
        && !(labels.len() == 2 && labels[0] == "www")
}

/// Certificate-infrastructure URLs (CRL, OCSP, AIA, CPS) embedded in DER
/// certificates. They use HTTP by design — the payloads are signed.
fn is_pki_url(host: &str, path: &str) -> bool {
    let path = path.to_lowercase();
    ["crl", "ocsp", "cacerts", "certs."]
        .iter()
        .any(|p| host.starts_with(p))
        || ["/pki/", "/appleca", "/certificateauthority", "/repository", "/cps"]
            .iter()
            .any(|p| path.contains(p))
        // DER-embedded URLs often carry a trailing tag byte ('0') after the extension.
        || [".crl", ".crt", ".cer", ".p7c"]
            .iter()
            .any(|e| path.ends_with(e) || path.ends_with(&format!("{}0", e)))
}

/// Schema, namespace, license and bug-tracker URLs: identifiers or links in
/// comments and license text, never fetched by the app.
fn is_reference_url(host: &str, path: &str, url: &str) -> bool {
    let path = path.to_lowercase();
    let file = path.split(['?', '#']).next().unwrap_or("");
    [".xsd", ".dtd", ".rdf", ".owl", ".xsl", ".xslt"]
        .iter()
        .any(|e| file.ends_with(e))
        // XML namespace identifiers: `http://check.sourceforge.net/ns`
        || file.ends_with("/ns")
        || file.starts_with("/ns/")
        || file.contains("/xmlns")
        // `http://json-schema.org/schema#`-style namespace identifiers
        || url.ends_with('#')
        // `/licenses/LICENSE-2.0`, `/COPYING.txt`; `/license/verify` is an API.
        || path.starts_with("/licenses/")
        || ["license", "copying"].iter().any(|n| {
            file.trim_end_matches('/')
                .rsplit('/')
                .next()
                .and_then(|seg| seg.strip_prefix(n))
                .is_some_and(|rest| rest.is_empty() || rest.starts_with(['.', '-']))
        })
        || ["bugzilla.", "bugs.", "bugreport."]
            .iter()
            .any(|p| host.starts_with(p))
}

fn is_noise_url(url: &str) -> bool {
    let rest = url
        .strip_prefix("http://")
        .or_else(|| url.strip_prefix("https://"))
        .unwrap_or("");
    let split = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let (authority, path) = rest.split_at(split);
    let host = authority
        .rsplit('@')
        .next()
        .unwrap_or("")
        .split(':')
        .next()
        .unwrap_or("")
        .to_lowercase();

    if !is_valid_host(&host) || host.starts_with("127.") || host == "0.0.0.0" {
        return true;
    }
    let path_lower = path.to_lowercase();
    NOISE_HOSTS.iter().any(|h| host_matches(&host, h))
        || NOISE_HOST_PATHS
            .iter()
            .any(|(h, p)| host_matches(&host, h) && path_lower.starts_with(p))
        || is_pki_url(&host, path)
        || is_reference_url(&host, path, url)
}

/// Files whose URLs are documentation, not endpoints: license and credits
/// text, and media/firmware whose metadata embeds project links. Secrets are
/// still scanned there; only URL and domain extraction is skipped.
pub fn is_reference_file(path: &str) -> bool {
    let lower = path.to_lowercase();
    let name = lower.rsplit('/').next().unwrap_or(&lower);
    const DOC_NAMES: &[&str] = &[
        "license",
        "licence",
        "copying",
        "notice",
        "acknowledg",
        "credits",
        "authors",
        "readme",
        "changelog",
    ];
    const MEDIA_EXTENSIONS: &[&str] = &[
        ".png", ".jpg", ".jpeg", ".gif", ".webp", ".heic", ".pdf", ".ttf", ".otf", ".woff",
        ".woff2", ".rom", ".fd", ".md",
    ];
    DOC_NAMES.iter().any(|n| name.contains(n)) || MEDIA_EXTENSIONS.iter().any(|e| name.ends_with(e))
}

pub struct UrlExtractResult {
    pub domains: Vec<DomainInfo>,
    pub findings: Vec<Finding>,
}

/// Extract URLs and domains from text.
///
/// Domain collection is intentionally URL-scoped: only hostnames that appear
/// inside an explicit `http://` or `https://` URL are collected. Raw domain
/// extraction (no scheme) was tried but is too noisy — dot notation is pervasive
/// in Swift/ObjC code, and many common code tokens (`.id`, `.map`, `.info`,
/// `.app`, `.zip`) are now valid IANA TLDs, making heuristic filtering
/// unreliable. Restricting to scheme-prefixed URLs gives high-precision results.
pub fn extract(text: &str, source_path: &str) -> UrlExtractResult {
    let mut domains: Vec<DomainInfo> = Vec::new();
    let mut findings: Vec<Finding> = Vec::new();
    let mut seen_domains: HashSet<String> = HashSet::new();
    let mut seen_http_urls: HashSet<String> = HashSet::new();

    for m in url_re().find_iter(text) {
        let url = trim_url(m.as_str());
        // Noise URLs (schemas, licenses, docs, malformed hosts) are neither
        // flagged nor counted as domains the app talks to.
        if is_noise_url(url) {
            continue;
        }

        // Flag HTTP (non-HTTPS) URLs
        if url.starts_with("http://") && seen_http_urls.insert(url.to_string()) {
            findings.push(Finding {
                    id: "QS-NET-001".to_string(),
                    title: "Insecure HTTP URL Found".to_string(),
                    description: format!(
                        "An HTTP (non-HTTPS) URL was found in '{}'. Communication over HTTP is unencrypted and susceptible to man-in-the-middle attacks.",
                        source_path
                    ),
                    severity: Severity::Warning,
                    category: "network".to_string(),
                    cwe: Some("CWE-319".to_string()),
                    owasp_mobile: Some("M3".to_string()),
                    owasp_masvs: Some("MSTG-NETWORK-1".to_string()),
                    evidence: vec![url.to_string()],
                    remediation: Some("Replace HTTP with HTTPS and ensure the server has a valid TLS certificate.".to_string()),
                });
        }

        // Collect the hostname from every URL (http and https)
        if let Some(domain) = extract_domain_from_url(url) {
            if seen_domains.insert(domain.clone()) {
                domains.push(DomainInfo {
                    domain,
                    context: source_path.to_string(),
                });
            }
        }
    }

    UrlExtractResult { domains, findings }
}

/// Drop punctuation the URL regex swallows from surrounding prose or code:
/// `(see https://x.app).` → `https://x.app`. A `)` is kept when the URL
/// opened one itself (`https://en.wikipedia.org/wiki/Foo_(bar)`).
fn trim_url(url: &str) -> &str {
    let mut url = url;
    loop {
        let trimmed = url.trim_end_matches(['.', ',', ';', ':', '!', '?', '\'', '*']);
        let trimmed = match trimmed.strip_suffix(')') {
            Some(t) if trimmed.matches('(').count() < trimmed.matches(')').count() => t,
            _ => trimmed,
        };
        if trimmed.len() == url.len() {
            return url;
        }
        url = trimmed;
    }
}

fn extract_domain_from_url(url: &str) -> Option<String> {
    // Strip scheme
    let without_scheme = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))?;

    // Take up to first / ? # : [ ] or end.
    // The URL regex allows [ ] for IPv6 literals, but that also lets the
    // next token (e.g. `]1085117749045_`) bleed into the hostname when a
    // closing bracket appears immediately after a domain in the source text.
    let host = without_scheme
        .split(['/', '?', '#', ':', '[', ']'])
        .next()?;

    if host.is_empty() || !host.contains('.') {
        return None;
    }

    Some(host.to_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_https_not_flagged() {
        let result = extract("See https://api.mycompany.net/v1 for details", "test.plist");
        assert!(
            result.findings.iter().all(|f| f.id != "QS-NET-001"),
            "HTTPS URL should not emit QS-NET-001"
        );
    }

    #[test]
    fn test_http_real_flagged() {
        let result = extract("endpoint: http://api.mycompany.net/v1", "config.json");
        let net_findings: Vec<_> = result
            .findings
            .iter()
            .filter(|f| f.id == "QS-NET-001")
            .collect();
        assert_eq!(
            net_findings.len(),
            1,
            "Expected exactly one QS-NET-001 finding"
        );
    }

    #[test]
    fn test_localhost_not_flagged() {
        let result = extract("dev server: http://localhost:8080/api", "debug.plist");
        assert!(
            result.findings.iter().all(|f| f.id != "QS-NET-001"),
            "localhost URL should not emit QS-NET-001"
        );
    }

    #[test]
    fn test_apple_schema_not_flagged() {
        let result = extract(
            r#"<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/dtds/PropertyList-1.0.dtd">"#,
            "Info.plist",
        );
        assert!(
            result.findings.iter().all(|f| f.id != "QS-NET-001"),
            "Apple DTD URL should not emit QS-NET-001"
        );
    }

    #[test]
    fn test_reference_urls_not_flagged() {
        for url in [
            "http://jabber.org/protocol/caps",
            "http://www.apache.org/licenses/LICENSE-2.0",
            "http://www.apple.com/appleca/root.crl0",
            "http://crl3.digicert.com/DigiCertGlobalRootCA.crl",
            "http://www.microsoft.com/pki/certs/MicRooCerAut_2010-06-23.crt0",
            "http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time",
            "http://www.",
            "http://.css",
            "http://www.icon",
            "http://169.254.170.2EnvConfigCredentialsinvalid",
            "http://standards.iso.org/ittf/PubliclyAvailableStandards/MPEG-DASH_schema_files/DASH-MPD.xsd",
            "http://json-schema.org/schema#",
            "http://purl.example.net/ns/core#",
            "http://www.cairographics.org/",
            "http://bugzilla.tianocore.org/show_bug.cgi?id=1",
            "http://www.zlib.net/COPYING",
            "http://foo.dev/LICENSE-2.0",
            "http://x.x.x.x",
            "http://%.*s",
            "http://check.sourceforge.net/ns",
            "http://check.sourceforge.net/xml/check_unittest.xslt",
            "http://captive.apple.com",
        ] {
            let result = extract(url, "Frameworks/X.framework/X");
            assert!(result.findings.is_empty(), "{} should not be flagged", url);
        }
    }

    #[test]
    fn test_noise_host_is_matched_on_host_not_substring() {
        // `example.com` inside another host's path or name must not hide it.
        for url in [
            "http://api.notexample.com/v1",
            "http://evil.net/example.com/",
            "http://www.microsoft.com/api/login",
        ] {
            let result = extract(url, "config.json");
            assert_eq!(result.findings.len(), 1, "{} should be flagged", url);
        }
    }

    #[test]
    fn test_api_paths_named_like_licenses_still_flagged() {
        for url in [
            "http://api.shop.io/license/verify",
            "http://api.shop.io/v1/licenses",
        ] {
            assert_eq!(extract(url, "config.json").findings.len(), 1, "{url}");
        }
    }

    #[test]
    fn test_domains_skip_noise_and_trailing_punctuation() {
        let text =
            "(see https://aidoku.app). Licensed under http://www.apache.org/licenses/LICENSE-2.0 \
                    https://en.wikipedia.org/wiki/Foo_(bar) http://x.x.x.x http://%.*s";
        let domains: Vec<String> = extract(text, "README")
            .domains
            .into_iter()
            .map(|d| d.domain)
            .collect();
        assert_eq!(domains, ["aidoku.app", "en.wikipedia.org"]);
        assert_eq!(
            trim_url("https://en.wikipedia.org/wiki/Foo_(bar)"),
            "https://en.wikipedia.org/wiki/Foo_(bar)"
        );
        assert_eq!(trim_url("https://aidoku.app)."), "https://aidoku.app");
    }

    #[test]
    fn test_reference_files() {
        for p in [
            "Payload/U.app/License.plist",
            "Payload/U.app/Settings.bundle/Acknowledgements.plist",
            "Payload/U.app/edk2-licenses.txt",
            "Payload/U.app/backtrack.png",
            "Payload/U.app/pxe-e1000.rom",
        ] {
            assert!(is_reference_file(p), "{p}");
        }
        for p in [
            "Payload/U.app/U",
            "Payload/U.app/Config.plist",
            "Payload/U.app/repositories.txt",
        ] {
            assert!(!is_reference_file(p), "{p}");
        }
    }

    #[test]
    fn test_domain_collected() {
        let result = extract("base: https://api.mycompany.net/v1", "config.json");
        assert!(
            result
                .domains
                .iter()
                .any(|d| d.domain == "api.mycompany.net"),
            "Expected api.mycompany.net in domains, got: {:?}",
            result.domains.iter().map(|d| &d.domain).collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_duplicate_http_single_finding() {
        let text = "http://api.mycompany.net/v1 and http://api.mycompany.net/v1";
        let result = extract(text, "config.plist");
        let count = result
            .findings
            .iter()
            .filter(|f| f.id == "QS-NET-001")
            .count();
        assert_eq!(
            count, 1,
            "Duplicate HTTP URL should produce exactly 1 finding, got {count}"
        );
    }
}
