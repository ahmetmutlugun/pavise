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

/// URL substrings (all lowercase) that indicate a reference/schema/test URL,
/// not a real runtime network call. Matched against a lowercased URL.
const NOISE_URL_PATTERNS: &[&str] = &[
    "apple.com/dtds/",       // XML plist DOCTYPE declarations
    "apple.com/xmlschemas/", // Apple XML schemas
    "www.w3.org/",           // XML schema declarations
    "xmlpull.org/",          // XML pull parser schema
    "schemas.android.com/",  // Android XML namespace
    "schemas.microsoft.com/",
    "schemas.xmlsoap.org/", // SOAP namespaces
    "videolan.org",         // VLC-related links (About UI, etc.)
    "jquery.org/license",   // Documentation/License links
    "example.invalid",      // RFC 2606 — used in gRPC and other test code
    "example.com",          // Generic test URLs in third-party libraries
    "example.org",
    "www.google.com/", // gRPC test URLs
    "localhost",
    "127.0.0.1",
    "0.0.0.0",
    "mozilla.org/mpl", // License header URLs
    "gnu.org/licenses",
    "opensource.org/licenses",
    "creativecommons.org/",
    // Apple PKI infrastructure embedded in code signatures — not app network calls
    "ocsp.apple.com/",
    "crl.apple.com/",
    "certs.apple.com/",
    "pki.apple.com/",
    // XML namespace identifiers (not network endpoints, just namespace URIs)
    "ns.adobe.com/", // XMP, TIFF, EXIF metadata namespace
    "www.iec.ch",    // ICC color profile standards
    "www.color.org", // ICC color profile standards
    "purl.org/",     // Dublin Core / persistent URL namespace
    "ogp.me/",       // Open Graph protocol namespace
    "rdfs.org/",     // RDF schema namespace
];

fn is_noise_url(url: &str) -> bool {
    // Compare lowercase URL against lowercase patterns
    let lower = url.to_lowercase();
    if NOISE_URL_PATTERNS.iter().any(|pat| lower.contains(*pat)) {
        return true;
    }
    // Filter malformed URLs with no real host (e.g., "http://,")
    let host = lower
        .strip_prefix("http://")
        .or_else(|| lower.strip_prefix("https://"))
        .unwrap_or("");
    let host = host.split('/').next().unwrap_or("");
    if host.is_empty() || !host.contains('.') || host.len() < 4 {
        return true;
    }
    false
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
        let url = m.as_str();

        // Flag HTTP (non-HTTPS) URLs, skipping noise
        if url.starts_with("http://")
            && !is_noise_url(url)
            && seen_http_urls.insert(url.to_string())
        {
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
