//! Unauthenticated access probes for the app's Firebase backend (`--network`).
//!
//! A Realtime Database or Storage bucket whose security rules allow public
//! reads leaks every user's data to anyone holding the (public) config. The
//! probes send one read-only GET each and report only the status code.

use std::time::Duration;

use tracing::{debug, warn};

use crate::types::{Finding, FirebaseInfo, Severity};

/// Probe the Realtime Database and Storage bucket named in the app's
/// GoogleService-Info.plist.
pub fn probe(info: &FirebaseInfo) -> Vec<Finding> {
    let agent = ureq::AgentBuilder::new()
        .timeout(Duration::from_secs(10))
        .redirects(0)
        .user_agent("pavise-security-scanner/1.0")
        .build();
    let mut findings = Vec::new();

    if let Some(url) = info.database_url.as_deref().and_then(rtdb_probe_url) {
        if get_status(&agent, &url) == Some(200) {
            findings.push(open_finding(
                "QS-FB-001",
                "Firebase Realtime Database Publicly Readable",
                "The app's Firebase Realtime Database answers unauthenticated reads. Its \
                security rules allow `.read` for everyone, so anyone with the bundled \
                database URL can download the stored data.",
                &url,
                "Restrict the database rules (e.g. `\".read\": \"auth != null\"` plus per-user \
                paths) and audit what was exposed.",
            ));
        }
    }

    if let Some(url) = info.storage_bucket.as_deref().and_then(storage_probe_url) {
        if get_status(&agent, &url) == Some(200) {
            findings.push(open_finding(
                "QS-FB-002",
                "Firebase Storage Bucket Publicly Listable",
                "The app's Firebase Storage bucket lists its objects to unauthenticated \
                clients. Its security rules allow public reads, exposing every uploaded file.",
                &url,
                "Require `request.auth != null` (and ownership checks) in the Storage rules.",
            ));
        }
    }
    findings
}

fn get_status(agent: &ureq::Agent, url: &str) -> Option<u16> {
    match agent.get(url).call() {
        Ok(resp) => Some(resp.status()),
        Err(ureq::Error::Status(code, _)) => {
            debug!("Firebase probe {} -> {}", url, code);
            Some(code)
        }
        Err(e) => {
            warn!("Firebase probe {} failed: {}", url, e);
            None
        }
    }
}

/// `<database_url>/.json?shallow=true` for a Firebase-hosted RTDB, else None.
/// Only Google's hosts are probed, whatever the plist claims.
fn rtdb_probe_url(database_url: &str) -> Option<String> {
    let host = database_url.strip_prefix("https://")?.trim_end_matches('/');
    let valid_label = |l: &str| {
        !l.is_empty()
            && l.bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    };
    let labels: Vec<&str> = host.split('.').collect();
    let firebase_host = match labels.as_slice() {
        [name, "firebaseio", "com"] => valid_label(name),
        [name, region, "firebasedatabase", "app"] => valid_label(name) && valid_label(region),
        _ => false,
    };
    firebase_host.then(|| format!("https://{}/.json?shallow=true", host))
}

/// Object-list URL for a Storage bucket name (`<project>.appspot.com` or
/// `<project>.firebasestorage.app`), else None.
fn storage_probe_url(bucket: &str) -> Option<String> {
    let valid = !bucket.is_empty()
        && bucket.len() <= 222
        && bucket
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"-_.".contains(&b));
    valid.then(|| {
        format!(
            "https://firebasestorage.googleapis.com/v0/b/{}/o?maxResults=1",
            bucket
        )
    })
}

fn open_finding(id: &str, title: &str, description: &str, url: &str, fix: &str) -> Finding {
    Finding {
        id: id.to_string(),
        title: title.to_string(),
        description: description.to_string(),
        severity: Severity::High,
        category: "network".to_string(),
        cwe: Some("CWE-284".to_string()),
        owasp_mobile: Some("M8".to_string()),
        owasp_masvs: None,
        evidence: vec![format!("GET {} -> HTTP 200 without credentials", url)],
        remediation: Some(fix.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rtdb_url_only_for_firebase_hosts() {
        assert_eq!(
            rtdb_probe_url("https://my-app-123.firebaseio.com/").as_deref(),
            Some("https://my-app-123.firebaseio.com/.json?shallow=true")
        );
        assert_eq!(
            rtdb_probe_url("https://my-app.europe-west1.firebasedatabase.app").as_deref(),
            Some("https://my-app.europe-west1.firebasedatabase.app/.json?shallow=true")
        );
        for bad in [
            "http://my-app.firebaseio.com",
            "https://evil.com/.firebaseio.com",
            "https://169.254.169.254",
            "https://a.b.firebaseio.com",
            "https://x.firebaseio.com@evil.com",
        ] {
            assert_eq!(rtdb_probe_url(bad), None, "{bad}");
        }
    }

    #[test]
    fn storage_url_rejects_path_injection() {
        assert_eq!(
            storage_probe_url("my-app.appspot.com").as_deref(),
            Some("https://firebasestorage.googleapis.com/v0/b/my-app.appspot.com/o?maxResults=1")
        );
        assert_eq!(storage_probe_url("a/../../x"), None);
        assert_eq!(storage_probe_url(""), None);
        assert_eq!(storage_probe_url("Upper.appspot.com"), None);
    }
}
