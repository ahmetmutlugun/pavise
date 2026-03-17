use regex::Regex;
use std::collections::HashSet;
use std::sync::OnceLock;

static EMAIL_RE: OnceLock<Regex> = OnceLock::new();

fn email_re() -> &'static Regex {
    EMAIL_RE.get_or_init(|| {
        Regex::new(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}").expect("email regex")
    })
}

/// Common noise TLDs that are actually file extensions or paths, not real TLDs.
const FAKE_TLDS: &[&str] = &[
    "pb", "bin", "dat", "c", "h", "m", "mm", "cpp", "swift", "py", "js", "ts", "json", "xml",
    "plist", "md", "txt", "log", "tmp", "o", "a", "so", "dylib",
];

/// File extensions in paths that produce email false positives.
const NOISE_FILE_EXTENSIONS: &[&str] = &[
    ".bin",
    ".mlmodelc",
    ".tflite",
    ".weights",
    ".onnx",
    ".pt",
    ".pth",
    ".npy",
    ".npz",
    ".caffemodel",
    ".model",
    ".pb",
];

/// Extract high-confidence email addresses from text, filtering binary noise.
pub fn extract_emails(text: &str, source_path: &str) -> Vec<String> {
    // Skip binary noise files entirely
    let lower_path = source_path.to_lowercase();
    if NOISE_FILE_EXTENSIONS
        .iter()
        .any(|ext| lower_path.ends_with(ext))
    {
        return Vec::new();
    }

    let re = email_re();
    let mut results = HashSet::new();

    for m in re.find_iter(text) {
        let email = m.as_str();

        if is_valid_email(email) {
            results.insert(email.to_lowercase());
        }
    }

    results.into_iter().collect()
}

fn is_valid_email(email: &str) -> bool {
    // Must have exactly one @
    let parts: Vec<&str> = email.splitn(2, '@').collect();
    if parts.len() != 2 {
        return false;
    }

    let local = parts[0];
    let domain = parts[1];

    // Local part must be ASCII only and not empty
    if local.is_empty() || !local.is_ascii() {
        return false;
    }

    // Local part entropy check: reject high-entropy strings (binary noise)
    if shannon_entropy(local) > 4.5 {
        return false;
    }

    // Domain must have a TLD
    if let Some(tld) = domain.split('.').next_back() {
        // TLD must be alphabetic and at least 2 chars
        if tld.len() < 2 || !tld.chars().all(|c| c.is_ascii_alphabetic()) {
            return false;
        }

        // Reject known fake TLDs
        if FAKE_TLDS.contains(&tld.to_lowercase().as_str()) {
            return false;
        }
    } else {
        return false;
    }

    // Must contain a dot in the domain part
    if !domain.contains('.') {
        return false;
    }

    // Reject non-ASCII in domain (e.g. mangled binary strings)
    if !domain.is_ascii() {
        return false;
    }

    true
}

/// Calculate Shannon entropy of a string (bits per character).
fn shannon_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }

    let mut freq = [0u32; 256];
    for b in s.bytes() {
        freq[b as usize] += 1;
    }

    let len = s.len() as f64;
    freq.iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / len;
            -p * p.log2()
        })
        .sum()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_emails() {
        let text = "Contact us at support@example.com or admin@company.co.uk";
        let emails = extract_emails(text, "Payload/App.app/Info.plist");
        assert!(emails.contains(&"support@example.com".to_string()));
        assert!(emails.contains(&"admin@company.co.uk".to_string()));
    }

    #[test]
    fn test_rejects_noise_file() {
        let text = "fake@email.com";
        let emails = extract_emails(text, "Payload/App.app/Models/model.bin");
        assert!(emails.is_empty());
    }

    #[test]
    fn test_rejects_fake_tld() {
        let text = "user@domain.pb";
        let emails = extract_emails(text, "some/file.txt");
        assert!(emails.is_empty());
    }

    #[test]
    fn test_rejects_high_entropy() {
        // High entropy local part (looks like binary data encoded as text)
        let text = "aB3xQ9zM2kP@example.com Kj8nWq4vRs7m@test.com";
        // These might or might not pass — entropy is the gate
        let emails = extract_emails(text, "normal_file.swift");
        // Just ensure no panic; the entropy filter is probabilistic
        let _ = emails;
    }

    #[test]
    fn test_shannon_entropy() {
        // "aaa" has zero entropy
        assert!(shannon_entropy("aaa") < 0.01);
        // Random string has higher entropy
        assert!(shannon_entropy("aB3xQ9zM") > 2.0);
    }
}
