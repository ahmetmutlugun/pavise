//! Software Composition Analysis (SCA) — extract version metadata from
//! framework Info.plists bundled inside the IPA, and from CocoaPods/SPM
//! lock files if present.

use crate::types::FrameworkComponent;
use crate::unpacker::ExtractedFile;
use tracing::debug;

/// For each framework binary path, look for a sibling `Info.plist` and
/// extract `CFBundleIdentifier` + `CFBundleShortVersionString`.
pub fn extract_components(
    framework_binary_paths: &[String],
    files: &[ExtractedFile],
) -> Vec<FrameworkComponent> {
    let mut components = Vec::new();

    for bin_path in framework_binary_paths {
        // bin_path is e.g. "Payload/App.app/Frameworks/Alamofire.framework/Alamofire"
        // The Info.plist lives at    "Payload/App.app/Frameworks/Alamofire.framework/Info.plist"
        let plist_path = {
            // Strip the binary filename (last segment) and append Info.plist
            let mut parts: Vec<&str> = bin_path.split('/').collect();
            if parts.is_empty() {
                continue;
            }
            let _binary_name = parts.pop().unwrap_or("");
            parts.push("Info.plist");
            parts.join("/")
        };

        // Derive a display name from the binary filename
        let name = bin_path
            .split('/')
            .next_back()
            .unwrap_or(bin_path.as_str())
            .to_string();

        let plist_file = match files.iter().find(|f| f.path == plist_path) {
            Some(f) => f,
            None => {
                debug!("No Info.plist found for framework: {}", bin_path);
                // Still emit an entry with no version so the framework appears in output
                components.push(FrameworkComponent {
                    name,
                    bundle_id: None,
                    version: None,
                    path: bin_path.clone(),
                });
                continue;
            }
        };

        let (bundle_id, version) = parse_framework_plist(&plist_file.data);
        components.push(FrameworkComponent {
            name,
            bundle_id,
            version,
            path: bin_path.clone(),
        });
    }

    components
}

/// Extract dependency components from CocoaPods `Podfile.lock` and SPM
/// `Package.resolved` files found anywhere in the IPA archive.
///
/// These files are not normally shipped in production IPAs, but developer or
/// CI-produced archives sometimes include them. Parsing them gives richer
/// transitive dependency coverage than bundled framework binaries alone.
pub fn extract_lockfile_deps(files: &[ExtractedFile]) -> Vec<FrameworkComponent> {
    let mut components = Vec::new();
    for f in files {
        let filename = f.path.split('/').next_back().unwrap_or(&f.path);
        match filename {
            "Podfile.lock" => {
                if let Ok(text) = std::str::from_utf8(&f.data) {
                    components.extend(parse_podfile_lock(text, &f.path));
                }
            }
            "Package.resolved" => {
                components.extend(parse_package_resolved(&f.data, &f.path));
            }
            _ => {}
        }
    }
    components
}

/// Parse first-level pod entries from a Podfile.lock.
///
/// Format:
/// ```text
/// PODS:
///   - Alamofire (5.6.4)
///   - Firebase/Analytics (10.0.0):
///     - FirebaseAnalytics (= 10.0.0)
/// ```
fn parse_podfile_lock(text: &str, source_path: &str) -> Vec<FrameworkComponent> {
    let mut components = Vec::new();
    let mut in_pods = false;

    for line in text.lines() {
        if line == "PODS:" {
            in_pods = true;
            continue;
        }
        // Any non-indented section header ends the PODS block
        if !line.starts_with(' ') && !line.is_empty() {
            in_pods = false;
        }
        if !in_pods {
            continue;
        }
        // First-level entries have exactly 2-space indent: "  - Name (version)"
        // Sub-dependencies have 4-space indent: "    - Name (= version)" — skip those
        if !line.starts_with("  - ") || line.starts_with("    ") {
            continue;
        }
        let rest = &line[4..]; // strip leading "  - "
        let name;
        let version;
        if let Some(paren_pos) = rest.find('(') {
            name = rest[..paren_pos].trim().trim_end_matches(':').to_string();
            let after_open = &rest[paren_pos + 1..];
            version = after_open
                .find(')')
                .map(|end| after_open[..end].trim().to_string());
        } else {
            continue;
        }
        if name.is_empty() {
            continue;
        }
        // Use the base pod name (strip "/Subspec" suffix if present)
        let base_name = name.split('/').next().unwrap_or(&name).to_string();

        components.push(FrameworkComponent {
            name: base_name,
            bundle_id: None,
            version,
            path: source_path.to_string(),
        });
    }

    // Deduplicate by name (keep first occurrence)
    let mut seen = std::collections::HashSet::new();
    components.retain(|c| seen.insert(c.name.clone()));
    components
}

/// Parse dependencies from a SPM `Package.resolved` file (v1 and v2 format).
fn parse_package_resolved(data: &[u8], source_path: &str) -> Vec<FrameworkComponent> {
    let value: serde_json::Value = match serde_json::from_slice(data) {
        Ok(v) => v,
        Err(e) => {
            debug!("Failed to parse Package.resolved: {}", e);
            return Vec::new();
        }
    };

    let version = value.get("version").and_then(|v| v.as_u64()).unwrap_or(1);

    let pins: Option<&serde_json::Value> = if version >= 2 {
        // v2: { "pins": [...], "version": 2 }
        value.get("pins")
    } else {
        // v1: { "object": { "pins": [...] }, "version": 1 }
        value.get("object").and_then(|o| o.get("pins"))
    };

    let pins_array = match pins.and_then(|p| p.as_array()) {
        Some(a) => a,
        None => return Vec::new(),
    };

    let mut components = Vec::new();
    for pin in pins_array {
        // Name: v2 uses "identity", v1 uses "package"
        let name = pin
            .get("identity")
            .or_else(|| pin.get("package"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        if name.is_empty() {
            continue;
        }

        let state = pin.get("state");
        let pkg_version = state
            .and_then(|s| s.get("version"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        components.push(FrameworkComponent {
            name,
            bundle_id: None,
            version: pkg_version,
            path: source_path.to_string(),
        });
    }

    components
}

fn parse_framework_plist(data: &[u8]) -> (Option<String>, Option<String>) {
    let value: plist::Value = match plist::from_bytes(data) {
        Ok(v) => v,
        Err(e) => {
            debug!("Failed to parse framework Info.plist: {}", e);
            return (None, None);
        }
    };

    let dict = match value.as_dictionary() {
        Some(d) => d,
        None => return (None, None),
    };

    let bundle_id = dict
        .get("CFBundleIdentifier")
        .and_then(|v| v.as_string())
        .map(|s| s.to_string());

    let version = dict
        .get("CFBundleShortVersionString")
        .and_then(|v| v.as_string())
        .map(|s| s.to_string())
        .or_else(|| {
            dict.get("CFBundleVersion")
                .and_then(|v| v.as_string())
                .map(|s| s.to_string())
        });

    (bundle_id, version)
}
