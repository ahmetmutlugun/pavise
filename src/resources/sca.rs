//! Software Composition Analysis (SCA) — extract version metadata from
//! framework Info.plists bundled inside the IPA.

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
