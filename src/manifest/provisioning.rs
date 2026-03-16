//! Parse `embedded.mobileprovision` files.
//!
//! A mobileprovision file is a CMS (PKCS#7) signed blob.  We don't need to
//! verify the signature — we just need the plist payload embedded inside.
//! The strategy is simple: scan the raw bytes for the start of a plist
//! (`<?xml` or the binary plist magic `bplist`) and extract until the
//! matching end tag or a fixed length, then parse normally.

use crate::types::ProvisioningInfo;
use tracing::debug;

pub fn parse(data: &[u8]) -> Option<ProvisioningInfo> {
    let plist_bytes = extract_plist_bytes(data)?;
    parse_plist(&plist_bytes)
}

/// Locate the embedded plist inside the CMS envelope.
fn extract_plist_bytes(data: &[u8]) -> Option<Vec<u8>> {
    // XML plist: find "<?xml" and "</plist>"
    if let Some(start) = find_subsequence(data, b"<?xml") {
        if let Some(end_offset) = find_subsequence(&data[start..], b"</plist>") {
            let end = start + end_offset + b"</plist>".len();
            return Some(data[start..end].to_vec());
        }
    }

    // Binary plist: find "bplist" magic
    if let Some(start) = find_subsequence(data, b"bplist00") {
        // Binary plists don't have a reliable end marker in raw bytes.
        // Return from the magic to the end of the file — plist will stop
        // reading when it has consumed the structure.
        return Some(data[start..].to_vec());
    }

    None
}

/// Convert a `SystemTime` to a `YYYY-MM-DD` string without external dependencies.
///
/// Uses the civil-time algorithm from Howard Hinnant:
/// <https://howardhinnant.github.io/date_algorithms.html>
fn format_date(sys: std::time::SystemTime) -> String {
    let secs = match sys.duration_since(std::time::UNIX_EPOCH) {
        Ok(d) => d.as_secs() as i64,
        Err(_) => return "unknown".to_string(),
    };

    // Days since 1970-01-01
    let z = secs / 86400 + 719468; // shift to March 1, 0000 era
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = z - era * 146097;                          // day of era [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365; // year of era [0, 399]
    let y   = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // day of year [0, 365]
    let mp  = (5 * doy + 2) / 153;                      // month prime [0, 11]
    let d   = doy - (153 * mp + 2) / 5 + 1;             // day [1, 31]
    let m   = if mp < 10 { mp + 3 } else { mp - 9 };    // month [1, 12]
    let y   = if m <= 2 { y + 1 } else { y };

    format!("{:04}-{:02}-{:02}", y, m, d)
}

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|w| w == needle)
}

fn parse_plist(data: &[u8]) -> Option<ProvisioningInfo> {
    let value: plist::Value = plist::from_bytes(data)
        .map_err(|e| debug!("Failed to parse mobileprovision plist: {}", e))
        .ok()?;

    let dict = value.as_dictionary()?;

    let name = dict
        .get("Name")
        .and_then(|v| v.as_string())
        .map(|s| s.to_string());

    let team_name = dict
        .get("TeamName")
        .and_then(|v| v.as_string())
        .map(|s| s.to_string());

    let team_id = dict
        .get("TeamIdentifier")
        .and_then(|v| v.as_array())
        .and_then(|arr| arr.first())
        .and_then(|v| v.as_string())
        .map(|s| s.to_string());

    // Expiration date
    let expiration_date = dict
        .get("ExpirationDate")
        .and_then(|v| v.as_date())
        .map(|d| {
            let sys: std::time::SystemTime = d.into();
            format_date(sys)
        });

    // Provisioned devices (ProvisionedDevices key, present in development and ad-hoc)
    let provisioned_device_count = dict
        .get("ProvisionedDevices")
        .and_then(|v| v.as_array())
        .map(|arr| arr.len())
        .unwrap_or(0);

    // Determine profile type
    let profile_type = determine_profile_type(dict, provisioned_device_count);

    Some(ProvisioningInfo {
        name,
        team_name,
        team_id,
        profile_type,
        expiration_date,
        provisioned_device_count,
    })
}

fn determine_profile_type(dict: &plist::Dictionary, device_count: usize) -> String {
    // ProvisionsAllDevices = true → Enterprise (in-house) distribution
    if dict
        .get("ProvisionsAllDevices")
        .and_then(|v| v.as_boolean())
        == Some(true)
    {
        return "enterprise".to_string();
    }

    // Check entitlements for get-task-allow = true → development
    let get_task_allow = dict
        .get("Entitlements")
        .and_then(|v| v.as_dictionary())
        .and_then(|e| e.get("get-task-allow"))
        .and_then(|v| v.as_boolean())
        .unwrap_or(false);

    if get_task_allow {
        return "development".to_string();
    }

    // Has specific device UDIDs → ad-hoc
    if device_count > 0 {
        return "ad-hoc".to_string();
    }

    "app-store".to_string()
}
