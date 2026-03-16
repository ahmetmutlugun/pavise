use tracing::debug;

use crate::types::FirebaseInfo;

/// Detect Firebase from GoogleService-Info.plist content.
pub fn parse_google_service_info(data: &[u8]) -> Option<FirebaseInfo> {
    let value: plist::Value = plist::from_bytes(data).ok()?;
    let dict = value.as_dictionary()?;

    let project_id = dict
        .get("PROJECT_ID")
        .and_then(|v| v.as_string())
        .map(|s| s.to_string());

    let database_url = dict
        .get("DATABASE_URL")
        .and_then(|v| v.as_string())
        .map(|s| s.to_string());

    let api_key = dict
        .get("API_KEY")
        .and_then(|v| v.as_string())
        .map(|s| s.to_string());

    let bundle_id = dict
        .get("BUNDLE_ID")
        .and_then(|v| v.as_string())
        .map(|s| s.to_string());

    let google_app_id = dict
        .get("GOOGLE_APP_ID")
        .and_then(|v| v.as_string())
        .map(|s| s.to_string());

    debug!(
        "Firebase detected: project_id={:?}, database_url={:?}",
        project_id, database_url
    );

    Some(FirebaseInfo {
        project_id,
        database_url,
        api_key,
        bundle_id,
        google_app_id,
    })
}
