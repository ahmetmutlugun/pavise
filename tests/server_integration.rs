//! Integration tests for the Pavise HTTP server.
//!
//! These tests use [`pavise::server::build_router`] to create an in-process
//! router and drive it with [`tower::ServiceExt::oneshot`], so no real TCP
//! listener is required.
//!
//! Covered scenarios
//! -----------------
//! * `GET /healthz` returns 200 JSON with `active_scans` and `cache_size`.
//! * `POST /api/upload` (upload init) returns 200 with a JSON `upload_id` — successful API call.
//! * A second `POST /api/upload` from the same IP exceeds the per-IP limit → 429.
//! * `PUT /api/upload/:id/0` with a body larger than `max_upload_bytes` → 413.
//! * `GET /api/scan/<nonexistent-id>/json` → 404.
//! * Upload-session caps, proxy-header spoofing, busy/failed scan cleanup
//!   (incl. non-IPA uploads), the per-scan extraction cap, and PDF on an unknown ID.
//! * Oversized direct multipart body → 413; TTL expiry of reports, cache and
//!   uploads; PDF download of a stored report (needs Chrome/Chromium).

mod common;

use std::{net::SocketAddr, path::Path, sync::Arc};

use axum::{
    body::Body,
    extract::ConnectInfo,
    http::{Request, StatusCode},
};
use http_body_util::BodyExt;
use pavise::server::{
    build_router, config::Config, evict_expired, proxy::Cidr, state::AppState, RESULT_TTL,
    UPLOAD_TTL,
};
use tower::ServiceExt; // for `.oneshot()`

// ── helpers ──────────────────────────────────────────────────────────────────

fn test_addr() -> ConnectInfo<SocketAddr> {
    ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 12345)))
}

/// Build a minimal router with custom config for testing.
fn make_app(config: Config) -> axum::Router {
    build_router(AppState::new(Arc::new(config)))
}

async fn body_bytes(resp: axum::response::Response) -> bytes::Bytes {
    resp.into_body()
        .collect()
        .await
        .expect("collect body")
        .to_bytes()
}

// ── tests ─────────────────────────────────────────────────────────────────────

/// `GET /healthz` should return 200 JSON with the expected keys.
#[tokio::test]
async fn test_healthz_returns_200_with_json() {
    let app = make_app(Config::for_testing());

    let resp = app
        .oneshot(
            Request::builder()
                .uri("/healthz")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);

    let body = body_bytes(resp).await;
    let json: serde_json::Value = serde_json::from_slice(&body).expect("valid JSON");
    assert!(
        json.get("active_scans").is_some(),
        "missing `active_scans` field"
    );
    assert!(
        json.get("cache_size").is_some(),
        "missing `cache_size` field"
    );
    assert_eq!(json["active_scans"], 0, "no scans should be running");
    assert_eq!(json["cache_size"], 0, "cache should be empty");
}

/// `POST /api/upload` with a fresh state should succeed and return an `upload_id`.
/// This exercises the happy-path for the chunked upload initialisation endpoint.
#[tokio::test]
async fn test_upload_init_success() {
    let app = make_app(Config::for_testing());

    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/upload")
                .extension(test_addr())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "upload init should return 200"
    );

    let body = body_bytes(resp).await;
    let json: serde_json::Value = serde_json::from_slice(&body).expect("valid JSON");
    assert!(
        json["upload_id"].as_str().is_some(),
        "response must contain upload_id string"
    );
    assert!(
        json["chunk_size"].as_u64().is_some(),
        "response must contain chunk_size"
    );
}

/// After `rate_limit_max` requests in the same window the next request should
/// get a 429 Too Many Requests.
#[tokio::test]
async fn test_rate_limit_returns_429() {
    // Allow exactly 1 request per minute so the 2nd is rejected.
    let config = Config {
        rate_limit_max: 1,
        ..Config::for_testing()
    };
    let app = make_app(config);

    let make_req = || {
        Request::builder()
            .method("POST")
            .uri("/api/upload")
            .extension(test_addr())
            .body(Body::empty())
            .unwrap()
    };

    // First request: within the limit (count becomes 1, limit is 1).
    let resp1 = app.clone().oneshot(make_req()).await.unwrap();
    assert_eq!(
        resp1.status(),
        StatusCode::OK,
        "first request should succeed"
    );

    // Second request: exceeds the limit (count becomes 2 > 1).
    let resp2 = app.clone().oneshot(make_req()).await.unwrap();
    assert_eq!(
        resp2.status(),
        StatusCode::TOO_MANY_REQUESTS,
        "second request should be rate-limited"
    );
}

/// Uploading a chunk whose size would push the total past `max_upload_bytes`
/// should return 413 Payload Too Large.
#[tokio::test]
async fn test_chunk_too_large_returns_413() {
    // Set a tiny limit so we can test with a small body.
    let config = Config {
        max_upload_bytes: 1024, // 1 KiB
        ..Config::for_testing()
    };
    let app = make_app(config);

    // Step 1: Initialise an upload session.
    let init_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/upload")
                .extension(test_addr())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(init_resp.status(), StatusCode::OK);
    let init_body = body_bytes(init_resp).await;
    let init_json: serde_json::Value =
        serde_json::from_slice(&init_body).expect("valid JSON from init");
    let upload_id = init_json["upload_id"]
        .as_str()
        .expect("upload_id string")
        .to_string();

    // Step 2: PUT a chunk that exceeds max_upload_bytes (2 KiB > 1 KiB limit).
    let big_chunk = vec![0u8; 2048];
    let chunk_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(format!("/api/upload/{upload_id}/0"))
                // chunk handler does NOT use ConnectInfo, so no extension needed
                .body(Body::from(big_chunk))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        chunk_resp.status(),
        StatusCode::PAYLOAD_TOO_LARGE,
        "oversized chunk should return 413"
    );
}

/// Requesting a JSON download for a scan ID that does not exist should return
/// 404 Not Found.
#[tokio::test]
async fn test_unknown_scan_id_returns_404() {
    let app = make_app(Config::for_testing());

    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/scan/nonexistent-scan-id/json")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

// ── hardening ────────────────────────────────────────────────────────────────

fn addr(ip: [u8; 4]) -> ConnectInfo<SocketAddr> {
    ConnectInfo(SocketAddr::from((ip, 40000)))
}

/// Config with its own upload dir, so tests can assert it ends up empty.
fn isolated_config(dir: &Path) -> Config {
    Config {
        upload_dir: dir.to_path_buf(),
        max_upload_bytes: 16 * 1024 * 1024,
        ..Config::for_testing()
    }
}

fn files_in(dir: &Path) -> usize {
    std::fs::read_dir(dir).unwrap().count()
}

async fn send(app: &axum::Router, req: Request<Body>) -> (StatusCode, String) {
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    (
        status,
        String::from_utf8_lossy(&body_bytes(resp).await).into_owned(),
    )
}

fn init_req(from: ConnectInfo<SocketAddr>) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri("/api/upload")
        .extension(from)
        .body(Body::empty())
        .unwrap()
}

/// Init a chunked upload and send `data` as chunk 0; returns the upload id.
async fn upload(app: &axum::Router, data: Vec<u8>) -> String {
    let (status, body) = send(app, init_req(test_addr())).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let json: serde_json::Value = serde_json::from_str(&body).unwrap();
    let id = json["upload_id"].as_str().unwrap().to_string();
    let chunk = Request::builder()
        .method("PUT")
        .uri(format!("/api/upload/{id}/0"))
        .body(Body::from(data))
        .unwrap();
    let (status, body) = send(app, chunk).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    id
}

fn scan_req(id: &str) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(format!("/api/upload/{id}/scan"))
        .header("Accept", "application/json")
        .extension(test_addr())
        .body(Body::empty())
        .unwrap()
}

fn fixture_ipa() -> Vec<u8> {
    let ipa = common::IpaBuilder::new("ServerTest").build();
    std::fs::read(ipa.path()).unwrap()
}

#[tokio::test]
async fn test_upload_sessions_capped_per_ip() {
    let dir = tempfile::tempdir().unwrap();
    let app = make_app(isolated_config(dir.path()));
    let a = addr([198, 51, 100, 1]);
    assert_eq!(send(&app, init_req(a)).await.0, StatusCode::OK);
    assert_eq!(send(&app, init_req(a)).await.0, StatusCode::OK);
    assert_eq!(
        send(&app, init_req(a)).await.0,
        StatusCode::SERVICE_UNAVAILABLE
    );
    // Another client still gets a session (global cap is 4 in testing config).
    assert_eq!(
        send(&app, init_req(addr([198, 51, 100, 2]))).await.0,
        StatusCode::OK
    );
}

#[tokio::test]
async fn test_forwarded_headers_ignored_from_untrusted_peer() {
    let config = Config {
        rate_limit_max: 1,
        ..Config::for_testing()
    };
    let app = make_app(config);
    let req = |fake: &str| {
        Request::builder()
            .method("POST")
            .uri("/api/upload")
            .header("X-Forwarded-For", fake)
            .header("CF-Connecting-IP", fake)
            .extension(addr([203, 0, 113, 7]))
            .body(Body::empty())
            .unwrap()
    };
    assert_ne!(
        send(&app, req("1.1.1.1")).await.0,
        StatusCode::TOO_MANY_REQUESTS
    );
    // A fresh fake IP must not reset the limit for the same peer.
    assert_eq!(
        send(&app, req("2.2.2.2")).await.0,
        StatusCode::TOO_MANY_REQUESTS
    );
}

#[tokio::test]
async fn test_forwarded_headers_honoured_from_trusted_peer() {
    let config = Config {
        rate_limit_max: 1,
        trusted_proxies: Cidr::parse_list("127.0.0.1").unwrap(),
        ..Config::for_testing()
    };
    let app = make_app(config);
    let req = |client: &str| {
        Request::builder()
            .method("POST")
            .uri("/api/upload")
            .header("CF-Connecting-IP", client)
            .extension(test_addr())
            .body(Body::empty())
            .unwrap()
    };
    // Two visitors behind the same proxy are limited separately.
    assert_eq!(send(&app, req("1.1.1.1")).await.0, StatusCode::OK);
    assert_eq!(send(&app, req("2.2.2.2")).await.0, StatusCode::OK);
    assert_eq!(
        send(&app, req("1.1.1.1")).await.0,
        StatusCode::TOO_MANY_REQUESTS
    );
}

#[tokio::test]
async fn test_busy_scan_keeps_upload_then_scan_cleans_up() {
    let dir = tempfile::tempdir().unwrap();
    let state = AppState::new(Arc::new(isolated_config(dir.path())));
    let app = build_router(state.clone());
    let id = upload(&app, fixture_ipa()).await;

    let all = state.config.max_concurrent_scans as u32;
    let held = Arc::clone(&state.semaphore)
        .acquire_many_owned(all)
        .await
        .unwrap();
    let (_, body) = send(&app, scan_req(&id)).await;
    assert!(body.contains("Server busy"), "{body}");
    assert!(
        state.uploads.read().await.contains_key(&id),
        "session kept for retry"
    );
    assert_eq!(files_in(dir.path()), 1, "upload kept on disk for retry");

    drop(held);
    let (status, body) = send(&app, scan_req(&id)).await;
    assert_eq!(status, StatusCode::OK);
    let report: serde_json::Value = serde_json::from_str(&body).expect("JSON report");
    assert!(report["grade"].is_string());
    assert_eq!(files_in(dir.path()), 0, "upload deleted after scan");
    assert_eq!(
        state.semaphore.available_permits(),
        all as usize,
        "permit released"
    );
}

#[tokio::test]
async fn test_failed_scan_cleans_up_upload() {
    let dir = tempfile::tempdir().unwrap();
    let app = make_app(isolated_config(dir.path()));
    let id = upload(&app, b"definitely not a zip".to_vec()).await;
    let (_, body) = send(&app, scan_req(&id)).await;
    assert!(body.contains("Scan failed"), "{body}");
    assert_eq!(files_in(dir.path()), 0);
}

#[tokio::test]
async fn test_extraction_cap_applies_to_server_scans() {
    let dir = tempfile::tempdir().unwrap();
    let config = Config {
        max_extracted_bytes: 64 * 1024,
        ..isolated_config(dir.path())
    };
    let app = make_app(config);
    // Random-ish bytes so deflate can't shrink it below the ratio check.
    let blob: Vec<u8> = (0..256 * 1024u32)
        .map(|i| (i.wrapping_mul(2654435761) >> 13) as u8)
        .collect();
    let ipa = common::IpaBuilder::new("Big")
        .add_bundle_file("blob.bin", blob)
        .build();
    let bytes = std::fs::read(ipa.path()).unwrap();
    let id = upload(&app, bytes.clone()).await;
    let (_, body) = send(&app, scan_req(&id)).await;
    assert!(body.contains("Scan failed"), "{body}");
    assert_eq!(files_in(dir.path()), 0);

    // Control: the same IPA scans fine under the default cap.
    let ok_app = make_app(isolated_config(dir.path()));
    let id = upload(&ok_app, bytes).await;
    let (status, body) = send(&ok_app, scan_req(&id)).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        serde_json::from_str::<serde_json::Value>(&body).is_ok(),
        "{body}"
    );
}

#[tokio::test]
async fn test_direct_multipart_scan_cleans_up() {
    let dir = tempfile::tempdir().unwrap();
    let app = make_app(isolated_config(dir.path()));
    let boundary = "XPAVISEBOUNDARY";
    let mut body = format!(
        "--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"a.ipa\"\r\n\
         Content-Type: application/octet-stream\r\n\r\n"
    )
    .into_bytes();
    body.extend(fixture_ipa());
    body.extend(format!("\r\n--{boundary}--\r\n").into_bytes());
    let req = Request::builder()
        .method("POST")
        .uri("/api/scan")
        .header(
            "Content-Type",
            format!("multipart/form-data; boundary={boundary}"),
        )
        .header("Accept", "application/json")
        .extension(test_addr())
        .body(Body::from(body))
        .unwrap();
    let (status, body) = send(&app, req).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        serde_json::from_str::<serde_json::Value>(&body).is_ok(),
        "{body}"
    );
    assert_eq!(files_in(dir.path()), 0, "temp upload deleted");
}

#[tokio::test]
async fn test_unknown_scan_id_pdf_returns_404() {
    let app = make_app(Config::for_testing());
    let req = Request::builder()
        .uri("/api/scan/nope/pdf")
        .extension(test_addr())
        .body(Body::empty())
        .unwrap();
    assert_eq!(send(&app, req).await.0, StatusCode::NOT_FOUND);
}

fn multipart_scan_req(payload: Vec<u8>) -> Request<Body> {
    let boundary = "XPAVISEBOUNDARY";
    let mut body = format!(
        "--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"a.ipa\"\r\n\
         Content-Type: application/octet-stream\r\n\r\n"
    )
    .into_bytes();
    body.extend(payload);
    body.extend(format!("\r\n--{boundary}--\r\n").into_bytes());
    Request::builder()
        .method("POST")
        .uri("/api/scan")
        .header(
            "Content-Type",
            format!("multipart/form-data; boundary={boundary}"),
        )
        .header("Accept", "application/json")
        .extension(test_addr())
        .body(Body::from(body))
        .unwrap()
}

#[tokio::test]
async fn test_oversized_direct_upload_returns_413() {
    let dir = tempfile::tempdir().unwrap();
    let config = Config {
        max_upload_bytes: 4 * 1024,
        ..isolated_config(dir.path())
    };
    let app = make_app(config);
    let (status, _) = send(&app, multipart_scan_req(vec![7u8; 8 * 1024])).await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(files_in(dir.path()), 0, "partial upload deleted");
}

fn scanned_report() -> Arc<pavise::types::ScanReport> {
    let ipa = common::IpaBuilder::new("TtlTest").build();
    let opts = pavise::ScanOptions {
        rules_dir: None,
        min_severity: pavise::types::Severity::Info,
        network: false,
        show_progress: false,
        max_extracted_bytes: None,
        max_in_flight_bytes: None,
    };
    Arc::new(pavise::scan_ipa(ipa.path(), &opts).expect("scan fixture"))
}

fn json_req(id: &str) -> Request<Body> {
    Request::builder()
        .uri(format!("/api/scan/{id}/json"))
        .body(Body::empty())
        .unwrap()
}

/// `Instant` that is `age` in the past.
fn aged(age: std::time::Duration) -> std::time::Instant {
    std::time::Instant::now()
        .checked_sub(age)
        .expect("monotonic clock far enough from boot")
}

#[tokio::test]
async fn test_expired_entries_not_served_and_evicted() {
    let dir = tempfile::tempdir().unwrap();
    let state = AppState::new(Arc::new(isolated_config(dir.path())));
    let app = build_router(state.clone());
    let report = scanned_report();
    let expired = RESULT_TTL + std::time::Duration::from_secs(1);
    {
        let mut store = state.store.write().await;
        store.insert(
            "fresh".into(),
            (Arc::clone(&report), aged(Default::default())),
        );
        store.insert("old".into(), (Arc::clone(&report), aged(expired)));
        let mut cache = state.cache.write().await;
        let cache_age = state.config.cache_ttl + std::time::Duration::from_secs(1);
        cache.insert("oldhash".into(), (Arc::clone(&report), aged(cache_age)));
    }

    // An expired report is gone before the sweep runs.
    assert_eq!(send(&app, json_req("fresh")).await.0, StatusCode::OK);
    assert_eq!(send(&app, json_req("old")).await.0, StatusCode::NOT_FOUND);

    // An upload session past its TTL is dropped and its file deleted.
    let id = upload(&app, b"partial".to_vec()).await;
    assert_eq!(files_in(dir.path()), 1);
    {
        let uploads = state.uploads.read().await;
        let mut session = uploads[&id].session.lock().unwrap();
        session.created_at = aged(UPLOAD_TTL + std::time::Duration::from_secs(1));
    }

    evict_expired(&state).await;
    let store = state.store.read().await;
    assert!(store.contains_key("fresh"));
    assert!(!store.contains_key("old"));
    assert!(state.cache.read().await.is_empty());
    assert!(state.uploads.read().await.is_empty());
    assert_eq!(files_in(dir.path()), 0, "abandoned upload deleted");
}

/// Renders through headless Chrome, which GitHub's runners ship; a missing
/// browser fails this test rather than skipping it.
#[tokio::test]
async fn test_pdf_download_of_stored_report() {
    let state = AppState::new(Arc::new(Config::for_testing()));
    let app = build_router(state.clone());
    state.store.write().await.insert(
        "0123456789abcdef".into(),
        (scanned_report(), aged(Default::default())),
    );
    let req = Request::builder()
        .uri("/api/scan/0123456789abcdef/pdf")
        .extension(test_addr())
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(resp.headers()["content-type"], "application/pdf");
    assert_eq!(
        resp.headers()["content-disposition"],
        "attachment; filename=\"pavise-01234567.pdf\""
    );
    let body = body_bytes(resp).await;
    assert!(body.starts_with(b"%PDF-"), "not a PDF");
    assert_eq!(
        state.pdf_semaphore.available_permits(),
        1,
        "permit released"
    );
}
