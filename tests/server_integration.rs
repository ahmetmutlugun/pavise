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

use std::{net::SocketAddr, sync::Arc};

use axum::{
    body::Body,
    extract::ConnectInfo,
    http::{Request, StatusCode},
};
use http_body_util::BodyExt;
use pavise::server::{build_router, config::Config, state::AppState};
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
