//! HTTP handlers and middleware for the web server (`pavise-server`).

use std::{
    io::Write,
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::{Duration, Instant},
};

use axum::{
    body::{Body, Bytes},
    extract::{ConnectInfo, Extension, Multipart, Path, State},
    http::{header, HeaderMap, Request, StatusCode},
    middleware::Next,
    response::{Html, IntoResponse, Response},
    Json,
};
use sha2::{Digest, Sha256};
use tempfile::TempPath;
use tokio::sync::OwnedSemaphorePermit;
use tracing::Instrument;
use uuid::Uuid;

use super::{
    proxy::real_ip,
    state::{insert_capped, AppState, RateLimitEntry, UploadSession, UploadSlot},
    RATE_LIMIT_WINDOW,
};
use crate::{
    report::{json, pdf},
    scan_ipa,
    types::{ScanReport, Severity},
    ScanOptions,
};

/// Budget for one PDF render (Chrome is torn down within it).
const PDF_TIMEOUT: Duration = Duration::from_secs(60);

/// Chunk size advertised to the browser client (must fit under `CHUNK_LIMIT`).
const CHUNK_SIZE: usize = 50 * 1024 * 1024;

/// Upload sessions one client IP may hold open at once.
const MAX_UPLOAD_SESSIONS_PER_IP: usize = 2;

// ── CSP nonce ─────────────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct CspNonce(String);

fn generate_nonce() -> String {
    Uuid::new_v4().simple().to_string()
}

// ── Health check ──────────────────────────────────────────────────────────────

#[derive(serde::Serialize)]
pub struct HealthResponse {
    active_scans: usize,
    cache_size: usize,
}

pub async fn healthz(State(state): State<AppState>) -> Json<HealthResponse> {
    let available = state.semaphore.available_permits();
    let active_scans = state.config.max_concurrent_scans.saturating_sub(available);
    let cache_size = state.cache.read().await.len();
    Json(HealthResponse {
        active_scans,
        cache_size,
    })
}

// ── HTML page handlers ────────────────────────────────────────────────────────

pub async fn landing(
    State(state): State<AppState>,
    Extension(nonce): Extension<CspNonce>,
) -> Response {
    serve_html(&state, "index.html", &nonce.0).await
}

pub async fn scan_page(
    State(state): State<AppState>,
    Extension(nonce): Extension<CspNonce>,
) -> Response {
    serve_html(&state, "scan.html", &nonce.0).await
}

async fn serve_html(state: &AppState, name: &str, nonce: &str) -> Response {
    let path = state.config.dist_dir.join(name);
    match tokio::fs::read_to_string(&path).await {
        Ok(html) => Html(inject_nonce(&html, nonce)).into_response(),
        Err(e) => {
            tracing::error!("Frontend file not found ({}): {e}", path.display());
            (StatusCode::INTERNAL_SERVER_ERROR, "Frontend not available").into_response()
        }
    }
}

/// Inject a CSP nonce attribute into inline `<script>` tags (those without a `src=` attribute).
fn inject_nonce(html: &str, nonce: &str) -> String {
    let mut result = String::with_capacity(html.len() + 128);
    let mut remaining = html;
    while let Some(start) = remaining.find("<script") {
        result.push_str(&remaining[..start]);
        remaining = &remaining[start..];
        if let Some(tag_end) = remaining.find('>') {
            let tag = &remaining[..tag_end];
            result.push_str(tag);
            if !tag.contains("src=") {
                result.push_str(&format!(" nonce=\"{nonce}\""));
            }
            result.push('>');
            remaining = &remaining[tag_end + 1..];
        } else {
            result.push_str(remaining);
            return result;
        }
    }
    result.push_str(remaining);
    result
}

pub async fn robots_txt() -> ([(header::HeaderName, &'static str); 1], &'static str) {
    (
        [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
        "User-agent: *\nAllow: /\nAllow: /scan\nDisallow: /api/\n\nSitemap: https://pavise.app/sitemap.xml\n",
    )
}

pub async fn sitemap_xml() -> ([(header::HeaderName, &'static str); 1], &'static str) {
    (
        [(header::CONTENT_TYPE, "application/xml; charset=utf-8")],
        r#"<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url>
    <loc>https://pavise.app/</loc>
    <changefreq>weekly</changefreq>
    <priority>1.0</priority>
  </url>
  <url>
    <loc>https://pavise.app/scan</loc>
    <changefreq>weekly</changefreq>
    <priority>0.8</priority>
  </url>
</urlset>"#,
    )
}

// ── Response format detection ─────────────────────────────────────────────────

/// Returns true when the caller wants a JSON response rather than an HTML fragment.
/// Triggered by `curl/*` User-Agent (default curl behaviour) or an explicit
/// `Accept: application/json` header.
fn wants_json(headers: &HeaderMap) -> bool {
    if headers
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|ua| ua.starts_with("curl/"))
    {
        return true;
    }
    headers
        .get(header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|a| a.contains("application/json"))
}

// ── Rate limiting ─────────────────────────────────────────────────────────────

fn client_ip(state: &AppState, addr: SocketAddr, headers: &HeaderMap) -> IpAddr {
    real_ip(addr, headers, &state.config.trusted_proxies)
}

/// Returns a `429 Too Many Requests` response if the caller has exceeded the
/// per-IP sliding-window limit, otherwise returns `None`.
async fn check_rate_limit(state: &AppState, ip: IpAddr) -> Option<Response> {
    let max = state.config.rate_limit_max;
    let mut limits = state.rate_limits.write().await;
    let entry = limits.entry(ip).or_insert(RateLimitEntry {
        count: 0,
        window_start: Instant::now(),
    });

    if entry.window_start.elapsed() >= RATE_LIMIT_WINDOW {
        entry.count = 0;
        entry.window_start = Instant::now();
    }

    entry.count += 1;
    if entry.count > max {
        tracing::warn!(ip = %ip, count = entry.count, limit = max, "Rate limit exceeded");
        Some(
            (
                StatusCode::TOO_MANY_REQUESTS,
                format!(
                    "Rate limit exceeded: maximum {max} requests per minute. Try again shortly."
                ),
            )
                .into_response(),
        )
    } else {
        None
    }
}

/// Take a scan slot. The permit is owned so it can move into the blocking
/// scan task: a client disconnect drops the handler future, but the slot
/// stays held until the scan really ends.
fn try_scan_permit(state: &AppState) -> Option<OwnedSemaphorePermit> {
    Arc::clone(&state.semaphore).try_acquire_owned().ok()
}

fn busy(state: &AppState) -> Response {
    error_fragment(&format!(
        "Server busy: maximum {} concurrent scans in progress. Try again shortly.",
        state.config.max_concurrent_scans
    ))
}

// ── Direct multipart upload ───────────────────────────────────────────────────

pub async fn scan_handler(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    mut multipart: Multipart,
) -> Response {
    if let Some(resp) = check_rate_limit(&state, client_ip(&state, addr, &headers)).await {
        return resp;
    }
    let json_response = wants_json(&headers);

    // Deleted on drop, on every early return below and on panic.
    let tmp = match tempfile::Builder::new()
        .suffix(".ipa")
        .tempfile_in(&state.config.upload_dir)
    {
        Ok(f) => f,
        Err(e) => {
            tracing::error!("Failed to create temp file: {e}");
            return error_fragment("Upload failed due to a server error");
        }
    };

    let mut writer = std::io::BufWriter::new(tmp.as_file());
    let mut hasher = Sha256::new();
    let mut received = 0u64;
    let max_bytes = state.config.max_upload_bytes;

    // The upload is read before a scan slot is taken, so slow uploads can't
    // starve scans (the body itself is bounded by the router's body timeout).
    loop {
        match multipart.next_field().await {
            Ok(Some(mut field)) => {
                if field.name() != Some("file") {
                    continue;
                }
                loop {
                    match field.chunk().await {
                        Ok(Some(chunk)) => {
                            received += chunk.len() as u64;
                            if received > max_bytes {
                                return too_large(max_bytes);
                            }
                            if let Err(e) = writer.write_all(&chunk) {
                                tracing::error!("Failed to write upload chunk: {e}");
                                return error_fragment("Upload failed due to a server error");
                            }
                            hasher.update(&chunk);
                        }
                        Ok(None) => break,
                        // The router's body limit fires before `max_bytes`
                        // (multipart framing counts toward it).
                        Err(e) if e.status() == StatusCode::PAYLOAD_TOO_LARGE => {
                            return too_large(max_bytes);
                        }
                        Err(e) => {
                            tracing::error!("Failed to read upload data: {e}");
                            return error_fragment("Upload failed due to a server error");
                        }
                    }
                }
            }
            Ok(None) => break,
            Err(e) if e.status() == StatusCode::PAYLOAD_TOO_LARGE => {
                return too_large(max_bytes);
            }
            Err(e) => {
                tracing::error!("Multipart parse error: {e}");
                return error_fragment("Upload failed due to a server error");
            }
        }
    }

    if received == 0 {
        return error_fragment("No IPA file received");
    }
    if let Err(e) = writer.flush() {
        tracing::error!("Failed to flush upload: {e}");
        return error_fragment("Upload failed due to a server error");
    }
    drop(writer);

    let hash = hex::encode(hasher.finalize());
    if let Some(response) = try_cache_hit(&state, &hash, json_response).await {
        return response;
    }
    let Some(permit) = try_scan_permit(&state) else {
        return busy(&state);
    };
    run_scan(state, tmp.into_temp_path(), hash, permit, json_response).await
}

fn too_large(max_bytes: u64) -> Response {
    (
        StatusCode::PAYLOAD_TOO_LARGE,
        format!(
            "Upload exceeds maximum size of {} MiB",
            max_bytes / (1024 * 1024)
        ),
    )
        .into_response()
}

// ── Chunked upload endpoints ──────────────────────────────────────────────────

#[derive(serde::Serialize)]
struct UploadInitResponse {
    upload_id: String,
    chunk_size: usize,
}

/// `POST /api/upload` — initialise a new chunked upload session.
///
/// Rate-limited with the same per-IP limiter applied to scan endpoints, and
/// capped globally and per IP: each session may grow to `max_upload_bytes`
/// on disk, so unbounded sessions could fill the upload volume.
pub async fn upload_init(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Response {
    let ip = client_ip(&state, addr, &headers);
    if let Some(resp) = check_rate_limit(&state, ip).await {
        return resp;
    }

    let mut uploads = state.uploads.write().await;
    let from_ip = uploads.values().filter(|s| s.ip == ip).count();
    if uploads.len() >= state.config.max_upload_sessions || from_ip >= MAX_UPLOAD_SESSIONS_PER_IP {
        tracing::warn!(ip = %ip, active = uploads.len(), from_ip, "Upload session cap reached");
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "Too many uploads in progress. Try again shortly.",
        )
            .into_response();
    }

    let upload_id = Uuid::new_v4().to_string();
    let file_path = state.config.upload_dir.join(format!("{upload_id}.ipa"));
    if let Err(e) = std::fs::File::create(&file_path) {
        tracing::error!("Failed to create upload file: {e}");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Upload initialization failed",
        )
            .into_response();
    }

    let session = UploadSession {
        path: file_path,
        hasher: Sha256::new(),
        received: 0,
        next_index: 0,
        created_at: Instant::now(),
    };
    let slot = UploadSlot {
        ip,
        session: std::sync::Mutex::new(session),
    };
    uploads.insert(upload_id.clone(), Arc::new(slot));
    drop(uploads);

    Json(UploadInitResponse {
        upload_id,
        chunk_size: CHUNK_SIZE,
    })
    .into_response()
}

pub async fn upload_chunk(
    State(state): State<AppState>,
    Path((id, index)): Path<(String, u32)>,
    body: Bytes,
) -> Response {
    let session = {
        let uploads = state.uploads.read().await;
        match uploads.get(&id) {
            Some(s) => Arc::clone(s),
            None => return (StatusCode::NOT_FOUND, "Upload session not found").into_response(),
        }
    };

    let mut session = match session.session.lock() {
        Ok(s) => s,
        Err(_) => {
            return (StatusCode::INTERNAL_SERVER_ERROR, "Session lock poisoned").into_response()
        }
    };

    if index != session.next_index {
        return (
            StatusCode::BAD_REQUEST,
            format!("Expected chunk index {}, got {}", session.next_index, index),
        )
            .into_response();
    }

    let new_total = session.received + body.len() as u64;
    if new_total > state.config.max_upload_bytes {
        return too_large(state.config.max_upload_bytes);
    }

    let mut file = match std::fs::OpenOptions::new().append(true).open(&session.path) {
        Ok(f) => f,
        Err(e) => {
            tracing::error!("Failed to open upload file: {e}");
            return (StatusCode::INTERNAL_SERVER_ERROR, "Upload failed").into_response();
        }
    };
    if let Err(e) = file.write_all(&body) {
        tracing::error!("Failed to write chunk: {e}");
        return (StatusCode::INTERNAL_SERVER_ERROR, "Upload failed").into_response();
    }

    session.hasher.update(&body);
    session.received = new_total;
    session.next_index += 1;

    (StatusCode::OK, session.received.to_string()).into_response()
}

pub async fn upload_scan(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    if let Some(resp) = check_rate_limit(&state, client_ip(&state, addr, &headers)).await {
        return resp;
    }
    let json_response = wants_json(&headers);

    let session = match state.uploads.write().await.remove(&id) {
        Some(s) => s,
        None => return error_fragment("Upload session not found or already completed"),
    };

    let (path, hash) = {
        let session = match session.session.lock() {
            Ok(s) => s,
            Err(_) => return error_fragment("Session lock poisoned"),
        };
        if session.received == 0 {
            std::fs::remove_file(&session.path).ok();
            return error_fragment("No data was uploaded");
        }
        let hash = hex::encode(session.hasher.clone().finalize());
        (session.path.clone(), hash)
    };

    if let Some(response) = try_cache_hit(&state, &hash, json_response).await {
        std::fs::remove_file(&path).ok();
        return response;
    }
    let Some(permit) = try_scan_permit(&state) else {
        // Keep the upload so the client can retry the scan without
        // re-uploading; the eviction task removes it if never retried.
        state.uploads.write().await.insert(id, session);
        return busy(&state);
    };

    run_scan(
        state,
        TempPath::from_path(path),
        hash,
        permit,
        json_response,
    )
    .await
}

// ── Shared scan + cache logic ─────────────────────────────────────────────────

async fn try_cache_hit(state: &AppState, hash: &str, json_response: bool) -> Option<Response> {
    let report = {
        let cache = state.cache.read().await;
        let (report, ts) = cache.get(hash)?;
        if ts.elapsed() >= state.config.cache_ttl {
            return None;
        }
        Arc::clone(report)
    };
    let id = Uuid::new_v4().to_string();
    insert_capped(
        &mut *state.store.write().await,
        id.clone(),
        Arc::clone(&report),
        state.config.cache_max_entries,
    );
    tracing::info!(hash = &hash[..16], scan_id = %id, "Cache hit");
    Some(format_scan_response(&id, &report, true, json_response))
}

/// Run scan_ipa in a blocking thread, store and cache results, return a response.
///
/// `upload` is deleted when the scan finishes, fails or panics. The scan
/// `permit` is released only when the blocking task ends. A `scan_id` is
/// attached to every log line so concurrent scans can be correlated.
async fn run_scan(
    state: AppState,
    upload: TempPath,
    hash: String,
    permit: OwnedSemaphorePermit,
    json_response: bool,
) -> Response {
    let scan_id = Uuid::new_v4().to_string();
    let span = tracing::info_span!("scan", scan_id = %scan_id, hash = &hash[..16]);
    let max_extracted = state.config.max_extracted_bytes;
    let max_in_flight = state.config.max_in_flight_bytes;

    let task = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        let opts = ScanOptions {
            rules_dir: None,
            min_severity: Severity::Info,
            network: false,
            show_progress: false,
            max_extracted_bytes: Some(max_extracted),
            max_in_flight_bytes: Some(max_in_flight),
        };
        let result = scan_ipa(&upload, &opts);
        drop(upload);
        result
    });

    async move {
        tracing::info!("Starting IPA scan");
        let report = match task.await {
            Ok(Ok(r)) => {
                tracing::info!(
                    duration_ms = r.scan_duration_ms,
                    grade = %r.grade,
                    score = r.security_score,
                    "Scan complete"
                );
                Arc::new(r)
            }
            Ok(Err(e)) => {
                tracing::error!(error = %e, "Scan failed");
                return error_fragment("Scan failed due to a server error");
            }
            Err(e) => {
                tracing::error!(error = %e, "Scan task panicked");
                return error_fragment("Internal server error");
            }
        };

        let cap = state.config.cache_max_entries;
        let id = Uuid::new_v4().to_string();
        insert_capped(
            &mut *state.store.write().await,
            id.clone(),
            Arc::clone(&report),
            cap,
        );
        insert_capped(
            &mut *state.cache.write().await,
            hash,
            Arc::clone(&report),
            cap,
        );
        format_scan_response(&id, &report, false, json_response)
    }
    .instrument(span)
    .await
}

// ── Response formatting ───────────────────────────────────────────────────────

fn format_scan_response(
    id: &str,
    report: &ScanReport,
    cached: bool,
    json_response: bool,
) -> Response {
    if !json_response {
        return Html(result_fragment(id, report, cached)).into_response();
    }
    match json::to_string(report) {
        Ok(s) => ([(header::CONTENT_TYPE, "application/json")], s).into_response(),
        Err(e) => {
            tracing::error!("Failed to serialize JSON report: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to serialize report",
            )
                .into_response()
        }
    }
}

// ── Download handlers ─────────────────────────────────────────────────────────

async fn stored_report(state: &AppState, id: &str) -> Option<Arc<ScanReport>> {
    let store = state.store.read().await;
    let (report, ts) = store.get(id)?;
    (ts.elapsed() < super::RESULT_TTL).then(|| Arc::clone(report))
}

pub async fn get_scan_fragment(State(state): State<AppState>, Path(id): Path<String>) -> Response {
    match stored_report(&state, &id).await {
        Some(report) => Html(result_fragment(&id, &report, false)).into_response(),
        None => error_fragment("Scan expired or not found"),
    }
}

/// `pavise-<first 8 chars of the scan id>.<ext>`; ids are server-issued UUIDs.
fn attachment(id: &str, ext: &str) -> String {
    let short: String = id.chars().take(8).collect();
    format!("attachment; filename=\"pavise-{short}.{ext}\"")
}

pub async fn download_json(State(state): State<AppState>, Path(id): Path<String>) -> Response {
    let Some(report) = stored_report(&state, &id).await else {
        return (StatusCode::NOT_FOUND, "Scan not found").into_response();
    };
    match json::to_string(&report) {
        Ok(s) => (
            [
                (header::CONTENT_TYPE, "application/json".to_string()),
                (header::CONTENT_DISPOSITION, attachment(&id, "json")),
            ],
            s,
        )
            .into_response(),
        Err(e) => {
            tracing::error!("Failed to serialize JSON report: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to generate report",
            )
                .into_response()
        }
    }
}

/// Renders through headless Chrome: rate-limited, and bounded by its own
/// semaphore so PDF requests can't spawn unlimited Chrome processes.
pub async fn download_pdf(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    if let Some(resp) = check_rate_limit(&state, client_ip(&state, addr, &headers)).await {
        return resp;
    }
    let Some(report) = stored_report(&state, &id).await else {
        return (StatusCode::NOT_FOUND, "Scan not found").into_response();
    };
    let Ok(permit) = Arc::clone(&state.pdf_semaphore).try_acquire_owned() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "PDF generation busy. Try again shortly.",
        )
            .into_response();
    };

    // The permit lives in the blocking task, so the slot frees only once
    // Chrome has exited (pdf::to_bytes_with_timeout bounds that itself).
    let task = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        pdf::to_bytes_with_timeout(&report, PDF_TIMEOUT)
    });
    match task.await {
        Ok(Ok(bytes)) => (
            [
                (header::CONTENT_TYPE, "application/pdf".to_string()),
                (header::CONTENT_DISPOSITION, attachment(&id, "pdf")),
            ],
            bytes,
        )
            .into_response(),
        Ok(Err(e)) => {
            tracing::error!("PDF generation failed: {e:#}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to generate PDF report",
            )
                .into_response()
        }
        Err(e) => {
            tracing::error!("PDF generation task panicked: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to generate PDF report",
            )
                .into_response()
        }
    }
}

// ── Middleware ────────────────────────────────────────────────────────────────

pub async fn cache_control_headers(req: Request<Body>, next: Next) -> Response {
    let path = req.uri().path().to_owned();
    let mut resp = next.run(req).await;
    let value = if path.starts_with("/assets/") {
        "public, max-age=31536000, immutable"
    } else if matches!(path.as_str(), "/" | "/scan") {
        "no-cache"
    } else {
        return resp;
    };
    resp.headers_mut().insert(
        header::CACHE_CONTROL,
        header::HeaderValue::from_static(value),
    );
    resp
}

pub async fn security_headers(mut req: Request<Body>, next: Next) -> Response {
    let nonce = generate_nonce();
    req.extensions_mut().insert(CspNonce(nonce.clone()));
    let mut resp = next.run(req).await;
    let h = resp.headers_mut();
    h.insert(
        "X-Content-Type-Options",
        header::HeaderValue::from_static("nosniff"),
    );
    h.insert("X-Frame-Options", header::HeaderValue::from_static("DENY"));
    h.insert(
        "Referrer-Policy",
        header::HeaderValue::from_static("strict-origin-when-cross-origin"),
    );
    if let Ok(csp) = format!(
        "default-src 'self'; \
         script-src 'self' 'nonce-{nonce}' stats.pavise.app; \
         style-src 'self' 'unsafe-inline' fonts.googleapis.com; \
         font-src fonts.gstatic.com; \
         connect-src 'self'; \
         img-src 'self' data:; \
         frame-ancestors 'none'"
    )
    .parse()
    {
        h.insert("Content-Security-Policy", csp);
    }
    resp
}

// ── HTML helpers ──────────────────────────────────────────────────────────────

fn error_fragment(msg: &str) -> Response {
    Html(format!(
        r#"<div class="error-card">
  <span class="error-icon">✗</span>
  <span class="error-msg">{}</span>
</div>"#,
        html_escape(msg)
    ))
    .into_response()
}

/// At most `max` characters of `s`. Byte slicing (`&s[..90]`) panics when the
/// cut lands inside a multi-byte character, e.g. in non-Latin evidence strings.
fn truncate_chars(s: &str, max: usize) -> &str {
    match s.char_indices().nth(max) {
        Some((i, _)) => &s[..i],
        None => s,
    }
}

fn result_fragment(id: &str, report: &ScanReport, cached: bool) -> String {
    let count = |sev: Severity| {
        report.findings.iter().filter(|f| f.severity == sev).count()
            + report.secrets.iter().filter(|s| s.severity == sev).count()
    };
    let high = count(Severity::High);
    let warn = count(Severity::Warning);
    let info = report
        .findings
        .iter()
        .filter(|f| f.severity == Severity::Info)
        .count();

    let grade_class = match report.grade.as_str() {
        "A" => "grade-a",
        "B" => "grade-b",
        "C" => "grade-c",
        "D" => "grade-d",
        _ => "grade-f",
    };

    let cache_badge = if cached {
        r#"<span class="cache-badge">cached</span>"#
    } else {
        ""
    };

    let findings_html: String = report
        .findings
        .iter()
        .take(25)
        .map(|f| {
            let (sev_class, sev_label) = match f.severity {
                Severity::High => ("sev-high", "HIGH"),
                Severity::Warning => ("sev-warn", "WARN"),
                Severity::Info => ("sev-info", "INFO"),
                Severity::Secure => ("sev-secure", "SECURE"),
            };
            let evidence = f
                .evidence
                .first()
                .map(|e| {
                    format!(
                        r#"<div class="finding-evidence">{}</div>"#,
                        html_escape(truncate_chars(e, 90))
                    )
                })
                .unwrap_or_default();
            format!(
                r#"<div class="finding-row">
  <span class="sev-badge {sev_class}">{sev_label}</span>
  <div class="finding-body">
    <div class="finding-title">{title}</div>
    {evidence}
  </div>
  <code class="finding-id">{fid}</code>
</div>"#,
                title = html_escape(&f.title),
                fid = html_escape(&f.id),
            )
        })
        .collect();

    let more_note = if report.findings.len() > 25 {
        format!(
            r#"<div class="more-note">+{} more findings — download JSON for full report</div>"#,
            report.findings.len() - 25
        )
    } else {
        String::new()
    };

    let protections_html = if let Some(bin) = &report.main_binary {
        let rows: String = bin
            .protections
            .iter()
            .map(|p| {
                let (icon, cls) = if p.enabled {
                    ("✓", "prot-ok")
                } else {
                    ("✗", "prot-fail")
                };
                format!(
                    r#"<div class="prot-row {cls}"><span class="prot-icon">{icon}</span>{name}</div>"#,
                    name = html_escape(&p.name),
                )
            })
            .collect();
        format!(
            r#"<div class="section-label">Binary Protections <span class="arch-badge">{}</span></div>
<div class="prot-grid">{}</div>"#,
            html_escape(&bin.arch),
            rows
        )
    } else {
        String::new()
    };

    let findings_section = if findings_html.is_empty() {
        String::new()
    } else {
        format!(
            r#"<div class="section-label">Findings</div><div class="findings-list">{findings_html}</div>"#
        )
    };

    format!(
        r#"<div class="result-card">
  <div class="result-header">
    <div class="app-info">
      <div class="app-name">{name} <span class="app-version">v{version}</span> {cache_badge}</div>
      <div class="app-id">{bundle_id}</div>
    </div>
    <div class="score-block">
      <div class="grade {grade_class}">{grade}</div>
      <div class="score-num">{score}<span class="score-denom">/100</span></div>
    </div>
  </div>

  <div class="stats-row">
    <div class="stat stat-high"><div class="stat-num">{high}</div><div class="stat-label">High</div></div>
    <div class="stat stat-warn"><div class="stat-num">{warn}</div><div class="stat-label">Warn</div></div>
    <div class="stat stat-info"><div class="stat-num">{info}</div><div class="stat-label">Info</div></div>
    <div class="stat"><div class="stat-num">{secrets}</div><div class="stat-label">Secrets</div></div>
    <div class="stat"><div class="stat-num">{trackers}</div><div class="stat-label">Trackers</div></div>
    <div class="stat"><div class="stat-num">{duration}ms</div><div class="stat-label">Scan Time</div></div>
  </div>

  <div class="download-row">
    <a href="/api/scan/{id}/json" class="btn btn-json" download>Download JSON</a>
    <a href="/api/scan/{id}/pdf" class="btn btn-pdf" download>Download PDF</a>
  </div>

  {protections_html}

  {findings_section}

  {more_note}
</div>"#,
        name = html_escape(&report.app_info.name),
        version = html_escape(&report.app_info.version),
        bundle_id = html_escape(&report.app_info.identifier),
        grade = html_escape(&report.grade),
        score = report.security_score,
        secrets = report.secrets.len(),
        trackers = report.trackers.len(),
        duration = report.scan_duration_ms,
        id = html_escape(id),
    )
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truncate_chars_respects_utf8_boundaries() {
        // 'ש' is 2 bytes: byte 90 falls mid-character.
        let hebrew = "ש".repeat(100);
        assert_eq!(truncate_chars(&hebrew, 90).chars().count(), 90);
        assert_eq!(truncate_chars("short", 90), "short");
    }

    #[test]
    fn attachment_never_panics_on_short_id() {
        assert_eq!(
            attachment("ab", "pdf"),
            "attachment; filename=\"pavise-ab.pdf\""
        );
    }

    #[test]
    fn nonce_only_on_inline_scripts() {
        let out = inject_nonce(r#"<script>a</script><script src="x.js"></script>"#, "N");
        assert_eq!(
            out,
            r#"<script nonce="N">a</script><script src="x.js"></script>"#
        );
    }
}
