use anyhow::Result;
use axum::{
    body::{Body, Bytes},
    extract::{ConnectInfo, DefaultBodyLimit, Extension, Multipart, Path, State},
    http::{header, HeaderMap, Request, StatusCode},
    middleware::Next,
    response::{Html, IntoResponse, Response},
    routing::{get, post, put},
    Json, Router,
};
use sha2::{Digest, Sha256};
use std::{io::Write, net::SocketAddr, path::PathBuf, sync::Arc, time::Instant};
use tower_http::{compression::CompressionLayer, services::ServeDir};
use uuid::Uuid;

use pavise::{
    report::{json, pdf},
    resolve_rules_dir, scan_ipa,
    server::{
        config::Config,
        spawn_eviction_task,
        state::{AppState, RateLimitEntry, UploadSession},
        CHUNK_LIMIT, RATE_LIMIT_WINDOW,
    },
    types::{ScanReport, Severity},
    ScanOptions,
};

// ── CSP nonce ─────────────────────────────────────────────────────────────────

#[derive(Clone)]
struct CspNonce(String);

fn generate_nonce() -> String {
    Uuid::new_v4().simple().to_string()
}

// ── Proxy-aware IP resolution ─────────────────────────────────────────────────

/// Resolve the real client IP, honouring proxy headers only when PAVISE_TRUSTED_PROXY is set.
fn real_ip(addr: SocketAddr, headers: &HeaderMap) -> std::net::IpAddr {
    if std::env::var("PAVISE_TRUSTED_PROXY").is_ok() {
        // Cloudflare sets this to the original visitor IP.
        if let Some(ip) = headers
            .get("CF-Connecting-IP")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.trim().parse().ok())
        {
            return ip;
        }
        // Standard reverse-proxy header; take the leftmost (client) address.
        if let Some(ip) = headers
            .get("X-Forwarded-For")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.split(',').next())
            .and_then(|s| s.trim().parse().ok())
        {
            return ip;
        }
    }
    addr.ip()
}

// ── Timeout ───────────────────────────────────────────────────────────────────

const PDF_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

// ── Main ──────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter("pavise=warn,pavise_server=info,tower_http=info")
        .with_writer(std::io::stderr)
        .init();

    let config = match Config::from_env() {
        Ok(c) => Arc::new(c),
        Err(errors) => {
            for e in &errors {
                eprintln!("Config error: {e}");
            }
            anyhow::bail!(
                "Server startup aborted: {} configuration error(s) — fix the above and retry",
                errors.len()
            );
        }
    };

    let state = AppState::new(Arc::clone(&config));
    spawn_eviction_task(&state);

    let max_upload = config.max_upload_bytes as usize;
    let dist = config.dist_dir.clone();
    let port = config.port;

    let scan_routes = Router::new()
        .route("/api/scan", post(scan_handler))
        .layer(DefaultBodyLimit::max(max_upload));

    let upload_routes = Router::new()
        .route("/api/upload", post(upload_init))
        .route("/api/upload/:id/:index", put(upload_chunk))
        .route("/api/upload/:id/scan", post(upload_scan))
        .layer(DefaultBodyLimit::max(CHUNK_LIMIT));

    let app = Router::new()
        .route("/", get(landing))
        .route("/scan", get(scan_page))
        .route("/healthz", get(healthz))
        .route("/robots.txt", get(robots_txt))
        .route("/sitemap.xml", get(sitemap_xml))
        .merge(scan_routes)
        .merge(upload_routes)
        .route("/api/scan/:id", get(get_scan_fragment))
        .route("/api/scan/:id/json", get(download_json))
        .route("/api/scan/:id/pdf", get(download_pdf))
        .nest_service("/assets", ServeDir::new(dist.join("assets")))
        .with_state(state)
        .layer(axum::middleware::from_fn(cache_control_headers))
        .layer(axum::middleware::from_fn(security_headers))
        .layer(CompressionLayer::new());

    let addr = format!("0.0.0.0:{port}");
    eprintln!("Pavise server listening on http://{addr}");
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;

    Ok(())
}

// ── Health check ──────────────────────────────────────────────────────────────

#[derive(serde::Serialize)]
struct HealthResponse {
    active_scans: usize,
    cache_size: usize,
}

async fn healthz(State(state): State<AppState>) -> Json<HealthResponse> {
    let available = state.semaphore.available_permits();
    let active_scans = state.config.max_concurrent_scans.saturating_sub(available);
    let cache_size = state.cache.read().await.len();
    Json(HealthResponse {
        active_scans,
        cache_size,
    })
}

// ── HTML page handlers ────────────────────────────────────────────────────────

async fn landing(Extension(nonce): Extension<CspNonce>) -> Response {
    serve_html("index.html", &nonce.0).await
}

async fn scan_page(Extension(nonce): Extension<CspNonce>) -> Response {
    serve_html("scan.html", &nonce.0).await
}

async fn serve_html(name: &str, nonce: &str) -> Response {
    let path = std::env::var("PAVISE_DIST_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| {
            let manifest = std::env::var("CARGO_MANIFEST_DIR")
                .map(std::path::PathBuf::from)
                .unwrap_or_else(|_| std::path::PathBuf::from("."));
            manifest.join("web/dist")
        })
        .join(name);
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
            if !tag.contains("src=") {
                result.push_str(tag);
                result.push_str(&format!(" nonce=\"{nonce}\""));
                result.push('>');
            } else {
                result.push_str(tag);
                result.push('>');
            }
            remaining = &remaining[tag_end + 1..];
        } else {
            result.push_str(remaining);
            return result;
        }
    }
    result.push_str(remaining);
    result
}

async fn robots_txt() -> ([(axum::http::header::HeaderName, &'static str); 1], &'static str) {
    (
        [(axum::http::header::CONTENT_TYPE, "text/plain; charset=utf-8")],
        "User-agent: *\nAllow: /\nAllow: /scan\nDisallow: /api/\n\nSitemap: https://pavise.app/sitemap.xml\n",
    )
}

async fn sitemap_xml() -> ([(axum::http::header::HeaderName, &'static str); 1], &'static str) {
    (
        [(axum::http::header::CONTENT_TYPE, "application/xml; charset=utf-8")],
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

// ── Rate limiting ─────────────────────────────────────────────────────────────

/// Returns a `429 Too Many Requests` response if the caller has exceeded the
/// per-IP sliding-window limit, otherwise returns `None`.
async fn check_rate_limit(
    state: &AppState,
    addr: SocketAddr,
    headers: &HeaderMap,
) -> Option<Response> {
    let ip = real_ip(addr, headers);
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
        tracing::warn!(
            ip = %ip,
            count = entry.count,
            limit = max,
            "Rate limit exceeded"
        );
        Some(
            (
                StatusCode::TOO_MANY_REQUESTS,
                format!(
                    "Rate limit exceeded: maximum {} requests per minute. Try again shortly.",
                    max
                ),
            )
                .into_response(),
        )
    } else {
        None
    }
}

// ── Direct multipart upload ───────────────────────────────────────────────────

async fn scan_handler(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    mut multipart: Multipart,
) -> Response {
    if let Some(resp) = check_rate_limit(&state, addr, &headers).await {
        return resp;
    }

    let max_scans = state.config.max_concurrent_scans;
    let sem = Arc::clone(&state.semaphore);
    let _permit = match sem.try_acquire() {
        Ok(p) => p,
        Err(_) => {
            return error_fragment(&format!(
                "Server busy: maximum {max_scans} concurrent scans in progress. Try again shortly."
            ))
        }
    };

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

    loop {
        match multipart.next_field().await {
            Ok(Some(mut field)) => {
                if field.name() == Some("file") {
                    loop {
                        match field.chunk().await {
                            Ok(Some(chunk)) => {
                                received += chunk.len() as u64;
                                if received > max_bytes {
                                    return (
                                        StatusCode::PAYLOAD_TOO_LARGE,
                                        format!(
                                            "Upload exceeds maximum size of {} MiB",
                                            max_bytes / (1024 * 1024)
                                        ),
                                    )
                                        .into_response();
                                }
                                if let Err(e) = writer.write_all(&chunk) {
                                    tracing::error!("Failed to write upload chunk: {e}");
                                    return error_fragment("Upload failed due to a server error");
                                }
                                hasher.update(&chunk);
                            }
                            Ok(None) => break,
                            Err(e) => {
                                tracing::error!("Failed to read upload data: {e}");
                                return error_fragment("Upload failed due to a server error");
                            }
                        }
                    }
                }
            }
            Ok(None) => break,
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

    if let Some(response) = try_cache_hit(&state, &hash).await {
        return response;
    }

    let path = tmp.path().to_path_buf();
    run_scan(state, path, hash, Some(tmp)).await
}

// ── Chunked upload endpoints ──────────────────────────────────────────────────

#[derive(serde::Serialize)]
struct UploadInitResponse {
    upload_id: String,
    chunk_size: usize,
}

/// `POST /api/upload` — initialise a new chunked upload session.
///
/// Rate-limited with the same per-IP limiter applied to scan endpoints.
async fn upload_init(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Response {
    if let Some(resp) = check_rate_limit(&state, addr, &headers).await {
        return resp;
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

    state
        .uploads
        .write()
        .await
        .insert(upload_id.clone(), Arc::new(std::sync::Mutex::new(session)));

    Json(UploadInitResponse {
        upload_id,
        chunk_size: 50 * 1024 * 1024,
    })
    .into_response()
}

async fn upload_chunk(
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

    let mut session = match session.lock() {
        Ok(s) => s,
        Err(_) => {
            return (StatusCode::INTERNAL_SERVER_ERROR, "Session lock poisoned").into_response()
        }
    };

    if index != session.next_index {
        return (
            StatusCode::BAD_REQUEST,
            format!(
                "Expected chunk index {}, got {}",
                session.next_index, index
            ),
        )
            .into_response();
    }

    let new_total = session.received + body.len() as u64;
    if new_total > state.config.max_upload_bytes {
        return (
            StatusCode::PAYLOAD_TOO_LARGE,
            format!(
                "Upload exceeds maximum size of {} MiB",
                state.config.max_upload_bytes / (1024 * 1024)
            ),
        )
            .into_response();
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

async fn upload_scan(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    if let Some(resp) = check_rate_limit(&state, addr, &headers).await {
        return resp;
    }

    let session = {
        let mut uploads = state.uploads.write().await;
        match uploads.remove(&id) {
            Some(s) => s,
            None => return error_fragment("Upload session not found or already completed"),
        }
    };

    let (path, hash) = {
        let session = match session.lock() {
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

    let max_scans = state.config.max_concurrent_scans;
    let sem = Arc::clone(&state.semaphore);
    let _permit = match sem.try_acquire() {
        Ok(p) => p,
        Err(_) => {
            return error_fragment(&format!(
                "Server busy: maximum {max_scans} concurrent scans in progress. Try again shortly."
            ))
        }
    };

    if let Some(response) = try_cache_hit(&state, &hash).await {
        std::fs::remove_file(&path).ok();
        return response;
    }

    run_scan(state, path, hash, None::<tempfile::NamedTempFile>).await
}

// ── Shared scan + cache logic ─────────────────────────────────────────────────

async fn try_cache_hit(state: &AppState, hash: &str) -> Option<Response> {
    let cache = state.cache.read().await;
    let (report, _) = cache.get(hash)?;
    let report = report.clone();
    drop(cache);

    let id = Uuid::new_v4().to_string();
    state
        .store
        .write()
        .await
        .insert(id.clone(), (report.clone(), Instant::now()));

    tracing::info!(hash = &hash[..16], scan_id = %id, "Cache hit");
    Some(Html(result_fragment(&id, &report, true)).into_response())
}

/// Run scan_ipa in a blocking thread, store and cache results, return an HTML fragment.
///
/// A `scan_id` is generated per invocation and attached to every log line so
/// concurrent scan requests can be correlated in structured logs.
async fn run_scan<T: Send + 'static>(
    state: AppState,
    path: PathBuf,
    hash: String,
    _keep_alive: Option<T>,
) -> Response {
    let scan_id = Uuid::new_v4().to_string();
    let span = tracing::info_span!("scan", scan_id = %scan_id, hash = &hash[..16]);
    let _enter = span.enter();

    tracing::info!("Starting IPA scan");

    let scan_path = path.clone();
    let report = match tokio::task::spawn_blocking(move || {
        let _keep = _keep_alive;
        let opts = ScanOptions {
            rules_dir: resolve_rules_dir(None),
            min_severity: Severity::Info,
            network: false,
            show_progress: false,
        };
        let result = scan_ipa(&scan_path, &opts);
        if scan_path
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|s| s.len() > 30 && s.ends_with(".ipa"))
        {
            std::fs::remove_file(&scan_path).ok();
        }
        result
    })
    .await
    {
        Ok(Ok(r)) => {
            tracing::info!(
                duration_ms = r.scan_duration_ms,
                grade = %r.grade,
                score = r.security_score,
                "Scan complete"
            );
            r
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

    let id = Uuid::new_v4().to_string();

    state
        .store
        .write()
        .await
        .insert(id.clone(), (report.clone(), Instant::now()));

    state
        .cache
        .write()
        .await
        .insert(hash, (report.clone(), Instant::now()));

    Html(result_fragment(&id, &report, false)).into_response()
}

// ── Download handlers ─────────────────────────────────────────────────────────

async fn get_scan_fragment(State(state): State<AppState>, Path(id): Path<String>) -> Response {
    let store = state.store.read().await;
    match store.get(&id) {
        Some((report, _)) => Html(result_fragment(&id, report, false)).into_response(),
        None => error_fragment("Scan expired or not found"),
    }
}

async fn download_json(State(state): State<AppState>, Path(id): Path<String>) -> Response {
    let store = state.store.read().await;
    let report = match store.get(&id) {
        Some((r, _)) => r,
        None => return (StatusCode::NOT_FOUND, "Scan not found").into_response(),
    };

    match json::to_string(report) {
        Ok(s) => Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "application/json")
            .header(
                header::CONTENT_DISPOSITION,
                format!("attachment; filename=\"pavise-{}.json\"", &id[..8]),
            )
            .body(Body::from(s))
            .unwrap_or_else(|e| {
                tracing::error!("Failed to build JSON response: {e}");
                (StatusCode::INTERNAL_SERVER_ERROR, "Failed to generate report").into_response()
            }),
        Err(e) => {
            tracing::error!("Failed to serialize JSON report: {e}");
            (StatusCode::INTERNAL_SERVER_ERROR, "Failed to generate report").into_response()
        }
    }
}

async fn download_pdf(State(state): State<AppState>, Path(id): Path<String>) -> Response {
    let report = {
        let store = state.store.read().await;
        match store.get(&id) {
            Some((r, _)) => r.clone(),
            None => return (StatusCode::NOT_FOUND, "Scan not found").into_response(),
        }
    };

    let task = tokio::task::spawn_blocking(move || pdf::to_bytes(&report));
    match tokio::time::timeout(PDF_TIMEOUT, task).await {
        Ok(Ok(Ok(bytes))) => Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "application/pdf")
            .header(
                header::CONTENT_DISPOSITION,
                format!("attachment; filename=\"pavise-{}.pdf\"", &id[..8]),
            )
            .body(Body::from(bytes))
            .unwrap_or_else(|e| {
                tracing::error!("Failed to build PDF response: {e}");
                (StatusCode::INTERNAL_SERVER_ERROR, "Failed to generate report").into_response()
            }),
        Ok(Ok(Err(e))) => {
            tracing::error!("PDF generation failed: {e}");
            (StatusCode::INTERNAL_SERVER_ERROR, "Failed to generate PDF report").into_response()
        }
        Ok(Err(e)) => {
            tracing::error!("PDF generation task panicked: {e}");
            (StatusCode::INTERNAL_SERVER_ERROR, "Failed to generate PDF report").into_response()
        }
        Err(_) => (StatusCode::GATEWAY_TIMEOUT, "PDF generation timed out").into_response(),
    }
}

// ── Middleware ────────────────────────────────────────────────────────────────

async fn cache_control_headers(req: Request<Body>, next: Next) -> Response {
    let path = req.uri().path().to_owned();
    let mut resp = next.run(req).await;
    let value = if path.starts_with("/assets/") {
        "public, max-age=31536000, immutable"
    } else if matches!(path.as_str(), "/" | "/scan") {
        "no-cache"
    } else {
        return resp;
    };
    resp.headers_mut()
        .insert(header::CACHE_CONTROL, value.parse().unwrap());
    resp
}

async fn security_headers(mut req: Request<Body>, next: Next) -> Response {
    let nonce = generate_nonce();
    req.extensions_mut().insert(CspNonce(nonce.clone()));
    let mut resp = next.run(req).await;
    let h = resp.headers_mut();
    h.insert("X-Content-Type-Options", "nosniff".parse().unwrap());
    h.insert("X-Frame-Options", "DENY".parse().unwrap());
    h.insert(
        "Referrer-Policy",
        "strict-origin-when-cross-origin".parse().unwrap(),
    );
    h.insert(
        "Content-Security-Policy",
        format!(
            "default-src 'self'; \
             script-src 'self' 'nonce-{nonce}' stats.pavise.app; \
             style-src 'self' 'unsafe-inline' fonts.googleapis.com; \
             font-src fonts.gstatic.com; \
             connect-src 'self'; \
             img-src 'self' data:; \
             frame-ancestors 'none'"
        )
        .parse()
        .unwrap(),
    );
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

fn result_fragment(id: &str, report: &ScanReport, cached: bool) -> String {
    let high = report
        .findings
        .iter()
        .filter(|f| f.severity == Severity::High)
        .count()
        + report
            .secrets
            .iter()
            .filter(|s| s.severity == Severity::High)
            .count();
    let warn = report
        .findings
        .iter()
        .filter(|f| f.severity == Severity::Warning)
        .count()
        + report
            .secrets
            .iter()
            .filter(|s| s.severity == Severity::Warning)
            .count();
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
                    let t = if e.len() > 90 { &e[..90] } else { e.as_str() };
                    format!(
                        r#"<div class="finding-evidence">{}</div>"#,
                        html_escape(t)
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
        grade_class = grade_class,
        cache_badge = cache_badge,
        score = report.security_score,
        high = high,
        warn = warn,
        info = info,
        secrets = report.secrets.len(),
        trackers = report.trackers.len(),
        duration = report.scan_duration_ms,
        protections_html = protections_html,
        findings_section = if findings_html.is_empty() {
            String::new()
        } else {
            format!(
                r#"<div class="section-label">Findings</div><div class="findings-list">{findings_html}</div>"#
            )
        },
        more_note = more_note,
        id = id,
    )
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}
