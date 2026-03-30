pub mod config;
pub mod state;

pub use state::AppState;

use std::{sync::Arc, time::Duration};

use axum::{
    extract::DefaultBodyLimit,
    routing::{get, post, put},
    Router,
};
use tower_http::{compression::CompressionLayer, services::ServeDir};

use self::config::Config;
use self::state::{CacheStore, RateLimitStore, ScanStore, UploadStore};

/// Chunk size limit: 52 MB per request (50 MB chunk + overhead, fits under Cloudflare 100 MB).
pub const CHUNK_LIMIT: usize = 52 * 1024 * 1024;

/// Scan results are evicted after this duration.
pub const RESULT_TTL: Duration = Duration::from_secs(60 * 60); // 1 hour

/// Abandoned uploads are cleaned up after this duration.
pub const UPLOAD_TTL: Duration = Duration::from_secs(30 * 60); // 30 minutes

/// Sliding window for the per-IP rate limiter.
pub const RATE_LIMIT_WINDOW: Duration = Duration::from_secs(60);

/// Build the fully-wired Axum router from resolved state.
///
/// The returned `Router` has state applied and all middleware layers attached.
/// Call `.into_make_service_with_connect_info::<SocketAddr>()` before
/// passing to `axum::serve` in production.
pub fn build_router(state: AppState) -> Router {
    let dist = state.config.dist_dir.clone();
    let max_upload = state.config.max_upload_bytes as usize;

    let scan_routes = Router::new()
        .route("/api/scan", post(handlers::scan_handler))
        .layer(DefaultBodyLimit::max(max_upload));

    let upload_routes = Router::new()
        .route("/api/upload", post(handlers::upload_init))
        .route("/api/upload/:id/:index", put(handlers::upload_chunk))
        .route("/api/upload/:id/scan", post(handlers::upload_scan))
        .layer(DefaultBodyLimit::max(CHUNK_LIMIT));

    Router::new()
        .route("/", get(handlers::landing))
        .route("/scan", get(handlers::scan_page))
        .route("/healthz", get(handlers::healthz))
        .route("/robots.txt", get(handlers::robots_txt))
        .route("/sitemap.xml", get(handlers::sitemap_xml))
        .merge(scan_routes)
        .merge(upload_routes)
        .route("/api/scan/:id", get(handlers::get_scan_fragment))
        .route("/api/scan/:id/json", get(handlers::download_json))
        .route("/api/scan/:id/pdf", get(handlers::download_pdf))
        .nest_service("/assets", ServeDir::new(dist.join("assets")))
        .with_state(state)
        .layer(axum::middleware::from_fn(handlers::cache_control_headers))
        .layer(axum::middleware::from_fn(handlers::security_headers))
        .layer(CompressionLayer::new())
}

/// Spawn the background task that evicts expired entries from all stores.
///
/// Call this once after creating `AppState`, before binding the listener.
pub fn spawn_eviction_task(state: &AppState) {
    let store: ScanStore = Arc::clone(&state.store);
    let uploads: UploadStore = Arc::clone(&state.uploads);
    let cache: CacheStore = Arc::clone(&state.cache);
    let rate_limits: RateLimitStore = Arc::clone(&state.rate_limits);
    let config: Arc<Config> = Arc::clone(&state.config);

    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(10 * 60));
        loop {
            interval.tick().await;

            {
                let mut map = store.write().await;
                let before = map.len();
                map.retain(|_, (_, ts)| ts.elapsed() < RESULT_TTL);
                let removed = before - map.len();
                if removed > 0 {
                    tracing::info!(removed, "Evicted expired scan results");
                }
            }

            {
                let mut map = uploads.write().await;
                let before = map.len();
                map.retain(|_, session| {
                    let keep = session
                        .lock()
                        .map(|s| s.created_at.elapsed() < UPLOAD_TTL)
                        .unwrap_or(false);
                    if !keep {
                        if let Ok(s) = session.lock() {
                            std::fs::remove_file(&s.path).ok();
                        }
                    }
                    keep
                });
                let removed = before - map.len();
                if removed > 0 {
                    tracing::info!(removed, "Evicted abandoned uploads");
                }
            }

            {
                let ttl = config.cache_ttl;
                let mut map = cache.write().await;
                let before = map.len();
                map.retain(|_, (_, ts)| ts.elapsed() < ttl);
                let removed = before - map.len();
                if removed > 0 {
                    tracing::info!(removed, "Evicted expired cache entries");
                }
            }

            {
                let mut map = rate_limits.write().await;
                map.retain(|_, entry| entry.window_start.elapsed() < RATE_LIMIT_WINDOW);
            }
        }
    });
}

// All HTTP handlers live in a private sub-module so they can share helpers
// without polluting the public API.
mod handlers {
    use std::{
        io::Write,
        net::SocketAddr,
        path::PathBuf,
        sync::Arc,
        time::Instant,
    };

    use axum::{
        body::{Body, Bytes},
        extract::{ConnectInfo, Multipart, Path, State},
        http::{header, Request, StatusCode},
        middleware::Next,
        response::{Html, IntoResponse, Response},
        Json,
    };
    use sha2::{Digest, Sha256};
    use uuid::Uuid;

    use super::{
        super::{
            report::{json, pdf},
            resolve_rules_dir, scan_ipa,
            types::{ScanReport, Severity},
            ScanOptions,
        },
        state::{AppState, RateLimitEntry, UploadSession},
        RATE_LIMIT_WINDOW,
    };

    // ── Health check ─────────────────────────────────────────────────────────

    #[derive(serde::Serialize)]
    pub struct HealthResponse {
        pub active_scans: usize,
        pub cache_size: usize,
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

    // ── Rate limiting ─────────────────────────────────────────────────────────

    /// Returns a `429 Too Many Requests` response if the caller has exceeded the
    /// per-IP sliding-window limit, otherwise returns `None`.
    pub async fn check_rate_limit(state: &AppState, addr: SocketAddr) -> Option<Response> {
        let ip = addr.ip();
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

    // ── HTML page handlers ────────────────────────────────────────────────────

    pub async fn landing() -> Response {
        serve_html("index.html").await
    }

    pub async fn scan_page() -> Response {
        serve_html("scan.html").await
    }

    async fn serve_html(name: &str) -> Response {
        let path = crate::server::handlers::dist_dir_from_state_unavailable(name);
        match tokio::fs::read_to_string(&path).await {
            Ok(html) => Html(html).into_response(),
            Err(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!(
                    "Frontend not built: {} not found. Run `npm run build` in web/",
                    path.display()
                ),
            )
                .into_response(),
        }
    }

    // Resolve the dist path without access to State (used for static pages).
    fn dist_dir_from_state_unavailable(name: &str) -> PathBuf {
        let dir = std::env::var("PAVISE_DIST_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| {
                let manifest = std::env::var("CARGO_MANIFEST_DIR")
                    .map(PathBuf::from)
                    .unwrap_or_else(|_| PathBuf::from("."));
                manifest.join("web/dist")
            });
        dir.join(name)
    }

    pub async fn robots_txt(
    ) -> ([(axum::http::header::HeaderName, &'static str); 1], &'static str) {
        (
            [(axum::http::header::CONTENT_TYPE, "text/plain; charset=utf-8")],
            "User-agent: *\nAllow: /\nAllow: /scan\nDisallow: /api/\n\nSitemap: https://pavise.app/sitemap.xml\n",
        )
    }

    pub async fn sitemap_xml(
    ) -> ([(axum::http::header::HeaderName, &'static str); 1], &'static str) {
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

    // ── Direct multipart upload ───────────────────────────────────────────────

    pub async fn scan_handler(
        State(state): State<AppState>,
        ConnectInfo(addr): ConnectInfo<SocketAddr>,
        mut multipart: Multipart,
    ) -> Response {
        if let Some(resp) = check_rate_limit(&state, addr).await {
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
            Err(e) => return error_fragment(&format!("Failed to create temp file: {e}")),
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
                                        return error_fragment(&format!(
                                            "Failed to write upload: {e}"
                                        ));
                                    }
                                    hasher.update(&chunk);
                                }
                                Ok(None) => break,
                                Err(e) => {
                                    return error_fragment(&format!(
                                        "Failed to read upload: {e}"
                                    ))
                                }
                            }
                        }
                    }
                }
                Ok(None) => break,
                Err(e) => return error_fragment(&format!("Multipart error: {e}")),
            }
        }

        if received == 0 {
            return error_fragment("No IPA file received");
        }

        if let Err(e) = writer.flush() {
            return error_fragment(&format!("Failed to flush upload: {e}"));
        }
        drop(writer);

        let hash = hex::encode(hasher.finalize());

        if let Some(response) = try_cache_hit(&state, &hash).await {
            return response;
        }

        let path = tmp.path().to_path_buf();
        run_scan(state, path, hash, Some(tmp)).await
    }

    // ── Chunked upload endpoints ──────────────────────────────────────────────

    #[derive(serde::Serialize)]
    pub struct UploadInitResponse {
        pub upload_id: String,
        pub chunk_size: usize,
    }

    /// `POST /api/upload` — initialise a new chunked upload session.
    ///
    /// Rate-limited with the same per-IP limiter applied to scan endpoints.
    pub async fn upload_init(
        State(state): State<AppState>,
        ConnectInfo(addr): ConnectInfo<SocketAddr>,
    ) -> Response {
        if let Some(resp) = check_rate_limit(&state, addr).await {
            return resp;
        }

        let upload_id = Uuid::new_v4().to_string();
        let file_path = state.config.upload_dir.join(format!("{upload_id}.ipa"));

        if let Err(e) = std::fs::File::create(&file_path) {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to create upload file: {e}"),
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

    pub async fn upload_chunk(
        State(state): State<AppState>,
        Path((id, index)): Path<(String, u32)>,
        body: Bytes,
    ) -> Response {
        let session = {
            let uploads = state.uploads.read().await;
            match uploads.get(&id) {
                Some(s) => Arc::clone(s),
                None => {
                    return (StatusCode::NOT_FOUND, "Upload session not found").into_response()
                }
            }
        };

        let mut session = match session.lock() {
            Ok(s) => s,
            Err(_) => {
                return (StatusCode::INTERNAL_SERVER_ERROR, "Session lock poisoned")
                    .into_response()
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
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("Failed to open upload file: {e}"),
                )
                    .into_response()
            }
        };

        if let Err(e) = file.write_all(&body) {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to write chunk: {e}"),
            )
                .into_response();
        }

        session.hasher.update(&body);
        session.received = new_total;
        session.next_index += 1;

        (StatusCode::OK, session.received.to_string()).into_response()
    }

    pub async fn upload_scan(
        State(state): State<AppState>,
        ConnectInfo(addr): ConnectInfo<SocketAddr>,
        Path(id): Path<String>,
    ) -> Response {
        if let Some(resp) = check_rate_limit(&state, addr).await {
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

    // ── Shared scan + cache logic ─────────────────────────────────────────────

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

    /// Run scan_ipa in a blocking thread, store and cache results, return HTML fragment.
    ///
    /// A unique `scan_id` is generated per invocation and attached to all log
    /// lines so concurrent scan requests can be correlated in the logs.
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
                tracing::warn!(error = %e, "Scan failed");
                return error_fragment(&format!("Scan failed: {e}"));
            }
            Err(e) => {
                tracing::error!(error = %e, "Scan task panicked");
                return error_fragment(&format!("Internal error: {e}"));
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

    // ── Download handlers ─────────────────────────────────────────────────────

    pub async fn get_scan_fragment(
        State(state): State<AppState>,
        Path(id): Path<String>,
    ) -> Response {
        let store = state.store.read().await;
        match store.get(&id) {
            Some((report, _)) => Html(result_fragment(&id, report, false)).into_response(),
            None => error_fragment("Scan expired or not found"),
        }
    }

    pub async fn download_json(
        State(state): State<AppState>,
        Path(id): Path<String>,
    ) -> Response {
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
                    (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response()
                }),
            Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
        }
    }

    pub async fn download_pdf(
        State(state): State<AppState>,
        Path(id): Path<String>,
    ) -> Response {
        const PDF_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

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
                    (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response()
                }),
            Ok(Ok(Err(e))) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
            Ok(Err(e)) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
            Err(_) => {
                (StatusCode::GATEWAY_TIMEOUT, "PDF generation timed out").into_response()
            }
        }
    }

    // ── Middleware ────────────────────────────────────────────────────────────

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
        resp.headers_mut()
            .insert(header::CACHE_CONTROL, value.parse().unwrap());
        resp
    }

    pub async fn security_headers(req: Request<Body>, next: Next) -> Response {
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
            "default-src 'self'; script-src 'self' 'unsafe-inline' stats.pavise.app; style-src 'self' 'unsafe-inline' fonts.googleapis.com; font-src fonts.gstatic.com; connect-src 'self'; img-src 'self' data:; frame-ancestors 'none'"
                .parse()
                .unwrap(),
        );
        resp
    }

    // ── HTML helpers ──────────────────────────────────────────────────────────

    pub fn error_fragment(msg: &str) -> Response {
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
}
