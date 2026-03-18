use anyhow::Result;
use axum::{
    body::{Body, Bytes},
    extract::{ConnectInfo, DefaultBodyLimit, Multipart, Path, State},
    http::{header, StatusCode},
    response::{Html, IntoResponse, Response},
    routing::{get, post, put},
    Json, Router,
};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    io::Write,
    net::SocketAddr,
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::{RwLock, Semaphore};
use uuid::Uuid;

use pavise::{
    report::{json, pdf},
    resolve_rules_dir, scan_ipa,
    types::{ScanReport, Severity},
    ScanOptions,
};

const INDEX_HTML: &str = include_str!("../templates/index.html");

/// Maximum number of concurrent scans to prevent resource exhaustion.
fn max_concurrent_scans() -> usize {
    std::env::var("PAVISE_MAX_SCANS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(4)
}

/// Chunk size limit: 52 MB per request (50 MB chunk + overhead, fits under Cloudflare 100 MB).
const CHUNK_LIMIT: usize = 52 * 1024 * 1024;

/// Scan results are evicted after this duration.
const RESULT_TTL: Duration = Duration::from_secs(60 * 60); // 1 hour

/// Cache TTL — cached scan results live longer since they're keyed by content hash.
fn cache_ttl() -> Duration {
    let hours: u64 = std::env::var("PAVISE_CACHE_TTL_HOURS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(24);
    Duration::from_secs(hours * 3600)
}

/// Timeout for PDF generation via Typst.
const PDF_TIMEOUT: Duration = Duration::from_secs(60);

/// Abandoned uploads are cleaned up after this duration.
const UPLOAD_TTL: Duration = Duration::from_secs(30 * 60); // 30 minutes

/// Maximum total upload size (default 15 GB, override via PAVISE_MAX_UPLOAD_BYTES).
fn max_upload_bytes() -> u64 {
    std::env::var("PAVISE_MAX_UPLOAD_BYTES")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(15 * 1024 * 1024 * 1024) // 15 GB
}

/// Directory for chunked upload temp files.
fn upload_dir() -> PathBuf {
    let dir = std::env::var("PAVISE_UPLOAD_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| std::env::temp_dir().join("pavise-uploads"));
    std::fs::create_dir_all(&dir).ok();
    dir
}

type ScanStore = Arc<RwLock<HashMap<String, (ScanReport, Instant)>>>;

/// In-progress chunked upload session.
struct UploadSession {
    path: PathBuf,
    hasher: Sha256,
    received: u64,
    next_index: u32,
    created_at: Instant,
}

type UploadStore = Arc<RwLock<HashMap<String, Arc<std::sync::Mutex<UploadSession>>>>>;

/// Scan cache keyed by SHA-256 of the uploaded file.
type CacheStore = Arc<RwLock<HashMap<String, (ScanReport, Instant)>>>;

/// Per-IP request rate limiter using a sliding window.
/// Maximum requests per IP within the configured window (default: 20 requests per minute).
fn rate_limit_max() -> u32 {
    std::env::var("PAVISE_RATE_LIMIT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(20)
}

const RATE_LIMIT_WINDOW: Duration = Duration::from_secs(60);

/// Tracks per-IP request timestamps for rate limiting.
struct RateLimitEntry {
    count: u32,
    window_start: Instant,
}

type RateLimitStore = Arc<RwLock<HashMap<std::net::IpAddr, RateLimitEntry>>>;

#[derive(Clone)]
struct AppState {
    store: ScanStore,
    uploads: UploadStore,
    cache: CacheStore,
    semaphore: Arc<Semaphore>,
    rate_limits: RateLimitStore,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter("pavise=warn,pavise_server=info,tower_http=info")
        .with_writer(std::io::stderr)
        .init();

    let store: ScanStore = Arc::new(RwLock::new(HashMap::new()));
    let uploads: UploadStore = Arc::new(RwLock::new(HashMap::new()));
    let cache: CacheStore = Arc::new(RwLock::new(HashMap::new()));
    let rate_limits: RateLimitStore = Arc::new(RwLock::new(HashMap::new()));

    // Background task: evict expired scan results, uploads, cache, and rate limit entries.
    {
        let store = Arc::clone(&store);
        let uploads = Arc::clone(&uploads);
        let cache = Arc::clone(&cache);
        let rate_limits = Arc::clone(&rate_limits);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(10 * 60));
            loop {
                interval.tick().await;

                // Evict expired scan results
                {
                    let mut map = store.write().await;
                    let before = map.len();
                    map.retain(|_, (_, ts)| ts.elapsed() < RESULT_TTL);
                    let removed = before - map.len();
                    if removed > 0 {
                        tracing::info!("Evicted {} expired scan results", removed);
                    }
                }

                // Evict abandoned uploads
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
                        tracing::info!("Evicted {} abandoned uploads", removed);
                    }
                }

                // Evict expired cache entries
                {
                    let ttl = cache_ttl();
                    let mut map = cache.write().await;
                    let before = map.len();
                    map.retain(|_, (_, ts)| ts.elapsed() < ttl);
                    let removed = before - map.len();
                    if removed > 0 {
                        tracing::info!("Evicted {} expired cache entries", removed);
                    }
                }

                // Evict expired rate limit entries
                {
                    let mut map = rate_limits.write().await;
                    map.retain(|_, entry| entry.window_start.elapsed() < RATE_LIMIT_WINDOW);
                }
            }
        });
    }

    let state = AppState {
        store,
        uploads,
        cache,
        semaphore: Arc::new(Semaphore::new(max_concurrent_scans())),
        rate_limits,
    };

    // Routes with per-group body limits
    let scan_routes = Router::new()
        .route("/api/scan", post(scan_handler))
        .layer(DefaultBodyLimit::max(512 * 1024 * 1024)); // 512 MB for direct upload

    let upload_routes = Router::new()
        .route("/api/upload", post(upload_init))
        .route("/api/upload/:id/:index", put(upload_chunk))
        .route("/api/upload/:id/scan", post(upload_scan))
        .layer(DefaultBodyLimit::max(CHUNK_LIMIT));

    let app = Router::new()
        .route("/", get(index))
        .merge(scan_routes)
        .merge(upload_routes)
        .route("/api/scan/:id", get(get_scan_fragment))
        .route("/api/scan/:id/json", get(download_json))
        .route("/api/scan/:id/pdf", get(download_pdf))
        .with_state(state);

    let port = std::env::var("PORT").unwrap_or_else(|_| "3000".to_string());
    let addr = format!("0.0.0.0:{}", port);
    eprintln!("Pavise server listening on http://{}", addr);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;
    Ok(())
}

async fn index() -> Html<&'static str> {
    Html(INDEX_HTML)
}

/// Check per-IP rate limit. Returns an error response if the limit is exceeded.
async fn check_rate_limit(state: &AppState, addr: SocketAddr) -> Option<Response> {
    let ip = addr.ip();
    let max = rate_limit_max();
    let mut limits = state.rate_limits.write().await;
    let entry = limits.entry(ip).or_insert(RateLimitEntry {
        count: 0,
        window_start: Instant::now(),
    });

    // Reset window if expired
    if entry.window_start.elapsed() >= RATE_LIMIT_WINDOW {
        entry.count = 0;
        entry.window_start = Instant::now();
    }

    entry.count += 1;
    if entry.count > max {
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

// ── Direct multipart upload (streaming to disk) ─────────────────────────────

async fn scan_handler(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    mut multipart: Multipart,
) -> Response {
    if let Some(resp) = check_rate_limit(&state, addr).await {
        return resp;
    }

    let sem = Arc::clone(&state.semaphore);
    let _permit = match sem.try_acquire() {
        Ok(p) => p,
        Err(_) => {
            return error_fragment(&format!(
                "Server busy: maximum {} concurrent scans in progress. Try again shortly.",
                max_concurrent_scans()
            ))
        }
    };

    // Stream multipart to disk while computing SHA-256
    let tmp = match tempfile::Builder::new()
        .suffix(".ipa")
        .tempfile_in(upload_dir())
    {
        Ok(f) => f,
        Err(e) => return error_fragment(&format!("Failed to create temp file: {e}")),
    };

    let mut writer = std::io::BufWriter::new(tmp.as_file());
    let mut hasher = Sha256::new();
    let mut received = 0u64;

    loop {
        match multipart.next_field().await {
            Ok(Some(mut field)) => {
                if field.name() == Some("file") {
                    loop {
                        match field.chunk().await {
                            Ok(Some(chunk)) => {
                                if let Err(e) = writer.write_all(&chunk) {
                                    return error_fragment(&format!("Failed to write upload: {e}"));
                                }
                                hasher.update(&chunk);
                                received += chunk.len() as u64;
                            }
                            Ok(None) => break,
                            Err(e) => {
                                return error_fragment(&format!("Failed to read upload: {e}"))
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

    // Check cache
    if let Some(response) = try_cache_hit(&state, &hash).await {
        return response;
    }

    // Run scan
    let path = tmp.path().to_path_buf();
    run_scan(state, path, hash, Some(tmp)).await
}

// ── Chunked upload endpoints ────────────────────────────────────────────────

#[derive(serde::Serialize)]
struct UploadInitResponse {
    upload_id: String,
    chunk_size: usize,
}

async fn upload_init(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
) -> Response {
    if let Some(resp) = check_rate_limit(&state, addr).await {
        return resp;
    }

    let upload_id = Uuid::new_v4().to_string();
    let file_path = upload_dir().join(format!("{upload_id}.ipa"));

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
            format!("Expected chunk index {}, got {}", session.next_index, index),
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

    // Enforce total upload size limit
    let new_total = session.received + body.len() as u64;
    if new_total > max_upload_bytes() {
        return (
            StatusCode::PAYLOAD_TOO_LARGE,
            format!(
                "Upload exceeds maximum size of {} GB",
                max_upload_bytes() / (1024 * 1024 * 1024)
            ),
        )
            .into_response();
    }

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

async fn upload_scan(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Path(id): Path<String>,
) -> Response {
    if let Some(resp) = check_rate_limit(&state, addr).await {
        return resp;
    }

    // Remove the session (finalize)
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

    // Acquire scan permit
    let sem = Arc::clone(&state.semaphore);
    let _permit = match sem.try_acquire() {
        Ok(p) => p,
        Err(_) => {
            return error_fragment(&format!(
                "Server busy: maximum {} concurrent scans in progress. Try again shortly.",
                max_concurrent_scans()
            ))
        }
    };

    // Check cache
    if let Some(response) = try_cache_hit(&state, &hash).await {
        std::fs::remove_file(&path).ok();
        return response;
    }

    run_scan(state, path, hash, None::<tempfile::NamedTempFile>).await
}

// ── Shared scan + cache logic ───────────────────────────────────────────────

/// Check cache for a previous scan of the same file (by SHA-256).
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

    tracing::info!("Cache hit for SHA-256 {}", &hash[..16]);
    Some(Html(result_fragment(&id, &report, true)).into_response())
}

/// Run scan_ipa, store results, populate cache, return HTML fragment.
async fn run_scan<T: Send + 'static>(
    state: AppState,
    path: PathBuf,
    hash: String,
    _keep_alive: Option<T>,
) -> Response {
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
        // Clean up chunked upload files (tempfile handles cleanup for NamedTempFile)
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
        Ok(Ok(r)) => r,
        Ok(Err(e)) => return error_fragment(&format!("Scan failed: {e}")),
        Err(e) => return error_fragment(&format!("Internal error: {e}")),
    };

    let id = Uuid::new_v4().to_string();

    state
        .store
        .write()
        .await
        .insert(id.clone(), (report.clone(), Instant::now()));

    // Populate cache
    state
        .cache
        .write()
        .await
        .insert(hash, (report.clone(), Instant::now()));

    Html(result_fragment(&id, &report, false)).into_response()
}

// ── Existing result/download handlers ───────────────────────────────────────

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
            .unwrap_or_else(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response()),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
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
            .unwrap_or_else(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response()),
        Ok(Ok(Err(e))) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
        Ok(Err(e)) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
        Err(_) => (StatusCode::GATEWAY_TIMEOUT, "PDF generation timed out").into_response(),
    }
}

// ── HTML helpers ────────────────────────────────────────────────────────────

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
                    format!(r#"<div class="finding-evidence">{}</div>"#, html_escape(t))
                })
                .unwrap_or_default();
            format!(
                r#"<div class="finding-row">
  <span class="sev-badge {sev_class}">{sev_label}</span>
  <div class="finding-body">
    <div class="finding-title">{title}</div>
    {evidence}
  </div>
  <code class="finding-id">{id}</code>
</div>"#,
                title = html_escape(&f.title),
                id = html_escape(&f.id),
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
}
