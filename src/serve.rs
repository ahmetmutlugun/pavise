use anyhow::Result;
use axum::{
    body::Body,
    extract::{DefaultBodyLimit, Multipart, Path, State},
    http::{header, StatusCode},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
    Router,
};
use std::{collections::HashMap, sync::Arc, time::{Duration, Instant}};
use tokio::sync::{RwLock, Semaphore};
use uuid::Uuid;

use pavise::{
    report::{json, pdf},
    resolve_rules_dir,
    scan_ipa,
    types::{ScanReport, Severity},
    ScanOptions,
};

const INDEX_HTML: &str = include_str!("../templates/index.html");

/// Maximum number of concurrent scans to prevent resource exhaustion.
const MAX_CONCURRENT_SCANS: usize = 4;

/// Scan results are evicted after this duration.
const RESULT_TTL: Duration = Duration::from_secs(60 * 60); // 1 hour

/// Timeout for PDF generation via Typst.
const PDF_TIMEOUT: Duration = Duration::from_secs(60);

type ScanStore = Arc<RwLock<HashMap<String, (ScanReport, Instant)>>>;

#[derive(Clone)]
struct AppState {
    store: ScanStore,
    semaphore: Arc<Semaphore>,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter("pavise=warn,pavise_server=info,tower_http=info")
        .with_writer(std::io::stderr)
        .init();

    let store: ScanStore = Arc::new(RwLock::new(HashMap::new()));

    // Background task: evict scan results older than RESULT_TTL.
    let cleanup_store = Arc::clone(&store);
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(10 * 60));
        loop {
            interval.tick().await;
            let mut map = cleanup_store.write().await;
            let before = map.len();
            map.retain(|_, (_, ts)| ts.elapsed() < RESULT_TTL);
            let removed = before - map.len();
            if removed > 0 {
                tracing::info!("Evicted {} expired scan results", removed);
            }
        }
    });

    let state = AppState {
        store,
        semaphore: Arc::new(Semaphore::new(MAX_CONCURRENT_SCANS)),
    };

    let app = Router::new()
        .route("/", get(index))
        .route("/api/scan", post(scan_handler))
        .route("/api/scan/:id/json", get(download_json))
        .route("/api/scan/:id/pdf", get(download_pdf))
        .layer(DefaultBodyLimit::max(512 * 1024 * 1024)) // 512 MB
        .with_state(state);

    let port = std::env::var("PORT").unwrap_or_else(|_| "3000".to_string());
    let addr = format!("0.0.0.0:{}", port);
    eprintln!("Pavise server listening on http://{}", addr);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

async fn index() -> Html<&'static str> {
    Html(INDEX_HTML)
}

async fn scan_handler(State(state): State<AppState>, mut multipart: Multipart) -> Response {
    // Reject immediately if at capacity rather than queuing unboundedly.
    let _permit = match state.semaphore.try_acquire() {
        Ok(p) => p,
        Err(_) => {
            return error_fragment(&format!(
                "Server busy: maximum {} concurrent scans in progress. Try again shortly.",
                MAX_CONCURRENT_SCANS
            ))
        }
    };

    let mut ipa_bytes: Option<Vec<u8>> = None;

    loop {
        match multipart.next_field().await {
            Ok(Some(field)) => {
                if field.name() == Some("file") {
                    match field.bytes().await {
                        Ok(bytes) => ipa_bytes = Some(bytes.to_vec()),
                        Err(e) => return error_fragment(&format!("Failed to read upload: {e}")),
                    }
                }
            }
            Ok(None) => break,
            Err(e) => return error_fragment(&format!("Multipart error: {e}")),
        }
    }

    let bytes = match ipa_bytes {
        Some(b) if !b.is_empty() => b,
        _ => return error_fragment("No IPA file received"),
    };

    let tmp = match tempfile::Builder::new().suffix(".ipa").tempfile() {
        Ok(f) => f,
        Err(e) => return error_fragment(&format!("Failed to create temp file: {e}")),
    };

    if let Err(e) = std::fs::write(tmp.path(), &bytes) {
        return error_fragment(&format!("Failed to write temp file: {e}"));
    }

    let path = tmp.path().to_path_buf();
    let opts = ScanOptions {
        rules_dir: resolve_rules_dir(None),
        min_severity: Severity::Info,
        network: false,
    };

    let report = match tokio::task::spawn_blocking(move || {
        let _keep = tmp; // keep temp file alive until scan is done
        scan_ipa(&path, &opts)
    })
    .await
    {
        Ok(Ok(r)) => r,
        Ok(Err(e)) => return error_fragment(&format!("Scan failed: {e}")),
        Err(e) => return error_fragment(&format!("Internal error: {e}")),
    };

    let id = Uuid::new_v4().to_string();
    state.store.write().await.insert(id.clone(), (report.clone(), Instant::now()));

    Html(result_fragment(&id, &report)).into_response()
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
                (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response()
            }),
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
            .unwrap_or_else(|e| {
                (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response()
            }),
        Ok(Ok(Err(e))) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
        Ok(Err(e)) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
        Err(_) => (StatusCode::GATEWAY_TIMEOUT, "PDF generation timed out").into_response(),
    }
}

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

fn result_fragment(id: &str, report: &ScanReport) -> String {
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
      <div class="app-name">{name} <span class="app-version">v{version}</span></div>
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

  {protections_html}

  {findings_section}

  {more_note}

  <div class="download-row">
    <a href="/api/scan/{id}/json" class="btn btn-json" download>Download JSON</a>
    <a href="/api/scan/{id}/pdf" class="btn btn-pdf" download>Download PDF</a>
  </div>
</div>"#,
        name = html_escape(&report.app_info.name),
        version = html_escape(&report.app_info.version),
        bundle_id = html_escape(&report.app_info.identifier),
        grade = html_escape(&report.grade),
        grade_class = grade_class,
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
