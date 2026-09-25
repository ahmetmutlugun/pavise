pub mod config;
mod handlers;
pub mod proxy;
pub mod state;

pub use state::AppState;

use std::time::Duration;

use axum::{
    extract::DefaultBodyLimit,
    routing::{get, post, put},
    Router,
};
use tower_http::{
    compression::CompressionLayer, services::ServeDir, timeout::RequestBodyTimeoutLayer,
};

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
    // A client trickling a body must not hold a connection (or, before the
    // permit reordering, a scan slot) indefinitely.
    let body_timeout = RequestBodyTimeoutLayer::new(state.config.body_timeout);

    let scan_routes = Router::new()
        .route("/api/scan", post(handlers::scan_handler))
        .layer(DefaultBodyLimit::max(max_upload));

    let upload_routes = Router::new()
        .route("/api/upload", post(handlers::upload_init))
        .route("/api/upload/:id/:index", put(handlers::upload_chunk))
        .route("/api/upload/:id/scan", post(handlers::upload_scan))
        .layer(DefaultBodyLimit::max(CHUNK_LIMIT));

    let body_routes = scan_routes.merge(upload_routes).layer(body_timeout);

    Router::new()
        .route("/", get(handlers::landing))
        .route("/scan", get(handlers::scan_page))
        .route("/healthz", get(handlers::healthz))
        .route("/robots.txt", get(handlers::robots_txt))
        .route("/sitemap.xml", get(handlers::sitemap_xml))
        .merge(body_routes)
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
    let state = state.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(10 * 60));
        loop {
            interval.tick().await;
            evict_expired(&state).await;
        }
    });
}

/// Drop expired scan results, cache entries and rate-limit windows, and
/// delete abandoned uploads from disk. Reads also check the TTLs, so an
/// entry is never served between expiry and the next sweep.
pub async fn evict_expired(state: &AppState) {
    {
        let mut map = state.store.write().await;
        let before = map.len();
        map.retain(|_, (_, ts)| ts.elapsed() < RESULT_TTL);
        let removed = before - map.len();
        if removed > 0 {
            tracing::info!(removed, "Evicted expired scan results");
        }
    }

    {
        let mut map = state.uploads.write().await;
        let before = map.len();
        map.retain(|_, slot| match slot.session.lock() {
            Ok(s) if s.created_at.elapsed() < UPLOAD_TTL => true,
            Ok(s) => {
                std::fs::remove_file(&s.path).ok();
                false
            }
            Err(poisoned) => {
                std::fs::remove_file(&poisoned.into_inner().path).ok();
                false
            }
        });
        let removed = before - map.len();
        if removed > 0 {
            tracing::info!(removed, "Evicted abandoned uploads");
        }
    }

    {
        let ttl = state.config.cache_ttl;
        let mut map = state.cache.write().await;
        let before = map.len();
        map.retain(|_, (_, ts)| ts.elapsed() < ttl);
        let removed = before - map.len();
        if removed > 0 {
            tracing::info!(removed, "Evicted expired cache entries");
        }
    }

    {
        let mut map = state.rate_limits.write().await;
        map.retain(|_, entry| entry.window_start.elapsed() < RATE_LIMIT_WINDOW);
    }
}
