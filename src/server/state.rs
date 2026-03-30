use sha2::Sha256;
use std::{collections::HashMap, net::IpAddr, path::PathBuf, sync::Arc, time::Instant};
use tokio::sync::{RwLock, Semaphore};

use crate::types::ScanReport;
use super::config::Config;

// ── Store type aliases ───────────────────────────────────────────────────────

/// Completed scan results keyed by scan UUID.
pub type ScanStore = Arc<RwLock<HashMap<String, (ScanReport, Instant)>>>;

/// In-progress chunked upload sessions.
pub type UploadStore =
    Arc<RwLock<HashMap<String, Arc<std::sync::Mutex<UploadSession>>>>>;

/// Scan cache keyed by SHA-256 hash of the uploaded file.
pub type CacheStore = Arc<RwLock<HashMap<String, (ScanReport, Instant)>>>;

/// Per-IP sliding-window counters.
pub type RateLimitStore = Arc<RwLock<HashMap<IpAddr, RateLimitEntry>>>;

// ── Domain structs ───────────────────────────────────────────────────────────

/// Tracks how many requests an IP has made within the current window.
pub struct RateLimitEntry {
    pub count: u32,
    pub window_start: Instant,
}

/// State for a single in-progress chunked upload session.
pub struct UploadSession {
    /// File being assembled on disk.
    pub path: PathBuf,
    /// Running SHA-256 over all received bytes.
    pub hasher: Sha256,
    /// Total bytes received so far.
    pub received: u64,
    /// Next expected chunk index (enforces sequential ordering).
    pub next_index: u32,
    pub created_at: Instant,
}

// ── Shared application state ─────────────────────────────────────────────────

/// Cloneable state injected into every Axum handler via `State<AppState>`.
///
/// All mutable fields are behind `Arc<RwLock<_>>` so they can be shared
/// across concurrent requests without blocking.
#[derive(Clone)]
pub struct AppState {
    pub store: ScanStore,
    pub uploads: UploadStore,
    pub cache: CacheStore,
    /// Semaphore that limits the number of concurrent scans.
    pub semaphore: Arc<Semaphore>,
    pub rate_limits: RateLimitStore,
    /// Immutable resolved configuration.
    pub config: Arc<Config>,
}

impl AppState {
    pub fn new(config: Arc<Config>) -> Self {
        let max = config.max_concurrent_scans;
        AppState {
            store: Arc::new(RwLock::new(HashMap::new())),
            uploads: Arc::new(RwLock::new(HashMap::new())),
            cache: Arc::new(RwLock::new(HashMap::new())),
            semaphore: Arc::new(Semaphore::new(max)),
            rate_limits: Arc::new(RwLock::new(HashMap::new())),
            config,
        }
    }
}
