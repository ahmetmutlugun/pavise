use sha2::Sha256;
use std::{collections::HashMap, net::IpAddr, path::PathBuf, sync::Arc, time::Instant};
use tokio::sync::{RwLock, Semaphore};

use super::config::Config;
use crate::types::ScanReport;

// ── Store type aliases ───────────────────────────────────────────────────────

/// Reports keyed by scan UUID (store) or upload SHA-256 (cache). Both maps
/// share one `Arc` per report.
pub type ReportMap = HashMap<String, (Arc<ScanReport>, Instant)>;

/// Completed scan results keyed by scan UUID.
pub type ScanStore = Arc<RwLock<ReportMap>>;

/// In-progress chunked upload sessions.
pub type UploadStore = Arc<RwLock<HashMap<String, Arc<UploadSlot>>>>;

/// A session plus its owner. The IP sits outside the mutex so counting a
/// client's sessions never waits behind a chunk write.
pub struct UploadSlot {
    pub ip: IpAddr,
    pub session: std::sync::Mutex<UploadSession>,
}

/// Scan cache keyed by SHA-256 hash of the uploaded file.
pub type CacheStore = Arc<RwLock<ReportMap>>;

/// Per-IP sliding-window counters.
pub type RateLimitStore = Arc<RwLock<HashMap<IpAddr, RateLimitEntry>>>;

/// Insert, evicting the oldest entries so the map never exceeds `cap`. TTL
/// eviction alone let a burst of distinct uploads grow memory without bound.
pub fn insert_capped<V>(
    map: &mut HashMap<String, (V, Instant)>,
    key: String,
    value: V,
    cap: usize,
) {
    while map.len() >= cap && !map.contains_key(&key) {
        let oldest = map
            .iter()
            .min_by_key(|(_, (_, ts))| *ts)
            .map(|(k, _)| k.clone());
        match oldest {
            Some(k) => map.remove(&k),
            None => break,
        };
    }
    map.insert(key, (value, Instant::now()));
}

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
    /// Semaphore that limits concurrent headless-Chrome PDF renders.
    pub pdf_semaphore: Arc<Semaphore>,
    pub rate_limits: RateLimitStore,
    /// Immutable resolved configuration.
    pub config: Arc<Config>,
}

impl AppState {
    pub fn new(config: Arc<Config>) -> Self {
        AppState {
            store: Arc::new(RwLock::new(HashMap::new())),
            uploads: Arc::new(RwLock::new(HashMap::new())),
            cache: Arc::new(RwLock::new(HashMap::new())),
            semaphore: Arc::new(Semaphore::new(config.max_concurrent_scans)),
            pdf_semaphore: Arc::new(Semaphore::new(config.max_pdf_renders)),
            rate_limits: Arc::new(RwLock::new(HashMap::new())),
            config,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insert_capped_evicts_oldest() {
        let mut map = HashMap::new();
        for i in 0..5u32 {
            insert_capped(&mut map, format!("k{i}"), i, 3);
        }
        assert_eq!(map.len(), 3);
        assert!(map.contains_key("k4") && map.contains_key("k3") && map.contains_key("k2"));
        // Re-inserting an existing key replaces it without evicting anything.
        insert_capped(&mut map, "k2".into(), 9, 3);
        assert_eq!(map.len(), 3);
        assert_eq!(map["k2"].0, 9);
    }
}
