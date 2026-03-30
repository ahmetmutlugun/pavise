use std::{path::PathBuf, time::Duration};

/// Resolved server configuration parsed from environment variables.
///
/// All values are read once at startup. Invalid values are collected and
/// reported together so every misconfiguration is visible at once rather
/// than one-at-a-time.
#[derive(Debug, Clone)]
pub struct Config {
    /// TCP port to listen on. Env: `PORT` (default: 3000).
    pub port: u16,
    /// Directory containing Vite-built frontend assets. Env: `PAVISE_DIST_DIR`.
    pub dist_dir: PathBuf,
    /// Maximum simultaneous IPA scans. Env: `PAVISE_MAX_SCANS` (default: 4).
    pub max_concurrent_scans: usize,
    /// Maximum upload size in bytes. Env: `PAVISE_MAX_UPLOAD_BYTES` (default: 512 MiB).
    ///
    /// The old default was 15 GiB which could exhaust memory inside an 8 GiB
    /// Docker container before the scan even started.
    pub max_upload_bytes: u64,
    /// Directory for chunked-upload temp files. Env: `PAVISE_UPLOAD_DIR`.
    pub upload_dir: PathBuf,
    /// Maximum requests per IP per minute. Env: `PAVISE_RATE_LIMIT` (default: 20).
    pub rate_limit_max: u32,
    /// How long to keep cached scan results. Env: `PAVISE_CACHE_TTL_HOURS` (default: 24).
    pub cache_ttl: Duration,
}

impl Config {
    /// Parse and validate every environment variable.
    ///
    /// All invalid values are collected before returning so operators see the
    /// full list of problems in a single startup failure.
    pub fn from_env() -> Result<Self, Vec<String>> {
        let mut errors: Vec<String> = Vec::new();

        let port = parse_u16("PORT", 3000, &mut errors);

        let dist_dir = std::env::var("PAVISE_DIST_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| {
                let manifest = std::env::var("CARGO_MANIFEST_DIR")
                    .map(PathBuf::from)
                    .unwrap_or_else(|_| PathBuf::from("."));
                manifest.join("web/dist")
            });

        let max_concurrent_scans = parse_nonzero_usize("PAVISE_MAX_SCANS", 4, &mut errors);
        let max_upload_bytes =
            parse_nonzero_u64("PAVISE_MAX_UPLOAD_BYTES", 512 * 1024 * 1024, &mut errors);
        let rate_limit_max = parse_nonzero_u32("PAVISE_RATE_LIMIT", 20, &mut errors);
        let cache_ttl_hours = parse_nonzero_u64("PAVISE_CACHE_TTL_HOURS", 24, &mut errors);

        let upload_dir = std::env::var("PAVISE_UPLOAD_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| std::env::temp_dir().join("pavise-uploads"));

        if !errors.is_empty() {
            return Err(errors);
        }

        if let Err(e) = std::fs::create_dir_all(&upload_dir) {
            return Err(vec![format!(
                "Cannot create upload directory '{}': {e}",
                upload_dir.display()
            )]);
        }

        let cfg = Config {
            port,
            dist_dir,
            max_concurrent_scans,
            max_upload_bytes,
            upload_dir,
            rate_limit_max,
            cache_ttl: Duration::from_secs(cache_ttl_hours.saturating_mul(3600)),
        };

        tracing::info!(
            port = cfg.port,
            max_concurrent_scans = cfg.max_concurrent_scans,
            max_upload_mb = cfg.max_upload_bytes / (1024 * 1024),
            rate_limit_per_min = cfg.rate_limit_max,
            cache_ttl_hours = cache_ttl_hours,
            dist_dir = %cfg.dist_dir.display(),
            upload_dir = %cfg.upload_dir.display(),
            "Pavise server configuration resolved"
        );

        Ok(cfg)
    }

    /// Convenience constructor used by integration tests.
    pub fn for_testing() -> Self {
        let upload_dir = std::env::temp_dir().join("pavise-test-uploads");
        std::fs::create_dir_all(&upload_dir).ok();
        Config {
            port: 0,
            dist_dir: PathBuf::from("web/dist"),
            max_concurrent_scans: 2,
            max_upload_bytes: 2 * 1024 * 1024, // 2 MiB — enough to test 413 cheaply
            upload_dir,
            rate_limit_max: 100,
            cache_ttl: Duration::from_secs(3600),
        }
    }
}

// ── Env-var parse helpers ────────────────────────────────────────────────────

fn parse_u16(name: &str, default: u16, errors: &mut Vec<String>) -> u16 {
    match std::env::var(name) {
        Ok(v) => v.parse().unwrap_or_else(|_| {
            errors.push(format!(
                "{name}={v:?} is not a valid port number (0-65535)"
            ));
            default
        }),
        Err(_) => default,
    }
}

fn parse_nonzero_usize(name: &str, default: usize, errors: &mut Vec<String>) -> usize {
    match std::env::var(name) {
        Ok(v) => match v.parse::<usize>() {
            Ok(0) => {
                errors.push(format!("{name}=0 is invalid; must be at least 1"));
                default
            }
            Ok(n) => n,
            Err(_) => {
                errors.push(format!("{name}={v:?} is not a valid positive integer"));
                default
            }
        },
        Err(_) => default,
    }
}

fn parse_nonzero_u32(name: &str, default: u32, errors: &mut Vec<String>) -> u32 {
    match std::env::var(name) {
        Ok(v) => match v.parse::<u32>() {
            Ok(0) => {
                errors.push(format!("{name}=0 is invalid; must be at least 1"));
                default
            }
            Ok(n) => n,
            Err(_) => {
                errors.push(format!("{name}={v:?} is not a valid positive integer"));
                default
            }
        },
        Err(_) => default,
    }
}

fn parse_nonzero_u64(name: &str, default: u64, errors: &mut Vec<String>) -> u64 {
    match std::env::var(name) {
        Ok(v) => match v.parse::<u64>() {
            Ok(0) => {
                errors.push(format!("{name}=0 is invalid; must be at least 1"));
                default
            }
            Ok(n) => n,
            Err(_) => {
                errors.push(format!("{name}={v:?} is not a valid positive integer"));
                default
            }
        },
        Err(_) => default,
    }
}
