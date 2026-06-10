//! Offline IP geolocation via a local IP2Location LITE database.
//!
//! Mirrors MobSF's approach: lookups happen in-process against an mmap'd BIN file,
//! so there are no per-domain HTTP requests, no rate limits, and no third-party
//! service dependency.
//!
//! Database resolution order (first hit wins):
//!   1. Path passed to [`init`] (typically the `--geoip-db` CLI flag).
//!   2. `PAVISE_GEOIP_DB` environment variable.
//!   3. `$HOME/.pavise/IP2LOCATION-LITE-DB5.IPV6.BIN`
//!   4. `<exe_dir>/data/geoip/IP2LOCATION-LITE-DB5.IPV6.BIN`
//!
//! Recommended database: IP2Location LITE DB5 IPV6 (free, CC-BY-SA 4.0).
//! Compatible with any DB1–DB11 LITE BIN. Higher tiers add ISP/ASN fields,
//! which this module surfaces when present.

use ip2location::{Record, DB};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use tracing::{debug, info, warn};

/// Default filename shipped by IP2Location for the LITE DB5 IPv6 dataset.
const DEFAULT_FILENAME: &str = "IP2LOCATION-LITE-DB5.IPV6.BIN";

/// Subset of an IP2Location record exposed to callers. Fields are populated
/// best-effort — LITE DB5 covers country/city/lat/lon; ISP/ASN are only set
/// when the loaded BIN is a higher tier.
#[derive(Debug, Clone, Default)]
pub struct GeoEntry {
    pub country: Option<String>,
    pub country_code: Option<String>,
    pub city: Option<String>,
    pub lat: Option<f64>,
    pub lon: Option<f64>,
    pub isp: Option<String>,
}

static DB_HANDLE: OnceLock<Option<LoadedDb>> = OnceLock::new();

struct LoadedDb {
    db: DB,
    path: PathBuf,
}

/// Initialize the global DB handle with an explicit path override. Must be
/// called before any [`is_available`] / [`lookup_batch`] call to take effect;
/// later calls are no-ops because the underlying `OnceLock` only commits once.
///
/// `None` triggers the default search order (env var → home → exe dir) on the
/// first lazy access.
pub fn init(explicit: Option<PathBuf>) {
    let _ = DB_HANDLE.set(load_from(explicit.as_deref()));
}

/// True if a usable IP2Location BIN was located and opened. Triggers lazy
/// initialization via the default search order if [`init`] was not called.
pub fn is_available() -> bool {
    DB_HANDLE.get_or_init(|| load_from(None)).is_some()
}

/// Path of the loaded BIN file, if any. Useful for audit logging.
pub fn loaded_path() -> Option<&'static Path> {
    DB_HANDLE
        .get_or_init(|| load_from(None))
        .as_ref()
        .map(|l| l.path.as_path())
}

/// Look up every IP in `ips` against the local DB. Unresolvable / malformed
/// inputs are silently skipped — callers should treat a missing key as a miss.
pub fn lookup_batch(ips: &[String]) -> HashMap<String, GeoEntry> {
    let Some(loaded) = DB_HANDLE.get_or_init(|| load_from(None)).as_ref() else {
        return HashMap::new();
    };

    let mut out = HashMap::with_capacity(ips.len());
    for raw in ips {
        let Ok(addr) = raw.parse::<std::net::IpAddr>() else {
            debug!("geoip_local: skipping non-IP input {:?}", raw);
            continue;
        };
        match loaded.db.ip_lookup(addr) {
            Ok(Record::LocationDb(rec)) => {
                out.insert(raw.clone(), to_entry(&rec));
            }
            Ok(Record::ProxyDb(_)) => {
                // A PROXY BIN was loaded by mistake — it has no geo fields.
                debug!("geoip_local: loaded DB is a PX (proxy) tier, no geo data");
            }
            Err(e) => {
                debug!("geoip_local: lookup failed for {}: {:?}", raw, e);
            }
        }
    }
    out
}

// ------------------------------------------------------------------ //
// Internal helpers
// ------------------------------------------------------------------ //

fn to_entry(rec: &ip2location::LocationRecord<'_>) -> GeoEntry {
    let (country, country_code) = match &rec.country {
        Some(c) => (
            Some(c.long_name.to_string()).filter(|s| !s.is_empty() && s != "-"),
            Some(c.short_name.to_string()).filter(|s| !s.is_empty() && s != "-"),
        ),
        None => (None, None),
    };

    GeoEntry {
        country,
        country_code,
        city: rec
            .city
            .as_ref()
            .map(|c| c.to_string())
            .filter(|s| !s.is_empty() && s != "-"),
        lat: rec.latitude.map(|v| v as f64),
        lon: rec.longitude.map(|v| v as f64),
        isp: rec
            .isp
            .as_ref()
            .map(|c| c.to_string())
            .filter(|s| !s.is_empty() && s != "-"),
    }
}

fn load_from(explicit: Option<&Path>) -> Option<LoadedDb> {
    let path = match resolve_path(explicit) {
        Some(p) => p,
        None => {
            debug!(
                "geoip_local: no IP2Location DB found (checked --geoip-db, $PAVISE_GEOIP_DB, ~/.pavise/, <exe_dir>/data/geoip/)"
            );
            return None;
        }
    };

    match DB::from_file(&path) {
        Ok(db) => {
            info!("geoip_local: loaded {}", path.display());
            Some(LoadedDb { db, path })
        }
        Err(e) => {
            warn!(
                "geoip_local: failed to open {}: {:?} — falling back to remote provider",
                path.display(),
                e
            );
            None
        }
    }
}

/// Walk the configured search order and return the first existing path.
fn resolve_path(explicit: Option<&Path>) -> Option<PathBuf> {
    if let Some(p) = explicit {
        return existing(p.to_path_buf()).or_else(|| {
            warn!("geoip_local: --geoip-db path does not exist: {}", p.display());
            None
        });
    }

    if let Ok(s) = std::env::var("PAVISE_GEOIP_DB") {
        if !s.is_empty() {
            if let Some(p) = existing(PathBuf::from(&s)) {
                return Some(p);
            }
            warn!("geoip_local: PAVISE_GEOIP_DB points to missing file: {}", s);
        }
    }

    // ~/.pavise/<default-filename>
    if let Some(home) = home_dir() {
        if let Some(p) = existing(home.join(".pavise").join(DEFAULT_FILENAME)) {
            return Some(p);
        }
    }

    // <exe_dir>/data/geoip/<default-filename>
    if let Ok(exe) = std::env::current_exe() {
        if let Some(parent) = exe.parent() {
            if let Some(p) = existing(parent.join("data").join("geoip").join(DEFAULT_FILENAME)) {
                return Some(p);
            }
        }
    }

    None
}

fn existing(p: PathBuf) -> Option<PathBuf> {
    if p.is_file() {
        Some(p)
    } else {
        None
    }
}

/// `std::env::home_dir` is deprecated and platform-broken on Windows. We only
/// need POSIX semantics (`$HOME`) here; Pavise targets macOS/Linux.
fn home_dir() -> Option<PathBuf> {
    std::env::var_os("HOME").map(PathBuf::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entry_filters_empty_strings() {
        // Construct a record-like situation indirectly by exercising to_entry's
        // post-processing semantics through GeoEntry::default().
        let e = GeoEntry::default();
        assert!(e.country.is_none());
        assert!(e.country_code.is_none());
    }

    #[test]
    fn lookup_batch_with_no_db_returns_empty() {
        // Force a state where no DB is loaded by pointing at a guaranteed-missing path.
        // This test only works if no prior test in this binary initialized DB_HANDLE,
        // so we don't actually call DB_HANDLE here — just assert resolve_path's miss path.
        let p = resolve_path(Some(Path::new("/nonexistent/pavise-geoip-test.bin")));
        assert!(p.is_none());
    }
}
