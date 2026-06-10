//! Network-based domain intelligence: DNS resolution, IP geolocation, OFAC checks.
//!
//! Provider strategy:
//!   1. If a local IP2Location BIN is available (see [`super::geoip_local`]),
//!      every IP is resolved offline — no HTTP, no rate limit, no third party.
//!   2. Otherwise the legacy ip-api.com batch endpoint is used as a fallback
//!      (45 req/min, no commercial use, requires `--network`).
//!
//! Only invoked when `--network` is supplied at the CLI layer.

use anyhow::Result;
use std::collections::HashMap;
use std::net::ToSocketAddrs;
use tracing::{debug, info};

use crate::network::geoip_local::{self, GeoEntry};
use crate::network::geoip_remote;
use crate::types::DomainGeoInfo;

/// OFAC-sanctioned country codes (ISO 3166-1 alpha-2).
/// Source: US Treasury OFAC primary sanctions programs.
const OFAC_SANCTIONED: &[&str] = &[
    "CU", // Cuba
    "IR", // Iran
    "KP", // North Korea
    "SY", // Syria
];

/// Resolve each domain to its first IP and return geolocation for all.
/// Domains that fail DNS resolution are included with `ip: None`.
pub fn analyze_domains(domains: &[String]) -> Result<Vec<DomainGeoInfo>> {
    if domains.is_empty() {
        return Ok(Vec::new());
    }

    // Step 1: DNS resolve — collect only what succeeds
    let mut domain_to_ip: HashMap<String, String> = HashMap::new();
    for domain in domains {
        // Bare IPs can be looked up directly
        if is_ip(domain) {
            domain_to_ip.insert(domain.clone(), domain.clone());
        } else if let Ok(ip) = resolve(domain) {
            domain_to_ip.insert(domain.clone(), ip);
        } else {
            debug!("DNS resolution failed for {}", domain);
        }
    }

    // Step 2: GeoIP for all resolved IPs (deduplicated). Prefer local DB.
    let unique_ips: Vec<String> = {
        let mut ips: Vec<String> = domain_to_ip.values().cloned().collect();
        ips.sort();
        ips.dedup();
        ips
    };

    let geo_by_ip: HashMap<String, GeoEntry> = if unique_ips.is_empty() {
        HashMap::new()
    } else if geoip_local::is_available() {
        if let Some(p) = geoip_local::loaded_path() {
            info!(
                "domain_intel: using offline IP2Location DB at {}",
                p.display()
            );
        }
        geoip_local::lookup_batch(&unique_ips)
    } else {
        debug!("domain_intel: no local DB — falling back to ip-api.com");
        geoip_remote::lookup_batch(&unique_ips).unwrap_or_default()
    };

    // Step 3: Assemble results
    let results = domains
        .iter()
        .map(|domain| {
            let ip = domain_to_ip.get(domain).cloned();
            let geo = ip.as_ref().and_then(|ip| geo_by_ip.get(ip));

            let country_code = geo.and_then(|g| g.country_code.clone());
            let is_ofac_sanctioned = country_code
                .as_deref()
                .map(|cc| OFAC_SANCTIONED.contains(&cc))
                .unwrap_or(false);

            DomainGeoInfo {
                domain: domain.clone(),
                ip,
                country: geo.and_then(|g| g.country.clone()),
                country_code,
                city: geo.and_then(|g| g.city.clone()),
                lat: geo.and_then(|g| g.lat),
                lon: geo.and_then(|g| g.lon),
                isp: geo.and_then(|g| g.isp.clone()),
                is_ofac_sanctioned,
            }
        })
        .collect();

    Ok(results)
}

// ------------------------------------------------------------------ //
// Internal helpers
// ------------------------------------------------------------------ //

/// Synchronous DNS resolution. Returns the first IPv4/IPv6 address as a string.
fn resolve(domain: &str) -> Result<String> {
    let addrs: Vec<_> = format!("{}:80", domain).to_socket_addrs()?.collect();
    addrs
        .first()
        .map(|a| a.ip().to_string())
        .ok_or_else(|| anyhow::anyhow!("no addresses returned for {}", domain))
}

/// True if the string is a bare IPv4/IPv6 address rather than a hostname.
fn is_ip(s: &str) -> bool {
    s.parse::<std::net::IpAddr>().is_ok()
}
