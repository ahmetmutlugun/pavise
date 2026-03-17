//! Network-based domain intelligence: DNS resolution, IP geolocation, OFAC checks.
//!
//! Only called when `--network` is supplied. Uses ip-api.com (free, no API key needed,
//! 45 req/min limit, no commercial use). Batch endpoint: POST ip-api.com/batch.

use anyhow::Result;
use serde::Deserialize;
use std::collections::HashMap;
use std::net::ToSocketAddrs;
use tracing::debug;

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
        // Skip bare IPs — ip-api.com can handle them directly
        if is_ip(domain) {
            domain_to_ip.insert(domain.clone(), domain.clone());
        } else if let Ok(ip) = resolve(domain) {
            domain_to_ip.insert(domain.clone(), ip);
        } else {
            debug!("DNS resolution failed for {}", domain);
        }
    }

    // Step 2: Batch geoIP for all resolved IPs (deduplicated)
    let unique_ips: Vec<String> = {
        let mut ips: Vec<String> = domain_to_ip.values().cloned().collect();
        ips.sort();
        ips.dedup();
        ips
    };
    let geo_by_ip = if unique_ips.is_empty() {
        HashMap::new()
    } else {
        geoip_batch(&unique_ips).unwrap_or_default()
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

/// Response schema from ip-api.com batch endpoint.
#[derive(Debug, Deserialize)]
struct IpApiEntry {
    #[serde(default)]
    status: String,
    country: Option<String>,
    #[serde(rename = "countryCode")]
    country_code: Option<String>,
    city: Option<String>,
    lat: Option<f64>,
    lon: Option<f64>,
    isp: Option<String>,
    /// The IP that was queried — used to correlate results.
    query: Option<String>,
}

/// Batch geoIP lookup via ip-api.com. Returns a map of IP → entry.
///
/// ip-api.com free tier: 45 requests/minute, max 100 IPs per batch request.
/// No API key required; not for commercial use.
fn geoip_batch(ips: &[String]) -> Result<HashMap<String, IpApiEntry>> {
    let agent = ureq::AgentBuilder::new()
        .timeout(std::time::Duration::from_secs(15))
        .user_agent("pavise-security-scanner/1.0")
        .build();

    let mut result_map: HashMap<String, IpApiEntry> = HashMap::new();

    for chunk in ips.chunks(100) {
        let body: Vec<serde_json::Value> = chunk
            .iter()
            .map(|ip| serde_json::json!({ "query": ip }))
            .collect();

        let response = match agent
            .post("https://ip-api.com/batch?fields=status,message,country,countryCode,city,lat,lon,isp,query")
            .send_json(serde_json::to_value(&body)?)
        {
            Ok(r) => r,
            Err(e) => {
                debug!("ip-api.com request failed: {}", e);
                continue;
            }
        };

        if response.status() != 200 {
            debug!("ip-api.com returned status {}", response.status());
            continue;
        }

        let entries: Vec<IpApiEntry> = match response.into_json() {
            Ok(v) => v,
            Err(e) => {
                debug!("Failed to parse ip-api.com response: {}", e);
                continue;
            }
        };

        for entry in entries {
            if entry.status == "success" {
                if let Some(ref ip) = entry.query {
                    result_map.insert(ip.clone(), entry);
                }
            }
        }
    }

    Ok(result_map)
}
