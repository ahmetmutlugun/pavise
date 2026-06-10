//! Remote IP geolocation via ip-api.com (free tier, no API key).
//!
//! Used only as a fallback when no local IP2Location DB has been configured —
//! see [`super::geoip_local`]. Free-tier limits: 45 req/min, max 100 IPs per
//! batch request, not for commercial use.

use anyhow::Result;
use serde::Deserialize;
use std::collections::HashMap;
use tracing::debug;

use crate::network::geoip_local::GeoEntry;

/// Batch geoIP lookup via ip-api.com. Returns a map of IP → [`GeoEntry`].
pub fn lookup_batch(ips: &[String]) -> Result<HashMap<String, GeoEntry>> {
    let agent = ureq::AgentBuilder::new()
        .timeout(std::time::Duration::from_secs(15))
        .user_agent("pavise-security-scanner/1.0")
        .build();

    let mut result_map: HashMap<String, GeoEntry> = HashMap::new();

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
                    result_map.insert(ip.clone(), entry.into_geo());
                }
            }
        }
    }

    Ok(result_map)
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

impl IpApiEntry {
    fn into_geo(self) -> GeoEntry {
        GeoEntry {
            country: self.country,
            country_code: self.country_code,
            city: self.city,
            lat: self.lat,
            lon: self.lon,
            isp: self.isp,
        }
    }
}
