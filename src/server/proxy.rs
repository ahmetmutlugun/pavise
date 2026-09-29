//! Client-IP resolution behind a reverse proxy.
//!
//! `CF-Connecting-IP` / `X-Forwarded-For` are plain request headers: any client
//! can send them. They are only believed when the TCP peer is a configured
//! proxy, otherwise one client could rotate fake IPs past the rate limiter.
//!
//! A trusted peer is not proof the request passed through Cloudflare: a shared
//! edge (Railway) forwards whatever headers a client that bypasses Cloudflare
//! sends. With an [`EdgeSecret`] set, `CF-Connecting-IP` is believed only when
//! the request carries the secret, which a Cloudflare Transform Rule adds.

use std::net::{IpAddr, SocketAddr};

use axum::http::HeaderMap;

/// An IP network (`10.0.0.0/8`, `::1/128`); a bare address is a /32 or /128.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cidr {
    addr: IpAddr,
    prefix: u8,
}

/// Loopback and private ranges: where a same-host or LAN proxy connects from.
const PRIVATE_RANGES: &[&str] = &[
    "127.0.0.0/8",
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "::1/128",
    "fc00::/7",
];

/// Header a Cloudflare Transform Rule sets to the `PAVISE_EDGE_SECRET` value.
pub const EDGE_SECRET_HEADER: &str = "X-Pavise-Edge";

/// Shared secret proving a request came through Cloudflare. `Debug` is
/// redacted so the value never reaches logs.
#[derive(Clone, PartialEq, Eq)]
pub struct EdgeSecret(String);

impl EdgeSecret {
    /// `None` for an empty or whitespace-only value.
    pub fn new(s: &str) -> Option<Self> {
        let s = s.trim();
        (!s.is_empty()).then(|| EdgeSecret(s.to_owned()))
    }

    /// Constant-time comparison, so response timing can't reveal the secret.
    fn matches(&self, candidate: &[u8]) -> bool {
        let secret = self.0.as_bytes();
        secret.len() == candidate.len()
            && secret
                .iter()
                .zip(candidate)
                .fold(0u8, |acc, (a, b)| acc | (a ^ b))
                == 0
    }
}

impl std::fmt::Debug for EdgeSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("EdgeSecret(<redacted>)")
    }
}

impl Cidr {
    pub fn parse(s: &str) -> Result<Self, String> {
        let (ip, prefix) = match s.split_once('/') {
            Some((ip, p)) => (ip, Some(p)),
            None => (s, None),
        };
        let addr: IpAddr = ip
            .parse()
            .map_err(|_| format!("invalid IP address {ip:?}"))?;
        let max = if addr.is_ipv4() { 32 } else { 128 };
        let prefix = match prefix {
            Some(p) => p
                .parse::<u8>()
                .ok()
                .filter(|p| *p <= max)
                .ok_or_else(|| format!("invalid prefix length in {s:?}"))?,
            None => max,
        };
        Ok(Cidr { addr, prefix })
    }

    /// Comma-separated CIDRs. `1`/`true`/`yes` (the old on/off form) means
    /// loopback + private ranges.
    pub fn parse_list(s: &str) -> Result<Vec<Self>, String> {
        if matches!(s.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes") {
            return PRIVATE_RANGES.iter().map(|r| Cidr::parse(r)).collect();
        }
        s.split(',')
            .map(str::trim)
            .filter(|p| !p.is_empty())
            .map(Cidr::parse)
            .collect()
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        let ip = match ip {
            IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
            v4 => v4,
        };
        match (self.addr, ip) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => {
                let mask = u32::MAX.checked_shl(32 - self.prefix as u32).unwrap_or(0);
                u32::from(net) & mask == u32::from(ip) & mask
            }
            (IpAddr::V6(net), IpAddr::V6(ip)) => {
                let mask = u128::MAX.checked_shl(128 - self.prefix as u32).unwrap_or(0);
                u128::from(net) & mask == u128::from(ip) & mask
            }
            _ => false,
        }
    }
}

/// True when no secret is configured or the request carries it.
fn carries_secret(headers: &HeaderMap, edge_secret: Option<&EdgeSecret>) -> bool {
    match edge_secret {
        None => true,
        Some(secret) => headers
            .get(EDGE_SECRET_HEADER)
            .is_some_and(|v| secret.matches(v.as_bytes())),
    }
}

/// A request that reached a trusted proxy without passing through Cloudflare:
/// a secret is configured, the peer is trusted, and the secret is missing or
/// wrong. The server rejects these (`handlers::require_edge`).
pub fn bypassed_edge(
    peer: SocketAddr,
    headers: &HeaderMap,
    trusted: &[Cidr],
    edge_secret: Option<&EdgeSecret>,
) -> bool {
    edge_secret.is_some()
        && trusted.iter().any(|c| c.contains(peer.ip()))
        && !carries_secret(headers, edge_secret)
}

/// The client IP: the TCP peer, unless the peer is a trusted proxy, in which
/// case `CF-Connecting-IP` (set by Cloudflare; with `edge_secret` set, only
/// when the request carries it) or the rightmost `X-Forwarded-For` hop
/// (appended by the proxy; leftmost is client-supplied).
pub fn real_ip(
    peer: SocketAddr,
    headers: &HeaderMap,
    trusted: &[Cidr],
    edge_secret: Option<&EdgeSecret>,
) -> IpAddr {
    let peer_ip = peer.ip();
    if !trusted.iter().any(|c| c.contains(peer_ip)) {
        return peer_ip;
    }
    let header = |name: &str| headers.get(name).and_then(|v| v.to_str().ok());
    if carries_secret(headers, edge_secret) {
        if let Some(ip) = header("CF-Connecting-IP").and_then(|s| s.trim().parse().ok()) {
            return ip;
        }
    }
    header("X-Forwarded-For")
        .and_then(|s| s.rsplit(',').next())
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(peer_ip)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer(ip: &str) -> SocketAddr {
        SocketAddr::new(ip.parse().unwrap(), 4000)
    }

    fn headers(pairs: &[(&'static str, &str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (k, v) in pairs {
            h.insert(*k, v.parse().unwrap());
        }
        h
    }

    #[test]
    fn cidr_contains() {
        let net = Cidr::parse("172.16.0.0/12").unwrap();
        assert!(net.contains("172.20.1.1".parse().unwrap()));
        assert!(!net.contains("172.32.0.1".parse().unwrap()));
        assert!(Cidr::parse("::1").unwrap().contains("::1".parse().unwrap()));
        assert!(Cidr::parse("0.0.0.0/0")
            .unwrap()
            .contains("8.8.8.8".parse().unwrap()));
        // IPv4-mapped IPv6 peers (dual-stack sockets) match IPv4 ranges.
        assert!(net.contains("::ffff:172.20.1.1".parse().unwrap()));
    }

    #[test]
    fn cidr_rejects_garbage() {
        assert!(Cidr::parse("10.0.0.0/33").is_err());
        assert!(Cidr::parse("proxy.local").is_err());
        assert!(Cidr::parse_list("10.0.0.1, nope").is_err());
    }

    #[test]
    fn legacy_flag_trusts_private_ranges() {
        let list = Cidr::parse_list("1").unwrap();
        assert!(list
            .iter()
            .any(|c| c.contains("127.0.0.1".parse().unwrap())));
        assert!(!list.iter().any(|c| c.contains("8.8.8.8".parse().unwrap())));
    }

    #[test]
    fn untrusted_peer_cannot_spoof() {
        let trusted = Cidr::parse_list("127.0.0.1").unwrap();
        let h = headers(&[
            ("CF-Connecting-IP", "1.2.3.4"),
            ("X-Forwarded-For", "5.6.7.8"),
        ]);
        assert_eq!(
            real_ip(peer("203.0.113.9"), &h, &trusted, None),
            "203.0.113.9".parse::<IpAddr>().unwrap()
        );
        assert_eq!(
            real_ip(peer("127.0.0.1"), &h, &[], None),
            "127.0.0.1".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn trusted_peer_headers_used() {
        let trusted = Cidr::parse_list("127.0.0.1").unwrap();
        let cf = headers(&[("CF-Connecting-IP", "1.2.3.4")]);
        assert_eq!(
            real_ip(peer("127.0.0.1"), &cf, &trusted, None),
            "1.2.3.4".parse::<IpAddr>().unwrap()
        );
        // Client-forged leftmost entry is ignored; the proxy-appended hop wins.
        let xff = headers(&[("X-Forwarded-For", "9.9.9.9, 5.6.7.8")]);
        assert_eq!(
            real_ip(peer("127.0.0.1"), &xff, &trusted, None),
            "5.6.7.8".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn edge_secret_gates_cloudflare_header() {
        let trusted = Cidr::parse_list("100.64.0.0/10").unwrap();
        let secret = EdgeSecret::new("s3cret").unwrap();
        let ip = |h: &HeaderMap| real_ip(peer("100.64.0.9"), h, &trusted, Some(&secret));
        // Through Cloudflare: the Transform Rule's header matches.
        let good = headers(&[
            (EDGE_SECRET_HEADER, "s3cret"),
            ("CF-Connecting-IP", "1.2.3.4"),
            ("X-Forwarded-For", "162.158.0.1"),
        ]);
        assert_eq!(ip(&good), "1.2.3.4".parse::<IpAddr>().unwrap());
        // Bypassing Cloudflare: a forged CF-Connecting-IP without (or with a
        // wrong) secret falls back to the hop the edge proxy appended.
        for forged in [
            headers(&[
                ("CF-Connecting-IP", "1.2.3.4"),
                ("X-Forwarded-For", "203.0.113.7"),
            ]),
            headers(&[
                (EDGE_SECRET_HEADER, "guess"),
                ("CF-Connecting-IP", "1.2.3.4"),
                ("X-Forwarded-For", "203.0.113.7"),
            ]),
            headers(&[
                (EDGE_SECRET_HEADER, "s3cre"),
                ("CF-Connecting-IP", "1.2.3.4"),
                ("X-Forwarded-For", "203.0.113.7"),
            ]),
        ] {
            assert_eq!(ip(&forged), "203.0.113.7".parse::<IpAddr>().unwrap());
        }
    }

    #[test]
    fn edge_secret_is_redacted_and_rejects_blank() {
        assert!(EdgeSecret::new("  ").is_none());
        let s = EdgeSecret::new(" abc ").unwrap();
        assert!(s.matches(b"abc"));
        assert_eq!(format!("{s:?}"), "EdgeSecret(<redacted>)");
    }

    #[test]
    fn bypass_needs_secret_trusted_peer_and_mismatch() {
        let trusted = Cidr::parse_list("100.64.0.0/10").unwrap();
        let secret = EdgeSecret::new("s3cret").unwrap();
        let edge = peer("100.64.0.9");
        let good = headers(&[(EDGE_SECRET_HEADER, "s3cret")]);
        let bad = headers(&[(EDGE_SECRET_HEADER, "nope")]);
        let none = HeaderMap::new();
        assert!(!bypassed_edge(edge, &good, &trusted, Some(&secret)));
        assert!(bypassed_edge(edge, &bad, &trusted, Some(&secret)));
        assert!(bypassed_edge(edge, &none, &trusted, Some(&secret)));
        // No secret configured, or an untrusted (direct, local) peer: allowed.
        assert!(!bypassed_edge(edge, &none, &trusted, None));
        assert!(!bypassed_edge(
            peer("127.0.0.1"),
            &none,
            &trusted,
            Some(&secret)
        ));
    }
}
