// NDR Engine — Enrichment Pipeline
// Orchestrates GeoIP, ASN, and threat intel enrichment.
// Private IP detection based on RFC1918/RFC4291 (recoded from scratch).
// Sensitive country list from Malcolm's 23_severity.conf (public domain concept).
// License: Apache-2.0

pub mod geoip;
pub mod asn;
pub mod threat_intel;
pub mod asset_id;
pub mod asset_intel;
use std::sync::Arc;


pub use geoip::{GeoIpLookup, GeoInfo};
pub use asn::{AsnLookup, AsnInfo};
pub use threat_intel::ThreatIntel;
pub use asset_id::AssetIdentifier;

use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::str::FromStr;

// ── Private IP detection ──────────────────────────────────────────────────
// Matches Malcolm's internal_ip_tag.rb logic — recoded from scratch.

/// Returns true if the IP is private, loopback, or link-local.
pub fn is_private_ip(ip_str: &str) -> bool {
    let Ok(addr) = IpAddr::from_str(ip_str) else { return false };
    match addr {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            o[0] == 10                                        // 10.0.0.0/8
                || (o[0] == 172 && (16..=31).contains(&o[1])) // 172.16.0.0/12
                || (o[0] == 192 && o[1] == 168)               // 192.168.0.0/16
                || o[0] == 127                                 // 127.0.0.0/8
                || (o[0] == 169 && o[1] == 254)               // 169.254.0.0/16
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || (v6.segments()[0] & 0xfe00 == 0xfc00) // fc00::/7 (ULA)
                || (v6.segments()[0] & 0xffc0 == 0xfe80) // fe80::/10 (link-local)
        }
    }
}

/// Traffic direction based on src/dst privacy. Mirrors Malcolm's tagging logic.
pub fn network_direction(src_ip: &str, dst_ip: &str) -> &'static str {
    match (is_private_ip(src_ip), is_private_ip(dst_ip)) {
        (true,  true)  => "internal",
        (true,  false) => "outbound",
        (false, true)  => "inbound",
        (false, false) => "external",
    }
}

// ── Sensitive country list ────────────────────────────────────────────────
// Source: Malcolm's 23_severity.conf ENV['SENSITIVE_COUNTRY_CODES'] default
// (public domain concept — these are common export control / high-risk countries)

pub const SENSITIVE_COUNTRIES: &[&str] = &[
    "AM", "AZ", "BY", "CN", "CU", "DZ", "GE", "HK", "IL", "IN",
    "IQ", "IR", "KG", "KP", "KZ", "LY", "MD", "MO", "PK", "RU",
    "SD", "SS", "SY", "TJ", "TM", "TW", "UA", "UZ",
];

// ── Enrichment result ─────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct EnrichmentData {
    pub src_geo:           Option<GeoInfo>,
    pub dst_geo:           Option<GeoInfo>,
    pub src_asn:           Option<AsnInfo>,
    pub dst_asn:           Option<AsnInfo>,
    pub is_malicious:      bool,
    pub direction:         String,
    pub sensitive_country: bool,
}

// ── Pipeline ──────────────────────────────────────────────────────────────

/// Holds all enrichment resources. Created once at startup and shared via Arc.
pub struct EnrichmentPipeline {
    pub geoip:        Option<GeoIpLookup>,
    pub asn:          Arc<Option<AsnLookup>>,
    pub threat_intel: Arc<ThreatIntel>,
    pub asset_id:     Arc<AssetIdentifier>,
}

impl EnrichmentPipeline {
    /// Enrich a src/dst IP pair. All steps are optional and fail silently.
    pub fn enrich(&self, src_ip: &str, dst_ip: &str) -> EnrichmentData {
        let src_external = !is_private_ip(src_ip);
        let dst_external = !is_private_ip(dst_ip);

        let src_geo = src_external
            .then(|| self.geoip.as_ref().and_then(|g| g.lookup(src_ip)))
            .flatten();

        let dst_geo = dst_external
            .then(|| self.geoip.as_ref().and_then(|g| g.lookup(dst_ip)))
            .flatten();

        let src_asn = src_external
            .then(|| (*self.asn).as_ref().and_then(|a| a.lookup(src_ip)))
            .flatten();

        let dst_asn = dst_external
            .then(|| (*self.asn).as_ref().and_then(|a| a.lookup(dst_ip)))
            .flatten();
        let is_malicious = self.threat_intel.is_malicious_ip(src_ip)
            || self.threat_intel.is_malicious_ip(dst_ip)
            || self.threat_intel.is_malicious_domain(src_ip)
            || self.threat_intel.is_malicious_domain(dst_ip);

        let direction = network_direction(src_ip, dst_ip).to_string();

        let sensitive_country = [&src_geo, &dst_geo]
            .iter()
            .filter_map(|g| g.as_ref())
            .any(|g| SENSITIVE_COUNTRIES.contains(&g.country_code.as_str()));

        EnrichmentData { src_geo, dst_geo, src_asn, dst_asn, is_malicious, direction, sensitive_country }
    }
}
