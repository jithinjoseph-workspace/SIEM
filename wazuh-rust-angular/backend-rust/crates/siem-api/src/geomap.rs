//! The world maps from real data, placed with provigil-common's GeoLite2 lookup
//! (the MaxMind database the NDR engine ships; nothing is sent to an outside service):
//! * `/api/threat-map`: where the public source IPs of the tenant's SIEM alerts
//!   of the last 7 days are, with their MITRE tactics / rules;
//! * `/api/admin/threat-map-all-tenants`: the same over every tenant (super admin);
//! * `/api/threat-intel-map`: where the IPs and ranges the threat-intel feeds list are.
//!
//! All answer `{ "countries": [{ country, code, lat, lon, count, hit_count, ip_count, ips, attacks }] }`.
//! Database: `GEOIP_CITY_DB`, else `data/GeoLite2-City.mmdb`, else the NDR engine's copy.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::OnceLock;

use axum::extract::{Extension, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use provigil_common::enrichment::geoip::{GeoInfo, GeoIpLookup};
use serde_json::{json, Value};

use crate::tenancy::AuthCtx;
use crate::AppState;

const TOP_COUNTRIES: usize = 15;
const IPS_PER_COUNTRY: usize = 25;

fn geo() -> Option<&'static GeoIpLookup> {
    static G: OnceLock<Option<GeoIpLookup>> = OnceLock::new();
    G.get_or_init(|| {
        let candidates = [
            std::env::var("GEOIP_CITY_DB").ok().map(std::path::PathBuf::from),
            Some(crate::data_file_path("GeoLite2-City.mmdb")),
            Some(std::path::PathBuf::from("../../ndr/rust/ndr-engine/data/GeoLite2-City.mmdb")),
            Some(std::path::PathBuf::from("../ndr/rust/ndr-engine/data/GeoLite2-City.mmdb")),
            Some(std::path::PathBuf::from("ndr/rust/ndr-engine/data/GeoLite2-City.mmdb")),
        ];
        for p in candidates.into_iter().flatten().filter(|p| p.exists()) {
            match GeoIpLookup::open(&p) {
                Ok(g) => {
                    tracing::info!("GeoIP: {}", p.display());
                    return Some(g);
                }
                Err(e) => tracing::warn!("GeoIP {}: {e}", p.display()),
            }
        }
        tracing::warn!("GeoIP database not found (GeoLite2-City.mmdb): the threat maps stay empty");
        None
    })
    .as_ref()
}

fn locate(ip: &str) -> Option<GeoInfo> {
    geo()?.lookup(ip).filter(|g| !g.country_code.is_empty())
}

fn asn_db() -> Option<&'static provigil_common::enrichment::AsnLookup> {
    static A: OnceLock<Option<provigil_common::enrichment::AsnLookup>> = OnceLock::new();
    A.get_or_init(|| {
        [std::env::var("GEOIP_ASN_DB").ok().map(std::path::PathBuf::from), Some(crate::data_file_path("GeoLite2-ASN.mmdb")), Some("../../ndr/rust/ndr-engine/data/GeoLite2-ASN.mmdb".into()), Some("../ndr/rust/ndr-engine/data/GeoLite2-ASN.mmdb".into()), Some("ndr/rust/ndr-engine/data/GeoLite2-ASN.mmdb".into())]
            .into_iter()
            .flatten()
            .filter(|p| p.exists())
            .find_map(|p| provigil_common::enrichment::AsnLookup::open(&p).ok())
    })
    .as_ref()
}

/// ISO country code of a public IP ("" when unknown): SOAR's `src_country`.
pub fn country_code(ip: &str) -> String {
    if !ip.parse::<IpAddr>().is_ok_and(provigil_common::soar::is_public) {
        return String::new();
    }
    locate(ip).map(|g| g.country_code).unwrap_or_default()
}

/// Where a public IP is and who runs it (`null` for private or unknown addresses).
pub fn describe(ip: &str) -> Value {
    if !ip.parse::<IpAddr>().is_ok_and(provigil_common::soar::is_public) {
        return Value::Null;
    }
    let g = locate(ip);
    let a = asn_db().and_then(|d| d.lookup(ip)).filter(|a| a.asn > 0);
    if g.is_none() && a.is_none() {
        return Value::Null;
    }
    json!({
        "country": g.as_ref().map(|g| g.country_name.clone()), "country_code": g.as_ref().map(|g| g.country_code.clone()),
        "city": g.as_ref().and_then(|g| g.city.clone()), "asn": a.as_ref().map(|a| a.asn), "org": a.as_ref().map(|a| a.org.clone()),
    })
}

#[derive(Default)]
struct Country {
    name: String,
    lat: f64,
    lon: f64,
    count: u64,
    ips: Vec<String>,
    ip_count: u64,
    tags: HashMap<String, u64>,
}

/// One located indicator: its IP, how often it was seen, and what it was seen doing.
pub struct Seen {
    pub ip: String,
    pub count: u64,
    pub tags: Vec<(String, u64)>,
}

/// Groups located IPs by country (biggest first); unlocatable ones are left out.
pub fn rollup(seen: Vec<Seen>, locate: impl Fn(&str) -> Option<GeoInfo>, top: usize) -> Vec<Value> {
    let mut by: HashMap<String, Country> = HashMap::new();
    for s in seen {
        let Some(g) = locate(&s.ip) else { continue };
        let c = by.entry(g.country_code.clone()).or_insert_with(|| Country { name: g.country_name.clone(), lat: g.latitude.unwrap_or(0.0), lon: g.longitude.unwrap_or(0.0), ..Default::default() });
        c.count += s.count;
        c.ip_count += 1;
        if c.ips.len() < IPS_PER_COUNTRY {
            c.ips.push(s.ip);
        }
        for (t, n) in s.tags {
            *c.tags.entry(t).or_default() += n;
        }
    }
    let mut out: Vec<(String, Country)> = by.into_iter().collect();
    out.sort_by(|a, b| b.1.count.cmp(&a.1.count).then(a.0.cmp(&b.0)));
    out.truncate(top);
    out.into_iter()
        .map(|(code, c)| {
            let mut tags: Vec<(String, u64)> = c.tags.into_iter().collect();
            tags.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
            json!({
                "country": c.name, "code": code, "lat": c.lat, "lon": c.lon,
                "count": c.count, "hit_count": c.count, "ip_count": c.ip_count, "ips": c.ips,
                "attacks": tags.into_iter().take(6).map(|(t, n)| json!({ "tag": t, "count": n })).collect::<Vec<_>>(),
            })
        })
        .collect()
}

/// The public source IPs of a tenant's alerts in the window, with what they did.
async fn alert_sources(state: &AppState, tenant: &str, since_ms: u64) -> Vec<(String, String, u64)> {
    state
        .db
        .tenant_client(tenant)
        .query(
            "SELECT src_ip, if(mitre_tactic != '', mitre_tactic, rule_description) AS tag, count() AS n FROM siem_alerts \
             WHERE timestamp >= ? AND src_ip != '' GROUP BY src_ip, tag ORDER BY n DESC LIMIT 20000",
        )
        .bind(since_ms)
        .fetch_all::<(String, String, u64)>()
        .await
        .unwrap_or_default()
}

fn by_ip(rows: Vec<(String, String, u64)>) -> Vec<Seen> {
    let mut m: HashMap<String, Seen> = HashMap::new();
    for (ip, tag, n) in rows {
        if !ip.parse::<IpAddr>().is_ok_and(provigil_common::soar::is_public) {
            continue;
        }
        let s = m.entry(ip.clone()).or_insert(Seen { ip, count: 0, tags: Vec::new() });
        s.count += n;
        s.tags.push((tag, n));
    }
    m.into_values().collect()
}

fn since_ms() -> u64 {
    (chrono::Utc::now().timestamp_millis().max(0) as u64).saturating_sub(crate::history::DEFAULT_HOURS as u64 * 3_600_000)
}

/// `GET /api/threat-map`: the caller's tenant.
pub async fn threat_map(State(state): State<AppState>, Extension(ctx): Extension<AuthCtx>) -> Json<Value> {
    let rows = alert_sources(&state, &ctx.scope(), since_ms()).await;
    Json(json!({ "countries": rollup(by_ip(rows), locate, TOP_COUNTRIES), "window_hours": crate::history::DEFAULT_HOURS }))
}

/// `GET /api/admin/threat-map-all-tenants` (super admin): every tenant together.
pub async fn threat_map_all_tenants(State(state): State<AppState>, Extension(ctx): Extension<AuthCtx>) -> axum::response::Response {
    if !ctx.is_super() {
        return (StatusCode::FORBIDDEN, Json(json!({ "status": "error", "message": "Platform admins only" }))).into_response();
    }
    let since = since_ms();
    let mut rows = Vec::new();
    for t in crate::predictions::tenant_ids(&state) {
        rows.extend(alert_sources(&state, &t, since).await);
    }
    Json(json!({ "countries": rollup(by_ip(rows), locate, TOP_COUNTRIES), "window_hours": crate::history::DEFAULT_HOURS })).into_response()
}

/// `GET /api/threat-intel-map`: the feeds' listed IPs (and each listed range's first
/// address) by country; `attacks` = which feeds list them.
pub async fn threat_intel_map() -> Json<Value> {
    let mut seen: Vec<Seen> = crate::intel::listed_ips().into_iter().map(|(ip, source)| Seen { ip: ip.to_string(), count: 1, tags: vec![(source, 1)] }).collect();
    seen.extend(crate::intel::listed_ranges().into_iter().filter_map(|(range, source)| {
        let net = range.split('/').next()?.to_string();
        Some(Seen { ip: net, count: 1, tags: vec![(format!("{source} (ranges)"), 1)] })
    }));
    Json(json!({ "countries": rollup(seen, locate, usize::MAX) }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(code: &str, name: &str) -> Option<GeoInfo> {
        Some(GeoInfo { country_code: code.into(), country_name: name.into(), city: None, latitude: Some(1.0), longitude: Some(2.0) })
    }

    #[test]
    fn rollup_by_country() {
        let fake = |ip: &str| match ip {
            "45.1.1.1" | "45.1.1.2" => at("RU", "Russia"),
            "8.8.8.8" => at("US", "United States"),
            _ => None,
        };
        let seen = vec![
            Seen { ip: "45.1.1.1".into(), count: 5, tags: vec![("Credential Access".into(), 5)] },
            Seen { ip: "45.1.1.2".into(), count: 2, tags: vec![("Credential Access".into(), 1), ("Discovery".into(), 1)] },
            Seen { ip: "8.8.8.8".into(), count: 3, tags: vec![("Discovery".into(), 3)] },
            Seen { ip: "203.0.113.1".into(), count: 9, tags: vec![] },
        ];
        let c = rollup(seen, fake, 15);
        assert_eq!(c.len(), 2, "the unlocatable IP is left out");
        assert_eq!((c[0]["code"].as_str(), c[0]["count"].as_u64(), c[0]["ip_count"].as_u64()), (Some("RU"), Some(7), Some(2)));
        assert_eq!(c[0]["attacks"][0], json!({ "tag": "Credential Access", "count": 6 }));
        assert_eq!(c[1]["code"], "US");
        assert_eq!(rollup(vec![Seen { ip: "45.1.1.1".into(), count: 1, tags: vec![] }], fake, 0).len(), 0);
    }

    #[test]
    fn only_public_sources() {
        let s = by_ip(vec![("10.0.0.5".into(), "x".into(), 4), ("45.1.1.1".into(), "a".into(), 2), ("45.1.1.1".into(), "b".into(), 1)]);
        assert_eq!(s.len(), 1);
        assert_eq!((s[0].count, s[0].tags.len()), (3, 2));
    }
}
