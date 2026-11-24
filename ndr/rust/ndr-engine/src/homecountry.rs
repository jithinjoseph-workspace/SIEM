//! A tenant's own country is not a "sensitive country".
//!
//! Traffic to a listed country adds +30 to an alert's score. The default list includes IN, so an
//! India-based tenant's ordinary traffic (its ISP's DNS server, local sites) became MEDIUM alerts.
//! Two problems are fixed here:
//!
//! 1. The tenant's editable "Sensitive Countries" setting was applied by two paths of the consumer
//!    but NOT by the main correlated-alert path (api::process_hit), which always used the built-in
//!    list, so editing the setting did not stop those alerts. `apply` is now used by all three.
//! 2. The countries the tenant's own sensors connect from ("home countries") are never counted as
//!    sensitive, even when they are on the list. They are learned from the address each sensor
//!    checks in from (X-Real-IP, set by nginx), looked up in the local GeoIP database.

use std::collections::HashSet;
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::{Arc, LazyLock};
use std::time::{Duration, Instant};

use axum::http::HeaderMap;
use dashmap::DashMap;
use redis::aio::MultiplexedConnection;

use crate::api::AppState;
use crate::enrichment::{EnrichmentData, GeoIpLookup, SENSITIVE_COUNTRIES};

const SENSOR_IP_TTL_SECS: usize = 7 * 24 * 3600;
const CACHE: Duration = Duration::from_secs(600);
const LIST_CACHE: Duration = Duration::from_secs(60);

static HOME: LazyLock<DashMap<String, (Instant, Arc<HashSet<String>>)>> = LazyLock::new(DashMap::new);
static LISTS: LazyLock<DashMap<String, (Instant, Arc<Vec<String>>)>> = LazyLock::new(DashMap::new);

fn redis_key(tenant: &str) -> String { format!("ndr:sensor_pubip:{tenant}") }

/// The address a sensor's request really came from: nginx sets X-Real-IP to the client (after its
/// real_ip handling of X-Forwarded-For); fall back to the first X-Forwarded-For entry.
pub fn client_ip(headers: &HeaderMap) -> Option<IpAddr> {
    let real = headers.get("x-real-ip").and_then(|v| v.to_str().ok()).map(str::trim);
    let fwd  = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(',').next()).map(str::trim);
    [real, fwd].into_iter().flatten().find_map(|s| IpAddr::from_str(s).ok())
}

/// Remember the public address `sensor_id` last checked in from. Private, loopback and link-local
/// addresses (Docker bridge, tunnel hops) say nothing about a country and are ignored.
pub async fn record_sensor_ip(redis: &mut MultiplexedConnection, tenant: &str, sensor_id: &str, ip: IpAddr) {
    if crate::enrichment::is_private_ip(&ip.to_string()) || ip.is_loopback() { return; }
    let key = redis_key(tenant);
    let _: Result<i64, _> = redis::cmd("HSET").arg(&key).arg(sensor_id).arg(ip.to_string()).query_async(redis).await;
    let _: Result<i64, _> = redis::cmd("EXPIRE").arg(&key).arg(SENSOR_IP_TTL_SECS).query_async(redis).await;
}

/// Country codes of a set of addresses, using the local GeoIP database.
pub fn countries_of<'a>(geo: &Option<GeoIpLookup>, ips: impl Iterator<Item = &'a str>) -> HashSet<String> {
    let Some(geo) = geo.as_ref() else { return HashSet::new() };
    ips.filter_map(|ip| geo.lookup(ip)).map(|g| g.country_code).filter(|c| !c.is_empty()).collect()
}

/// Sensitive means: on the tenant's list, involved in this flow, and not one of the tenant's own countries.
pub fn is_sensitive(list: &[String], src_cc: &str, dst_cc: &str, home: &HashSet<String>) -> bool {
    list.iter().any(|c| (c == src_cc || c == dst_cc) && !c.is_empty() && !home.contains(c))
}

/// The countries this tenant's sensors connect from (cached 10 min).
pub async fn home_countries(state: &AppState, tenant: &str) -> Arc<HashSet<String>> {
    if let Some(e) = HOME.get(tenant) {
        if e.0.elapsed() < CACHE { return e.1.clone(); }
    }
    let mut rc = state.redis_mux.clone();
    let ips: Vec<String> = redis::cmd("HVALS").arg(redis_key(tenant)).query_async(&mut rc).await.unwrap_or_default();
    let set = Arc::new(countries_of(&state.enrichment.geoip, ips.iter().map(String::as_str)));
    HOME.insert(tenant.to_string(), (Instant::now(), set.clone()));
    set
}

/// The tenant's "Sensitive Countries" setting, or the built-in list when it has none (cached 60 s).
pub async fn sensitive_list(state: &AppState, tenant: &str) -> Arc<Vec<String>> {
    if let Some(e) = LISTS.get(tenant) {
        if e.0.elapsed() < LIST_CACHE { return e.1.clone(); }
    }
    let configured = state.ch_storage.get_settings_by_tenant(tenant).await.ok()
        .and_then(|s| s["sensitive_countries"].as_str().map(str::to_string));
    let list: Vec<String> = match configured {
        Some(csv) => csv.split(',').map(|c| c.trim().to_string()).filter(|c| !c.is_empty()).collect(),
        None      => SENSITIVE_COUNTRIES.iter().map(|c| c.to_string()).collect(),
    };
    let list = Arc::new(list);
    LISTS.insert(tenant.to_string(), (Instant::now(), list.clone()));
    list
}

/// Set `enrich.sensitive_country` from the tenant's list minus its home countries. Use this instead of
/// the built-in flag `EnrichmentPipeline::enrich` sets from the fixed default list.
pub async fn apply(state: &AppState, tenant: &str, enrich: &mut EnrichmentData) {
    let list = sensitive_list(state, tenant).await;
    let home = home_countries(state, tenant).await;
    let src = enrich.src_geo.as_ref().map(|g| g.country_code.as_str()).unwrap_or("");
    let dst = enrich.dst_geo.as_ref().map(|g| g.country_code.as_str()).unwrap_or("");
    enrich.sensitive_country = is_sensitive(&list, src, dst, &home);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set(v: &[&str]) -> HashSet<String> { v.iter().map(|s| s.to_string()).collect() }
    fn list(v: &[&str]) -> Vec<String> { v.iter().map(|s| s.to_string()).collect() }

    #[test]
    fn the_tenants_own_country_is_never_sensitive() {
        let l = list(&["CN", "IN", "RU"]);
        assert!(!is_sensitive(&l, "IN", "", &set(&["IN"])), "home country on the list: not sensitive");
        assert!(!is_sensitive(&l, "", "IN", &set(&["IN"])));
        assert!(is_sensitive(&l, "IN", "", &set(&[])), "no home learned yet: the list applies as before");
        assert!(is_sensitive(&l, "", "CN", &set(&["IN"])), "another listed country still counts");
        assert!(is_sensitive(&l, "IN", "CN", &set(&["IN"])), "a flow between home and a listed country still counts");
        assert!(!is_sensitive(&l, "US", "DE", &set(&["IN"])), "unlisted countries never count");
        assert!(!is_sensitive(&l, "", "", &set(&[])), "unknown country");
        assert!(!is_sensitive(&list(&[]), "CN", "", &set(&[])), "empty list");
    }

    #[test]
    fn the_client_address_is_taken_from_the_proxy_headers() {
        let mut h = HeaderMap::new();
        assert_eq!(client_ip(&h), None);
        h.insert("x-forwarded-for", "203.0.113.7, 10.0.0.1".parse().unwrap());
        assert_eq!(client_ip(&h), IpAddr::from_str("203.0.113.7").ok());
        h.insert("x-real-ip", "198.51.100.4".parse().unwrap());
        assert_eq!(client_ip(&h), IpAddr::from_str("198.51.100.4").ok(), "X-Real-IP wins");
        h.insert("x-real-ip", "not-an-ip".parse().unwrap());
        assert_eq!(client_ip(&h), IpAddr::from_str("203.0.113.7").ok(), "a bad value falls through");
    }

    // Real GeoLite2 database + real Redis. Run from the crate directory:
    //   cargo test -p ndr-engine homecountry -- --ignored
    #[tokio::test]
    #[ignore]
    async fn a_sensor_in_india_makes_india_a_home_country() {
        let geo = GeoIpLookup::open("data/GeoLite2-City.mmdb").ok();
        let url = std::env::var("TEST_REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379/5".into());
        let mut c = redis::Client::open(url).unwrap().get_multiplexed_async_connection().await.unwrap();
        let tenant = format!("hometest{}", std::process::id());
        let _: Result<i64, _> = redis::cmd("DEL").arg(redis_key(&tenant)).query_async(&mut c).await;

        record_sensor_ip(&mut c, &tenant, "S-1", IpAddr::from_str("103.160.195.230").unwrap()).await;
        record_sensor_ip(&mut c, &tenant, "S-2", IpAddr::from_str("172.18.0.1").unwrap()).await;   // docker hop
        record_sensor_ip(&mut c, &tenant, "S-3", IpAddr::from_str("127.0.0.1").unwrap()).await;    // loopback
        let ips: Vec<String> = redis::cmd("HVALS").arg(redis_key(&tenant)).query_async(&mut c).await.unwrap();
        assert_eq!(ips, vec!["103.160.195.230".to_string()], "only the public address is kept");

        let home = countries_of(&geo, ips.iter().map(String::as_str));
        assert!(home.contains("IN"), "103.160.195.230 is in India: {home:?}");
        assert!(!is_sensitive(&list(&["IN", "CN"]), "", "IN", &home), "the alert from your bug report: no longer sensitive");
        let _: Result<i64, _> = redis::cmd("DEL").arg(redis_key(&tenant)).query_async(&mut c).await;
    }
}
