//! Threat intel for the SIEM, from provigil-common:
//! * the collector (CISA KEV, Emerging Threats, Feodo, URLhaus, ThreatFox,
//!   Spamhaus DROP/EDROP; AbuseIPDB and OTX when `ABUSEIPDB_API_KEY` /
//!   `OTX_API_KEY` are set) into `siem_threat_intel`, every 6 hours, and an
//!   in-memory index of it (source and description per IOC);
//! * the `ThreatIntel` engine (Feodo, URLhaus, MalwareBazaar, JA3, Spamhaus
//!   ranges), refreshed hourly, for IPs inside listed ranges and hashes.
//!
//! Used by SOAR (`is_malicious`, so the decision engine's `intel.malicious`),
//! the Threat Intel page and the investigation. API: `/api/v1/siem/intel/*`.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::{OnceLock, RwLock};
use std::time::Duration;

use axum::extract::{Extension, Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use provigil_common::threat_intel::{collector, ThreatCollectorStore, ThreatIntel, ThreatIntelEntry};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::tenancy::AuthCtx;
use crate::AppState;

/// One feed entry an indicator matched.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Hit {
    pub source: String,
    pub kind: String,
    pub attack_type: String,
    pub severity: String,
    pub description: String,
}

#[derive(Default)]
struct Index {
    /// lower-case IOC value -> entries
    exact: HashMap<String, Vec<Hit>>,
    /// listed ranges (Spamhaus) from the table
    ranges: Vec<(String, Hit)>,
    loaded_at: u64,
}

fn index() -> &'static RwLock<Index> {
    static I: OnceLock<RwLock<Index>> = OnceLock::new();
    I.get_or_init(|| RwLock::new(Index::default()))
}

fn engine() -> &'static ThreatIntel {
    static E: OnceLock<ThreatIntel> = OnceLock::new();
    E.get_or_init(ThreatIntel::new)
}

fn now() -> u64 {
    chrono::Utc::now().timestamp().max(0) as u64
}

/// The address an IP indicator is about ("1.2.3.4:443" -> "1.2.3.4").
fn ip_of(v: &str) -> Option<IpAddr> {
    let v = v.trim();
    v.parse().ok().or_else(|| v.rsplit_once(':').and_then(|(h, p)| p.parse::<u16>().ok().and(h.trim_matches(['[', ']']).parse().ok())))
}

fn build(rows: Vec<(String, String, String, String, String, String)>) -> Index {
    let mut ix = Index { loaded_at: now(), ..Default::default() };
    for (source, attack_type, severity, kind, value, description) in rows {
        // Emerging Threats gives attack categories, not indicators
        if value.trim().is_empty() {
            continue;
        }
        let hit = Hit { source, kind: kind.clone(), attack_type, severity, description };
        if kind == "cidr" {
            ix.ranges.push((value, hit));
            continue;
        }
        let key = match kind.as_str() {
            "ip" | "ip:port" => ip_of(&value).map(|a| a.to_string()).unwrap_or_else(|| value.to_lowercase()),
            _ => value.trim().to_lowercase(),
        };
        let list = ix.exact.entry(key).or_default();
        if !list.iter().any(|h| h.source == hit.source) {
            list.push(hit);
        }
    }
    ix
}

async fn reload(state: &AppState) -> Result<usize, String> {
    let rows = state
        .db
        .tenant_client(crate::tenancy::DEFAULT_TENANT)
        .query("SELECT source, attack_type, severity, ioc_type, ioc_value, description FROM siem_threat_intel FINAL")
        .fetch_all::<(String, String, String, String, String, String)>()
        .await
        .map_err(|e| e.to_string())?;
    let ix = build(rows);
    let n = ix.exact.len() + ix.ranges.len();
    *index().write().unwrap() = ix;
    Ok(n)
}

/// What the feeds say about one indicator (IP, hash, domain, URL or CVE).
pub fn lookup(value: &str) -> Vec<Hit> {
    lookup_in(&index().read().unwrap(), value)
}

/// The feeds and the tenant's own watchlist.
pub fn lookup_for(tenant: &str, value: &str) -> Vec<Hit> {
    let mut hits = lookup(value);
    hits.extend(watch_hits(tenant, value));
    hits
}

fn lookup_in(ix: &Index, value: &str) -> Vec<Hit> {
    let v = value.trim();
    if v.is_empty() {
        return Vec::new();
    }
    let mut hits = Vec::new();
    match ip_of(v) {
        Some(ip) => {
            hits.extend(ix.exact.get(&ip.to_string()).cloned().unwrap_or_default());
            hits.extend(ix.ranges.iter().filter(|(r, _)| crate::decisions::in_range(ip, r)).map(|(r, h)| Hit { description: format!("{} (listed range {r})", h.description), ..h.clone() }));
            if hits.is_empty() && engine().is_malicious_ip(&ip.to_string()) {
                hits.push(Hit { source: "abuse.ch blocklist".into(), kind: "ip".into(), attack_type: "malicious_ip".into(), severity: "HIGH".into(), description: "On the abuse.ch / Spamhaus blocklists".into() });
            }
        }
        None => {
            let key = v.to_lowercase();
            hits.extend(ix.exact.get(&key).cloned().unwrap_or_default());
            let looks_hash = matches!(key.len(), 32 | 40 | 64) && key.chars().all(|c| c.is_ascii_hexdigit());
            if hits.is_empty() && looks_hash && engine().is_malicious_hash(&key) {
                hits.push(Hit { source: "MalwareBazaar".into(), kind: "hash".into(), attack_type: "malware".into(), severity: "HIGH".into(), description: "Known malware sample".into() });
            }
            if hits.is_empty() && !looks_hash && key.contains('.') && engine().is_malicious_domain(&key) {
                hits.push(Hit { source: "URLhaus".into(), kind: "domain".into(), attack_type: "malware_distribution".into(), severity: "HIGH".into(), description: "Domain serving malware".into() });
            }
        }
    }
    hits
}

/// Every listed IP address with the feed that lists it (the index, then the blocklists).
pub fn listed_ips() -> Vec<(IpAddr, String)> {
    let mut out: Vec<(IpAddr, String)> = index().read().unwrap().exact.iter().filter_map(|(k, h)| Some((k.parse().ok()?, h[0].source.clone()))).collect();
    let known: HashSet<IpAddr> = out.iter().map(|(ip, _)| *ip).collect();
    out.extend(engine().malicious_ips.iter().map(|ip| *ip).filter(|ip| !known.contains(ip)).map(|ip| (ip, "abuse.ch blocklist".to_string())));
    out
}

/// Every listed address range ("1.2.3.0/24") with its feed.
pub fn listed_ranges() -> Vec<(String, String)> {
    index().read().unwrap().ranges.iter().map(|(r, h)| (r.clone(), h.source.clone())).collect()
}

/// The indicators in a Wazuh alert: public source/destination IPs, file hashes, URL hosts.
pub fn indicators(alert: &Value) -> Vec<String> {
    let s = |v: &Value| v.as_str().map(str::trim).filter(|x| !x.is_empty()).map(String::from);
    let mut out = Vec::new();
    for v in [&alert["data"]["srcip"], &alert["data"]["dstip"], &alert["decoded"]["src_ip"], &alert["decoded"]["dst_ip"]] {
        if let Some(ip) = s(v).filter(|x| x.parse::<IpAddr>().is_ok_and(provigil_common::soar::is_public)) {
            out.push(ip);
        }
    }
    for v in [&alert["syscheck"]["sha256_after"], &alert["syscheck"]["sha1_after"], &alert["syscheck"]["md5_after"], &alert["data"]["virustotal"]["source"]["sha1"], &alert["data"]["virustotal"]["source"]["md5"]] {
        out.extend(s(v).map(|h| h.to_lowercase()));
    }
    if let Some(u) = s(&alert["data"]["url"]) {
        out.push(u.split("://").nth(1).unwrap_or(&u).split(['/', ':', '?']).next().unwrap_or("").to_lowercase());
    }
    out.retain(|x| !x.is_empty());
    out.sort();
    out.dedup();
    out
}

/// The alert's indicators that the feeds or its tenant's watchlist list.
pub fn alert_hits(alert: &Value) -> Vec<(String, Vec<Hit>)> {
    let tenant = alert["data"]["tenant_id"].as_str().unwrap_or(crate::tenancy::DEFAULT_TENANT);
    let ix = index().read().unwrap();
    indicators(alert)
        .into_iter()
        .map(|i| {
            let mut h = lookup_in(&ix, &i);
            h.extend(watch_hits(tenant, &i));
            (i, h)
        })
        .filter(|(_, h)| !h.is_empty())
        .collect()
}

// ───────────────────────── the tenant's watchlist ─────────────────────────

pub const WATCHLIST_DDL: &str = "CREATE TABLE IF NOT EXISTS siem_intel_watchlist (id String, doc String, version UInt64) ENGINE = ReplacingMergeTree(version) ORDER BY id";

/// An indicator the tenant's analysts listed themselves (closing a case, or on the Threat Intel page).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Watched {
    pub id: String,
    pub kind: String,
    pub value: String,
    pub group: String,
    pub added_by: String,
    pub added_at: u64,
}

fn watchlists() -> &'static RwLock<HashMap<String, Vec<Watched>>> {
    static W: OnceLock<RwLock<HashMap<String, Vec<Watched>>>> = OnceLock::new();
    W.get_or_init(Default::default)
}

/// How an indicator is compared: an IP in canonical form, anything else lower-case.
fn key_of(value: &str) -> String {
    ip_of(value).map(|a| a.to_string()).unwrap_or_else(|| value.trim().to_lowercase())
}

/// The kind of an indicator an analyst typed; None when it is none of them.
fn kind_of(value: &str) -> Option<&'static str> {
    let v = value.trim();
    if v.parse::<IpAddr>().is_ok() {
        return Some("ip");
    }
    if matches!(v.len(), 32 | 40 | 64) && v.chars().all(|c| c.is_ascii_hexdigit()) {
        return Some("hash");
    }
    let domain = v.contains('.') && !v.starts_with('.') && !v.ends_with('.') && v.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-');
    domain.then_some("domain")
}

fn watch_hits(tenant: &str, value: &str) -> Vec<Hit> {
    let k = key_of(value);
    watchlists()
        .read()
        .unwrap()
        .get(&crate::tenancy::normalize_tenant(tenant))
        .map(|l| {
            l.iter()
                .filter(|w| w.value == k)
                .map(|w| Hit {
                    source: "Analyst watchlist".into(),
                    kind: w.kind.clone(),
                    attack_type: if w.group.is_empty() { "watchlist".into() } else { w.group.clone() },
                    severity: "HIGH".into(),
                    description: format!("Listed by {}", w.added_by),
                })
                .collect()
        })
        .unwrap_or_default()
}

async fn load_watchlists(state: &AppState) {
    for t in crate::predictions::tenant_ids(state) {
        let list: Vec<Watched> = state.db.docs(&t, crate::db::DocTable::Watchlist, 100_000).await.unwrap_or_default().iter().filter_map(|d| serde_json::from_str(d).ok()).collect();
        watchlists().write().unwrap().insert(crate::tenancy::normalize_tenant(&t), list);
    }
}

fn bad(code: StatusCode, m: &str) -> Response {
    (code, Json(json!({ "status": "error", "message": m }))).into_response()
}

/// `GET /api/v1/siem/intel/watchlist`
pub async fn watchlist(Extension(ctx): Extension<AuthCtx>) -> Json<Value> {
    let mut l = watchlists().read().unwrap().get(&crate::tenancy::normalize_tenant(&ctx.scope())).cloned().unwrap_or_default();
    l.sort_by(|a, b| b.added_at.cmp(&a.added_at));
    Json(json!({ "status": "ok", "watchlist": l }))
}

#[derive(Deserialize)]
pub struct NewWatched {
    pub value: String,
    #[serde(default)]
    pub group: String,
}

/// `POST /api/v1/siem/intel/watchlist {value, group}`: an IP, file hash or domain.
pub async fn add_watched(State(state): State<AppState>, Extension(ctx): Extension<AuthCtx>, Json(b): Json<NewWatched>) -> Response {
    let value = b.value.trim();
    let Some(kind) = kind_of(value).filter(|_| value.len() <= 253) else {
        return bad(StatusCode::BAD_REQUEST, "Enter an IP address, a file hash (MD5 / SHA-1 / SHA-256) or a domain");
    };
    let tenant = crate::tenancy::normalize_tenant(&ctx.scope());
    let key = key_of(value);
    if watchlists().read().unwrap().get(&tenant).is_some_and(|l| l.iter().any(|w| w.value == key)) {
        return bad(StatusCode::CONFLICT, &format!("{key} is already on the watchlist"));
    }
    let w = Watched { id: uuid::Uuid::new_v4().to_string(), kind: kind.into(), value: key, group: b.group.trim().chars().take(80).collect(), added_by: ctx.username.clone(), added_at: now() };
    if let Err(e) = state.db.put_doc(&tenant, crate::db::DocTable::Watchlist, &w.id, &serde_json::to_string(&w).unwrap_or_default()).await {
        return bad(StatusCode::SERVICE_UNAVAILABLE, &format!("Could not save: {e}"));
    }
    watchlists().write().unwrap().entry(tenant).or_default().push(w.clone());
    Json(json!({ "status": "ok", "entry": w })).into_response()
}

/// `DELETE /api/v1/siem/intel/watchlist/:id`
pub async fn remove_watched(State(state): State<AppState>, Extension(ctx): Extension<AuthCtx>, Path(id): Path<String>) -> Response {
    let tenant = crate::tenancy::normalize_tenant(&ctx.scope());
    if !watchlists().read().unwrap().get(&tenant).is_some_and(|l| l.iter().any(|w| w.id == id)) {
        return bad(StatusCode::NOT_FOUND, "Not on the watchlist");
    }
    if let Err(e) = state.db.delete_doc(&tenant, crate::db::DocTable::Watchlist, &id).await {
        return bad(StatusCode::SERVICE_UNAVAILABLE, &format!("Could not remove: {e}"));
    }
    if let Some(l) = watchlists().write().unwrap().get_mut(&tenant) {
        l.retain(|w| w.id != id);
    }
    Json(json!({ "status": "ok" })).into_response()
}

// ───────────────────────── collection ─────────────────────────

struct Store(crate::db::ClickHouseDb);

#[async_trait::async_trait]
impl ThreatCollectorStore for Store {
    async fn fetch_existing_iocs(&self) -> HashSet<(String, String)> {
        self.0
            .tenant_client(crate::tenancy::DEFAULT_TENANT)
            .query("SELECT source, ioc_value FROM siem_threat_intel")
            .fetch_all::<(String, String)>()
            .await
            .unwrap_or_default()
            .into_iter()
            .collect()
    }

    async fn get_api_keys(&self) -> (String, String) {
        (std::env::var("ABUSEIPDB_API_KEY").unwrap_or_default(), std::env::var("OTX_API_KEY").unwrap_or_default())
    }

    async fn insert_ioc_entries(&self, existing: &HashSet<(String, String)>, entries: Vec<ThreatIntelEntry>) -> usize {
        let mut seen = HashSet::new();
        let new: Vec<ThreatIntelEntry> = entries.into_iter().filter(|e| !existing.contains(&(e.source.clone(), e.ioc_value.clone())) && seen.insert((e.source.clone(), e.ioc_value.clone()))).collect();
        self.0.insert_threat_intel_entries(&new).await
    }
}

/// Collection every 6 hours (first one 30 s after start), the engine hourly, and the index from what is stored.
pub fn spawn(state: AppState) {
    let s = state.clone();
    tokio::spawn(async move {
        load_watchlists(&s).await;
        let _ = reload(&s).await;
        tokio::time::sleep(Duration::from_secs(30)).await;
        loop {
            if s.db.is_connected() {
                collector::collect_all(&Store(s.db.clone())).await;
                match reload(&s).await {
                    Ok(n) => tracing::info!("threat intel: {n} indicators indexed"),
                    Err(e) => tracing::warn!("threat intel index not reloaded: {e}"),
                }
            }
            tokio::time::sleep(Duration::from_secs(6 * 3600)).await;
        }
    });
    let s2 = state.clone();
    tokio::spawn(async move {
        loop {
            engine().refresh().await;
            if s2.db.is_connected() {
                persist_malware_bazaar(&s2).await;
            }
            tokio::time::sleep(Duration::from_secs(3600)).await;
        }
    });
}

/// MalwareBazaar's hashes (the engine keeps only what it fetched since start) into
/// `siem_threat_intel` with the other feeds: kept over restarts, in the lookup index, 90 days.
async fn persist_malware_bazaar(state: &AppState) {
    let client = state.db.tenant_client(crate::tenancy::DEFAULT_TENANT);
    let known: HashSet<String> = client.query("SELECT ioc_value FROM siem_threat_intel WHERE ioc_type = 'hash'").fetch_all::<String>().await.unwrap_or_default().into_iter().collect();
    let today = chrono::Utc::now().format("%Y-%m-%d");
    let new: Vec<ThreatIntelEntry> = engine()
        .malicious_hashes
        .iter()
        .filter(|h| !known.contains(h.as_str()))
        .map(|h| ThreatIntelEntry {
            source: "malwarebazaar".into(),
            attack_type: "malware".into(),
            severity: "HIGH".into(),
            ioc_type: "hash".into(),
            ioc_value: h.clone(),
            description: "MalwareBazaar malware sample".into(),
            threat_pattern: format!("first_seen:{today}"),
        })
        .collect();
    let added = state.db.insert_threat_intel_entries(&new).await;
    let cutoff = (chrono::Utc::now() - chrono::Duration::days(90)).format("%Y-%m-%d");
    if let Err(e) = client.query("DELETE FROM siem_threat_intel WHERE source = 'malwarebazaar' AND threat_pattern < ?").bind(format!("first_seen:{cutoff}")).execute().await {
        tracing::warn!("MalwareBazaar samples older than 90 days not removed: {e}");
    }
    if added > 0 {
        tracing::info!("MalwareBazaar: {added} new hashes stored in ClickHouse");
        let _ = reload(state).await;
    }
}

// ───────────────────────── API ─────────────────────────

/// `GET /api/v1/siem/intel/status`: what the feeds hold.
pub async fn status(State(state): State<AppState>) -> Json<Value> {
    let feeds = state
        .db
        .tenant_client(crate::tenancy::DEFAULT_TENANT)
        .query("SELECT source, if(ioc_type = '', 'attack categories', ioc_type), count() FROM siem_threat_intel FINAL GROUP BY source, ioc_type ORDER BY source, ioc_type")
        .fetch_all::<(String, String, u64)>()
        .await
        .unwrap_or_default();
    let mut by: Vec<Value> = Vec::new();
    for (source, kind, n) in feeds {
        match by.iter_mut().find(|f| f["source"] == source) {
            Some(f) => f["types"][kind] = json!(n),
            None => by.push(json!({ "source": source, "types": { kind: n } })),
        }
    }
    let e = engine();
    let ix = index().read().unwrap();
    Json(json!({
        "status": "ok",
        "feeds": by,
        "indexed": ix.exact.len() + ix.ranges.len(),
        "indexed_at": ix.loaded_at,
        "blocklists": { "ips": e.ip_count(), "ranges": e.cidr_count(), "hashes": e.hash_count(), "domains": e.domain_count(), "ja3": e.ja3_count(), "refreshed": e.last_refreshed_at.load(std::sync::atomic::Ordering::Relaxed) },
    }))
}

#[derive(Deserialize)]
pub struct LookupQuery {
    pub q: String,
}

/// `GET /api/v1/siem/intel/lookup?q=`
pub async fn lookup_handler(Extension(ctx): Extension<AuthCtx>, Query(q): Query<LookupQuery>) -> Json<Value> {
    let v = q.q.trim().chars().take(512).collect::<String>();
    Json(json!({ "status": "ok", "q": v, "hits": lookup_for(&ctx.scope(), &v), "geo": crate::geomap::describe(&v) }))
}

#[derive(clickhouse::Row, Deserialize)]
struct IpRow {
    ip: String,
    alerts: u64,
    last: u64,
    max_level: u8,
    agents: Vec<String>,
}

/// `GET /api/v1/siem/intel/matches`: the tenant's alert IPs (last 24 h) that the feeds list.
pub async fn matches(State(state): State<AppState>, Extension(ctx): Extension<AuthCtx>) -> Json<Value> {
    let since = (chrono::Utc::now().timestamp_millis().max(0) as u64).saturating_sub(86_400_000);
    let rows = state
        .db
        .tenant_client(&ctx.scope())
        .query(
            "SELECT ip, count() AS alerts, max(timestamp) AS last, max(rule_level) AS max_level, groupUniqArray(10)(agent_name) AS agents \
             FROM (SELECT src_ip AS ip, timestamp, rule_level, agent_name FROM siem_alerts WHERE timestamp >= ? AND src_ip != '' \
                   UNION ALL SELECT dst_ip AS ip, timestamp, rule_level, agent_name FROM siem_alerts WHERE timestamp >= ? AND dst_ip != '') \
             GROUP BY ip ORDER BY alerts DESC LIMIT 5000",
        )
        .bind(since)
        .bind(since)
        .fetch_all::<IpRow>()
        .await
        .unwrap_or_default();
    let out: Vec<Value> = rows
        .into_iter()
        .filter(|r| r.ip.parse::<IpAddr>().is_ok_and(provigil_common::soar::is_public))
        .filter_map(|r| {
            let hits = lookup_for(&ctx.scope(), &r.ip);
            (!hits.is_empty()).then(|| json!({ "value": r.ip, "geo": crate::geomap::describe(&r.ip), "hits": hits, "alerts": r.alerts, "last_seen": r.last, "max_level": r.max_level, "agents": r.agents }))
        })
        .collect();
    Json(json!({ "status": "ok", "matches": out }))
}

#[cfg(test)]
mod watch_tests {
    use super::*;

    #[test]
    fn kinds_keys_and_tenant_scope() {
        assert_eq!((kind_of("203.0.113.9"), kind_of("2001:db8::1"), kind_of(&"a".repeat(64)), kind_of("evil.example.com")), (Some("ip"), Some("ip"), Some("hash"), Some("domain")));
        assert_eq!((kind_of("hello"), kind_of("a b.com"), kind_of(".com")), (None, None, None));
        assert_eq!(key_of(" Evil.Example.COM "), "evil.example.com");
        watchlists().write().unwrap().insert("t-watch".into(), vec![Watched { id: "1".into(), kind: "ip".into(), value: "203.0.113.9".into(), group: "apt-x".into(), added_by: "ana".into(), added_at: 0 }]);
        assert_eq!(watch_hits("t-watch", "203.0.113.9")[0].attack_type, "apt-x");
        assert!(watch_hits("other-tenant", "203.0.113.9").is_empty(), "a tenant's watchlist is its own");
        let alert = json!({ "data": { "tenant_id": "t-watch", "srcip": "203.0.113.9" } });
        assert_eq!(alert_hits(&alert).len(), 1);
    }
}

#[cfg(test)]
pub fn set_index_for_tests(rows: Vec<(String, String, String, String, String, String)>) {
    *index().write().unwrap() = build(rows);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(source: &str, kind: &str, value: &str) -> (String, String, String, String, String, String) {
        (source.into(), "c2".into(), "HIGH".into(), kind.into(), value.into(), format!("{source} {value}"))
    }

    #[test]
    fn index_and_lookups() {
        let ix = build(vec![row("feodo", "ip:port", "45.155.205.233:443"), row("threatfox", "ip", "45.155.205.233"), row("spamhaus", "cidr", "185.220.101.0/24"), row("urlhaus", "domain", "Evil.Example"), row("cisa_kev", "cve", "CVE-2024-3400")]);
        assert_eq!(ix.exact.get("45.155.205.233").map(|v| v.len()), Some(2), "ip:port and ip are one indicator, two sources");
        assert!(ix.exact.contains_key("evil.example") && ix.exact.contains_key("cve-2024-3400"));
        assert_eq!(lookup_in(&ix, "45.155.205.233").len(), 2);
        assert_eq!(lookup_in(&ix, "185.220.101.45")[0].source, "spamhaus", "inside a listed range");
        assert!(lookup_in(&ix, "8.8.8.8").is_empty());
        assert_eq!(lookup_in(&ix, "EVIL.example")[0].source, "urlhaus");
        assert_eq!(lookup_in(&ix, "cve-2024-3400").len(), 1);

        let alert = json!({ "data": { "srcip": "45.155.205.233", "dstip": "10.0.0.5", "url": "http://evil.example/x.exe" }, "syscheck": { "sha256_after": "" } });
        let mut want = vec!["45.155.205.233".to_string(), "evil.example".to_string()];
        want.sort();
        assert_eq!(indicators(&alert), want, "private IPs and empty fields are not indicators");
        assert_eq!(indicators(&alert).iter().filter(|i| !lookup_in(&ix, i).is_empty()).count(), 2);
    }
}
