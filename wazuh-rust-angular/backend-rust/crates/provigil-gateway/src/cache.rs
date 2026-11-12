//! Keys, registry, tenant keys and tenants: in memory, refreshed from ClickHouse. siem-api writes
//! them; here they are only read. A key is found by its hash, so the bearer alone identifies the
//! agent, and then compared in full in constant time.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering::Relaxed};
use std::sync::{Arc, RwLock};

use clickhouse::{Client, Row};
use provigil_agent_server::keys;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use tracing::{info, warn};

type Hash = [u8; 32];

fn hash(k: &str) -> Hash {
    Sha256::digest(k.trim().as_bytes()).into()
}

/// A write may commit after a later one was read: the last seconds are read again.
const OVERLAP_MS: u64 = 10_000;

#[derive(Row, Deserialize)]
struct KeyRow {
    agent_id: String,
    key_enc: String,
    deleted: u8,
    updated_at: u64,
}

#[derive(Row, Deserialize)]
struct RegistryRow {
    agent_id: String,
    name: String,
    tenant_id: String,
    groups: String,
    os_type: String,
    deleted: u8,
    #[allow(dead_code)]
    enrolled_at: u64,
    updated_at: u64,
    disabled: u8,
}

#[derive(Row, Deserialize)]
struct TenantKeyRow {
    tenant_id: String,
    agent_key: String,
    #[allow(dead_code)]
    created_at: u64,
}

/// A deployment token (siem-api `deploy_tokens.rs`): only its hash is stored.
#[derive(Row, Deserialize)]
struct DeployTokenRow {
    token_hash: String,
    tenant_id: String,
    expires_at: u64,
    revoked: u8,
}

/// A deployment token's tenant and whether it may still enroll new agents.
#[derive(Clone, Debug)]
struct DeployToken {
    tenant: String,
    expires_at: u64,
    revoked: bool,
}

#[derive(Row, Deserialize)]
struct TenantRow {
    id: String,
    active: u8,
}

#[derive(Debug)]
pub struct Key {
    pub id: String,
    pub key: String,
    /// `any`, an address or a network.
    pub allow: String,
}

#[derive(Debug, Clone, Default)]
pub struct Registered {
    pub name: String,
    pub tenant: String,
    pub groups: String,
    pub os_type: String,
    pub deleted: bool,
    pub disabled: bool,
}

#[derive(Default)]
struct Inner {
    by_hash: HashMap<Hash, Arc<Key>>,
    hash_of: HashMap<String, Hash>,
    registry: HashMap<String, Arc<Registered>>,
    /// Hash of the key -> (key, tenant).
    tenant_keys: HashMap<Hash, (String, String)>,
    /// Hex SHA-256 of a deployment token -> its tenant and state.
    deploy_tokens: HashMap<String, DeployToken>,
    inactive: HashSet<String>,
}

#[derive(Default)]
pub struct Cache {
    inner: RwLock<Inner>,
    keys_mark: AtomicU64,
    registry_mark: AtomicU64,
    pub ready: AtomicBool,
    pub last_poll_ms: AtomicU64,
}

/// An agent whose headers passed.
#[derive(Debug, Clone)]
pub struct Authed {
    pub id: String,
    pub tenant: String,
    pub reg: Arc<Registered>,
}

fn normalize(t: &str) -> String {
    if t.is_empty() || t == "global" {
        "default".to_string()
    } else {
        t.to_string()
    }
}

fn same_id(a: &str, b: &str) -> bool {
    a == b || matches!((a.parse::<u32>(), b.parse::<u32>()), (Ok(x), Ok(y)) if x == y)
}

/// Whether `peer` is inside `allow` (`any`, `a.b.c.d`, `a.b.c.d/n`, or an IPv6 address).
pub fn allowed(allow: &str, peer: IpAddr) -> bool {
    if matches!(allow, "any" | "0.0.0.0/0" | "::/0") {
        return true;
    }
    let peer = peer.to_canonical();
    let (net, bits) = allow.split_once('/').map_or((allow, None), |(n, b)| (n, b.parse::<u32>().ok()));
    match (net.parse::<IpAddr>(), peer) {
        (Ok(IpAddr::V4(n)), IpAddr::V4(p)) => {
            let bits = bits.unwrap_or(32).min(32);
            let mask = if bits == 0 { 0 } else { u32::MAX << (32 - bits) };
            u32::from(n) & mask == u32::from(p) & mask
        }
        (Ok(IpAddr::V6(n)), IpAddr::V6(p)) => {
            let bits = bits.unwrap_or(128).min(128);
            let mask = if bits == 0 { 0 } else { u128::MAX << (128 - bits) };
            u128::from(n) & mask == u128::from(p) & mask
        }
        // a value that is not understood lets nobody in
        _ => false,
    }
}

impl Cache {
    /// The checks of `specs/provigil-gateway.md` 3.7, in order, on headers only: the status when
    /// refused. `claimed`: the id in `x-agent-id` or the path.
    pub fn check(&self, key: Option<&str>, claimed: Option<&str>, tenant_key: Option<&str>, peer: IpAddr) -> Result<Authed, u16> {
        let c = self.inner.read().unwrap();
        let found = key.and_then(|k| c.by_hash.get(&hash(k)).filter(|e| keys::ct_eq(k.trim().as_bytes(), e.key.as_bytes())));
        let Some(entry) = found else {
            // a removed agent's key row is gone: its id says so, and the agent enrolls again
            return Err(if claimed.is_some_and(|i| c.registry.get(i).is_some_and(|r| r.deleted)) { 404 } else { 401 });
        };
        if claimed.is_some_and(|i| !same_id(i, &entry.id)) {
            return Err(401);
        }
        let reg = c.registry.get(&entry.id).cloned().unwrap_or_default();
        if reg.deleted {
            return Err(404);
        }
        if reg.disabled {
            return Err(410);
        }
        if !allowed(&entry.allow, peer) {
            return Err(401);
        }
        let keyed = match tenant_key.map(str::trim).filter(|k| !k.is_empty()) {
            Some(k) => Some(c.tenant_for(k).ok_or(401u16)?),
            None => None,
        };
        if keyed.as_ref().is_some_and(|t| c.inactive.contains(t)) {
            return Err(403);
        }
        let tenant = normalize(&reg.tenant);
        let tenant = match keyed {
            // an agent id belongs to one tenant: another tenant's key cannot take it over
            Some(k) if !reg.tenant.is_empty() && k != tenant => return Err(409),
            Some(k) if reg.tenant.is_empty() => k,
            _ => tenant,
        };
        Ok(Authed { id: entry.id.clone(), tenant, reg })
    }

    /// The tenant of an enrollment's key; the status when refused.
    pub fn tenant_of_key(&self, tenant_key: Option<&str>) -> Result<String, u16> {
        let c = self.inner.read().unwrap();
        let k = tenant_key.map(str::trim).filter(|k| !k.is_empty()).ok_or(401u16)?;
        // a deployment token enrolls new agents only while it is valid (siem-api checks its count)
        let now = chrono::Utc::now().timestamp_millis().max(0) as u64;
        if let Some(d) = c.deploy_tokens.get(&hex_hash(k)) {
            if d.revoked || d.expires_at <= now {
                return Err(401);
            }
        }
        let t = c.tenant_for(k).ok_or(401u16)?;
        if c.inactive.contains(&t) {
            return Err(403);
        }
        Ok(t)
    }

    /// Whether a key is a known deployment token, whatever its state (a run's results may come
    /// after it expired or was revoked).
    pub fn is_deploy_token(&self, k: &str) -> bool {
        self.inner.read().unwrap().deploy_tokens.contains_key(&hex_hash(k.trim()))
    }

    /// An enrollment that passed through here, ahead of the next poll. Only for the time until
    /// that poll: the rows in ClickHouse are the master copy.
    pub fn learn(&self, id: &str, key: &str, reg: Registered) {
        let mut c = self.inner.write().unwrap();
        let h = hash(key);
        if let Some(old) = c.hash_of.insert(id.to_string(), h) {
            c.by_hash.remove(&old);
        }
        c.by_hash.insert(h, Arc::new(Key { id: id.to_string(), key: key.trim().to_string(), allow: "any".to_string() }));
        c.registry.insert(id.to_string(), Arc::new(reg));
    }

    pub fn registered(&self, id: &str) -> Option<Arc<Registered>> {
        self.inner.read().unwrap().registry.get(id).cloned()
    }

    /// (keys, registry rows, tenant keys, inactive tenants)
    pub fn sizes(&self) -> (usize, usize, usize, usize) {
        let c = self.inner.read().unwrap();
        (c.by_hash.len(), c.registry.len(), c.tenant_keys.len(), c.inactive.len())
    }

    /// Reads what changed; the agents whose key changed, whose per-agent caches must go.
    pub async fn poll(&self, db: &Client, cipher: &keys::Cipher) -> Result<Vec<String>, clickhouse::error::Error> {
        let since = |m: &AtomicU64| m.load(Relaxed).saturating_sub(OVERLAP_MS);
        let key_rows: Vec<KeyRow> = db.query("SELECT ?fields FROM agent_keys FINAL WHERE updated_at >= ?").bind(since(&self.keys_mark)).fetch_all().await?;
        let reg_rows: Vec<RegistryRow> = db.query("SELECT ?fields FROM agent_registry FINAL WHERE updated_at >= ?").bind(since(&self.registry_mark)).fetch_all().await?;
        // few rows: read whole, so a rotated key or a tenant switched off counts within a poll
        let tk: Vec<TenantKeyRow> = db.query("SELECT ?fields FROM tenant_agent_keys FINAL").fetch_all().await?;
        let tenants: Vec<TenantRow> = db.query("SELECT id, active FROM ndr.tenants FINAL").fetch_all().await?;
        // missing until siem-api created it: no tokens then
        let tokens: Vec<DeployTokenRow> = db.query("SELECT token_hash, tenant_id, expires_at, revoked FROM deploy_tokens FINAL").fetch_all().await.unwrap_or_default();

        let mut changed = Vec::new();
        let decoded: Vec<(KeyRow, Option<String>)> = key_rows
            .into_iter()
            .map(|r| {
                let line = (r.deleted == 0).then(|| keys::decrypt(cipher, &r.key_enc)).flatten();
                if r.deleted == 0 && line.is_none() {
                    warn!("agent_keys: cannot decrypt the key of agent {} (AGENT_KEYS_SECRET changed?)", r.agent_id);
                }
                (r, line)
            })
            .collect();
        let mut c = self.inner.write().unwrap();
        for (r, line) in decoded {
            self.keys_mark.fetch_max(r.updated_at, Relaxed);
            let parsed = line.as_deref().and_then(keys::parse_line);
            let new_hash = parsed.map(|(_, _, k)| hash(k));
            let old = c.hash_of.get(&r.agent_id).copied();
            if old == new_hash {
                continue;
            }
            if let Some(h) = old {
                c.by_hash.remove(&h);
                c.hash_of.remove(&r.agent_id);
            }
            if let Some((_, allow, key)) = parsed {
                let h = hash(key);
                c.by_hash.insert(h, Arc::new(Key { id: r.agent_id.clone(), key: key.trim().to_string(), allow: allow.to_string() }));
                c.hash_of.insert(r.agent_id.clone(), h);
            }
            changed.push(r.agent_id);
        }
        for r in reg_rows {
            self.registry_mark.fetch_max(r.updated_at, Relaxed);
            let reg = Registered { name: r.name, tenant: r.tenant_id, groups: r.groups, os_type: r.os_type, deleted: r.deleted != 0, disabled: r.disabled != 0 };
            c.registry.insert(r.agent_id, Arc::new(reg));
        }
        c.tenant_keys = tk.into_iter().map(|r| (hash(&r.agent_key), (r.agent_key, normalize(&r.tenant_id)))).collect();
        c.inactive = tenants.into_iter().filter(|t| t.active == 0).map(|t| t.id).collect();
        c.deploy_tokens = tokens.into_iter().map(|r| (r.token_hash.to_ascii_lowercase(), DeployToken { tenant: normalize(&r.tenant_id), expires_at: r.expires_at, revoked: r.revoked != 0 })).collect();
        if !self.ready.swap(true, Relaxed) {
            info!("Caches loaded: {} keys, {} registry rows, {} tenant keys", c.by_hash.len(), c.registry.len(), c.tenant_keys.len());
        }
        Ok(changed)
    }
}

impl Inner {
    /// The tenant of a tenant key or of a deployment token, valid or not: agents keep sending the
    /// token they enrolled with, and an expired or revoked token must not cut them off.
    fn tenant_for(&self, key: &str) -> Option<String> {
        self.tenant_keys
            .get(&hash(key))
            .filter(|(k, _)| keys::ct_eq(k.as_bytes(), key.as_bytes()))
            .map(|(_, t)| t.clone())
            .or_else(|| self.deploy_tokens.get(&hex_hash(key)).map(|d| d.tenant.clone()))
    }
}

fn hex_hash(k: &str) -> String {
    hash(k).iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cache() -> Cache {
        let c = Cache::default();
        {
            let mut i = c.inner.write().unwrap();
            let mut add = |id: &str, key: &str, allow: &str, reg: Registered| {
                let h = hash(key);
                i.by_hash.insert(h, Arc::new(Key { id: id.into(), key: key.into(), allow: allow.into() }));
                i.hash_of.insert(id.into(), h);
                i.registry.insert(id.into(), Arc::new(reg));
            };
            let t = |t: &str| Registered { tenant: t.into(), name: "pc".into(), ..Default::default() };
            add("001", "k1", "any", t("acme"));
            add("002", "k2", "any", Registered { disabled: true, ..t("acme") });
            add("003", "k3", "10.1.0.0/16", t("acme"));
            add("004", "k4", "any", t("off"));
            i.registry.insert("009".into(), Arc::new(Registered { deleted: true, ..t("acme") }));
            i.tenant_keys.insert(hash("tk-acme"), ("tk-acme".into(), "acme".into()));
            i.tenant_keys.insert(hash("tk-other"), ("tk-other".into(), "other".into()));
            i.tenant_keys.insert(hash("tk-off"), ("tk-off".into(), "off".into()));
            i.inactive.insert("off".into());
            let tok = |tenant: &str, expires_at: u64, revoked: bool| DeployToken { tenant: tenant.into(), expires_at, revoked };
            i.deploy_tokens.insert(hex_hash("pvd_live"), tok("acme", u64::MAX, false));
            i.deploy_tokens.insert(hex_hash("pvd_old"), tok("acme", 1, false));
            i.deploy_tokens.insert(hex_hash("pvd_gone"), tok("acme", u64::MAX, true));
        }
        c
    }

    #[test]
    fn deployment_tokens_enroll_only_while_valid_but_keep_enrolled_agents() {
        let c = cache();
        assert_eq!(c.tenant_of_key(Some("pvd_live")).unwrap(), "acme");
        assert_eq!(c.tenant_of_key(Some("pvd_old")).unwrap_err(), 401, "expired");
        assert_eq!(c.tenant_of_key(Some("pvd_gone")).unwrap_err(), 401, "revoked");
        let peer: IpAddr = "10.1.2.3".parse().unwrap();
        // agent 001 (acme) still sends the token it enrolled with
        assert_eq!(c.check(Some("k1"), Some("001"), Some("pvd_old"), peer).unwrap().tenant, "acme");
        assert_eq!(c.check(Some("k1"), Some("001"), Some("pvd_gone"), peer).unwrap().tenant, "acme");
        assert_eq!(c.check(Some("k1"), Some("001"), Some("pvd_unknown"), peer).unwrap_err(), 401);
        assert!(c.is_deploy_token(" pvd_gone") && !c.is_deploy_token("pvd_unknown") && !c.is_deploy_token("tk-acme"));
    }

    const PEER: IpAddr = IpAddr::V4(std::net::Ipv4Addr::new(10, 1, 2, 3));

    #[test]
    fn checks_in_order() {
        let c = cache();
        let code = |k, id, tk| c.check(k, id, tk, PEER).map(|a| a.tenant).unwrap_err();
        assert_eq!(c.check(Some("k1"), Some("001"), Some("tk-acme"), PEER).unwrap().tenant, "acme");
        assert_eq!(c.check(Some("k1"), None, None, PEER).unwrap().id, "001", "the key says who");
        assert_eq!(c.check(Some("k1"), Some("1"), None, PEER).unwrap().id, "001");
        assert_eq!(code(None, Some("001"), None), 401);
        assert_eq!(code(Some("wrong"), Some("001"), None), 401);
        assert_eq!(code(Some("k1"), Some("003"), None), 401, "another agent's id");
        assert_eq!(code(Some("wrong"), Some("777"), None), 401, "an id with no key");
        assert_eq!(code(None, Some("777"), None), 401);
        assert_eq!(code(Some("k9"), Some("009"), None), 404, "removed");
        assert_eq!(code(Some("k2"), Some("002"), None), 410, "deactivated");
        assert_eq!(code(Some("k1"), Some("001"), Some("nope")), 401, "unknown tenant key");
        assert_eq!(code(Some("k4"), Some("004"), Some("tk-off")), 403, "inactive tenant");
        assert_eq!(code(Some("k1"), Some("001"), Some("tk-other")), 409, "another tenant's key");
    }

    #[test]
    fn network_restricted_keys() {
        let c = cache();
        assert!(c.check(Some("k3"), None, None, PEER).is_ok());
        assert_eq!(c.check(Some("k3"), None, None, "10.2.0.1".parse().unwrap()).unwrap_err(), 401);
        assert!(allowed("10.1.2.3", PEER) && !allowed("10.1.2.4", PEER));
        assert!(allowed("any", PEER) && allowed("10.1.2.3", "::ffff:10.1.2.3".parse().unwrap()));
        assert!(!allowed("nonsense", PEER), "not understood: nobody");
    }

    #[test]
    fn enrollment_needs_a_live_tenant_key() {
        let c = cache();
        assert_eq!(c.tenant_of_key(Some("tk-acme")).unwrap(), "acme");
        assert_eq!(c.tenant_of_key(None).unwrap_err(), 401);
        assert_eq!(c.tenant_of_key(Some("")).unwrap_err(), 401);
        assert_eq!(c.tenant_of_key(Some("nope")).unwrap_err(), 401);
        assert_eq!(c.tenant_of_key(Some("tk-off")).unwrap_err(), 403);
    }
}
