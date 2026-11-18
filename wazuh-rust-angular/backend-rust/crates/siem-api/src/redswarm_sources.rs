//! Which logs each computer actually sends, for Red Swarm: a round the rules catch is only
//! Defended when the computer sends the log the attack shows up in (a Windows event channel, a
//! Linux program's lines). Read from the stored events of the last 7 days, every 10 minutes.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use crate::tenancy;
use crate::AppState;

const REFRESH: Duration = Duration::from_secs(10 * 60);

/// agent id -> the log sources it sent lately; None until the first read worked.
static SEEN: RwLock<Option<HashMap<String, HashSet<String>>>> = RwLock::new(None);

/// Whether the computer sent the log lately; None while not known (no read yet).
pub fn sent(agent_id: &str, source: &str) -> Option<bool> {
    let seen = SEEN.read().unwrap();
    Some(seen.as_ref()?.get(agent_id).is_some_and(|s| s.contains(source)))
}

/// The program of a syslog line (`Nov 18 10:00:01 host sshd[1]:`, or with an ISO time).
const PROGRAM: &str = "regexpExtract(message, '^[A-Za-z0-9:.+-]+( +[0-9]+ [0-9:]+)? [^ ]+ ([A-Za-z0-9_./-]+)[^A-Za-z0-9_./ -]', 2)";

async fn read(state: &AppState) -> Option<HashMap<String, HashSet<String>>> {
    let mut dbs: HashSet<String> = state.agent_tenants.read().unwrap().values().map(|t| tenancy::tenant_db_name(t)).collect();
    dbs.insert(tenancy::tenant_db_name(tenancy::DEFAULT_TENANT));
    let since = (chrono::Utc::now() - chrono::Duration::days(7)).timestamp_millis() as u64;
    let mut seen: HashMap<String, HashSet<String>> = HashMap::new();
    for db in dbs {
        let q = format!(
            "SELECT DISTINCT agent_id, if(location = 'EventChannel', JSONExtractString(message, 'win', 'system', 'channel'), {PROGRAM}) AS src \
             FROM `{db}`.siem_events WHERE timestamp > {since} AND src != ''"
        );
        match state.db.root().query(&q).fetch_all::<(String, String)>().await {
            Ok(rows) => rows.into_iter().for_each(|(a, s)| {
                seen.entry(a).or_default().insert(s);
            }),
            // a tenant without events yet has no table: nothing sent
            Err(e) if e.to_string().contains("UNKNOWN_TABLE") || e.to_string().contains("UNKNOWN_DATABASE") => {}
            Err(e) => {
                tracing::warn!("Red Swarm: log sources of {db} not read: {e}");
                return None;
            }
        }
    }
    Some(seen)
}

/// Reads the log sources now and every 10 minutes, and gives Red Swarm the check.
pub fn spawn(state: AppState) {
    if !state.db.is_connected() {
        return;
    }
    state.redswarm.set_source_check(Arc::new(sent));
    tokio::spawn(async move {
        loop {
            // a failed read keeps the last good one
            if let Some(s) = read(&state).await {
                tracing::info!("Red Swarm: log sources of {} computer(s) read", s.len());
                *SEEN.write().unwrap() = Some(s);
            }
            tokio::time::sleep(REFRESH).await;
        }
    });
}
