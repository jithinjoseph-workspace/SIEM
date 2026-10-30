//! The AI-learned log parsers (siem-parser-gen) in ClickHouse
//! (`<tenant db>.learned_parsers`, one row per parser) instead of
//! `data/learned_parsers.json`. The file of older installs is imported once.
//! Each tenant has its own parsers: they hold sample lines of its logs.

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;

use clickhouse::Row;
use serde::{Deserialize, Serialize};
use siem_parser_gen::{DynamicParser, DynamicParserRegistry};
use tracing::{info, warn};

use crate::db::ClickHouseDb;
use crate::tenancy::{self, DEFAULT_DB};
use crate::AppState;

pub const LEGACY_FILE: &str = "data/learned_parsers.json";

#[derive(Row, Serialize, Deserialize)]
struct ParserRow {
    id: String,
    parser: String,
    deleted: u8,
    updated_at: u64,
}

fn now_ms() -> u64 {
    chrono::Utc::now().timestamp_millis() as u64
}

async fn ensure_table(db: &ClickHouseDb, database: &str) -> bool {
    let q = format!(
        "CREATE TABLE IF NOT EXISTS `{database}`.learned_parsers (
            id String,
            parser String,
            deleted UInt8,
            updated_at UInt64
        ) ENGINE = ReplacingMergeTree(updated_at)
        ORDER BY id"
    );
    match db.root().query(&q).execute().await {
        Ok(()) => true,
        Err(e) => {
            warn!("learned_parsers: {e}");
            false
        }
    }
}

/// Loads the stored parsers into the registry (importing the legacy file
/// when the table is empty); returns the ids stored in ClickHouse.
pub async fn load(db: &ClickHouseDb, registry: &DynamicParserRegistry, database: &str) -> Option<BTreeSet<String>> {
    if !db.is_connected() || !ensure_table(db, database).await {
        return None;
    }
    let rows = match db
        .root()
        .query(&format!("SELECT ?fields FROM `{database}`.learned_parsers FINAL WHERE deleted = 0"))
        .fetch_all::<ParserRow>()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            warn!("learned_parsers: {e}");
            return None;
        }
    };
    let ids: BTreeSet<String> = rows.iter().map(|r| r.id.clone()).collect();
    let parsers: Vec<DynamicParser> = rows.iter().filter_map(|r| serde_json::from_str(&r.parser).ok()).collect();
    if !parsers.is_empty() {
        info!("Loaded {} learned parsers from ClickHouse", registry.load_parsers(parsers));
    } else if database == DEFAULT_DB {
        let Ok(bytes) = std::fs::read(LEGACY_FILE) else { return Some(ids) };
        if let Ok(parsers) = serde_json::from_slice::<Vec<DynamicParser>>(&bytes) {
            info!("Imported {} learned parsers from {LEGACY_FILE}", registry.load_parsers(parsers));
            // written to ClickHouse by the first sync; the file is kept, renamed
            let _ = std::fs::rename(LEGACY_FILE, format!("{LEGACY_FILE}.imported"));
        }
    }
    Some(ids)
}

/// Writes the registry when it changed: every parser, and a tombstone for removed ones.
async fn save(db: &ClickHouseDb, registry: &DynamicParserRegistry, stored: &mut BTreeSet<String>, database: &str) -> bool {
    let at = now_ms();
    let parsers = registry.list_parsers();
    let current: BTreeSet<String> = parsers.iter().map(|p| p.id.to_string()).collect();
    let mut rows: Vec<ParserRow> = parsers
        .iter()
        .map(|p| ParserRow { id: p.id.to_string(), parser: serde_json::to_string(p).unwrap_or_default(), deleted: 0, updated_at: at })
        .collect();
    rows.extend(stored.difference(&current).map(|id| ParserRow { id: id.clone(), parser: String::new(), deleted: 1, updated_at: at }));
    let c = db.root().clone().with_database(database);
    let mut ins = match c.insert("learned_parsers") {
        Ok(i) => i,
        Err(e) => {
            warn!("learned_parsers: {e}");
            return false;
        }
    };
    for r in &rows {
        if let Err(e) = ins.write(r).await {
            warn!("learned_parsers: {e}");
            return false;
        }
    }
    if let Err(e) = ins.end().await {
        warn!("learned_parsers: {e}");
        return false;
    }
    *stored = current;
    true
}

/// Saves the parsers every 30 s when they changed (and once at start, for imports and defaults).
pub fn spawn_sync(db: ClickHouseDb, registry: Arc<DynamicParserRegistry>, mut stored: BTreeSet<String>, database: String) {
    tokio::spawn(async move {
        let mut saved_version = None;
        loop {
            let v = registry.version();
            if saved_version != Some(v) && save(&db, &registry, &mut stored, &database).await {
                saved_version = Some(v);
            }
            tokio::time::sleep(Duration::from_secs(30)).await;
        }
    });
}

/// The tenant's parser registry: the default tenant's is `state.parser_registry`; another
/// tenant's is made on first use and filled from its database in the background.
pub fn for_tenant(state: &AppState, tenant: &str) -> Arc<DynamicParserRegistry> {
    let t = tenancy::normalize_tenant(tenant);
    if t == tenancy::DEFAULT_TENANT {
        return state.parser_registry.clone();
    }
    if let Some(r) = state.parser_tenants.read().unwrap().get(&t) {
        return r.clone();
    }
    let mut all = state.parser_tenants.write().unwrap();
    all.entry(t.clone())
        .or_insert_with(|| {
            let r = Arc::new(DynamicParserRegistry::new(""));
            let (db, reg, database) = (state.db.clone(), r.clone(), tenancy::tenant_db_name(&t));
            tokio::spawn(async move {
                if let Some(ids) = load(&db, &reg, &database).await {
                    spawn_sync(db, reg, ids, database);
                }
            });
            r
        })
        .clone()
}
