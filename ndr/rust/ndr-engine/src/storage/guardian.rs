//! Automatic storage guardian for ClickHouse.
//!
//! Watches the disk ClickHouse writes to and, as it fills, takes the least destructive action
//! first. The decision (what to do at which level) is a pure function so it can be tested
//! without a database; `run_once` carries the decision out.
//!
//!   70%  compress: switch raw event text to ZSTD (new and merged parts shrink; nothing removed)
//!   80%  shorten the raw-event TTL to `raw_days` (never lengthens an existing TTL), and delete
//!        evidence zip files whose bundle has expired — ClickHouse's TTL removes the row but
//!        never the zip on disk, which is the largest source of growth
//!   90%  critical: the same as 80% plus a critical flag on the status endpoint
//!
//! Never deleted, at any level: alerts (ndr_hits), cases, evidence on legal hold, and the
//! evidence of any session still linked to an open case.
//!
//! Mode (ndr.settings `storage_guardian_mode`): `off`, `dry_run` (the default — records what
//! it would do, changes nothing), or `enforce`. Anything unrecognised is treated as `dry_run`.

use serde::Serialize;
use std::collections::HashSet;

use crate::storage::clickhouse::ClickhouseStorage;

pub const COMPRESS_PCT: f64 = 70.0;
pub const SHORTEN_PCT: f64 = 80.0;
pub const CRITICAL_PCT: f64 = 90.0;
pub const DEFAULT_RAW_DAYS: u32 = 14;
const AUDIT_KEEP: usize = 50;
const MODE_KEY: &str = "storage_guardian_mode";
const RAW_DAYS_KEY: &str = "storage_guardian_raw_days";
const AUDIT_KEY: &str = "storage_guardian_audit";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Level { Ok, Compress, Shorten, Critical }

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Mode { Off, DryRun, Enforce }

impl Mode {
    /// Anything that is not exactly "off" or "enforce" is dry-run: a typo must never delete data.
    pub fn parse(s: &str) -> Mode {
        match s.trim().to_ascii_lowercase().as_str() {
            "off" => Mode::Off,
            "enforce" => Mode::Enforce,
            _ => Mode::DryRun,
        }
    }
}

pub fn level_for(used_pct: f64) -> Level {
    if used_pct >= CRITICAL_PCT { Level::Critical }
    else if used_pct >= SHORTEN_PCT { Level::Shorten }
    else if used_pct >= COMPRESS_PCT { Level::Compress }
    else { Level::Ok }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum Action {
    CompressRaw { db: String },
    ShortenRawTtl { db: String, days: u32 },
    DeleteExpiredEvidence { db: String },
}

/// What a level calls for, across every database. Levels accumulate: a higher level includes
/// everything a lower one does.
pub fn plan(level: Level, dbs: &[String], raw_days: u32) -> Vec<Action> {
    let mut out = Vec::new();
    if level == Level::Ok { return out; }
    for db in dbs {
        out.push(Action::CompressRaw { db: db.clone() });
    }
    if matches!(level, Level::Shorten | Level::Critical) {
        for db in dbs {
            out.push(Action::ShortenRawTtl { db: db.clone(), days: raw_days });
            out.push(Action::DeleteExpiredEvidence { db: db.clone() });
        }
    }
    out
}

/// Bundle file deletion is only allowed for an expired bundle with no legal hold, whose session
/// is not still linked to an open case. Returns the bundle ids that may be deleted.
pub fn deletable_bundles<'a>(
    expired: &'a [(String, String, String)], // (bundle_id, file_path, community_id)
    open_case_cids: &HashSet<String>,
) -> Vec<&'a (String, String, String)> {
    expired.iter()
        .filter(|(_, path, cid)| !path.is_empty() && !open_case_cids.contains(cid))
        .collect()
}

/// Days in a table's TTL clause, read from its CREATE statement. Handles both the
/// `INTERVAL n DAY` and the `toIntervalDay(n)` spellings ClickHouse may use.
pub fn ttl_days(create_sql: &str) -> Option<u32> {
    for pattern in [r"INTERVAL\s+(\d+)\s+DAY", r"toIntervalDay\((\d+)\)"] {
        if let Some(c) = regex::Regex::new(pattern).ok().and_then(|re| re.captures(create_sql)) {
            if let Some(n) = c.get(1).and_then(|m| m.as_str().parse().ok()) {
                return Some(n);
            }
        }
    }
    None
}

#[derive(Debug, Clone, Serialize)]
pub struct Report {
    pub at: String,
    pub used_pct: f64,
    pub level: Level,
    pub mode: Mode,
    /// Human-readable record of each action: the SQL it runs, or what it would delete.
    pub actions: Vec<String>,
    pub errors: Vec<String>,
}

/// Percentage of the ClickHouse data disk in use, from ClickHouse's own view of its disk.
pub async fn disk_used_pct(ch: &ClickhouseStorage) -> Option<f64> {
    let (total, free): (u64, u64) = ch.client
        .query("SELECT total_space, free_space FROM system.disks WHERE name = 'default'")
        .fetch_one().await.ok()?;
    if total == 0 { return None; }
    Some((total - free) as f64 / total as f64 * 100.0)
}

/// Every database this platform writes events to: the default one and each active tenant's.
pub async fn event_databases(ch: &ClickhouseStorage) -> Vec<String> {
    #[derive(clickhouse::Row, serde::Deserialize)]
    struct TenantRow { id: String }
    let tenants = ch.client
        .query("SELECT id FROM ndr.tenants WHERE active = 1")
        .fetch_all::<TenantRow>().await.unwrap_or_default();
    let mut dbs = vec!["ndr".to_string()];
    for t in tenants {
        if t.id != "default" { dbs.push(format!("ndr_{}", t.id.replace('-', "_"))); }
    }
    dbs
}

pub async fn current_mode(ch: &ClickhouseStorage) -> Mode {
    Mode::parse(&ch.get_global_setting(MODE_KEY).await.unwrap_or_default())
}

pub async fn current_raw_days(ch: &ClickhouseStorage) -> u32 {
    ch.get_global_setting(RAW_DAYS_KEY).await
        .and_then(|v| v.trim().parse::<u32>().ok())
        .unwrap_or(DEFAULT_RAW_DAYS)
        .clamp(1, 365)
}

/// One pass: measure, decide, and (in enforce mode only) act. The report is kept for the
/// status endpoint and appended to a bounded audit history.
pub async fn run_once(ch: &ClickhouseStorage, now: &str) -> Option<Report> {
    let mode = current_mode(ch).await;
    if mode == Mode::Off { return None; }
    let used_pct = disk_used_pct(ch).await?;
    let level = level_for(used_pct);
    let raw_days = current_raw_days(ch).await;
    let dbs = event_databases(ch).await;

    let mut report = Report { at: now.to_string(), used_pct, level, mode, actions: vec![], errors: vec![] };
    for action in plan(level, &dbs, raw_days) {
        match execute(ch, &action, mode, &mut report).await {
            Ok(()) => {}
            Err(e) => report.errors.push(format!("{action:?}: {e}")),
        }
    }
    record(ch, &report).await;
    Some(report)
}

async fn execute(ch: &ClickhouseStorage, action: &Action, mode: Mode, report: &mut Report) -> anyhow::Result<()> {
    match action {
        Action::CompressRaw { db } => {
            let create = table_create_sql(ch, db, "ndr_events").await;
            if create.contains("CODEC(ZSTD") { return Ok(()); }
            let sql = format!("ALTER TABLE {db}.ndr_events ON CLUSTER ndr_cluster MODIFY COLUMN raw String CODEC(ZSTD(3))");
            report.actions.push(sql.clone());
            if mode == Mode::Enforce { ch.client.query(&sql).execute().await?; }
        }
        Action::ShortenRawTtl { db, days } => {
            let create = table_create_sql(ch, db, "ndr_events").await;
            // only ever shorten: a table already keeping fewer days stays as it is
            match ttl_days(&create) {
                Some(current) if current <= *days => return Ok(()),
                _ => {}
            }
            let sql = format!("ALTER TABLE {db}.ndr_events ON CLUSTER ndr_cluster MODIFY TTL timestamp + INTERVAL {days} DAY");
            report.actions.push(sql.clone());
            if mode == Mode::Enforce { ch.client.query(&sql).execute().await?; }
        }
        Action::DeleteExpiredEvidence { db } => {
            #[derive(clickhouse::Row, serde::Deserialize)]
            struct Row { id: String, file_path: String, community_id: String }
            let expired: Vec<(String, String, String)> = ch.client
                .query(&format!(
                    "SELECT id, file_path, community_id FROM {db}.evidence_bundles FINAL \
                     WHERE expires_at < now() AND legal_hold = 0 AND file_path != ''"
                ))
                .fetch_all::<Row>().await?
                .into_iter().map(|r| (r.id, r.file_path, r.community_id)).collect();
            let open: HashSet<String> = ch.client
                .query(&format!(
                    "SELECT DISTINCT community_id FROM {db}.soar_cases FINAL \
                     WHERE lower(status) NOT IN ('closed', 'resolved') AND community_id != ''"
                ))
                .fetch_all::<String>().await?
                .into_iter().collect();
            for (id, path, _cid) in deletable_bundles(&expired, &open) {
                report.actions.push(format!("delete expired evidence file {path} (bundle {id}, db {db})"));
                if mode == Mode::Enforce {
                    if let Err(e) = tokio::fs::remove_file(path).await {
                        if e.kind() != std::io::ErrorKind::NotFound {
                            report.errors.push(format!("remove {path}: {e}"));
                        }
                    }
                }
            }
        }
    }
    Ok(())
}

async fn table_create_sql(ch: &ClickhouseStorage, db: &str, table: &str) -> String {
    ch.client
        .query(&format!("SELECT create_table_query FROM system.tables WHERE database = '{db}' AND name = '{table}'"))
        .fetch_one::<String>().await
        .unwrap_or_default()
}

async fn record(ch: &ClickhouseStorage, report: &Report) {
    let mut history: Vec<serde_json::Value> = ch.get_global_setting(AUDIT_KEY).await
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default();
    history.push(serde_json::json!(report));
    if history.len() > AUDIT_KEEP {
        let drop = history.len() - AUDIT_KEEP;
        history.drain(0..drop);
    }
    let _ = ch.set_global_setting(AUDIT_KEY, &serde_json::Value::Array(history).to_string()).await;
}

pub async fn status(ch: &ClickhouseStorage) -> serde_json::Value {
    let used = disk_used_pct(ch).await;
    let history: Vec<serde_json::Value> = ch.get_global_setting(AUDIT_KEY).await
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default();
    serde_json::json!({
        "used_pct": used,
        "level": used.map(level_for),
        "mode": current_mode(ch).await,
        "raw_retention_days": current_raw_days(ch).await,
        "thresholds": { "compress": COMPRESS_PCT, "shorten": SHORTEN_PCT, "critical": CRITICAL_PCT },
        "last": history.last(),
        "history": history.iter().rev().take(10).collect::<Vec<_>>(),
    })
}

/// GET /api/storage/status — super admin only (storage is a platform concern, not a tenant's).
pub async fn status_handler(
    axum::extract::State(state): axum::extract::State<crate::api::AppState>,
    headers: axum::http::HeaderMap,
) -> axum::Json<serde_json::Value> {
    match crate::api::extract_claims(&headers) {
        Some(c) if c.role == "super_admin" => axum::Json(status(&state.ch_storage).await),
        Some(_) => axum::Json(serde_json::json!({ "error": "super admin only" })),
        None => axum::Json(serde_json::json!({ "error": "unauthorized" })),
    }
}

#[derive(serde::Deserialize)]
pub struct ModeBody { pub mode: String, pub raw_days: Option<u32> }

/// POST /api/storage/mode  {"mode": "off" | "dry_run" | "enforce", "raw_days": 14}
/// Anything not exactly "off" or "enforce" is stored as dry_run (see Mode::parse).
pub async fn set_mode_handler(
    axum::extract::State(state): axum::extract::State<crate::api::AppState>,
    headers: axum::http::HeaderMap,
    axum::Json(body): axum::Json<ModeBody>,
) -> axum::Json<serde_json::Value> {
    match crate::api::extract_claims(&headers) {
        Some(c) if c.role == "super_admin" => {}
        Some(_) => return axum::Json(serde_json::json!({ "error": "super admin only" })),
        None => return axum::Json(serde_json::json!({ "error": "unauthorized" })),
    }
    let canonical = match Mode::parse(&body.mode) {
        Mode::Off => "off",
        Mode::Enforce => "enforce",
        Mode::DryRun => "dry_run",
    };
    let _ = state.ch_storage.set_global_setting(MODE_KEY, canonical).await;
    if let Some(days) = body.raw_days {
        let _ = state.ch_storage.set_global_setting(RAW_DAYS_KEY, &days.clamp(1, 365).to_string()).await;
    }
    axum::Json(status(&state.ch_storage).await)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn thresholds_are_exact_at_each_boundary() {
        assert_eq!(level_for(69.9), Level::Ok);
        assert_eq!(level_for(70.0), Level::Compress);
        assert_eq!(level_for(79.9), Level::Compress);
        assert_eq!(level_for(80.0), Level::Shorten);
        assert_eq!(level_for(89.9), Level::Shorten);
        assert_eq!(level_for(90.0), Level::Critical);
        assert_eq!(level_for(100.0), Level::Critical);
    }

    #[test]
    fn nothing_is_planned_while_there_is_room() {
        assert!(plan(Level::Ok, &["ndr".into()], 14).is_empty());
    }

    #[test]
    fn each_level_includes_everything_below_it() {
        let dbs = vec!["ndr".to_string(), "ndr_acm".to_string()];
        let compress = plan(Level::Compress, &dbs, 14);
        assert_eq!(compress.len(), 2, "compression only, no deletion or TTL change at 70%");
        assert!(compress.iter().all(|a| matches!(a, Action::CompressRaw { .. })));

        let shorten = plan(Level::Shorten, &dbs, 14);
        assert!(shorten.iter().any(|a| matches!(a, Action::CompressRaw { .. })), "80% still compresses");
        assert!(shorten.iter().any(|a| matches!(a, Action::ShortenRawTtl { days: 14, .. })));
        assert!(shorten.iter().any(|a| matches!(a, Action::DeleteExpiredEvidence { .. })));
        assert_eq!(shorten.len(), 2 + 2 * 2);

        assert_eq!(plan(Level::Critical, &dbs, 14), shorten, "90% plans the same as 80%; it adds an alert, not new deletions");
    }

    #[test]
    fn a_typo_in_the_mode_never_turns_on_deletion() {
        assert_eq!(Mode::parse("enforce"), Mode::Enforce);
        assert_eq!(Mode::parse("  ENFORCE "), Mode::Enforce);
        assert_eq!(Mode::parse("off"), Mode::Off);
        assert_eq!(Mode::parse("enfroce"), Mode::DryRun, "a misspelled mode is dry-run, never enforce");
        assert_eq!(Mode::parse(""), Mode::DryRun, "unset is dry-run");
    }

    #[test]
    fn only_expired_unheld_unlinked_bundles_with_a_file_are_deletable() {
        let expired = vec![
            ("b1".to_string(), "/opt/e/b1.zip".to_string(), "1:open=".to_string()),   // open case: keep
            ("b2".to_string(), "/opt/e/b2.zip".to_string(), "1:closed=".to_string()), // deletable
            ("b3".to_string(), "".to_string(), "1:nofile=".to_string()),              // no file: nothing to do
        ];
        let open: HashSet<String> = ["1:open=".to_string()].into_iter().collect();
        let ok: Vec<&str> = deletable_bundles(&expired, &open).iter().map(|b| b.0.as_str()).collect();
        assert_eq!(ok, vec!["b2"]);
    }

    #[test]
    fn ttl_is_read_in_both_clickhouse_spellings() {
        assert_eq!(ttl_days("... TTL timestamp + INTERVAL 30 DAY SETTINGS"), Some(30));
        assert_eq!(ttl_days("... TTL timestamp + toIntervalDay(7)"), Some(7));
        assert_eq!(ttl_days("no ttl here"), None);
    }

    // Against the real ClickHouse cluster (a throwaway database, dropped at the end):
    //   CLICKHOUSE_URL=... CLICKHOUSE_USER=... CLICKHOUSE_PASSWORD=... \
    //   cargo test -p ndr-engine guardian_changes_the_real_tables -- --ignored
    #[tokio::test]
    #[ignore]
    async fn guardian_changes_the_real_tables_only_when_enforced_and_never_lengthens_a_ttl() {
        let ch = ClickhouseStorage::new();
        let db = "ndr_zz_guardian";
        let run = |q: String| { let c = ch.client.clone(); async move { c.query(&q).execute().await.unwrap() } };
        let _ = ch.client.query(&format!("DROP DATABASE IF EXISTS {db} ON CLUSTER ndr_cluster")).execute().await;
        run(format!("CREATE DATABASE {db} ON CLUSTER ndr_cluster")).await;
        run(format!("CREATE TABLE {db}.ndr_events ON CLUSTER ndr_cluster (timestamp DateTime, raw String) \
             ENGINE = ReplicatedMergeTree('/clickhouse/tables/{{shard}}/zz_guardian/ndr_events', '{{replica}}') \
             ORDER BY timestamp TTL timestamp + INTERVAL 30 DAY")).await;

        // dry-run: the plan is recorded, nothing changes
        let mut dry = Report { at: "t".into(), used_pct: 85.0, level: Level::Shorten, mode: Mode::DryRun, actions: vec![], errors: vec![] };
        execute(&ch, &Action::ShortenRawTtl { db: db.into(), days: 14 }, Mode::DryRun, &mut dry).await.unwrap();
        execute(&ch, &Action::CompressRaw { db: db.into() }, Mode::DryRun, &mut dry).await.unwrap();
        assert_eq!(dry.actions.len(), 2, "both actions are recorded: {:?}", dry.actions);
        assert!(ttl_days(&table_create_sql(&ch, db, "ndr_events").await) == Some(30), "dry-run must not touch the TTL");
        assert!(!table_create_sql(&ch, db, "ndr_events").await.contains("ZSTD"), "dry-run must not touch the codec");

        // enforce: shorten to 14 days and compress
        let mut enf = Report { at: "t".into(), used_pct: 85.0, level: Level::Shorten, mode: Mode::Enforce, actions: vec![], errors: vec![] };
        execute(&ch, &Action::ShortenRawTtl { db: db.into(), days: 14 }, Mode::Enforce, &mut enf).await.unwrap();
        execute(&ch, &Action::CompressRaw { db: db.into() }, Mode::Enforce, &mut enf).await.unwrap();
        assert!(enf.errors.is_empty(), "{:?}", enf.errors);
        let after = table_create_sql(&ch, db, "ndr_events").await;
        assert_eq!(ttl_days(&after), Some(14), "the TTL is now 14 days");
        assert!(after.contains("ZSTD"), "raw is now ZSTD-compressed");

        // never lengthen: asking for 60 days on a 14-day table changes nothing
        let mut noop = Report { at: "t".into(), used_pct: 85.0, level: Level::Shorten, mode: Mode::Enforce, actions: vec![], errors: vec![] };
        execute(&ch, &Action::ShortenRawTtl { db: db.into(), days: 60 }, Mode::Enforce, &mut noop).await.unwrap();
        assert!(noop.actions.is_empty(), "a longer TTL is never applied: {:?}", noop.actions);
        assert_eq!(ttl_days(&table_create_sql(&ch, db, "ndr_events").await), Some(14));

        let _ = ch.client.query(&format!("DROP DATABASE IF EXISTS {db} ON CLUSTER ndr_cluster")).execute().await;
    }
}
