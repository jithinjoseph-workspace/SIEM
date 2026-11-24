// SIEM Correlation Engine — SLA Clock + Breach Checker
// SLA clock starts when an alert is created (status = 'New').
// Breach times by severity:
//   CRITICAL → 15 min  |  HIGH → 60 min  |  MEDIUM → 4 h  |  LOW/INFO → 24 h
// Background task (every 2 min) checks for breached alerts under a distributed lock.
// Only one siem-engine instance runs the checker at a time.
// License: Apache-2.0

use anyhow::Result;
use clickhouse::Client;
use chrono::Utc;
use serde::Deserialize;

// ─────────────────────────────────────────────────────────────────────────────
// Distributed lock key and TTL
// ─────────────────────────────────────────────────────────────────────────────

const SLA_LOCK_KEY: &str   = "siem:sla:checker:lock";
const SLA_LOCK_TTL: usize  = 120; // 120-second lock TTL (≥ check interval)
const SLA_CHECK_INTERVAL_SECS: u64 = 120; // 2 minutes

// ─────────────────────────────────────────────────────────────────────────────
// ClickHouse row for SLA breach query
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize, clickhouse::Row)]
struct BreachRow {
    alert_id:       String,
    tenant_id:      String,
    rule_id:        String,
    severity:       String,
    title:          String,
    sla_breached_at: u32,   // toUnixTimestamp(sla_breached_at)
}

// ─────────────────────────────────────────────────────────────────────────────
// Background SLA checker task
// ─────────────────────────────────────────────────────────────────────────────

/// Spawn the SLA breach-checker background task.
///
/// Every 2 minutes, tries to acquire the Valkey distributed lock.
/// If acquired, scans unified_alerts for overdue alerts and logs a warning.
pub fn spawn_sla_checker(ch: Client, redis_url: String) {
    tokio::spawn(async move {
        let redis_client = match redis::Client::open(redis_url.clone()) {
            Ok(c)  => c,
            Err(e) => {
                tracing::error!("SLA checker: Redis connect failed: {}", e);
                return;
            }
        };
        let mut conn = match redis_client.get_multiplexed_async_connection().await {
            Ok(c)  => c,
            Err(e) => {
                tracing::error!("SLA checker: Redis multiplexed connection failed: {}", e);
                return;
            }
        };

        let mut ticker = tokio::time::interval(
            tokio::time::Duration::from_secs(SLA_CHECK_INTERVAL_SECS)
        );
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            ticker.tick().await;

            // Try to acquire the distributed lock (SET NX EX)
            let acquired: Option<String> = match redis::cmd("SET")
                .arg(SLA_LOCK_KEY)
                .arg("1")
                .arg("NX")
                .arg("EX")
                .arg(SLA_LOCK_TTL)
                .query_async(&mut conn)
                .await
            {
                Ok(v)  => v,
                Err(e) => {
                    tracing::warn!("SLA checker: lock acquire error: {}", e);
                    continue;
                }
            };

            if acquired.is_none() {
                // Another instance holds the lock
                continue;
            }

            // Run the breach check
            if let Err(e) = run_breach_check(&ch).await {
                tracing::warn!("SLA checker: breach check error: {}", e);
            }

            // Release lock immediately after work (best-effort)
            let _: redis::RedisResult<()> = redis::cmd("DEL")
                .arg(SLA_LOCK_KEY)
                .query_async(&mut conn)
                .await;
        }
    });
}

fn tenant_db(tenant_id: &str) -> String {
    if tenant_id == "default" || tenant_id.is_empty() {
        "ndr".to_string()
    } else {
        format!("ndr_{}", tenant_id.replace('-', "_"))
    }
}

/// Query all per-tenant siem_alerts for SLA breaches.
async fn run_breach_check(ch: &Client) -> Result<()> {
    let now = Utc::now().timestamp() as u32;

    // Get all tenant IDs from the global tenants table
    #[derive(serde::Deserialize, clickhouse::Row)]
    struct TRow { id: String }
    let tenant_ids: Vec<String> = ch
        .query("SELECT id FROM ndr.tenants FINAL")
        .fetch_all::<TRow>().await.unwrap_or_default()
        .into_iter().map(|r| r.id).collect();

    let mut dbs: Vec<String> = vec!["ndr".to_string()];
    for tid in &tenant_ids {
        let db = tenant_db(tid);
        if !dbs.contains(&db) { dbs.push(db); }
    }

    let mut rows: Vec<BreachRow> = vec![];
    for db in &dbs {
        let sql = format!(
            "SELECT \
                alert_id, tenant_id, rule_id, severity, title, \
                toUnixTimestamp(sla_breached_at) AS sla_breached_at \
             FROM {db}.siem_alerts FINAL \
             WHERE sla_breached_at IS NOT NULL \
               AND toUnixTimestamp(sla_breached_at) < {now} \
               AND status NOT IN ('Resolved', 'Closed', 'Suppressed') \
             LIMIT 500",
            db = db, now = now,
        );
        let mut db_rows: Vec<BreachRow> = ch.query(&sql).fetch_all().await.unwrap_or_default();
        rows.append(&mut db_rows);
    }

    if rows.is_empty() {
        tracing::debug!("SLA checker: no breached alerts found");
        return Ok(());
    }

    tracing::warn!(
        count = rows.len(),
        "SLA BREACH: {} alerts have exceeded their SLA deadline",
        rows.len()
    );

    for row in &rows {
        let overdue_secs = now as i64 - row.sla_breached_at as i64;
        tracing::warn!(
            alert_id  = %row.alert_id,
            tenant_id = %row.tenant_id,
            rule_id   = %row.rule_id,
            severity  = %row.severity,
            overdue_minutes = overdue_secs / 60,
            "SLA BREACHED: '{}' — overdue by {} min",
            row.title,
            overdue_secs / 60
        );
    }

    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// SLA deadline calculator (also used in types.rs SiemAlert::new)
// ─────────────────────────────────────────────────────────────────────────────

/// Returns the SLA deadline in minutes for a given severity string.
pub fn sla_minutes(severity: &str) -> i64 {
    match severity {
        "CRITICAL" => 15,
        "HIGH"     => 60,
        "MEDIUM"   => 240,
        _          => 1440,  // LOW / INFO
    }
}
