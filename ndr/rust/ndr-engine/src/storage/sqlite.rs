// NDR Engine — SQLite Storage Backend
// Uses rusqlite with bundled SQLite — no separate install required.
// License: Apache-2.0

use crate::correlator::CorrelationHit;
use crate::detection::DetectionMatch;
use crate::enrichment::EnrichmentData;
use crate::scoring::RiskResult;
use anyhow::Result;
use rusqlite::{params, Connection};
use std::collections::HashMap;
use std::sync::Mutex;
use tracing::warn;

pub struct SqliteStorage {
    conn: Mutex<Connection>,
}

impl SqliteStorage {
    pub fn new(db_path: &str) -> Result<Self> {
        let conn = Connection::open(db_path)?;
        conn.execute_batch("
            PRAGMA journal_mode=WAL;
            PRAGMA synchronous=NORMAL;

            CREATE TABLE IF NOT EXISTS ndr_hits (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp    INTEGER NOT NULL,
                community_id TEXT    NOT NULL,
                src_ip       TEXT,
                dst_ip       TEXT,
                src_port     INTEGER,
                dst_port     INTEGER,
                proto        TEXT,
                event_type   TEXT,
                score        REAL,
                severity     TEXT,
                tags         TEXT,
                reasons      TEXT,
                conn_state   TEXT,
                rule_hits    TEXT,
                src_country  TEXT,
                dst_country  TEXT,
                is_malicious INTEGER,
                direction    TEXT
            );

            CREATE INDEX IF NOT EXISTS idx_cid       ON ndr_hits(community_id);
            CREATE INDEX IF NOT EXISTS idx_ts        ON ndr_hits(timestamp);
            CREATE INDEX IF NOT EXISTS idx_score     ON ndr_hits(score);
            CREATE INDEX IF NOT EXISTS idx_severity  ON ndr_hits(severity);

            CREATE TABLE IF NOT EXISTS ndr_settings (
                key   TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS ndr_custom_iocs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ioc_type TEXT NOT NULL,
                ioc_value TEXT NOT NULL UNIQUE,
                source TEXT DEFAULT 'manual',
                active BOOLEAN DEFAULT 1,
                added_at INTEGER NOT NULL
            );
        ")?;
        Ok(Self { conn: Mutex::new(conn) })
    }

    // ── Settings CRUD ─────────────────────────────────────────────────────

    /// Read all settings as a key-value map.
    pub fn get_settings(&self) -> HashMap<String, String> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare("SELECT key, value FROM ndr_settings")
            .unwrap();
        let rows = stmt.query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        }).unwrap();

        let mut map = HashMap::new();
        for row in rows {
            if let Ok((k, v)) = row {
                map.insert(k, v);
            }
        }
        map
    }

    /// Upsert a single setting.
    pub fn set_setting(&self, key: &str, value: &str) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO ndr_settings (key, value) VALUES (?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![key, value],
        )?;
        Ok(())
    }

    /// Bulk upsert settings from a key-value map (single transaction).
    pub fn set_settings_bulk(&self, settings: &HashMap<String, String>) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        let tx = conn.unchecked_transaction()?;
        {
            let mut stmt = tx.prepare(
                "INSERT INTO ndr_settings (key, value) VALUES (?1, ?2)
                 ON CONFLICT(key) DO UPDATE SET value = excluded.value"
            )?;
            for (k, v) in settings {
                stmt.execute(params![k, v])?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    // ── Custom IOCs ───────────────────────────────────────────────────────

    /// Bulk insert custom IOCs, ignoring duplicates.
    pub fn add_custom_iocs(&self, iocs: &[(String, String)], source: &str) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        let tx = conn.unchecked_transaction()?;
        let now = chrono::Utc::now().timestamp() as i64;
        {
            let mut stmt = tx.prepare(
                "INSERT INTO ndr_custom_iocs (ioc_type, ioc_value, source, active, added_at)
                 VALUES (?1, ?2, ?3, 1, ?4)
                 ON CONFLICT(ioc_value) DO NOTHING"
            )?;
            for (ioc_type, value) in iocs {
                stmt.execute(params![ioc_type, value, source, now])?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    /// Retrieve all active custom IOCs. Returns a vector of (ioc_type, ioc_value).
    pub fn get_active_custom_iocs(&self) -> Vec<(String, String)> {
        let conn = self.conn.lock().unwrap();
        let mut map = Vec::new();
        if let Ok(mut stmt) = conn.prepare("SELECT ioc_type, ioc_value FROM ndr_custom_iocs WHERE active = 1") {
            if let Ok(rows) = stmt.query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            }) {
                for row in rows {
                    if let Ok(r) = row {
                        map.push(r);
                    }
                }
            }
        }
        map
    }

    // ── Hit Storage ───────────────────────────────────────────────────────

    pub fn store_hit(
        &self,
        hit:        &CorrelationHit,
        risk:       &RiskResult,
        detections: &[DetectionMatch],
        enrichment: &EnrichmentData,
    ) -> Result<()> {
        let conn = self.conn.lock().unwrap();

        let src_ip   = hit.agent_s.source_ip.as_deref().or(hit.agent_z.source_ip.as_deref()).unwrap_or("-");
        let dst_ip   = hit.agent_s.dest_ip.as_deref().or(hit.agent_z.dest_ip.as_deref()).unwrap_or("-");
        let src_port = hit.agent_s.source_port.or(hit.agent_z.source_port).unwrap_or(0) as i64;
        let dst_port = hit.agent_s.dest_port.or(hit.agent_z.dest_port).unwrap_or(0) as i64;

        conn.execute(
            "INSERT INTO ndr_hits (
                timestamp, community_id, src_ip, dst_ip, src_port, dst_port,
                proto, event_type, score, severity, tags, reasons, conn_state,
                rule_hits, src_country, dst_country, is_malicious, direction
             ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18)",
            params![
                hit.hit_time as i64,
                hit.community_id,
                src_ip, dst_ip, src_port, dst_port,
                hit.agent_z.proto.as_deref().unwrap_or("-"),
                hit.agent_s.event_type.as_deref().unwrap_or("-"),
                risk.score as f64,
                risk.severity.as_str(),
                risk.tags.join(","),
                risk.reasons.join("|"),
                hit.agent_z.conn_state.as_deref().unwrap_or("-"),
                detections.iter().map(|d| d.title.as_str()).collect::<Vec<_>>().join(","),
                enrichment.src_geo.as_ref().map(|g| g.country_code.as_str()).unwrap_or(""),
                enrichment.dst_geo.as_ref().map(|g| g.country_code.as_str()).unwrap_or(""),
                enrichment.is_malicious as i32,
                enrichment.direction,
            ],
        ).unwrap_or_else(|e| { warn!("SQLite insert error: {}", e); 0 });

        Ok(())
    }
}
