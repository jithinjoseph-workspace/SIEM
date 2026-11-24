// NDR ↔ SIEM Cross-Corroboration Module
//
// Every 60 seconds:
//   1. Pull recent ndr_hits (last 5 min, not yet corroborated) from ndr.ndr_hits
//   2. For each hit: HMAC-SHA256(src_ip, IP_TOKEN_KEY) → ip_token
//   3. Query the tenant's siem_logs WHERE has(ip_tokens, token) — same 5-min window
//   4. If SIEM logs found for that IP → write unified_alerts with source='corroborated'
//   5. Mark the ndr_hit corroborated_at = now() so we don't re-process it
//
// Safe in SIEM-only deployments: if ndr_hits is empty or has no recent rows,
// the loop returns immediately with no errors.

use anyhow::Result;
use clickhouse::Client;
use chrono::Utc;
use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

// ─────────────────────────────────────────────────────────────────────────────
// Entry point — spawns the background task
// ─────────────────────────────────────────────────────────────────────────────

pub fn spawn_corroboration(ch: Client) {
    let ip_token_key = std::env::var("IP_TOKEN_KEY").unwrap_or_default();

    if ip_token_key.is_empty() {
        tracing::warn!("corroboration: IP_TOKEN_KEY not set — NDR↔SIEM cross-corroboration disabled");
        return;
    }

    tokio::spawn(async move {
        // Initial delay: let Kafka consumer warm up first
        tokio::time::sleep(tokio::time::Duration::from_secs(30)).await;

        let mut ticker = tokio::time::interval(tokio::time::Duration::from_secs(60));
        loop {
            ticker.tick().await;
            if let Err(e) = run_corroboration_cycle(&ch, &ip_token_key).await {
                tracing::warn!("corroboration cycle error: {e}");
            }
        }
    });
}

// ─────────────────────────────────────────────────────────────────────────────
// One cycle
// ─────────────────────────────────────────────────────────────────────────────

fn tenant_db(tenant_id: &str) -> String {
    if tenant_id == "default" || tenant_id.is_empty() {
        "ndr".to_string()
    } else {
        format!("ndr_{}", tenant_id.replace('-', "_"))
    }
}

async fn run_corroboration_cycle(ch: &Client, ip_token_key: &str) -> Result<()> {
    // Fetch recent NDR hits that haven't been corroborated yet.
    // ndr_hits is in the shared ndr DB with a tenant_id column for isolation.

    #[derive(Debug, clickhouse::Row, serde::Deserialize)]
    struct TenantRow { id: String }

    #[derive(Debug, clickhouse::Row, serde::Deserialize)]
    struct NdrHitRow {
        community_id: String,
        tenant_id:    String,
        src_ip:       String,
        dst_ip:       String,
        severity:     String,
        tags:         Vec<String>,
    }

    // ndr_hits is per-tenant. Query each known tenant DB by reading the tenants list first.
    let tenant_ids: Vec<String> = ch
        .query("SELECT id FROM ndr.tenants FINAL FORMAT JSONEachRow")
        .fetch_all::<TenantRow>()
        .await
        .unwrap_or_default()
        .into_iter()
        .map(|r| r.id)
        .collect();

    // Always include the 'default' tenant (database: ndr)
    let mut dbs: Vec<String> = vec!["ndr".to_string()];
    for tid in &tenant_ids {
        if tid != "default" && !tid.is_empty() {
            dbs.push(format!("ndr_{}", tid));
        }
    }

    let mut hits: Vec<NdrHitRow> = vec![];
    for db in &dbs {
        let sql = format!(
            "SELECT community_id, tenant_id, src_ip, dst_ip, severity, tags \
             FROM {db}.ndr_hits FINAL \
             WHERE timestamp >= now() - INTERVAL 5 MINUTE \
               AND corroborated_at = toDateTime(0) \
             LIMIT 200"
        );
        let mut rows = ch.query(&sql).fetch_all::<NdrHitRow>().await.unwrap_or_default();
        hits.append(&mut rows);
    }

    if hits.is_empty() {
        return Ok(());
    }

    tracing::debug!("corroboration: {} recent NDR hits to check", hits.len());

    for hit in &hits {
        // Compute HMAC token for src_ip (same algorithm as SIEM ingest)
        let src_token = hmac_token(&hit.src_ip, ip_token_key);

        // siem_logs is in the per-tenant database; unified_alerts is shared (tenant_id column)
        let db = tenant_db(&hit.tenant_id);

        // Find SIEM logs from the same 5-min window that contain this IP token
        #[derive(Debug, clickhouse::Row, serde::Deserialize)]
        struct SiemLogRow {
            log_id:      String,
            event_class: String,
            severity:    String,
        }

        let siem_sql = format!(
            "SELECT log_id, event_class, severity \
             FROM {db}.siem_logs \
             WHERE timestamp >= now() - INTERVAL 5 MINUTE \
               AND has(ip_tokens, '{token}') \
             LIMIT 50",
            db    = db,
            token = esc(&src_token),
        );

        let siem_rows = ch
            .query(&siem_sql)
            .fetch_all::<SiemLogRow>()
            .await
            .unwrap_or_default();

        if siem_rows.is_empty() {
            // No SIEM activity for this NDR IP — not corroborated
            continue;
        }

        tracing::info!(
            community_id = %hit.community_id,
            tenant_id    = %hit.tenant_id,
            src_ip_token = %src_token,
            siem_hits    = siem_rows.len(),
            "corroboration: NDR hit matched SIEM logs — writing corroborated alert"
        );

        // Build linked log id list
        let linked_siem_ids: Vec<String> = siem_rows.iter().map(|r| r.log_id.clone()).collect();

        // Determine severity: escalate to the highest seen across NDR and SIEM
        let severity = escalate_severity(&hit.severity, &siem_rows.iter().map(|r| r.severity.as_str()).collect::<Vec<_>>());

        // Write unified alert
        if let Err(e) = write_corroborated_alert(
            ch,
            &hit.tenant_id,
            &hit.community_id,
            &src_token,
            &severity,
            &hit.tags,
            &linked_siem_ids,
        ).await {
            tracing::warn!("corroboration: failed to write alert for {}: {e}", hit.community_id);
            continue;
        }

        // Mark the ndr_hit as corroborated so we don't re-process it
        mark_ndr_hit_corroborated(ch, &hit.tenant_id, &hit.community_id).await;
    }

    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Write a corroborated alert into ndr.unified_alerts
// ─────────────────────────────────────────────────────────────────────────────

async fn write_corroborated_alert(
    ch:               &Client,
    tenant_id:        &str,
    community_id:     &str,
    src_ip_token:     &str,
    severity:         &str,
    ndr_tags:         &[String],
    linked_siem_ids:  &[String],
) -> Result<()> {
    let alert_id   = uuid::Uuid::new_v4().to_string();
    let now        = Utc::now().timestamp() as u32;
    let sla_min: i64 = match severity {
        "CRITICAL" => 15,
        "HIGH"     => 60,
        "MEDIUM"   => 240,
        _          => 1440,
    };
    let sla_breached = (Utc::now() + chrono::Duration::minutes(sla_min)).timestamp() as u32;

    let tag_summary = if ndr_tags.is_empty() {
        "network anomaly".to_string()
    } else {
        ndr_tags.join(", ")
    };

    let title       = format!("Corroborated Threat: NDR+SIEM confirmed on same IP ({})", src_ip_token);
    let description = format!(
        "NDR network hit (tags: {}) corroborated by {} SIEM log event(s) from the same source IP within 5 minutes. \
         Both network traffic and endpoint/log activity confirm this IP is suspicious.",
        tag_summary,
        linked_siem_ids.len()
    );

    // Encode linked_siem_ids as ClickHouse Array(String) literal
    let siem_ids_ch = ch_array(linked_siem_ids);
    // community_id is the NDR evidence reference
    let ndr_ids_ch  = ch_array(&[community_id.to_string()]);

    // unified_alerts is per-tenant — write to ndr_{tenant_id}.unified_alerts
    let db = tenant_db(tenant_id);
    let sql = format!(
        "INSERT INTO {db}.unified_alerts \
         (alert_id, tenant_id, source, severity, rule_id, rule_name, title, description, \
          affected_hosts, mitre_techniques, mitre_sources, mitre_confidences, status, \
          linked_ndr_event_ids, linked_siem_log_ids, \
          sla_started_at, sla_breached_at, created_at, updated_at) \
         VALUES \
         ('{aid}', '{tid}', 'corroborated', '{sev}', \
          'corroboration-module', 'NDR+SIEM Corroboration', \
          '{title}', '{desc}', \
          ['{src_token}'], ['T1078'], ['corroboration-module'], [0.90], \
          'New', \
          {ndr_ids}, {siem_ids}, \
          {now}, {sla}, {now}, {now})",
        aid        = esc(&alert_id),
        tid        = esc(tenant_id),
        sev        = esc(severity),
        title      = esc(&title),
        desc       = esc(&description),
        src_token  = esc(src_ip_token),
        db         = db,
        ndr_ids    = ndr_ids_ch,
        siem_ids   = siem_ids_ch,
        now        = now,
        sla        = sla_breached,
    );

    ch.query(&sql).execute().await?;
    tracing::info!(alert_id = %alert_id, tenant_id = %tenant_id, severity = %severity, "Corroborated alert written");
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Mark the NDR hit corroborated (re-INSERT with corroborated_at = now())
// Uses ReplacingMergeTree dedup on (tenant_id, community_id)
// ─────────────────────────────────────────────────────────────────────────────

async fn mark_ndr_hit_corroborated(ch: &Client, tenant_id: &str, community_id: &str) {
    let db  = tenant_db(tenant_id);
    let now = Utc::now().timestamp() as u32;
    let sql = format!(
        "INSERT INTO {db}.ndr_hits \
         (timestamp, community_id, src_ip, dst_ip, score, severity, tags, \
          sigma_hits, threat_intel, src_country, dst_country, tenant_id, \
          correlation_status, agent_z_details, agent_s_details, \
          corroborated_at, agent_s_rule_id, agent_s_category, updated_at, sensor_id) \
         SELECT \
          timestamp, community_id, src_ip, dst_ip, score, severity, tags, \
          sigma_hits, threat_intel, src_country, dst_country, tenant_id, \
          'corroborated' AS correlation_status, agent_z_details, agent_s_details, \
          toDateTime({now}) AS corroborated_at, agent_s_rule_id, agent_s_category, \
          toDateTime({now}) AS updated_at, sensor_id \
         FROM {db}.ndr_hits FINAL \
         WHERE community_id = '{cid}'",
        db  = db,
        now = now,
        cid = esc(community_id),
    );

    if let Err(e) = ch.query(&sql).execute().await {
        tracing::warn!("corroboration: failed to mark ndr_hit corroborated ({community_id}): {e}");
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

fn hmac_token(ip: &str, key: &str) -> String {
    let mut mac = HmacSha256::new_from_slice(key.as_bytes())
        .expect("HMAC accepts any key length");
    mac.update(ip.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

fn escalate_severity(ndr_sev: &str, siem_sevs: &[&str]) -> String {
    let rank = |s: &str| match s.to_uppercase().as_str() {
        "CRITICAL" => 4,
        "HIGH"     => 3,
        "MEDIUM"   => 2,
        "LOW"      => 1,
        _          => 0,
    };
    let sev_name = |r: u8| match r {
        4 => "CRITICAL",
        3 => "HIGH",
        2 => "MEDIUM",
        1 => "LOW",
        _ => "INFO",
    };

    let mut max = rank(ndr_sev) as u8;
    for s in siem_sevs {
        let r = rank(s) as u8;
        if r > max { max = r; }
    }
    sev_name(max).to_string()
}

fn ch_array(ids: &[String]) -> String {
    if ids.is_empty() {
        return "[]".to_string();
    }
    let inner: Vec<String> = ids.iter().map(|id| format!("'{}'", esc(id))).collect();
    format!("[{}]", inner.join(", "))
}

fn esc(s: &str) -> String {
    s.replace('\\', "\\\\").replace('\'', "\\'")
}
