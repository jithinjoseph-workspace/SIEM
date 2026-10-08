// SIEM Sigma Rule Evaluator — Option B: scheduled batch queries against siem_logs
//
// Every 5 minutes, for each tenant:
//   1. Load enabled rules from ndr.sigma_rules (filtered by ndr.rules_state)
//   2. Compile each rule's Sigma conditions → ClickHouse SQL WHERE clause
//   3. Query ndr_{tenant}.siem_logs for matches in the last 5 min
//   4. If hits → write alert to ndr_{tenant}.siem_alerts (deduped per rule/hour)
//
// License: Apache-2.0

use std::collections::HashMap;
use std::time::Duration;

use anyhow::Result;
use clickhouse::Client;
use uuid::Uuid;

use provigil_common::detection::sigma::{
    ConditionExpr, FieldCondition, Matcher, SelectionGroup, SigmaRule,
};
use provigil_common::detection::parse_rule_content;

use crate::correlation::alerts::tenant_db;

// ─────────────────────────────────────────────────────────────────────────────
// Entry point
// ─────────────────────────────────────────────────────────────────────────────

pub fn spawn_sigma_evaluator(ch: Client) {
    tokio::spawn(async move {
        // First run 2 minutes after start (let tables settle)
        tokio::time::sleep(Duration::from_secs(120)).await;
        let mut ticker = tokio::time::interval(Duration::from_secs(300)); // 5 min
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            ticker.tick().await;
            if let Err(e) = run_evaluation_cycle(&ch).await {
                tracing::warn!("sigma_eval: cycle error: {e}");
            }
        }
    });
}

// ─────────────────────────────────────────────────────────────────────────────
// Evaluation cycle — runs every 5 min
// ─────────────────────────────────────────────────────────────────────────────

async fn run_evaluation_cycle(ch: &Client) -> Result<()> {
    // Load all tenant IDs
    #[derive(serde::Deserialize, clickhouse::Row)]
    struct TRow { id: String }
    let tenants: Vec<String> = ch
        .query("SELECT id FROM ndr.tenants FINAL")
        .fetch_all::<TRow>().await.unwrap_or_default()
        .into_iter().map(|r| r.id).collect();

    // Load enabled Sigma rules from global table
    let rules = load_enabled_rules(ch).await?;
    if rules.is_empty() {
        tracing::debug!("sigma_eval: no enabled rules — skipping");
        return Ok(());
    }

    // Load per-tenant rule disable overrides from rules_state
    let disabled_map = load_disabled_overrides(ch).await?;

    tracing::debug!("sigma_eval: evaluating {} rules across {} tenants", rules.len(), tenants.len());

    for tenant_id in &tenants {
        let disabled = disabled_map.get(tenant_id.as_str());
        let applicable: Vec<&SigmaRule> = rules.iter()
            .filter(|r| {
                // Skip globally disabled rules for this tenant
                disabled.map_or(true, |d: &std::collections::HashSet<String>| !d.contains(&r.id))
            })
            .collect();

        for rule in applicable {
            if let Err(e) = evaluate_rule(ch, tenant_id, rule).await {
                tracing::debug!("sigma_eval: rule {} tenant {} error: {}", rule.id, tenant_id, e);
            }
        }
    }

    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Load rules from ndr.sigma_rules
// ─────────────────────────────────────────────────────────────────────────────

async fn load_enabled_rules(ch: &Client) -> Result<Vec<SigmaRule>> {
    #[derive(serde::Deserialize, clickhouse::Row)]
    struct Row { id: String, content: String }

    let rows: Vec<Row> = ch
        .query("SELECT id, content FROM ndr.sigma_rules FINAL WHERE enabled = 1")
        .fetch_all()
        .await
        .unwrap_or_default();

    let mut rules = Vec::new();
    for row in rows {
        match parse_rule_content(&row.content) {
            Ok(r)  => rules.push(r),
            Err(e) => tracing::debug!("sigma_eval: skipping rule {} — parse error: {}", row.id, e),
        }
    }
    Ok(rules)
}

async fn load_disabled_overrides(
    ch: &Client,
) -> Result<HashMap<String, std::collections::HashSet<String>>> {
    #[derive(serde::Deserialize, clickhouse::Row)]
    struct Row { id: String, tenant_id: String }

    let rows: Vec<Row> = ch
        .query("SELECT id, tenant_id FROM ndr.rules_state FINAL WHERE enabled = 0")
        .fetch_all()
        .await
        .unwrap_or_default();

    let mut map: HashMap<String, std::collections::HashSet<String>> = HashMap::new();
    for row in rows {
        map.entry(row.tenant_id).or_default().insert(row.id);
    }
    Ok(map)
}

// ─────────────────────────────────────────────────────────────────────────────
// Evaluate one rule against one tenant's siem_logs
// ─────────────────────────────────────────────────────────────────────────────

async fn evaluate_rule(ch: &Client, tenant_id: &str, rule: &SigmaRule) -> Result<()> {
    let sql_where = match compile_rule_to_sql(rule) {
        Some(w) => w,
        None    => return Ok(()), // unsupported condition
    };

    let db = tenant_db(tenant_id);

    // Deduplication: one alert per rule per hour
    let hour_bucket = chrono::Utc::now().timestamp() / 3600;
    let alert_id = format!("{}-{}-{}", rule.id, tenant_id, hour_bucket);

    // Check if alert already exists for this window
    #[derive(serde::Deserialize, clickhouse::Row)]
    struct Cnt { cnt: u64 }
    let already: Cnt = ch
        .query(&format!(
            "SELECT count() AS cnt FROM {db}.siem_alerts FINAL WHERE alert_id = '{aid}'",
            db  = db,
            aid = escape(&alert_id),
        ))
        .fetch_one()
        .await
        .unwrap_or(Cnt { cnt: 0 });

    if already.cnt > 0 { return Ok(()); }

    // Query siem_logs for matches in last 5 min
    let query_sql = format!(
        "SELECT log_id FROM {db}.siem_logs \
         WHERE ({where_clause}) \
           AND timestamp >= now() - INTERVAL 5 MINUTE \
         LIMIT 50",
        db          = db,
        where_clause = sql_where,
    );

    #[derive(serde::Deserialize, clickhouse::Row)]
    struct LogRow { log_id: String }

    let matched: Vec<LogRow> = ch
        .query(&query_sql)
        .fetch_all()
        .await
        .unwrap_or_default();

    if matched.is_empty() { return Ok(()); }

    let log_ids: Vec<String> = matched.into_iter().map(|r| r.log_id).collect();

    tracing::info!(
        rule  = %rule.id,
        title = %rule.title,
        tenant = %tenant_id,
        hits  = log_ids.len(),
        "sigma_eval: rule fired — writing alert"
    );

    write_sigma_alert(ch, tenant_id, rule, alert_id, log_ids).await
}

// ─────────────────────────────────────────────────────────────────────────────
// Write alert to ndr_{tenant}.siem_alerts
// ─────────────────────────────────────────────────────────────────────────────

async fn write_sigma_alert(
    ch:        &Client,
    tenant_id: &str,
    rule:      &SigmaRule,
    alert_id:  String,
    log_ids:   Vec<String>,
) -> Result<()> {
    let db       = tenant_db(tenant_id);
    let now      = chrono::Utc::now().timestamp() as u32;
    let severity = normalize_severity(&rule.severity);

    // Extract MITRE technique tags (attack.tNNNN)
    let mitre: Vec<String> = rule.tags.iter()
        .filter(|t| t.to_lowercase().starts_with("attack.t"))
        .map(|t| t.to_uppercase().replace("ATTACK.", ""))
        .collect();

    let log_ids_literal = array_literal(&log_ids);
    let mitre_literal   = array_literal(&mitre);
    let title_esc       = escape(&rule.title);
    let rule_id_esc     = escape(&rule.id);
    let tenant_esc      = escape(tenant_id);

    // SLA deadline
    let sla_mins: i64 = match severity {
        "CRITICAL" => 15,
        "HIGH"     => 60,
        "MEDIUM"   => 240,
        _          => 1440,
    };
    let sla_ts = now as i64 + sla_mins * 60;

    let sql = format!(
        "INSERT INTO {db}.siem_alerts \
         (alert_id, tenant_id, severity, rule_id, rule_name, title, description, \
          affected_hosts, mitre_techniques, mitre_sources, mitre_confidences, \
          status, linked_siem_log_ids, sla_started_at, sla_breached_at, created_at, updated_at) \
         VALUES \
         ('{alert_id}', '{tenant}', '{sev}', '{rule_id}', '{rule_name}', '{title}', \
          'Sigma rule match', [], {mitre}, [], [], \
          'New', {log_ids}, toDateTime({now}), toDateTime({sla}), toDateTime({now}), toDateTime({now}))",
        db        = db,
        alert_id  = escape(&alert_id),
        tenant    = tenant_esc,
        sev       = severity,
        rule_id   = rule_id_esc,
        rule_name = title_esc,
        title     = title_esc,
        mitre     = mitre_literal,
        log_ids   = log_ids_literal,
        now       = now,
        sla       = sla_ts,
    );

    ch.query(&sql).execute().await?;
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Sigma → ClickHouse SQL compiler
// ─────────────────────────────────────────────────────────────────────────────

/// Compile a parsed SigmaRule into a ClickHouse SQL WHERE clause.
/// Returns None for unsupported conditions (e.g. count-based aggregations).
fn compile_rule_to_sql(rule: &SigmaRule) -> Option<String> {
    let sql = compile_expr(&rule.condition_expr, &rule.selections);
    if sql.is_empty() || sql == "0" { None } else { Some(sql) }
}

fn compile_expr(expr: &ConditionExpr, selections: &HashMap<String, SelectionGroup>) -> String {
    match expr {
        ConditionExpr::Named(name) => {
            match selections.get(name) {
                Some(g) => compile_group(g),
                None    => "0".to_string(),
            }
        }
        ConditionExpr::Not(inner) => {
            let inner_sql = compile_expr(inner, selections);
            if inner_sql == "0" { "1".to_string() }
            else { format!("NOT ({})", inner_sql) }
        }
        ConditionExpr::And(parts) => {
            let parts_sql: Vec<String> = parts.iter()
                .map(|p| compile_expr(p, selections))
                .filter(|s| s != "0")
                .collect();
            if parts_sql.is_empty() { return "0".to_string(); }
            format!("({})", parts_sql.join(" AND "))
        }
        ConditionExpr::Or(parts) => {
            let parts_sql: Vec<String> = parts.iter()
                .map(|p| compile_expr(p, selections))
                .filter(|s| s != "0")
                .collect();
            if parts_sql.is_empty() { return "0".to_string(); }
            format!("({})", parts_sql.join(" OR "))
        }
        ConditionExpr::AnyOf(prefix) => {
            let groups: Vec<String> = selections.iter()
                .filter(|(k, _)| k.starts_with(prefix.as_str()))
                .map(|(_, g)| compile_group(g))
                .collect();
            if groups.is_empty() { "0".to_string() }
            else { format!("({})", groups.join(" OR ")) }
        }
        ConditionExpr::AllOf(prefix) => {
            let groups: Vec<String> = selections.iter()
                .filter(|(k, _)| k.starts_with(prefix.as_str()))
                .map(|(_, g)| compile_group(g))
                .collect();
            if groups.is_empty() { "0".to_string() }
            else { format!("({})", groups.join(" AND ")) }
        }
        ConditionExpr::AnyOfThem => {
            let groups: Vec<String> = selections.values()
                .map(|g| compile_group(g))
                .collect();
            if groups.is_empty() { "0".to_string() }
            else { format!("({})", groups.join(" OR ")) }
        }
        ConditionExpr::AllOfThem => {
            let groups: Vec<String> = selections.values()
                .map(|g| compile_group(g))
                .collect();
            if groups.is_empty() { "0".to_string() }
            else { format!("({})", groups.join(" AND ")) }
        }
        ConditionExpr::AlwaysTrue     => "1".to_string(),
        ConditionExpr::AlwaysFalse    => "0".to_string(),
        ConditionExpr::Unsupported(_) => "0".to_string(),
    }
}

/// SelectionGroup: alternatives are OR'd; within each alternative, conditions are AND'd.
fn compile_group(group: &SelectionGroup) -> String {
    let alts: Vec<String> = group.alternatives.iter()
        .map(|alt| {
            let conds: Vec<String> = alt.iter()
                .map(compile_field_condition)
                .collect();
            if conds.len() == 1 { conds[0].clone() }
            else { format!("({})", conds.join(" AND ")) }
        })
        .collect();

    if alts.is_empty()   { "0".to_string() }
    else if alts.len() == 1 { alts[0].clone() }
    else { format!("({})", alts.join(" OR ")) }
}

fn compile_field_condition(cond: &FieldCondition) -> String {
    // Wildcard field — search anywhere in the raw log
    if cond.field == "*" {
        let parts: Vec<String> = cond.values.iter()
            .map(|v| format!("lower(raw_log) LIKE lower('%{}%')", escape_like(v)))
            .collect();
        let expr = if parts.len() == 1 { parts[0].clone() }
                   else { format!("({})", parts.join(" OR ")) };
        return if cond.negated { format!("NOT ({})", expr) } else { expr };
    }

    let field_sql = field_expr(&cond.field);

    // Multiple values are always OR'd within one field condition
    let parts: Vec<String> = cond.values.iter().enumerate().map(|(i, v)| {
        match &cond.matcher {
            Matcher::Equals     => {
                if v == "*" { format!("{} IS NOT NULL", field_sql) }
                else { format!("lower({}) = lower('{}')", field_sql, escape(v)) }
            }
            Matcher::Contains   => format!("lower({}) LIKE lower('%{}%')",   field_sql, escape_like(v)),
            Matcher::StartsWith => format!("lower({}) LIKE lower('{}%')",    field_sql, escape_like(v)),
            Matcher::EndsWith   => format!("lower({}) LIKE lower('%{}')",    field_sql, escape_like(v)),
            Matcher::Regex      => format!("match({}, '{}')",                field_sql, escape_regex(v)),
            Matcher::Cidr       => {
                // isIPAddressInRange requires a real IP — fall back to LIKE for safety
                format!("lower({}) LIKE lower('{}%')", field_sql, escape_like(&v.split('/').next().unwrap_or(v)))
            }
        }
    }).collect();

    let expr = if parts.len() == 1 { parts[0].clone() }
               else { format!("({})", parts.join(" OR ")) };
    if cond.negated { format!("NOT ({})", expr) } else { expr }
}

/// Map a Sigma field name to a ClickHouse SQL expression extracting from parsed_json.
///
/// Supports:
///   - Flat fields:   EventID → JSONExtractString(parsed_json, 'EventID')
///   - Dotted paths:  event.code → JSONExtractString(parsed_json, 'event', 'code')
///   - Windows aliases: EventID → also checks winlog.event_id
fn field_expr(field: &str) -> String {
    // Windows Sigma field → ECS/Winlogbeat JSON path aliases
    // Used because SigmaHQ windows rules use flat names, Winlogbeat sends ECS format
    let alias: Option<&str> = match field {
        "EventID"         => Some("winlog.event_id"),
        "LogonType"       => Some("winlog.event_data.LogonType"),
        "CommandLine"     => Some("process.command_line"),
        "Image"           => Some("process.executable"),
        "ParentImage"     => Some("process.parent.executable"),
        "ParentCommandLine" => Some("process.parent.command_line"),
        "User"            => Some("winlog.event_data.SubjectUserName"),
        "TargetUserName"  => Some("winlog.event_data.TargetUserName"),
        "ProcessId"       => Some("process.pid"),
        "ParentProcessId" => Some("process.parent.pid"),
        "DestinationIp"   => Some("destination.ip"),
        "DestinationPort" => Some("destination.port"),
        "SourceIp"        => Some("source.ip"),
        "SourcePort"      => Some("source.port"),
        "Hostname"        => Some("host.name"),
        "ComputerName"    => Some("host.name"),
        "Channel"         => Some("winlog.channel"),
        "Provider_Name"   => Some("winlog.provider_name"),
        "SubjectUserName" => Some("winlog.event_data.SubjectUserName"),
        "TargetFilename"  => Some("file.path"),
        "RegistryKey"     => Some("registry.key"),
        "ServiceName"     => Some("service.name"),
        _                 => None,
    };

    let path = alias.unwrap_or(field);
    json_extract(path)
}

/// Build a JSONExtractString ClickHouse expression for a dot-separated path.
fn json_extract(path: &str) -> String {
    let parts: Vec<String> = path.split('.').map(|p| format!("'{}'", p)).collect();
    format!("JSONExtractString(parsed_json, {})", parts.join(", "))
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

fn normalize_severity(s: &str) -> &'static str {
    match s.to_lowercase().as_str() {
        "critical"                       => "CRITICAL",
        "high"                           => "HIGH",
        "medium" | "moderate"            => "MEDIUM",
        "low" | "info" | "informational" => "LOW",
        _                                => "MEDIUM",
    }
}

fn array_literal(items: &[String]) -> String {
    if items.is_empty() {
        return "[]".to_string();
    }
    let inner = items.iter()
        .map(|s| format!("'{}'", escape(s)))
        .collect::<Vec<_>>()
        .join(", ");
    format!("[{}]", inner)
}

fn escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('\'', "\\'")
}

fn escape_like(s: &str) -> String {
    s.replace('\\', "\\\\").replace('\'', "\\'")
     .replace('%', "\\%").replace('_', "\\_")
}

fn escape_regex(s: &str) -> String {
    s.replace('\'', "\\'")
}
