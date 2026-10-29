//! Per-tenant SOAR for the SIEM: the shared provigil-common SOAR (playbooks,
//! integrations, runs and cases in each tenant's own database, the same tables
//! and API the NDR uses) run on the tenant's Wazuh alerts. Actions on a SIEM
//! alert go through the ported Wazuh code: the integration scripts of
//! integratord (Slack, PagerDuty, VirusTotal, Shuffle, Maltiverse), csyslogd's
//! syslog formats, and active response for `block_ip`.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use axum::extract::{Extension, Path, State};
use axum::Json;
use provigil_common::soar::{self as ps, ActiveBlock, SoarContext, SoarNativePlaybook, SoarPlaybookRun, SoarStore};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::tenancy::AuthCtx;
use crate::AppState;

/// Config keys that are secrets: returned empty, kept when a save leaves them empty.
pub(crate) const SECRET_KEYS: [&str; 9] = ["api_key", "routing_key", "smtp_pass", "bot_token", "password", "token", "community", "aws_secret_access_key", "secret"];
/// Runs of one playbook per minute; more matching alerts in that minute are not acted on.
const MAX_RUNS_PER_MINUTE: u32 = 30;
const CACHE_TTL: Duration = Duration::from_secs(30);

// ───────────────────────── storage (the tenant's database) ─────────────────────────

pub struct Store {
    pub db: crate::db::ClickHouseDb,
    /// For active responses (`block_ip`); `None` in tests.
    pub state: Option<AppState>,
}

#[derive(clickhouse::Row, Deserialize)]
struct PlaybookRow {
    id: String,
    name: String,
    description: String,
    enabled: u8,
    cond_field: String,
    cond_op: String,
    cond_value: String,
    action_type: String,
    action_config: String,
    run_count: u64,
    last_run_ts: Option<u32>,
    created_at_ts: u32,
    updated_at_ts: u32,
}

#[derive(clickhouse::Row, Deserialize)]
struct CaseRow {
    id: String,
    case_number: String,
    title: String,
    description: String,
    severity: String,
    priority: String,
    status: String,
    assigned_to: String,
    src_ip: String,
    dst_ip: String,
    community_id: String,
    tags: Vec<String>,
    created_at_ts: u32,
    updated_at_ts: u32,
    closed_at_ts: Option<u32>,
}

const CASE_COLUMNS: &str = "id, case_number, title, description, severity, priority, status, assigned_to, src_ip, dst_ip, community_id, tags, tenant_id, created_at, updated_at, closed_at";

impl Store {
    fn db(&self, tenant: &str) -> clickhouse::Client {
        self.db.tenant_client(tenant)
    }

    pub async fn integrations(&self, tenant: &str) -> anyhow::Result<Vec<Value>> {
        let rows = self.db(tenant).query("SELECT id, name, type, config, enabled FROM soar_integrations FINAL ORDER BY created_at").fetch_all::<(String, String, String, String, u8)>().await?;
        Ok(rows
            .into_iter()
            .map(|r| {
                // secrets are stored sealed (secrets.rs); `raw_config` is what the row holds
                let raw = serde_json::from_str::<Value>(&r.3).unwrap_or(json!({}));
                json!({ "id": r.0, "name": r.1, "type": r.2, "config": crate::secrets::open_config(&raw, &SECRET_KEYS), "raw_config": raw, "enabled": r.4 == 1 })
            })
            .collect())
    }

    async fn integration(&self, tenant: &str, id: &str) -> Option<Value> {
        self.integrations(tenant).await.ok()?.into_iter().find(|i| i["id"].as_str() == Some(id))
    }

    /// A new version of an integration row (ReplacingMergeTree, ordered by id).
    pub async fn put_integration(&self, tenant: &str, id: &str, name: &str, kind: &str, config: &Value, enabled: bool) -> anyhow::Result<()> {
        self.db(tenant)
            .query("INSERT INTO soar_integrations (id, name, type, config, enabled, tenant_id) VALUES (?, ?, ?, ?, ?, ?)")
            .bind(id)
            .bind(name)
            .bind(kind)
            .bind(crate::secrets::seal_config(config, &SECRET_KEYS).to_string())
            .bind(enabled as u8)
            .bind(tenant)
            .execute()
            .await?;
        Ok(())
    }

    /// `table` is one of ours, never user input.
    async fn delete_row(&self, tenant: &str, table: &'static str, id: &str) -> anyhow::Result<()> {
        self.db(tenant).query(&format!("ALTER TABLE {table} DELETE WHERE id = ? SETTINGS mutations_sync = 1")).bind(id).execute().await?;
        Ok(())
    }

    pub async fn insert_playbook(&self, tenant: &str, id: &str, r: &PlaybookReq) -> anyhow::Result<()> {
        let or = |v: &str, d: &'static str| if v.is_empty() { d.to_string() } else { v.to_string() };
        self.db(tenant)
            .query("INSERT INTO soar_native_playbooks (id, name, description, enabled, cond_field, cond_op, cond_value, action_type, action_config, tenant_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
            .bind(id)
            .bind(r.name.trim())
            .bind(&r.description)
            .bind(r.enabled.unwrap_or(true) as u8)
            .bind(or(&r.cond_field, "score"))
            .bind(or(&r.cond_op, ">"))
            .bind(or(&r.cond_value, "75"))
            .bind(&r.action_type)
            .bind(or(&r.action_config, "{}"))
            .bind(tenant)
            .execute()
            .await?;
        invalidate(tenant);
        Ok(())
    }

    /// INSERT SELECT keeps run_count / last_run / created_at (ndr-engine does the same).
    pub async fn update_playbook(&self, tenant: &str, id: &str, r: &PlaybookReq) -> anyhow::Result<()> {
        self.db(tenant)
            .query(
                "INSERT INTO soar_native_playbooks (id, name, description, enabled, cond_field, cond_op, cond_value, action_type, action_config, run_count, last_run, created_at, updated_at, tenant_id) \
                 SELECT id, ?, ?, ?, ?, ?, ?, ?, ?, run_count, last_run, created_at, now(), tenant_id FROM soar_native_playbooks FINAL WHERE id = ?",
            )
            .bind(r.name.trim())
            .bind(&r.description)
            .bind(r.enabled.unwrap_or(true) as u8)
            .bind(&r.cond_field)
            .bind(&r.cond_op)
            .bind(&r.cond_value)
            .bind(&r.action_type)
            .bind(if r.action_config.is_empty() { "{}" } else { &r.action_config })
            .bind(id)
            .execute()
            .await?;
        invalidate(tenant);
        Ok(())
    }

    /// The last 100 playbook runs.
    pub async fn runs(&self, tenant: &str) -> anyhow::Result<Vec<Value>> {
        let rows = self
            .db(tenant)
            .query("SELECT id, playbook_id, playbook_name, hit_id, status, detail, toUnixTimestamp(created_at) FROM soar_playbook_runs ORDER BY created_at DESC LIMIT 100")
            .fetch_all::<(String, String, String, String, String, String, u32)>()
            .await?;
        Ok(rows.into_iter().map(|r| json!({ "id": r.0, "playbook_id": r.1, "playbook_name": r.2, "hit_id": r.3, "status": r.4, "detail": r.5, "created_at": r.6 })).collect())
    }

    pub async fn comments(&self, tenant: &str, case_id: &str) -> anyhow::Result<Vec<Value>> {
        let rows = self
            .db(tenant)
            .query("SELECT id, case_id, author, comment, toUnixTimestamp(created_at) FROM soar_case_comments WHERE case_id = ? ORDER BY created_at ASC")
            .bind(case_id)
            .fetch_all::<(String, String, String, String, u32)>()
            .await?;
        Ok(rows.into_iter().map(|r| json!({ "id": r.0, "case_id": r.1, "author": r.2, "comment": r.3, "created_at": r.4 })).collect())
    }

    pub async fn playbooks(&self, tenant: &str) -> anyhow::Result<Vec<SoarNativePlaybook>> {
        let rows = self
            .db(tenant)
            // run_count / last_run from the runs table (an ALTER UPDATE per run would be a
            // ClickHouse mutation per alert); counts cover the runs' 90-day TTL
            .query(
                "SELECT p.id AS id, p.name AS name, p.description AS description, p.enabled AS enabled, p.cond_field AS cond_field, p.cond_op AS cond_op, \
                 p.cond_value AS cond_value, p.action_type AS action_type, p.action_config AS action_config, r.c AS run_count, \
                 if(r.c = 0, CAST(NULL, 'Nullable(UInt32)'), toUInt32(toUnixTimestamp(r.last))) AS last_run_ts, \
                 toUInt32(toUnixTimestamp(p.created_at)) AS created_at_ts, toUInt32(toUnixTimestamp(p.updated_at)) AS updated_at_ts \
                 FROM soar_native_playbooks AS p FINAL \
                 LEFT JOIN (SELECT playbook_id, count() AS c, max(created_at) AS last FROM soar_playbook_runs GROUP BY playbook_id) AS r ON r.playbook_id = p.id",
            )
            .fetch_all::<PlaybookRow>()
            .await?;
        Ok(rows
            .into_iter()
            .map(|r| SoarNativePlaybook {
                id: r.id,
                name: r.name,
                description: r.description,
                enabled: r.enabled,
                cond_field: r.cond_field,
                cond_op: r.cond_op,
                cond_value: r.cond_value,
                action_type: r.action_type,
                action_config: r.action_config,
                run_count: r.run_count,
                last_run: r.last_run_ts.map(|t| t.to_string()),
                created_at: r.created_at_ts.to_string(),
                updated_at: r.updated_at_ts.to_string(),
                tenant_id: tenant.to_string(),
            })
            .collect())
    }

    async fn cases(&self, tenant: &str) -> anyhow::Result<Vec<Value>> {
        let rows = self.db(tenant).query("SELECT id, case_number, title, description, severity, priority, status, assigned_to, src_ip, dst_ip, community_id, tags, toUnixTimestamp(created_at) AS created_at_ts, toUnixTimestamp(updated_at) AS updated_at_ts, toUnixTimestamp(closed_at) AS closed_at_ts FROM soar_cases FINAL ORDER BY created_at DESC").fetch_all::<CaseRow>().await?;
        Ok(rows
            .into_iter()
            .map(|r| json!({
                "id": r.id, "case_number": r.case_number, "title": r.title, "description": r.description,
                "severity": r.severity, "priority": r.priority, "status": r.status, "assigned_to": r.assigned_to,
                "src_ip": r.src_ip, "dst_ip": r.dst_ip, "community_id": r.community_id, "tags": r.tags,
                "created_at": r.created_at_ts, "updated_at": r.updated_at_ts, "closed_at": r.closed_at_ts,
            }))
            .collect())
    }

    /// A new version of a case row (ReplacingMergeTree keeps the newest `updated_at`).
    async fn rewrite_case(&self, tenant: &str, id: &str, set: &[(&str, &str)], closed_now: bool) -> anyhow::Result<()> {
        let mut cols: Vec<String> = CASE_COLUMNS.split(", ").map(String::from).collect();
        // values bound in column order, the order their '?' appear in
        let mut values = Vec::new();
        for c in cols.iter_mut() {
            if let Some((k, v)) = set.iter().find(|(k, _)| k == c) {
                *c = format!("? AS {k}");
                values.push(*v);
            } else if c == "updated_at" || c == "closed_at" && closed_now {
                *c = "now()".into();
            }
        }
        let sql = format!("INSERT INTO soar_cases ({CASE_COLUMNS}) SELECT {} FROM soar_cases FINAL WHERE id = ?", cols.join(", "));
        let mut q = self.db(tenant).query(&sql);
        for v in values {
            q = q.bind(v);
        }
        q.bind(id).execute().await?;
        Ok(())
    }
}

#[async_trait::async_trait]
impl SoarStore for Store {
    async fn soar_get_integrations(&self, tenant_id: &str) -> Vec<Value> {
        self.integrations(tenant_id).await.unwrap_or_default()
    }

    async fn soar_find_open_case(&self, src: &str, dst: &str, tenant_id: &str) -> Option<(String, String, String, String)> {
        self.db(tenant_id)
            .query("SELECT id, case_number, severity, priority FROM soar_cases FINAL WHERE src_ip = ? AND dst_ip = ? AND status NOT IN ('Closed', 'Resolved', 'False Positive') AND created_at >= now() - INTERVAL 7 DAY ORDER BY created_at DESC LIMIT 1")
            .bind(src)
            .bind(dst)
            .fetch_one::<(String, String, String, String)>()
            .await
            .ok()
    }

    async fn soar_add_comment(&self, case_id: &str, author: &str, comment: &str, tenant_id: &str) {
        let _ = self
            .db(tenant_id)
            .query("INSERT INTO soar_case_comments (id, case_id, author, comment, tenant_id) VALUES (?, ?, ?, ?, ?)")
            .bind(uuid::Uuid::new_v4().to_string())
            .bind(case_id)
            .bind(author)
            .bind(comment)
            .bind(tenant_id)
            .execute()
            .await;
    }

    async fn soar_escalate_case(&self, case_id: &str, severity: &str, priority: &str, tenant_id: &str) {
        let _ = self.rewrite_case(tenant_id, case_id, &[("severity", severity), ("priority", priority)], false).await;
    }

    async fn soar_next_case_number(&self, tenant_id: &str) -> String {
        let year = chrono::Utc::now().format("%Y").to_string();
        let n = self.db(tenant_id).query("SELECT count() + 1 FROM soar_cases FINAL WHERE toYear(created_at) = ?").bind(year.parse::<u32>().unwrap_or(2026)).fetch_one::<u64>().await.unwrap_or(1);
        format!("INC-{year}-{n:04}")
    }

    async fn soar_create_case(
        &self, id: &str, case_number: &str, title: &str, description: &str, severity: &str, priority: &str, status: &str, assigned_to: &str,
        src_ip: &str, dst_ip: &str, community_id: &str, tags: &[String], tenant_id: &str,
    ) -> anyhow::Result<()> {
        self.db(tenant_id)
            .query("INSERT INTO soar_cases (id, case_number, title, description, severity, priority, status, assigned_to, src_ip, dst_ip, community_id, tags, tenant_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
            .bind(id)
            .bind(case_number)
            .bind(title)
            .bind(description)
            .bind(severity)
            .bind(priority)
            .bind(status)
            .bind(assigned_to)
            .bind(src_ip)
            .bind(dst_ip)
            .bind(community_id)
            .bind(tags)
            .bind(tenant_id)
            .execute()
            .await?;
        // every new case is investigated (evidence, login pattern, verdict), as playbooks open them
        if let Some(s) = &self.state {
            crate::case_ai::spawn_for_new_case(s.clone(), tenant_id.to_string(), id.to_string());
        }
        Ok(())
    }

    async fn soar_get_pcap_sessions(&self, _tenant_id: &str, _cid: &str, _limit: usize) -> Vec<Value> {
        Vec::new()
    }

    /// No NDR flow events in the SIEM (`collect_evidence` records the case without them).
    async fn soar_get_events(&self, _community_id: &str, _tenant_id: &str) -> Value {
        json!([])
    }

    async fn soar_insert_block(&self, _block: &ActiveBlock) -> anyhow::Result<()> {
        // SIEM blocks are active responses (recorded by soar_product_action)
        Ok(())
    }

    async fn soar_insert_run(&self, run: &SoarPlaybookRun) -> anyhow::Result<()> {
        self.db(&run.tenant_id).query("INSERT INTO soar_playbook_runs (id, playbook_id, playbook_name, hit_id, status, detail, tenant_id) VALUES (?, ?, ?, ?, ?, ?, ?)")
            .bind(&run.id)
            .bind(&run.playbook_id)
            .bind(&run.playbook_name)
            .bind(&run.hit_id)
            .bind(&run.status)
            .bind(&run.detail)
            .bind(&run.tenant_id)
            .execute()
            .await?;
        Ok(())
    }

    async fn soar_product_action(&self, pb: &SoarNativePlaybook, config: &Value, ctx: &SoarContext) -> Option<(bool, String)> {
        let alert = ctx.alert.as_ref()?;
        let tenant = &pb.tenant_id;
        let integration = |kind: &'static str| async move { ps::actions::find_integration(self, tenant, kind, config).await };
        let r = match pb.action_type.as_str() {
            "slack" => match config["webhook_url"].as_str().filter(|u| !u.is_empty()) {
                Some(url) => run_wazuh_script("slack", alert, "", url).await,
                None => Err("Missing webhook_url".into()),
            },
            "pagerduty" => match integration("pagerduty").await {
                Some(c) => run_wazuh_script("pagerduty", alert, c["routing_key"].as_str().or(c["api_key"].as_str()).unwrap_or(""), "").await,
                None => Err("No enabled PagerDuty integration".into()),
            },
            "virustotal" => match integration("virustotal").await {
                Some(c) => run_wazuh_script("virustotal", alert, c["api_key"].as_str().unwrap_or(""), "").await,
                None => Err("No enabled VirusTotal integration".into()),
            },
            "shuffle" => match integration("shuffle").await {
                Some(c) => run_wazuh_script("shuffle", alert, "", c["webhook_url"].as_str().unwrap_or("")).await,
                None => Err("No enabled Shuffle integration".into()),
            },
            "maltiverse" => match integration("maltiverse").await {
                Some(c) => run_wazuh_script("maltiverse", alert, c["api_key"].as_str().unwrap_or(""), c["hook_url"].as_str().filter(|u| !u.is_empty()).unwrap_or("https://api.maltiverse.com")).await,
                None => Err("No enabled Maltiverse integration".into()),
            },
            "webhook" => match config["webhook_url"].as_str().filter(|u| !u.is_empty()) {
                Some(url) => post_alert(url, alert).await,
                None => Err("Missing webhook_url".into()),
            },
            "syslog" => match integration("syslog").await {
                Some(c) => send_syslog(&c, alert).await,
                None => Err("No enabled syslog integration".into()),
            },
            // the agent (Wazuh active response) and the perimeter firewall / cloud (response.rs)
            "block_ip" => match &self.state {
                Some(s) => {
                    let agent = alert["agent"]["id"].as_str();
                    let hours = config["duration_hours"].as_u64().or_else(|| config["duration_hours"].as_str().and_then(|h| h.parse().ok())).unwrap_or(24);
                    crate::response::block(s, tenant, &ctx.src_ip, hours, config["enforcement"].as_str().unwrap_or("both"), agent, &format!("soar:{}", pb.name), &format!("Playbook: {}", pb.name)).await.map(|(_, d)| d)
                }
                None => Err("active response unavailable".into()),
            },
            // the alert's host into a quarantine VLAN on its switch, or denied in the cloud
            "isolate_host" => match &self.state {
                Some(s) => {
                    let ip = alert["agent"]["ip"].as_str().unwrap_or("");
                    let vlan = config["quarantine_vlan"].as_u64().or_else(|| config["quarantine_vlan"].as_str().and_then(|v| v.parse().ok())).map(|v| v as u16);
                    crate::response::isolate(s, tenant, ip, config["enforcement"].as_str().filter(|e| !e.is_empty()), vlan, "", &format!("soar:{}", pb.name), &format!("Playbook: {}", pb.name), alert["agent"]["id"].as_str()).await.map(|(_, d)| d)
                }
                None => Err("isolation unavailable".into()),
            },
            // teams, discord, email, create_case, collect_evidence: the shared actions
            _ => return None,
        };
        Some(match r {
            Ok(d) => (true, d),
            Err(e) => (false, e),
        })
    }
}

// ───────────────────────── the Wazuh actions ─────────────────────────

async fn run_wazuh_script(name: &str, alert: &Value, api_key: &str, hook_url: &str) -> Result<String, String> {
    run_script_in(&crate::wazuh_manager::home(), name, alert, api_key, hook_url).await
}

/// One integration script on one alert, with integratord's arguments
/// `<alert file> <api_key> <hook_url> <debug> <options file> <timeout> <retries>`
/// (OS_StrBreak keeps the empty ones, so each stays at its index).
async fn run_script_in(home: &std::path::Path, name: &str, alert: &Value, api_key: &str, hook_url: &str) -> Result<String, String> {
    if !hook_url.is_empty() {
        ps::check_url(hook_url).await?;
    }
    let script = home.join("integrations").join(crate::wazuh_manager::exe_name(name));
    if !script.is_file() {
        return Err(format!("integration script {} is not installed", script.display()));
    }
    let tmp = tempfile::Builder::new().prefix(&format!("{name}-")).suffix(".alert").tempfile().map_err(|e| e.to_string())?;
    std::fs::write(tmp.path(), format!("{alert}\n")).map_err(|e| e.to_string())?;
    // no debug, no options file; integratord's defaults: 10 s timeout, 3 retries
    let args = [tmp.path().display().to_string(), api_key.into(), hook_url.into(), String::new(), String::new(), "10".into(), "3".into()];
    let out = tokio::time::timeout(Duration::from_secs(60), tokio::process::Command::new(&script).args(&args).current_dir(home).output())
        .await
        .map_err(|_| format!("{name} timed out"))?
        .map_err(|e| format!("{name}: {e}"))?;
    if out.status.success() {
        Ok(format!("{name} integration sent"))
    } else {
        let mut msg = String::from_utf8_lossy(&out.stderr).trim().to_string();
        if msg.is_empty() {
            msg = String::from_utf8_lossy(&out.stdout).trim().to_string();
        }
        let tail: String = msg.lines().last().unwrap_or("").chars().take(300).collect();
        Err(format!("{name} exited with {}{}", out.status.code().unwrap_or(-1), if tail.is_empty() { String::new() } else { format!(": {tail}") }))
    }
}

/// The whole Wazuh alert as JSON (what Wazuh's custom integrations receive).
async fn post_alert(url: &str, alert: &Value) -> Result<String, String> {
    ps::check_url(url).await?;
    match reqwest::Client::new().post(url).json(alert).timeout(Duration::from_secs(10)).send().await {
        Ok(r) if r.status().is_success() => Ok("Webhook sent".into()),
        Ok(r) => Err(format!("HTTP error: {}", r.status())),
        Err(e) => Err(format!("Request failed: {e}")),
    }
}

/// csyslogd's message for this alert to the integration's server, in its
/// format (default, cef, json, splunk).
async fn send_syslog(ic: &Value, alert: &Value) -> Result<String, String> {
    use siem_csyslogd::config::{Syslog, CEF_CSYSLOG, DEFAULT_CSYSLOG, JSON_CSYSLOG, SPLUNK_CSYSLOG};
    let host = ic["host"].as_str().unwrap_or("").trim().to_string();
    let port = ic["port"].as_u64().or_else(|| ic["port"].as_str().and_then(|p| p.trim().parse().ok())).unwrap_or(514) as u32;
    if host.is_empty() || port == 0 || port > 65535 {
        return Err("Syslog integration needs a host and a port".into());
    }
    let format = match ic["format"].as_str().unwrap_or("default") {
        "cef" => CEF_CSYSLOG,
        "json" => JSON_CSYSLOG,
        "splunk" => SPLUNK_CSYSLOG,
        _ => DEFAULT_CSYSLOG,
    };
    ps::check_target(&host, port as u16).await?;
    let alert = alert.clone();
    tokio::task::spawn_blocking(move || {
        let mut c = Syslog { server: host.clone(), port, format, ..Default::default() };
        siem_csyslogd::resolve_hostname(&mut c.server, 1);
        let ip = siem_csyslogd::ip_of(&c.server).to_string();
        c.socket = Some(siem_csyslogd::connect_udp(port, &ip).map_err(|e| format!("syslog {host}:{port}: {}", siem_csyslogd::strerror(&e)))?);
        let hosts = siem_csyslogd::Hostnames::get();
        let sent = if format == JSON_CSYSLOG {
            let mut j = siem_cjson::parse_str(&alert.to_string()).ok_or("alert is not JSON")?;
            siem_csyslogd::alert::send_json(&mut j, &mut c, &hosts)
        } else {
            siem_csyslogd::alert::send_log(&mut alert_data(&alert), &mut c, &hosts)
        };
        if sent == 1 && c.socket.is_some() {
            Ok(format!("Syslog sent to {host}:{port}"))
        } else {
            Err(format!("Syslog to {host}:{port} failed"))
        }
    })
    .await
    .map_err(|e| e.to_string())?
}

/// The alerts.log record of a JSON alert (what csyslogd's default, CEF and
/// Splunk formats read): `** Alert <id>: - <groups>,` / `<date> <location>` /
/// `Rule: <id> (level <n>) -> '<description>'` / the fields / the log.
pub fn alert_data(a: &Value) -> siem_maild::alert::AlertData {
    let s = |v: &Value| match v {
        Value::String(x) => Some(x.clone()),
        Value::Number(n) => Some(n.to_string()),
        _ => None,
    };
    let rule = &a["rule"];
    let groups = rule["groups"].as_array().map(|g| g.iter().filter_map(|x| x.as_str()).map(|x| format!("{x},")).collect::<String>());
    // analysisd's "(agent) ip->location", or "manager->location" for its own events
    let agent = &a["agent"];
    let location = a["location"].as_str().unwrap_or("");
    let loc = if agent["id"].as_str().unwrap_or("000") == "000" {
        format!("{}->{location}", a["manager"]["name"].as_str().or(agent["name"].as_str()).unwrap_or(""))
    } else {
        format!("({}) {}->{location}", agent["name"].as_str().unwrap_or(""), agent["ip"].as_str().unwrap_or("any"))
    };
    let date = a["timestamp"]
        .as_str()
        .and_then(|t| chrono::DateTime::parse_from_str(t, "%Y-%m-%dT%H:%M:%S%.f%z").ok())
        .map(|t| t.with_timezone(&chrono::Local).format("%Y %b %d %H:%M:%S").to_string());
    let port = |v: &Value| s(v).and_then(|p| p.parse::<i32>().ok()).unwrap_or(0);
    let data = &a["data"];
    siem_maild::alert::AlertData {
        rule: s(&rule["id"]).and_then(|r| r.parse().ok()).unwrap_or(0),
        level: rule["level"].as_u64().unwrap_or(0) as u32,
        alertid: s(&a["id"]),
        date,
        location: Some(loc),
        comment: s(&rule["description"]),
        group: groups,
        srcip: s(&data["srcip"]),
        srcport: port(&data["srcport"]),
        dstip: s(&data["dstip"]),
        dstport: port(&data["dstport"]),
        user: s(&data["dstuser"]).or_else(|| s(&data["srcuser"])),
        filename: s(&a["syscheck"]["path"]),
        log: a["full_log"].as_str().map(|l| l.lines().map(String::from).collect()).unwrap_or_default(),
    }
}

/// Blocks `ip` on the agent for `hours` (also run when a held block is approved).
pub async fn block_now(state: &AppState, agent_id: &str, ip: &str, hours: u64, reason: &str) -> Result<String, String> {
    let (agent_id, ip) = (agent_id.to_string(), ip.to_string());
    if ip.parse::<std::net::IpAddr>().map_or(true, |a| !ps::is_public(a)) {
        return Err(format!("block_ip skipped: source '{ip}' is not a public address"));
    }
    if agent_id.is_empty() || agent_id == "000" || !crate::wazuh_manager::is_wazuh_agent(&agent_id).await {
        return Err(format!("block_ip skipped: agent '{agent_id}' cannot run active responses"));
    }
    let command = crate::wazuh_manager::block_ip(&agent_id, crate::agent_is_windows(state, &agent_id), &ip, hours * 3600, None).await?;
    let timeout = command.trim_start_matches(|c: char| !c.is_ascii_digit()).parse().unwrap_or(hours * 3600);
    let rec = crate::ActiveResponseRecord {
        id: format!("ar-{}", &uuid::Uuid::new_v4().to_string()[..8]),
        command: command.clone(),
        target_ip: ip.clone(),
        agent_id: agent_id.clone(),
        reason: reason.to_string(),
        triggered_at: chrono::Utc::now(),
        duration_seconds: timeout,
        status: "Active".into(),
    };
    state.active_responses.write().unwrap().insert(0, rec.clone());
    crate::persist::save_active_response(state, &rec).await;
    Ok(format!("{ip} blocked on agent {agent_id} ({command})"))
}

// ───────────────────────── running playbooks on alerts ─────────────────────────

/// A Wazuh alert as the playbook conditions see it.
pub fn context(alert: &Value, tenant: &str) -> SoarContext {
    let level = alert["rule"]["level"].as_u64().unwrap_or(0);
    let s = |v: &Value| match v {
        Value::String(x) => x.clone(),
        Value::Number(n) => n.to_string(),
        _ => String::new(),
    };
    let mut tags: Vec<String> = alert["rule"]["groups"].as_array().map(|g| g.iter().filter_map(|x| x.as_str().map(String::from)).collect()).unwrap_or_default();
    if let Some(ids) = alert["rule"]["mitre"]["id"].as_array() {
        tags.extend(ids.iter().filter_map(|x| x.as_str().map(String::from)));
    }
    let data = &alert["data"];
    SoarContext {
        score: (level as f32 * 100.0 / 15.0).min(100.0),
        severity: match level {
            12.. => "CRITICAL",
            8..=11 => "HIGH",
            4..=7 => "MEDIUM",
            _ => "LOW",
        }
        .into(),
        // threat intel: the alert's own groups, the feeds (intel.rs), or other organisations saw it too (swarm)
        is_malicious: tags.iter().any(|t| t == "threat_intel" || t == "malware" || t == "virustotal" && alert["data"]["virustotal"]["malicious"].as_str() == Some("1"))
            || !crate::intel::alert_hits(alert).is_empty()
            || crate::swarm::known(tenant, alert),
        // GeoLite2 (geomap.rs): the playbook condition "src_country"
        src_country: crate::geomap::country_code(&s(&data["srcip"])),
        tags,
        src_ip: s(&data["srcip"]),
        dst_ip: s(&data["dstip"]),
        src_port: s(&data["srcport"]).parse().unwrap_or(0),
        dst_port: s(&data["dstport"]).parse().unwrap_or(0),
        community_id: s(&alert["id"]),
        tenant_id: tenant.to_string(),
        alert: Some(alert.clone()),
    }
}

/// Enabled playbooks per tenant, re-read every 30 s or after a change.
static PLAYBOOKS: Mutex<Option<HashMap<String, (Instant, Vec<SoarNativePlaybook>)>>> = Mutex::new(None);
/// Runs per playbook in the current minute.
static RATE: Mutex<Option<HashMap<String, (Instant, u32)>>> = Mutex::new(None);

fn invalidate(tenant: &str) {
    if let Some(m) = PLAYBOOKS.lock().unwrap().as_mut() {
        m.remove(tenant);
    }
}

async fn enabled_playbooks(store: &Store, tenant: &str) -> Vec<SoarNativePlaybook> {
    if let Some((t, pbs)) = PLAYBOOKS.lock().unwrap().get_or_insert_with(HashMap::new).get(tenant) {
        if t.elapsed() < CACHE_TTL {
            return pbs.clone();
        }
    }
    let pbs: Vec<_> = store.playbooks(tenant).await.unwrap_or_default().into_iter().filter(|p| p.enabled == 1).collect();
    PLAYBOOKS.lock().unwrap().get_or_insert_with(HashMap::new).insert(tenant.to_string(), (Instant::now(), pbs.clone()));
    pbs
}

fn allow_run(pb: &SoarNativePlaybook) -> bool {
    let mut g = RATE.lock().unwrap();
    let e = g.get_or_insert_with(HashMap::new).entry(format!("{}:{}", pb.tenant_id, pb.id)).or_insert((Instant::now(), 0));
    if e.0.elapsed() >= Duration::from_secs(60) {
        *e = (Instant::now(), 0);
    }
    e.1 += 1;
    if e.1 == MAX_RUNS_PER_MINUTE + 1 {
        tracing::warn!("SOAR playbook '{}' ({}) matched more than {MAX_RUNS_PER_MINUTE} alerts this minute; the rest are skipped", pb.name, pb.tenant_id);
    }
    e.1 <= MAX_RUNS_PER_MINUTE
}

/// Runs each tenant's playbooks on its new alerts (called once they are stored).
pub fn on_alerts(state: &AppState, alerts: Vec<(Value, String)>) {
    if alerts.is_empty() || !state.db.is_connected() {
        return;
    }
    let store = store(state);
    tokio::spawn(async move { run_playbooks(&store, alerts).await });
}

pub async fn run_playbooks(store: &Store, alerts: Vec<(Value, String)>) {
    for (alert, tenant) in alerts {
        let pbs = enabled_playbooks(store, &tenant).await;
        if pbs.is_empty() {
            continue;
        }
        let ctx = context(&alert, &tenant);
        for pb in pbs.iter().filter(|pb| ps::conditions::evaluate_condition(pb, &ctx)) {
            if !allow_run(pb) {
                continue;
            }
            // blocks and isolations are high-impact actions: the policy decides first (decisions.rs)
            if let (true, Some(state)) = (matches!(pb.action_type.as_str(), "block_ip" | "isolate_host"), &store.state) {
                if let Err((status, detail)) = crate::decisions::gate_network(state, pb, &ctx).await {
                    let run = SoarPlaybookRun {
                        id: uuid::Uuid::new_v4().to_string(),
                        playbook_id: pb.id.clone(),
                        playbook_name: pb.name.clone(),
                        hit_id: ctx.community_id.clone(),
                        status,
                        detail,
                        created_at: chrono::Utc::now().to_rfc3339(),
                        tenant_id: tenant.clone(),
                    };
                    let _ = store.soar_insert_run(&run).await;
                    continue;
                }
            }
            ps::actions::execute_action(store, pb, &ctx).await;
        }
    }
}

// ───────────────────────── HTTP API (what the SOAR page calls) ─────────────────────────

fn ok_data(v: impl serde::Serialize) -> Json<Value> {
    Json(json!({ "status": "success", "data": v }))
}

fn err(e: impl std::fmt::Display) -> Json<Value> {
    Json(json!({ "status": "error", "message": e.to_string() }))
}

pub(crate) fn store(state: &AppState) -> Store {
    Store { db: state.db.clone(), state: Some(state.clone()) }
}

fn mask(mut i: Value) -> Value {
    if let Some(o) = i.as_object_mut() {
        o.remove("raw_config");
    }
    if let Some(c) = i["config"].as_object_mut() {
        for k in SECRET_KEYS {
            if c.get(k).and_then(|v| v.as_str()).is_some_and(|v| !v.is_empty()) {
                c.insert(k.into(), json!(""));
                c.insert(format!("{k}_set"), json!(true));
            }
        }
    }
    i
}

/// The submitted config, with secrets left empty taken from the stored one.
fn merge_secrets(mut new: Value, old: Option<&Value>) -> Value {
    if let (Some(n), Some(o)) = (new.as_object_mut(), old.and_then(|o| o.as_object())) {
        for k in SECRET_KEYS {
            let empty = n.get(k).and_then(|v| v.as_str()).map_or(true, str::is_empty);
            if empty {
                if let Some(v) = o.get(k).filter(|v| v.as_str().is_some_and(|s| !s.is_empty())) {
                    n.insert(k.into(), v.clone());
                }
            }
            n.remove(&format!("{k}_set"));
        }
    }
    new
}

/// Checks a submitted integration: known type, outbound targets allowed.
async fn validate_integration(kind: &str, config: &Value) -> Result<(), String> {
    for k in ["webhook_url", "hook_url", "url"] {
        if let Some(u) = config[k].as_str().filter(|u| !u.trim().is_empty()) {
            ps::check_url(u.trim()).await?;
        }
    }
    if kind == "syslog" {
        let host = config["host"].as_str().unwrap_or("").trim();
        let port = config["port"].as_u64().or_else(|| config["port"].as_str().and_then(|p| p.trim().parse().ok())).unwrap_or(514);
        if host.is_empty() || !(1..=65535).contains(&port) {
            return Err("Syslog needs a host and a port (1-65535)".into());
        }
        if !matches!(config["format"].as_str().unwrap_or("default"), "default" | "cef" | "json" | "splunk") {
            return Err("Syslog format is default, cef, json or splunk".into());
        }
        ps::check_target(host, port as u16).await?;
    }
    Ok(())
}

/// `GET /api/soar/status`: the legacy playbook list (none in the SIEM).
pub async fn get_status() -> Json<Value> {
    Json(json!({ "playbooks": [], "active_count": 0, "ndr_playbooks_count": 0 }))
}

/// `GET /api/soar/integrations`
pub async fn get_integrations(State(state): State<AppState>, Extension(ctx): Extension<AuthCtx>) -> Json<Value> {
    let list = store(&state).integrations(&ctx.scope()).await.unwrap_or_default();
    Json(json!({ "status": "ok", "integrations": list.into_iter().map(mask).collect::<Vec<_>>() }))
}

#[derive(Deserialize)]
pub struct IntegrationReq {
    #[serde(default)]
    id: String,
    #[serde(default)]
    name: String,
    #[serde(default, rename = "type")]
    kind: String,
    #[serde(default)]
    config: Value,
    #[serde(default)]
    enabled: Option<bool>,
}

/// `POST /api/soar/integrations`
pub async fn save_integration(State(state): State<AppState>, Extension(ctx): Extension<AuthCtx>, Json(r): Json<IntegrationReq>) -> Json<Value> {
    if r.name.trim().is_empty() || r.kind.trim().is_empty() {
        return err("name and type required");
    }
    let config = merge_secrets(r.config, None);
    if let Err(e) = validate_integration(&r.kind, &config).await {
        return err(e);
    }
    let id = format!("int-{}", uuid::Uuid::new_v4());
    match store(&state).put_integration(&ctx.scope(), &id, r.name.trim(), r.kind.trim(), &config, true).await {
        Ok(()) => Json(json!({ "status": "ok", "id": id, "message": format!("{} integration saved!", r.name.trim()) })),
        Err(e) => err(e),
    }
}

/// `PUT /api/soar/integrations/:id`
pub async fn update_integration(State(state): State<AppState>, Extension(ctx): Extension<AuthCtx>, Path(id): Path<String>, Json(r): Json<IntegrationReq>) -> Json<Value> {
    let tenant = ctx.scope();
    let st = store(&state);
    let Some(old) = st.integration(&tenant, &id).await else { return err("Integration not found") };
    let config = merge_secrets(r.config, Some(&old["config"]));
    let kind = if r.kind.is_empty() { old["type"].as_str().unwrap_or("").to_string() } else { r.kind };
    if let Err(e) = validate_integration(&kind, &config).await {
        return err(e);
    }
    let name = if r.name.trim().is_empty() { old["name"].as_str().unwrap_or("").to_string() } else { r.name.trim().to_string() };
    match st.put_integration(&tenant, &id, &name, &kind, &config, old["enabled"].as_bool().unwrap_or(true)).await {
        Ok(()) => Json(json!({ "status": "ok", "message": "Integration updated" })),
        Err(e) => err(e),
    }
}

/// `POST /api/soar/integrations/toggle`
pub async fn toggle_integration(State(state): State<AppState>, Extension(ctx): Extension<AuthCtx>, Json(r): Json<IntegrationReq>) -> Json<Value> {
    let tenant = ctx.scope();
    let st = store(&state);
    let Some(old) = st.integration(&tenant, &r.id).await else { return err("Integration not found") };
    match st.put_integration(&tenant, &r.id, old["name"].as_str().unwrap_or(""), old["type"].as_str().unwrap_or(""), &old["config"], r.enabled.unwrap_or(false)).await {
        Ok(()) => Json(json!({ "status": "ok", "message": "Integration updated" })),
        Err(e) => err(e),
    }
}

/// `POST /api/soar/integrations/delete` and `DELETE /api/soar/integrations/:id`
pub async fn delete_integration(State(state): State<AppState>, Extension(ctx): Extension<AuthCtx>, id: Option<Path<String>>, body: Option<Json<IntegrationReq>>) -> Json<Value> {
    let id = id.map(|p| p.0).or_else(|| body.map(|b| b.0.id)).unwrap_or_default();
    if id.is_empty() {
        return err("id required");
    }
    match store(&state).delete_row(&ctx.scope(), "soar_integrations", &id).await {
        Ok(()) => Json(json!({ "status": "ok", "message": "Integration deleted" })),
        Err(e) => err(e),
    }
}

/// `POST /api/soar/integrations/test`: a test message through the integration.
pub async fn test_integration(State(state): State<AppState>, Extension(ctx): Extension<AuthCtx>, Json(r): Json<IntegrationReq>) -> Json<Value> {
    let old = if r.id.is_empty() { None } else { store(&state).integration(&ctx.scope(), &r.id).await };
    let config = merge_secrets(r.config, old.as_ref().map(|o| &o["config"]));
    let result: Result<String, String> = async {
        validate_integration(&r.kind, &config).await?;
        let test_alert = json!({
            "timestamp": chrono::Utc::now().format("%Y-%m-%dT%H:%M:%S%.3f%z").to_string(),
            "rule": { "level": 3, "description": "Provigil SOAR test message", "id": "100000", "groups": ["soar_test"] },
            "agent": { "id": "000", "name": "provigil" }, "manager": { "name": "provigil" },
            "id": format!("{}.0", chrono::Utc::now().timestamp()), "full_log": "Provigil SOAR integration test", "location": "soar",
        });
        match r.kind.as_str() {
            "slack" => run_wazuh_script("slack", &test_alert, "", config["webhook_url"].as_str().unwrap_or("")).await,
            "shuffle" => run_wazuh_script("shuffle", &test_alert, "", config["webhook_url"].as_str().unwrap_or("")).await,
            "pagerduty" => run_wazuh_script("pagerduty", &test_alert, config["routing_key"].as_str().unwrap_or(""), "").await,
            "syslog" => send_syslog(&config, &test_alert).await,
            "webhook" | "teams" | "discord" => post_alert(config["webhook_url"].as_str().unwrap_or(""), &json!({ "text": "✅ Provigil SOAR test message" })).await,
            // VirusTotal / Maltiverse spend API quota on a lookup: only the key is checked
            "virustotal" | "maltiverse" => {
                if config["api_key"].as_str().is_some_and(|k| !k.is_empty()) { Ok(format!("{} API key set", r.kind)) } else { Err("API key missing".into()) }
            }
            "smtp" => {
                let host = config["smtp_host"].as_str().unwrap_or("").to_string();
                let port = config["smtp_port"].as_u64().or_else(|| config["smtp_port"].as_str().and_then(|p| p.parse().ok())).unwrap_or(587) as u16;
                ps::check_target(&host, port).await?;
                tokio::time::timeout(Duration::from_secs(5), tokio::net::TcpStream::connect((host.as_str(), port))).await.map_err(|_| "SMTP connect timed out".to_string())?.map_err(|e| format!("SMTP connect failed: {e}"))?;
                Ok(format!("SMTP reachable ({host}:{port})"))
            }
            _ => Ok("Configuration saved (no test for this type)".into()),
        }
    }
    .await;
    match result {
        Ok(m) => Json(json!({ "status": "ok", "message": format!("✅ {m}") })),
        Err(e) => Json(json!({ "status": "error", "message": format!("❌ {e}") })),
    }
}

/// `GET /api/soar/native/playbooks`
pub async fn get_playbooks(State(state): State<AppState>, Extension(ctx): Extension<AuthCtx>) -> Json<Value> {
    match store(&state).playbooks(&ctx.scope()).await {
        Ok(p) => ok_data(p),
        Err(e) => err(e),
    }
}

#[derive(Deserialize)]
pub struct PlaybookReq {
    #[serde(default)]
    name: String,
    #[serde(default)]
    description: String,
    enabled: Option<bool>,
    #[serde(default)]
    cond_field: String,
    #[serde(default)]
    cond_op: String,
    #[serde(default)]
    cond_value: String,
    #[serde(default)]
    action_type: String,
    #[serde(default)]
    action_config: String,
}

async fn validate_playbook(r: &PlaybookReq) -> Result<(), String> {
    if r.name.trim().is_empty() || r.action_type.trim().is_empty() {
        return Err("name and action type required".into());
    }
    let cfg: Value = serde_json::from_str(if r.action_config.is_empty() { "{}" } else { &r.action_config }).map_err(|_| "action_config must be JSON")?;
    if let Some(u) = cfg["webhook_url"].as_str().filter(|u| !u.is_empty()) {
        ps::check_url(u).await?;
    }
    Ok(())
}

/// `POST /api/soar/native/playbooks`
pub async fn create_playbook(State(state): State<AppState>, Extension(ctx): Extension<AuthCtx>, Json(r): Json<PlaybookReq>) -> Json<Value> {
    if let Err(e) = validate_playbook(&r).await {
        return err(e);
    }
    match store(&state).insert_playbook(&ctx.scope(), &uuid::Uuid::new_v4().to_string(), &r).await {
        Ok(()) => Json(json!({ "status": "success", "message": "Playbook created" })),
        Err(e) => err(e),
    }
}

/// `PUT /api/soar/native/playbooks/:id`
pub async fn update_playbook(State(state): State<AppState>, Extension(ctx): Extension<AuthCtx>, Path(id): Path<String>, Json(r): Json<PlaybookReq>) -> Json<Value> {
    if let Err(e) = validate_playbook(&r).await {
        return err(e);
    }
    match store(&state).update_playbook(&ctx.scope(), &id, &r).await {
        Ok(()) => Json(json!({ "status": "success", "message": "Playbook updated" })),
        Err(e) => err(e),
    }
}

/// `DELETE /api/soar/native/playbooks/:id`
pub async fn delete_playbook(State(state): State<AppState>, Extension(ctx): Extension<AuthCtx>, Path(id): Path<String>) -> Json<Value> {
    let tenant = ctx.scope();
    let r = store(&state).delete_row(&tenant, "soar_native_playbooks", &id).await;
    invalidate(&tenant);
    match r {
        Ok(()) => Json(json!({ "status": "success", "message": "Playbook deleted" })),
        Err(e) => err(e),
    }
}

/// `GET /api/soar/runs`: the last 100.
pub async fn get_runs(State(state): State<AppState>, Extension(ctx): Extension<AuthCtx>) -> Json<Value> {
    match store(&state).runs(&ctx.scope()).await {
        Ok(r) => ok_data(r),
        Err(e) => err(e),
    }
}

/// `GET /api/soar/cases`
pub async fn get_cases(State(state): State<AppState>, Extension(ctx): Extension<AuthCtx>) -> Json<Value> {
    match store(&state).cases(&ctx.scope()).await {
        Ok(c) => ok_data(c),
        Err(e) => err(e),
    }
}

/// `POST /api/soar/cases`
pub async fn create_case(State(state): State<AppState>, Extension(ctx): Extension<AuthCtx>, Json(p): Json<Value>) -> Json<Value> {
    let title = p["title"].as_str().unwrap_or("").trim().to_string();
    if title.is_empty() {
        return err("Title is required");
    }
    let tenant = ctx.scope();
    let st = store(&state);
    let id = uuid::Uuid::new_v4().to_string();
    let number = st.soar_next_case_number(&tenant).await;
    let g = |k: &str, d: &str| p[k].as_str().unwrap_or(d).to_string();
    let tags: Vec<String> = p["tags"].as_array().map(|a| a.iter().filter_map(|t| t.as_str().map(String::from)).collect()).unwrap_or_default();
    match st.soar_create_case(&id, &number, &title, &g("description", ""), &g("severity", "MEDIUM"), &g("priority", "P2"), "New", &g("assigned_to", ""), &g("src_ip", ""), &g("dst_ip", ""), &g("community_id", ""), &tags, &tenant).await {
        Ok(()) => Json(json!({ "status": "success", "id": id, "case_number": number })),
        Err(e) => err(e),
    }
}

/// `PUT /api/soar/cases/:id`
pub async fn update_case(State(state): State<AppState>, Extension(ctx): Extension<AuthCtx>, Path(id): Path<String>, Json(p): Json<Value>) -> Json<Value> {
    let g = |k: &str, d: &str| p[k].as_str().unwrap_or(d).to_string();
    let (title, desc, assigned, pri, sev) = (g("title", ""), g("description", ""), g("assigned_to", ""), g("priority", "P2"), g("severity", "MEDIUM"));
    let set = [("title", title.as_str()), ("description", desc.as_str()), ("assigned_to", assigned.as_str()), ("priority", pri.as_str()), ("severity", sev.as_str())];
    match store(&state).rewrite_case(&ctx.scope(), &id, &set, false).await {
        Ok(()) => Json(json!({ "status": "success", "message": "Case updated" })),
        Err(e) => err(e),
    }
}

/// `PUT /api/soar/cases/:id/status`
pub async fn update_case_status(State(state): State<AppState>, Extension(ctx): Extension<AuthCtx>, Path(id): Path<String>, Json(p): Json<Value>) -> Json<Value> {
    let status = p["status"].as_str().unwrap_or("");
    if status.is_empty() {
        return err("Status cannot be empty");
    }
    let closed = matches!(status, "Resolved" | "Closed" | "False Positive");
    match store(&state).rewrite_case(&ctx.scope(), &id, &[("status", status)], closed).await {
        Ok(()) => {
            // a closed case becomes part of the tenant's security memory
            if closed {
                if let Some(l) = crate::org_memory::from_case(&state, &ctx.scope(), &id, &ctx.username).await {
                    crate::org_memory::record(&state, &ctx.scope(), &l).await;
                }
            }
            Json(json!({ "status": "success", "message": "Status updated" }))
        }
        Err(e) => err(e),
    }
}

/// `GET /api/soar/cases/:id/comments`
pub async fn get_case_comments(State(state): State<AppState>, Extension(ctx): Extension<AuthCtx>, Path(id): Path<String>) -> Json<Value> {
    match store(&state).comments(&ctx.scope(), &id).await {
        Ok(r) => ok_data(r),
        Err(e) => err(e),
    }
}

/// `POST /api/soar/cases/:id/comments`
pub async fn add_case_comment(State(state): State<AppState>, Extension(ctx): Extension<AuthCtx>, Path(id): Path<String>, Json(p): Json<Value>) -> Json<Value> {
    let comment = p["comment"].as_str().unwrap_or("").trim();
    if comment.is_empty() {
        return err("Comment cannot be empty");
    }
    store(&state).soar_add_comment(&id, &ctx.username, comment, &ctx.scope()).await;
    Json(json!({ "status": "success", "message": "Comment added" }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn alert() -> Value {
        json!({
            "timestamp": "2026-10-23T06:15:11.123+0000",
            "rule": { "level": 10, "description": "sshd: brute force", "id": "5712", "groups": ["syslog", "sshd", "authentication_failures"], "mitre": { "id": ["T1110"] } },
            "agent": { "id": "001", "name": "web-01", "ip": "10.0.0.5" }, "manager": { "name": "mgr" },
            "id": "1729664111.1234", "full_log": "Oct 23 06:15:11 web-01 sshd[1]: Failed password\nsecond line",
            "data": { "srcip": "203.0.113.9", "srcport": "51022", "dstuser": "root" }, "location": "/var/log/auth.log",
        })
    }

    #[test]
    fn context_from_wazuh_alert() {
        let c = context(&alert(), "acme");
        assert_eq!((c.severity.as_str(), c.src_ip.as_str(), c.src_port, c.tenant_id.as_str()), ("HIGH", "203.0.113.9", 51022, "acme"));
        assert!(c.tags.contains(&"sshd".to_string()) && c.tags.contains(&"T1110".to_string()));
        assert_eq!(c.community_id, "1729664111.1234");
        let pb = |f: &str, o: &str, v: &str| SoarNativePlaybook {
            id: "p".into(), name: "p".into(), description: String::new(), enabled: 1, cond_field: f.into(), cond_op: o.into(), cond_value: v.into(),
            action_type: "slack".into(), action_config: "{}".into(), run_count: 0, last_run: None, created_at: String::new(), updated_at: String::new(), tenant_id: "acme".into(),
        };
        assert!(ps::conditions::evaluate_condition(&pb("rule_level", ">=", "10"), &c));
        assert!(ps::conditions::evaluate_condition(&pb("severity", "==", "high"), &c));
        assert!(ps::conditions::evaluate_condition(&pb("sigma_tag", "==", "T1110"), &c));
    }

    #[test]
    fn alerts_log_record_of_json_alert() {
        let d = alert_data(&alert());
        assert_eq!((d.rule, d.level), (5712, 10));
        assert_eq!(d.location.as_deref(), Some("(web-01) 10.0.0.5->/var/log/auth.log"));
        assert_eq!(d.group.as_deref(), Some("syslog,sshd,authentication_failures,"));
        assert_eq!((d.srcip.as_deref(), d.user.as_deref(), d.srcport), (Some("203.0.113.9"), Some("root"), 51022));
        assert_eq!(d.log.len(), 2);
        assert!(d.date.is_some());
        let mut m = alert();
        m["agent"]["id"] = json!("000");
        assert_eq!(alert_data(&m).location.as_deref(), Some("mgr->/var/log/auth.log"));
    }

    #[test]
    fn secrets_are_masked_and_kept() {
        let stored = json!({ "api_key": "SECRET", "webhook_url": "https://x" });
        let shown = mask(json!({ "config": stored.clone() }));
        assert_eq!(shown["config"]["api_key"], "");
        assert_eq!(shown["config"]["api_key_set"], true);
        let merged = merge_secrets(shown["config"].clone(), Some(&stored));
        assert_eq!(merged, stored);
        let changed = merge_secrets(json!({ "api_key": "NEW" }), Some(&stored));
        assert_eq!(changed["api_key"], "NEW");
    }

    /// An HTTP server for one request: its URL, and the request it got.
    fn http_once() -> (String, std::thread::JoinHandle<String>) {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://127.0.0.1:{}/hook", l.local_addr().unwrap().port());
        let server = std::thread::spawn(move || {
            use std::io::{Read, Write};
            let (mut s, _) = l.accept().unwrap();
            s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            let mut req = Vec::new();
            let mut buf = [0u8; 8192];
            // headers, then Content-Length bytes of body
            loop {
                let n = s.read(&mut buf).unwrap_or(0);
                req.extend_from_slice(&buf[..n]);
                let t = String::from_utf8_lossy(&req).to_string();
                if let Some(h) = t.find("\r\n\r\n") {
                    let len = t[..h].lines().find_map(|l| l.to_lowercase().strip_prefix("content-length:").map(|v| v.trim().parse::<usize>().unwrap_or(0))).unwrap_or(0);
                    if req.len() >= h + 4 + len {
                        break;
                    }
                }
                if n == 0 {
                    break;
                }
            }
            s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok").unwrap();
            String::from_utf8_lossy(&req).to_string()
        });
        (url, server)
    }

    fn pb_req(name: &str, field: &str, op: &str, value: &str, action: &str, config: Value, enabled: bool) -> PlaybookReq {
        PlaybookReq { name: name.into(), description: String::new(), enabled: Some(enabled), cond_field: field.into(), cond_op: op.into(), cond_value: value.into(), action_type: action.into(), action_config: config.to_string() }
    }

    /// Against the local ClickHouse, in a scratch tenant database it drops:
    /// integrations, playbooks, runs and cases, and playbooks firing on Wazuh alerts.
    /// `cargo test -p siem-api soar::tests::live_clickhouse -- --ignored`
    #[tokio::test]
    #[ignore]
    async fn live_clickhouse() {
        let db = crate::db::ClickHouseDb::init().await;
        assert!(db.is_connected(), "ClickHouse is not reachable (CLICKHOUSE_URL)");
        let tenant = format!("soartest{}", std::process::id());
        let dbname = db.provision_tenant_db(&tenant).await.unwrap();
        let store = Store { db: db.clone(), state: None };
        let result = std::panic::AssertUnwindSafe(async {
            let rx = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
            rx.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            let port = rx.local_addr().unwrap().port();
            store.put_integration(&tenant, "int-sys", "SIEM syslog", "syslog", &json!({ "host": "127.0.0.1", "port": port, "format": "json" }), true).await.unwrap();
            let (url, server) = http_once();
            store.insert_playbook(&tenant, "pb-sys", &pb_req("Forward level 10+", "rule_level", ">=", "10", "syslog", json!({}), true)).await.unwrap();
            store.insert_playbook(&tenant, "pb-hook", &pb_req("sshd to webhook", "rule_group", "==", "sshd", "webhook", json!({ "webhook_url": url }), true)).await.unwrap();
            store.insert_playbook(&tenant, "pb-case", &pb_req("Open a case", "severity", "==", "HIGH", "create_case", json!({}), true)).await.unwrap();
            store.insert_playbook(&tenant, "pb-miss", &pb_req("Other rule", "rule_id", "in", "1, 2", "syslog", json!({}), true)).await.unwrap();
            store.insert_playbook(&tenant, "pb-off", &pb_req("Disabled", "rule_level", ">=", "0", "syslog", json!({}), false)).await.unwrap();
            assert_eq!(store.playbooks(&tenant).await.unwrap().len(), 5);

            run_playbooks(&store, vec![(alert(), tenant.clone())]).await;
            let mut buf = [0u8; 65536];
            let n = rx.recv(&mut buf).expect("syslog datagram");
            assert!(String::from_utf8_lossy(&buf[..n]).contains("\"id\":\"5712\""));
            let req = server.join().unwrap();
            assert!(req.contains("\"description\":\"sshd: brute force\""), "{req}");
            let runs = store.runs(&tenant).await.unwrap();
            assert_eq!(runs.len(), 3, "{runs:?}");
            assert!(runs.iter().all(|r| r["status"] == "success"), "{runs:?}");
            assert!(runs.iter().all(|r| r["hit_id"] == "1729664111.1234"));
            let cases = store.cases(&tenant).await.unwrap();
            assert_eq!(cases.len(), 1);
            let case_id = cases[0]["id"].as_str().unwrap().to_string();
            assert_eq!((cases[0]["src_ip"].as_str(), cases[0]["severity"].as_str()), (Some("203.0.113.9"), Some("HIGH")));

            // the same source again: grouped into the open case
            let mut a2 = alert();
            a2["id"] = json!("1729664999.5678");
            a2["rule"]["groups"] = json!(["syslog"]);
            run_playbooks(&store, vec![(a2, tenant.clone())]).await;
            let _ = rx.recv(&mut buf).expect("second datagram");
            assert_eq!(store.cases(&tenant).await.unwrap().len(), 1);
            assert_eq!(store.comments(&tenant, &case_id).await.unwrap().len(), 1);

            // case updates and playbook edits are new row versions
            store.rewrite_case(&tenant, &case_id, &[("status", "Resolved")], true).await.unwrap();
            let c = store.cases(&tenant).await.unwrap();
            assert_eq!((c.len(), c[0]["status"].as_str()), (1, Some("Resolved")));
            assert!(c[0]["closed_at"].is_number());
            store.update_playbook(&tenant, "pb-sys", &pb_req("Forward level 12+", "rule_level", ">=", "12", "syslog", json!({}), true)).await.unwrap();
            let pbs = store.playbooks(&tenant).await.unwrap();
            assert_eq!(pbs.len(), 5);
            assert!(pbs.iter().any(|p| p.id == "pb-sys" && p.name == "Forward level 12+" && p.cond_value == "12"));
            // counted from the runs: the webhook ran on the first alert only, the syslog one on both
            let count = |id: &str| pbs.iter().find(|p| p.id == id).map(|p| (p.run_count, p.last_run.is_some())).unwrap();
            assert_eq!((count("pb-hook"), count("pb-sys"), count("pb-off")), ((1, true), (2, true), (0, false)));

            // a disabled integration is not used
            store.put_integration(&tenant, "int-sys", "SIEM syslog", "syslog", &json!({ "host": "127.0.0.1", "port": port, "format": "json" }), false).await.unwrap();
            let mut a3 = alert();
            a3["rule"]["level"] = json!(13);
            a3["data"]["srcip"] = json!("198.51.100.7");
            run_playbooks(&store, vec![(a3, tenant.clone())]).await;
            let runs = store.runs(&tenant).await.unwrap();
            assert!(runs.iter().any(|r| r["status"] == "failed" && r["detail"].as_str().unwrap_or("").contains("No enabled syslog")), "{runs:?}");
            store.delete_row(&tenant, "soar_native_playbooks", "pb-off").await.unwrap();
            assert_eq!(store.playbooks(&tenant).await.unwrap().len(), 4);
        });
        let r = futures_util::FutureExt::catch_unwind(result).await;
        db.root().query(&format!("DROP DATABASE IF EXISTS `{dbname}`")).execute().await.unwrap();
        if let Err(p) = r {
            std::panic::resume_unwind(p);
        }
    }

    /// The Wazuh Slack script (siem-integratord's `integrations` program) posts the
    /// alert to the hook. Needs `cargo build -p siem-integratord --bin integrations`.
    #[tokio::test]
    async fn wazuh_slack_script_posts_the_alert() {
        let bin = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/debug").join(crate::wazuh_manager::exe_name("integrations"));
        if !bin.is_file() {
            eprintln!("skipped: {} not built", bin.display());
            return;
        }
        let home = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(home.path().join("integrations")).unwrap();
        std::fs::create_dir_all(home.path().join("logs")).unwrap();
        std::fs::copy(&bin, home.path().join("integrations").join(crate::wazuh_manager::exe_name("slack"))).unwrap();
        let (url, server) = http_once();
        let r = run_script_in(home.path(), "slack", &alert(), "", &url).await;
        let req = server.join().unwrap();
        assert!(r.is_ok(), "{r:?}");
        assert!(req.starts_with("POST /hook"), "{req}");
        // the Wazuh Slack message: the rule description and the agent
        assert!(req.contains("sshd: brute force") && req.contains("web-01"), "{req}");
    }

    #[tokio::test]
    async fn syslog_json_and_default_reach_the_server() {
        let rx = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        rx.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        let port = rx.local_addr().unwrap().port();
        for (fmt, want) in [("json", "\"rule\""), ("default", "ossec: Alert Level: 10; Rule: 5712 - sshd: brute force; Location: (web-01) 10.0.0.5->/var/log/auth.log;"), ("cef", "CEF:0|Wazuh Inc.|Wazuh|v4.14.7|5712|"), ("splunk", "crit=10 id=5712 description=\"sshd: brute force\"")] {
            let r = send_syslog(&json!({ "host": "127.0.0.1", "port": port, "format": fmt }), &alert()).await;
            assert!(r.is_ok(), "{fmt}: {r:?}");
            let mut buf = [0u8; 65536];
            let n = rx.recv(&mut buf).unwrap();
            let got = String::from_utf8_lossy(&buf[..n]);
            assert!(got.contains(want), "{fmt}: {got}");
        }
    }
}
