//! Per-tenant PDF reports: a summary, charts of the alerts by severity, day, rule, agent
//! and MITRE technique, the top vulnerabilities, and what the numbers mean. Counted by
//! ClickHouse from the tenant's own tables (the console's dashboard reads the same), drawn
//! by pdf.rs. Downloaded on demand, or e-mailed on the tenant admin's schedule (daily,
//! weekly or monthly) through the platform SMTP account.
//!
//! `GET /api/v1/reports/pdf?hours=168` (the caller's tenant),
//! `GET|PUT /api/v1/reports/schedule`, `POST /api/v1/reports/schedule/send-now` (tenant admin).
//! The schedule: `siem_report_schedule` in the tenant's database (id "schedule").

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use axum::extract::{Extension, Json as JsonBody, Query, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use chrono::{DateTime, Datelike, Duration as ChronoDuration, NaiveDate, TimeZone, Utc};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::db::WindowCounts;
use crate::pdf::{Pdf, ACCENT, MUTED};
use crate::tenancy::{self, AuthCtx};
use crate::vulnerability::VulnItem;
use crate::AppState;

pub const DDL: &str = "CREATE TABLE IF NOT EXISTS siem_report_schedule (id String, doc String, version UInt64) ENGINE = ReplacingMergeTree(version) ORDER BY id";
const SCHEDULE_ID: &str = "schedule";
const CHECK_EVERY: Duration = Duration::from_secs(300);
/// A failed scheduled report is tried again after this long.
const RETRY_AFTER: Duration = Duration::from_secs(3600);
const MAX_HOURS: u32 = 90 * 24;
const MAX_RECIPIENTS: usize = 20;

const CRIT: [f32; 3] = [0.84, 0.16, 0.16];
const HIGH: [f32; 3] = [0.93, 0.45, 0.10];
const MED: [f32; 3] = [0.95, 0.70, 0.10];
const LOW: [f32; 3] = [0.55, 0.62, 0.70];

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "lowercase")]
pub enum Frequency {
    Daily,
    #[default]
    Weekly,
    Monthly,
}

impl Frequency {
    /// The period a report of this frequency covers.
    pub fn hours(self) -> u32 {
        match self {
            Frequency::Daily => 24,
            Frequency::Weekly => 7 * 24,
            Frequency::Monthly => 30 * 24,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct Schedule {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub frequency: Frequency,
    /// The hour (UTC) the report goes out: daily, Mondays (weekly) or the 1st (monthly).
    #[serde(default = "default_hour")]
    pub hour_utc: u8,
    #[serde(default)]
    pub recipients: Vec<String>,
    /// When the last scheduled report went out (unix seconds); kept by the server.
    #[serde(default)]
    pub last_sent: i64,
    #[serde(default)]
    pub updated_by: String,
    #[serde(default)]
    pub updated_at: String,
}

fn default_hour() -> u8 {
    6
}

impl Schedule {
    fn validate(mut self) -> Result<Schedule, String> {
        self.recipients = self
            .recipients
            .iter()
            .map(|r| r.trim().to_lowercase())
            .filter(|r| !r.is_empty())
            .collect();
        self.recipients.dedup();
        if self.recipients.len() > MAX_RECIPIENTS {
            return Err(format!("At most {MAX_RECIPIENTS} recipients"));
        }
        if let Some(bad) = self
            .recipients
            .iter()
            .find(|r| !crate::mail_settings::MailSettings::valid_email(r))
        {
            return Err(format!("Invalid recipient: {bad}"));
        }
        if self.hour_utc > 23 {
            return Err("The hour must be between 0 and 23".into());
        }
        if self.enabled && self.recipients.is_empty() {
            return Err("Add at least one recipient to turn scheduled reports on".into());
        }
        Ok(self)
    }
}

/// The start of the period `now` is in: today's / this Monday's / this month's 1st at the hour.
pub fn period_start(f: Frequency, hour: u8, now: DateTime<Utc>) -> DateTime<Utc> {
    let at = |d: NaiveDate| {
        Utc.from_utc_datetime(&d.and_hms_opt(hour.min(23) as u32, 0, 0).unwrap_or_default())
    };
    let today = now.date_naive();
    match f {
        Frequency::Daily => {
            let s = at(today);
            if s > now {
                s - ChronoDuration::days(1)
            } else {
                s
            }
        }
        Frequency::Weekly => {
            let s = at(today - ChronoDuration::days(today.weekday().num_days_from_monday() as i64));
            if s > now {
                s - ChronoDuration::days(7)
            } else {
                s
            }
        }
        Frequency::Monthly => {
            let first = |y: i32, m: u32| NaiveDate::from_ymd_opt(y, m, 1).unwrap_or(today);
            let s = at(first(today.year(), today.month()));
            if s > now {
                let (y, m) = if today.month() == 1 {
                    (today.year() - 1, 12)
                } else {
                    (today.year(), today.month() - 1)
                };
                at(first(y, m))
            } else {
                s
            }
        }
    }
}

/// Whether the scheduled report of the current period is still to be sent.
pub fn due(s: &Schedule, now: DateTime<Utc>) -> bool {
    s.enabled
        && !s.recipients.is_empty()
        && s.last_sent < period_start(s.frequency, s.hour_utc, now).timestamp()
}

/// Narrows a report to the alerts that match every filter set (all optional).
#[derive(Debug, Clone, Default, Deserialize)]
pub struct Filter {
    /// a rule group, e.g. `authentication_failed`
    pub group: Option<String>,
    pub rule: Option<String>,
    /// lowest rule level
    pub level: Option<String>,
    pub location: Option<String>,
    pub srcip: Option<String>,
    pub user: Option<String>,
    /// a file path (file integrity alerts)
    pub file: Option<String>,
    /// agent id or name
    pub agent: Option<String>,
    /// a breakdown of one field against another, e.g. `srcip,user`
    pub by: Option<String>,
    /// up to 100 matching alerts listed at the end
    #[serde(default)]
    pub samples: bool,
    pub title: Option<String>,
}

/// The fields a breakdown can use, as (name, ClickHouse expression).
const BREAKDOWN: [(&str, &str); 7] = [
    ("rule", "toString(rule_id)"),
    ("level", "toString(rule_level)"),
    ("agent", "agent_name"),
    ("srcip", "src_ip"),
    ("dstip", "dst_ip"),
    ("user", "user"),
    ("location", "location"),
];

fn text(v: &Option<String>) -> Option<&str> {
    v.as_deref().map(str::trim).filter(|t| !t.is_empty())
}

impl Filter {
    /// The SQL condition (the alert filters only) and its bound values, or why a filter is invalid.
    pub fn condition(&self) -> Result<(String, Vec<String>), String> {
        let mut parts = vec!["1".to_string()];
        let mut binds = Vec::new();
        for (v, sql, times) in [
            (&self.group, "has(JSONExtract(alert_json, 'rule', 'groups', 'Array(String)'), ?)", 1),
            (&self.location, "location = ?", 1),
            (&self.srcip, "src_ip = ?", 1),
            (&self.user, "user = ?", 1),
            (&self.file, "(JSONExtractString(alert_json, 'decoded', 'file_path') = ? OR JSONExtractString(alert_json, 'data', 'syscheck', 'path') = ?)", 2),
            (&self.agent, "(agent_id = ? OR agent_name = ?)", 2),
        ] {
            if let Some(t) = text(v) {
                if t.chars().count() > 256 {
                    return Err("A filter value is too long".into());
                }
                parts.push(sql.to_string());
                binds.extend(std::iter::repeat_n(t.to_string(), times));
            }
        }
        if let Some(r) = text(&self.rule) {
            let id: u32 = r
                .parse()
                .map_err(|_| "The rule filter must be a rule number".to_string())?;
            parts.push(format!("rule_id = {id}"));
        }
        if let Some(l) = text(&self.level) {
            let lvl: u8 = l
                .parse()
                .ok()
                .filter(|l| *l <= 16)
                .ok_or("The level filter must be 0 to 16")?;
            parts.push(format!("rule_level >= {lvl}"));
        }
        Ok((parts.join(" AND "), binds))
    }

    /// The breakdown's two (name, expression) pairs, when one is asked for.
    pub fn breakdown(&self) -> Result<Option<[(&'static str, &'static str); 2]>, String> {
        let Some(by) = text(&self.by) else {
            return Ok(None);
        };
        let field = |f: &str| {
            BREAKDOWN
                .iter()
                .copied()
                .find(|(n, _)| *n == f.trim())
                .ok_or(format!(
                    "Breakdown fields: {}",
                    BREAKDOWN.map(|b| b.0).join(", ")
                ))
        };
        match by.split_once(',') {
            Some((a, b)) => Ok(Some([field(a)?, field(b)?])),
            None => Err("The breakdown needs two fields, e.g. srcip,user".into()),
        }
    }

    /// The filters set, for the report, e.g. ["rule group: sshd", "level 10 or higher"].
    pub fn describe(&self) -> Vec<String> {
        let mut out = Vec::new();
        for (label, v) in [
            ("Rule group", &self.group),
            ("Rule", &self.rule),
            ("Location", &self.location),
            ("Source IP", &self.srcip),
            ("User", &self.user),
            ("File", &self.file),
            ("Agent", &self.agent),
        ] {
            if let Some(t) = text(v) {
                out.push(format!("{label}: {t}"));
            }
        }
        if let Some(l) = text(&self.level) {
            out.push(format!("Level {l} or higher"));
        }
        out
    }

    /// Whether any alert filter is set (the breakdown, samples and title do not count).
    pub fn is_filtered(&self) -> bool {
        !self.describe().is_empty()
    }
}

/// One alert listed in the report.
#[derive(clickhouse::Row, Deserialize, Debug, Clone)]
pub struct Sample {
    pub timestamp: u64,
    pub rule_level: u8,
    pub rule_id: u32,
    pub rule_description: String,
    pub agent_name: String,
    pub full_log: String,
}

/// What a report shows, counted by ClickHouse.
pub struct ReportData {
    pub tenant_name: String,
    pub title: String,
    pub from: DateTime<Utc>,
    pub to: DateTime<Utc>,
    /// The filters set, in words; empty for the whole tenant.
    pub filters: Vec<String>,
    pub counts: WindowCounts,
    /// (label, [critical, high, medium, low]) per hour or day, oldest first.
    pub buckets: Vec<(String, [u64; 4])>,
    pub rules: Vec<(u32, String, u64)>,
    /// (agent id, agent name, alerts)
    pub agents: Vec<(String, String, u64)>,
    /// (technique id, alerts, highest level)
    pub mitre: Vec<(String, u64, u8)>,
    /// Shown for the whole tenant or one agent; empty otherwise.
    pub vulns: Vec<VulnItem>,
    /// (the two field names, rows of (value 1, value 2, alerts))
    pub breakdown: Option<([String; 2], Vec<(String, String, u64)>)>,
    pub samples: Vec<Sample>,
}

#[derive(clickhouse::Row, Deserialize)]
struct LevelRow {
    rule_level: u8,
    n: u64,
}

#[derive(clickhouse::Row, Deserialize)]
struct BucketRow {
    ago: u64,
    critical: u64,
    high: u64,
    medium: u64,
    low: u64,
}

#[derive(clickhouse::Row, Deserialize)]
struct RuleRow {
    rule_id: u32,
    rule_description: String,
    n: u64,
}

#[derive(clickhouse::Row, Deserialize)]
struct AgentRow {
    agent_id: String,
    // not `agent_name`: that alias would hide the column the agent filter reads
    name: String,
    n: u64,
}

#[derive(clickhouse::Row, Deserialize)]
struct MitreRow {
    mitre_id: String,
    n: u64,
    max_level: u8,
}

#[derive(clickhouse::Row, Deserialize)]
struct PairRow {
    a: String,
    b: String,
    n: u64,
}

/// A query of the tenant's alerts: `sql` has the leading values' `?` first, then the filter's.
async fn rows<T>(
    state: &AppState,
    tenant: &str,
    sql: &str,
    lead: &[u64],
    binds: &[String],
) -> Result<Vec<T>, String>
where
    T: clickhouse::Row + for<'b> Deserialize<'b>,
{
    let mut q = state.db.tenant_client(tenant).query(sql);
    for v in lead {
        q = q.bind(*v);
    }
    for v in binds {
        q = q.bind(v.as_str());
    }
    q.fetch_all::<T>().await.map_err(|e| e.to_string())
}

/// The report of the tenant's last `hours`, as the console counts it, narrowed by `f`.
pub async fn gather(
    state: &AppState,
    tenant: &str,
    hours: u32,
    f: &Filter,
) -> Result<ReportData, String> {
    if !state.db.is_connected() {
        return Err("ClickHouse is not available".into());
    }
    let (cond, binds) = f.condition()?;
    let breakdown_fields = f.breakdown()?;
    let to = Utc::now();
    let now_ms = to.timestamp_millis().max(0) as u64;
    let since = now_ms.saturating_sub(hours as u64 * 3_600_000);

    // events are only counted for the whole tenant (filters narrow alerts)
    let mut counts = WindowCounts::default();
    if !f.is_filtered() {
        counts.events = state
            .db
            .window_counts(tenant, since, now_ms.saturating_sub(3_600_000))
            .await
            .ok_or("ClickHouse is not available")?
            .events;
    }
    for r in rows::<LevelRow>(state, tenant, &format!("SELECT rule_level, count() AS n FROM siem_alerts WHERE timestamp >= ? AND {cond} GROUP BY rule_level"), &[since], &binds).await? {
        counts.levels[r.rule_level.min(16) as usize] += r.n;
    }

    let (bucket_ms, n) = if hours <= 48 {
        (3_600_000u64, hours as usize)
    } else {
        (86_400_000u64, (hours as usize).div_ceil(24))
    };
    let mut raw = vec![[0u64; 4]; n];
    let sql = format!(
        "SELECT intDiv(? - timestamp, ?) AS ago, countIf(rule_level >= 12) AS critical, countIf(rule_level BETWEEN 8 AND 11) AS high, \
         countIf(rule_level BETWEEN 4 AND 7) AS medium, countIf(rule_level < 4) AS low \
         FROM siem_alerts WHERE timestamp > ? AND timestamp <= ? AND {cond} GROUP BY ago"
    );
    for r in rows::<BucketRow>(
        state,
        tenant,
        &sql,
        &[
            now_ms,
            bucket_ms,
            now_ms.saturating_sub(bucket_ms * n as u64),
            now_ms,
        ],
        &binds,
    )
    .await?
    {
        if let Some(slot) = (r.ago as usize)
            .checked_add(1)
            .and_then(|a| n.checked_sub(a))
        {
            raw[slot] = [r.critical, r.high, r.medium, r.low];
        }
    }
    let buckets = raw
        .into_iter()
        .enumerate()
        .map(|(i, b)| {
            let start = to - ChronoDuration::milliseconds((bucket_ms * (n - i) as u64) as i64);
            (
                if bucket_ms == 3_600_000 {
                    start.format("%H:00").to_string()
                } else {
                    start.format("%d %b").to_string()
                },
                b,
            )
        })
        .collect();

    let rules = rows::<RuleRow>(state, tenant, &format!("SELECT rule_id, rule_description, count() AS n FROM siem_alerts WHERE timestamp >= ? AND {cond} GROUP BY rule_id, rule_description ORDER BY n DESC LIMIT 10"), &[since], &binds)
        .await?
        .into_iter()
        .map(|r| (r.rule_id, r.rule_description, r.n))
        .collect();
    let agents = rows::<AgentRow>(state, tenant, &format!("SELECT agent_id, any(agent_name) AS name, count() AS n FROM siem_alerts WHERE timestamp >= ? AND {cond} GROUP BY agent_id ORDER BY n DESC LIMIT 10"), &[since], &binds)
        .await?
        .into_iter()
        .map(|r| (r.agent_id, r.name, r.n))
        .collect();
    let mitre = rows::<MitreRow>(state, tenant, &format!("SELECT mitre_id, count() AS n, max(rule_level) AS max_level FROM siem_alerts WHERE timestamp >= ? AND mitre_id != '' AND {cond} GROUP BY mitre_id ORDER BY n DESC LIMIT 10"), &[since], &binds)
        .await?
        .into_iter()
        .map(|r| (r.mitre_id, r.n, r.max_level))
        .collect();

    let breakdown = match breakdown_fields {
        Some([(na, ea), (nb, eb)]) => {
            let sql = format!("SELECT {ea} AS a, {eb} AS b, count() AS n FROM siem_alerts WHERE timestamp >= ? AND {cond} GROUP BY a, b ORDER BY n DESC LIMIT 25");
            let r = rows::<PairRow>(state, tenant, &sql, &[since], &binds).await?;
            Some((
                [na.to_string(), nb.to_string()],
                r.into_iter().map(|r| (r.a, r.b, r.n)).collect(),
            ))
        }
        None => None,
    };
    let samples = if f.samples {
        rows::<Sample>(state, tenant, &format!("SELECT timestamp, rule_level, rule_id, rule_description, agent_name, full_log FROM siem_alerts WHERE timestamp >= ? AND {cond} ORDER BY timestamp DESC LIMIT 100"), &[since], &binds).await?
    } else {
        Vec::new()
    };

    // vulnerabilities are not alerts: shown for the whole tenant, or for the one agent asked for
    let only_agent = f.group.is_none()
        && f.rule.is_none()
        && f.level.is_none()
        && f.location.is_none()
        && f.srcip.is_none()
        && f.user.is_none()
        && f.file.is_none();
    let vulns = if only_agent {
        let mut v = crate::vulnerability::current(state, tenant, None).await?;
        if let Some(a) = text(&f.agent) {
            v.retain(|x| x.agent_id == a || x.agent_name == a);
        }
        v
    } else {
        Vec::new()
    };
    let title = text(&f.title)
        .map(|t| t.chars().take(120).collect())
        .unwrap_or_else(|| "Security report".to_string());
    Ok(ReportData {
        tenant_name: crate::alert_mail::tenant_name(state, tenant),
        title,
        from: to - ChronoDuration::hours(hours as i64),
        to,
        filters: f.describe(),
        counts,
        buckets,
        rules,
        agents,
        mitre,
        vulns,
        breakdown,
        samples,
    })
}

fn sev_rank(s: &str) -> u8 {
    match s {
        "Critical" => 0,
        "High" => 1,
        "Medium" => 2,
        "Low" => 3,
        _ => 4,
    }
}

fn pct(n: u64, of: u64) -> String {
    if of == 0 {
        "0".into()
    } else {
        format!("{:.0}", n as f64 * 100.0 / of as f64)
    }
}

fn n(v: u64) -> String {
    let s = v.to_string();
    let mut o = String::new();
    for (i, c) in s.chars().enumerate() {
        if i > 0 && (s.len() - i) % 3 == 0 {
            o.push(',');
        }
        o.push(c);
    }
    o
}

/// What the numbers say, in plain sentences.
pub fn summary_text(d: &ReportData) -> Vec<String> {
    let c = &d.counts;
    let total = c.alerts();
    let mut out = vec![if d.filters.is_empty() {
        format!(
            "In this period {} had {} alerts from {} events: {} critical (level 12 or higher) and {} high (level 8 to 11).",
            d.tenant_name,
            n(total),
            n(c.events),
            n(c.critical()),
            n(c.high())
        )
    } else {
        format!(
            "In this period {} had {} alerts matching the filters ({}): {} critical (level 12 or higher) and {} high (level 8 to 11).",
            d.tenant_name,
            n(total),
            d.filters.join("; "),
            n(c.critical()),
            n(c.high())
        )
    }];
    if c.critical() > 0 {
        out.push("Review the critical alerts first: they are the attacks and failures most likely to cause damage.".into());
    } else if total > 0 {
        out.push("There were no critical alerts in this period.".into());
    }
    if let Some((id, desc, k)) = d.rules.first() {
        out.push(format!(
            "The most frequent alert was \"{desc}\" (rule {id}), {} times: {}% of all alerts.",
            n(*k),
            pct(*k, total)
        ));
    }
    if let Some((id, name, k)) = d.agents.first() {
        out.push(format!(
            "The agent with the most alerts was {name} ({id}), with {} ({}%).",
            n(*k),
            pct(*k, total)
        ));
    }
    let crit = d.vulns.iter().filter(|v| v.severity == "Critical").count();
    let high = d.vulns.iter().filter(|v| v.severity == "High").count();
    if !d.filters.is_empty() && d.vulns.is_empty() {
        // a filtered report lists no vulnerabilities
    } else if d.vulns.is_empty() {
        out.push("No open vulnerabilities were found on the agents.".into());
    } else {
        let hosts = d
            .vulns
            .iter()
            .map(|v| &v.agent_id)
            .collect::<std::collections::HashSet<_>>()
            .len();
        out.push(format!(
            "{} open vulnerabilities on {hosts} agent(s), {crit} critical and {high} high. Update the critical ones first: the table lists the version that fixes each.",
            n(d.vulns.len() as u64)
        ));
    }
    out
}

/// The report as a PDF file.
pub fn render(d: &ReportData) -> Vec<u8> {
    let c = &d.counts;
    let period = format!(
        "{} to {} (UTC)",
        d.from.format("%d %b %Y %H:%M"),
        d.to.format("%d %b %Y %H:%M")
    );
    let mut p = Pdf::new(&format!(
        "ProVigil security report - {} - generated {}",
        d.tenant_name,
        d.to.format("%Y-%m-%d %H:%M UTC")
    ));
    p.title(&d.title, &format!("{}   |   {period}", d.tenant_name));
    if !d.filters.is_empty() {
        p.paragraph(&format!("Filters: {}.", d.filters.join("; ")));
    }

    p.heading("Summary");
    let crit_v = d.vulns.iter().filter(|v| v.severity == "Critical").count() as u64;
    p.tiles(&[
        ("Alerts", n(c.alerts()), ACCENT),
        ("Critical (12+)", n(c.critical()), CRIT),
        ("High (8-11)", n(c.high()), HIGH),
        if d.filters.is_empty() {
            ("Events", n(c.events), MUTED)
        } else {
            ("Filtered", "yes".into(), MUTED)
        },
        ("Medium (4-7)", n(c.medium()), MED),
        (
            "Low (0-3)",
            n(c.alerts() - c.critical() - c.high() - c.medium()),
            LOW,
        ),
        ("Agents with alerts", n(d.agents.len() as u64), ACCENT),
        ("Critical vulnerabilities", n(crit_v), CRIT),
    ]);
    for s in summary_text(d) {
        p.paragraph(&s);
    }

    p.heading("Alerts by severity");
    let low = c.alerts() - c.critical() - c.high() - c.medium();
    p.bars(&[
        ("Critical (level 12-16)".into(), c.critical(), CRIT),
        ("High (level 8-11)".into(), c.high(), HIGH),
        ("Medium (level 4-7)".into(), c.medium(), MED),
        ("Low (level 0-3)".into(), low, LOW),
    ]);

    p.heading(
        if d.buckets.len() <= 48 && d.to - d.from <= ChronoDuration::hours(48) {
            "Alerts per hour"
        } else {
            "Alerts per day"
        },
    );
    // drawn bottom-up: low, medium, high, critical
    let cols: Vec<(String, Vec<u64>)> = d
        .buckets
        .iter()
        .map(|(l, b)| (l.clone(), vec![b[3], b[2], b[1], b[0]]))
        .collect();
    p.columns(
        &cols,
        &[LOW, MED, HIGH, CRIT],
        &["Low", "Medium", "High", "Critical"],
    );

    p.heading("Top rules");
    p.bars(
        &d.rules
            .iter()
            .map(|(id, desc, k)| (format!("{id}  {desc}"), *k, ACCENT))
            .collect::<Vec<_>>(),
    );

    p.heading("Agents with the most alerts");
    p.bars(
        &d.agents
            .iter()
            .map(|(id, name, k)| (format!("{name} ({id})"), *k, ACCENT))
            .collect::<Vec<_>>(),
    );

    if !d.mitre.is_empty() {
        p.heading("MITRE ATT&CK techniques");
        p.bars(
            &d.mitre
                .iter()
                .map(|(id, k, lvl)| {
                    (
                        id.clone(),
                        *k,
                        if *lvl >= 12 {
                            CRIT
                        } else if *lvl >= 8 {
                            HIGH
                        } else {
                            ACCENT
                        },
                    )
                })
                .collect::<Vec<_>>(),
        );
    }

    if let Some(([a, b], pairs)) = &d.breakdown {
        p.heading(&format!("Breakdown: {a} by {b}"));
        if pairs.is_empty() {
            p.paragraph("No alerts in this period.");
        } else {
            let rows: Vec<Vec<String>> = pairs
                .iter()
                .map(|(x, y, k)| {
                    vec![
                        if x.is_empty() { "-".into() } else { x.clone() },
                        if y.is_empty() { "-".into() } else { y.clone() },
                        n(*k),
                    ]
                })
                .collect();
            p.table(
                &[a.as_str(), b.as_str(), "Alerts"],
                &[0.42, 0.42, 0.16],
                &rows,
            );
        }
    }

    if !d.filters.is_empty() && d.vulns.is_empty() {
        return finish_report(p, d);
    }
    p.heading("Top vulnerabilities");
    let mut v: Vec<&VulnItem> = d.vulns.iter().collect();
    v.sort_by(|a, b| {
        sev_rank(&a.severity)
            .cmp(&sev_rank(&b.severity))
            .then(b.cvss_score.total_cmp(&a.cvss_score))
    });
    if v.is_empty() {
        p.paragraph("No open vulnerabilities.");
    } else {
        let by_sev = |s: &str| d.vulns.iter().filter(|x| x.severity == s).count() as u64;
        p.bars(&[
            ("Critical".into(), by_sev("Critical"), CRIT),
            ("High".into(), by_sev("High"), HIGH),
            ("Medium".into(), by_sev("Medium"), MED),
            ("Low".into(), by_sev("Low"), LOW),
        ]);
        let rows: Vec<Vec<String>> = v
            .iter()
            .take(15)
            .map(|x| {
                vec![
                    x.cve.clone(),
                    x.severity.clone(),
                    if x.cvss_score >= 0.0 {
                        format!("{:.1}", x.cvss_score)
                    } else {
                        "-".into()
                    },
                    format!("{} {}", x.package_name, x.installed_version),
                    x.fixed_version.clone().unwrap_or_else(|| "-".into()),
                    format!("{} ({})", x.agent_name, x.agent_id),
                ]
            })
            .collect();
        p.table(
            &["CVE", "Severity", "CVSS", "Package", "Fixed in", "Agent"],
            &[0.17, 0.10, 0.07, 0.27, 0.14, 0.25],
            &rows,
        );
        if v.len() > 15 {
            p.paragraph(&format!(
                "{} more on the console's Vulnerabilities page.",
                n(v.len() as u64 - 15)
            ));
        }
    }

    finish_report(p, d)
}

/// The sample alerts (when asked for) and the explanations, then the file.
fn finish_report(mut p: Pdf, d: &ReportData) -> Vec<u8> {
    if !d.samples.is_empty() {
        p.heading(&format!("Latest matching alerts ({})", d.samples.len()));
        let rows: Vec<Vec<String>> = d
            .samples
            .iter()
            .map(|a| {
                let t = DateTime::from_timestamp_millis(a.timestamp as i64)
                    .map(|t| t.format("%d %b %H:%M:%S").to_string())
                    .unwrap_or_default();
                vec![
                    t,
                    a.rule_level.to_string(),
                    format!("{} {}", a.rule_id, a.rule_description),
                    a.agent_name.clone(),
                    a.full_log.replace(['\n', '\r', '\t'], " "),
                ]
            })
            .collect();
        p.table(
            &["Time", "Level", "Rule", "Agent", "Log"],
            &[0.15, 0.07, 0.30, 0.14, 0.34],
            &rows,
        );
    }
    p.heading("How to read this report");
    for s in [
        "Every alert has a level from 0 to 16, set by the rule that raised it. Critical (12 to 16): an attack or failure that needs action now. High (8 to 11): suspicious activity to review the same day. Medium (4 to 7): worth a look, often policy or configuration issues. Low (0 to 3): information.",
        "Top rules shows which detections fire most: a rule that fires very often on harmless activity can be tuned or suppressed. Agents with the most alerts shows which computers to look at first.",
        "MITRE ATT&CK techniques maps the alerts to the attacker behaviour they suggest (for example T1110, brute force). Vulnerabilities are the installed programs with known security flaws (CVE); CVSS scores them from 0 to 10.",
        "The numbers are counted from this organisation's stored alerts and vulnerability results, the same data the console's dashboard shows for the same period.",
    ] {
        p.paragraph(s);
    }
    p.finish()
}

fn err(code: StatusCode, m: impl Into<String>) -> Response {
    (
        code,
        Json(json!({ "status": "error", "message": m.into() })),
    )
        .into_response()
}

fn file_name(tenant: &str, to: DateTime<Utc>) -> String {
    let t: String = tenant
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
        .collect();
    format!("provigil-report-{t}-{}.pdf", to.format("%Y-%m-%d"))
}

#[derive(Deserialize)]
pub struct PdfQuery {
    pub hours: Option<u32>,
    pub group: Option<String>,
    pub rule: Option<String>,
    pub level: Option<String>,
    pub location: Option<String>,
    pub srcip: Option<String>,
    pub user: Option<String>,
    pub file: Option<String>,
    pub agent: Option<String>,
    pub by: Option<String>,
    pub samples: Option<String>,
    pub title: Option<String>,
}

/// `GET /api/v1/reports/pdf?hours=168` and the optional filters `group`, `rule`, `level` (lowest),
/// `location`, `srcip`, `user`, `file`, `agent`; `by=srcip,user` (a breakdown), `samples=1`, `title`.
pub async fn get_pdf(
    State(state): State<AppState>,
    Extension(ctx): Extension<AuthCtx>,
    Query(q): Query<PdfQuery>,
) -> Response {
    let tenant = ctx.scope();
    let hours = q
        .hours
        .unwrap_or(crate::history::DEFAULT_HOURS)
        .clamp(1, MAX_HOURS);
    let f = Filter {
        group: q.group,
        rule: q.rule,
        level: q.level,
        location: q.location,
        srcip: q.srcip,
        user: q.user,
        file: q.file,
        agent: q.agent,
        by: q.by,
        samples: matches!(q.samples.as_deref(), Some("1" | "true" | "yes")),
        title: q.title,
    };
    // a bad filter is the caller's mistake, not ClickHouse's
    if let Err(e) = f.condition().and_then(|_| f.breakdown()) {
        return err(StatusCode::BAD_REQUEST, e);
    }
    let d = match gather(&state, &tenant, hours, &f).await {
        Ok(d) => d,
        Err(e) => {
            return err(
                StatusCode::SERVICE_UNAVAILABLE,
                format!("Report not made: {e}"),
            )
        }
    };
    let name = file_name(&tenant, d.to);
    let pdf = tokio::task::spawn_blocking(move || render(&d))
        .await
        .unwrap_or_default();
    (
        [
            (header::CONTENT_TYPE, "application/pdf".to_string()),
            (
                header::CONTENT_DISPOSITION,
                format!("attachment; filename=\"{name}\""),
            ),
        ],
        pdf,
    )
        .into_response()
}

pub async fn load(state: &AppState, tenant: &str) -> Result<Schedule, String> {
    let rows = state
        .db
        .tenant_client(tenant)
        .query("SELECT doc FROM siem_report_schedule FINAL WHERE id = ? LIMIT 1")
        .bind(SCHEDULE_ID)
        .fetch_all::<String>()
        .await
        .map_err(|e| e.to_string())?;
    Ok(rows
        .first()
        .and_then(|d| serde_json::from_str(d).ok())
        .unwrap_or_default())
}

async fn store(state: &AppState, tenant: &str, s: &Schedule) -> Result<(), String> {
    let version = Utc::now().timestamp_micros().max(0) as u64;
    state
        .db
        .tenant_client(tenant)
        .query("INSERT INTO siem_report_schedule (id, doc, version) VALUES (?, ?, ?)")
        .bind(SCHEDULE_ID)
        .bind(serde_json::to_string(s).unwrap_or_default())
        .bind(version)
        .execute()
        .await
        .map_err(|e| e.to_string())
}

/// Makes the report of the schedule's period and e-mails it to its recipients.
async fn send_report(state: &AppState, tenant: &str, s: &Schedule) -> Result<usize, String> {
    if s.recipients.is_empty() {
        return Err("Save at least one recipient first".into());
    }
    let d = gather(state, tenant, s.frequency.hours(), &Filter::default()).await?;
    let c = &d.counts;
    let mut text = format!(
        "ProVigil security report for {}, {} to {} (UTC).\n\nAlerts: {} (critical {}, high {})\nEvents: {}\nOpen vulnerabilities: {}\n\n",
        d.tenant_name,
        d.from.format("%d %b %Y"),
        d.to.format("%d %b %Y"),
        n(c.alerts()),
        n(c.critical()),
        n(c.high()),
        n(c.events),
        n(d.vulns.len() as u64)
    );
    text.push_str(&summary_text(&d).join("\n"));
    text.push_str("\n\nThe full report with charts is attached (PDF).\n");
    let subject = format!(
        "ProVigil security report - {} - {}",
        d.tenant_name,
        d.to.format("%d %b %Y")
    );
    let name = file_name(tenant, d.to);
    let pdf = tokio::task::spawn_blocking(move || render(&d))
        .await
        .map_err(|e| e.to_string())?;
    crate::alert_mail::send(
        state,
        s.recipients.clone(),
        subject,
        text,
        Some((name, "application/pdf", pdf)),
    )
    .await?;
    Ok(s.recipients.len())
}

/// `GET /api/v1/reports/schedule`
pub async fn get_schedule(
    State(state): State<AppState>,
    Extension(ctx): Extension<AuthCtx>,
) -> Response {
    let tenant = ctx.scope();
    if !ctx.can_manage(&tenant) {
        return tenancy::forbidden();
    }
    let smtp_ready = crate::mail_settings::load(&state)
        .await
        .and_then(|m| m.smtp_auth())
        .is_some();
    match load(&state, &tenant).await {
        Ok(s) => {
            Json(json!({ "status": "ok", "schedule": s, "smtp_ready": smtp_ready })).into_response()
        }
        Err(e) => err(
            StatusCode::SERVICE_UNAVAILABLE,
            format!("Schedule not read: {e}"),
        ),
    }
}

/// `PUT /api/v1/reports/schedule`
pub async fn put_schedule(
    State(state): State<AppState>,
    Extension(ctx): Extension<AuthCtx>,
    JsonBody(body): JsonBody<Schedule>,
) -> Response {
    let tenant = ctx.scope();
    if !ctx.can_manage(&tenant) {
        return tenancy::forbidden();
    }
    let mut s = match body.validate() {
        Ok(s) => s,
        Err(m) => return err(StatusCode::BAD_REQUEST, m),
    };
    let old = match load(&state, &tenant).await {
        Ok(o) => o,
        Err(e) => {
            return err(
                StatusCode::SERVICE_UNAVAILABLE,
                format!("Schedule not read: {e}"),
            )
        }
    };
    // the server keeps when it last sent; turning it on starts with the next period, not now
    s.last_sent = if s.enabled && !old.enabled {
        Utc::now().timestamp()
    } else {
        old.last_sent
    };
    s.updated_by = ctx.username.clone();
    s.updated_at = Utc::now().to_rfc3339();
    if let Err(e) = store(&state, &tenant, &s).await {
        return err(
            StatusCode::SERVICE_UNAVAILABLE,
            format!("Schedule not saved: {e}"),
        );
    }
    tracing::info!(
        "report schedule of tenant {tenant} saved by {}: {} {:?} at {}:00 UTC",
        ctx.username,
        if s.enabled { "on" } else { "off" },
        s.frequency,
        s.hour_utc
    );
    Json(json!({ "status": "ok", "schedule": s })).into_response()
}

/// `POST /api/v1/reports/schedule/send-now`: the report of the schedule's period, e-mailed now.
pub async fn send_now(
    State(state): State<AppState>,
    Extension(ctx): Extension<AuthCtx>,
) -> Response {
    let tenant = ctx.scope();
    if !ctx.can_manage(&tenant) {
        return tenancy::forbidden();
    }
    let s = match load(&state, &tenant).await {
        Ok(s) => s,
        Err(e) => {
            return err(
                StatusCode::SERVICE_UNAVAILABLE,
                format!("Schedule not read: {e}"),
            )
        }
    };
    match send_report(&state, &tenant, &s).await {
        Ok(k) => Json(
            json!({ "status": "ok", "message": format!("Report e-mailed to {k} recipient(s)") }),
        )
        .into_response(),
        Err(e) => err(StatusCode::BAD_GATEWAY, e),
    }
}

static FAILED: Mutex<Option<HashMap<String, Instant>>> = Mutex::new(None);

/// Every 5 minutes: each tenant whose scheduled report is due gets it.
pub fn spawn(state: AppState) {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(CHECK_EVERY).await;
            if !state.db.is_connected() {
                continue;
            }
            for tenant in crate::predictions::tenant_ids(&state) {
                let Ok(s) = load(&state, &tenant).await else {
                    continue;
                };
                let now = Utc::now();
                if !due(&s, now) {
                    continue;
                }
                if FAILED
                    .lock()
                    .unwrap()
                    .get_or_insert_with(HashMap::new)
                    .get(&tenant)
                    .is_some_and(|t| t.elapsed() < RETRY_AFTER)
                {
                    continue;
                }
                // one siem-api sends it when several share Valkey
                let key = format!(
                    "provigil:report:{tenant}:{}",
                    period_start(s.frequency, s.hour_utc, now).timestamp()
                );
                if tenancy::valkey_ok().await
                    && !tenancy::valkey_lock(&key, RETRY_AFTER.as_secs()).await
                {
                    continue;
                }
                match send_report(&state, &tenant, &s).await {
                    Ok(k) => {
                        tracing::info!(
                            "scheduled report of tenant {tenant} e-mailed to {k} recipient(s)"
                        );
                        FAILED
                            .lock()
                            .unwrap()
                            .get_or_insert_with(HashMap::new)
                            .remove(&tenant);
                        // re-read: the admin may have edited the schedule meanwhile
                        let mut latest = load(&state, &tenant).await.unwrap_or(s);
                        latest.last_sent = now.timestamp();
                        if let Err(e) = store(&state, &tenant, &latest).await {
                            tracing::warn!(
                                "report schedule of tenant {tenant}: last sent time not saved: {e}"
                            );
                        }
                    }
                    Err(e) => {
                        tracing::warn!("scheduled report of tenant {tenant} not sent (tried again in an hour): {e}");
                        FAILED
                            .lock()
                            .unwrap()
                            .get_or_insert_with(HashMap::new)
                            .insert(tenant.clone(), Instant::now());
                    }
                }
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(s: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(s).unwrap().with_timezone(&Utc)
    }

    #[test]
    fn periods() {
        // Wednesday 4 Nov 2026
        let now = t("2026-11-04T05:30:00Z");
        assert_eq!(
            period_start(Frequency::Daily, 6, now),
            t("2026-11-03T06:00:00Z")
        );
        assert_eq!(
            period_start(Frequency::Daily, 5, now),
            t("2026-11-04T05:00:00Z")
        );
        assert_eq!(
            period_start(Frequency::Weekly, 6, now),
            t("2026-11-02T06:00:00Z")
        );
        assert_eq!(
            period_start(Frequency::Monthly, 6, now),
            t("2026-11-01T06:00:00Z")
        );
        assert_eq!(
            period_start(Frequency::Monthly, 6, t("2027-01-01T03:00:00Z")),
            t("2026-12-01T06:00:00Z")
        );
        assert_eq!(
            period_start(Frequency::Weekly, 6, t("2026-11-02T05:00:00Z")),
            t("2026-10-26T06:00:00Z")
        );
    }

    #[test]
    fn due_once_per_period() {
        let mut s = Schedule {
            enabled: true,
            frequency: Frequency::Daily,
            hour_utc: 6,
            recipients: vec!["a@b.io".into()],
            ..Default::default()
        };
        s.last_sent = t("2026-11-03T06:02:00Z").timestamp();
        assert!(!due(&s, t("2026-11-04T05:59:00Z")));
        assert!(due(&s, t("2026-11-04T06:00:00Z")));
        s.last_sent = t("2026-11-04T06:05:00Z").timestamp();
        assert!(!due(&s, t("2026-11-04T23:00:00Z")));
        assert!(!due(
            &Schedule {
                enabled: false,
                ..s.clone()
            },
            t("2026-11-09T07:00:00Z")
        ));
        assert!(Schedule {
            recipients: vec![],
            ..s.clone()
        }
        .validate()
        .is_err());
        assert!(Schedule { hour_utc: 24, ..s }.validate().is_err());
    }

    fn data() -> ReportData {
        let mut counts = WindowCounts {
            events: 12_345,
            ..Default::default()
        };
        counts.levels[3] = 50;
        counts.levels[5] = 30;
        counts.levels[10] = 15;
        counts.levels[12] = 5;
        let vuln = |cve: &str, sev: &str, score: f64| VulnItem {
            cve: cve.into(),
            title: String::new(),
            severity: sev.into(),
            cvss_score: score,
            package_name: "openssl".into(),
            installed_version: "1.1.1".into(),
            fixed_version: Some("1.1.1w".into()),
            agent_id: "049".into(),
            agent_name: "pc-49".into(),
            status: "active".into(),
            detected_at: String::new(),
            description: String::new(),
            reference: String::new(),
            category: String::new(),
            os: String::new(),
            package_path: String::new(),
            published_at: String::new(),
            needs_review: false,
        };
        ReportData {
            tenant_name: "Acme".into(),
            title: "Security report".into(),
            filters: Vec::new(),
            breakdown: None,
            samples: Vec::new(),
            from: t("2026-10-28T00:00:00Z"),
            to: t("2026-11-04T00:00:00Z"),
            counts,
            buckets: (0..7)
                .map(|i| (format!("{:02} Nov", i + 1), [1, 2, 3, i]))
                .collect(),
            rules: vec![
                (
                    5710,
                    "sshd: attempt to login using a non-existent user".into(),
                    40,
                ),
                (60106, "Windows logon success".into(), 20),
            ],
            agents: vec![
                ("049".into(), "pc-49".into(), 70),
                ("044".into(), "srv-44".into(), 30),
            ],
            mitre: vec![("T1110".into(), 40, 10)],
            vulns: vec![
                vuln("CVE-2023-0001", "High", 7.5),
                vuln("CVE-2024-0002", "Critical", 9.8),
            ],
        }
    }

    #[test]
    fn summary_matches_the_numbers() {
        let s = summary_text(&data()).join(" ");
        assert!(
            s.contains("Acme had 100 alerts from 12,345 events: 5 critical"),
            "{s}"
        );
        assert!(s.contains("15 high"));
        assert!(s.contains("rule 5710), 40 times: 40% of all alerts"));
        assert!(s.contains("pc-49 (049), with 70 (70%)"));
        assert!(s.contains("2 open vulnerabilities on 1 agent(s), 1 critical and 1 high"));
    }

    #[test]
    fn filters_make_safe_sql() {
        let f = Filter {
            group: Some("sshd".into()),
            rule: Some(" 5710 ".into()),
            level: Some("10".into()),
            agent: Some("pc-49".into()),
            file: Some("/etc/passwd".into()),
            ..Default::default()
        };
        let (sql, binds) = f.condition().unwrap();
        assert_eq!(sql.matches('?').count(), binds.len(), "{sql}");
        assert!(sql.contains("rule_id = 5710") && sql.contains("rule_level >= 10"));
        assert_eq!(
            binds,
            vec!["sshd", "/etc/passwd", "/etc/passwd", "pc-49", "pc-49"]
        );
        // values are bound, never written into the SQL
        let evil = Filter {
            user: Some("x' OR 1=1 --".into()),
            ..Default::default()
        };
        assert!(!evil.condition().unwrap().0.contains("OR 1=1"));
        assert!(Filter {
            rule: Some("1; DROP".into()),
            ..Default::default()
        }
        .condition()
        .is_err());
        assert!(Filter {
            level: Some("17".into()),
            ..Default::default()
        }
        .condition()
        .is_err());
        assert_eq!(
            Filter {
                by: Some("srcip, user".into()),
                ..Default::default()
            }
            .breakdown()
            .unwrap()
            .unwrap()[1],
            ("user", "user")
        );
        assert!(Filter {
            by: Some("srcip,password".into()),
            ..Default::default()
        }
        .breakdown()
        .is_err());
        assert!(Filter {
            by: Some("srcip".into()),
            ..Default::default()
        }
        .breakdown()
        .is_err());
        assert!(!Filter {
            samples: true,
            by: Some("srcip,user".into()),
            ..Default::default()
        }
        .is_filtered());
        assert_eq!(
            Filter::default().condition().unwrap(),
            ("1".to_string(), Vec::new())
        );
    }

    #[test]
    fn filtered_pdf_has_breakdown_and_samples() {
        let mut d = data();
        d.title = "SSH report".into();
        d.filters = vec!["Rule group: sshd".into()];
        d.vulns.clear();
        d.breakdown = Some((
            ["srcip".into(), "user".into()],
            vec![("203.0.113.9".into(), "root".into(), 12)],
        ));
        d.samples = vec![Sample {
            timestamp: 1_762_000_000_000,
            rule_level: 10,
            rule_id: 5712,
            rule_description: "sshd: brute force".into(),
            agent_name: "pc-49".into(),
            full_log: "Failed password for root".into(),
        }];
        let s = String::from_utf8_lossy(&render(&d)).to_string();
        assert!(s.contains("(SSH report)") && s.contains("(Filters: Rule group: sshd.)"));
        assert!(
            s.contains("(Breakdown: srcip by user)")
                && s.contains("(203.0.113.9)")
                && s.contains("(root)")
        );
        assert!(
            s.contains("(Latest matching alerts \\(1\\))")
                && s.contains("(Failed password for root)")
        );
        assert!(!s.contains("(Top vulnerabilities)"));
        assert!(summary_text(&d)[0].contains("alerts matching the filters (Rule group: sshd)"));
    }

    #[test]
    fn renders_a_pdf() {
        let b = render(&data());
        let s = String::from_utf8_lossy(&b);
        assert!(s.starts_with("%PDF-1.4") && s.ends_with("%%EOF\n"));
        // critical first in the vulnerability table
        let (c, h) = (
            s.find("(CVE-2024-0002)").unwrap(),
            s.find("(CVE-2023-0001)").unwrap(),
        );
        assert!(c < h);
        assert!(s.contains("(Security report)") && s.contains("(How to read this report)"));
        assert_eq!(
            file_name("acme corp/../x", t("2026-11-04T00:00:00Z")),
            "provigil-report-acmecorpx-2026-11-04.pdf"
        );
    }
}
