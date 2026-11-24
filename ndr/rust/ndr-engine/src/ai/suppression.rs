//! "Hide alerts like this": a preview of what a suppression would hide, and the guarded apply.
//!
//! The analyst opens an AI analysis and can hide either just that session or every alert of the same
//! kind (same source and tag, the suppression the Suppress button on the alerts page creates).
//! Before anything is hidden they see how many past alerts it would take away, by severity, and
//! whether any of them must stay visible. The server decides that, not the browser:
//!
//!   * an alert that matches threat intel, triggered a detection rule, is HIGH/CRITICAL or carries an
//!     alarm tag can never be hidden from here (the same guard rails as Alert Triage);
//!   * if the AI's stored verdict for the session is TRUE_POSITIVE it cannot be hidden either;
//!   * a sensor-restricted analyst cannot hide a pattern that also occurs on sensors they do not have;
//!   * a suppression is only ever created by an explicit apply call, for 1 to 168 hours.

use axum::extract::{Query, State};
use axum::http::HeaderMap;
use axum::Json;
use serde::Serialize;
use serde_json::{json, Value};
use std::collections::HashMap;

use crate::api::{extract_claims, AppState};
use crate::storage::ClickhouseStorage;
use crate::triage::rules::{impact, primary_tag, AlertRow, Impact};

const DEFAULT_DAYS: u32 = 7;

#[derive(Debug, Serialize, PartialEq)]
pub struct Choice {
    pub impact:  Impact,
    pub allowed: bool,
    /// Why it is not allowed (empty when it is).
    pub blocked: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct Plan {
    pub community_id: String,
    pub src_ip:       String,
    pub dst_ip:       String,
    pub tag:          String,
    pub days:         u32,
    pub ai_verdict:   Option<String>,
    /// Hide just this session.
    pub session:      Choice,
    /// Hide every alert with this source and tag, for the chosen hours.
    pub pattern:      Choice,
}

fn rows_of(v: &[Value]) -> Vec<AlertRow> {
    v.iter().filter_map(AlertRow::from_json).collect()
}

/// The decision for one scope, from the alerts it would hide.
pub fn decide(rows: &[AlertRow], ai_verdict: Option<&str>, allowed_sensors: &[String]) -> Choice {
    let imp = impact(rows);
    let mut blocked = Vec::new();
    if imp.total == 0 {
        blocked.push("No stored alerts match, so there is nothing to hide.".to_string());
    }
    for r in &imp.reasons {
        blocked.push(format!("{r}: these must stay visible."));
    }
    if ai_verdict == Some("TRUE_POSITIVE") {
        blocked.push("The AI investigation judged this session a likely real attack.".to_string());
    }
    // The suppression is tenant-wide; a restricted analyst may not hide alerts on sensors outside their assignment.
    if !allowed_sensors.is_empty() && rows.iter().any(|r| !allowed_sensors.contains(&r.sensor_id)) {
        blocked.push("The same alerts also occur on sensors that are not assigned to you. Ask a tenant admin.".to_string());
    }
    Choice { impact: imp, allowed: blocked.is_empty(), blocked }
}

/// Everything the preview and the apply need, computed from the stored alerts.
pub async fn plan(ch: &ClickhouseStorage, tenant: &str, sensor_ids: &[String], community_id: &str, days: u32)
    -> Result<Plan, &'static str>
{
    let session_json = ch.session_alert_rows(tenant, sensor_ids, community_id).await;
    let session_rows = rows_of(&session_json);
    // The session's own alerts name the source and the tag. A session the caller cannot see (or that no
    // longer has alerts) has none, and is answered the same way as one that does not exist.
    let top = session_rows.iter()
        .max_by(|a, b| a.score.partial_cmp(&b.score).unwrap_or(std::cmp::Ordering::Equal))
        .ok_or("No stored alerts for this session.")?;
    let (src, dst) = (top.src_ip.clone(), top.dst_ip.clone());
    let tag = primary_tag(&top.tags, &top.sigma_hits);

    let ai_verdict = ch.get_aria_verdict(tenant, community_id).await
        .and_then(|v| v["verdict"].as_str().map(str::to_string));
    let pattern_rows = rows_of(&ch.pattern_alert_rows(tenant, &src, &tag, days).await);

    Ok(Plan {
        community_id: community_id.to_string(),
        session: decide(&session_rows, ai_verdict.as_deref(), sensor_ids),
        pattern: decide(&pattern_rows, ai_verdict.as_deref(), sensor_ids),
        src_ip: src, dst_ip: dst, tag, days, ai_verdict,
    })
}

fn clamp_days(params: &HashMap<String, String>) -> u32 {
    params.get("days").and_then(|v| v.parse::<u32>().ok()).unwrap_or(DEFAULT_DAYS).clamp(1, 30)
}

/// GET /api/ai-activity/suppression-preview?community_id=...&days=7
pub async fn preview(
    State(state): State<AppState>, headers: HeaderMap, Query(params): Query<HashMap<String, String>>,
) -> Json<Value> {
    let Some(claims) = extract_claims(&headers) else { return Json(json!({"error": "unauthorized"})) };
    let cid = params.get("community_id").map(|s| s.trim()).unwrap_or("");
    if cid.is_empty() { return Json(json!({"error": "community_id required"})); }
    match plan(&state.ch_storage, &claims.tenant_id, &claims.sensor_ids, cid, clamp_days(&params)).await {
        Ok(p)  => Json(json!(p)),
        Err(e) => Json(json!({"error": e})),
    }
}

#[derive(serde::Deserialize)]
pub struct ApplyBody {
    pub community_id: String,
    /// "session" or "pattern"
    pub scope: String,
    pub hours: Option<u32>,
}

/// POST /api/ai-activity/suppress. Recomputes the plan on the server; the browser's preview is never trusted.
pub async fn apply(State(state): State<AppState>, headers: HeaderMap, Json(body): Json<ApplyBody>) -> Json<Value> {
    let Some(claims) = extract_claims(&headers) else { return Json(json!({"error": "unauthorized"})) };
    let cid = body.community_id.trim();
    if cid.is_empty() { return Json(json!({"error": "community_id required"})); }
    if body.scope != "session" && body.scope != "pattern" {
        return Json(json!({"error": "scope must be 'session' or 'pattern'"}));
    }
    let plan = match plan(&state.ch_storage, &claims.tenant_id, &claims.sensor_ids, cid, DEFAULT_DAYS).await {
        Ok(p) => p,
        Err(e) => return Json(json!({"error": e})),
    };
    let chosen = if body.scope == "session" { &plan.session } else { &plan.pattern };
    if !chosen.allowed {
        return Json(json!({"error": chosen.blocked.join(" ")}));
    }

    let hours = body.hours.unwrap_or(24).clamp(1, 168);
    let expires = (chrono::Utc::now().timestamp().max(0) as u64 + hours as u64 * 3600) as u32;
    let verdict = plan.ai_verdict.as_deref().map(|v| format!(", AI verdict {v}")).unwrap_or_default();
    let reason = format!(
        "Applied from AI Activity ({} of {} alert(s) hidden{}).",
        if body.scope == "session" { "this session" } else { "all alerts of this kind" }, chosen.impact.total, verdict
    );
    // An empty community id is what makes a suppression cover the whole source + tag (group scope).
    let (suppress_cid, scope) = if body.scope == "session" { (cid, "individual") } else { ("", "group") };
    match state.ch_storage.save_ai_suppression(
        &claims.tenant_id, 0, &plan.tag, "by_src", &plan.src_ip, &plan.src_ip, &plan.dst_ip,
        suppress_cid, &reason, 100, "", Some(expires), scope,
    ).await {
        Ok(_)  => Json(json!({"ok": true, "scope": body.scope, "hours": hours, "hidden_alerts": chosen.impact.total})),
        Err(e) => Json(json!({"error": e.to_string()})),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn alert(sev: &str, score: u32, tags: &[&str], sigma: &[&str], ti: bool, sensor: &str) -> AlertRow {
        AlertRow {
            src_ip: "192.168.1.76".into(), dst_ip: "208.95.112.1".into(), severity: sev.into(), score: score as f32,
            tags: tags.iter().map(|t| t.to_string()).collect(), sigma_hits: sigma.iter().map(|t| t.to_string()).collect(),
            threat_intel: ti, timestamp: 1000, sensor_id: sensor.into(),
        }
    }

    #[test]
    fn routine_alerts_can_be_hidden() {
        let rows = vec![alert("LOW", 20, &["trusted-cloud"], &[], false, "s1"), alert("MEDIUM", 50, &["ids-alert"], &[], false, "s1")];
        let d = decide(&rows, Some("FALSE_POSITIVE"), &[]);
        assert!(d.allowed, "{:?}", d.blocked);
        assert_eq!((d.impact.total, d.impact.protected), (2, 0));
    }

    #[test]
    fn nothing_that_must_stay_visible_can_be_hidden() {
        for (name, row) in [
            ("threat intel", alert("LOW", 20, &[], &[], true, "s1")),
            ("detection rule", alert("LOW", 20, &[], &["et-trojan"], false, "s1")),
            ("critical", alert("CRITICAL", 95, &[], &[], false, "s1")),
            ("alarm tag", alert("MEDIUM", 50, &["dns-tunneling"], &[], false, "s1")),
        ] {
            let d = decide(&[alert("LOW", 20, &[], &[], false, "s1"), row], None, &[]);
            assert!(!d.allowed, "{name} must block");
            assert_eq!(d.impact.protected, 1, "{name}");
            assert!(d.blocked.iter().any(|b| b.contains("must stay visible")), "{name}: {:?}", d.blocked);
        }
    }

    #[test]
    fn one_protected_alert_among_hundreds_blocks_the_whole_pattern() {
        let mut rows: Vec<AlertRow> = (0..300).map(|_| alert("LOW", 20, &["trusted-cloud"], &[], false, "s1")).collect();
        rows.push(alert("HIGH", 80, &[], &[], false, "s1"));
        let d = decide(&rows, None, &[]);
        assert!(!d.allowed);
        assert_eq!((d.impact.total, d.impact.protected), (301, 1));
        assert_eq!(d.impact.by_severity["LOW"], 300);
    }

    #[test]
    fn a_likely_real_attack_verdict_from_the_ai_blocks_hiding() {
        let rows = vec![alert("LOW", 20, &[], &[], false, "s1")];
        let d = decide(&rows, Some("TRUE_POSITIVE"), &[]);
        assert!(!d.allowed && d.blocked.iter().any(|b| b.contains("likely real attack")));
        assert!(decide(&rows, Some("SUSPICIOUS"), &[]).allowed, "an unsure AI does not block; the alert guards still do their job");
    }

    #[test]
    fn a_restricted_analyst_cannot_hide_alerts_on_other_sensors() {
        let rows = vec![alert("LOW", 20, &[], &[], false, "s1"), alert("LOW", 20, &[], &[], false, "s2")];
        assert!(!decide(&rows, None, &["s1".to_string()]).allowed);
        assert!(decide(&rows, None, &["s1".to_string(), "s2".to_string()]).allowed);
        assert!(decide(&rows, None, &[]).allowed, "an unrestricted analyst is not limited");
    }

    #[test]
    fn nothing_stored_means_nothing_to_hide() {
        let d = decide(&[], None, &[]);
        assert!(!d.allowed && d.blocked[0].contains("nothing to hide"));
    }

    // Against a real ClickHouse (a throwaway tenant database that is dropped at the end):
    //   CLICKHOUSE_URL=... CLICKHOUSE_USER=... CLICKHOUSE_PASSWORD=... \
    //   cargo test -p ndr-engine suppression_preview -- --ignored
    #[tokio::test]
    #[ignore]
    async fn suppression_preview_matches_what_the_alert_list_would_actually_hide() {
        let ch = ClickhouseStorage::new();
        let tenant = "zz_supprev";
        let db = crate::storage::clickhouse::tenant_db_pub(tenant);
        let run = |q: String| { let c = ch.client.clone(); async move { c.query(&q).execute().await.unwrap() } };
        let _ = ch.client.query(&format!("DROP DATABASE IF EXISTS {db}")).execute().await;
        run(format!("CREATE DATABASE {db}")).await;
        run(format!("CREATE TABLE {db}.ndr_hits (community_id String, src_ip String, dst_ip String, severity LowCardinality(String), score Float32, \
             tags Array(String), sigma_hits Array(String), threat_intel UInt8 DEFAULT 0, sensor_id String, timestamp DateTime, \
             src_country String DEFAULT '', dst_country String DEFAULT '', correlation_status LowCardinality(String) DEFAULT '', \
             agent_s_rule_id String DEFAULT '', corroborated_at DateTime DEFAULT toDateTime(0)) \
             ENGINE = ReplacingMergeTree ORDER BY (community_id, timestamp, dst_ip)")).await;
        run(format!("CREATE TABLE {db}.evidence_annotations (community_id String, tag String, note String, created_at DateTime DEFAULT now()) ENGINE = MergeTree ORDER BY created_at")).await;
        run(format!("CREATE TABLE {db}.ai_suppressions (id String DEFAULT toString(generateUUIDv4()), tenant_id String DEFAULT 'default', \
             signature_id UInt64 DEFAULT 0, signature_name String DEFAULT '', suppress_type String DEFAULT 'by_dst', suppress_ip String DEFAULT '', \
             src_ip String DEFAULT '', dst_ip String DEFAULT '', community_id String DEFAULT '', ai_reason String DEFAULT '', ai_confidence UInt8 DEFAULT 0, \
             sensor_id String DEFAULT '', active UInt8 DEFAULT 1, created_at DateTime DEFAULT now(), expires_at Nullable(DateTime) DEFAULT NULL, \
             suppress_scope String DEFAULT 'individual') ENGINE = ReplacingMergeTree(created_at) \
             ORDER BY (tenant_id, signature_id, suppress_type, suppress_ip, signature_name, community_id)")).await;

        // host .76: 30 routine "port-note" alerts (session cS is one of them) + a different tag that must not match
        for i in 0..30 {
            run(format!("INSERT INTO {db}.ndr_hits (community_id, src_ip, dst_ip, severity, score, tags, sigma_hits, sensor_id, timestamp) \
                 VALUES ('{}','192.168.1.76','208.95.112.{}','MEDIUM',50,['odd-port'],[],'s1',now() - {})", if i == 0 { "cS".to_string() } else { format!("c{i}") }, i % 3, i * 60)).await;
        }
        run(format!("INSERT INTO {db}.ndr_hits (community_id, src_ip, dst_ip, severity, score, tags, sigma_hits, sensor_id, timestamp) \
             VALUES ('other','192.168.1.76','203.0.113.9','LOW',20,['trusted-cloud'],[],'s1',now())")).await;
        // an old alert outside the window
        run(format!("INSERT INTO {db}.ndr_hits (community_id, src_ip, dst_ip, severity, score, tags, sigma_hits, sensor_id, timestamp) \
             VALUES ('old','192.168.1.76','208.95.112.0','MEDIUM',50,['odd-port'],[],'s1',now() - INTERVAL 20 DAY)")).await;
        // host .99: same tag but one alert triggered a detection rule; another sensor too
        run(format!("INSERT INTO {db}.ndr_hits (community_id, src_ip, dst_ip, severity, score, tags, sigma_hits, sensor_id, timestamp) \
             VALUES ('cP','192.168.1.99','208.95.112.1','MEDIUM',50,['odd-port'],[],'s1',now()),\
                    ('cP2','192.168.1.99','208.95.112.2','MEDIUM',50,['odd-port'],['et-scan-rule'],'s2',now())")).await;

        let p = plan(&ch, tenant, &[], "cS", 7).await.unwrap();
        assert_eq!((p.src_ip.as_str(), p.tag.as_str()), ("192.168.1.76", "odd-port"));
        assert_eq!((p.session.impact.total, p.session.allowed), (1, true), "one session = one alert here");
        assert_eq!((p.pattern.impact.total, p.pattern.impact.destinations, p.pattern.allowed), (30, 3, true),
            "30 routine alerts over 3 destinations; the other tag and the 20-day-old alert are not counted");
        assert_eq!(p.pattern.impact.by_severity["MEDIUM"], 30);
        assert_eq!(plan(&ch, tenant, &[], "cS", 30).await.unwrap().pattern.impact.total, 31, "a 30-day window includes the old alert");

        // the preview is exactly what the alert list stops showing once the suppression exists
        let before = ch.get_recent_hits_by_tenant(500, tenant, &[], 24, None).await.unwrap().len();
        assert!(before >= 31, "the alert list itself must work on this table before the check means anything: {before}");
        ch.save_ai_suppression(tenant, 0, "odd-port", "by_src", "192.168.1.76", "192.168.1.76", "", "", "test", 100, "", None, "group").await.unwrap();
        let after = ch.get_recent_hits_by_tenant(500, tenant, &[], 24, None).await.unwrap().len();
        assert_eq!(before - after, 30, "the alert list hides exactly the alerts the preview counted (within 24h)");

        // host .99: a rule-triggered alert blocks the pattern, and the other sensor blocks a restricted analyst
        let bad = plan(&ch, tenant, &[], "cP", 7).await.unwrap();
        assert!(!bad.pattern.allowed && bad.pattern.blocked.iter().any(|b| b.contains("detection rule")), "{:?}", bad.pattern.blocked);
        assert!(bad.session.allowed, "this one session has no protected alert");
        let scoped = plan(&ch, tenant, &["s1".to_string()], "cP", 7).await.unwrap();
        assert!(scoped.pattern.blocked.iter().any(|b| b.contains("not assigned to you")));
        // a restricted analyst cannot even see a session on another sensor
        assert!(plan(&ch, tenant, &["s1".to_string()], "cP2", 7).await.is_err());
        // a stored AI verdict of TRUE_POSITIVE blocks the routine session
        run(format!("INSERT INTO {db}.evidence_annotations (community_id, tag, note) VALUES ('cS','aria_verdict','{{\"verdict\":\"TRUE_POSITIVE\",\"confidence\":90}}')")).await;
        let tp = plan(&ch, tenant, &[], "cS", 7).await.unwrap();
        assert!(!tp.session.allowed && !tp.pattern.allowed);
        assert!(plan(&ch, tenant, &[], "nope", 7).await.is_err());
        let _ = ch.client.query(&format!("DROP DATABASE IF EXISTS {db}")).execute().await;
    }
}
