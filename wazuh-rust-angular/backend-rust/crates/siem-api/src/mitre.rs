//! MITRE ATT&CK matrix: the full Enterprise catalog from the manager's
//! `var/db/mitre.db` (SQLite, built from the ruleset's enterprise-attack.json, as
//! Wazuh's own mitre.db), with the tenant's alerts per technique from ClickHouse.
//! Read on each request (a few ms); nothing is kept in memory.
//!
//! `GET /api/v1/mitre/matrix`

use std::collections::{BTreeMap, HashMap};

use axum::extract::{Extension, State};
use axum::response::IntoResponse;
use axum::Json;
use serde_json::json;

use crate::tenancy::AuthCtx;
use crate::AppState;

/// ATT&CK's kill-chain order of the Enterprise tactics.
const TACTIC_ORDER: [&str; 14] = ["TA0043", "TA0042", "TA0001", "TA0002", "TA0003", "TA0004", "TA0005", "TA0006", "TA0007", "TA0008", "TA0009", "TA0011", "TA0010", "TA0040"];

/// Every technique of a tactic, sub-techniques included (deprecated and revoked ones left out).
const CATALOG_SQL: &str = "SELECT tr.external_id, t.name, r.external_id, te.name, te.description, COALESCE(pr.external_id, '') \
    FROM technique te \
    JOIN reference r ON r.id = te.id AND r.source = 'mitre-attack' AND r.type = 'technique' \
    JOIN phase p ON p.tech_id = te.id \
    JOIN tactic t ON t.id = p.tactic_id \
    JOIN reference tr ON tr.id = t.id AND tr.source = 'mitre-attack' AND tr.type = 'tactic' \
    LEFT JOIN reference pr ON pr.id = te.subtechnique_of AND pr.source = 'mitre-attack' AND pr.type = 'technique' \
    WHERE te.deprecated = 0 AND (te.revoked_by IS NULL OR te.revoked_by = '')";

#[derive(Debug, Clone, PartialEq)]
pub struct CatalogRow {
    pub tactic_id: String,
    pub tactic: String,
    pub id: String,
    pub name: String,
    pub description: String,
    /// The parent technique of a sub-technique, else empty.
    pub parent: String,
}

/// The catalog rows of a mitre.db.
pub fn read_catalog(path: &std::path::Path) -> Result<Vec<CatalogRow>, String> {
    let (rc, db) = siem_sqlite::Db::open_v2(path.to_string_lossy().as_bytes(), siem_sqlite::SQLITE_OPEN_READONLY);
    let db = db.filter(|_| rc == siem_sqlite::SQLITE_OK).ok_or_else(|| format!("cannot open {}", path.display()))?;
    db.busy_timeout(5_000);
    let mut rows = Vec::new();
    let (rc, err) = db.exec_rows(CATALOG_SQL.as_bytes(), |cols, _| {
        let c = |i: usize| cols.get(i).copied().flatten().map(|b| String::from_utf8_lossy(b).into_owned()).unwrap_or_default();
        rows.push(CatalogRow { tactic_id: c(0), tactic: c(1), id: c(2), name: c(3), description: summary(&c(4)), parent: c(5) });
        0
    });
    if rc != siem_sqlite::SQLITE_OK {
        return Err(String::from_utf8_lossy(&err.unwrap_or_default()).into_owned());
    }
    Ok(rows)
}

/// The first sentence of an ATT&CK description, without citations and link markup.
fn summary(d: &str) -> String {
    let mut out = String::new();
    let mut rest = d;
    // "(Citation: X)" and "[text](url)" -> "" and "text"
    while let Some(i) = rest.find(['(', '[']) {
        out.push_str(&rest[..i]);
        let tail = &rest[i..];
        if let Some(end) = tail.strip_prefix("(Citation:").and_then(|t| t.find(')')) {
            rest = &tail["(Citation:".len() + end + 1..];
        } else if let (Some(close), true) = (tail.find("]("), tail.starts_with('[')) {
            let after = &tail[close + 2..];
            out.push_str(&tail[1..close]);
            rest = after.find(')').map_or("", |e| &after[e + 1..]);
        } else {
            out.push_str(&tail[..1]);
            rest = &tail[1..];
        }
    }
    out.push_str(rest);
    let text = out.split_whitespace().collect::<Vec<_>>().join(" ");
    let first = text.find(". ").map_or(text.as_str(), |i| &text[..=i]);
    if first.chars().count() > 240 {
        first.chars().take(237).collect::<String>() + "..."
    } else {
        first.to_string()
    }
}

/// The matrix: tactics in ATT&CK order, each with its techniques (detected first), the
/// alerts of a technique counting its sub-techniques'. `by_id`: (technique id, alerts, max level).
pub fn build(catalog: &[CatalogRow], by_id: &[(String, u64, u8)]) -> serde_json::Value {
    let count = |tid: &str| {
        by_id.iter().filter(|(id, _, _)| id == tid || id.strip_prefix(tid).is_some_and(|r| r.starts_with('.'))).fold((0u64, 0u8), |(n, l), (_, c, m)| (n + c, l.max(*m)))
    };
    let mut subs: HashMap<(&str, &str), Vec<String>> = HashMap::new();
    for r in catalog.iter().filter(|r| !r.parent.is_empty()) {
        subs.entry((r.tactic_id.as_str(), r.parent.as_str())).or_default().push(r.id.clone());
    }
    let mut tactics: BTreeMap<usize, (String, String, Vec<serde_json::Value>)> = BTreeMap::new();
    let mut known: Vec<&str> = Vec::new();
    for r in catalog {
        known.push(&r.id);
        if !r.parent.is_empty() {
            continue;
        }
        let Some(pos) = TACTIC_ORDER.iter().position(|t| *t == r.tactic_id) else { continue };
        let (n, max) = count(&r.id);
        let mut s = subs.get(&(r.tactic_id.as_str(), r.id.as_str())).cloned().unwrap_or_default();
        s.sort();
        tactics.entry(pos).or_insert_with(|| (r.tactic_id.clone(), r.tactic.clone(), Vec::new())).2.push(json!({
            "id": r.id, "name": r.name, "description": r.description, "alert_count": n, "max_level": max, "subtechniques": s,
        }));
    }
    let matrix: Vec<serde_json::Value> = tactics
        .into_values()
        .map(|(id, name, mut techniques)| {
            techniques.sort_by(|a, b| b["alert_count"].as_u64().cmp(&a["alert_count"].as_u64()).then_with(|| a["id"].as_str().cmp(&b["id"].as_str())));
            json!({ "tactic_id": id, "name": name, "techniques": techniques })
        })
        .collect();
    // technique ids in alerts that the catalog does not have (revoked, or a typo in a rule)
    let unmapped: Vec<serde_json::Value> = by_id
        .iter()
        .filter(|(id, _, _)| !known.iter().any(|k| *k == id || id.strip_prefix(*k).is_some_and(|r| r.starts_with('.'))))
        .map(|(id, n, m)| json!({ "id": id, "alert_count": n, "max_level": m }))
        .collect();
    json!({
        "total_tactics": matrix.len(),
        "total_techniques": catalog.iter().filter(|r| r.parent.is_empty()).map(|r| &r.id).collect::<std::collections::HashSet<_>>().len(),
        "total_mitre_alerts": by_id.iter().map(|(_, n, _)| n).sum::<u64>(),
        "unmapped": unmapped,
        "matrix": matrix,
    })
}

/// `GET /api/v1/mitre/matrix`
pub async fn matrix(State(state): State<AppState>, Extension(ctx): Extension<AuthCtx>) -> impl IntoResponse {
    let path = crate::wazuh_manager::home().join("var/db/mitre.db");
    let (catalog, by_id) = tokio::join!(
        tokio::task::spawn_blocking(move || read_catalog(&path)),
        crate::history::mitre_counts(&state, &ctx, crate::history::DEFAULT_HOURS)
    );
    let catalog = match catalog.map_err(|e| e.to_string()).and_then(|r| r) {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!("MITRE matrix: {e}");
            return (axum::http::StatusCode::SERVICE_UNAVAILABLE, Json(json!({ "status": "error", "message": format!("The MITRE catalog (mitre.db) is not available: {e}") }))).into_response();
        }
    };
    let mut body = build(&catalog, &by_id);
    body["last_updated"] = json!(chrono::Utc::now());
    Json(body).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn summary_keeps_the_first_sentence_without_citations() {
        let d = "Adversaries may directly access a volume to bypass file access controls. (Citation: Hakobyan 2009) More text [here](https://x).";
        assert_eq!(summary(d), "Adversaries may directly access a volume to bypass file access controls.");
        assert_eq!(summary("Uses [PowerShell](https://attack.mitre.org/techniques/T1059/001) to run code."), "Uses PowerShell to run code.");
    }

    #[test]
    fn matrix_counts_sub_techniques_and_lists_unknown_ids() {
        let row = |ta: &str, t: &str, id: &str, parent: &str| CatalogRow { tactic_id: ta.into(), tactic: t.into(), id: id.into(), name: id.into(), description: String::new(), parent: parent.into() };
        let cat = vec![
            row("TA0002", "Execution", "T1059", ""),
            row("TA0002", "Execution", "T1059.001", "T1059"),
            row("TA0005", "Defense Evasion", "T1006", ""),
            row("TA0002", "Execution", "T1204", ""),
        ];
        let by_id = vec![("T1059.001".to_string(), 5, 10), ("T1059".to_string(), 2, 7), ("T1006".to_string(), 9, 4), ("T1086".to_string(), 3, 6), ("T10590".to_string(), 1, 3)];
        let m = build(&cat, &by_id);
        let ex = &m["matrix"][0];
        assert_eq!((ex["tactic_id"].as_str(), ex["techniques"][0]["id"].as_str()), (Some("TA0002"), Some("T1059")), "kill-chain order, detected first");
        assert_eq!((ex["techniques"][0]["alert_count"].as_u64(), ex["techniques"][0]["max_level"].as_u64()), (Some(7), Some(10)), "T1059 = itself + T1059.001, not T10590");
        assert_eq!(ex["techniques"][0]["subtechniques"], json!(["T1059.001"]));
        assert_eq!(m["matrix"][1]["techniques"][0]["alert_count"].as_u64(), Some(9), "T1006 is in the matrix");
        assert_eq!(m["unmapped"].as_array().unwrap().iter().map(|u| u["id"].as_str().unwrap()).collect::<Vec<_>>(), ["T1086", "T10590"]);
        assert_eq!(m["total_mitre_alerts"].as_u64(), Some(20));
    }

    /// The manager's real mitre.db (when built): the full catalog, T1006 included.
    #[test]
    fn reads_the_manager_mitre_db() {
        let db = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../data/manager/var/db/mitre.db");
        if !db.exists() {
            return;
        }
        let rows = read_catalog(&db).unwrap();
        let tactics: std::collections::HashSet<&str> = rows.iter().map(|r| r.tactic_id.as_str()).collect();
        assert_eq!(tactics.len(), 14);
        assert!(rows.iter().any(|r| r.id == "T1006" && r.parent.is_empty()));
        assert!(rows.iter().any(|r| r.id == "T1059.001" && r.parent == "T1059"));
        assert!(rows.iter().filter(|r| r.parent.is_empty()).count() > 150);
    }
}
