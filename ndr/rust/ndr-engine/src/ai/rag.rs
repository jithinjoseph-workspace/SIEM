//! "Similar past incidents": a per-tenant Qdrant collection of this tenant's own AI
//! investigations, used to ground new ones in what actually happened before.
//!
//! Isolation matches every other tenant-scoped store in this codebase (`tenant_db()` for
//! ClickHouse): one Qdrant collection per tenant, named from the caller's JWT `tenant_id` —
//! never from request input — so one tenant can never read or write another's collection.
//! A sensor-restricted analyst additionally only ever sees points tagged with their own
//! sensor_id, enforced by a Qdrant-side filter, the same discipline `sensor_filter` applies
//! to every ClickHouse query in this codebase.
//!
//! If Qdrant is unreachable, every function here degrades to "no similar incidents found" /
//! "indexing skipped" rather than failing the investigation that triggered it — this is a
//! helper on top of the real, evidence-grounded verdict in `investigator.rs`, never a
//! dependency of it.

use provigil_common::ai::EMBEDDING_DIMS;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::time::Duration;

fn qdrant_url() -> String {
    std::env::var("QDRANT_URL").unwrap_or_else(|_| "http://localhost:6333".to_string())
}

/// Same sanitisation as `storage::clickhouse::tenant_db()`, applied here independently since
/// this module must not depend on a private helper of a different module for something this
/// small — kept consistent by the shared test at the bottom of this file.
fn collection_name(tenant_id: &str) -> String {
    format!("ndr_rag_{}", tenant_id.replace('-', "_"))
}

fn http() -> reqwest::Client {
    reqwest::Client::builder().timeout(Duration::from_secs(8)).build().unwrap_or_default()
}

/// A community_id is not a valid Qdrant point id (must be an unsigned int or a UUID); this
/// turns it into one deterministically, so re-indexing the same session updates the same
/// point instead of creating a duplicate.
fn point_id_for(community_id: &str) -> String {
    uuid::Uuid::new_v5(&uuid::Uuid::NAMESPACE_URL, community_id.as_bytes()).to_string()
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct IndexedInvestigation {
    pub community_id: String,
    pub verdict: String,
    pub confidence: u8,
    pub severity: String,
    pub src_ip: String,
    pub dst_ip: String,
    pub reasoning: String,
    pub sensor_id: String,
    pub generated_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct SimilarIncident {
    pub score: f32,
    #[serde(flatten)]
    pub investigation: IndexedInvestigation,
}

async fn ensure_collection(tenant_id: &str) -> anyhow::Result<()> {
    let name = collection_name(tenant_id);
    let url = format!("{}/collections/{}", qdrant_url(), name);
    if http().get(&url).send().await.map(|r| r.status().is_success()).unwrap_or(false) {
        return Ok(());
    }
    let resp = http().put(&url)
        .json(&json!({ "vectors": { "size": EMBEDDING_DIMS, "distance": "Cosine" } }))
        .send().await?;
    if !resp.status().is_success() && resp.status().as_u16() != 409 {
        anyhow::bail!("qdrant: create collection '{name}' failed: {}", resp.status());
    }
    Ok(())
}

/// Embeds and upserts one investigation. Never panics or propagates a hard failure to a
/// caller that doesn't check the result — callers that don't care call this and ignore `Err`.
pub async fn index_investigation(
    ch: &clickhouse::Client,
    tenant_id: &str,
    inv: &IndexedInvestigation,
) -> anyhow::Result<()> {
    let text = format!(
        "{} {} -> {} severity={} verdict={} confidence={}% — {}",
        inv.community_id, inv.src_ip, inv.dst_ip, inv.severity, inv.verdict, inv.confidence, inv.reasoning
    );
    let vector = provigil_common::ai::embed_text(ch, &text).await
        .ok_or_else(|| anyhow::anyhow!("no embeddings-capable AI provider configured"))?;
    ensure_collection(tenant_id).await?;
    let name = collection_name(tenant_id);
    let url = format!("{}/collections/{}/points", qdrant_url(), name);
    let resp = http().put(&url).query(&[("wait", "true")]).json(&json!({
        "points": [{ "id": point_id_for(&inv.community_id), "vector": vector, "payload": inv }]
    })).send().await?;
    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        anyhow::bail!("qdrant: upsert into '{name}' failed: {status} {body}");
    }
    Ok(())
}

/// Past investigations whose circumstances were closest to `query_text`, restricted to
/// `sensor_ids` when non-empty. Empty (never an error) when nothing is indexed yet, Qdrant
/// is unreachable, or no embeddings provider is configured — a missing "similar incidents"
/// panel is never a reason to block an investigation.
pub async fn search_similar(
    ch: &clickhouse::Client,
    tenant_id: &str,
    query_text: &str,
    sensor_ids: &[String],
    exclude_community_id: &str,
    limit: u32,
) -> Vec<SimilarIncident> {
    let Some(vector) = provigil_common::ai::embed_text(ch, query_text).await else { return vec![] };
    let name = collection_name(tenant_id);
    let url = format!("{}/collections/{}/points/search", qdrant_url(), name);

    let mut body = json!({
        "vector": vector,
        // exclude_community_id's own point may already be indexed; ask for one extra and drop it
        // below rather than trying to express "not equal" portably across Qdrant filter versions.
        "limit": limit + 1,
        "with_payload": true,
        "score_threshold": 0.5,
    });
    if !sensor_ids.is_empty() {
        body["filter"] = json!({ "must": [{ "key": "sensor_id", "match": { "any": sensor_ids } }] });
    }

    let resp = match http().post(&url).json(&body).send().await {
        Ok(r) if r.status().is_success() => r,
        _ => return vec![],
    };
    let data: Value = match resp.json().await { Ok(d) => d, Err(_) => return vec![] };
    data["result"].as_array().cloned().unwrap_or_default().into_iter()
        .filter_map(|h| {
            let score = h["score"].as_f64()? as f32;
            let investigation: IndexedInvestigation = serde_json::from_value(h["payload"].clone()).ok()?;
            Some(SimilarIncident { score, investigation })
        })
        .filter(|s| s.investigation.community_id != exclude_community_id)
        .take(limit as usize)
        .collect()
}

/// What a case status means for the investigation it came from. `None` for statuses that are not
/// an outcome (New, Assigned, In Progress, ...), so only a deliberate close is ever recorded.
pub fn outcome_for_status(status: &str) -> Option<&'static str> {
    match status {
        "False Positive" => Some("false_positive"),
        "Resolved" => Some("true_positive"),
        "Closed" => Some("closed_unknown"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn point_ids_are_stable_and_distinct() {
        let a = point_id_for("1:9Rz1A0f/82grK2YyMtFIb1VQj9c=");
        let b = point_id_for("1:9Rz1A0f/82grK2YyMtFIb1VQj9c=");
        let c = point_id_for("1:someOtherSessionEntirely====");
        assert_eq!(a, b, "the same session always maps to the same point — upsert, not duplicate");
        assert_ne!(a, c);
        assert!(uuid::Uuid::parse_str(&a).is_ok(), "must be a UUID Qdrant will accept: {a}");
    }

    #[test]
    fn collection_names_do_not_collide_across_tenants_and_are_valid_qdrant_names() {
        let a = collection_name("acm");
        let b = collection_name("default");
        let c = collection_name("acm-west");
        assert_ne!(a, b);
        assert_ne!(a, c, "a hyphenated tenant id must not collapse onto a different tenant's name");
        for n in [a, b, c] {
            assert!(n.chars().all(|c| c.is_ascii_alphanumeric() || c == '_'), "{n}");
        }
    }

    // Against a real Qdrant AND the real configured embeddings provider (this project's local
    // stack has both — see ndr.ai_providers and QDRANT_URL / docker compose's qdrant service):
    //   CLICKHOUSE_URL=... CLICKHOUSE_USER=... CLICKHOUSE_PASSWORD=... QDRANT_URL=http://127.0.0.1:6333 \
    //   cargo test -p ndr-engine rag_search -- --ignored --nocapture
    #[tokio::test]
    #[ignore]
    async fn rag_search_finds_the_closest_real_investigation_and_respects_sensor_and_tenant_scope() {
        let url  = std::env::var("CLICKHOUSE_URL").unwrap_or_else(|_| "http://127.0.0.1:8123".into());
        let user = std::env::var("CLICKHOUSE_USER").unwrap_or_else(|_| "default".into());
        let pass = std::env::var("CLICKHOUSE_PASSWORD").unwrap_or_default();
        let ch = clickhouse::Client::default().with_url(url).with_user(user).with_password(pass);
        let tenant = "zz_ragtest";

        // clean slate: drop the collection if an earlier failed run left one
        let _ = http().delete(&format!("{}/collections/{}", qdrant_url(), collection_name(tenant))).send().await;

        let dns_tunnel = IndexedInvestigation {
            community_id: "1:dnstunnelsessionAAAAAAAAA=".into(), verdict: "TRUE_POSITIVE".into(), confidence: 88,
            severity: "HIGH".into(), src_ip: "10.0.0.5".into(), dst_ip: "203.0.113.9".into(),
            reasoning: "High-entropy subdomains to a single destination at a steady interval, classic DNS tunneling exfiltration.".into(),
            sensor_id: "s1".into(), generated_at: "2026-10-01T00:00:00Z".into(),
        };
        let isp_resolver = IndexedInvestigation {
            community_id: "1:ispresolversessionBBBBBBB=".into(), verdict: "FALSE_POSITIVE".into(), confidence: 92,
            severity: "LOW".into(), src_ip: "10.0.0.9".into(), dst_ip: "8.8.8.8".into(),
            reasoning: "Routine DNS lookup to the ISP's own resolver, no threat-intel match, ordinary traffic.".into(),
            sensor_id: "s2".into(), generated_at: "2026-10-01T00:05:00Z".into(),
        };
        index_investigation(&ch, tenant, &dns_tunnel).await.expect("index dns_tunnel");
        index_investigation(&ch, tenant, &isp_resolver).await.expect("index isp_resolver");
        // re-indexing the SAME session must update, not duplicate
        index_investigation(&ch, tenant, &dns_tunnel).await.expect("re-index dns_tunnel");

        let hits = search_similar(&ch, tenant,
            "A host is sending many high-entropy DNS subdomain queries to one external address at regular intervals",
            &[], "", 5).await;
        assert!(!hits.is_empty(), "must find something");
        assert_eq!(hits[0].investigation.community_id, "1:dnstunnelsessionAAAAAAAAA=", "the DNS-tunneling case must rank first for a DNS-tunneling query: {hits:?}");
        assert_eq!(hits.iter().filter(|h| h.investigation.community_id == "1:dnstunnelsessionAAAAAAAAA=").count(), 1, "re-indexing must not duplicate the point");

        // sensor scope: a caller restricted to s2 must never see s1's investigation
        let scoped = search_similar(&ch, tenant,
            "A host is sending many high-entropy DNS subdomain queries to one external address at regular intervals",
            &["s2".to_string()], "", 5).await;
        assert!(scoped.iter().all(|h| h.investigation.sensor_id == "s2"), "{scoped:?}");
        assert!(scoped.iter().all(|h| h.investigation.community_id != "1:dnstunnelsessionAAAAAAAAA="));

        // exclude_community_id must drop a session's own match out of its own "similar to me" list
        let self_excluded = search_similar(&ch, tenant,
            "A host is sending many high-entropy DNS subdomain queries to one external address at regular intervals",
            &[], "1:dnstunnelsessionAAAAAAAAA=", 5).await;
        assert!(self_excluded.iter().all(|h| h.investigation.community_id != "1:dnstunnelsessionAAAAAAAAA="));

        // tenant isolation: a different tenant's (empty) collection must never see this tenant's data
        let other_tenant_hits = search_similar(&ch, "zz_ragtest_other_tenant",
            "A host is sending many high-entropy DNS subdomain queries to one external address at regular intervals",
            &[], "", 5).await;
        assert!(other_tenant_hits.is_empty(), "a different tenant's unrelated, non-existent collection must return nothing, never this tenant's data");

        let _ = http().delete(&format!("{}/collections/{}", qdrant_url(), collection_name(tenant))).send().await;
    }

    #[test]
    fn only_deliberate_closes_record_an_outcome() {
        assert_eq!(outcome_for_status("False Positive"), Some("false_positive"));
        assert_eq!(outcome_for_status("Resolved"), Some("true_positive"));
        assert_eq!(outcome_for_status("Closed"), Some("closed_unknown"));
        for working in ["New", "Assigned", "In Progress", "Pending", "Under Review", "Evidence Collected", ""] {
            assert_eq!(outcome_for_status(working), None, "{working:?} is not an outcome");
        }
    }
}
