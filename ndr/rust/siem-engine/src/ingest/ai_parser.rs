// AI-assisted log parser — one-time Claude API call per unknown source.
// Saves field mappings to siem_parsers ClickHouse table.
// All future logs from the same source use the saved parser — zero more AI calls.
// Parsed output is OCSF-aligned, so all OOTB correlation rules work automatically.

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;
use serde::{Deserialize, Serialize};
use clickhouse::Client;
use chrono::Utc;
use tracing::{info, warn};

use crate::ingest::normalizer::OcsfEvent;

// ─── Field mapping produced by Claude ────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldMapping {
    pub source_field: String,
    pub ocsf_field:   String,
    pub transform:    String, // "direct" | "uppercase" | "parse_int" | "parse_ip"
    pub confidence:   f32,
}

// ─── Saved parser ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct SavedParser {
    pub parser_id:   String,
    pub source_id:   String,
    pub tenant_id:   String,
    pub version:     u32,
    pub mappings:    Vec<FieldMapping>,
    pub event_class: String,
}

// ─── Sample buffer — accumulates raw lines until 10 collected ─────────────────

pub struct SampleBuffer {
    samples:    Arc<Mutex<HashMap<String, Vec<String>>>>,
    generating: Arc<Mutex<std::collections::HashSet<String>>>,
}

impl SampleBuffer {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            samples:    Arc::new(Mutex::new(HashMap::new())),
            generating: Arc::new(Mutex::new(std::collections::HashSet::new())),
        })
    }

    fn key(tenant_id: &str, source_id: &str) -> String {
        format!("{tenant_id}::{source_id}")
    }

    /// Returns true once 10 samples are buffered.
    pub async fn push(&self, tenant_id: &str, source_id: &str, raw: &str) -> bool {
        let key = Self::key(tenant_id, source_id);
        let mut map = self.samples.lock().await;
        let bucket = map.entry(key).or_default();
        if bucket.len() < 10 {
            bucket.push(raw.to_string());
        }
        bucket.len() >= 10
    }

    pub async fn take(&self, tenant_id: &str, source_id: &str) -> Vec<String> {
        self.samples.lock().await.remove(&Self::key(tenant_id, source_id)).unwrap_or_default()
    }

    pub async fn is_generating(&self, tenant_id: &str, source_id: &str) -> bool {
        self.generating.lock().await.contains(&Self::key(tenant_id, source_id))
    }

    pub async fn set_generating(&self, tenant_id: &str, source_id: &str) {
        self.generating.lock().await.insert(Self::key(tenant_id, source_id));
    }

    pub async fn clear_generating(&self, tenant_id: &str, source_id: &str) {
        self.generating.lock().await.remove(&Self::key(tenant_id, source_id));
    }
}

// ─── In-memory parser cache ───────────────────────────────────────────────────

pub struct ParserCache {
    inner: Arc<Mutex<HashMap<String, SavedParser>>>,
}

impl ParserCache {
    pub fn new() -> Arc<Self> {
        Arc::new(Self { inner: Arc::new(Mutex::new(HashMap::new())) })
    }

    fn key(tenant_id: &str, source_id: &str) -> String {
        format!("{tenant_id}::{source_id}")
    }

    pub async fn get(&self, tenant_id: &str, source_id: &str) -> Option<SavedParser> {
        self.inner.lock().await.get(&Self::key(tenant_id, source_id)).cloned()
    }

    pub async fn insert(&self, parser: SavedParser) {
        let key = Self::key(&parser.tenant_id, &parser.source_id);
        self.inner.lock().await.insert(key, parser);
    }

    /// Load all approved parsers from ClickHouse at startup.
    pub async fn load_all(&self, ch: &Client) {
        #[derive(clickhouse::Row, serde::Deserialize)]
        struct Row {
            parser_id:   String,
            source_id:   String,
            tenant_id:   String,
            version:     u32,
            ocsf_mapping: String,
            event_class: String,
        }

        let sql = "SELECT parser_id, source_id, tenant_id, version, ocsf_mapping, event_class \
                   FROM ndr.siem_parsers FINAL WHERE status = 'active'";

        match ch.query(sql).fetch_all::<Row>().await {
            Ok(rows) => {
                let mut cache = self.inner.lock().await;
                for row in rows {
                    let mappings: Vec<FieldMapping> =
                        serde_json::from_str(&row.ocsf_mapping).unwrap_or_default();
                    cache.insert(Self::key(&row.tenant_id, &row.source_id), SavedParser {
                        parser_id:   row.parser_id,
                        source_id:   row.source_id,
                        tenant_id:   row.tenant_id,
                        version:     row.version,
                        mappings,
                        event_class: row.event_class,
                    });
                }
                info!("ParserCache: loaded {} custom AI parsers", cache.len());
            }
            Err(e) => warn!("ParserCache: could not load (table may not exist yet): {e}"),
        }
    }
}

// ─── Claude API — one call, one parser ───────────────────────────────────────

const SYSTEM_PROMPT: &str = r#"You are an expert SIEM log parser. Given sample log lines from an unknown source, produce OCSF field mappings.

Return ONLY a JSON object:
{
  "event_class": "<authentication|network_activity|process_activity|account_change|system_activity|file_activity|unknown>",
  "mappings": [
    {"source_field":"<field in raw log>","ocsf_field":"<OCSF path>","transform":"<direct|uppercase|parse_int|parse_ip>","confidence":<0.0-1.0>}
  ]
}

Map to these OCSF paths when found:
  src_ip/source_ip → src_endpoint.ip
  dst_ip/dest_ip   → dst_endpoint.ip
  src_port         → src_endpoint.port
  dst_port         → dst_endpoint.port
  user/username    → actor.user.name
  hostname/host    → src_endpoint.hostname
  timestamp/time   → metadata.original_time
  action/result    → activity_name
  severity/level   → severity
  process/proc     → process.name
  cmdline/command  → process.cmd_line
  filepath/file    → file.path"#;

/// Generate OCSF field mappings for an unknown log source.
/// Uses the DB-configured AI provider (super admin Settings > AI Configuration)
/// via provigil_common::ai — no env var required.
pub async fn generate_parser(
    samples: &[String],
    ch: &clickhouse::Client,
    source_id: &str,
) -> Option<(Vec<FieldMapping>, String)> {
    let samples_text = samples.iter().enumerate()
        .map(|(i, s)| format!("Sample {}:\n{}", i + 1, s))
        .collect::<Vec<_>>()
        .join("\n\n");

    let user_msg = format!(
        "Source ID: {source_id}\n\nSample logs:\n\n{samples_text}\n\nGenerate OCSF field mappings."
    );

    let raw = provigil_common::ai::generate_simple(ch, "threat", SYSTEM_PROMPT, &user_msg).await;

    if raw.is_empty() {
        warn!("ai_parser: no AI provider returned a response for {source_id}");
        return None;
    }

    // Strip markdown fences if the model wrapped output
    let text = if let Some(s) = raw.find('{') {
        let e = raw.rfind('}').map(|x| x + 1).unwrap_or(raw.len());
        &raw[s..e]
    } else { &raw };

    let parsed: serde_json::Value = serde_json::from_str(text).ok()?;
    let event_class = parsed["event_class"].as_str().unwrap_or("unknown").to_string();
    let mappings: Vec<FieldMapping> = serde_json::from_value(parsed["mappings"].clone()).ok()?;

    info!("ai_parser: {} mappings generated for {source_id} class={event_class}", mappings.len());
    Some((mappings, event_class))
}

// ─── Persist parser to ClickHouse ────────────────────────────────────────────

pub async fn save_parser(
    ch: &Client,
    tenant_id: &str,
    source_id: &str,
    mappings: &[FieldMapping],
    event_class: &str,
) -> Option<SavedParser> {
    let parser_id     = uuid::Uuid::new_v4().to_string();
    let mappings_json = serde_json::to_string(mappings).unwrap_or_default();
    let now           = Utc::now().to_rfc3339();

    let sql = format!(
        "INSERT INTO ndr.siem_parsers \
         (parser_id, tenant_id, source_id, source_type, name, version, ocsf_mapping, \
          event_class, status, approved_by, rollback_version, created_at, updated_at) \
         VALUES ('{}','{}','{}','ai_generated','{}',1,'{}','{}','active','ai',0,'{}','{}')",
        parser_id,
        esc(tenant_id),
        esc(source_id),
        esc(source_id),   // name = source_id for readability
        esc(&mappings_json),
        esc(event_class),
        now,
        now,
    );

    match ch.query(&sql).execute().await {
        Ok(_) => {
            info!("ai_parser: saved parser {parser_id} for {source_id}");
            Some(SavedParser {
                parser_id,
                source_id:   source_id.to_string(),
                tenant_id:   tenant_id.to_string(),
                version:     1,
                mappings:    mappings.to_vec(),
                event_class: event_class.to_string(),
            })
        }
        Err(e) => { warn!("ai_parser: save failed for {source_id}: {e}"); None }
    }
}

fn esc(s: &str) -> String { s.replace('\\', "\\\\").replace('\'', "\\'") }

// ─── Apply saved parser → OCSF OcsfEvent ─────────────────────────────────────

/// Apply a saved parser's field mappings to a raw log line.
/// Output is OCSF-aligned → ip_token + threat_intel + all correlation rules work automatically.
pub fn apply(parser: &SavedParser, raw: &str, tenant_id: &str, source_id: &str) -> OcsfEvent {
    let source_obj = serde_json::from_str::<serde_json::Value>(raw)
        .unwrap_or_else(|_| parse_kv(raw));

    let mut ocsf = serde_json::json!({});

    for m in &parser.mappings {
        let val = source_obj.get(&m.source_field)
            .or_else(|| source_obj.get(&m.source_field.to_lowercase()))
            .cloned();

        if let Some(v) = val {
            let transformed = transform(&v, &m.transform);
            set_path(&mut ocsf, &m.ocsf_field, transformed);
        }
    }

    // Preserve unmapped fields so raw data is still searchable
    if let (Some(src), Some(dst)) = (source_obj.as_object(), ocsf.as_object_mut()) {
        for (k, v) in src {
            dst.entry(k.clone()).or_insert(v.clone());
        }
    }

    let timestamp = get_str(&ocsf, "metadata.original_time")
        .or_else(|| get_str(&ocsf, "timestamp"))
        .or_else(|| get_str(&ocsf, "time"))
        .or_else(|| get_str(&ocsf, "@timestamp"))
        .unwrap_or_else(|| Utc::now().to_rfc3339());

    OcsfEvent {
        log_id:      uuid::Uuid::new_v4().to_string(),
        tenant_id:   tenant_id.to_string(),
        source_id:   source_id.to_string(),
        source_type: format!("ai_parser_v{}", parser.version),
        event_class: parser.event_class.clone(),
        severity:    "INFO".to_string(),
        timestamp,
        raw_log:     raw.to_string(),
        parsed:      ocsf,
        ip_tokens:   vec![],
        threat_match: None,
    }
}

fn transform(val: &serde_json::Value, t: &str) -> serde_json::Value {
    match t {
        "uppercase" => val.as_str()
            .map(|s| serde_json::Value::String(s.to_uppercase()))
            .unwrap_or_else(|| val.clone()),
        "parse_int" => val.as_str()
            .and_then(|s| s.parse::<i64>().ok())
            .map(serde_json::Value::from)
            .unwrap_or_else(|| val.clone()),
        _ => val.clone(),
    }
}

fn set_path(obj: &mut serde_json::Value, path: &str, val: serde_json::Value) {
    let (head, tail) = path.split_once('.').map(|(h, t)| (h, Some(t))).unwrap_or((path, None));
    if let Some(o) = obj.as_object_mut() {
        if let Some(rest) = tail {
            let inner = o.entry(head).or_insert(serde_json::json!({}));
            set_path(inner, rest, val);
        } else {
            o.insert(head.to_string(), val);
        }
    }
}

fn get_str(obj: &serde_json::Value, path: &str) -> Option<String> {
    let (head, tail) = path.split_once('.').map(|(h, t)| (h, Some(t))).unwrap_or((path, None));
    let child = obj.get(head)?;
    if let Some(rest) = tail { get_str(child, rest) } else { child.as_str().map(String::from) }
}

fn parse_kv(s: &str) -> serde_json::Value {
    let mut map = serde_json::Map::new();
    for pair in s.split_whitespace() {
        if let Some((k, v)) = pair.split_once('=') {
            map.insert(k.to_string(), serde_json::Value::String(
                v.trim_matches('"').to_string()
            ));
        }
    }
    serde_json::Value::Object(map)
}
