use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ParserStatus {
    Active,
    Draft,
    NeedsReview,
    Disabled,
}

impl Default for ParserStatus {
    fn default() -> Self {
        ParserStatus::Active
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ParserType {
    Regex,
    Grok,
    JsonPath,
}

impl Default for ParserType {
    fn default() -> Self {
        ParserType::Regex
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParserFieldDefinition {
    pub name: String,
    pub field_type: String, // "string", "ip", "integer", "datetime", "float", "boolean"
    pub example: String,
    pub ecs_target: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DynamicParser {
    pub id: Uuid,
    pub fingerprint: u64,
    pub fingerprint_signature: String,
    pub name: String,
    pub description: String,
    pub parser_type: ParserType,
    pub pattern: String,
    pub fields: Vec<ParserFieldDefinition>,
    pub normalization: HashMap<String, String>,
    pub confidence: f32,
    pub version: u32,
    pub status: ParserStatus,
    pub sample_logs: Vec<String>,
    pub hit_count: u64,
    pub success_count: u64,
    pub created_at: DateTime<Utc>,
    pub last_used: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DynamicParsedResult {
    pub parser_id: Uuid,
    pub parser_name: String,
    pub fingerprint: u64,
    pub extracted_fields: HashMap<String, String>,
    pub normalized_fields: HashMap<String, serde_json::Value>,
    pub execution_time_us: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParserTestResult {
    pub success: bool,
    pub matches_count: usize,
    pub total_samples: usize,
    pub extracted_fields: HashMap<String, String>,
    pub execution_time_us: u64,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SynthesizeRequest {
    pub fingerprint: Option<u64>,
    pub samples: Vec<String>,
    pub custom_instructions: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnmatchedFingerprintSummary {
    pub fingerprint: u64,
    pub signature: String,
    pub sample_count: usize,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub ready_for_synthesis: bool,
    pub sample_previews: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParserStatsSummary {
    pub total_learned_parsers: usize,
    pub active_parsers: usize,
    pub pending_novel_fingerprints: usize,
    pub total_parses_executed: u64,
    pub average_latency_us: f64,
}
