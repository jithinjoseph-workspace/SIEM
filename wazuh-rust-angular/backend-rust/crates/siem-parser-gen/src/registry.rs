use crate::accumulator::SampleAccumulator;
use crate::fingerprint::FingerprintEngine;
use crate::models::{
    DynamicParsedResult, DynamicParser, ParserStatsSummary, ParserStatus, ParserTestResult,
};
use crate::synthesizer::AiParserSynthesizer;
use crate::validator::ParserValidator;
use chrono::Utc;
use regex::{Regex, RegexBuilder};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Instant;
use tracing::{error, info};
use uuid::Uuid;

pub struct CompiledDynamicParser {
    pub parser: DynamicParser,
    pub regex: Option<Regex>,
}

#[derive(Clone)]
pub struct DynamicParserRegistry {
    parsers: Arc<RwLock<HashMap<u64, CompiledDynamicParser>>>,
    by_id: Arc<RwLock<HashMap<Uuid, u64>>>,
    pub accumulator: Arc<SampleAccumulator>,
    storage_path: PathBuf,
    total_executions: Arc<AtomicU64>,
    total_latency_us: Arc<AtomicU64>,
}

impl DynamicParserRegistry {
    pub fn new(storage_path: impl AsRef<Path>) -> Self {
        let registry = Self {
            parsers: Arc::new(RwLock::new(HashMap::new())),
            by_id: Arc::new(RwLock::new(HashMap::new())),
            accumulator: Arc::new(SampleAccumulator::new(20, 5)), // 5 samples trigger synthesis
            storage_path: storage_path.as_ref().to_path_buf(),
            total_executions: Arc::new(AtomicU64::new(0)),
            total_latency_us: Arc::new(AtomicU64::new(0)),
        };

        // Load existing persisted parsers
        registry.load_from_disk();
        registry
    }

    /// Primary Hot-Path Log Execution (< 5 microseconds, ZERO AI overhead).
    /// If format is known, runs compiled regex.
    /// If format is unknown, pushes sample to Cold-Path Accumulator.
    pub fn execute(&self, raw_log: &str) -> Option<DynamicParsedResult> {
        let start = Instant::now();
        let (fingerprint, signature) = FingerprintEngine::compute(raw_log);

        // Fast read lock check
        let maybe_match = {
            let guard = self.parsers.read().unwrap();
            guard.get(&fingerprint).and_then(|compiled| {
                if compiled.parser.status != ParserStatus::Active {
                    return None;
                }
                if let Some(ref re) = compiled.regex {
                    re.captures(raw_log).map(|caps| {
                        let mut extracted = HashMap::new();
                        for name in re.capture_names().flatten() {
                            if let Some(m) = caps.name(name) {
                                extracted.insert(name.to_string(), m.as_str().to_string());
                            }
                        }
                        (compiled.parser.id, compiled.parser.name.clone(), compiled.parser.normalization.clone(), extracted)
                    })
                } else {
                    None
                }
            })
        };

        if let Some((parser_id, parser_name, normalization, extracted)) = maybe_match {
            let elapsed = start.elapsed().as_micros() as u64;
            self.total_executions.fetch_add(1, Ordering::Relaxed);
            self.total_latency_us.fetch_add(elapsed, Ordering::Relaxed);

            // Update stats
            {
                let mut guard = self.parsers.write().unwrap();
                if let Some(compiled) = guard.get_mut(&fingerprint) {
                    compiled.parser.hit_count += 1;
                    compiled.parser.success_count += 1;
                    compiled.parser.last_used = Some(Utc::now());
                }
            }

            // Normalize fields according to parser configuration
            let mut normalized_fields = HashMap::new();
            for (k, v) in &extracted {
                let target_key = normalization.get(k).cloned().unwrap_or_else(|| k.clone());
                normalized_fields.insert(target_key, serde_json::Value::String(v.clone()));
            }

            return Some(DynamicParsedResult {
                parser_id,
                parser_name,
                fingerprint,
                extracted_fields: extracted,
                normalized_fields,
                execution_time_us: elapsed,
            });
        }

        // UNMATCHED FORMAT -> Cold Path Async Buffering
        if let Some(samples) = self.accumulator.push_sample(fingerprint, &signature, raw_log) {
            info!(
                "Fingerprint 0x{:x} reached sample threshold ({}) -> Triggering async AI parser synthesis...",
                fingerprint,
                samples.len()
            );
            let registry_clone = self.clone();
            tokio::spawn(async move {
                let _ = registry_clone.synthesize_and_register(fingerprint, &signature, &samples, None).await;
            });
        }

        None
    }

    /// Background or on-demand worker to synthesize, sandbox-test, and register parser
    pub async fn synthesize_and_register(
        &self,
        fingerprint: u64,
        signature: &str,
        samples: &[String],
        custom_instructions: Option<&str>,
    ) -> Result<DynamicParser, String> {
        let result = AiParserSynthesizer::synthesize(fingerprint, signature, samples, custom_instructions).await;

        match result {
            Ok(parser) => {
                info!(
                    "Synthesized parser '{}' for fingerprint 0x{:x}. Registering in registry...",
                    parser.name, fingerprint
                );
                self.register_parser(parser.clone())?;
                self.accumulator.remove(fingerprint);
                let _ = self.save_to_disk();
                Ok(parser)
            }
            Err(e) => {
                error!("Failed to synthesize parser for 0x{:x}: {}", fingerprint, e);
                self.accumulator.mark_synthesizing(fingerprint, false);
                Err(e)
            }
        }
    }

    /// Register a verified parser into memory
    pub fn register_parser(&self, parser: DynamicParser) -> Result<(), String> {
        let re = RegexBuilder::new(&parser.pattern)
            .size_limit(1024 * 1024)
            .build()
            .map_err(|e| format!("Invalid regex pattern '{}': {}", parser.pattern, e))?;

        let fp = parser.fingerprint;
        let id = parser.id;

        {
            let mut parsers_guard = self.parsers.write().unwrap();
            let mut id_guard = self.by_id.write().unwrap();

            parsers_guard.insert(
                fp,
                CompiledDynamicParser {
                    parser,
                    regex: Some(re),
                },
            );
            id_guard.insert(id, fp);
        }

        let _ = self.save_to_disk();
        Ok(())
    }

    pub fn list_parsers(&self) -> Vec<DynamicParser> {
        let guard = self.parsers.read().unwrap();
        let mut list: Vec<DynamicParser> = guard.values().map(|c| c.parser.clone()).collect();
        list.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        list
    }

    pub fn get_parser(&self, id: Uuid) -> Option<DynamicParser> {
        let id_guard = self.by_id.read().unwrap();
        let fp = id_guard.get(&id)?;
        let parsers_guard = self.parsers.read().unwrap();
        parsers_guard.get(fp).map(|c| c.parser.clone())
    }

    pub fn update_parser(&self, id: Uuid, updated: DynamicParser) -> Result<(), String> {
        let re = RegexBuilder::new(&updated.pattern)
            .size_limit(1024 * 1024)
            .build()
            .map_err(|e| format!("Invalid regex pattern: {}", e))?;

        let id_guard = self.by_id.read().unwrap();
        let fp = id_guard.get(&id).ok_or("Parser not found")?;

        let mut parsers_guard = self.parsers.write().unwrap();
        if let Some(existing) = parsers_guard.get_mut(fp) {
            existing.parser = updated;
            existing.regex = Some(re);
            drop(parsers_guard);
            drop(id_guard);
            let _ = self.save_to_disk();
            Ok(())
        } else {
            Err("Parser not found".to_string())
        }
    }

    pub fn delete_parser(&self, id: Uuid) -> bool {
        let mut id_guard = self.by_id.write().unwrap();
        if let Some(fp) = id_guard.remove(&id) {
            let mut parsers_guard = self.parsers.write().unwrap();
            parsers_guard.remove(&fp);
            drop(parsers_guard);
            drop(id_guard);
            let _ = self.save_to_disk();
            true
        } else {
            false
        }
    }

    pub fn toggle_status(&self, id: Uuid, status: ParserStatus) -> Result<DynamicParser, String> {
        let id_guard = self.by_id.read().unwrap();
        let fp = id_guard.get(&id).ok_or("Parser not found")?;

        let mut parsers_guard = self.parsers.write().unwrap();
        if let Some(compiled) = parsers_guard.get_mut(fp) {
            compiled.parser.status = status;
            let cloned = compiled.parser.clone();
            drop(parsers_guard);
            drop(id_guard);
            let _ = self.save_to_disk();
            Ok(cloned)
        } else {
            Err("Parser not found".to_string())
        }
    }

    pub fn test_parser(&self, pattern: &str, raw_log: &str) -> Result<ParserTestResult, String> {
        ParserValidator::validate(pattern, &[raw_log.to_string()])
    }

    pub fn stats(&self) -> ParserStatsSummary {
        let parsers_guard = self.parsers.read().unwrap();
        let total = parsers_guard.len();
        let active = parsers_guard.values().filter(|c| c.parser.status == ParserStatus::Active).count();
        let pending = self.accumulator.count_pending();
        let execs = self.total_executions.load(Ordering::Relaxed);
        let total_us = self.total_latency_us.load(Ordering::Relaxed);
        let avg_lat = if execs > 0 {
            total_us as f64 / execs as f64
        } else {
            0.0
        };

        ParserStatsSummary {
            total_learned_parsers: total,
            active_parsers: active,
            pending_novel_fingerprints: pending,
            total_parses_executed: execs,
            average_latency_us: avg_lat,
        }
    }

    pub fn save_to_disk(&self) -> Result<(), String> {
        let parsers = self.list_parsers();
        if let Some(parent) = self.storage_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let json = serde_json::to_string_pretty(&parsers).map_err(|e| e.to_string())?;
        std::fs::write(&self.storage_path, json).map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn load_from_disk(&self) {
        if !self.storage_path.exists() {
            return;
        }
        if let Ok(bytes) = std::fs::read(&self.storage_path) {
            if let Ok(parsers) = serde_json::from_slice::<Vec<DynamicParser>>(&bytes) {
                let count = parsers.len();
                for p in parsers {
                    let _ = self.register_parser(p);
                }
                info!("DynamicParserRegistry: Loaded {} learned parsers from disk", count);
            }
        }
    }
}
