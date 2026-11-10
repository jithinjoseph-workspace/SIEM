use crate::models::ParserTestResult;
use regex::RegexBuilder;
use std::collections::HashMap;
use std::time::Instant;

pub struct ParserValidator;

impl ParserValidator {
    /// Sandboxed validation of a candidate regex pattern against a collection of sample logs.
    /// Defends against ReDoS via strict regex size and complexity limits.
    pub fn validate(
        pattern: &str,
        samples: &[String],
    ) -> Result<ParserTestResult, String> {
        if samples.is_empty() {
            return Err("No sample logs provided for validation".to_string());
        }

        // 1. Safe regex compilation with 1MB memory/complexity ceiling
        let re = RegexBuilder::new(pattern)
            .size_limit(1024 * 1024)
            .dfa_size_limit(2 * 1024 * 1024)
            .build()
            .map_err(|e| format!("Invalid regex pattern: {}", e))?;

        let capture_names: Vec<String> = re
            .capture_names()
            .flatten()
            .map(|s| s.to_string())
            .collect();

        if capture_names.is_empty() {
            return Err("Candidate regex does not define any named capture groups (?P<name>...)".to_string());
        }

        let mut matches_count = 0;
        let mut sample_extracted_fields = HashMap::new();
        let start_time = Instant::now();

        for sample in samples {
            if let Some(caps) = re.captures(sample) {
                matches_count += 1;

                if sample_extracted_fields.is_empty() {
                    for name in &capture_names {
                        if let Some(m) = caps.name(name) {
                            sample_extracted_fields.insert(name.clone(), m.as_str().to_string());
                        }
                    }
                }
            }
        }

        let elapsed = start_time.elapsed().as_micros() as u64;
        let total_samples = samples.len();
        let success = matches_count == total_samples || (matches_count as f32 / total_samples as f32) >= 0.8;

        if !success {
            return Ok(ParserTestResult {
                success: false,
                matches_count,
                total_samples,
                extracted_fields: sample_extracted_fields,
                execution_time_us: elapsed,
                error: Some(format!(
                    "Pattern only matched {}/{} samples ({:.0}%). Required >= 80%.",
                    matches_count,
                    total_samples,
                    (matches_count as f32 / total_samples as f32) * 100.0
                )),
            });
        }

        Ok(ParserTestResult {
            success: true,
            matches_count,
            total_samples,
            extracted_fields: sample_extracted_fields,
            execution_time_us: elapsed,
            error: None,
        })
    }

    /// Fast test of a single log against a pattern
    pub fn test_single(pattern: &str, raw_log: &str) -> Result<HashMap<String, String>, String> {
        let re = RegexBuilder::new(pattern)
            .size_limit(1024 * 1024)
            .build()
            .map_err(|e| format!("Invalid regex: {}", e))?;

        if let Some(caps) = re.captures(raw_log) {
            let mut map = HashMap::new();
            for name in re.capture_names().flatten() {
                if let Some(m) = caps.name(name) {
                    map.insert(name.to_string(), m.as_str().to_string());
                }
            }
            Ok(map)
        } else {
            Err("Regex did not match the provided log".to_string())
        }
    }
}
