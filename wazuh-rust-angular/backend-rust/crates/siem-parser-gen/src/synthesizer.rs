use crate::models::{DynamicParser, ParserFieldDefinition, ParserStatus, ParserType};
use crate::validator::ParserValidator;
use chrono::Utc;
use regex::Regex;
use serde_json::Value;
use std::collections::HashMap;
use tracing::info;
use uuid::Uuid;

pub struct AiParserSynthesizer;

impl AiParserSynthesizer {
    /// Synthesize a reusable parser from sample logs.
    /// Tries AI LLM first (Groq/OpenAI if API key available), falls back to built-in structural inference.
    pub async fn synthesize(
        fingerprint: u64,
        signature: &str,
        samples: &[String],
        custom_instructions: Option<&str>,
    ) -> Result<DynamicParser, String> {
        if samples.is_empty() {
            return Err("No log samples provided for parser synthesis".to_string());
        }

        // Try AI generation first if GROQ_API_KEY or OPENAI_API_KEY is available
        let maybe_ai_result = Self::try_llm_synthesis(fingerprint, signature, samples, custom_instructions).await;

        let candidate = match maybe_ai_result {
            Ok(parser) => {
                info!("AI LLM successfully synthesized parser '{}'", parser.name);
                parser
            }
            Err(err_msg) => {
                info!("LLM synthesis unavailable or bypassed ({}). Using high-accuracy heuristic synthesizer.", err_msg);
                Self::synthesize_heuristic(fingerprint, signature, samples)?
            }
        };

        // Strictly validate candidate pattern against all samples in sandboxed validator
        let val_result = ParserValidator::validate(&candidate.pattern, samples)?;
        if !val_result.success {
            return Err(val_result.error.unwrap_or_else(|| "Validation on samples failed".to_string()));
        }

        Ok(candidate)
    }

    /// High-precision built-in structural inference engine (100% offline & autonomous)
    pub fn synthesize_heuristic(
        fingerprint: u64,
        signature: &str,
        samples: &[String],
    ) -> Result<DynamicParser, String> {
        let sample = samples.first().unwrap().trim();
        let mut fields = Vec::new();
        let mut normalization = HashMap::new();

        // 1. Check if log is JSON
        if (sample.starts_with('{') && sample.ends_with('}')) || (sample.starts_with('[') && sample.ends_with(']')) {
            if let Ok(Value::Object(map)) = serde_json::from_str::<Value>(sample) {
                for (k, v) in map.iter().take(10) {
                    let field_name = sanitize_group_name(k);
                    let field_type = match v {
                        Value::Number(_) => "integer".to_string(),
                        Value::Bool(_) => "boolean".to_string(),
                        _ => "string".to_string(),
                    };
                    fields.push(ParserFieldDefinition {
                        name: field_name.clone(),
                        field_type,
                        example: v.to_string(),
                        ecs_target: Some(format!("data.{}", k)),
                    });
                    normalization.insert(field_name, format!("data.{}", k));
                }
                let pattern = r#"^\{.*\}$"#.to_string();
                return Ok(DynamicParser {
                    id: Uuid::new_v4(),
                    fingerprint,
                    fingerprint_signature: signature.to_string(),
                    name: format!("json_auto_parser_{:x}", fingerprint),
                    description: "Auto-generated JSON log parser".to_string(),
                    parser_type: ParserType::JsonPath,
                    pattern,
                    fields,
                    normalization,
                    confidence: 0.95,
                    version: 1,
                    status: ParserStatus::Active,
                    sample_logs: samples.to_vec(),
                    hit_count: 0,
                    success_count: 0,
                    created_at: Utc::now(),
                    last_used: None,
                });
            }
        }

        // 2. Check if log contains Key-Value pairs (e.g. user=john src=192.168.1.50)
        let kv_re = Regex::new(r#"([\w\.\-]+)=([^\s,]+|"[^"]*")"#).unwrap();
        let kv_matches: Vec<_> = kv_re.captures_iter(sample).collect();

        if kv_matches.len() >= 2 {
            // Build key-value aware regex
            let mut pattern = String::from("^");
            let mut last_idx = 0;

            for cap in &kv_matches {
                let full_match = cap.get(0).unwrap();
                let key = &cap[1];
                let group_name = sanitize_group_name(key);

                // Escape intermediate literal prefix, generalizing any leading timestamp
                if full_match.start() > last_idx {
                    let prefix = &sample[last_idx..full_match.start()];
                    if last_idx == 0 {
                        let iso_ts = Regex::new(r"^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?\s+").unwrap();
                        let sys_ts = Regex::new(r"^(?:[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+").unwrap();
                        if let Some(m) = iso_ts.find(prefix) {
                            pattern.push_str(r"(?P<timestamp>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+");
                            let remainder = &prefix[m.end()..];
                            pattern.push_str(&regex::escape(remainder));
                            fields.insert(0, ParserFieldDefinition {
                                name: "timestamp".to_string(),
                                field_type: "datetime".to_string(),
                                example: m.as_str().trim().to_string(),
                                ecs_target: Some("@timestamp".to_string()),
                            });
                            normalization.insert("timestamp".to_string(), "timestamp".to_string());
                        } else if let Some(m) = sys_ts.find(prefix) {
                            pattern.push_str(r"(?P<timestamp>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+");
                            let remainder = &prefix[m.end()..];
                            pattern.push_str(&regex::escape(remainder));
                            fields.insert(0, ParserFieldDefinition {
                                name: "timestamp".to_string(),
                                field_type: "datetime".to_string(),
                                example: m.as_str().trim().to_string(),
                                ecs_target: Some("@timestamp".to_string()),
                            });
                            normalization.insert("timestamp".to_string(), "timestamp".to_string());
                        } else {
                            pattern.push_str(&regex::escape(prefix));
                        }
                    } else {
                        pattern.push_str(&regex::escape(prefix));
                    }
                }

                // Append capture group for value
                pattern.push_str(&format!("{}=(?P<{}>[^\\s,]+|\"[^\"]*\")", regex::escape(key), group_name));
                last_idx = full_match.end();

                let ecs = map_ecs_field(&group_name);
                fields.push(ParserFieldDefinition {
                    name: group_name.clone(),
                    field_type: infer_type(&cap[2]),
                    example: cap[2].to_string(),
                    ecs_target: Some(ecs.clone()),
                });
                normalization.insert(group_name, ecs);
            }

            if last_idx < sample.len() {
                pattern.push_str(&regex::escape(&sample[last_idx..]));
            }
            pattern.push('$');

            // Test if compiled regex works
            if ParserValidator::validate(&pattern, samples).map(|r| r.success).unwrap_or(false) {
                return Ok(DynamicParser {
                    id: Uuid::new_v4(),
                    fingerprint,
                    fingerprint_signature: signature.to_string(),
                    name: format!("kv_auto_parser_{:x}", fingerprint),
                    description: format!("Auto-generated Key-Value parser with {} extracted fields", fields.len()),
                    parser_type: ParserType::Regex,
                    pattern,
                    fields,
                    normalization,
                    confidence: 0.92,
                    version: 1,
                    status: ParserStatus::Active,
                    sample_logs: samples.to_vec(),
                    hit_count: 0,
                    success_count: 0,
                    created_at: Utc::now(),
                    last_used: None,
                });
            }
        }

        // 2B. Multi-sample cross-correlated Key-Value synthesizer
        // Identifies keys present across >= 70% of samples and safely handles unquoted spaces/variable parameters
        let kv_key_finder = Regex::new(r#"([\w\.\-]+)="#).unwrap();
        let mut sample_key_lists: Vec<Vec<String>> = Vec::new();
        for s in samples {
            let keys: Vec<String> = kv_key_finder
                .captures_iter(s)
                .map(|c| c[1].to_string())
                .collect();
            sample_key_lists.push(keys);
        }

        if !sample_key_lists.is_empty() && !sample_key_lists[0].is_empty() {
            let s0_keys = &sample_key_lists[0];
            let mut common_keys: Vec<String> = Vec::new();
            for k in s0_keys {
                let count = sample_key_lists.iter().filter(|l| l.contains(k)).count();
                if count * 10 >= samples.len() * 7 && k != "dc" {
                    if !common_keys.contains(k) {
                        common_keys.push(k.clone());
                    }
                }
            }

            if common_keys.len() >= 2 {
                let mut kv2_fields = Vec::new();
                let mut kv2_norm = HashMap::new();
                let mut pattern_parts = Vec::new();
                pattern_parts.push("^".to_string());

                // Check for timestamp prefix in sample 0
                let ts_re = Regex::new(r"^(?P<ts>\d{4}[-/]\d{2}[-/]\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)").unwrap();
                if let Some(m) = ts_re.captures(sample) {
                    pattern_parts.push(r"(?P<timestamp>\d{4}[-/]\d{2}[-/]\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+".to_string());
                    kv2_fields.push(ParserFieldDefinition {
                        name: "timestamp".to_string(),
                        field_type: "datetime".to_string(),
                        example: m["ts"].to_string(),
                        ecs_target: Some("@timestamp".to_string()),
                    });
                    kv2_norm.insert("timestamp".to_string(), "timestamp".to_string());
                }

                for (idx, key) in common_keys.iter().enumerate() {
                    let gname = sanitize_group_name(key);
                    let ecs = map_ecs_field(&gname);

                    if idx == common_keys.len() - 1 {
                        pattern_parts.push(format!(
                            r".*?{}=(?P<{}>.+?)(?:\s.*)?$",
                            regex::escape(key),
                            gname
                        ));
                    } else {
                        pattern_parts.push(format!(
                            r#".*?{}=(?P<{}>[^\s,]+|"[^"]*")"#,
                            regex::escape(key),
                            gname
                        ));
                    }

                    kv2_fields.push(ParserFieldDefinition {
                        name: gname.clone(),
                        field_type: "string".to_string(),
                        example: "".to_string(),
                        ecs_target: Some(ecs.clone()),
                    });
                    kv2_norm.insert(gname, ecs);
                }

                let pattern = pattern_parts.concat();
                if ParserValidator::validate(&pattern, samples).map(|r| r.success).unwrap_or(false) {
                    return Ok(DynamicParser {
                        id: Uuid::new_v4(),
                        fingerprint,
                        fingerprint_signature: signature.to_string(),
                        name: format!("kv_cross_corr_parser_{:x}", fingerprint),
                        description: format!("Cross-sample correlated Key-Value parser with {} extracted fields", kv2_fields.len()),
                        parser_type: ParserType::Regex,
                        pattern,
                        fields: kv2_fields,
                        normalization: kv2_norm,
                        confidence: 0.94,
                        version: 1,
                        status: ParserStatus::Active,
                        sample_logs: samples.to_vec(),
                        hit_count: 0,
                        success_count: 0,
                        created_at: Utc::now(),
                        last_used: None,
                    });
                }
            }
        }

        // 3. Check for standard Syslog structure: <timestamp> <host> <program>[<pid>]: <message>
        let syslog_re = Regex::new(
            r"^(?P<timestamp>(?:[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}|\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}))\s+(?P<hostname>\S+)\s+(?P<program>[\w\.\-]+)(?:\[(?P<pid>\d+)\])?:\s+(?P<message>.*)$"
        ).unwrap();

        if let Some(caps) = syslog_re.captures(sample) {
            let pattern = r"^(?P<timestamp>(?:[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}|\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}))\s+(?P<hostname>\S+)\s+(?P<program>[\w\.\-]+)(?:\[(?P<pid>\d+)\])?:\s+(?P<message>.*)$".to_string();

            // Try to extract additional tokens from message
            let msg = &caps["message"];
            let mut extra_fields = Vec::new();
            if let Some(ip_re) = Regex::new(r"\b(?P<src_ip>(?:\d{1,3}\.){3}\d{1,3})\b").ok() {
                if let Some(m) = ip_re.captures(msg) {
                    extra_fields.push(ParserFieldDefinition {
                        name: "src_ip".to_string(),
                        field_type: "ip".to_string(),
                        example: m["src_ip"].to_string(),
                        ecs_target: Some("source.ip".to_string()),
                    });
                    normalization.insert("src_ip".to_string(), "srcip".to_string());
                }
            }

            fields.push(ParserFieldDefinition {
                name: "timestamp".to_string(),
                field_type: "datetime".to_string(),
                example: caps["timestamp"].to_string(),
                ecs_target: Some("@timestamp".to_string()),
            });
            fields.push(ParserFieldDefinition {
                name: "hostname".to_string(),
                field_type: "string".to_string(),
                example: caps["hostname"].to_string(),
                ecs_target: Some("host.hostname".to_string()),
            });
            fields.push(ParserFieldDefinition {
                name: "program".to_string(),
                field_type: "string".to_string(),
                example: caps["program"].to_string(),
                ecs_target: Some("process.name".to_string()),
            });
            fields.push(ParserFieldDefinition {
                name: "message".to_string(),
                field_type: "string".to_string(),
                example: msg.to_string(),
                ecs_target: Some("message".to_string()),
            });
            fields.extend(extra_fields);

            normalization.insert("hostname".to_string(), "hostname".to_string());
            normalization.insert("program".to_string(), "program_name".to_string());

            return Ok(DynamicParser {
                id: Uuid::new_v4(),
                fingerprint,
                fingerprint_signature: signature.to_string(),
                name: format!("syslog_auto_parser_{:x}", fingerprint),
                description: format!("Auto-generated Syslog parser for '{}'", &caps["program"]),
                parser_type: ParserType::Regex,
                pattern,
                fields,
                normalization,
                confidence: 0.90,
                version: 1,
                status: ParserStatus::Active,
                sample_logs: samples.to_vec(),
                hit_count: 0,
                success_count: 0,
                created_at: Utc::now(),
                last_used: None,
            });
        }

        // 4. Token-split generic positional parser
        let tokens: Vec<&str> = sample.split_whitespace().collect();
        let mut pattern_parts = Vec::new();

        for (i, tok) in tokens.iter().enumerate() {
            if Regex::new(r"^\d{4}-\d{2}-\d{2}$").unwrap().is_match(tok) {
                pattern_parts.push(r"(?P<date>\d{4}-\d{2}-\d{2})".to_string());
                fields.push(ParserFieldDefinition {
                    name: "date".to_string(),
                    field_type: "datetime".to_string(),
                    example: tok.to_string(),
                    ecs_target: Some("@timestamp".to_string()),
                });
            } else if Regex::new(r"^\d{2}:\d{2}:\d{2}$").unwrap().is_match(tok) {
                pattern_parts.push(r"(?P<time>\d{2}:\d{2}:\d{2})".to_string());
                fields.push(ParserFieldDefinition {
                    name: "time".to_string(),
                    field_type: "datetime".to_string(),
                    example: tok.to_string(),
                    ecs_target: None,
                });
            } else if Regex::new(r"^(?:\d{1,3}\.){3}\d{1,3}$").unwrap().is_match(tok) {
                let name = format!("ip_{}", i);
                pattern_parts.push(format!(r"(?P<{}>\d+\.\d+\.\d+\.\d+)", name));
                fields.push(ParserFieldDefinition {
                    name: name.clone(),
                    field_type: "ip".to_string(),
                    example: tok.to_string(),
                    ecs_target: Some("source.ip".to_string()),
                });
                normalization.insert(name, "srcip".to_string());
            } else if Regex::new(r"^\d+$").unwrap().is_match(tok) {
                let name = format!("num_{}", i);
                pattern_parts.push(format!(r"(?P<{}>\d+)", name));
                fields.push(ParserFieldDefinition {
                    name,
                    field_type: "integer".to_string(),
                    example: tok.to_string(),
                    ecs_target: None,
                });
            } else {
                // Static anchor word
                pattern_parts.push(regex::escape(tok));
            }
        }

        let pattern = format!("^{}$", pattern_parts.join(r"\s+"));
        Ok(DynamicParser {
            id: Uuid::new_v4(),
            fingerprint,
            fingerprint_signature: signature.to_string(),
            name: format!("token_auto_parser_{:x}", fingerprint),
            description: "Auto-generated positional token parser".to_string(),
            parser_type: ParserType::Regex,
            pattern,
            fields,
            normalization,
            confidence: 0.85,
            version: 1,
            status: ParserStatus::Active,
            sample_logs: samples.to_vec(),
            hit_count: 0,
            success_count: 0,
            created_at: Utc::now(),
            last_used: None,
        })
    }

    /// Call LLM API (Groq llama-3.3-70b / OpenAI) if an API key is configured
    async fn try_llm_synthesis(
        fingerprint: u64,
        signature: &str,
        samples: &[String],
        custom_instructions: Option<&str>,
    ) -> Result<DynamicParser, String> {
        let (api_key, api_url, model) = if let Ok(key) = std::env::var("GROQ_API_KEY") {
            (key, "https://api.groq.com/openai/v1/chat/completions".to_string(), "llama-3.3-70b-versatile".to_string())
        } else if let Ok(key) = std::env::var("OPENAI_API_KEY") {
            (key, "https://api.openai.com/v1/chat/completions".to_string(), "gpt-4o-mini".to_string())
        } else {
            return Err("No GROQ_API_KEY or OPENAI_API_KEY found in environment".to_string());
        };

        let sample_bullet_points = samples
            .iter()
            .take(10)
            .enumerate()
            .map(|(i, s)| format!("{}. {}", i + 1, s))
            .collect::<Vec<_>>()
            .join("\n");

        let system_prompt = "You are an expert cybersecurity SIEM parser generator. \
Analyze the provided log samples and create a high-performance, robust Regex with named capture groups (?P<name>...). \
Normalize fields to ECS/Wazuh standard naming conventions (srcip, dstip, srcuser, dstuser, program_name, action, status). \
Return ONLY a valid JSON object matching the requested schema with no surrounding conversational text or markdown codeblocks.";

        let user_prompt = format!(
            "Log Fingerprint: 0x{:x}\nStructural Signature: {}\n\nSample Logs:\n{}\n\nAdditional Instructions: {}\n\n\
Return JSON format:\n\
{{\n  \"parser_name\": \"...\",\n  \"description\": \"...\",\n  \"pattern\": \"^regex_with_named_capture_groups$\",\n  \"fields\": [\n    {{\"name\": \"...\", \"field_type\": \"...\", \"example\": \"...\", \"ecs_target\": \"...\"}}\n  ],\n  \"normalization\": {{\n    \"extracted_name\": \"standard_wazuh_field\"\n  }},\n  \"confidence\": 0.95\n}}",
            fingerprint,
            signature,
            sample_bullet_points,
            custom_instructions.unwrap_or("None")
        );

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(12))
            .build()
            .map_err(|e| e.to_string())?;

        let body = serde_json::json!({
            "model": model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ],
            "response_format": {"type": "json_object"},
            "temperature": 0.1
        });

        let resp = client
            .post(&api_url)
            .bearer_auth(api_key)
            .json(&body)
            .send()
            .await
            .map_err(|e| format!("HTTP request to LLM failed: {}", e))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            return Err(format!("LLM API returned status {}: {}", status, text));
        }

        let json_resp: Value = resp.json().await.map_err(|e| format!("Failed to parse LLM response: {}", e))?;
        let content = json_resp["choices"][0]["message"]["content"]
            .as_str()
            .ok_or("Empty content in LLM response")?;

        let parsed: Value = serde_json::from_str(content)
            .map_err(|e| format!("Failed to parse inner JSON from LLM: {}. Content: {}", e, content))?;

        let name = parsed["parser_name"].as_str().unwrap_or("ai_generated_parser").to_string();
        let description = parsed["description"].as_str().unwrap_or("Parser synthesized by AI").to_string();
        let pattern = parsed["pattern"].as_str().ok_or("Missing 'pattern' in LLM response")?.to_string();
        let confidence = parsed["confidence"].as_f64().unwrap_or(0.9) as f32;

        let mut fields = Vec::new();
        if let Some(arr) = parsed["fields"].as_array() {
            for f in arr {
                fields.push(ParserFieldDefinition {
                    name: f["name"].as_str().unwrap_or_default().to_string(),
                    field_type: f["field_type"].as_str().unwrap_or("string").to_string(),
                    example: f["example"].as_str().unwrap_or_default().to_string(),
                    ecs_target: f["ecs_target"].as_str().map(|s| s.to_string()),
                });
            }
        }

        let mut normalization = HashMap::new();
        if let Some(obj) = parsed["normalization"].as_object() {
            for (k, v) in obj {
                if let Some(target) = v.as_str() {
                    normalization.insert(k.clone(), target.to_string());
                }
            }
        }

        Ok(DynamicParser {
            id: Uuid::new_v4(),
            fingerprint,
            fingerprint_signature: signature.to_string(),
            name,
            description,
            parser_type: ParserType::Regex,
            pattern,
            fields,
            normalization,
            confidence,
            version: 1,
            status: ParserStatus::Active,
            sample_logs: samples.to_vec(),
            hit_count: 0,
            success_count: 0,
            created_at: Utc::now(),
            last_used: None,
        })
    }
}

fn sanitize_group_name(raw: &str) -> String {
    let clean: String = raw
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '_' { c } else { '_' })
        .collect();
    if clean.chars().next().map(|c| c.is_ascii_digit()).unwrap_or(false) {
        format!("field_{}", clean)
    } else if clean.is_empty() {
        "field".to_string()
    } else {
        clean
    }
}

fn infer_type(val: &str) -> String {
    let trimmed = val.trim_matches('"').trim_matches('\'');
    if Regex::new(r"^(?:\d{1,3}\.){3}\d{1,3}$").unwrap().is_match(trimmed) {
        "ip".to_string()
    } else if trimmed.parse::<i64>().is_ok() {
        "integer".to_string()
    } else if trimmed.parse::<f64>().is_ok() {
        "float".to_string()
    } else if trimmed.eq_ignore_ascii_case("true") || trimmed.eq_ignore_ascii_case("false") {
        "boolean".to_string()
    } else {
        "string".to_string()
    }
}

fn map_ecs_field(name: &str) -> String {
    let lower = name.to_lowercase();
    if lower.contains("user") || lower.contains("srcuser") {
        "srcuser".to_string()
    } else if lower.contains("src") || lower.contains("ip") {
        "srcip".to_string()
    } else if lower.contains("dst") {
        "dstip".to_string()
    } else if lower.contains("port") {
        "srcport".to_string()
    } else if lower.contains("action") {
        "action".to_string()
    } else if lower.contains("status") {
        "status".to_string()
    } else {
        format!("data.{}", lower)
    }
}
