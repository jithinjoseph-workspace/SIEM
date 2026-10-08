//! Wazuh LogCollector Engine (src/logcollector/logcollector.c)
//!
//! Orchestrates file harvesting, command execution, multiline parsing,
//! ignore/restrict filtering, state tracking, and log forwarding.

use crate::config::{LocalFileConfig, LogCollectorConfig, LogFormat};
use crate::filter::{apply_out_format, check_ignore_and_restrict};
use crate::readers::{
    decode_djb_multilog, format_command_output, FullCommandTracker, MultilineRegexParser,
};
use crate::state::FileStateManager;
use regex::Regex;
use std::fs::File;
use std::io::{BufRead, BufReader, Seek, SeekFrom};
use std::path::{Path, PathBuf};

/// Harvested event emitted by LogCollector
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HarvestedEvent {
    pub location: String,
    pub format: LogFormat,
    pub payload: String,
    pub target: Vec<String>,
}

pub struct LogCollectorEngine {
    pub config: LogCollectorConfig,
    pub state_mgr: FileStateManager,
    full_cmd_tracker: FullCommandTracker,
    multiline_parsers: Vec<Option<MultilineRegexParser>>,
    ignore_regexes: Vec<Vec<Regex>>,
    restrict_regexes: Vec<Vec<Regex>>,
}

impl LogCollectorEngine {
    pub fn new(config: LogCollectorConfig, state_mgr: FileStateManager) -> Self {
        let mut multiline_parsers = Vec::new();
        let mut ignore_regexes = Vec::new();
        let mut restrict_regexes = Vec::new();

        for lf in &config.localfiles {
            // Multiline
            if let Some(ref ml_cfg) = lf.multiline {
                let parser = MultilineRegexParser::new(ml_cfg.clone()).ok();
                multiline_parsers.push(parser);
            } else {
                multiline_parsers.push(None);
            }

            // Ignore regexes
            let mut ign_vec = Vec::new();
            for ign in &lf.ignore {
                if let Ok(re) = Regex::new(ign) {
                    ign_vec.push(re);
                }
            }
            ignore_regexes.push(ign_vec);

            // Restrict regexes
            let mut rest_vec = Vec::new();
            for rest in &lf.restrict {
                if let Ok(re) = Regex::new(rest) {
                    rest_vec.push(re);
                }
            }
            restrict_regexes.push(rest_vec);
        }

        Self {
            config,
            state_mgr,
            full_cmd_tracker: FullCommandTracker::new(),
            multiline_parsers,
            ignore_regexes,
            restrict_regexes,
        }
    }

    /// Scan and harvest all configured localfiles and commands
    pub fn harvest_all(&mut self) -> Vec<HarvestedEvent> {
        let mut events = Vec::new();

        for i in 0..self.config.localfiles.len() {
            let lf = self.config.localfiles[i].clone();

            match lf.log_format {
                LogFormat::Command => {
                    if let Some(ref cmd_str) = lf.command {
                        let alias = lf.alias.as_deref().unwrap_or(cmd_str);
                        if let Ok(output) = run_shell_command(cmd_str) {
                            for line in output.lines() {
                                let formatted = format_command_output(alias, line);
                                if !self.is_ignored(i, &formatted) {
                                    events.push(HarvestedEvent {
                                        location: alias.to_string(),
                                        format: LogFormat::Command,
                                        payload: formatted,
                                        target: lf.target.clone(),
                                    });
                                }
                            }
                        }
                    }
                }
                LogFormat::FullCommand => {
                    if let Some(ref cmd_str) = lf.command {
                        let alias = lf.alias.as_deref().unwrap_or(cmd_str);
                        if let Ok(output) = run_shell_command(cmd_str) {
                            if let Some(diff_out) = self.full_cmd_tracker.evaluate_output(alias, &output) {
                                if !self.is_ignored(i, &diff_out) {
                                    events.push(HarvestedEvent {
                                        location: alias.to_string(),
                                        format: LogFormat::FullCommand,
                                        payload: diff_out,
                                        target: lf.target.clone(),
                                    });
                                }
                            }
                        }
                    }
                }
                _ => {
                    // File-based sources (syslog, json, multiline, audit, etc.)
                    if let Some(ref loc) = lf.location {
                        let paths = resolve_globs(loc);
                        for path in paths {
                            let file_events = self.harvest_file(i, &path, &lf);
                            events.extend(file_events);
                        }
                    }
                }
            }
        }

        events
    }

    fn harvest_file(&mut self, lf_idx: usize, path: &Path, lf: &LocalFileConfig) -> Vec<HarvestedEvent> {
        let mut events = Vec::new();
        let path_str = path.to_string_lossy().to_string();

        let file = match File::open(path) {
            Ok(f) => f,
            Err(_) => return events,
        };

        let file_len = match file.metadata() {
            Ok(m) => m.len(),
            Err(_) => return events,
        };

        let mut reader = BufReader::new(file);

        // Resume from previous offset
        let prev_offset = self.state_mgr.get_offset(&path_str).unwrap_or(0);
        let start_offset = if prev_offset > file_len {
            // File truncated / rotated! Start from beginning
            0
        } else {
            prev_offset
        };

        if reader.seek(SeekFrom::Start(start_offset)).is_err() {
            return events;
        }

        let mut current_offset = start_offset;
        let mut line_buf = String::new();
        let mut lines_count = 0u64;
        let mut drop_count = 0u64;

        loop {
            line_buf.clear();
            match reader.read_line(&mut line_buf) {
                Ok(0) => break, // EOF reached
                Ok(bytes) => {
                    current_offset += bytes as u64;
                    let line = line_buf.trim_end_matches(['\r', '\n']);

                    if line.is_empty() {
                        continue;
                    }

                    // DJB decoding
                    let decoded_line = if lf.log_format == LogFormat::DjbMultilog {
                        decode_djb_multilog(line)
                    } else {
                        line.to_string()
                    };

                    // Check ignore & restrict
                    if self.is_ignored(lf_idx, &decoded_line) {
                        drop_count += 1;
                        continue;
                    }

                    // Multiline handling
                    if let Some(ref mut ml_parser) = self.multiline_parsers[lf_idx] {
                        if let Some(agg) = ml_parser.process_line(&decoded_line) {
                            lines_count += 1;
                            let final_payload = apply_out_format_if_configured(&agg, lf, &path_str);
                            events.push(HarvestedEvent {
                                location: path_str.clone(),
                                format: lf.log_format.clone(),
                                payload: final_payload,
                                target: lf.target.clone(),
                            });
                        }
                    } else {
                        lines_count += 1;
                        let final_payload = apply_out_format_if_configured(&decoded_line, lf, &path_str);
                        events.push(HarvestedEvent {
                            location: path_str.clone(),
                            format: lf.log_format.clone(),
                            payload: final_payload,
                            target: lf.target.clone(),
                        });
                    }
                }
                Err(_) => break,
            }
        }

        // Flush any remaining multiline buffer
        if let Some(ref mut ml_parser) = self.multiline_parsers[lf_idx] {
            if let Some(agg) = ml_parser.flush() {
                lines_count += 1;
                let final_payload = apply_out_format_if_configured(&agg, lf, &path_str);
                events.push(HarvestedEvent {
                    location: path_str.clone(),
                    format: lf.log_format.clone(),
                    payload: final_payload,
                    target: lf.target.clone(),
                });
            }
        }

        // Update state
        let hash = FileStateManager::calculate_file_hash(path, 64).unwrap_or_default();
        self.state_mgr.update(&path_str, current_offset, &hash, lines_count, drop_count);

        events
    }

    fn is_ignored(&self, lf_idx: usize, line: &str) -> bool {
        let ignore = &self.ignore_regexes[lf_idx];
        let restrict = &self.restrict_regexes[lf_idx];
        check_ignore_and_restrict(ignore, restrict, line)
    }
}

fn apply_out_format_if_configured(payload: &str, lf: &LocalFileConfig, location: &str) -> String {
    if let Some(out_fmt) = lf.out_format.first() {
        apply_out_format(&out_fmt.format, location, payload)
    } else {
        payload.to_string()
    }
}

fn resolve_globs(pattern: &str) -> Vec<PathBuf> {
    if pattern.contains('*') || pattern.contains('?') {
        glob::glob(pattern)
            .map(|paths| paths.filter_map(Result::ok).collect())
            .unwrap_or_default()
    } else {
        let p = PathBuf::from(pattern);
        if p.exists() {
            vec![p]
        } else {
            Vec::new()
        }
    }
}

fn run_shell_command(cmd: &str) -> Result<String, String> {
    #[cfg(target_os = "windows")]
    let output = std::process::Command::new("powershell")
        .args(["-NoProfile", "-Command", cmd])
        .output();

    #[cfg(not(target_os = "windows"))]
    let output = std::process::Command::new("sh")
        .args(["-c", cmd])
        .output();

    match output {
        Ok(out) => Ok(String::from_utf8_lossy(&out.stdout).to_string()),
        Err(e) => Err(e.to_string()),
    }
}
