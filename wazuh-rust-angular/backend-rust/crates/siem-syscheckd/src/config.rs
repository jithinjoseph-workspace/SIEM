use quick_xml::events::Event;
use quick_xml::reader::Reader;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

// FIM Bitmask flags matching Wazuh syscheck.h
pub const CHECK_SIZE: u32 = 0x0001;
pub const CHECK_PERM: u32 = 0x0002;
pub const CHECK_OWNER: u32 = 0x0004;
pub const CHECK_GROUP: u32 = 0x0008;
pub const CHECK_MD5SUM: u32 = 0x0010;
pub const CHECK_SHA1SUM: u32 = 0x0020;
pub const CHECK_REALTIME: u32 = 0x0040;
pub const CHECK_SEECHANGES: u32 = 0x0080; // report_changes
pub const CHECK_SHA256SUM: u32 = 0x0100;
pub const CHECK_WHODATA: u32 = 0x0200;
pub const CHECK_INODE: u32 = 0x0400;
pub const CHECK_MTIME: u32 = 0x0800;
pub const CHECK_FOLLOW_SYMLINK: u32 = 0x1000;

pub const CHECK_ALL: u32 = CHECK_SIZE
    | CHECK_PERM
    | CHECK_OWNER
    | CHECK_GROUP
    | CHECK_MD5SUM
    | CHECK_SHA1SUM
    | CHECK_SHA256SUM
    | CHECK_INODE
    | CHECK_MTIME;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitoredDirectory {
    pub path: PathBuf,
    pub options: u32,
    pub recursion_limit: Option<usize>,
}

impl MonitoredDirectory {
    pub fn new(path: impl Into<PathBuf>, options: u32) -> Self {
        Self {
            path: path.into(),
            options,
            recursion_limit: None,
        }
    }

    pub fn has_opt(&self, opt: u32) -> bool {
        (self.options & opt) != 0
    }
}

#[derive(Debug, Clone)]
pub struct SyscheckConfig {
    pub disabled: bool,
    pub frequency: u64,
    pub scan_on_start: bool,
    pub max_files_per_second: usize,
    pub file_limit: usize,
    pub disk_quota_mb: usize,
    pub file_size_limit_mb: usize,
    pub directories: Vec<MonitoredDirectory>,
    pub ignore_patterns: Vec<Regex>,
    pub nodiff_patterns: Vec<Regex>,
    pub registry_keys: Vec<String>,
}

impl Default for SyscheckConfig {
    fn default() -> Self {
        Self {
            disabled: false,
            frequency: 43200, // 12 hours
            scan_on_start: true,
            max_files_per_second: 1000,
            file_limit: 100000,
            disk_quota_mb: 1024,
            file_size_limit_mb: 50,
            directories: Vec::new(),
            ignore_patterns: Vec::new(),
            nodiff_patterns: Vec::new(),
            registry_keys: Vec::new(),
        }
    }
}

impl SyscheckConfig {
    /// Check if a path should be ignored from FIM scanning
    pub fn is_ignored(&self, path_str: &str) -> bool {
        self.ignore_patterns.iter().any(|re| re.is_match(path_str))
    }

    /// Check if a path is excluded from diff generation
    pub fn is_nodiff(&self, path_str: &str) -> bool {
        self.nodiff_patterns.iter().any(|re| re.is_match(path_str))
    }

    /// Parses options string (e.g. check_all="yes", realtime="yes", report_changes="yes")
    pub fn parse_opts(attrs: &[(&str, &str)]) -> u32 {
        let mut opts = 0u32;
        let mut check_all = false;

        for (k, v) in attrs {
            let is_yes = *v == "yes" || *v == "true" || *v == "1";
            match *k {
                "check_all" if is_yes => check_all = true,
                "check_sum" | "check_sha256sum" if is_yes => opts |= CHECK_SHA256SUM,
                "check_sha1sum" if is_yes => opts |= CHECK_SHA1SUM,
                "check_md5sum" if is_yes => opts |= CHECK_MD5SUM,
                "check_size" if is_yes => opts |= CHECK_SIZE,
                "check_owner" if is_yes => opts |= CHECK_OWNER,
                "check_group" if is_yes => opts |= CHECK_GROUP,
                "check_perm" if is_yes => opts |= CHECK_PERM,
                "check_mtime" if is_yes => opts |= CHECK_MTIME,
                "check_inode" if is_yes => opts |= CHECK_INODE,
                "realtime" if is_yes => opts |= CHECK_REALTIME,
                "report_changes" | "seechanges" if is_yes => opts |= CHECK_SEECHANGES,
                "whodata" if is_yes => opts |= CHECK_WHODATA,
                "follow_symbolic_link" if is_yes => opts |= CHECK_FOLLOW_SYMLINK,
                _ => {}
            }
        }

        if check_all {
            opts |= CHECK_ALL;
        }

        if opts == 0 {
            opts = CHECK_ALL; // Default if nothing specified
        }

        opts
    }

    /// Parse XML <syscheck> configuration block
    pub fn parse_xml(xml: &str) -> Result<Self, String> {
        let mut cfg = Self::default();
        let mut reader = Reader::from_str(xml);
        reader.config_mut().trim_text(true);

        let mut buf = Vec::new();
        let mut current_tag = String::new();
        let mut current_attrs: Vec<(String, String)> = Vec::new();

        loop {
            match reader.read_event_into(&mut buf) {
                Ok(Event::Start(ref e)) => {
                    current_tag = String::from_utf8_lossy(e.name().as_ref()).to_string();
                    current_attrs.clear();
                    for a in e.attributes().flatten() {
                        let k = String::from_utf8_lossy(a.key.as_ref()).to_string();
                        let v = String::from_utf8_lossy(&a.value).to_string();
                        current_attrs.push((k, v));
                    }
                }
                Ok(Event::Text(ref e)) => {
                    let text = e.unescape().map_err(|err| err.to_string())?.to_string();
                    let trimmed = text.trim();
                    if trimmed.is_empty() {
                        continue;
                    }

                    match current_tag.as_str() {
                        "disabled" => cfg.disabled = trimmed == "yes",
                        "frequency" => cfg.frequency = trimmed.parse().unwrap_or(43200),
                        "scan_on_start" => cfg.scan_on_start = trimmed == "yes",
                        "max_files_per_second" => cfg.max_files_per_second = trimmed.parse().unwrap_or(1000),
                        "file_limit" => cfg.file_limit = trimmed.parse().unwrap_or(100000),
                        "directories" => {
                            let attr_refs: Vec<(&str, &str)> = current_attrs
                                .iter()
                                .map(|(k, v)| (k.as_str(), v.as_str()))
                                .collect();
                            let opts = Self::parse_opts(&attr_refs);

                            for path_item in trimmed.split(',') {
                                let p = path_item.trim();
                                if !p.is_empty() {
                                    cfg.directories.push(MonitoredDirectory::new(p, opts));
                                }
                            }
                        }
                        "ignore" => {
                            if let Ok(re) = Regex::new(trimmed) {
                                cfg.ignore_patterns.push(re);
                            }
                        }
                        "nodiff" => {
                            if let Ok(re) = Regex::new(trimmed) {
                                cfg.nodiff_patterns.push(re);
                            }
                        }
                        "windows_registry" => {
                            cfg.registry_keys.push(trimmed.to_string());
                        }
                        _ => {}
                    }
                }
                Ok(Event::End(_)) => {
                    current_tag.clear();
                    current_attrs.clear();
                }
                Ok(Event::Eof) => break,
                Err(e) => return Err(format!("XML error: {e}")),
                _ => {}
            }
            buf.clear();
        }

        Ok(cfg)
    }
}
