//! Port of `src/shared/remoted_op.c` (`parse_agent_update_msg`,
//! `parse_uname_string`, `get_os_arch`): turns an agent keepalive into the
//! `agent_info_data` that remoted stores in wazuh-db.

use regex::Regex;
use serde_json::{Map, Value};
use std::sync::OnceLock;

/// `os_data`
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OsData {
    pub os_name: Option<String>,
    pub os_major: Option<String>,
    pub os_minor: Option<String>,
    pub os_build: Option<String>,
    pub os_version: Option<String>,
    pub os_codename: Option<String>,
    pub os_platform: Option<String>,
    pub os_arch: Option<String>,
    pub os_uname: Option<String>,
}

/// `agent_info_data`
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AgentInfoData {
    pub id: i64,
    pub osd: Option<OsData>,
    pub version: Option<String>,
    pub config_sum: Option<String>,
    pub merged_sum: Option<String>,
    pub manager_host: Option<String>,
    pub node_name: Option<String>,
    pub agent_ip: Option<String>,
    pub labels: Option<String>,
    pub connection_status: Option<String>,
    pub sync_status: Option<String>,
    pub group_config_status: Option<String>,
}

impl AgentInfoData {
    /// JSON for `global update-agent-data` (`wdb_update_agent_data`). NULL
    /// strings are omitted, as `cJSON_AddStringToObject(obj, k, NULL)` does.
    pub fn to_wdb_json(&self) -> String {
        let mut m = Map::new();
        let mut put = |k: &str, v: &Option<String>| {
            if let Some(v) = v {
                m.insert(k.into(), Value::String(v.clone()));
            }
        };
        put("version", &self.version);
        put("config_sum", &self.config_sum);
        put("merged_sum", &self.merged_sum);
        put("manager_host", &self.manager_host);
        put("node_name", &self.node_name);
        put("agent_ip", &self.agent_ip);
        put("labels", &self.labels);
        put("connection_status", &self.connection_status);
        put("sync_status", &self.sync_status);
        put("group_config_status", &self.group_config_status);
        if let Some(o) = &self.osd {
            put("os_name", &o.os_name);
            put("os_version", &o.os_version);
            put("os_major", &o.os_major);
            put("os_minor", &o.os_minor);
            put("os_codename", &o.os_codename);
            put("os_platform", &o.os_platform);
            put("os_build", &o.os_build);
            put("os_uname", &o.os_uname);
            put("os_arch", &o.os_arch);
        }
        // cJSON keeps insertion order with "id" first.
        let mut out = String::from("{\"id\":");
        out.push_str(&self.id.to_string());
        for (k, v) in m.iter_ordered() {
            out.push(',');
            out.push_str(&serde_json::to_string(k).unwrap());
            out.push(':');
            out.push_str(&serde_json::to_string(v).unwrap());
        }
        out.push('}');
        out
    }
}

/// serde_json's Map sorts keys unless `preserve_order` is on; keep the
/// insertion order explicitly to match cJSON output.
trait OrderedIter {
    fn iter_ordered(&self) -> Vec<(&String, &Value)>;
}
impl OrderedIter for Map<String, Value> {
    fn iter_ordered(&self) -> Vec<(&String, &Value)> {
        const ORDER: &[&str] = &[
            "version", "config_sum", "merged_sum", "manager_host", "node_name", "agent_ip", "labels",
            "connection_status", "sync_status", "group_config_status", "os_name", "os_version", "os_major",
            "os_minor", "os_codename", "os_platform", "os_build", "os_uname", "os_arch",
        ];
        let mut v: Vec<(&String, &Value)> = self.iter().collect();
        v.sort_by_key(|(k, _)| ORDER.iter().position(|o| o == k).unwrap_or(usize::MAX));
        v
    }
}

/// `get_os_arch`
pub fn get_os_arch(header: &str) -> Option<String> {
    const ARCHS: &[&str] = &["x86_64", "i386", "i686", "sparc", "amd64", "i86pc", "ia64", "AIX", "armv6", "armv7", "aarch64", "arm64"];
    ARCHS.iter().find(|a| header.contains(*a)).map(|a| a.to_string())
}

fn re(p: &'static str, cell: &'static OnceLock<Regex>) -> &'static Regex {
    cell.get_or_init(|| Regex::new(p).unwrap())
}

static RE_MAJOR: OnceLock<Regex> = OnceLock::new();
static RE_MINOR: OnceLock<Regex> = OnceLock::new();
static RE_BUILD: OnceLock<Regex> = OnceLock::new();
static RE_SUSE: OnceLock<Regex> = OnceLock::new();

/// `w_regexec(pattern, str, 2, match)`: capture group 1 of a POSIX ERE.
fn cap1(r: &Regex, s: &str) -> Option<String> {
    r.captures(s).and_then(|c| c.get(1)).map(|m| m.as_str().to_string())
}

fn major(s: &str) -> Option<String> {
    cap1(re(r"^([0-9]+)\.*", &RE_MAJOR), s)
}
fn minor(s: &str) -> Option<String> {
    cap1(re(r"^[0-9]+\.([0-9]+)\.*", &RE_MINOR), s)
}
fn build(s: &str) -> Option<String> {
    cap1(re(r"^[0-9]+\.[0-9]+\.([0-9]+(\.[0-9]+)*)\.*", &RE_BUILD), s)
}

/// `parse_uname_string` (non-Windows manager build).
pub fn parse_uname_string(uname: &str) -> OsData {
    let mut osd = OsData::default();
    if let Some(p) = uname.find(" [Ver: ") {
        // Windows: "Microsoft Windows 10 Pro [Ver: 10.0.19045.3693] |arch"
        osd.os_name = Some(uname[..p].to_string());
        let mut rest = uname[p + 7..].to_string();
        if let Some(b) = rest.find(']') {
            let after = rest[b + 1..].to_string();
            rest.truncate(b);
            if let Some(bar) = after.rfind('|') {
                let a = after[bar + 1..].trim_start_matches(' ');
                let a = a.split(' ').next().unwrap_or("");
                if !a.is_empty() {
                    osd.os_arch = Some(a.to_string());
                }
            }
        } else {
            tracing::warn!("Windows uname missing closing ']' in version field: '{rest}'");
        }
        osd.os_major = major(&rest);
        osd.os_minor = minor(&rest);
        osd.os_build = build(&rest);
        osd.os_version = Some(rest);
        osd.os_platform = Some("windows".into());
    } else {
        if let Some(p) = uname.find(" [") {
            let mut name = uname[p + 2..].to_string();
            if let Some(q) = name.find(": ") {
                let mut version = name[q + 2..].to_string();
                name.truncate(q);
                if version.ends_with(']') {
                    version.pop();
                }
                if let Some(c) = version.find(" (") {
                    let mut code = version[c + 2..].to_string();
                    version.truncate(c);
                    if code.ends_with(')') {
                        code.pop();
                    }
                    osd.os_codename = Some(code);
                }
                osd.os_major = major(&version);
                osd.os_minor = minor(&version).or_else(|| {
                    cap1(re(r"^[0-9]+-[Ss][Pp]([0-9]+)\.*", &RE_SUSE), &version)
                });
                osd.os_version = Some(version);
            } else if name.ends_with(']') {
                name.pop();
            }
            if let Some(b) = name.find('|') {
                osd.os_platform = Some(name[b + 1..].to_string());
                name.truncate(b);
            }
            osd.os_name = Some(name);
        }
        // The C code cut `uname` at " [" before looking for the architecture.
        osd.os_arch = get_os_arch(truncated_uname(uname));
    }
    osd
}

/// `parse_uname_string` writes a NUL at " [Ver: " (Windows) or " [" (others);
/// callers keep using that shortened string.
pub fn truncated_uname(uname: &str) -> &str {
    if let Some(p) = uname.find(" [Ver: ") {
        &uname[..p]
    } else if let Some(p) = uname.find(" [") {
        &uname[..p]
    } else {
        uname
    }
}

/// `parse_agent_update_msg`
pub fn parse_agent_update_msg(msg: &str, ossec_name: &str) -> AgentInfoData {
    let mut d = AgentInfoData::default();
    const AGENT_IP_LABEL: &str = "#\"_agent_ip\":";
    for line in msg.split('\n').filter(|l| !l.is_empty()) {
        match line.as_bytes()[0] {
            b'#' | b'!' | b'"' => {
                if let Some(ip) = line.strip_prefix(AGENT_IP_LABEL) {
                    d.agent_ip = Some(ip.to_string());
                } else {
                    // wm_strcat(&labels, line, '\n')
                    match &mut d.labels {
                        Some(l) => {
                            l.push('\n');
                            l.push_str(line);
                        }
                        None => d.labels = Some(line.to_string()),
                    }
                }
            }
            _ => {
                if let Some(p) = line.find(" - ") {
                    let uname = &line[..p];
                    let rest = &line[p + 3..];
                    let mut osd = parse_uname_string(uname);
                    osd.os_uname = Some(truncated_uname(uname).to_string());
                    d.osd = Some(osd);
                    if let Some(q) = rest.find(" / ") {
                        d.version = Some(rest[..q].to_string());
                        d.config_sum = Some(rest[q + 3..].to_string());
                    } else if let Some(q) = rest.find(ossec_name) {
                        d.version = Some(rest[q..].to_string());
                    }
                } else if let Some(p) = line.find(' ') {
                    // strncmp(str_tmp, "merged.mg", strlen("merged.mg") - 1)
                    if line[p + 1..].starts_with("merged.m") {
                        d.merged_sum = Some(line[..p].to_string());
                    }
                }
            }
        }
    }
    d
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn linux_keepalive() {
        let msg = "Linux |web01 |5.15.0-91-generic |#101-Ubuntu SMP |x86_64 [Ubuntu|ubuntu: 22.04.3 LTS (Jammy Jellyfish)] - Wazuh v4.14.7 / ab73af41699f13fdd81903b5f23d8d00\n\
                   fd756ba04d9c32c8848d4608bec41251 merged.mg\n#\"_agent_ip\":10.0.2.15\n\"env\":prod\n";
        let d = parse_agent_update_msg(msg, "Wazuh");
        let o = d.osd.as_ref().unwrap();
        assert_eq!(o.os_name.as_deref(), Some("Ubuntu"));
        assert_eq!(o.os_platform.as_deref(), Some("ubuntu"));
        assert_eq!(o.os_version.as_deref(), Some("22.04.3 LTS"));
        assert_eq!(o.os_codename.as_deref(), Some("Jammy Jellyfish"));
        assert_eq!(o.os_major.as_deref(), Some("22"));
        assert_eq!(o.os_minor.as_deref(), Some("04"));
        assert_eq!(o.os_arch.as_deref(), Some("x86_64"));
        assert_eq!(d.version.as_deref(), Some("Wazuh v4.14.7"));
        assert_eq!(d.config_sum.as_deref(), Some("ab73af41699f13fdd81903b5f23d8d00"));
        assert_eq!(d.merged_sum.as_deref(), Some("fd756ba04d9c32c8848d4608bec41251"));
        assert_eq!(d.agent_ip.as_deref(), Some("10.0.2.15"));
        assert_eq!(d.labels.as_deref(), Some("\"env\":prod"));
        assert_eq!(o.os_uname.as_deref(), Some("Linux |web01 |5.15.0-91-generic |#101-Ubuntu SMP |x86_64"));
    }

    #[test]
    fn windows_keepalive() {
        let o = parse_uname_string("Microsoft Windows 10 Pro [Ver: 10.0.19045.3693] |x86_64");
        assert_eq!(o.os_name.as_deref(), Some("Microsoft Windows 10 Pro"));
        assert_eq!(o.os_version.as_deref(), Some("10.0.19045.3693"));
        assert_eq!(o.os_major.as_deref(), Some("10"));
        assert_eq!(o.os_minor.as_deref(), Some("0"));
        assert_eq!(o.os_build.as_deref(), Some("19045.3693"));
        assert_eq!(o.os_platform.as_deref(), Some("windows"));
        assert_eq!(o.os_arch.as_deref(), Some("x86_64"));
    }

    #[test]
    fn wdb_json_order_and_nulls() {
        let d = AgentInfoData { id: 1, version: Some("Wazuh v4.14.7".into()), connection_status: Some("active".into()), ..Default::default() };
        assert_eq!(d.to_wdb_json(), r#"{"id":1,"version":"Wazuh v4.14.7","connection_status":"active"}"#);
    }
}
