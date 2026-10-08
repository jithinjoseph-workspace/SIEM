//! Port of `src/shared/cluster_utils.c`: cluster role lookups that read
//! `ossec.conf` directly.

use siem_xml::OsXml;
use std::path::Path;

fn read(cfg: &Path) -> Option<OsXml> {
    match OsXml::read_file(cfg, false) {
        Ok(x) => Some(x),
        Err(e) => {
            tracing::debug!("{}", crate::messages::xml_error(&cfg.display().to_string(), &e.message, e.line));
            None
        }
    }
}

fn is_worker_type(t: &str) -> bool {
    t == "client" || t == "worker"
}

/// `w_is_worker`: `Some(true)` worker, `Some(false)` master or no cluster,
/// `None` when `ossec.conf` cannot be read or the type is missing.
pub fn is_worker(cfg: &Path) -> Option<bool> {
    let mut x = read(cfg)?;
    let cl = x.get_one_content_for_element(&["ossec_config", "cluster"]);
    match cl {
        Some(c) if !c.is_empty() => {
            let ty = x.get_one_content_for_element(&["ossec_config", "cluster", "node_type"]);
            match ty {
                Some(t) if !t.is_empty() => {
                    let st = x.get_one_content_for_element(&["ossec_config", "cluster", "disabled"]);
                    match st {
                        Some(s) if !s.is_empty() => Some(s == "no" && is_worker_type(&t)),
                        _ => Some(is_worker_type(&t)),
                    }
                }
                _ => None,
            }
        }
        _ => Some(false),
    }
}

/// `w_is_single_node`: (is_single_node, is_worker). `None` for unreadable config.
pub fn is_single_node(cfg: &Path) -> (Option<bool>, Option<bool>) {
    let Some(mut x) = read(cfg) else { return (None, None) };
    let cl = x.get_one_content_for_element(&["ossec_config", "cluster"]);
    match cl {
        Some(c) if !c.is_empty() => {
            let ty = x.get_one_content_for_element(&["ossec_config", "cluster", "node_type"]);
            match ty {
                Some(t) if !t.is_empty() => {
                    let st = x.get_one_content_for_element(&["ossec_config", "cluster", "disabled"]);
                    match st {
                        Some(s) if !s.is_empty() && s == "no" => (Some(false), Some(is_worker_type(&t))),
                        _ => (Some(true), None),
                    }
                }
                _ => (Some(true), None),
            }
        }
        _ => (Some(true), None),
    }
}

fn get(cfg: &Path, path: &[&str]) -> String {
    read(cfg)
        .and_then(|mut x| x.get_one_content_for_element(path))
        .unwrap_or_else(|| "undefined".to_string())
}

/// `get_node_name`
pub fn node_name(cfg: &Path) -> String {
    get(cfg, &["ossec_config", "cluster", "node_name"])
}

/// `get_cluster_name`
pub fn cluster_name(cfg: &Path) -> String {
    get(cfg, &["ossec_config", "cluster", "name"])
}

/// `get_master_node`
pub fn master_node(cfg: &Path) -> String {
    get(cfg, &["ossec_config", "cluster", "nodes", "node"])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roles() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("ossec.conf");
        std::fs::write(&f, "<ossec_config><global><logall>no</logall></global></ossec_config>").unwrap();
        assert_eq!(is_worker(&f), Some(false));
        assert_eq!(is_single_node(&f).0, Some(true));
        assert_eq!(node_name(&f), "undefined");
        std::fs::write(
            &f,
            "<ossec_config>\n  <cluster>\n    <name>wazuh</name>\n    <node_name>worker01</node_name>\n    <node_type>worker</node_type>\n    <disabled>no</disabled>\n  </cluster>\n</ossec_config>\n",
        )
        .unwrap();
        assert_eq!(is_worker(&f), Some(true));
        assert_eq!(is_single_node(&f), (Some(false), Some(true)));
        assert_eq!(node_name(&f), "worker01");
        assert_eq!(cluster_name(&f), "wazuh");
        std::fs::write(&f, "<ossec_config><cluster><node_type>master</node_type><disabled>yes</disabled></cluster></ossec_config>").unwrap();
        // <cluster> has no text content of its own here, so Wazuh treats it as absent.
        assert_eq!(is_worker(&f), Some(false));
    }
}

/// The `_Config` fields `Read_Cluster` (config/cluster-config.c) sets.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ClusterSettings {
    pub cluster_name: Option<String>,
    pub node_name: Option<String>,
    pub node_type: Option<String>,
    pub hide_cluster_info: bool,
}

const C_VALID: &str = r##"!"#$%&'-.0123456789:<=>?ABCDEFGHIJKLMNOPQRESTUVWXYZ[\]^_abcdefghijklmnopqrstuvwxyz{|}~"##;

fn all_valid(s: &str) -> bool {
    s.bytes().all(|b| C_VALID.as_bytes().contains(&b))
}

/// `Read_Cluster`. Note the C scoping: the `disabled` override is applied
/// after every element, so `disabled=yes` always wins over `hidden`.
pub fn read_cluster(
    ctx: &mut crate::ConfigContext,
    xml: &OsXml,
    nodes: &[siem_xml::XmlNode],
    cfg: &mut ClusterSettings,
) -> crate::Result<()> {
    use crate::{messages, ConfigError};
    cfg.hide_cluster_info = false;
    let mut disable = false;
    for n in nodes {
        let Some(c) = n.content.as_deref() else {
            return Err(ConfigError::new(messages::xml_valuenull(&n.element)));
        };
        match n.element.as_str() {
            "name" => {
                if c.is_empty() {
                    return Err(ConfigError::new("Cluster name is empty in configuration"));
                } else if !all_valid(c) {
                    return Err(ConfigError::new(format!(
                        "Detected a not allowed character in cluster name: \"{c}\". Characters allowed: \"{C_VALID}\"."
                    )));
                }
                cfg.cluster_name = Some(c.to_string());
            }
            "node_name" => {
                if c.is_empty() {
                    return Err(ConfigError::new("Node name is empty in configuration"));
                } else if !all_valid(c) {
                    return Err(ConfigError::new(format!(
                        "Detected a not allowed character in node name: \"{c}\". Characters allowed: \"{C_VALID}\"."
                    )));
                }
                cfg.node_name = Some(c.to_string());
            }
            "node_type" => {
                if c.is_empty() {
                    return Err(ConfigError::new("Node type is empty in configuration"));
                } else if c != "worker" && c != "client" && c != "master" {
                    return Err(ConfigError::new(format!(
                        "Detected a not allowed node type '{c}'. Valid types are 'master' and 'worker'."
                    )));
                }
                cfg.node_type = Some(c.to_string());
            }
            "key" | "socket_timeout" | "connection_timeout" | "nodes" | "port" | "bind_addr" => {}
            "disabled" => {
                if c != "yes" && c != "no" {
                    return Err(ConfigError::new(format!(
                        "Detected a not allowed value for disabled tag '{c}'. Valid values are 'yes' and 'no'."
                    )));
                }
                if c == "yes" {
                    disable = true;
                }
            }
            "hidden" => match c {
                "yes" => cfg.hide_cluster_info = true,
                "no" => cfg.hide_cluster_info = false,
                _ => return Err(ConfigError::new(messages::xml_valueerr(&n.element, c))),
            },
            "interval" => ctx.warn("Detected a deprecated configuration for cluster. Interval option is not longer available."),
            "haproxy_helper" => {
                let Some(children) = xml.get_elements_by_node(Some(n)) else {
                    continue;
                };
                for ch in &children {
                    let cc = ch.content.as_deref().unwrap_or("");
                    match ch.element.as_str() {
                        "haproxy_disabled" => {
                            if cc != "yes" && cc != "no" {
                                return Err(ConfigError::new(format!(
                                    "Detected an invalid value for the disabled tag '{}'. Valid values are 'yes' and 'no'.",
                                    ch.element
                                )));
                            }
                        }
                        // These checks look at the <haproxy_helper> node's own content.
                        "haproxy_address" if c.is_empty() => {
                            return Err(ConfigError::new("HAProxy address is missing in the configuration"))
                        }
                        "haproxy_user" if c.is_empty() => {
                            return Err(ConfigError::new("HAProxy user is missing in the configuration"))
                        }
                        "haproxy_password" if c.is_empty() => {
                            return Err(ConfigError::new("HAProxy password is missing in the configuration"))
                        }
                        "haproxy_protocol" => {
                            if cc != "http" && cc != "https" {
                                return Err(ConfigError::new(format!(
                                    "Detected an invalid value for the haproxy_protocol tag '{}'. Valid values are 'http' and 'https'.",
                                    ch.element
                                )));
                            }
                        }
                        "frequency" | "haproxy_address" | "haproxy_port" | "haproxy_user" | "haproxy_password"
                        | "haproxy_cert" | "client_cert" | "client_cert_key" | "client_cert_password" | "haproxy_backend"
                        | "haproxy_resolver" | "excluded_nodes" | "agent_chunk_size" | "agent_reconnection_time"
                        | "agent_reconnection_stability_time" | "imbalance_tolerance" | "remove_disconnected_node_after" => {}
                        e => return Err(ConfigError::new(messages::xml_invelem(e))),
                    }
                }
            }
            e => return Err(ConfigError::new(messages::xml_invelem(e))),
        }
        if disable {
            cfg.hide_cluster_info = true;
        }
    }
    Ok(())
}
