//! Port of `src/config/remote-config.c` (`Read_Remote`) and the `remoted`
//! configuration structure (`remote-config.h`).

use crate::messages::*;
use crate::util::{atoi, parse_time, str_is_num, strtol};
use crate::{ConfigContext, ConfigError, Result};
use siem_regex::{is_valid_ip, OsIp};
use siem_xml::{OsXml, XmlNode};

pub const SYSLOG_CONN: i32 = 1;
pub const SECURE_CONN: i32 = 2;
pub const REMOTED_NET_PROTOCOL_TCP: i32 = 1 << 0;
pub const REMOTED_NET_PROTOCOL_UDP: i32 = 1 << 1;
pub const REMOTED_NET_PROTOCOL_TCP_UDP: i32 = REMOTED_NET_PROTOCOL_TCP | REMOTED_NET_PROTOCOL_UDP;
pub const REMOTED_NET_PROTOCOL_DEFAULT: i32 = REMOTED_NET_PROTOCOL_TCP;
pub const REMOTED_NET_PROTOCOL_TCP_STR: &str = "TCP";
pub const REMOTED_NET_PROTOCOL_UDP_STR: &str = "UDP";
pub const REMOTED_NET_PROTOCOL_DEFAULT_STR: &str = "TCP";
pub const REMOTED_RIDS_CLOSING_TIME_DEFAULT: i32 = 5 * 60;
pub const DEFAULT_SECURE: i32 = 1514;
pub const DEFAULT_SYSLOG: i32 = 514;

/// One `<remote>` block.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RemoteConnection {
    pub conn: i32,
    pub port: i32,
    pub proto: i32,
    pub ipv6: bool,
    pub lip: Option<String>,
}

/// `remoted` (configuration part).
#[derive(Debug, Clone)]
pub struct RemotedConfig {
    pub connections: Vec<RemoteConnection>,
    pub allowips: Vec<OsIp>,
    pub denyips: Vec<OsIp>,
    pub allow_higher_versions: bool,
    pub queue_size: i64,
    pub rids_closing_time: i32,
    pub connection_overtake_time: i32,
    /// `global.agents_disconnection_time`
    pub agents_disconnection_time: i64,
    /// `global.agents_disconnection_alert_time`
    pub agents_disconnection_alert_time: i64,
}

impl Default for RemotedConfig {
    /// Values set by `RemotedConfig()` before `ReadConfig`.
    fn default() -> Self {
        Self {
            connections: Vec::new(),
            allowips: Vec::new(),
            denyips: Vec::new(),
            allow_higher_versions: false,
            queue_size: 131072,
            rids_closing_time: REMOTED_RIDS_CLOSING_TIME_DEFAULT,
            connection_overtake_time: 60,
            agents_disconnection_time: 900,
            agents_disconnection_alert_time: 0,
        }
    }
}

/// `w_remoted_get_net_protocol`
fn get_net_protocol(ctx: &mut ConfigContext, content: &str) -> i32 {
    let mut ret = 0;
    if let Some(parts) = siem_regex::str_break(',', content, 64) {
        for p in parts {
            let w = p.trim_start_matches(' ');
            let w = w.split(' ').next().unwrap_or("");
            if w.eq_ignore_ascii_case(REMOTED_NET_PROTOCOL_TCP_STR) {
                ret |= REMOTED_NET_PROTOCOL_TCP;
            } else if w.eq_ignore_ascii_case(REMOTED_NET_PROTOCOL_UDP_STR) {
                ret |= REMOTED_NET_PROTOCOL_UDP;
            } else {
                ctx.warn(remoted_inv_value_ignore(w, "protocol"));
            }
        }
    }
    if ret == 0 {
        ctx.warn(remoted_net_protocol_error(REMOTED_NET_PROTOCOL_DEFAULT_STR));
        ret = REMOTED_NET_PROTOCOL_DEFAULT;
    }
    ret
}

/// `Read_Remote`
pub fn read_remote(ctx: &mut ConfigContext, xml: &OsXml, nodes: &[XmlNode], logr: &mut RemotedConfig) -> Result<()> {
    let mut secure_count = logr.connections.iter().filter(|c| c.conn == SECURE_CONN).count();
    if secure_count > 1 {
        return Err(ConfigError::new(DUP_SECURE));
    }
    let mut cur = RemoteConnection::default();
    logr.rids_closing_time = REMOTED_RIDS_CLOSING_TIME_DEFAULT;
    let mut defined_queue_size = false;

    for n in nodes {
        let Some(c) = n.content.as_deref() else {
            return Err(ConfigError::new(xml_valuenull(&n.element)));
        };
        let el = n.element.as_str();
        if el.eq_ignore_ascii_case("connection") {
            if c == "syslog" {
                cur.conn = SYSLOG_CONN;
            } else if c == "secure" {
                cur.conn = SECURE_CONN;
                secure_count += 1;
                if secure_count > 1 {
                    return Err(ConfigError::new(DUP_SECURE));
                }
            } else {
                return Err(ConfigError::new(xml_valueerr(el, c)));
            }
        } else if el.eq_ignore_ascii_case("port") {
            if !str_is_num(c) {
                return Err(ConfigError::new(xml_valueerr(el, c)));
            }
            cur.port = atoi(c);
            if cur.port <= 0 || cur.port > 65535 {
                return Err(ConfigError::new(port_error(cur.port as i64)));
            }
        } else if el.eq_ignore_ascii_case("protocol") {
            cur.proto = get_net_protocol(ctx, c);
        } else if el.eq_ignore_ascii_case("ipv6") {
            if c.eq_ignore_ascii_case("yes") {
                cur.ipv6 = true;
            } else if c.eq_ignore_ascii_case("no") {
                cur.ipv6 = false;
            } else {
                ctx.warn(remoted_inv_value_ignore(c, "ipv6"));
            }
        } else if el.eq_ignore_ascii_case("local_ip") {
            if is_valid_ip(c).0 != 1 {
                return Err(ConfigError::new(invalid_ip(c)));
            }
            cur.lip = Some(if c.contains(':') {
                siem_regex::os_ip::expand_ipv6(c).unwrap_or_else(|| c.to_string())
            } else {
                c.to_string()
            });
        } else if el == "allowed-ips" {
            match is_valid_ip(c) {
                (0, _) | (_, None) => return Err(ConfigError::new(invalid_ip(c))),
                (_, Some(ip)) => logr.allowips.push(ip),
            }
        } else if el == "denied-ips" {
            match is_valid_ip(c) {
                (0, _) | (_, None) => return Err(ConfigError::new(invalid_ip(c))),
                (_, Some(ip)) => logr.denyips.push(ip),
            }
        } else if el == "queue_size" {
            let (v, end) = strtol(c);
            logr.queue_size = v;
            if end != c.len() || v < 1 {
                return Err(ConfigError::new("Invalid value for option '<queue_size>'"));
            }
            defined_queue_size = true;
        } else if el == "rids_closing_time" {
            let unit = c.find(|ch: char| "sSmMhHdD".contains(ch));
            let mut t = parse_time(c);
            if unit.map(|i| i + 1 != c.len()).unwrap_or(false) || t <= 0 || t > i32::MAX as i64 {
                ctx.warn(remoted_inv_value_default(c, "rids_closing_time"));
                t = REMOTED_RIDS_CLOSING_TIME_DEFAULT as i64;
            }
            logr.rids_closing_time = t as i32;
        } else if el == "connection_overtake_time" {
            let msg = |cur: i32| format!("Invalid value for element '{el}':'{c}'. Setting to default value: '{cur}'.");
            if !str_is_num(c) {
                let m = msg(logr.connection_overtake_time);
                ctx.warn(m);
            } else {
                let v = atoi(c);
                if !(0..=3600).contains(&v) {
                    let m = msg(logr.connection_overtake_time);
                    ctx.warn(m);
                } else {
                    logr.connection_overtake_time = v;
                }
            }
        } else if el.eq_ignore_ascii_case("agents") {
            if let Some(children) = xml.get_elements_by_node(Some(n)) {
                for a in &children {
                    if a.element.eq_ignore_ascii_case("allow_higher_versions") {
                        match a.content.as_deref().unwrap_or("") {
                            "no" => logr.allow_higher_versions = false,
                            "yes" => logr.allow_higher_versions = true,
                            v => ctx.warn(remoted_inv_value_ignore(v, "allow_higher_versions")),
                        }
                    } else {
                        ctx.warn(xml_invelem(&a.element));
                    }
                }
            }
        } else {
            return Err(ConfigError::new(xml_invelem(el)));
        }
    }

    if cur.conn == 0 {
        return Err(ConfigError::new(CONN_ERROR));
    }
    if cur.port == 0 {
        cur.port = if cur.conn == SECURE_CONN { DEFAULT_SECURE } else { DEFAULT_SYSLOG };
    }
    if cur.proto == 0 {
        cur.proto = REMOTED_NET_PROTOCOL_DEFAULT;
    } else if cur.conn != SECURE_CONN && cur.proto == REMOTED_NET_PROTOCOL_TCP_UDP {
        ctx.warn(remoted_net_protocol_only_secure(REMOTED_NET_PROTOCOL_DEFAULT_STR));
        cur.proto = REMOTED_NET_PROTOCOL_DEFAULT;
    }
    if cur.conn == SYSLOG_CONN && defined_queue_size {
        return Err(ConfigError::new("Invalid option <queue_size> for Syslog remote connection."));
    }
    logr.connections.push(cur);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{modules, read_config_xml, ConfigHandler, Platform, Section};

    struct H {
        remote: RemotedConfig,
    }
    impl ConfigHandler for H {
        fn section(&mut self, ctx: &mut ConfigContext, xml: &OsXml, s: Section, _n: &XmlNode, ch: Option<&[XmlNode]>) -> Result<()> {
            if s == Section::Remote {
                read_remote(ctx, xml, ch.unwrap_or(&[]), &mut self.remote)?;
            }
            Ok(())
        }
    }

    fn parse(conf: &str) -> std::result::Result<(RemotedConfig, Vec<String>), String> {
        let xml = OsXml::read_string(conf, false).map_err(|e| e.message)?;
        let mut ctx = ConfigContext::new(Platform::MANAGER);
        let mut h = H { remote: RemotedConfig::default() };
        read_config_xml(&mut ctx, modules::CREMOTE | modules::CGLOBAL, &xml, "ossec.conf", &mut h).map_err(|e| e.0)?;
        Ok((h.remote, ctx.warnings))
    }

    #[test]
    fn default_wazuh_remote_block() {
        let (r, w) = parse(
            "<ossec_config><remote><connection>secure</connection><port>1514</port><protocol>tcp</protocol><queue_size>131072</queue_size></remote></ossec_config>",
        )
        .unwrap();
        assert!(w.is_empty());
        assert_eq!(r.connections, vec![RemoteConnection { conn: SECURE_CONN, port: 1514, proto: REMOTED_NET_PROTOCOL_TCP, ipv6: false, lip: None }]);
    }

    #[test]
    fn syslog_and_secure_defaults_and_errors() {
        let (r, _) = parse(
            "<ossec_config><remote><connection>syslog</connection><allowed-ips>10.0.0.0/8</allowed-ips></remote>\
             <remote><connection>secure</connection><protocol>tcp,udp</protocol></remote></ossec_config>",
        )
        .unwrap();
        assert_eq!(r.connections[0].port, 514);
        assert_eq!(r.connections[0].proto, REMOTED_NET_PROTOCOL_TCP);
        assert_eq!(r.connections[1].port, 1514);
        assert_eq!(r.connections[1].proto, REMOTED_NET_PROTOCOL_TCP_UDP);
        assert_eq!(r.allowips.len(), 1);

        assert_eq!(
            parse("<ossec_config><remote><connection>secure</connection></remote><remote><connection>secure</connection></remote></ossec_config>").unwrap_err(),
            DUP_SECURE
        );
        assert_eq!(parse("<ossec_config><remote><port>1514</port></remote></ossec_config>").unwrap_err(), CONN_ERROR);
        // Empty <remote/> has no children: Wazuh reports it as an invalid element.
        assert_eq!(parse("<ossec_config><remote/></ossec_config>").unwrap_err(), xml_invelem("remote"));
        assert_eq!(
            parse("<ossec_config><remote><connection>syslog</connection><queue_size>5</queue_size></remote></ossec_config>").unwrap_err(),
            "Invalid option <queue_size> for Syslog remote connection."
        );
        let (_, w) = parse("<ossec_config><remote><connection>syslog</connection><protocol>tcp,udp</protocol></remote></ossec_config>").unwrap();
        assert_eq!(w, vec![remoted_net_protocol_only_secure("TCP")]);
    }
}
