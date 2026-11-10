//! Port of `src/config/client-config.c`, `buffer-config.c` and the agent
//! structure of `client-config.h` (`Read_Client`, `Read_Client_Shared`,
//! `Read_Client_Server`, `Read_Client_Enrollment`, `Read_AntiTampering`,
//! `Read_ClientBuffer`, `Validate_Address`) plus the enrollment
//! configuration defaults of `shared/enrollment_op.c`.

use crate::messages::*;
use crate::util::{atoi, parse_time, str_is_num};
use crate::{ConfigContext, ConfigError, Result};
use siem_regex::is_valid_ip;
use siem_xml::{OsXml, XmlNode};

pub const DEFAULT_SECURE: i32 = 1514;
pub const DEFAULT_MAX_RETRIES: i32 = 5;
pub const DEFAULT_RETRY_INTERVAL: i32 = 10;
pub const IPPROTO_TCP: i32 = 6;
pub const IPPROTO_UDP: i32 = 17;
/// `W_METH_BLOWFISH` / `W_METH_AES` (`sec.h`).
pub const W_METH_BLOWFISH: i32 = 0;
pub const W_METH_AES: i32 = 1;
/// `os_auth/auth.h`
pub const DEFAULT_PORT: i32 = 1515;
pub const DEFAULT_CIPHERS: &str = "HIGH:!ADH:!EXP:!MD5:!RC4:!3DES:!CAMELLIA:@STRENGTH";
/// `defs.h` (non-Windows)
pub const AUTHD_PASS: &str = "etc/authd.pass";
/// `IPSIZE` (`INET6_ADDRSTRLEN`)
pub const IPSIZE: usize = 46;

pub fn ag_inv_host(h: &str) -> String {
    format!("(4104): Invalid hostname: '{h}'.")
}

/// `agent_server`
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AgentServer {
    pub rip: String,
    pub port: i32,
    pub protocol: i32,
    pub network_interface: u32,
    pub max_retries: i32,
    pub retry_interval: i32,
}

/// `w_enrollment_target` (`w_enrollment_target_init` defaults).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnrollmentTarget {
    pub manager_name: Option<String>,
    pub port: i32,
    pub network_interface: u32,
    pub agent_name: Option<String>,
    pub centralized_group: Option<String>,
    pub sender_ip: Option<String>,
    pub use_src_ip: bool,
}

impl Default for EnrollmentTarget {
    fn default() -> Self {
        Self {
            manager_name: None,
            port: DEFAULT_PORT,
            network_interface: 0,
            agent_name: None,
            centralized_group: None,
            sender_ip: None,
            use_src_ip: false,
        }
    }
}

/// `w_enrollment_cert` (`w_enrollment_cert_init` defaults).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnrollmentCert {
    pub ciphers: String,
    pub authpass_file: String,
    pub authpass: Option<String>,
    pub agent_cert: Option<String>,
    pub agent_key: Option<String>,
    pub ca_cert: Option<String>,
    pub auto_method: bool,
}

impl Default for EnrollmentCert {
    fn default() -> Self {
        Self {
            ciphers: DEFAULT_CIPHERS.into(),
            authpass_file: AUTHD_PASS.into(),
            authpass: None,
            agent_cert: None,
            agent_key: None,
            ca_cert: None,
            auto_method: false,
        }
    }
}

/// The configuration part of `w_enrollment_ctx` (`w_enrollment_init`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnrollmentConfig {
    pub target: EnrollmentTarget,
    pub cert: EnrollmentCert,
    pub enabled: bool,
    pub allow_localhost: bool,
    pub delay_after_enrollment: i64,
    pub agent_version: String,
    pub recv_timeout: i32,
}

impl EnrollmentConfig {
    pub fn new(agent_version: &str) -> Self {
        Self {
            target: EnrollmentTarget::default(),
            cert: EnrollmentCert::default(),
            enabled: true,
            allow_localhost: true,
            delay_after_enrollment: 20,
            agent_version: agent_version.into(),
            recv_timeout: 0,
        }
    }
}

/// The configuration fields of the agent's `agent` structure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentConfig {
    pub server: Vec<AgentServer>,
    /// `execdq`: -1 when `<disable-active-response>yes`.
    pub execdq: i32,
    pub notify_time: i32,
    pub max_time_reconnect_try: i32,
    pub force_reconnect_interval: i64,
    pub main_ip_update_interval: i32,
    pub profile: Option<String>,
    pub buffer: bool,
    pub buflength: i32,
    pub events_persec: i32,
    pub crypto_method: i32,
    pub auto_restart: bool,
    pub remote_conf: bool,
    pub enrollment: EnrollmentConfig,
}

impl AgentConfig {
    /// Values `ClientConf` sets before reading the configuration.
    pub fn client_defaults(agent_version: &str) -> Self {
        Self {
            server: Vec::new(),
            execdq: 0,
            notify_time: 0,
            max_time_reconnect_try: 0,
            force_reconnect_interval: 0,
            main_ip_update_interval: 0,
            profile: None,
            buffer: true,
            buflength: 5000,
            events_persec: 500,
            crypto_method: W_METH_AES,
            auto_restart: true,
            remote_conf: false,
            enrollment: EnrollmentConfig::new(agent_version),
        }
    }
}

/// `snprintf(buf, 127, fmt, ...)`: keep at most 126 bytes.
fn trunc126(s: String) -> String {
    if s.len() <= 126 {
        return s;
    }
    let mut n = 126;
    while !s.is_char_boundary(n) {
        n -= 1;
    }
    s[..n].to_string()
}

/// `os_strdup` + `os_realloc(IPSIZE + 1)` + `OS_ExpandIPv6(.., IPSIZE)` when
/// the text has a ':'. On failure the text is left as it was.
fn maybe_expand_ipv6(s: String) -> String {
    if !s.contains(':') {
        return s;
    }
    // strncpy(aux_ip, ip_address, IPSIZE): the copy is cut at IPSIZE bytes.
    let mut cut = s.len().min(IPSIZE);
    while !s.is_char_boundary(cut) {
        cut -= 1;
    }
    match siem_regex::os_ip::expand_ipv6(&s[..cut]) {
        Some(x) => {
            // snprintf(ip_address, IPSIZE, ...)
            let mut x = x;
            x.truncate(IPSIZE - 1);
            x
        }
        None => s,
    }
}

fn content<'a>(n: &'a XmlNode) -> Result<&'a str> {
    n.content.as_deref().ok_or_else(|| ConfigError::new(xml_valuenull(&n.element)))
}

fn valueerr(el: &str, c: &str) -> ConfigError {
    ConfigError::new(xml_valueerr(el, c))
}

/// `Read_Client`
pub fn read_client(ctx: &mut ConfigContext, xml: &OsXml, nodes: &[XmlNode], logr: &mut AgentConfig) -> Result<()> {
    let mut port = DEFAULT_SECURE;
    let mut protocol = IPPROTO_TCP;

    for n in nodes {
        let mut rip: Option<String> = None;
        let c = content(n)?;
        let el = n.element.as_str();
        match el {
            "local_ip" => ctx.warn("The <local_ip> tag has no functionality, so it will have no effect."),
            "server-ip" => {
                ctx.warn("The <server-ip> tag is deprecated, please use <server><address> instead.");
                if is_valid_ip(c).0 != 1 {
                    return Err(ConfigError::new(invalid_ip(c)));
                }
                rip = Some(c.to_string());
            }
            "server-hostname" => {
                ctx.warn("The <server-hostname> tag is deprecated, please use <server><address> instead.");
                if !c.contains('/') {
                    rip = Some(trunc126(format!("{c}/")));
                } else {
                    return Err(ConfigError::new(ag_inv_host(c)));
                }
            }
            "port" => {
                ctx.warn("The <port> tag is deprecated, please use <server><port> instead.");
                if !str_is_num(c) {
                    return Err(valueerr(el, c));
                }
                port = atoi(c);
                if port <= 0 || port > 65535 {
                    return Err(ConfigError::new(port_error(port as i64)));
                }
            }
            "server" => {
                let Some(ch) = xml.get_elements_by_node(Some(n)) else {
                    return Err(ConfigError::new(xml_invelem(el)));
                };
                read_client_server(&ch, logr)?;
            }
            "enrollment" => {
                if let Some(ch) = xml.get_elements_by_node(Some(n)) {
                    read_client_enrollment(&ch, logr)?;
                }
            }
            "notify_time" => {
                if !str_is_num(c) {
                    return Err(valueerr(el, c));
                }
                logr.notify_time = atoi(c);
                if logr.notify_time < 0 {
                    return Err(valueerr(el, c));
                }
            }
            "time-reconnect" => {
                if !str_is_num(c) {
                    return Err(valueerr(el, c));
                }
                logr.max_time_reconnect_try = atoi(c);
                if logr.max_time_reconnect_try < 0 {
                    return Err(valueerr(el, c));
                }
            }
            "force_reconnect_interval" => {
                let t = parse_time(c);
                if t < 0 {
                    ctx.warn(xml_valueerr(el, c));
                } else {
                    logr.force_reconnect_interval = t;
                }
            }
            "ip_update_interval" => {
                if !str_is_num(c) {
                    return Err(valueerr(el, c));
                }
                logr.main_ip_update_interval = atoi(c);
                if logr.main_ip_update_interval < 0 {
                    return Err(valueerr(el, c));
                }
            }
            "disable-active-response" => match c {
                "yes" => logr.execdq = -1,
                "no" => logr.execdq = 0,
                _ => return Err(valueerr(el, c)),
            },
            "config-profile" => logr.profile = Some(c.to_string()),
            "auto_restart" => match c {
                "yes" => logr.auto_restart = true,
                "no" => logr.auto_restart = false,
                _ => return Err(valueerr(el, c)),
            },
            "protocol" => {
                ctx.warn("The <protocol> tag is deprecated, please use <server><protocol> instead.");
                match c {
                    "tcp" => protocol = IPPROTO_TCP,
                    "udp" => protocol = IPPROTO_UDP,
                    _ => return Err(valueerr(el, c)),
                }
            }
            "crypto_method" => match c {
                "blowfish" => logr.crypto_method = W_METH_BLOWFISH,
                "aes" => logr.crypto_method = W_METH_AES,
                _ => return Err(valueerr(el, c)),
            },
            _ => return Err(ConfigError::new(xml_invelem(el))),
        }

        // Add extra server (legacy configuration)
        if let Some(rip) = rip {
            logr.server.push(AgentServer {
                rip,
                port: 0,
                protocol: 0,
                network_interface: 0,
                max_retries: DEFAULT_MAX_RETRIES,
                retry_interval: DEFAULT_RETRY_INTERVAL,
            });
        }
    }

    // Assign global port and protocol to legacy configurations
    for s in logr.server.iter_mut() {
        if s.port == 0 {
            s.port = port;
        }
        if s.protocol == 0 {
            s.protocol = protocol;
        }
    }
    Ok(())
}

/// `Read_Client_Shared` (`<client>` inside the shared `agent.conf`).
pub fn read_client_shared(ctx: &mut ConfigContext, nodes: &[XmlNode], logr: &mut AgentConfig) -> Result<()> {
    logr.force_reconnect_interval = 0;
    for n in nodes {
        let c = content(n)?;
        if n.element == "force_reconnect_interval" {
            let t = parse_time(c);
            if t < 0 {
                ctx.warn(xml_valueerr(&n.element, c));
            } else {
                logr.force_reconnect_interval = t;
            }
        } else {
            return Err(ConfigError::new(xml_invelem(&n.element)));
        }
    }
    Ok(())
}

/// `Read_Client_Server`
pub fn read_client_server(nodes: &[XmlNode], logr: &mut AgentConfig) -> Result<()> {
    let mut rip: Option<String> = None;
    let mut network_interface = 0u32;
    let mut port = DEFAULT_SECURE;
    let mut protocol = IPPROTO_TCP;
    let mut max_retries = DEFAULT_MAX_RETRIES;
    let mut retry_interval = DEFAULT_RETRY_INTERVAL;

    for n in nodes {
        let c = content(n)?;
        let el = n.element.as_str();
        match el {
            "address" => {
                if is_valid_ip(c).0 == 1 {
                    rip = Some(c.to_string());
                } else if !c.contains('/') {
                    rip = Some(trunc126(c.to_string()));
                } else {
                    return Err(ConfigError::new(ag_inv_host(c)));
                }
            }
            "port" => {
                if !str_is_num(c) {
                    return Err(valueerr(el, c));
                }
                port = atoi(c);
                if port <= 0 || port > 65535 {
                    return Err(ConfigError::new(port_error(port as i64)));
                }
            }
            "interface_index" => {
                if !str_is_num(c) {
                    return Err(valueerr(el, c));
                }
                let v = atoi(c);
                if v <= 0 {
                    return Err(valueerr(el, c));
                }
                network_interface = v as u32;
            }
            "protocol" => match c {
                "tcp" => protocol = IPPROTO_TCP,
                "udp" => protocol = IPPROTO_UDP,
                _ => return Err(valueerr(el, c)),
            },
            "max_retries" => {
                if !str_is_num(c) {
                    return Err(valueerr(el, c));
                }
                max_retries = atoi(c);
                if max_retries <= 0 {
                    return Err(valueerr(el, c));
                }
            }
            "retry_interval" => {
                if !str_is_num(c) {
                    return Err(valueerr(el, c));
                }
                retry_interval = atoi(c);
                if retry_interval <= 0 {
                    return Err(valueerr(el, c));
                }
            }
            _ => return Err(ConfigError::new(xml_invelem(el))),
        }
    }

    let Some(rip) = rip else {
        return Err(ConfigError::new("No such address in the configuration."));
    };
    logr.server.push(AgentServer {
        rip: maybe_expand_ipv6(rip),
        port,
        protocol,
        network_interface,
        max_retries,
        retry_interval,
    });
    Ok(())
}

/// `Read_Client_Enrollment`
pub fn read_client_enrollment(nodes: &[XmlNode], logr: &mut AgentConfig) -> Result<()> {
    let e = &mut logr.enrollment;
    for n in nodes {
        let c = content(n)?;
        let el = n.element.as_str();
        let invalid_content = || ConfigError::new(format!("Invalid content for tag '{el}'."));
        match el {
            "enabled" => match c {
                "yes" => e.enabled = true,
                "no" => e.enabled = false,
                _ => return Err(invalid_content()),
            },
            "manager_address" => {
                let remote_ip = if is_valid_ip(c).0 == 1 {
                    c.to_string()
                } else if !c.contains('/') {
                    trunc126(c.to_string())
                } else {
                    return Err(ConfigError::new(ag_inv_host(c)));
                };
                e.target.manager_name = Some(maybe_expand_ipv6(remote_ip));
            }
            "port" => {
                if !str_is_num(c) {
                    return Err(valueerr(el, c));
                }
                let port = atoi(c);
                if port <= 0 || port > 65535 {
                    return Err(ConfigError::new(port_error(port as i64)));
                }
                e.target.port = port;
            }
            "interface_index" => {
                if !str_is_num(c) {
                    return Err(valueerr(el, c));
                }
                let v = atoi(c);
                if v <= 0 {
                    return Err(valueerr(el, c));
                }
                e.target.network_interface = v as u32;
            }
            "agent_name" => e.target.agent_name = Some(c.to_string()),
            "groups" => e.target.centralized_group = Some(c.to_string()),
            "agent_address" => {
                if is_valid_ip(c).0 != 0 {
                    e.target.sender_ip = Some(maybe_expand_ipv6(c.to_string()));
                } else {
                    return Err(ConfigError::new(ag_inv_host(c)));
                }
            }
            "ssl_cipher" => e.cert.ciphers = c.to_string(),
            "server_ca_path" => e.cert.ca_cert = Some(c.to_string()),
            "agent_certificate_path" => e.cert.agent_cert = Some(c.to_string()),
            "agent_key_path" => e.cert.agent_key = Some(c.to_string()),
            "authorization_pass_path" => e.cert.authpass_file = c.to_string(),
            "auto_method" => match c {
                "yes" => e.cert.auto_method = true,
                "no" => e.cert.auto_method = false,
                _ => return Err(invalid_content()),
            },
            "delay_after_enrollment" => {
                if !str_is_num(c) {
                    return Err(valueerr(el, c));
                }
                let d = atoi(c);
                if d <= 0 {
                    return Err(valueerr(el, c));
                }
                e.delay_after_enrollment = d as i64;
            }
            "use_source_ip" => match c {
                "yes" => e.target.use_src_ip = true,
                "no" => e.target.use_src_ip = false,
                _ => return Err(invalid_content()),
            },
            _ => return Err(ConfigError::new(xml_invelem(el))),
        }
    }
    Ok(())
}

/// `Read_AntiTampering`: returns `package_uninstallation`.
pub fn read_anti_tampering(nodes: &[XmlNode], package_uninstallation: &mut bool) -> Result<()> {
    for n in nodes {
        let c = content(n)?;
        if n.element == "package_uninstallation" {
            match c {
                "yes" => *package_uninstallation = true,
                "no" => *package_uninstallation = false,
                _ => return Err(ConfigError::new(format!("Invalid content for tag '{}'.", n.element))),
            }
        } else {
            return Err(ConfigError::new(xml_invelem(&n.element)));
        }
    }
    Ok(())
}

/// `Read_ClientBuffer` (a `<client_buffer>` with no children is accepted).
pub fn read_client_buffer(ctx: &mut ConfigContext, nodes: Option<&[XmlNode]>, logr: &mut AgentConfig) -> Result<()> {
    let Some(nodes) = nodes else { return Ok(()) };
    for n in nodes {
        let c = content(n)?;
        let el = n.element.as_str();
        match el {
            "disabled" | "disable" => match c {
                "yes" => logr.buffer = false,
                "no" => logr.buffer = true,
                _ => return Err(valueerr(el, c)),
            },
            "queue_size" | "length" => {
                if el == "length" {
                    ctx.warn("The <length> tag is deprecated for version newer than 2.1.1, please use <queue_size> instead.");
                }
                if !str_is_num(c) {
                    return Err(valueerr(el, c));
                }
                logr.buflength = atoi(c);
                if logr.buflength <= 0 || logr.buflength > 100000 {
                    return Err(valueerr(el, c));
                }
            }
            "events_per_second" => {
                if !str_is_num(c) {
                    return Err(valueerr(el, c));
                }
                logr.events_persec = atoi(c);
                if logr.events_persec <= 0 || logr.events_persec > 1000 {
                    return Err(valueerr(el, c));
                }
            }
            _ => return Err(ConfigError::new(xml_invelem(el))),
        }
    }
    Ok(())
}

/// `Validate_Address`
pub fn validate_address(servers: &[AgentServer]) -> bool {
    servers.iter().any(|s| s.rip != "MANAGER_IP" && s.rip != "0.0.0.0" && !s.rip.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{read_config_xml, ConfigHandler, Platform, Section};
    use crate::modules::*;

    struct H<'a>(&'a mut AgentConfig);
    impl ConfigHandler for H<'_> {
        fn section(
            &mut self,
            ctx: &mut ConfigContext,
            xml: &OsXml,
            s: Section,
            _node: &XmlNode,
            ch: Option<&[XmlNode]>,
        ) -> Result<()> {
            match s {
                Section::Client => read_client(ctx, xml, ch.unwrap_or(&[]), self.0),
                Section::ClientBuffer => read_client_buffer(ctx, ch, self.0),
                _ => Ok(()),
            }
        }
    }

    fn parse(x: &str) -> (Result<()>, AgentConfig, ConfigContext) {
        let xml = OsXml::read_string(x, false).unwrap();
        let mut a = AgentConfig::client_defaults("v4.14.7");
        let mut ctx = ConfigContext::new(Platform::LINUX_AGENT);
        let r = read_config_xml(&mut ctx, CCLIENT | CBUFFER, &xml, "ossec.conf", &mut H(&mut a));
        (r, a, ctx)
    }

    #[test]
    fn servers_and_legacy() {
        let (r, a, _) = parse(
            "<ossec_config><client><server><address>fe80::1</address><port>1600</port><protocol>udp</protocol></server>\
             <server-hostname>mgr</server-hostname><port>1700</port><protocol>udp</protocol></client>\
             <client_buffer><queue_size>10</queue_size></client_buffer></ossec_config>",
        );
        r.unwrap();
        assert_eq!(a.server[0].rip, "FE80:0000:0000:0000:0000:0000:0000:0001");
        assert_eq!((a.server[0].port, a.server[0].protocol), (1600, IPPROTO_UDP));
        assert_eq!(a.server[1].rip, "mgr/");
        assert_eq!((a.server[1].port, a.server[1].protocol), (1700, IPPROTO_UDP));
        assert_eq!(a.buflength, 10);
    }

    #[test]
    fn error_logs() {
        let (r, _, ctx) = parse("<ossec_config><client><notify_time>x</notify_time></client></ossec_config>");
        assert!(r.is_err());
        let msgs: Vec<_> = ctx.log.iter().map(|(_, m)| m.as_str()).collect();
        assert_eq!(
            msgs,
            vec![
                "(1235): Invalid value for element 'notify_time': x.",
                "(1202): Configuration error at 'ossec.conf'."
            ]
        );
    }
}
