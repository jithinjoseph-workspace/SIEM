//! `client-agent/config.c`: `ClientConf` and the `get*Config` /
//! `getAgentInternalOptions` JSON used by `agcom getconfig`.

use std::sync::atomic::Ordering;
use std::sync::Arc;

use siem_cjson::Json;
use siem_config::client::{
    read_anti_tampering, read_client, read_client_buffer, read_client_shared, AgentConfig, IPPROTO_UDP,
    W_METH_AES, W_METH_BLOWFISH,
};
use siem_config::labels::{read_labels, Label};
use siem_config::modules::*;
use siem_config::{read_config, AgentIdentity, ConfigContext, ConfigHandler, LogLevel, Platform, Result, Section};
use siem_xml::{OsXml, XmlNode};

use crate::*;

/// The `ReadConfig` callbacks agentd passes (`agt`, `&agt->labels`, `atc`).
pub struct Handler<'a> {
    pub agent: &'a mut AgentConfig,
    pub labels: &'a mut Vec<Label>,
    pub package_uninstallation: &'a mut bool,
}

impl ConfigHandler for Handler<'_> {
    fn section(
        &mut self,
        ctx: &mut ConfigContext,
        xml: &OsXml,
        section: Section,
        _node: &XmlNode,
        children: Option<&[XmlNode]>,
    ) -> Result<()> {
        let ch = children.unwrap_or(&[]);
        match section {
            Section::Client => read_client(ctx, xml, ch, self.agent),
            Section::ClientShared => read_client_shared(ctx, ch, self.agent),
            Section::ClientBuffer => read_client_buffer(ctx, children, self.agent),
            Section::Labels => read_labels(ctx, ch, self.labels),
            Section::AntiTampering => read_anti_tampering(ch, self.package_uninstallation),
            _ => Ok(()),
        }
    }
}

/// `os_read_agent_name` / `os_read_agent_profile` / `getuname` for the
/// `<agent_config>` filters.
pub fn agent_identity() -> AgentIdentity {
    let data = std::fs::read(AGENT_INFO_FILE).ok();
    let lines: Vec<String> = data
        .as_deref()
        .map(|d| d.split_inclusive(|&c| c == b'\n').map(|l| String::from_utf8_lossy(l).into_owned()).collect())
        .unwrap_or_default();
    let name = lines.first().map(|l| {
        let mut s = l.clone();
        while s.len() > 1 && s.ends_with('\n') {
            s.pop();
        }
        s
    });
    let profile = lines.get(3).map(|l| l.trim_end_matches(['\r', '\n']).to_string());
    AgentIdentity { name, uname: Some(siem_fileop::version_op::getuname().to_string()), profile }
}

/// Write what the configuration readers logged.
pub fn flush_ctx(ag: &Agentd, ctx: &mut ConfigContext) {
    for (lv, m) in ctx.log.drain(..) {
        match lv {
            LogLevel::Debug1 => ag.log.debug1(m),
            LogLevel::Debug2 => ag.log.debug2(m),
            LogLevel::Info => ag.log.info(m),
            LogLevel::Warn => ag.log.warn(m),
            LogLevel::Error => ag.log.error(m),
        }
    }
    ctx.warnings.clear();
}

/// `ReadConfig(mods, file, ...)` on agentd's structures.
pub fn read(
    ag: &Agentd,
    mods: u32,
    file: &str,
    agent: &mut AgentConfig,
    labels: &mut Vec<Label>,
    pu: &mut bool,
) -> std::result::Result<(), ()> {
    let mut ctx = ConfigContext::new(Platform::LINUX_AGENT);
    if mods & CAGENT_CONFIG != 0 {
        ctx.agent = agent_identity();
    }
    let remote_conf =
        if mods & CAGENT_CONFIG != 0 { Some(ag.define_int("agent", "remote_conf", 0, 1) != 0) } else { None };
    let r = read_config(&mut ctx, mods, file, remote_conf, &mut Handler { agent, labels, package_uninstallation: pu });
    flush_ctx(ag, &mut ctx);
    r.map_err(|_| ())
}

/// `ClientConf(cfgfile)`
pub fn client_conf(ag: &Agentd, cfgfile: &str) -> std::result::Result<(), ()> {
    let mut agent = AgentConfig::client_defaults(OSSEC_VERSION);
    let mut labels: Vec<Label> = Vec::new();
    let mut pu = false;
    agent.enrollment.allow_localhost = false;
    agent.enrollment.recv_timeout = ag.define_int("agent", "recv_timeout", 1, 600);

    read(ag, CCLIENT, cfgfile, &mut agent, &mut labels, &mut pu)?;
    read(ag, CLABELS | CBUFFER, cfgfile, &mut agent, &mut labels, &mut pu)?;

    let remote = ag.define_int("agent", "remote_conf", 0, 1);
    agent.remote_conf = remote != 0;
    ag.remote_conf_flag.store(remote != 0, Ordering::SeqCst);
    if remote != 0 {
        ag.ints.remote_conf.store(remote, Ordering::SeqCst);
        let _ = read(ag, CLABELS | CBUFFER | CAGENT_CONFIG, AGENTCONFIG, &mut agent, &mut labels, &mut pu);
        let _ = read(ag, CCLIENT | CAGENT_CONFIG, AGENTCONFIG, &mut agent, &mut labels, &mut pu);
    }
    read(ag, ATAMPERING, cfgfile, &mut agent, &mut labels, &mut pu)?;

    let min_eps = ag.define_int("agent", "min_eps", 1, 1000);
    ag.ints.min_eps.store(min_eps, Ordering::SeqCst);
    if agent.events_persec < min_eps {
        ag.log.warn(format!("Client buffer throughput too low: set to {min_eps} eps"));
        agent.events_persec = min_eps;
    }

    *ag.cfg.write().unwrap() = agent;
    *ag.labels.write().unwrap() = Arc::new(labels);
    ag.package_uninstallation.store(pu, Ordering::SeqCst);
    Ok(())
}

fn n(v: impl Into<f64>) -> Json {
    Json::number(v.into())
}

fn s(v: &str) -> Json {
    Json::string(v)
}

fn yes_no(b: bool) -> Json {
    s(if b { "yes" } else { "no" })
}

/// `getClientConfig`
pub fn get_client_config(ag: &Agentd) -> Json {
    let a = ag.cfg.read().unwrap();
    let mut client = Json::object();
    if let Some(p) = &a.profile {
        client.add("config-profile", s(p));
    }
    client.add("notify_time", n(a.notify_time));
    client.add("time-reconnect", n(a.max_time_reconnect_try));
    client.add("force_reconnect_interval", n(a.force_reconnect_interval as f64));
    client.add("ip_update_interval", n(a.main_ip_update_interval));
    client.add("auto_restart", yes_no(a.auto_restart));
    client.add("remote_conf", yes_no(ag.remote_conf_flag.load(Ordering::SeqCst)));
    if a.crypto_method == W_METH_BLOWFISH {
        client.add("crypto_method", s("blowfish"));
    } else if a.crypto_method == W_METH_AES {
        client.add("crypto_method", s("aes"));
    }
    let mut servers = Json::array();
    for sv in &a.server {
        let mut o = Json::object();
        o.add("address", s(&sv.rip));
        o.add("port", n(sv.port));
        if sv.network_interface != 0 {
            o.add("interface_index", n(sv.network_interface));
        }
        o.add("max_retries", n(sv.max_retries));
        o.add("retry_interval", n(sv.retry_interval));
        o.add("protocol", s(if sv.protocol == IPPROTO_UDP { "udp" } else { "tcp" }));
        servers.push(o);
    }
    client.add("server", servers);

    let e = &a.enrollment;
    let mut en = Json::object();
    en.add("enabled", yes_no(e.enabled));
    en.add("delay_after_enrollment", n(e.delay_after_enrollment as f64));
    if let Some(m) = &e.target.manager_name {
        en.add("manager_address", s(m));
    }
    if e.target.network_interface != 0 {
        en.add("interface_index", n(e.target.network_interface));
    }
    en.add("port", n(e.target.port));
    if let Some(v) = &e.target.agent_name {
        en.add("agent_name", s(v));
    }
    if let Some(v) = &e.target.centralized_group {
        en.add("group", s(v));
    }
    en.add("ssl_cipher", s(&e.cert.ciphers));
    if let Some(v) = &e.cert.ca_cert {
        en.add("server_certificate_path", s(v));
    }
    if let Some(v) = &e.cert.agent_cert {
        en.add("agent_certificate_path", s(v));
    }
    if let Some(v) = &e.cert.agent_key {
        en.add("agent_key_path", s(v));
    }
    if e.cert.authpass.is_some() {
        en.add("authorization_pass_path", s(&e.cert.authpass_file));
    }
    en.add("auto_method", yes_no(e.cert.auto_method));
    client.add("enrollment", en);

    let mut root = Json::object();
    root.add("client", client);
    root
}

/// `getBufferConfig`
pub fn get_buffer_config(ag: &Agentd) -> Json {
    let a = ag.cfg.read().unwrap();
    let mut b = Json::object();
    b.add("disabled", yes_no(!a.buffer));
    b.add("queue_size", n(a.buflength));
    b.add("events_per_second", n(a.events_persec));
    let mut root = Json::object();
    root.add("buffer", b);
    root
}

/// `getLabelsConfig`
pub fn get_labels_config(ag: &Agentd) -> Json {
    let labels = ag.labels.read().unwrap().clone();
    let mut arr = Json::array();
    for l in labels.iter() {
        let mut o = Json::object();
        o.add("value", s(&l.value));
        o.add("key", s(&l.key));
        o.add("hidden", yes_no(l.flags.hidden));
        arr.push(o);
    }
    let mut root = Json::object();
    root.add("labels", arr);
    root
}

/// `getAntiTamperingConfig`: C adds the string to an array, so the value
/// is `["yes"]` / `["no"]`.
pub fn get_anti_tampering_config(ag: &Agentd) -> Json {
    let mut arr = Json::array();
    arr.push(yes_no(ag.package_uninstallation.load(Ordering::SeqCst)));
    let mut root = Json::object();
    root.add("package_uninstallation", arr);
    root
}

/// `getAgentInternalOptions`
pub fn get_agent_internal_options(ag: &Agentd) -> Json {
    let i = &ag.ints;
    let g = |v: &std::sync::atomic::AtomicI32| n(v.load(Ordering::SeqCst));
    let mut agent = Json::object();
    agent.add("debug", g(&i.agent_debug_level));
    agent.add("warn_level", g(&i.warn_level));
    agent.add("normal_level", g(&i.normal_level));
    agent.add("tolerance", g(&i.tolerance));
    agent.add("recv_timeout", g(&i.timeout));
    agent.add("state_interval", g(&i.interval));
    agent.add("min_eps", g(&i.min_eps));
    agent.add("remote_conf", g(&i.remote_conf));
    let mut internals = Json::object();
    internals.add("agent", agent);

    let mut monitord = Json::object();
    monitord.add("rotate_log", g(&i.rotate_log));
    monitord.add("compress", g(&i.log_compress));
    monitord.add("keep_log_days", g(&i.keep_log_days));
    monitord.add("day_wait", g(&i.day_wait));
    monitord.add("size_rotate", g(&i.size_rotate_read));
    monitord.add("daily_rotations", g(&i.daily_rotations));
    internals.add("monitord", monitord);

    let k = ag.keys.lock().unwrap();
    let mut remoted = Json::object();
    remoted.add("request_pool", g(&i.request_pool));
    remoted.add("request_rto_sec", g(&i.rto_sec));
    remoted.add("request_rto_msec", g(&i.rto_msec));
    remoted.add("max_attempts", g(&i.max_attempts));
    remoted.add("comp_average_printout", n(k.comp_print));
    remoted.add("recv_counter_flush", n(k.recv_flush));
    remoted.add("verify_msg_id", n(u32::from(k.verify_counter)));
    internals.add("remoted", remoted);

    let mut root = Json::object();
    root.add("internal", internals);
    root
}
