//! `client-agent/reload_agent.c`: `reloadAgent` (asks execd, through the
//! `com` socket, to restart the agent) and `verifyRemoteConf` (the
//! `Test_*` checks of a new `agent.conf` before applying it).

use siem_config::client::AgentConfig;
use siem_config::labels::Label;
use siem_config::modules::*;
#[cfg(unix)]
use siem_ipc::os_net;

use crate::sendmsg::send_msg;
use crate::*;

const AG_IN_RCON: &str = "wazuh: Invalid remote configuration";

/// `reloadAgent` (Windows): `wcom_dispatch("reload")` in this process.
#[cfg(windows)]
pub fn reload_agent(ag: &Agentd) {
    if let Some(d) = ag.hooks.get().and_then(|h| h.find(b"com")) {
        d(b"reload");
    }
}

/// `reloadAgent`
#[cfg(unix)]
pub fn reload_agent(ag: &Agentd) {
    let sock = os_net::connect_unix_domain(COM_LOCAL_SOCK, os_net::SOCK_STREAM, os_net::OS_MAXSTR);
    if sock < 0 {
        let e = errno();
        if e == os_net::ECONNREFUSED {
            ag.log.error("Could not auto-reload agent. Is Active Response enabled?");
        } else {
            ag.log.error(format!(
                "At reloadAgent(): Could not connect to socket '{COM_LOCAL_SOCK}': {} ({e}).",
                strerror(e)
            ));
        }
        return;
    }
    if os_net::send_secure_tcp(sock, b"reload") != 0 {
        ag.log.error(format!("OS_SendSecureTCP(): {}", strerror(errno())));
    }
    os_net::close_fd(sock);
}

/// `Test_<name>`: read `path` for `mods` into throw-away structures.
///
/// The syscheck, rootcheck and wodle readers come from the daemons the agent
/// runs ([`Agentd::conf_tests`]); without one, those sections are accepted as
/// long as the document and its `<agent_config>` blocks are valid.
fn test(ag: &Agentd, mods: u32, name: &str, path: &str) -> i32 {
    if mods & CLOCALFILE != 0 {
        return test_localfile(ag, path);
    }
    if let Some(mut h) = ag.conf_tests.get().and_then(|f| f(mods)) {
        let mut ctx = siem_config::ConfigContext::new(siem_config::Platform::AGENT);
        ctx.agent = crate::config::agent_identity();
        let remote = Some(ag.define_int("agent", "remote_conf", 0, 1) != 0);
        let r = siem_config::read_config(&mut ctx, CAGENT_CONFIG | mods, path, remote, h.as_mut());
        crate::config::flush_ctx(ag, &mut ctx);
        if r.is_err() {
            ag.log.error(format!("(1207): {name} remote configuration in '{path}' is corrupted."));
            return -1;
        }
        return 0;
    }
    let mut agent = AgentConfig::client_defaults(OSSEC_VERSION);
    let mut labels: Vec<Label> = Vec::new();
    let mut pu = false;
    if crate::config::read(ag, CAGENT_CONFIG | mods, path, &mut agent, &mut labels, &mut pu).is_err() {
        ag.log.error(format!("(1207): {name} remote configuration in '{path}' is corrupted."));
        return -1;
    }
    0
}

/// `verifyRemoteConf`: 0 when the shared configuration is valid.
pub fn verify_remote_conf(ag: &Agentd) -> i32 {
    let path = AGENTCONFIG;
    let checks: [(u32, &str, &str); 7] = [
        (CSYSCHECK, "Syscheck", "syscheck"),
        (CROOTCHECK, "Rootcheck", "rootcheck"),
        (CLOCALFILE | CLGCSOCKET, "Localfile", "localfile"),
        (CCLIENT, "Client", "client"),
        (CBUFFER, "ClientBuffer", "client_buffer"),
        (CWMODULE, "WModule", "wodle"),
        (CLABELS, "Labels", "labels"),
    ];
    for (mods, name, what) in checks {
        if test(ag, mods, name, path) < 0 {
            let msg = agent_event(&format!("{AG_IN_RCON}: '{what}'. "));
            ag.log.debug2("Invalid remote configuration received");
            send_msg(ag, msg.as_bytes());
            return -1;
        }
    }
    0
}

/// `ReadConfig` callbacks of `Test_Localfile`.
struct LocalfileTest<'a>(&'a mut siem_config::localfile::LogreaderConfig);

impl siem_config::ConfigHandler for LocalfileTest<'_> {
    fn section(
        &mut self,
        ctx: &mut siem_config::ConfigContext,
        _xml: &siem_xml::OsXml,
        section: siem_config::Section,
        _node: &siem_xml::XmlNode,
        children: Option<&[siem_xml::XmlNode]>,
    ) -> siem_config::Result<()> {
        let ch = children.unwrap_or(&[]);
        match section {
            siem_config::Section::Localfile => siem_config::localfile::read_localfile(ctx, ch, self.0),
            siem_config::Section::LogcollectorSocket => siem_config::socket::read_socket(ch, &mut self.0.socket_list),
            _ => Ok(()),
        }
    }
}

/// `Test_Localfile` (`ReadConfig(CAGENT_CONFIG | CLOCALFILE | CLGCSOCKET)`).
fn test_localfile(ag: &Agentd, path: &str) -> i32 {
    let mut cfg = siem_config::localfile::LogreaderConfig::default();
    let mut ctx = siem_config::ConfigContext::new(siem_config::Platform::AGENT);
    ctx.agent = crate::config::agent_identity();
    let remote = Some(ag.define_int("agent", "remote_conf", 0, 1) != 0);
    let r = siem_config::read_config(&mut ctx, CAGENT_CONFIG | CLOCALFILE | CLGCSOCKET, path, remote, &mut LocalfileTest(&mut cfg));
    crate::config::flush_ctx(ag, &mut ctx);
    if r.is_err() {
        ag.log.error(format!("(1207): Localfile remote configuration in '{path}' is corrupted."));
        return -1;
    }
    0
}
