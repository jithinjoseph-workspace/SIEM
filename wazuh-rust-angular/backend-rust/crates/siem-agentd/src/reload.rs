//! `client-agent/reload_agent.c`: `reloadAgent` (asks execd, through the
//! `com` socket, to restart the agent) and `verifyRemoteConf` (the
//! `Test_*` checks of a new `agent.conf` before applying it).

use siem_config::client::AgentConfig;
use siem_config::labels::Label;
use siem_config::modules::*;
use siem_ipc::os_net;

use crate::sendmsg::send_msg;
use crate::*;

const AG_IN_RCON: &str = "wazuh: Invalid remote configuration";

/// `reloadAgent`
pub fn reload_agent(ag: &Agentd) {
    let sock = os_net::connect_unix_domain(COM_LOCAL_SOCK, libc::SOCK_STREAM, os_net::OS_MAXSTR);
    if sock < 0 {
        let e = errno();
        if e == libc::ECONNREFUSED {
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
    // SAFETY: closing our own socket.
    unsafe { libc::close(sock) };
}

/// `Test_<name>`: read `path` for `mods` into throw-away structures.
///
/// The syscheck, rootcheck, localfile and wodle section readers belong to
/// those daemons' ports; until they land, their sections are accepted as
/// long as the document and its `<agent_config>` blocks are valid.
fn test(ag: &Agentd, mods: u32, name: &str, path: &str) -> i32 {
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
