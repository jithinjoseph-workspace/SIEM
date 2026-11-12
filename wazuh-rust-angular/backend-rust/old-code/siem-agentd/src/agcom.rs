//! `client-agent/agcom.c`: the `agent` request target (`getconfig
//! <section>`, `getstate`).

use crate::*;

/// `agcom_dispatch`
pub fn agcom_dispatch(ag: &Agentd, command: &[u8]) -> Vec<u8> {
    let (comm, args) = match command.iter().position(|&c| c == b' ') {
        Some(p) => (&command[..p], Some(&command[p + 1..])),
        None => (command, None),
    };
    match comm {
        b"getconfig" => match args {
            None => {
                ag.log.debug1("AGCOM getconfig needs arguments.");
                b"err AGCOM getconfig needs arguments".to_vec()
            }
            Some(a) => agcom_getconfig(ag, &String::from_utf8_lossy(a)),
        },
        b"getstate" => crate::state::state_get(ag).into_bytes(),
        _ => {
            ag.log.debug1(format!("AGCOM Unrecognized command '{}'.", String::from_utf8_lossy(comm)));
            b"err Unrecognized command".to_vec()
        }
    }
}

/// `agcom_getconfig`
pub fn agcom_getconfig(ag: &Agentd, section: &str) -> Vec<u8> {
    let cfg = match section {
        "client" => Some(crate::config::get_client_config(ag)),
        "buffer" => Some(crate::config::get_buffer_config(ag)),
        "labels" => Some(crate::config::get_labels_config(ag)),
        "internal" => Some(crate::config::get_agent_internal_options(ag)),
        "anti_tampering" => Some(crate::config::get_anti_tampering_config(ag)),
        _ => None,
    };
    match cfg {
        Some(j) => format!("ok {}", j.to_string_unformatted()).into_bytes(),
        None => {
            ag.log.debug1(format!("At AGCOM getconfig: Could not get '{section}' section"));
            b"err Could not get requested section".to_vec()
        }
    }
}
