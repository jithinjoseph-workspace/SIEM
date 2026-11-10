//! Upgrade module dispatcher (`w_dispatch_upgrade_module_thread`): agent
//! upgrade messages get the agent id added to their `parameters` and are
//! forwarded to the upgrade module socket.

use siem_cjson::Json;

use crate::daemon::Env;

/// `WM_UPGRADE_SOCK`
pub const WM_UPGRADE_SOCK: &str = "queue/tasks/upgrade";

/// The message forwarded for `log` from `agent_id`, or the error to log.
pub fn dispatch(env: &mut dyn Env, agent_id: &[u8], log: &[u8]) {
    let Ok((mut root, _)) = siem_cjson::parse_with_opts(log, false) else {
        env.log("ERROR", &[&b"Could not parse upgrade message: "[..], log].concat());
        return;
    };
    let agent = crate::rules::atoi(&String::from_utf8_lossy(agent_id));
    let Some(params) = root.get_mut("parameters") else {
        env.log("ERROR", &[&b"Could not get parameters from upgrade message: "[..], log].concat());
        return;
    };
    // cJSON_AddItemToObject links the item into any node's children: an
    // array prints it, a scalar does not
    let agents = Json::Array(vec![Json::number(agent as f64)]);
    match params {
        Json::Object(_) => {
            params.add("agents", agents);
        }
        Json::Array(a) => a.push(agents),
        _ => {}
    }
    let msg = root.print_unformatted();
    // the message is a C string (strlen)
    let msg = &msg[..msg.iter().position(|&c| c == 0).unwrap_or(msg.len())];
    if let Err((_, t)) = env.send_local(WM_UPGRADE_SOCK, msg) {
        env.log("ERROR", format!("Could not connect to upgrade module socket at '{WM_UPGRADE_SOCK}'. Error: {t}").as_bytes());
    }
}
