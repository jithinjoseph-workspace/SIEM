//! Engine-triggered responses and dump requests become queued commands (`specs/provigil-gateway.md`
//! 3.6). The queues belong to the old gateway while it runs, so this is off until it retires
//! (`GATEWAY_ENGINE_QUEUES=1`).

use std::sync::atomic::Ordering::Relaxed;
use std::sync::Arc;

use provigil_agent_server::{agent_state, commands as cmd};
use serde_json::{json, Value};
use siem_ipc::local::DatagramReceiver;
use tracing::{error, warn};

use crate::core::Gw;

const RESPONSE_QUEUE: &str = "queue/alerts/ar";
const DUMP_QUEUE: &str = "queue/alerts/cfgarq";

/// What a request asks for.
#[derive(Debug, PartialEq)]
pub enum Request {
    One { agent: String, command: Value },
    All { command: Value },
    Dump { agent: String, policy: String },
}

/// `syscheck restart`, else the response message (the JSON before any trailing text).
fn command_of(payload: &str) -> Option<Value> {
    if payload.trim() == "syscheck restart" {
        return Some(json!({ "type": "scan" }));
    }
    let message = serde_json::Deserializer::from_str(payload).into_iter::<Value>().next()?.ok()?;
    Some(json!({ "type": "ar", "message": message }))
}

/// `(msg_to_agent) [] <flags> <id> <payload>`: the flags' first letter `A` means all agents.
pub fn parse_response(msg: &str) -> Option<Request> {
    let rest = msg.strip_prefix("(msg_to_agent) [] ")?;
    let (flags, rest) = rest.split_once(' ')?;
    let (id, payload) = rest.split_once(' ')?;
    let command = command_of(payload)?;
    if flags.starts_with('A') {
        return Some(Request::All { command });
    }
    let n: u32 = id.parse().ok()?;
    Some(Request::One { agent: format!("{n:03}"), command })
}

/// `<id>:sca-dump:<policy>:<first scan>`
// shortcut: the form comes from the old agents' protocol, not from the engine's code (out of this
// clean room); phase 2 checks it against the engine when the queue moves.
pub fn parse_dump(msg: &str) -> Option<Request> {
    let mut p = msg.splitn(4, ':');
    let (id, op, policy) = (p.next()?, p.next()?, p.next()?);
    let n: u32 = id.trim().parse().ok()?;
    (op == "sca-dump" && !policy.is_empty()).then(|| Request::Dump { agent: format!("{n:03}"), policy: policy.to_string() })
}

async fn apply(gw: &Gw, r: Request) {
    let push = |agent: &str, command: &Value| {
        let tenant = gw.cache.registered(agent).map(|r| r.tenant.clone()).unwrap_or_default();
        // shortcut: a day like the console's commands; a block's own duration is not read from the
        // payload, so a stale response can run when an agent returns. Read it when rules use it.
        gw.queue.push(agent, &tenant, "engine", command, cmd::DEFAULT_TTL_MS);
        gw.stats.c.engine_responses_queued.fetch_add(1, Relaxed);
    };
    match r {
        Request::One { agent, command } => push(&agent, &command),
        Request::Dump { agent, policy } => push(&agent, &json!({ "type": "sca_full", "policy_id": policy })),
        Request::All { command } => {
            gw.stats.c.engine_all_agents_expansions.fetch_add(1, Relaxed);
            // every gateway's keepalives end up in global.db: this sees all of them
            let since = chrono::Utc::now().timestamp() - gw.s.disconnection_secs as i64;
            let rows = agent_state::global_rows(&format!("SELECT id FROM agent WHERE id > 0 AND last_keepalive > {since} AND version LIKE 'ProVigil%'")).await.unwrap_or_default();
            for id in rows.iter().filter_map(|r| r["id"].as_u64()) {
                push(&format!("{id:03}"), &command);
            }
        }
    }
}

async fn read(gw: Arc<Gw>, path: &'static str, parse: fn(&str) -> Option<Request>) {
    let r = match DatagramReceiver::bind(gw.s.home.join(path)).await {
        Ok(r) => r,
        Err(e) => return error!("Engine queue {path} not read: {e}"),
    };
    loop {
        let Ok(m) = r.recv(siem_ipc::OS_MAXSTR).await else { continue };
        gw.stats.c.engine_responses_received.fetch_add(1, Relaxed);
        let text = String::from_utf8_lossy(&m);
        match parse(text.trim_end_matches('\0')) {
            Some(q) => apply(&gw, q).await,
            None => {
                gw.stats.c.engine_responses_invalid.fetch_add(1, Relaxed);
                warn!("Engine request not understood: {}", &text[..text.floor_char_boundary(160)]);
            }
        }
    }
}

pub fn start(gw: Arc<Gw>) {
    tokio::spawn(read(gw.clone(), RESPONSE_QUEUE, parse_response));
    tokio::spawn(read(gw, DUMP_QUEUE, parse_dump));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requests() {
        let m = r#"(msg_to_agent) [] NNS 58 {"version": 1, "command": "x"} - null (from_the_server) (no_rule_id)"#;
        assert_eq!(parse_response(m), Some(Request::One { agent: "058".into(), command: json!({ "type": "ar", "message": { "version": 1, "command": "x" } }) }));
        assert_eq!(parse_response("(msg_to_agent) [] N!S 58 syscheck restart"), Some(Request::One { agent: "058".into(), command: json!({ "type": "scan" }) }));
        assert!(matches!(parse_response(r#"(msg_to_agent) [] ANN (null) {"command": "x"}"#), Some(Request::All { .. })));
        assert_eq!(parse_response("rubbish"), None);
        assert_eq!(parse_response("(msg_to_agent) [] NNS x {}"), None);
        assert_eq!(parse_dump("7:sca-dump:cis_win11:1"), Some(Request::Dump { agent: "007".into(), policy: "cis_win11".into() }));
        assert_eq!(parse_dump("7:other:x"), None);
    }
}
