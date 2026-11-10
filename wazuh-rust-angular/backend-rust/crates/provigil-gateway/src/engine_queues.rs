//! The engine's assessment "dump" requests become queued `sca_full` commands
//! (`specs/provigil-gateway.md` 3.6). Its responses for ProVigil agents go to siem-api's queue
//! (`queue/alerts/provigil-ar`), which writes them to the shared table. One gateway per manager
//! host reads the dump queue (`GATEWAY_ENGINE_QUEUES=0` on the others).

use std::sync::atomic::Ordering::Relaxed;
use std::sync::Arc;

use provigil_agent_server::commands as cmd;
use serde_json::json;
use siem_ipc::local::DatagramReceiver;
use tracing::{error, warn};

use crate::core::Gw;

const DUMP_QUEUE: &str = "queue/alerts/cfgarq";

/// `<id>:sca-dump:<policy>:<first scan>` (the engine's `push_dump`): the agent and the policy.
pub fn parse_dump(msg: &str) -> Option<(String, String)> {
    let mut p = msg.splitn(4, ':');
    let (id, op, policy) = (p.next()?, p.next()?, p.next()?);
    let n: u32 = id.trim().parse().ok()?;
    (op == "sca-dump" && !policy.is_empty()).then(|| (format!("{n:03}"), policy.to_string()))
}

async fn read(gw: Arc<Gw>) {
    let r = match DatagramReceiver::bind(gw.s.home.join(DUMP_QUEUE)).await {
        Ok(r) => r,
        Err(e) => return error!("Engine queue {DUMP_QUEUE} not read: {e}"),
    };
    loop {
        let Ok(m) = r.recv(siem_ipc::OS_MAXSTR).await else { continue };
        gw.stats.c.engine_responses_received.fetch_add(1, Relaxed);
        let text = String::from_utf8_lossy(&m);
        match parse_dump(text.trim_end_matches('\0')) {
            Some((agent, policy)) => {
                let tenant = gw.cache.registered(&agent).map(|r| r.tenant.clone()).unwrap_or_default();
                gw.queue.push(&agent, &tenant, "engine", &json!({ "type": "sca_full", "policy_id": policy }), cmd::DEFAULT_TTL_MS);
                gw.stats.c.engine_responses_queued.fetch_add(1, Relaxed);
            }
            None => {
                gw.stats.c.engine_responses_invalid.fetch_add(1, Relaxed);
                warn!("Engine request not understood: {}", &text[..text.floor_char_boundary(160)]);
            }
        }
    }
}

pub fn start(gw: Arc<Gw>) {
    tokio::spawn(read(gw));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dump_requests() {
        assert_eq!(parse_dump("7:sca-dump:cis_win11:1"), Some(("007".into(), "cis_win11".into())));
        assert_eq!(parse_dump("7:other:x"), None);
        assert_eq!(parse_dump("x:sca-dump:p:0"), None);
        assert_eq!(parse_dump("7:sca-dump::0"), None);
    }
}
