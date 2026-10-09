//! `SchemaAdapter::adaptJsonMessage` (router/src/schemaAdapter.hpp): turns
//! an agent's JSON message plus its context into the JSON the flatbuffers
//! schema parser reads.

use crate::sjson;

/// `msg_type`
pub const MT_INVALID: i32 = 0;
pub const MT_SYS_DELTAS: i32 = 1;
pub const MT_SYNC: i32 = 2;
pub const MT_SYSCHECK_DELTAS: i32 = 3;

/// `struct agent_ctx` (C strings; `agent_version` may be NULL).
#[derive(Clone, Copy, Debug)]
pub struct AgentCtx<'a> {
    pub agent_id: &'a [u8],
    pub agent_name: &'a [u8],
    pub agent_ip: &'a [u8],
    pub agent_version: Option<&'a [u8]>,
}

/// The bytes a `const char*` designates.
pub(crate) fn c_view(s: &[u8]) -> &[u8] {
    s.split(|&c| c == 0).next().unwrap_or_default()
}

/// `adaptJsonMessage(message, schema, agentCtx, buffer)`: `Err` is the
/// exception's `what()`.
pub fn adapt_json_message(message: &[u8], schema: i32, agent_ctx: Option<&AgentCtx>, buffer: &mut Vec<u8>) -> Result<(), Vec<u8>> {
    let Some(ctx) = agent_ctx else {
        return Err(b"Agent context is null".to_vec());
    };
    let Ok(parsed) = sjson::parse(message) else {
        return Err([b"Failed to parse the indexer response ".as_slice(), message].concat());
    };
    let Ok(type_elem) = parsed.at_key(b"type") else {
        return Err([b"No 'type' object in message: ".as_slice(), message].concat());
    };
    let ty = type_elem.get_string().map_err(|e| e.as_bytes().to_vec())?;
    if matches!(ty, b"integrity_check_left" | b"integrity_check_right" | b"scan_start" | b"scan_end") {
        return Ok(());
    }
    if parsed.at_key(b"ID").is_ok() && parsed.at_key(b"timestamp").is_ok() {
        return Ok(());
    }
    buffer.extend_from_slice(br#"{"agent_info":{"agent_id":""#);
    buffer.extend_from_slice(c_view(ctx.agent_id));
    buffer.extend_from_slice(br#"","agent_name":""#);
    buffer.extend_from_slice(c_view(ctx.agent_name));
    buffer.extend_from_slice(br#"","agent_ip":""#);
    buffer.extend_from_slice(c_view(ctx.agent_ip));
    buffer.extend_from_slice(br#"","agent_version":""#);
    buffer.extend_from_slice(ctx.agent_version.map(c_view).unwrap_or_default());
    buffer.extend_from_slice(br#""},"#);
    buffer.extend_from_slice(br#""data_type":""#);
    buffer.extend_from_slice(ty);
    buffer.extend_from_slice(br#"","#);
    if schema == MT_SYS_DELTAS || schema == MT_SYSCHECK_DELTAS {
        buffer.extend_from_slice(&message[1..]);
    } else if schema == MT_SYNC {
        let Ok(data) = parsed.at_key(b"data") else {
            return Err([b"No 'data' object in MT_SYNC message: ".as_slice(), message].concat());
        };
        if !matches!(ty, b"state" | b"integrity_check_global" | b"integrity_clear") {
            return Err([b"Type ".as_slice(), ty, b" not implemented"].concat());
        }
        let mut sb = Vec::new();
        data.get_object().map_err(|e| e.as_bytes().to_vec())?.append_to(&mut sb);
        buffer.extend_from_slice(br#""data":{"attributes_type":""#);
        let component = parsed.at_key(b"component").and_then(|c| c.get_string()).map_err(|e| e.as_bytes().to_vec())?;
        buffer.extend_from_slice(component);
        buffer.extend_from_slice(br#"","#);
        buffer.extend_from_slice(&sb[1..]);
        buffer.push(b'}');
    } else {
        return Err(b"Not implemented".to_vec());
    }
    Ok(())
}
