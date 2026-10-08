//! The analysis socket (`queue/sockets/analysis`, analysisd/asyscom.c):
//! `getstats`, `getagentsstats`, `getconfig` and `reload-ruleset`.

use siem_cjson::Json;

use crate::config_json as cj;
use crate::daemon::{Analysis, Env};
use crate::logmsg::LogList;
use crate::state::ASYS_MAX_NUM_AGENTS_STATS;

/// `ANLSYS_LOCAL_SOCK`
pub const ANLSYS_LOCAL_SOCK: &str = "queue/sockets/analysis";

const ERROR_OK: i32 = 0;
const ERROR_DUE: i32 = 1;
const ERROR_INVALID_INPUT: i32 = 2;
const ERROR_EMPTY_COMMAND: i32 = 3;
const ERROR_UNRECOGNIZED_COMMAND: i32 = 4;
const ERROR_EMPTY_PARAMATERS: i32 = 5;
const ERROR_EMPTY_SECTION: i32 = 6;
const ERROR_UNRECOGNIZED_SECTION: i32 = 7;
const ERROR_INVALID_AGENTS: i32 = 8;
const ERROR_EMPTY_AGENTS: i32 = 9;
const ERROR_EMPTY_LASTID: i32 = 10;
const ERROR_TOO_MANY_AGENTS: i32 = 11;

fn message(code: i32) -> &'static str {
    match code {
        ERROR_OK => "ok",
        ERROR_DUE => "due",
        ERROR_INVALID_INPUT => "Invalid JSON input",
        ERROR_EMPTY_COMMAND => "Empty command",
        ERROR_UNRECOGNIZED_COMMAND => "Unrecognized command",
        ERROR_EMPTY_PARAMATERS => "Empty parameters",
        ERROR_EMPTY_SECTION => "Empty section",
        ERROR_UNRECOGNIZED_SECTION => "Unrecognized or not configured section",
        ERROR_INVALID_AGENTS => "Invalid agents parameter",
        ERROR_EMPTY_AGENTS => "Error getting agents from DB",
        ERROR_EMPTY_LASTID => "Empty last id",
        _ => "Too many agents",
    }
}

/// `asyscom_output_builder`
fn output(code: i32, data: Option<Json>) -> Vec<u8> {
    let mut root = Json::object();
    root.add("error", Json::number(code as f64));
    root.add("message", Json::string(message(code)));
    root.add("data", data.unwrap_or_else(Json::object));
    root.print_unformatted()
}

/// `asyscom_getconfig`
pub fn getconfig(a: &Analysis, section: &[u8]) -> Option<Json> {
    let cfg = &a.cfg;
    Some(match section {
        b"global" => cj::global(cfg),
        b"active_response" => cj::active_response(cfg),
        b"alerts" => cj::alerts(cfg),
        b"decoders" => cj::decoders(&a.engine.decoders, cfg.internal.decoder_order_size as usize),
        b"rules" => cj::rules(&a.engine.rules),
        b"internal" => cj::internal(cfg),
        b"command" => cj::commands(cfg),
        b"labels" => cj::labels(cfg),
        b"rule_test" => cj::rule_test(cfg),
        _ => return None,
    })
}

/// `strcmp` sees a JSON string up to its first NUL.
fn cstr(b: &[u8]) -> &[u8] {
    &b[..b.iter().position(|&c| c == 0).unwrap_or(b.len())]
}

/// `json_parse_agents`: the ids, or None if an element is not a number.
fn parse_agents(agents: &Json) -> Option<Vec<i32>> {
    let mut ids = Vec::new();
    for a in agents.children() {
        match a {
            Json::Number { int, .. } => ids.push(*int),
            _ => return None,
        }
    }
    Some(ids)
}

/// `asyscom_dispatch`: the response to one request.
pub fn dispatch(a: &mut Analysis, env: &mut dyn Env, request: &[u8]) -> Vec<u8> {
    // the request is a C string in a calloc'ed buffer
    let request = &request[..request.iter().position(|&c| c == 0).unwrap_or(request.len())];
    let Ok((req, _)) = siem_cjson::parse_with_opts(request, false) else {
        return output(ERROR_INVALID_INPUT, None);
    };
    let Some(Json::String(command)) = req.get("command") else {
        return output(ERROR_EMPTY_COMMAND, None);
    };
    let now = a.engine.clock.now().sec;
    match cstr(command) {
        b"getstats" => output(ERROR_OK, Some(a.state_json())),
        b"getagentsstats" => {
            let Some(params) = req.get("parameters").filter(|p| p.is_object()) else {
                return output(ERROR_EMPTY_PARAMATERS, None);
            };
            match params.get("agents") {
                Some(agents) if agents.is_array() => {
                    if agents.children().len() >= ASYS_MAX_NUM_AGENTS_STATS {
                        return output(ERROR_TOO_MANY_AGENTS, None);
                    }
                    match parse_agents(agents) {
                        Some(ids) => output(ERROR_OK, Some(a.state.agents_json(now, &ids))),
                        None => output(ERROR_EMPTY_AGENTS, None),
                    }
                }
                Some(Json::String(s)) if cstr(s) == b"all" => match params.get("last_id") {
                    Some(Json::Number { int, .. }) if *int >= 0 => {
                        match env.agents_of_node(*int, ASYS_MAX_NUM_AGENTS_STATS as i32) {
                            Some(ids) => {
                                let code = if ids.len() < ASYS_MAX_NUM_AGENTS_STATS { ERROR_OK } else { ERROR_DUE };
                                output(code, Some(a.state.agents_json(now, &ids)))
                            }
                            None => output(ERROR_EMPTY_AGENTS, None),
                        }
                    }
                    _ => output(ERROR_EMPTY_LASTID, None),
                },
                _ => output(ERROR_INVALID_AGENTS, None),
            }
        }
        b"getconfig" => {
            let Some(params) = req.get("parameters").filter(|p| p.is_object()) else {
                return output(ERROR_EMPTY_PARAMATERS, None);
            };
            let Some(Json::String(section)) = params.get("section") else {
                return output(ERROR_EMPTY_SECTION, None);
            };
            match getconfig(a, cstr(section)) {
                Some(c) => output(ERROR_OK, Some(c)),
                None => output(ERROR_UNRECOGNIZED_SECTION, None),
            }
        }
        b"reload-ruleset" => {
            let mut list = LogList::bounded();
            let fail = a.reload_ruleset(env, &mut list);
            let data = Json::Array(list.msgs.iter().map(|m| Json::string(&m.msg)).collect());
            output(if fail { ERROR_DUE } else { ERROR_OK }, Some(data))
        }
        _ => output(ERROR_UNRECOGNIZED_COMMAND, None),
    }
}
