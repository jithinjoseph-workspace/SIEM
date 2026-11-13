//! The analysis socket `queue/sockets/analysis` (spec section 2.22): `getstats`,
//! `getagentsstats`, `getconfig`, `reload-ruleset`; answers
//! `{"error":N,"message":..,"data":..}`.

use provigil_json::Json;

use crate::stats::AGENTS_PER_ANSWER;

pub const PATH: &str = "queue/sockets/analysis";

/// What the socket asks of the service.
pub trait Service {
    fn stats(&mut self) -> Json;
    fn agents_stats(&mut self, ids: &[i32]) -> Json;
    /// Active agents of this node after `last` (at most `limit`).
    fn agents_of_node(&mut self, last: i32, limit: i32) -> Option<Vec<i32>>;
    fn config(&mut self, section: &[u8]) -> Option<Json>;
    /// Reloads the ruleset: (failed, the load messages).
    fn reload(&mut self) -> (bool, Vec<String>);
}

const OK: i32 = 0;
const DUE: i32 = 1;
const INVALID_INPUT: i32 = 2;
const EMPTY_COMMAND: i32 = 3;
const UNKNOWN_COMMAND: i32 = 4;
const EMPTY_PARAMETERS: i32 = 5;
const EMPTY_SECTION: i32 = 6;
const UNKNOWN_SECTION: i32 = 7;
const INVALID_AGENTS: i32 = 8;
const NO_AGENTS: i32 = 9;
const EMPTY_LAST_ID: i32 = 10;
const TOO_MANY_AGENTS: i32 = 11;

fn answer(code: i32, data: Option<Json>) -> Vec<u8> {
    let text = match code {
        OK => "ok",
        DUE => "due",
        INVALID_INPUT => "Invalid JSON input",
        EMPTY_COMMAND => "Empty command",
        UNKNOWN_COMMAND => "Unrecognized command",
        EMPTY_PARAMETERS => "Empty parameters",
        EMPTY_SECTION => "Empty section",
        UNKNOWN_SECTION => "Unrecognized or not configured section",
        INVALID_AGENTS => "Invalid agents parameter",
        NO_AGENTS => "Error getting agents from DB",
        EMPTY_LAST_ID => "Empty last id",
        _ => "Too many agents",
    };
    let mut root = Json::object();
    root.add("error", Json::number(f64::from(code)));
    root.add("message", Json::string(text));
    root.add("data", data.unwrap_or_else(Json::object));
    root.print_unformatted()
}

fn cut(b: &[u8]) -> &[u8] {
    crate::event::text_at(b, 0)
}

/// The answer to one request.
pub fn request(s: &mut dyn Service, raw: &[u8]) -> Vec<u8> {
    let Ok((req, _)) = provigil_json::parse_with_opts(cut(raw), false) else { return answer(INVALID_INPUT, None) };
    let Some(Json::String(command)) = req.get("command") else { return answer(EMPTY_COMMAND, None) };
    let params = || req.get("parameters").filter(|p| matches!(p, Json::Object(_)));
    match cut(command) {
        b"getstats" => answer(OK, Some(s.stats())),
        b"getagentsstats" => {
            let Some(p) = params() else { return answer(EMPTY_PARAMETERS, None) };
            match p.get("agents") {
                Some(Json::Array(list)) => {
                    if list.len() >= AGENTS_PER_ANSWER {
                        return answer(TOO_MANY_AGENTS, None);
                    }
                    let ids: Option<Vec<i32>> = list.iter().map(|a| if let Json::Number { int, .. } = a { Some(*int) } else { None }).collect();
                    match ids {
                        Some(ids) => answer(OK, Some(s.agents_stats(&ids))),
                        None => answer(NO_AGENTS, None),
                    }
                }
                Some(Json::String(all)) if cut(all) == b"all" => match p.get("last_id") {
                    Some(Json::Number { int, .. }) if *int >= 0 => match s.agents_of_node(*int, AGENTS_PER_ANSWER as i32) {
                        Some(ids) => answer(if ids.len() < AGENTS_PER_ANSWER { OK } else { DUE }, Some(s.agents_stats(&ids))),
                        None => answer(NO_AGENTS, None),
                    },
                    _ => answer(EMPTY_LAST_ID, None),
                },
                _ => answer(INVALID_AGENTS, None),
            }
        }
        b"getconfig" => {
            let Some(p) = params() else { return answer(EMPTY_PARAMETERS, None) };
            let Some(Json::String(section)) = p.get("section") else { return answer(EMPTY_SECTION, None) };
            match s.config(cut(section)) {
                Some(c) => answer(OK, Some(c)),
                None => answer(UNKNOWN_SECTION, None),
            }
        }
        b"reload-ruleset" => {
            let (failed, msgs) = s.reload();
            answer(if failed { DUE } else { OK }, Some(Json::Array(msgs.into_iter().map(Json::string).collect())))
        }
        _ => answer(UNKNOWN_COMMAND, None),
    }
}
