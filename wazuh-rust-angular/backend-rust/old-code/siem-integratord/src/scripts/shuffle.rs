//! `integrations/shuffle.py`

use super::{args_repr, contains, fmt, get, idx, number, post, Ctx, PyErr, R};
use crate::pyjson::{dict, dumps, repr, Py};

const ALERT_INDEX: usize = 1;
const WEBHOOK_INDEX: usize = 3;
const SKIP_RULE_IDS: [&str; 14] = ["87924", "87900", "87901", "87902", "87903", "87904", "86001", "86002", "86003", "87932", "80710", "87929", "87928", "5710"];

pub fn main(ctx: &mut Ctx) -> R<()> {
    let a = &ctx.args;
    let (msg, bad) = if a.len() >= 4 {
        let m = format!("{} {} {} {} {}", a[1], a[2], a[3], a.get(4).map(String::as_str).unwrap_or(""), a.get(5).map(String::as_str).unwrap_or(""));
        ctx.debug_enabled = a.len() > 4 && a[4] == "debug";
        (m, false)
    } else {
        ("# ERROR: Wrong arguments".to_string(), true)
    };
    ctx.append_log(&format!("{msg}\n"))?;
    if bad {
        ctx.debug(&format!("# ERROR: Exiting, bad arguments. Inputted: {}", args_repr(&ctx.args)));
        return Err(PyErr::Exit(2));
    }
    ctx.debug("# Running Shuffle script");
    let alert_file = ctx.arg(ALERT_INDEX).to_string();
    let webhook = ctx.arg(WEBHOOK_INDEX).to_string();
    let opt_file = ctx.options_location();
    let options = ctx.json_options(&opt_file)?;
    ctx.debug(&format!("# Opening options file at '{opt_file}' with '{}'", fmt(&options)));
    let alert = ctx.json_alert(&alert_file, (6, 7), "# JSON file for alert {} doesn't exist", "Failed getting JSON alert. Error: {}")?;
    ctx.debug(&format!("# Opening alert file at '{alert_file}' with '{}'", repr(&alert)));
    ctx.debug("# Generating message");
    let Some(msg) = generate_msg(&alert, &options)? else { return Ok(()) };
    ctx.debug(&format!("# Sending message {msg} to Shuffle server"));
    let res = post(&webhook, msg, &[("content-type", "application/json"), ("Accept-Charset", "UTF-8")], 10)?;
    ctx.debug(&format!("# Response received: {}", res.json_method_repr()));
    Ok(())
}

/// `None` for the rules Shuffle skips (the script prints a line and sends nothing).
pub fn generate_msg(alert: &Py, options: &Py) -> R<Option<String>> {
    let rule = idx(alert, "rule")?;
    let id = idx(rule, "id")?;
    if id.as_str().is_some_and(|i| SKIP_RULE_IDS.contains(&i)) {
        println!("Skipping rule {}", fmt(id));
        return Ok(None);
    }
    let lv = number(idx(rule, "level")?, "<=")?;
    let severity = if lv <= 4.0 {
        1
    } else if (5.0..=7.0).contains(&lv) {
        2
    } else {
        3
    };
    let mut msg = dict(vec![
        ("severity", Py::int(severity)),
        ("pretext", Py::str("WAZUH Alert")),
        ("title", if contains(rule, "description")? { idx(rule, "description")?.clone() } else { Py::str("N/A") }),
        ("text", get(alert, "full_log")?.cloned().unwrap_or(Py::None)),
        ("rule_id", id.clone()),
        ("timestamp", idx(alert, "timestamp")?.clone()),
        ("id", idx(alert, "id")?.clone()),
        ("all_fields", alert.clone()),
    ]);
    if options.truthy() {
        msg.update(options);
    }
    Ok(Some(dumps(&msg)))
}
