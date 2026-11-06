//! `integrations/slack.py`

use super::{args_repr, contains, fmt, get, idx, number, post, Ctx, PyErr, R};
use crate::pyjson::{dict, dumps, repr, Py};

const ALERT_INDEX: usize = 1;
const WEBHOOK_INDEX: usize = 3;

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
    process_args(ctx)
}

fn process_args(ctx: &Ctx) -> R<()> {
    ctx.debug("# Running Slack script");
    let alert_file = ctx.arg(ALERT_INDEX).to_string();
    let webhook = ctx.arg(WEBHOOK_INDEX).to_string();
    let opt_file = ctx.options_location();
    let options = ctx.json_options(&opt_file)?;
    ctx.debug(&format!("# Opening options file at '{opt_file}' with '{}'", fmt(&options)));
    let alert = ctx.json_alert(&alert_file, (6, 7), "# JSON file for alert {} doesn't exist", "Failed getting JSON alert. Error: {}")?;
    ctx.debug(&format!("# Opening alert file at '{alert_file}' with '{}'", repr(&alert)));
    ctx.debug("# Generating message");
    let msg = generate_msg(&alert, &options)?;
    ctx.debug(&format!("# Sending message {msg} to Slack server"));
    let res = post(&webhook, msg, &[("content-type", "application/json"), ("Accept-Charset", "UTF-8")], 10)?;
    ctx.debug(&format!("# Response received: {}", res.json_method_repr()));
    Ok(())
}

pub fn generate_msg(alert: &Py, options: &Py) -> R<String> {
    let rule = idx(alert, "rule")?;
    let level = idx(rule, "level")?;
    let lv = number(level, "<=")?;
    let color = if lv <= 4.0 {
        "good"
    } else if (5.0..=7.0).contains(&lv) {
        "warning"
    } else {
        "danger"
    };
    let mut fields = Vec::new();
    if contains(alert, "agent")? {
        let ag = idx(alert, "agent")?;
        fields.push(dict(vec![("title", Py::str("Agent")), ("value", Py::Str(format!("({}) - {}", fmt(idx(ag, "id")?), fmt(idx(ag, "name")?))))]));
    }
    if contains(alert, "agentless")? {
        fields.push(dict(vec![("title", Py::str("Agentless Host")), ("value", idx(idx(alert, "agentless")?, "host")?.clone())]));
    }
    fields.push(dict(vec![("title", Py::str("Location")), ("value", idx(alert, "location")?.clone())]));
    fields.push(dict(vec![("title", Py::str("Rule ID")), ("value", Py::Str(format!("{} _(Level {})_", fmt(idx(rule, "id")?), fmt(level))))]));
    let mut msg = dict(vec![
        ("color", Py::str(color)),
        ("pretext", Py::str("WAZUH Alert")),
        ("title", if contains(rule, "description")? { idx(rule, "description")?.clone() } else { Py::str("N/A") }),
        ("text", get(alert, "full_log")?.cloned().unwrap_or(Py::None)),
        ("fields", Py::List(fields)),
        ("ts", idx(alert, "id")?.clone()),
    ]);
    if options.truthy() {
        msg.update(options);
    }
    Ok(dumps(&dict(vec![("attachments", Py::List(vec![msg]))])))
}
