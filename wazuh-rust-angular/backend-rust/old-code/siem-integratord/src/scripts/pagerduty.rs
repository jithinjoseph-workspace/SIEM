//! `integrations/pagerduty.py`

use super::{args_repr, contains, fmt, idx, join, number, post, Ctx, PyErr, R};
use crate::pyjson::{dict, dumps, repr, Py};

const ALERT_INDEX: usize = 1;
const APIKEY_INDEX: usize = 2;
pub const URL: &str = "https://events.pagerduty.com/v2/enqueue";

pub fn main(ctx: &mut Ctx) -> R<()> {
    let a = &ctx.args;
    let (msg, bad) = if a.len() >= 4 {
        ctx.debug_enabled = a.len() > 4 && a[4] == "debug";
        (String::new(), false)
    } else {
        ("# ERROR: Wrong arguments\n".to_string(), true)
    };
    ctx.append_log(&msg)?;
    if bad {
        ctx.debug(&format!("# ERROR: Exiting, bad arguments. Inputted: {}", args_repr(&ctx.args)));
        return Err(PyErr::Exit(2));
    }
    ctx.debug("# Running PagerDuty script");
    let alert_file = ctx.arg(ALERT_INDEX).to_string();
    let apikey = ctx.arg(APIKEY_INDEX).to_string();
    let opt_file = ctx.options_location();
    let options = ctx.json_options(&opt_file)?;
    ctx.debug(&format!("# Opening options file at '{opt_file}' with '{}'", fmt(&options)));
    let alert = ctx.json_alert(&alert_file, (6, 7), "# JSON file for alert {} doesn't exist", "Failed getting JSON alert. Error: {}")?;
    ctx.debug(&format!("# Opening alert file at '{alert_file}' with '{}'", repr(&alert)));
    ctx.debug("# Generating message");
    let msg = generate_msg(&alert, &options, &apikey)?;
    ctx.debug(&format!("# Sending message {msg} to PagerDuty server"));
    let res = post(URL, msg, &[("content-type", "application/json"), ("Accept-Charset", "UTF-8")], 10)?;
    ctx.debug(&format!("# Response received: {}", res.json_method_repr()));
    Ok(())
}

pub fn generate_msg(alert: &Py, options: &Py, apikey: &str) -> R<String> {
    let rule = idx(alert, "rule")?;
    let level = number(idx(rule, "level")?, ">=")?;
    // as in the script, the first test wins: only "info" or "warning"
    let severity = if level >= 7.0 { "warning" } else { "info" };
    let groups = join(idx(rule, "groups")?, ", ")?;
    let mut msg = dict(vec![
        ("routing_key", Py::str(apikey)),
        ("event_action", Py::str("trigger")),
        (
            "payload",
            dict(vec![
                ("summary", if contains(rule, "description")? { idx(rule, "description")?.clone() } else { Py::str("N/A") }),
                ("timestamp", idx(alert, "timestamp")?.clone()),
                ("source", idx(idx(alert, "agent")?, "name")?.clone()),
                ("severity", Py::str(severity)),
                ("group", Py::Str(groups)),
                ("custom_details", alert.clone()),
            ]),
        ),
        ("client", Py::str("Wazuh Monitoring Service")),
        ("client_url", Py::str("https://wazuh.com")),
    ]);
    if options.truthy() {
        msg.update(options);
    }
    Ok(dumps(&msg))
}
