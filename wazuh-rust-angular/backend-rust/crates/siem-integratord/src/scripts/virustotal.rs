//! `integrations/virustotal.py`: looks up the md5 of a FIM alert and sends
//! the result back to analysisd as a new event.

use super::{agent_location, args_repr, contains, idx, Ctx, PyErr, R};
use crate::pyjson::{dict, dumps, repr, Py};

const ALERT_INDEX: usize = 1;
const APIKEY_INDEX: usize = 2;
const TIMEOUT_INDEX: usize = 6;
const RETRIES_INDEX: usize = 7;
pub const URL: &str = "https://www.virustotal.com/vtapi/v2/file/report";

struct Vt {
    timeout: u64,
    retries: i64,
}

/// `int(s)`
fn py_int(s: &str) -> R<i64> {
    s.trim().parse::<i64>().map_err(|_| PyErr::Value(format!("invalid literal for int() with base 10: {}", crate::pyjson::str_repr(s))))
}

pub fn main(ctx: &mut Ctx) -> R<()> {
    let mut vt = Vt { timeout: 10, retries: 3 };
    let a = ctx.args.clone();
    let (msg, bad) = if a.len() >= 4 {
        ctx.debug_enabled = a.len() > 4 && a[4] == "debug";
        if a.len() > TIMEOUT_INDEX {
            vt.timeout = py_int(&a[TIMEOUT_INDEX])?.max(0) as u64;
        }
        if a.len() > RETRIES_INDEX {
            vt.retries = py_int(&a[RETRIES_INDEX])?;
        }
        (String::new(), false)
    } else {
        ("# Error: Wrong arguments\n".to_string(), true)
    };
    ctx.append_log(&msg)?;
    if bad {
        ctx.debug(&format!("# Error: Exiting, bad arguments. Inputted: {}", args_repr(&ctx.args)));
        return Err(PyErr::Exit(2));
    }
    ctx.debug("# Running VirusTotal script");
    let alert_file = ctx.arg(ALERT_INDEX).to_string();
    let apikey = ctx.arg(APIKEY_INDEX).to_string();
    let alert = ctx.json_alert(&alert_file, (6, 7), "# JSON file for alert {} doesn't exist", "Failed getting JSON alert. Error: {}")?;
    ctx.debug(&format!("# Opening alert file at '{alert_file}' with '{}'", repr(&alert)));
    ctx.debug("# Requesting VirusTotal information");
    let Some(out) = request_virustotal_info(ctx, &vt, &alert, &apikey)? else {
        ctx.debug("# Error: Empty message");
        return Err(PyErr::Exc(String::new()));
    };
    send_msg(ctx, &out, Some(idx(&alert, "agent")?))
}

fn md5_ok(v: &Py) -> bool {
    static RE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    let re = RE.get_or_init(|| regex::Regex::new(r"\b([a-f\d]{32}|[A-F\d]{32})\b").unwrap());
    v.as_str().is_some_and(|s| re.find_iter(s).count() == 1)
}

fn request_virustotal_info(ctx: &Ctx, vt: &Vt, alert: &Py, apikey: &str) -> R<Option<Py>> {
    let mut out = dict(vec![("virustotal", Py::dict()), ("integration", Py::str("virustotal"))]);
    if !contains(alert, "syscheck")? {
        ctx.debug("# No syscheck block present in the alert");
        return Ok(None);
    }
    let sk = idx(alert, "syscheck")?;
    if !contains(sk, "md5_after")? {
        ctx.debug("# No md5 checksum present in the alert");
        return Ok(None);
    }
    if !md5_ok(idx(sk, "md5_after")?) {
        ctx.debug("# md5_after field in the alert is not a md5 hash checksum");
        return Ok(None);
    }
    let data = request_info_from_api(ctx, vt, alert, &mut out, apikey)?;
    let v = out.get_mut("virustotal").unwrap();
    v.set("found", Py::int(0));
    v.set("malicious", Py::int(0));
    v.set(
        "source",
        dict(vec![
            ("alert_id", idx(alert, "id")?.clone()),
            ("file", idx(sk, "path")?.clone()),
            ("md5", idx(sk, "md5_after")?.clone()),
            ("sha1", idx(sk, "sha1_after")?.clone()),
        ]),
    );
    // in_database(): response_code == 0 means not found
    let rc = idx(&data, "response_code")?;
    if !(rc.num() == Some(0.0)) {
        v.set("found", Py::int(1));
    }
    if v.get("found").and_then(Py::num) == Some(1.0) {
        let positives = idx(&data, "positives")?;
        if super::number(positives, ">")? > 0.0 {
            v.set("malicious", Py::int(1));
        }
        for k in ["sha1", "scan_date", "positives", "total", "permalink"] {
            let x = idx(&data, k)?.clone();
            v.set(k, x);
        }
    }
    Ok(Some(out))
}

fn request_info_from_api(ctx: &Ctx, vt: &Vt, alert: &Py, out: &mut Py, apikey: &str) -> R<Py> {
    let mut attempt = 0;
    while attempt < vt.retries + 1 {
        match query_api(ctx, vt, idx(idx(alert, "syscheck")?, "md5_after")?, apikey) {
            Ok(d) => return Ok(d),
            Err(PyErr::Requests(c, _)) if c.contains("Timeout") => {
                ctx.debug(&format!("# Error: Request timed out. Remaining retries: {}", vt.retries - attempt));
            }
            Err(PyErr::Exit(c)) => return Err(PyErr::Exit(c)),
            Err(e) => {
                ctx.debug(&e.text());
                return Err(PyErr::Exit(4));
            }
        }
        attempt += 1;
    }
    ctx.debug("# Error: Request timed out and maximum number of retries was exceeded");
    let v = out.get_mut("virustotal").unwrap();
    v.set("error", Py::int(408));
    v.set("description", Py::str("Error: API request timed out"));
    send_msg(ctx, out, None)?;
    Err(PyErr::Exit(4))
}

fn query_api(ctx: &Ctx, vt: &Vt, hash: &Py, apikey: &str) -> R<Py> {
    ctx.debug("# Querying VirusTotal API");
    let h = super::fmt(hash);
    let r = super::get_url(URL, &[("apikey", apikey), ("resource", &h)], &[("Accept-Encoding", "gzip, deflate"), ("User-Agent", "gzip,  Python library-client-VirusTotal")], Some(vt.timeout))?;
    if r.status == 200 {
        return r.json();
    }
    let (desc, raise) = match r.status {
        204 => ("Error: Public API request rate limit reached", "# Error: VirusTotal Public API request rate limit reached"),
        403 => ("Error: Check credentials", "# Error: VirusTotal credentials, required privileges error"),
        _ => ("Error: API request fail", "# Error: VirusTotal credentials, required privileges error"),
    };
    let out = dict(vec![("virustotal", dict(vec![("error", Py::int(r.status as i64)), ("description", Py::str(desc))])), ("integration", Py::str("virustotal"))]);
    send_msg(ctx, &out, None)?;
    Err(PyErr::Exc(raise.into()))
}

fn send_msg(ctx: &Ctx, msg: &Py, agent: Option<&Py>) -> R<()> {
    let string = match agent.map(|a| agent_location(a, "virustotal")).transpose()?.flatten() {
        None => format!("1:virustotal:{}", dumps(msg)),
        Some(loc) => format!("1:{loc}:{}", dumps(msg)),
    };
    ctx.debug(&format!("# Request result from VT server: {string}"));
    match super::queue_send(ctx, string.as_bytes()) {
        Ok(()) => Ok(()),
        Err(2) => {
            ctx.debug(&format!("# Error: Unable to open socket connection at {}", ctx.home.join("queue").join("sockets").join("queue").display()));
            Err(PyErr::Exit(5))
        }
        Err(e) => Err(PyErr::Exc(format!("[Errno {e}] {}", std::io::Error::from_raw_os_error(e).to_string().split(" (os error").next().unwrap_or("")))),
    }
}
