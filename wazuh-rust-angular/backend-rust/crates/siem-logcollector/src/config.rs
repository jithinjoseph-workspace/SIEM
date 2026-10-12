//! `logcollector/config.c`: `LogCollectorConfig` and the `getconfig`
//! JSON (`getLocalfileConfig`, `getSocketConfig`,
//! `getLogcollectorInternalOptions`).

use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};

use siem_cjson::Json;
use siem_config::localfile::{
    multiline_attr_match_str, multiline_attr_replace_str, read_localfile, LogreaderConfig, EVENTLOG,
    MACOS_LOG_TYPE_ACTIVITY, MACOS_LOG_TYPE_LOG, MACOS_LOG_TYPE_TRACE,
};
use siem_config::modules::*;
use siem_config::socket::{read_socket, SocketMode};
use siem_config::{read_config, ConfigContext, ConfigHandler, LogLevel, Platform, Result, Section};
use siem_xml::{OsXml, XmlNode};

use crate::*;

struct Handler<'a>(&'a mut LogreaderConfig);

impl ConfigHandler for Handler<'_> {
    fn section(
        &mut self,
        ctx: &mut ConfigContext,
        _xml: &OsXml,
        section: Section,
        _node: &XmlNode,
        children: Option<&[XmlNode]>,
    ) -> Result<()> {
        let ch = children.unwrap_or(&[]);
        match section {
            Section::Localfile => read_localfile(ctx, ch, self.0),
            Section::LogcollectorSocket => read_socket(ch, &mut self.0.socket_list),
            _ => Ok(()),
        }
    }
}

fn flush(lc: &Lc, ctx: &mut ConfigContext) {
    for (lv, m) in ctx.log.drain(..) {
        match lv {
            LogLevel::Debug1 => lc.log.debug1(m),
            LogLevel::Debug2 => lc.log.debug2(m),
            LogLevel::Info => lc.log.info(m),
            LogLevel::Warn => lc.log.warn(m),
            LogLevel::Error => lc.log.error(m),
        }
    }
}

/// `os_read_agent_name` / `os_read_agent_profile` / `getuname` for `<agent_config>`.
fn agent_identity() -> siem_config::AgentIdentity {
    let data = siem_fileop::crt::read_text(AGENT_INFO_FILE).ok();
    let lines: Vec<String> = data
        .as_deref()
        .map(|d| d.split_inclusive(|&c| c == b'\n').map(|l| String::from_utf8_lossy(l).into_owned()).collect())
        .unwrap_or_default();
    let name = lines.first().map(|l| {
        let mut s = l.clone();
        while s.len() > 1 && s.ends_with('\n') {
            s.pop();
        }
        s
    });
    let profile = lines.get(3).map(|l| l.trim_end_matches(['\r', '\n']).to_string());
    siem_config::AgentIdentity { name, uname: Some(siem_fileop::version_op::getuname().to_string()), profile }
}

/// `LogCollectorConfig`: -1 / `OS_SIZELIM` (-3) on errors, 1 on success.
pub fn log_collector_config(lc: &Lc, cfgfile: &str) -> i32 {
    let i = &lc.ints;
    let set = |a: &std::sync::atomic::AtomicI32, v: i32| a.store(v, Ordering::SeqCst);
    let accept_remote = lc.define_int("logcollector", "remote_commands", 0, 1);
    set(&i.accept_remote, accept_remote);
    set(&i.loop_timeout, lc.define_int("logcollector", "loop_timeout", 1, 120));
    set(&i.open_file_attempts, lc.define_int("logcollector", "open_attempts", 0, 998));
    set(&i.vcheck_files, lc.define_int("logcollector", "vcheck_files", 0, 1024));
    set(&i.maximum_lines, lc.define_int("logcollector", "max_lines", 0, 1000000));
    set(&i.maximum_files, lc.define_int("logcollector", "max_files", 1, 100000));
    set(&i.sock_fail_time, lc.define_int("logcollector", "sock_fail_time", 1, 3600));
    set(&i.sample_log_length, lc.define_int("logcollector", "sample_log_length", 1, 4096));
    set(&i.force_reload, lc.define_int("logcollector", "force_reload", 0, 1));
    set(&i.reload_interval, lc.define_int("logcollector", "reload_interval", 1, 86400));
    set(&i.reload_delay, lc.define_int("logcollector", "reload_delay", 0, 30000));
    set(&i.free_excluded_files_interval, lc.define_int("logcollector", "exclude_files_interval", 1, 172800));
    set(&i.state_interval, lc.define_int("logcollector", "state_interval", 0, 3600));

    lc.total_files.store(0, Ordering::SeqCst);
    lc.current_files.store(0, Ordering::SeqCst);

    if get(&i.force_reload) != 0 && get(&i.reload_interval) < get(&i.vcheck_files) {
        lc.log.warn(format!(
            "Reload interval ({}) must be greater or equal than the checking interval ({}).",
            get(&i.reload_interval),
            get(&i.vcheck_files)
        ));
    }
    #[cfg(unix)]
    set(&i.nofile, lc.define_int("logcollector", "rlimit_nofile", 1024, 1048576));

    let ml = get(&i.maximum_lines);
    if ml > 0 && ml < 100 {
        lc.log.error("Definition 'logcollector.max_lines' must be 0 or 100..1000000.");
        return -1;
    }
    #[cfg(unix)]
    if get(&i.maximum_files) > get(&i.nofile) - 100 {
        lc.log.error("Definition 'logcollector.max_files' must be lower than ('logcollector.rlimit_nofile' - 100).");
        return -3;
    }
    // Limit files on Windows as file descriptors are shared
    #[cfg(windows)]
    if get(&i.maximum_files) > WIN32_MAX_FILES {
        set(&i.maximum_files, WIN32_MAX_FILES);
        lc.log.debug1(format!(
            "The maximum number of files to monitor cannot exceed {WIN32_MAX_FILES} in Windows, so it will be limited."
        ));
    }

    let mut cfg = LogreaderConfig {
        agent_cfg: false,
        accept_remote: accept_remote != 0,
        maximum_files: get(&i.maximum_files),
        ..Default::default()
    };
    let mut ctx = ConfigContext::new(Platform::AGENT);
    let r = read_config(&mut ctx, CLOCALFILE | CLGCSOCKET, cfgfile, None, &mut Handler(&mut cfg));
    flush(lc, &mut ctx);
    if r.is_err() {
        return -1;
    }

    // CLIENT: the shared agent.conf
    cfg.agent_cfg = true;
    let mut ctx = ConfigContext::new(Platform::AGENT);
    ctx.agent = agent_identity();
    let remote = Some(lc.define_int("agent", "remote_conf", 0, 1) != 0);
    let _ = read_config(&mut ctx, CAGENT_CONFIG | CLOCALFILE | CLGCSOCKET, AGENTCONFIG, remote, &mut Handler(&mut cfg));
    flush(lc, &mut ctx);
    cfg.agent_cfg = false;

    lc.current_files.store(cfg.current_files, Ordering::SeqCst);
    lc.total_files.store(cfg.total_files, Ordering::SeqCst);

    // logff ends at the first entry without log_format (update_current)
    let mut files = lc.files.write().unwrap();
    files.logff = cfg.config.into_iter().map(|c| Mutex::new(Reader::new(c))).collect();
    files.globs = cfg
        .globs
        .into_iter()
        .map(|g| Glob {
            gpath: g.gpath,
            exclude_path: g.exclude_path,
            num_files: g.num_files,
            gfiles: g.gfiles.into_iter().map(|c| Mutex::new(Reader::new(c))).collect(),
        })
        .collect();
    *lc.logsk.write().unwrap() = cfg
        .socket_list
        .into_iter()
        .map(|s| Arc::new(SockFwd::new(&s.name, &s.location, s.mode, s.prefix)))
        .collect();
    1
}

fn s(v: &str) -> Json {
    Json::string(v)
}

/// `_getLocalfilesListJSON`
fn localfile_json(r: &Reader, gpath: Option<&str>) -> Json {
    let c = &r.c;
    let mut f = Json::object();
    if let Some(g) = gpath {
        f.add("file", s(g));
    } else if let Some(x) = &c.ffile {
        f.add("file", s(x));
    } else if let Some(x) = &c.file {
        f.add("file", s(x));
    }
    if let Some(x) = &c.channel_str {
        f.add("channel", s(x));
    }
    if let Some(x) = &c.logformat {
        f.add("logformat", s(x));
    }
    if let Some(x) = &c.command {
        f.add("command", s(x));
    }
    if let Some(x) = &c.djb_program_name {
        f.add("djb_program_name", s(x));
    }
    if let Some(x) = &c.alias {
        f.add("alias", s(x));
    }
    if let Some(q) = &c.query {
        let mut o = Json::object();
        if !q.is_empty() {
            o.add("value", s(q));
        }
        if let Some(l) = &c.query_level {
            o.add("level", s(l));
        }
        if c.query_type > 0 {
            let mut t = Json::array();
            if c.query_type & MACOS_LOG_TYPE_LOG != 0 {
                t.push(s("log"));
            }
            if c.query_type & MACOS_LOG_TYPE_ACTIVITY != 0 {
                t.push(s("activity"));
            }
            if c.query_type & MACOS_LOG_TYPE_TRACE != 0 {
                t.push(s("trace"));
            }
            o.add("type", t);
        }
        f.add("query", o);
    }
    if c.journal_log.is_none() {
        f.add("ignore_binaries", s(if c.filter_binary != 0 { "yes" } else { "no" }));
    }
    if let Some(x) = &c.age_str {
        f.add("age", s(x));
    }
    if let Some(x) = &c.exclude {
        f.add("exclude", s(x));
    }
    if let Some(fmt) = &c.logformat {
        if fmt != EVENTLOG && fmt != "command" && fmt != "full_command" {
            if c.future == 1 {
                f.add("only-future-events", s("yes"));
            } else {
                f.add("only-future-events", s("no"));
                let mut off = c.diff_max_size.to_string();
                off.truncate(10);
                f.add("max-size", s(&off));
            }
        }
    }
    if let Some(t) = c.target.as_ref().filter(|t| !t.is_empty()) {
        let mut a = Json::array();
        for x in t.iter() {
            a.push(s(x));
        }
        f.add("target", a);
    }
    if let Some(of) = c.out_format.as_ref().filter(|o| !o.is_empty()) {
        let mut a = Json::array();
        for o in of.iter() {
            let mut it = Json::object();
            it.add("target", s(o.target.as_deref().unwrap_or("all")));
            it.add("format", s(&o.format));
            a.push(it);
        }
        f.add("out_format", a);
    }
    if r.duplicated != 0 {
        f.add("duplicate", Json::number(r.duplicated as f64));
    }
    if let Some(l) = c.labels.as_ref().filter(|l| !l.is_empty()) {
        let mut o = Json::object();
        for x in l.iter() {
            o.add(&x.key, s(&x.value));
        }
        f.add("labels", o);
    }
    let is_cmd = matches!(c.logformat.as_deref(), Some("command") | Some("full_command"));
    if c.ign != 0 && is_cmd {
        f.add("frequency", Json::number(c.ign as f64));
    }
    if c.reconnect_time != 0 && c.logformat.as_deref() == Some("eventchannel") {
        f.add("reconnect_time", Json::number(c.reconnect_time as f64));
    }
    if let Some(m) = &c.multiline {
        let mut o = Json::object();
        o.add("match", s(multiline_attr_match_str(m.match_type)));
        o.add("replace", s(multiline_attr_replace_str(m.replace_type)));
        o.add("regex", s(m.regex.pattern().unwrap_or("")));
        o.add("timeout", Json::number(m.timeout as f64));
        f.add("multiline_regex", o);
    }
    if let Some(jl) = &c.journal_log {
        if jl.filters.is_some() {
            if let Some(js) = journal_filters_json(jl) {
                f.add("filters", js);
            }
            f.add("filters_disabled", Json::bool(jl.disable_filters));
        }
    }
    for (name, list) in [("ignore", &c.regex_ignore), ("restrict", &c.regex_restrict)] {
        if let Some(l) = list {
            if !l.is_empty() {
                let mut a = Json::array();
                for e in l.iter() {
                    let mut o = Json::object();
                    o.add("value", s(e.pattern().unwrap_or("")));
                    o.add("type", s(e.type_str().unwrap_or("")));
                    a.push(o);
                }
                f.add(name, a);
            }
        }
    }
    f
}

/// `w_journal_filter_list_as_json`
fn journal_filters_json(jl: &siem_config::localfile::JournalLogConfig) -> Option<Json> {
    let mut arr = Json::array();
    for flt in jl.active_filters() {
        if flt.units.is_empty() {
            return None;
        }
        let mut fa = Json::array();
        for u in &flt.units {
            let mut o = Json::object();
            o.add("field", s(&u.field));
            o.add("expression", s(u.exp.pattern().unwrap_or("")));
            o.add("ignore_if_missing", Json::bool(u.ignore_if_missing));
            fa.push(o);
        }
        arr.push(fa);
    }
    Some(arr)
}

/// `getLocalfileConfig`
pub fn get_localfile_config(lc: &Lc) -> Option<Json> {
    let files = lc.files.read().unwrap();
    let mut arr = Json::array();
    // for (i = 0; logff[i].target; i++)
    for m in &files.logff {
        let r = m.lock().unwrap_or_else(|e| e.into_inner());
        if r.c.target.is_none() {
            break;
        }
        arr.push(localfile_json(&r, None));
    }
    for g in &files.globs {
        if let Some(m) = g.gfiles.first() {
            let r = m.lock().unwrap_or_else(|e| e.into_inner());
            arr.push(localfile_json(&r, Some(&g.gpath)));
        }
    }
    let mut root = Json::object();
    if !arr.is_empty() {
        root.add("localfile", arr);
    }
    Some(root)
}

/// `getSocketConfig`
pub fn get_socket_config(lc: &Lc) -> Option<Json> {
    let sk = lc.logsk.read().unwrap();
    let mut arr = Json::array();
    for x in sk.iter() {
        let mut o = Json::object();
        o.add("name", s(&x.name));
        o.add("location", s(&x.location));
        o.add("mode", s(if x.mode == SocketMode::Udp { "udp" } else { "tcp" }));
        if let Some(p) = &x.prefix {
            o.add("prefix", s(p));
        }
        arr.push(o);
    }
    let mut root = Json::object();
    if !arr.is_empty() {
        root.add("socket", arr);
    }
    Some(root)
}

/// `getLogcollectorInternalOptions`
pub fn get_internal_options(lc: &Lc) -> Json {
    let i = &lc.ints;
    let n = |v: &std::sync::atomic::AtomicI32| Json::number(get(v) as f64);
    let mut l = Json::object();
    l.add("remote_commands", n(&i.accept_remote));
    l.add("loop_timeout", n(&i.loop_timeout));
    l.add("open_attempts", n(&i.open_file_attempts));
    l.add("vcheck_files", n(&i.vcheck_files));
    l.add("max_lines", n(&i.maximum_lines));
    l.add("max_files", n(&i.maximum_files));
    l.add("sock_fail_time", n(&i.sock_fail_time));
    l.add("debug", n(&i.lc_debug_level));
    l.add("sample_log_length", n(&i.sample_log_length));
    l.add("queue_size", n(&i.output_queue_size));
    l.add("input_threads", n(&i.n_input_threads));
    l.add("force_reload", n(&i.force_reload));
    l.add("reload_interval", n(&i.reload_interval));
    l.add("reload_delay", n(&i.reload_delay));
    l.add("exclude_files_interval", n(&i.free_excluded_files_interval));
    l.add("state_interval", n(&i.state_interval));
    #[cfg(unix)]
    l.add("rlimit_nofile", n(&i.nofile));
    let mut internals = Json::object();
    internals.add("logcollector", l);
    let mut root = Json::object();
    root.add("internal", internals);
    root
}
