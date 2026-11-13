//! Reading the settings, old against new: generated `ossec.conf` files and internal options
//! must give the same values, warnings and notes, or the same error text.

use std::path::Path;

use provigil_analysisd::config::Config;
use siem_analysisd::daemon_config::AnalysisdConfig;

/// `safe`: mostly the first (valid) choice of each list.
struct Rng(u64, bool);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
    fn pick<'a>(&mut self, v: &[&'a str]) -> &'a str {
        if self.1 && self.below(10) < 8 {
            return v[0];
        }
        v[self.below(v.len())]
    }
    fn one_in(&mut self, n: usize) -> bool {
        self.below(n) == 0
    }
    /// A deliberate mistake, never in safe mode.
    fn bad(&mut self, n: usize) -> bool {
        !self.1 && self.one_in(n)
    }
}

fn old_lines(c: &AnalysisdConfig) -> Vec<String> {
    let g = &c.global;
    let mut l = vec![
        format!(
            "global {} {} {} {} {} {} {} {} {:?} {} {:?} {} {:?} {:?} {:?} {} {} {} {}",
            g.logall != 0, g.logall_json != 0, g.stats, g.integrity, g.rootcheck, g.hostinfo, g.mailnotify, g.prelude != 0, g.prelude_profile, g.prelude_log_level, g.geoipdb_file,
            g.zeromq_output != 0, g.zeromq_output_uri, g.zeromq_output_server_cert, g.zeromq_output_client_cert, g.jsonout_output != 0, g.alerts_log != 0, g.update_check != 0, g.memorysize
        ),
        format!("white {:?} {:?}", g.white_list, g.hostname_white_list.iter().map(|m| m.patterns().iter().map(|p| p.to_vec()).collect::<Vec<_>>()).collect::<Vec<_>>()),
        format!("custom {:?} forward {:?}", (g.custom_alert_output != 0).then(|| g.custom_alert_output_format.clone()).flatten(), g.forwarders_list),
        format!("rotate {} {} {} {}", g.rotate_interval, g.min_rotate_interval, g.max_output_size, g.queue_size),
        format!("eps {} {} {}", g.eps.maximum, g.eps.timeframe, g.eps.maximum_found),
        format!("disc {} {} {:?} {:?} {:?}", g.agents_disconnection_time, g.agents_disconnection_alert_time, g.cti_url, g.geoip_db_path, g.geoip6_db_path),
        format!("sk {} {} {} {} {:?}", g.syscheck_auto_ignore != 0, g.syscheck_ignore_frequency, g.syscheck_ignore_time, g.syscheck_alert_new != 0, g.syscheck_ignore),
        format!("levels {} {} cluster {:?} {:?} {:?} {} labels {} {} ar {}", g.mailbylevel, g.logbylevel, g.cluster_name, g.node_name, g.node_type, g.hide_cluster_info != 0, g.label_cache_maxage, g.show_hidden_labels, g.ar),
        format!("ruleset {:?} {:?} {:?} {:?} {:?}", c.ruleset.decoders, c.ruleset.includes, c.ruleset.lists, c.ruleset.mailbylevel, c.ruleset.logbylevel),
        format!("cl {:?} {:?} {:?} {}", c.cluster.cluster_name, c.cluster.node_name, c.cluster.node_type, c.cluster.hide_cluster_info),
    ];
    for x in &c.labels {
        l.push(format!("label {:?} {:?} {} {}", x.key, x.value, x.flags.hidden, x.flags.system));
    }
    for s in &c.sockets {
        l.push(format!("socket {:?} {:?} {} {:?}", s.name, s.location, format!("{:?}", s.mode) == "Tcp", s.prefix));
    }
    for x in &c.ar.commands {
        l.push(format!("cmd {:?} {:?} {} {:?}", x.name, x.executable, x.timeout_allowed, x.extra_args));
    }
    for r in &c.ar.responses {
        l.push(format!("resp {:?} {:?} {} {} {} {} {:?} {:?} {:?}", r.name, r.command, r.ar_cmd, r.location, r.level, r.timeout, r.agent_id, r.rules_id, r.rules_group));
    }
    l.push(format!("arflag {} conf {:?} notes {:?}", c.ar.ar_flag, c.ar.ar_conf, c.ar.notes));
    l.push(format!("logtest {} {} {} {}", c.logtest.enabled, c.logtest.threads, c.logtest.max_sessions, c.logtest.session_timeout));
    let i = &c.internal;
    l.push(format!(
        "internal {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {}",
        i.debug, i.decoder_order_size, i.log_fw, i.label_cache_maxage, i.show_hidden_labels, i.min_rotate_interval, i.default_timeframe, i.fts_list_size, i.fts_min_size_for_str,
        i.rule_matching_threads, i.stats_maxdiff, i.stats_mindiff, i.stats_percent_diff, i.rlimit_nofile, i.state_interval, i.event_threads, i.geoip_jsonout
    ));
    l.push(format!("threads {:?}", [i.syscheck_threads, i.syscollector_threads, i.rootcheck_threads, i.sca_threads, i.hostinfo_threads, i.winevt_threads, i.dbsync_threads]));
    let q = &i.q;
    l.push(format!(
        "queues {:?}",
        [q.archives, q.alerts, q.statistical, q.firewall, q.fts, q.syscheck, q.syscollector, q.rootcheck, q.sca, q.hostinfo, q.winevt, q.event, q.output, q.dbsync, q.upgrade]
    ));
    l.push(format!("warnings {:?}", c.warnings));
    l
}

fn new_lines(c: &Config) -> Vec<String> {
    let g = &c.global;
    let mut l = vec![
        format!(
            "global {} {} {} {} {} {} {} {} {:?} {} {:?} {} {:?} {:?} {:?} {} {} {} {}",
            g.logall, g.logall_json, g.stats, g.integrity, g.rootcheck, g.hostinfo, g.mailnotify, g.prelude, g.prelude_profile, g.prelude_log_level, g.geoipdb, g.zeromq_output,
            g.zeromq_uri, g.zeromq_server_cert, g.zeromq_client_cert, g.jsonout_output, g.alerts_log, g.update_check, g.memory_size
        ),
        format!("white {:?} {:?}", g.white_list, g.hostname_white_list.iter().map(|m| m.patterns().iter().map(|p| p.to_vec()).collect::<Vec<_>>()).collect::<Vec<_>>()),
        format!("custom {:?} forward {:?}", g.custom_alert_output, g.forward_to),
        format!("rotate {} {} {} {}", g.rotate_interval, g.min_rotate_interval, g.max_output_size, g.queue_size),
        format!("eps {} {} {}", g.eps_maximum, g.eps_timeframe, g.eps_maximum_found),
        format!("disc {} {} {:?} {:?} {:?}", g.agents_disconnection_time, g.agents_disconnection_alert_time, g.cti_url, g.geoip_db_path, g.geoip6_db_path),
        format!("sk {} {} {} {} {:?}", g.syscheck_auto_ignore, g.syscheck_ignore_frequency, g.syscheck_ignore_time, g.syscheck_alert_new, g.syscheck_ignore),
        format!("levels {} {} cluster {:?} {:?} {:?} {} labels {} {} ar {}", g.mailbylevel, g.logbylevel, g.cluster_name, g.node_name, g.node_type, g.hide_cluster_info, g.label_cache_maxage, g.show_hidden_labels, g.ar),
        format!("ruleset {:?} {:?} {:?} {:?} {:?}", c.ruleset.decoders, c.ruleset.rules, c.ruleset.lists, c.ruleset.email_level, c.ruleset.log_level),
        format!("cl {:?} {:?} {:?} {}", c.cluster.name, c.cluster.node_name, c.cluster.node_type, c.cluster.hidden),
    ];
    for x in &c.labels {
        l.push(format!("label {:?} {:?} {} {}", x.key, x.value, x.hidden, x.system));
    }
    for s in &c.sockets {
        l.push(format!("socket {:?} {:?} {} {:?}", s.name, s.location, s.tcp, s.prefix));
    }
    for x in &c.ar.commands {
        l.push(format!("cmd {:?} {:?} {} {:?}", x.name, x.executable, x.timeout_allowed, x.extra_args));
    }
    for r in &c.ar.responses {
        l.push(format!("resp {:?} {:?} {} {} {} {} {:?} {:?} {:?}", r.name, r.command, r.command_index, r.location, r.level, r.timeout, r.agent_id, r.rules_id, r.rules_group));
    }
    l.push(format!("arflag {} conf {:?} notes {:?}", c.ar.flags, c.ar.ar_conf, c.ar.notes));
    l.push(format!("logtest {} {} {} {}", c.logtest.enabled, c.logtest.threads, c.logtest.max_sessions, c.logtest.session_timeout));
    let i = &c.internal;
    l.push(format!(
        "internal {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {}",
        i.debug, i.decoder_order_size, i.log_fw, i.label_cache_maxage, i.show_hidden_labels, i.min_rotate_interval, i.default_timeframe, i.fts_list_size, i.fts_min_size_for_str,
        i.rule_matching_threads, i.stats_maxdiff, i.stats_mindiff, i.stats_percent_diff, i.rlimit_nofile, i.state_interval, i.event_threads, i.geoip_jsonout
    ));
    l.push(format!("threads {:?}", i.decoder_threads));
    l.push(format!("queues {:?}", i.queues));
    l.push(format!("warnings {:?}", c.warnings));
    l
}

const GLOBAL: &[(&str, &[&str])] = &[
    ("logall", &["yes", "no", "maybe"]),
    ("logall_json", &["yes", "no"]),
    ("jsonout_output", &["yes", "no", ""]),
    ("alerts_log", &["yes", "no"]),
    ("email_notification", &["yes", "no", "x"]),
    ("prelude_output", &["yes", "no"]),
    ("prelude_profile", &["p"]),
    ("prelude_log_level", &["3", "x", "300"]),
    ("zeromq_output", &["yes", "no"]),
    ("zeromq_uri", &["tcp://x"]),
    ("zeromq_server_cert", &["a"]),
    ("zeromq_client_cert", &["b"]),
    ("update_check", &["yes", "no", "1"]),
    ("compress_alerts", &["anything"]),
    ("integrity_checking", &["8", "x", "999"]),
    ("rootkit_detection", &["8", "-1"]),
    ("host_information", &["8"]),
    ("stats", &["4", "12", "a"]),
    ("memory_size", &["128", "9000", "x", "99999999999"]),
    ("white_list", &["127.0.0.1", "10.0.0.0/8", "!192.168.1.1", "999.1.1.1", "localhost", "^host$", "::1", "1.2.3.4/33", "a|b", "1.2.3.4/255.255.255.0"]),
    ("email_to", &["a@b.c", "nobody", "@x"]),
    ("email_from", &["a@b"]),
    ("email_maxperhour", &["0", "x"]),
    ("email_log_source", &["alerts.log", "1"]),
    ("smtp_server", &["smtp"]),
    ("custom_alert_output", &["$TIMESTAMP $HOSTNAME", ""]),
    ("forward_to", &["a, b ,c", "x", ""]),
    ("geoipdb", &["/g"]),
    ("geoip_db_path", &["/a"]),
    ("geoip6_db_path", &["/b"]),
    ("rotate_interval", &["0", "10", "1d", "2h", "30m", "100s", "5x", "x", "-5", "99999999999d", "86401", "9"]),
    ("max_output_size", &["0", "1G", "2M", "500k", "1000b", "5x", "x", "999", "2T", "1200000"]),
    ("queue_size", &["131072", "0", "-1", "10x", "", "99999999999999999999"]),
    ("agents_disconnection_time", &["10m", "0", "1w", "x", "-1"]),
    ("agents_disconnection_alert_time", &["0", "1h", "x", "-1"]),
    ("cti-url", &["https://example", ""]),
    ("unknown_option", &["1"]),
];

fn global(r: &mut Rng) -> String {
    let mut s = String::from("<global>");
    for _ in 0..1 + r.below(5) {
        let (k, vals) = GLOBAL[r.below(GLOBAL.len() - if r.1 { 1 } else { 0 })];
        s.push_str(&format!("<{k}>{}</{k}>", r.pick(vals)));
    }
    if r.one_in(5) {
        let eps = format!("<eps>{}{}{}</eps>", r.pick(&["", "<maximum>100</maximum>", "<maximum>x</maximum>", "<maximum>100001</maximum>"]), r.pick(&["", "<timeframe>5</timeframe>", "<timeframe>0</timeframe>", "<timeframe>3601</timeframe>"]), r.pick(&["", "<other>1</other>"]));
        s.push_str(&format!("<limits>{}</limits>", r.pick(&[&eps, "<eps/>", "<x>1</x>", ""])));
    }
    s.push_str("</global>");
    s
}

fn syscheck(r: &mut Rng) -> String {
    let opts = [
        format!("<auto_ignore{}>{}</auto_ignore>", r.pick(&["", " frequency=\"10\"", " frequency=\"x\"", " frequency=\"100\"", " frequency=\"5\" timeframe=\"3600\"", " timeframe=\"60\" frequency=\"20\"", " timeframe=\"x\"", " timeframe=\"50000\"", " other=\"1\""]), r.pick(&["yes", "no", "x"])),
        format!("<alert_new_files>{}</alert_new_files>", r.pick(&["yes", "no", "x"])),
        format!("<ignore>{}</ignore>", r.pick(&["/etc/x", ""])),
        "<directories>/etc</directories>".to_string(),
    ];
    format!("<syscheck>{}{}</syscheck>", opts[r.below(4)], opts[r.below(4)])
}

fn cluster(r: &mut Rng) -> String {
    let opts = [
        format!("<name>{}</name>", r.pick(&["provigil", "", "a b", "x;y"])),
        format!("<node_name>{}</node_name>", r.pick(&["node01", "", "n@"])),
        format!("<node_type>{}</node_type>", r.pick(&["master", "worker", "client", "", "boss"])),
        format!("<disabled>{}</disabled>", r.pick(&["yes", "no", "x"])),
        format!("<hidden>{}</hidden>", r.pick(&["yes", "no", "x"])),
        "<interval>2m</interval>".to_string(),
        "<key>k</key><port>1516</port><nodes><node>a</node></nodes>".to_string(),
        format!("<haproxy_helper>{}{}</haproxy_helper>", r.pick(&["", "text"]), r.pick(&["<haproxy_disabled>x</haproxy_disabled>", "<haproxy_protocol>ftp</haproxy_protocol>", "<haproxy_address>a</haproxy_address>", "<frequency>1</frequency>", "<bad>1</bad>"])),
        "<bad>1</bad>".to_string(),
    ];
    let n = 1 + r.below(4);
    format!("<cluster>{}</cluster>", (0..n).map(|_| opts[r.below(opts.len())].clone()).collect::<String>())
}

fn socket(r: &mut Rng) -> String {
    let mut s = String::from("<socket>");
    if !r.bad(6) {
        s.push_str(&format!("<name>{}</name>", r.pick(&["s1", "agent", ""])));
    }
    if !r.bad(6) {
        s.push_str(&format!("<location>{}</location>", r.pick(&["/tmp/s", ""])));
    }
    if r.one_in(2) {
        s.push_str(&format!("<mode>{}</mode>", r.pick(&["tcp", "UDP", "x"])));
    }
    if r.one_in(2) {
        s.push_str(&format!("<prefix>{}</prefix>", r.pick(&["a\\;b", "p:", "x\\"])));
    }
    if r.bad(8) {
        s.push_str("<bad>1</bad>");
    }
    s + "</socket>"
}

fn labels(r: &mut Rng) -> String {
    let mut s = String::from("<labels>");
    for _ in 0..1 + r.below(3) {
        let attrs = r.pick(&[" key=\"a\"", " key=\"b\" hidden=\"yes\"", " key=\"_x\"", " key=\"\"", "", " key=\"a\" hidden=\"x\"", " hidden=\"no\" key=\"c\""]);
        s.push_str(&format!("<{} {attrs}>{}</{0}>", r.pick(&["label", "label", "label", "lbl"]), r.pick(&["v", "", "w"])));
    }
    s + "</labels>"
}

fn command(r: &mut Rng) -> String {
    let mut s = String::from("<command>");
    if !r.bad(8) {
        s.push_str(&format!("<name>{}</name>", r.pick(&["fw", "host-deny", "!bad", "net"])));
    }
    if !r.bad(8) {
        s.push_str(&format!("<executable>{}</executable>", r.pick(&["fw.cmd", "host-deny"])));
    }
    if r.one_in(2) {
        s.push_str(&format!("<timeout_allowed>{}</timeout_allowed>", r.pick(&["yes", "no", "x"])));
    }
    if r.one_in(4) {
        s.push_str("<expect>srcip</expect>");
    }
    if r.one_in(4) {
        s.push_str("<extra_args>-a</extra_args>");
    }
    if r.bad(12) {
        s.push_str("<bad>1</bad>");
    }
    s + "</command>"
}

fn response(r: &mut Rng) -> String {
    let mut s = String::from("<active-response>");
    if !r.bad(8) {
        s.push_str(&format!("<command>{}</command>", r.pick(&["fw", "host-deny", "missing", ""])));
    }
    if !r.bad(8) {
        s.push_str(&format!("<location>{}</location>", r.pick(&["local", "server", "all", "defined-agent", "AS", "nowhere", "any", ""])));
    }
    let extras = [
        format!("<level>{}</level>", r.pick(&["5", "21", "x"])),
        format!("<timeout>{}</timeout>", r.pick(&["600", "0", "x"])),
        format!("<agent_id>{}</agent_id>", r.pick(&["001", "0", "x"])),
        "<rules_id>100,200</rules_id>".to_string(),
        "<rules_group>web</rules_group>".to_string(),
        format!("<disabled>{}</disabled>", r.pick(&["yes", "no", "x"])),
        "<repeated_offenders>1,5</repeated_offenders>".to_string(),
        "<ca_store>x</ca_store>".to_string(),
        "<bad>1</bad>".to_string(),
    ];
    for _ in 0..r.below(4) {
        let cut = if r.bad(10) { 0 } else { 1 };
        let e = &extras[r.below(extras.len() - cut)];
        s.push_str(e);
    }
    s + "</active-response>"
}

fn rule_test(r: &mut Rng) -> String {
    let opts = [
        format!("<enabled>{}</enabled>", r.pick(&["yes", "no", "x"])),
        format!("<threads>{}</threads>", r.pick(&["auto", "1", "200", "x", "70000", ""])),
        format!("<max_sessions>{}</max_sessions>", r.pick(&["64", "600", "-1"])),
        format!("<session_timeout>{}</session_timeout>", r.pick(&["15m", "0", "2w", "x", "400d"])),
        "<bad>1</bad>".to_string(),
    ];
    format!("<rule_test>{}{}</rule_test>", opts[r.below(opts.len())], opts[r.below(4)])
}

fn ruleset(r: &mut Rng) -> String {
    let opts = [
        format!("<decoder_dir{}>{}</decoder_dir>", r.pick(&["", " pattern=\"_a\\.xml$\"", " pattern=\"(\"", " other=\"x\"", " pattern=\"a\" PATTERN=\"b.xml$\""]), r.pick(&["ruleset/decoders", "etc/decoders", "missing"])),
        format!("<rule_dir{}>{}</rule_dir>", r.pick(&["", " pattern=\"^etc\"", " var=\"1\""]), r.pick(&["ruleset/rules", "etc/rules"])),
        format!("<rule_include>{}</rule_include>", r.pick(&["x.xml", "etc/rules/a.xml"])),
        format!("<decoder_include>{}</decoder_include>", r.pick(&["y.xml", "a/b.xml"])),
        format!("<rule_exclude>{}</rule_exclude>", r.pick(&["0010-a_rules.xml", "ruleset/rules/0020-b_rules.xml"])),
        format!("<decoder_exclude>{}</decoder_exclude>", r.pick(&["0005-x_decoders.xml"])),
        format!("<list>{}</list>", r.pick(&["etc/lists/l1", "etc/lists/l2"])),
        "<bad>1</bad>".to_string(),
    ];
    let n = r.below(5);
    format!("<ruleset>{}</ruleset>", (0..n).map(|_| { let cut = if r.bad(10) { 0 } else { 1 }; opts[r.below(opts.len() - cut)].clone() }).collect::<String>())
}

fn alerts(r: &mut Rng) -> String {
    format!("<alerts><log_alert_level>{}</log_alert_level><email_alert_level>{}</email_alert_level><other>1</other></alerts>", r.pick(&["3", "x", "300"]), r.pick(&["12", "7"]))
}

fn others(r: &mut Rng) -> String {
    if r.1 {
        return ["<remote><connection>secure</connection></remote>", "<sca/>", "<logging/>", "<rootcheck/>", "<client_buffer/>"][r.below(5)].to_string();
    }
    r.pick(&[
        "<remote><connection>secure</connection></remote>",
        "<localfile><log_format>syslog</log_format></localfile>",
        "<wodle name=\"x\"><disabled>yes</disabled></wodle>",
        "<sca/>",
        "<logging/>",
        "<rootcheck/>",
        "<database_output><x>1</x></database_output>",
        "<global/>",
        "<labels/>",
        "<unknown><x>1</x></unknown>",
        "<vulnerability-detector><x>1</x></vulnerability-detector>",
        "<auth><x>1</x></auth>",
        "<client_buffer/>",
        "<email_alerts><x>1</x></email_alerts>",
    ])
    .to_string()
}

fn document(r: &mut Rng) -> String {
    let mut out = String::new();
    for _ in 0..1 + r.below(2) {
        let mut b = String::from("<ossec_config>\n");
        for _ in 0..r.below(7) {
            let s = match if r.1 && r.below(3) == 0 { 5 } else { r.below(12) } {
                0 => global(r),
                1 => syscheck(r),
                2 => cluster(r),
                3 => socket(r),
                4 => labels(r),
                5 | 6 => command(r),
                7 => response(r),
                8 => rule_test(r),
                9 => ruleset(r),
                10 => alerts(r),
                _ => others(r),
            };
            b.push_str(&s);
            b.push('\n');
        }
        b.push_str("</ossec_config>\n");
        out.push_str(&b);
    }
    if r.bad(30) {
        out.push_str("<other_root><x>1</x></other_root>");
    }
    if r.bad(40) {
        out.push_str("<broken>");
    }
    out
}

const ANALYSISD_OPTIONS: &[(&str, &[&str])] = &[
    ("debug", &["0", "3", "x", "", " 1"]),
    ("decoder_order_size", &["256", "31"]),
    ("min_rotate_interval", &["600", "5"]),
    ("label_cache_maxage", &["10", "61"]),
    ("rlimit_nofile", &["458752", "1"]),
    ("syscheck_threads", &["0", "33"]),
    ("winevt_threads", &["4"]),
    ("alerts_queue_size", &["16384", "100", "3000000"]),
    ("upgrade_queue_size", &["16384", "127"]),
];

fn setup(home: &Path) {
    let etc = home.join("etc");
    std::fs::create_dir_all(etc.join("shared")).unwrap();
    for d in ["ruleset/rules", "ruleset/decoders", "etc/rules", "etc/decoders"] {
        std::fs::create_dir_all(home.join(d)).unwrap();
    }
    for f in ["ruleset/rules/0010-a_rules.xml", "ruleset/rules/0020-b_rules.xml", "ruleset/rules/readme.txt", "etc/rules/local_rules.xml", "etc/rules/0010-a_rules.xml"] {
        std::fs::write(home.join(f), "").unwrap();
    }
    for f in ["ruleset/decoders/0005-x_decoders.xml", "ruleset/decoders/0010-y_decoders.xml", "ruleset/decoders/_a.xml", "etc/decoders/local_decoder.xml"] {
        std::fs::write(home.join(f), "").unwrap();
    }
}

fn base_options() -> String {
    let p = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../data/manager/etc/internal_options.conf");
    std::fs::read_to_string(p).expect("the shipped internal options")
}

#[test]
fn generated_settings() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path();
    setup(home);
    let base = base_options();
    let conf = home.join("etc/ossec.conf");
    let mut r = Rng(0x2545F4914F6CDD1D, false);
    let (mut ok, mut failed) = (0, 0);
    let mut why = std::collections::BTreeMap::<String, usize>::new();
    for round in 0..6000 {
        r.1 = round % 2 == 0;
        let mut local = String::new();
        if r.one_in(5) {
            let (k, vals) = ANALYSISD_OPTIONS[r.below(ANALYSISD_OPTIONS.len())];
            local.push_str(&format!("analysisd.{k}{}={}\r\n", r.pick(&["", " "]), r.pick(vals)));
        }
        std::fs::write(home.join("etc/local_internal_options.conf"), &local).unwrap();
        std::fs::write(home.join("etc/internal_options.conf"), &base).unwrap();
        let doc = document(&mut r);
        std::fs::write(&conf, &doc).unwrap();
        let write = round % 7 == 0;
        let oc = AnalysisdConfig::load(home, &conf, write);
        let old_ar = std::fs::read(home.join("etc/shared/ar.conf")).ok();
        let _ = std::fs::remove_file(home.join("etc/shared/ar.conf"));
        let nc = Config::load(home, &conf, write);
        if let (Ok(x), Ok(y)) = (&oc, &nc) {
            use provigil_analysisd::getconfig as ng;
            use siem_analysisd::config_json as og;
            for (a, b) in [
                (og::global(x), ng::global(y)),
                (og::active_response(x), ng::active_response(y)),
                (og::commands(x), ng::commands(y)),
                (og::alerts(x), ng::alerts(y)),
                (og::internal(x), ng::internal(y)),
                (og::labels(x), ng::labels(y)),
                (og::rule_test(x), ng::rule_test(y)),
            ] {
                assert_eq!(String::from_utf8_lossy(&a.print_unformatted()), String::from_utf8_lossy(&b.print_unformatted()), "getconfig of {doc}");
            }
        }
        let old = oc.map(|c| old_lines(&c)).map_err(|e| e.0);
        let new = nc.map(|c| new_lines(&c));
        let new_ar = std::fs::read(home.join("etc/shared/ar.conf")).ok();
        let _ = std::fs::remove_file(home.join("etc/shared/ar.conf"));
        assert_eq!(old_ar, new_ar, "ar.conf for {doc}\n{local}");
        match (&old, &new) {
            (Ok(a), Ok(b)) => {
                ok += 1;
                for (x, y) in a.iter().zip(b) {
                    assert_eq!(x, y, "document:\n{doc}\n{local}");
                }
                assert_eq!(a.len(), b.len(), "document:\n{doc}");
            }
            (Err(a), Err(b)) => {
                failed += 1;
                *why.entry(a.chars().take(40).collect()).or_default() += 1;
                assert_eq!(a, b, "document:\n{doc}\n{local}");
            }
            _ => panic!("document:\n{doc}\n{local}\n old: {old:?}\n new: {new:?}"),
        }
    }
    // both kinds must be well represented
    let mut top: Vec<_> = why.into_iter().collect();
    top.sort_by_key(|(_, n)| std::cmp::Reverse(*n));
    top.truncate(8);
    assert!(ok > 1500 && failed > 1500, "ok {ok} failed {failed} {top:?}");
}

/// The shipped manager settings and ruleset folders (read only).
#[test]
fn shipped_settings() {
    let home = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../data/manager");
    let conf = home.join("etc/ossec.conf");
    let old = AnalysisdConfig::load(&home, &conf, false).map(|c| old_lines(&c)).map_err(|e| e.0);
    let new = Config::load(&home, &conf, false).map(|c| new_lines(&c));
    assert_eq!(old, new);
    let lines = new.unwrap();
    assert!(lines.iter().any(|l| l.starts_with("ruleset [\"")), "the shipped ruleset lists files: {lines:?}");
}

/// getconfig of the shipped decoders and rules.
#[test]
fn shipped_decoders_and_rules_config() {
    let home = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../data/manager");
    let cfg = Config::load(&home, &home.join("etc/ossec.conf"), false).unwrap();
    let mut o = siem_analysisd::engine::Engine::new(siem_analysisd::engine::EngineConfig { rule: siem_analysisd::rules::RuleConfig { home: home.clone(), ..Default::default() }, ..Default::default() });
    let mut n = provigil_analysisd::engine::Engine::new(provigil_analysisd::engine::EngineSettings { rules: provigil_analysisd::rules::RuleSettings { home: home.clone(), ..Default::default() }, ..Default::default() });
    let (mut a, mut b) = (siem_analysisd::logmsg::LogList::default(), provigil_analysisd::messages::Messages::default());
    assert!(o.load_ruleset(&cfg.ruleset.decoders, &cfg.ruleset.lists, &cfg.ruleset.rules, None, &mut a));
    assert!(n.load_ruleset(&cfg.ruleset.decoders, &cfg.ruleset.lists, &cfg.ruleset.rules, None, &mut b));
    for order in [256, 0, 5] {
        assert_eq!(siem_analysisd::config_json::decoders(&o.decoders, order).print_unformatted(), provigil_analysisd::getconfig::decoders(&n.decoders, order).print_unformatted());
    }
    assert_eq!(siem_analysisd::config_json::rules(&o.rules).print_unformatted(), provigil_analysisd::getconfig::rules(&n.rules).print_unformatted());
}
