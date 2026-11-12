//! `wazuh_modules/wm_sca.c` (the module: scans, events, the results
//! database and the dump requests) and `config/wmodules-sca.c` (its
//! configuration).

use std::collections::HashMap;
use std::sync::mpsc::{sync_channel, Receiver, SyncSender, TrySendError};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use parking_lot::Mutex;
use sha2::{Digest, Sha256};
use siem_cjson::Json;
use siem_log::WLog;
use siem_regex::ExpType;
use siem_xml::{OsXml, XmlNode};

use crate::check::{cat, get_pattern, msg1024, Engine, RETURN_FOUND, RETURN_INVALID, RETURN_NOT_FOUND, TAG};
use crate::sched::{is_sched_tag, SchedScan};
use crate::{crt, yaml};

/// `SCA_WM_NAME`
pub const NAME: &str = "sca";
/// `WM_SCA_STAMP`
pub const WM_SCA_STAMP: &str = "sca";
/// `SCA_MQ`
pub const SCA_MQ: u8 = b'p';
/// `WM_CONFIGURATION_ASSESSMENT_DB_DUMP`
pub const DB_DUMP: &str = "sca-dump";

/// `SECURITY_CONFIGURATION_ASSESSMENT_DIR(_WIN)` + separator
#[cfg(windows)]
const RULESET_PATH: &str = "ruleset\\sca\\";
#[cfg(unix)]
const RULESET_PATH: &str = "ruleset/sca/";
#[cfg(windows)]
const PATH_MAX: usize = 260;
#[cfg(unix)]
const PATH_MAX: usize = 4096;

const WM_SCA_COND_ALL: i32 = 0x001;
const WM_SCA_COND_ANY: i32 = 0x002;
const WM_SCA_COND_NON: i32 = 0x008;
const WM_SCA_COND_INV: i32 = 0x010;

const OLD_POLICIES: [&str; 24] = [
    "acsc_office2016_rcl.yml",
    "cis_apache2224_rcl.yml",
    "cis_debian_linux_rcl.yml",
    "cis_debianlinux7-8_L1_rcl.yml",
    "cis_debianlinux7-8_L2_rcl.yml",
    "cis_mysql5-6_community_rcl.yml",
    "cis_mysql5-6_enterprise_rcl.yml",
    "cis_rhel5_linux_rcl.yml",
    "cis_rhel6_linux_rcl.yml",
    "cis_rhel7_linux_rcl.yml",
    "cis_sles11_linux_rcl.yml",
    "cis_sles12_linux_rcl.yml",
    "cis_solaris11_rcl.yml",
    "cis_win10_enterprise_L1_rcl.yml",
    "cis_win10_enterprise_L2_rcl.yml",
    "cis_win2012r2_domainL1_rcl.yml",
    "cis_win2012r2_domainL2_rcl.yml",
    "cis_win2012r2_memberL1_rcl.yml",
    "cis_win2012r2_memberL2_rcl.yml",
    "system_audit_pw.yml",
    "system_audit_rcl_mac.yml",
    "system_audit_rcl.yml",
    "system_audit_ssh.yml",
    "win_audit_rcl.yml",
];

/// `wm_sca_policy_t`
#[derive(Clone, Debug)]
pub struct Policy {
    pub enabled: bool,
    pub remote: bool,
    pub path: String,
}

/// `wm_sca_t` (the configuration part)
#[derive(Clone, Debug)]
pub struct WmSca {
    pub enabled: bool,
    pub scan_on_start: bool,
    pub skip_nfs: bool,
    pub policies: Vec<Policy>,
    pub scan_config: SchedScan,
}

impl Default for WmSca {
    fn default() -> Self {
        WmSca { enabled: true, scan_on_start: true, skip_nfs: true, policies: Vec::new(), scan_config: SchedScan::default() }
    }
}

/// `GetFullPathName` / `realpath`: None when it fails.
fn full_path(p: &str) -> Option<String> {
    #[cfg(windows)]
    {
        let c = crt::cstring(p.as_bytes());
        let mut buf = [0u8; PATH_MAX];
        // SAFETY: the C buffer and its size.
        let n = unsafe { windows_sys::Win32::Storage::FileSystem::GetFullPathNameA(c.as_ptr() as *const u8, PATH_MAX as u32, buf.as_mut_ptr(), std::ptr::null_mut()) };
        (n != 0).then(|| String::from_utf8_lossy(crate::check::cs(&buf)).into_owned())
    }
    #[cfg(unix)]
    std::fs::canonicalize(p).ok().map(|x| x.to_string_lossy().into_owned())
}

/// `IsFile`: true when it is a regular file.
fn is_file(p: &str) -> bool {
    matches!(crt::stat_mode(p.as_bytes()), Ok(m) if m & crt::S_IFMT == crt::S_IFREG)
}

/// `wm_sca_read`: one `<sca>` block (or None for no children).
pub fn wm_sca_read(log: &WLog, xml: &OsXml, nodes: Option<&[XmlNode]>, sca: &mut WmSca) -> Result<(), ()> {
    let info = |m: String| log.tagged(TAG, "INFO", m);
    let warn = |m: String| log.tagged(TAG, "WARNING", m);
    let error = |m: String| log.tagged(TAG, "ERROR", m);
    // every ruleset policy by default
    match crt::read_dir(RULESET_PATH.as_bytes()) {
        Ok(names) => {
            for n in names {
                let name = String::from_utf8_lossy(&n).into_owned();
                if name == "." || name == ".." {
                    continue;
                }
                match name.rfind('.') {
                    Some(i) if &name[i..] == ".yml" || &name[i..] == ".yaml" => {}
                    _ => continue,
                }
                let mut rel = format!("{RULESET_PATH}{name}");
                rel.truncate(PATH_MAX - 1);
                let Some(real) = full_path(&rel) else {
                    warn(format!("File '{name}' not found."));
                    continue;
                };
                if sca.policies.iter().any(|p| p.path == real) {
                    continue;
                }
                sca.policies.push(Policy { enabled: true, remote: false, path: real });
            }
        }
        Err(e) => info(format!("Could not open the default SCA ruleset folder '{RULESET_PATH}': {}", crt::strerror(e))),
    }
    let Some(nodes) = nodes else { return Ok(()) };
    let eval_bool = |c: Option<&str>| match c {
        Some("yes") => Some(true),
        Some("no") => Some(false),
        _ => None,
    };
    for n in nodes {
        match n.element.as_str() {
            "" => {
                error("(1231): Invalid NULL element in the configuration.".into());
                return Err(());
            }
            "enabled" => match eval_bool(n.content.as_deref()) {
                Some(b) => sca.enabled = b,
                None => {
                    error("Invalid content for tag 'enabled'".into());
                    return Err(());
                }
            },
            "scan_on_start" => match eval_bool(n.content.as_deref()) {
                Some(b) => sca.scan_on_start = b,
                None => {
                    error("Invalid content for tag 'enabled'".into());
                    return Err(());
                }
            },
            "policies" => {
                let Some(children) = xml.get_elements_by_node(Some(n)) else {
                    return Err(());
                };
                for c in &children {
                    if c.element != "policy" {
                        error("(1231): Invalid NULL element in the configuration.".into());
                        return Err(());
                    }
                    let enabled = !(c.attributes.first().map(|a| a == "enabled").unwrap_or(false) && c.values.first().map(|v| v == "no").unwrap_or(false));
                    let content = c.content.clone().unwrap_or_default();
                    if content.len() >= PATH_MAX {
                        error(format!("Policy path is too long. Max path length is {PATH_MAX}."));
                        return Err(());
                    } else if content.is_empty() {
                        error("Empty policy value.".into());
                        return Err(());
                    }
                    // find_string_in_array: strncmp(content, old, strlen(content))
                    if OLD_POLICIES.iter().any(|o| o.len() >= content.len() && o.as_bytes()[..content.len()] == *content.as_bytes()) {
                        continue;
                    }
                    let Some(real) = full_path(&content) else {
                        warn(format!("File '{content}' not found."));
                        continue;
                    };
                    #[cfg(windows)]
                    if siem_fileop::crt::is_network_path(&real) {
                        warn(format!("(9801): Network path not allowed in configuration. 'policy': {real}."));
                        continue;
                    }
                    let mut found = false;
                    if let Some(p) = sca.policies.iter_mut().find(|p| p.path == real) {
                        p.enabled = enabled;
                        found = true;
                    }
                    if !is_file(&real) {
                        warn(format!("Policy file '{real}' not found. Check your configuration."));
                        continue;
                    }
                    if !found {
                        #[cfg(windows)]
                        let remote = real.contains("shared\\");
                        #[cfg(unix)]
                        let remote = real.contains("etc/shared/");
                        sca.policies.push(Policy { enabled, remote, path: real });
                    }
                }
            }
            "skip_nfs" => match eval_bool(n.content.as_deref()) {
                Some(b) => sca.skip_nfs = b,
                None => {
                    error("Invalid content for tag 'skip_nfs'".into());
                    return Err(());
                }
            },
            t if is_sched_tag(t) => {}
            t => {
                error(format!("No such tag '{t}' at module '{NAME}'."));
                return Err(());
            }
        }
    }
    sca.scan_config.read(log, nodes, NAME)
}

/// `wm_sca_dump`
pub fn wm_sca_dump(sca: &WmSca) -> Json {
    let mut wd = Json::object();
    sca.scan_config.dump(&mut wd);
    let yn = |b: bool| Json::string(if b { "yes" } else { "no" });
    wd.add("enabled", yn(sca.enabled));
    wd.add("scan_on_start", yn(sca.scan_on_start));
    wd.add("skip_nfs", yn(sca.skip_nfs));
    if !sca.policies.is_empty() {
        let mut arr = Json::array();
        for p in sca.policies.iter().filter(|p| p.enabled) {
            arr.push(Json::string(&p.path));
        }
        wd.add("policies", arr);
    }
    let mut root = Json::object();
    root.add("sca", wd);
    root
}

/// What the module needs from its process.
pub struct Env {
    pub log: Arc<WLog>,
    /// `SendMSG(queue, msg, WM_SCA_STAMP, SCA_MQ)`: < 0 on error.
    pub send: Box<dyn Fn(&[u8]) -> i32 + Send + Sync>,
    /// `getDefine_Int(section, name, min, max)`
    pub define_int: Box<dyn Fn(&str, &str, i32, i32) -> i32 + Send + Sync>,
    /// `wm_max_eps`
    pub max_eps: i32,
    /// `CLIENT` build (an agent): `sca.remote_commands` is read.
    pub client: bool,
}

/// `cis_db_info_t`
struct Elem {
    id: i32,
    result: String,
    event: Json,
}

/// One policy's results: `cis_db[i]`, `cis_db_for_hash[i]` (a NULL-ended
/// array), `last_sha256[i]` and `last_summary_json[i]`.
#[derive(Default)]
struct PolicyDb {
    db: HashMap<String, Arc<Elem>>,
    for_hash: Vec<Option<Arc<Elem>>>,
    last_sha256: String,
    last_summary: Option<Json>,
}

impl PolicyDb {
    /// The elements before the first NULL.
    fn prefix(&self) -> usize {
        self.for_hash.iter().position(|e| e.is_none()).unwrap_or(self.for_hash.len())
    }
}

/// The options `wm_sca_main` reads, and the request queue.
struct Rt {
    msg_delay: i32,
    summary_delay: u32,
    request_db_interval: u32,
    remote_commands: bool,
    commands_timeout: u32,
    requests: SyncSender<(usize, i32)>,
}

/// The module: configuration, process services and the C statics.
pub struct Sca {
    pub cfg: WmSca,
    env: Env,
    /// `policies[i]->policy_id` (set by the first scan of each policy)
    ids: Mutex<Vec<Option<String>>>,
    /// The results, under `dump_rwlock`.
    db: Mutex<Vec<PolicyDb>>,
    rt: OnceLock<Rt>,
}

/// `os_random()` (`randombytes(int) % RAND_MAX`)
fn os_random() -> i32 {
    use std::hash::{BuildHasher, Hasher};
    let r = std::collections::hash_map::RandomState::new().build_hasher().finish() as u32 as i32;
    #[cfg(windows)]
    const RAND_MAX: i32 = 0x7fff;
    #[cfg(unix)]
    const RAND_MAX: i32 = 0x7fffffff;
    r % RAND_MAX
}

/// The scan id: Windows `atoi("%u%u")` of two `os_random()`, Unix one; made positive.
fn scan_random() -> i32 {
    #[cfg(windows)]
    let id = crt::atoi(format!("{}{}", os_random() as u32, os_random() as u32).as_bytes());
    #[cfg(unix)]
    let id = os_random();
    if id < 0 {
        id.wrapping_neg()
    } else {
        id
    }
}

/// `wm_strcat(&s, add, sep)`
fn strcat(s: &mut Option<Vec<u8>>, add: &[u8], sep: u8) {
    match s {
        Some(v) => {
            v.push(sep);
            v.extend_from_slice(add);
        }
        None => *s = Some(add.to_vec()),
    }
}

/// `wm_sort_variables`: the names, longest first (the C swap sort).
pub fn sort_variables(variables: Option<&Json>) -> Option<Vec<Vec<u8>>> {
    let Some(Json::Object(m)) = variables else { return None };
    if m.is_empty() {
        return None;
    }
    let mut v: Vec<Vec<u8>> = m.iter().map(|(k, _)| k.clone()).collect();
    for i in 0..v.len() {
        for j in i + 1..v.len() {
            if v[j].len() > v[i].len() {
                v.swap(i, j);
            }
        }
    }
    Some(v)
}

/// `wstr_replace`
fn str_replace(s: &[u8], search: &[u8], replace: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut rest = s;
    while let Some(i) = rest.windows(search.len()).position(|w| w == search) {
        out.extend_from_slice(&rest[..i]);
        out.extend_from_slice(replace);
        rest = &rest[i + search.len()..];
    }
    out.extend_from_slice(rest);
    out
}

/// `wm_sca_get_value`: the rule type and the value after ':'.
fn get_value(buf: &[u8]) -> Option<(i32, &[u8])> {
    let i = buf.iter().position(|&c| c == b':')?;
    let mut t = &buf[..i];
    if t.first() == Some(&b'!') {
        t = &t[1..];
    }
    let ty = match t {
        b"f" => 1,
        b"r" => 2,
        b"p" => 3,
        b"d" => 4,
        b"c" => 5,
        _ => return None,
    };
    Some((ty, &buf[i + 1..]))
}

/// The rule after `ExpandEnvironmentStrings(rule, buf, 2048)` (the 32-bit agent's view).
#[cfg(windows)]
fn expand_rule(rule: &[u8]) -> Vec<u8> {
    use siem_sysinfo::win::enc::{ansi_to_wstring, expand_env_w32, wstring_to_ansi};
    let a = match expand_env_w32(&ansi_to_wstring(rule)) {
        Some(w) => wstring_to_ansi(&w),
        None => Vec::new(),
    };
    // shortcut: a result over 2047 bytes leaves the zeroed buffer (empty) here; Windows' exact
    // partial-buffer behaviour is not reproduced.
    if a.len() >= 2048 {
        Vec::new()
    } else {
        a
    }
}

impl Sca {
    pub fn new(cfg: WmSca, env: Env) -> Arc<Sca> {
        let n = cfg.policies.len();
        Arc::new(Sca { cfg, env, ids: Mutex::new(vec![None; n]), db: Mutex::new((0..n).map(|_| PolicyDb::default()).collect()), rt: OnceLock::new() })
    }

    fn info(&self, m: impl AsRef<[u8]>) {
        self.env.log.tagged(TAG, "INFO", m);
    }
    fn warn(&self, m: impl AsRef<[u8]>) {
        self.env.log.tagged(TAG, "WARNING", m);
    }
    fn error(&self, m: impl AsRef<[u8]>) {
        self.env.log.tagged(TAG, "ERROR", m);
    }
    fn d1(&self, m: impl AsRef<[u8]>) {
        self.env.log.tagged(TAG, "DEBUG", m);
    }
    fn d2(&self, m: impl AsRef<[u8]>) {
        self.env.log.tagged(TAG, "DEBUG2", m);
    }

    /// `wm_sca_main`: runs the scans forever (returns when disabled).
    pub fn main(self: &Arc<Self>) {
        if !self.cfg.enabled {
            self.info("Module disabled. Exiting.");
            return;
        }
        self.info("Module started.");
        if self.cfg.policies.is_empty() {
            self.info("No policies defined. Exiting.");
            return;
        }
        let mut scan_config = self.cfg.scan_config.clone();
        let mut request_db_interval = ((self.env.define_int)("sca", "request_db_interval", 1, 60) * 60) as u32;
        let commands_timeout = (self.env.define_int)("sca", "commands_timeout", 1, 300) as u32;
        let remote_commands = if self.env.client { (self.env.define_int)("sca", "remote_commands", 0, 1) != 0 } else { true };
        if request_db_interval > scan_config.interval {
            request_db_interval = scan_config.interval;
            self.info("The request_db_interval option cannot be higher than the scan interval. It will be redefined to that value.");
        }
        for p in &self.cfg.policies {
            if p.enabled {
                self.info(format!("Loaded policy '{}'", p.path));
            } else {
                self.info(format!("Policy '{}' disabled by configuration.", p.path));
            }
        }
        let (tx, rx) = sync_channel(1024);
        let _ = self.rt.set(Rt {
            msg_delay: 1000000 / self.env.max_eps.max(1),
            summary_delay: 3,
            request_db_interval,
            remote_commands,
            commands_timeout,
            requests: tx,
        });
        let me = Arc::clone(self);
        let _ = std::thread::Builder::new().name("wm_sca_dump_db".into()).spawn(move || me.dump_db_thread(rx));
        // wm_sca_start
        let mut first_scan = true;
        loop {
            let time_sleep = scan_config.time_until_next_scan(&self.env.log, TAG, self.cfg.scan_on_start);
            if time_sleep != 0 {
                let next = scan_config.next_scheduled_scan_time as i32 as i64;
                self.d2(format!("Sleeping until: {}", crate::sched::timestamp(next)));
                crate::sched::sleep_until(next);
            }
            self.info("Starting Security Configuration Assessment scan.");
            let start = crt::now();
            self.read_files(&mut first_scan);
            self.send_policies_scanned();
            self.info(format!("Security Configuration Assessment scan finished. Duration: {} seconds.", (crt::now() - start) as i32));
        }
    }

    fn rt(&self) -> &Rt {
        self.rt.get().expect("set by main")
    }

    /// `wm_sca_send_alert`
    fn send_alert(&self, j: &Json) {
        let msg = j.print_unformatted();
        self.d2(cat(&[b"Sending event: ", &msg]));
        std::thread::sleep(Duration::from_millis((self.rt().msg_delay / 1000).max(0) as u64));
        if (self.env.send)(&msg) < 0 {
            let e = crt::errno();
            self.d1(format!("(1210): Queue 'queue/sockets/queue' not accessible: '{}'", crt::strerror(e)));
            // StartMQ succeeds on Windows: the message is sent again
            std::thread::sleep(Duration::from_millis((self.rt().msg_delay / 1000).max(0) as u64));
            if (self.env.send)(&msg) < 0 {
                self.d1(format!("(1210): Queue 'queue/sockets/queue' not accessible: '{}'", crt::strerror(crt::errno())));
            }
        }
    }

    /// `wm_sca_send_policies_scanned`
    fn send_policies_scanned(&self) {
        let mut arr = Json::array();
        let ids = self.ids.lock();
        for (p, id) in self.cfg.policies.iter().zip(ids.iter()) {
            if let (true, Some(id)) = (p.enabled, id) {
                arr.push(Json::string(id));
            }
        }
        drop(ids);
        let mut o = Json::object();
        o.add("type", Json::string("policies"));
        o.add("policies", arr);
        self.d2("Sending scanned policies.");
        self.send_alert(&o);
    }

    /// `wm_sca_read_files`
    fn read_files(&self, first_scan: &mut bool) {
        let mut check_list: HashMap<Vec<u8>, Vec<u8>> = HashMap::new();
        for (i, p) in self.cfg.policies.iter().enumerate() {
            if !p.enabled {
                continue;
            }
            self.read_policy(i, p, &mut check_list, *first_scan);
        }
        *first_scan = false;
    }

    /// One policy of `wm_sca_read_files` (the body before `next:`).
    fn read_policy(&self, i: usize, p: &Policy, check_list: &mut HashMap<Vec<u8>, Vec<u8>>, first_scan: bool) {
        let path = &p.path;
        // wfopen(path, "r")
        #[cfg(windows)]
        let opened = !siem_fileop::crt::is_network_path(path) && std::fs::File::open(path).is_ok();
        #[cfg(unix)]
        let opened = std::fs::File::open(path).is_ok();
        if !opened {
            #[cfg(windows)]
            if siem_fileop::crt::is_network_path(path) {
                self.env.log.warn(siem_fileop::crt::network_path_executed(path));
            }
            self.warn(format!("Policy file not found: '{path}'. Skipping it."));
            return;
        }
        let mut ywarn = |m: String| self.env.log.warn(m);
        let Some(mut doc) = yaml::parse_file(path, &mut ywarn) else {
            self.warn(format!("Error found while parsing file: '{path}'. Skipping it."));
            return;
        };
        let Some(object) = doc.to_json(true, &mut ywarn) else {
            self.warn(format!("Error found while transforming yaml to json: '{path}'. Skipping it."));
            return;
        };
        drop(doc);
        let policy = object.get("policy");
        let variables = object.get("variables");
        let checks = object.get("checks");
        let requirements = object.get("requirements");
        if self.check_policy(policy, checks, check_list) {
            self.warn(format!("Error found while validating policy file: '{path}'. Skipping it."));
            return;
        }
        let (Some(policy), Some(checks)) = (policy, checks) else { return };
        let regex_type = match policy.get("regex_type") {
            Some(t) => t.as_str().map(|s| s.into_owned()).unwrap_or_default(),
            None => siem_regex::expression::OSREGEX_STR.to_string(),
        };
        if let Some(r) = requirements {
            if self.check_requirements(r) {
                self.warn(format!("Error found while reading 'requirements' section of file: '{path}'. Skipping it."));
                return;
            }
        }
        {
            let mut ids = self.ids.lock();
            if ids[i].is_none() {
                ids[i] = policy.get("id").and_then(|v| v.as_str()).map(|s| s.into_owned());
            }
        }
        let sorted_variables = sort_variables(variables);
        // wm_sca_get_vars: the first value of each name wins (OSStore_Put)
        let mut vars: HashMap<Vec<u8>, Option<Vec<u8>>> = HashMap::new();
        if let Some(Json::Object(m)) = variables {
            for (k, v) in m {
                if k.first() != Some(&b'$') {
                    self.error(cat(&[b"Invalid variable: '", k, b"'"]));
                    self.warn(format!("Error found while reading the 'variables' section of file: '{path}'. Skipping it."));
                    return;
                }
                vars.entry(k.clone()).or_insert_with(|| v.as_bytes().map(|b| b.to_vec()));
            }
        }
        let id = scan_random();
        self.d1(format!("Calculating hash for policy file '{path}'"));
        let integrity_hash_file = match siem_fileop::crt::read_text(path) {
            Ok(d) => Some(hex(&Sha256::digest(&d))),
            Err(_) => {
                self.error(format!("Unable to calculate SHA256 for file '{path}'"));
                None
            }
        };
        let mut db = self.db.lock();
        let st = &mut db[i];
        if !st.last_sha256.is_empty() {
            if let Some(h) = &integrity_hash_file {
                if *h != st.last_sha256 {
                    st.db.clear();
                    st.for_hash.clear();
                }
            }
        }
        let mut requirements_satisfied = requirements.is_none();
        let mut checks_number = 0;
        let mut summary = [0u32; 3];
        if let Some(r) = requirements {
            let arr = Json::Array(vec![r.clone()]);
            if self.do_scan(&arr, &vars, id, policy, true, st, p.remote, first_scan, &mut checks_number, sorted_variables.as_deref(), &regex_type, &mut summary) == 0 {
                requirements_satisfied = true;
            }
        }
        if requirements_satisfied {
            let time_start = crt::now();
            self.info(format!("Starting evaluation of policy: '{path}'"));
            if self.do_scan(checks, &vars, id, policy, false, st, p.remote, first_scan, &mut checks_number, sorted_variables.as_deref(), &regex_type, &mut summary) != 0 {
                self.error(format!("Error while evaluating the policy '{path}'"));
            }
            self.d1("Calculating hash for scanned results.");
            let integrity_hash = self.hash_integrity(st);
            let time_end = crt::now();
            if let (Some(h), Some(hf)) = (&integrity_hash, &integrity_hash_file) {
                std::thread::sleep(Duration::from_secs(self.rt().summary_delay as u64));
                self.send_summary(st, id, summary, policy, time_start, time_end, h, hf, first_scan, checks_number);
                st.last_sha256 = hf.clone();
            }
            self.info(format!("Evaluation finished for policy '{path}'"));
        } else {
            let title = requirements.and_then(|r| r.get("title")).and_then(|t| t.as_str().map(|s| s.into_owned())).unwrap_or_default();
            self.info(format!("Skipping policy '{path}': '{title}'"));
        }
    }

    /// `wm_sca_check_policy`: true on error.
    fn check_policy(&self, policy: Option<&Json>, checks: Option<&Json>, list: &mut HashMap<Vec<u8>, Vec<u8>>) -> bool {
        let Some(policy) = policy else { return true };
        let Some(id) = policy.get("id") else {
            self.warn("Field 'id' not found in policy header.");
            return true;
        };
        let Some(id) = id.as_bytes() else {
            self.warn("Invalid format for field 'id'");
            return true;
        };
        if let Some(f) = list.get(id) {
            self.warn(cat(&[b"Found duplicated policy ID: ", id, b". File '", f, b"' contains the same ID."]));
            return true;
        }
        for (field, name) in [("name", "name"), ("file", "file")] {
            match policy.get(field) {
                None => {
                    self.warn(format!("Field '{name}' not found in policy header."));
                    return true;
                }
                Some(v) if !v.is_string() => {
                    self.warn(format!("Invalid format for field '{name}'"));
                    return true;
                }
                _ => {}
            }
        }
        let Some(description) = policy.get("description") else {
            self.warn("Field 'description' not found in policy header.");
            return true;
        };
        if policy.get("regex_type").is_none() {
            self.d1("Field 'regex_type' not found in policy header. The OS_REGEX engine shall be used.");
        }
        if !description.is_string() {
            self.warn("Invalid format for field 'description'");
            return true;
        }
        let Some(checks) = checks else {
            self.warn("Section 'checks' not found.");
            return true;
        };
        let mut read_id: Vec<i32> = Vec::new();
        for check in checks.children() {
            let Some(check_id) = check.get("id") else {
                self.warn("Check ID not found.");
                return true;
            };
            let Some(cid) = check_id.as_i32().filter(|_| check_id.is_number()) else {
                self.warn("Invalid check ID type: must be a number.");
                return true;
            };
            if let Some(cp) = list.get(cid.to_string().as_bytes()) {
                self.warn(cat(&[b"Found duplicated check ID: ", cid.to_string().as_bytes(), b". First appearance at policy '", cp, b"'"]));
                return true;
            }
            // read_id is 0-terminated: an id 0 ends the list
            if read_id.iter().take_while(|&&r| r != 0).any(|&r| r == cid) {
                self.warn(format!("Found duplicated check ID: {cid}"));
                return true;
            }
            let n = read_id.iter().take_while(|&&r| r != 0).count();
            read_id.truncate(n);
            read_id.push(cid);
            let Some(rules) = check.get("rules") else {
                self.warn(format!("Invalid check {cid}: no rules found."));
                return true;
            };
            let mut rules_n = 0;
            for rule in rules.children() {
                let Some(r) = rule.as_bytes() else {
                    self.warn(format!("Invalid check {cid}: Empty rule."));
                    return true;
                };
                let r = if r.starts_with(b"NOT ") || r.starts_with(b"not ") { &r[4..] } else { r };
                match r.first() {
                    #[cfg(windows)]
                    Some(b'r') => {}
                    Some(b'f' | b'd' | b'p' | b'c') => {}
                    None => {
                        self.warn(format!("Invalid check {cid}: Empty rule."));
                        return true;
                    }
                    _ => {
                        self.warn(format!("Invalid check {cid}: Invalid rule format."));
                        return true;
                    }
                }
                rules_n += 1;
                if rules_n > 255 {
                    self.warn(format!("Invalid check {cid}: Maximum number of rules is 255."));
                    return true;
                }
            }
            if rules_n == 0 {
                self.warn(format!("Invalid check {cid}: no rules found."));
                return true;
            }
        }
        let file = policy.get("file").and_then(|f| f.as_bytes()).unwrap_or(b"").to_vec();
        if list.contains_key(id) {
            self.error(cat(&[b"Error validating duplicated ID. Policy ", id, b" in file ", &file, b" is duplicated"]));
            return true;
        }
        list.insert(id.to_vec(), file);
        for r in read_id.iter().take_while(|&&r| r != 0) {
            let k = r.to_string().into_bytes();
            if list.contains_key(&k) {
                self.error(cat(&[b"Error validating duplicated ID. Check ", id, b" in policy ", id, b" is duplicated"]));
                return true;
            }
            list.insert(k, id.to_vec());
        }
        false
    }

    /// `wm_sca_check_requirements`: true on error.
    fn check_requirements(&self, r: &Json) -> bool {
        for (f, missing, bad) in [
            ("title", "Field 'title' not found on requirements.", "Field 'title' must be a string."),
            ("description", "Field 'description' not found on policy.", "Field 'description' must be a string."),
            ("condition", "Field 'condition' not found on policy.", "Field 'condition' must be a string."),
        ] {
            match r.get(f) {
                None => {
                    self.error(missing);
                    return true;
                }
                Some(v) if !v.is_string() => {
                    self.error(bad);
                    return true;
                }
                _ => {}
            }
        }
        match r.get("rules") {
            None => {
                self.error("Field 'rules' must be present.");
                true
            }
            Some(v) if !v.is_array() => {
                self.error("Field 'rules' must be an array.");
                true
            }
            _ => false,
        }
    }

    /// `wm_sca_do_scan`
    #[allow(clippy::too_many_arguments)]
    fn do_scan(
        &self,
        checks: &Json,
        vars: &HashMap<Vec<u8>, Option<Vec<u8>>>,
        id: i32,
        policy: &Json,
        requirements_scan: bool,
        st: &mut PolicyDb,
        remote_policy: bool,
        first_scan: bool,
        checks_number: &mut i32,
        sorted_variables: Option<&[Vec<u8>]>,
        policy_engine: &str,
        summary: &mut [u32; 3],
    ) -> i32 {
        let rt = self.rt();
        let mut eng = Engine::new(&self.env.log, self.cfg.skip_nfs, rt.commands_timeout);
        let mut ret_val = 0;
        let mut check_count: usize = 0;
        for check in checks.children() {
            let check_id_str = if requirements_scan {
                "Requirements check".to_string()
            } else {
                match check.get("id").filter(|c| c.is_number()).and_then(|c| c.as_i32()) {
                    Some(c) => format!("id: {c}"),
                    None => {
                        self.error(format!("Skipping check. Check ID is invalid. Offending check number: {check_count}"));
                        ret_val = 1;
                        continue;
                    }
                }
            };
            let Some(title) = check.get("title").and_then(|t| t.as_bytes()) else {
                self.error(format!("Skipping check with {check_id_str}: Check name is invalid."));
                if requirements_scan {
                    return 1;
                }
                continue;
            };
            let Some(cond) = check.get("condition").and_then(|t| t.as_bytes()) else {
                self.error(cat(&[b"Skipping check '", check_id_str.as_bytes(), b": ", title, b"': Check condition not found."]));
                if requirements_scan {
                    return 1;
                }
                continue;
            };
            let condition = match cond {
                b"all" => WM_SCA_COND_ALL,
                b"any" => WM_SCA_COND_ANY,
                b"none" => WM_SCA_COND_NON,
                b"any required" => {
                    self.info("Modifier 'required' is deprecated. Defaults to 'any'");
                    WM_SCA_COND_ANY
                }
                b"all required" => {
                    self.info("Modifier 'required' is deprecated. Defaults to 'all'");
                    WM_SCA_COND_ALL
                }
                _ => WM_SCA_COND_INV,
            };
            if condition == WM_SCA_COND_INV {
                self.error(cat(&[b"Skipping check '", check_id_str.as_bytes(), b": ", title, b"': Check condition (", cond, b") is invalid."]));
                if requirements_scan {
                    return 1;
                }
                continue;
            }
            let mut g_found = if condition & (WM_SCA_COND_ANY | WM_SCA_COND_NON) != 0 { RETURN_NOT_FOUND } else { RETURN_FOUND };
            self.d1(cat(&[b"Beginning evaluation of check ", check_id_str.as_bytes(), b" '", title, b"'"]));
            self.d1(cat(&[b"Rule aggregation strategy for this check is '", cond, b"'"]));
            self.d2(format!("Initial rule-aggregator value por this type of rule is '{g_found}'"));
            self.d1("Beginning rules evaluation.");
            let Some(rules) = check.get("rules") else {
                self.error(cat(&[b"Skipping check ", check_id_str.as_bytes(), b" '", title, b"': No rules found."]));
                if requirements_scan {
                    return 1;
                }
                continue;
            };
            let engine = check.get("regex_type").map(|e| e.as_bytes().unwrap_or(b"")).unwrap_or(policy_engine.as_bytes());
            let exp = if engine == siem_regex::expression::PCRE2_STR.as_bytes() { ExpType::Pcre2 } else { ExpType::OsRegex };
            self.d1(format!("SCA will use '{}' engine to check the rules.", if exp == ExpType::Pcre2 { "pcre2" } else { "osregex" }));
            for rule_ref in rules.children() {
                let Some(rule) = rule_ref.as_bytes() else {
                    self.d1("Field 'rule' must be a string.");
                    return 1;
                };
                self.d1(cat(&[b"Considering rule: '", rule, b"'"]));
                #[cfg(windows)]
                let expanded = {
                    let e = expand_rule(rule);
                    self.d2(cat(&[b"Rule after variable expansion: '", &e, b"'"]));
                    e
                };
                #[cfg(unix)]
                let expanded = rule.to_vec();
                let mut r = expanded.as_slice();
                let mut negated = 0;
                if r.starts_with(b"NOT ") || r.starts_with(b"not ") {
                    self.d2("Rule is negated.");
                    negated = 1;
                    r = &r[4..];
                }
                let Some((ty, value)) = get_value(r) else {
                    self.error(cat(&[b"Invalid rule: '", rule, b"'. Skipping policy."]));
                    return 1;
                };
                let mut found = RETURN_NOT_FOUND;
                // variables replaced in the rule location; None skips the rule
                let replace = |loc: &[u8], msg: &str| -> Option<Vec<u8>> {
                    let mut loc = loc.to_vec();
                    for v in sorted_variables.unwrap_or(&[]) {
                        if loc.windows(v.len()).any(|w| w == v.as_slice()) {
                            self.d2(cat(&[b"Variable '", v, b"' found at rule '", &loc, b"'. Replacing it."]));
                            match vars.get(v).and_then(|x| x.as_ref()) {
                                Some(val) => loc = str_replace(&loc, v, val),
                                None => {
                                    self.error(cat(&[msg.as_bytes(), b": '", v, b"'. Skipping check."]));
                                    return None;
                                }
                            }
                            self.d2(cat(&[b"Variable replaced: '", &loc, b"'"]));
                        }
                    }
                    Some(loc)
                };
                match ty {
                    1 => {
                        let (loc, pattern) = get_pattern(value);
                        let Some(loc) = replace(loc, "Invalid variable replacement") else { continue };
                        let result = eng.check_file_list(&loc, pattern, exp);
                        if result == RETURN_FOUND || result == RETURN_INVALID {
                            found = result;
                        }
                        eng.append_msg(msg1024(cat(&[b" File: ", &loc])));
                    }
                    5 => {
                        let (loc, pattern) = get_pattern(value);
                        let loc = if !rt.remote_commands && remote_policy {
                            let name = policy.get("name").and_then(|n| n.as_bytes()).unwrap_or(b"");
                            self.warn(cat(&[b"Ignoring check for policy '", name, b"'. The internal option 'sca.remote_commands' is disabled."]));
                            eng.set_reason(cat(&[b"Ignoring check for running command '", loc, b"'. The internal option 'sca.remote_commands' is disabled"]));
                            found = RETURN_INVALID;
                            loc.to_vec()
                        } else {
                            let Some(loc) = replace(loc, "Invalid variable") else { continue };
                            self.d2(cat(&[b"Running command: '", &loc, b"'"]));
                            let val = eng.read_command(&loc, pattern, exp);
                            if val == RETURN_FOUND {
                                self.d2("Command output matched.");
                                found = RETURN_FOUND;
                            } else if val == RETURN_INVALID {
                                self.d2("Command output did not match.");
                                found = RETURN_INVALID;
                            }
                            loc
                        };
                        eng.append_msg(msg1024(cat(&[b" Command: ", &loc])));
                    }
                    4 => {
                        self.d2(cat(&[b"Processing directory rule '", value, b"'"]));
                        let (loc, file) = get_pattern(value);
                        let Some(loc) = replace(loc, "Invalid variable") else { continue };
                        let (file, pattern) = match file {
                            Some(f) => {
                                let (f, p) = get_pattern(f);
                                (Some(f), p)
                            }
                            None => (None, None),
                        };
                        found = eng.check_dir_list(&loc, file, pattern, exp);
                        self.d2(format!("Check directory rule result: {found}"));
                    }
                    3 => {
                        eng.load_process_list();
                        self.d2(cat(&[b"Checking process: '", value, b"'"]));
                        if eng.check_process_is_running(value, exp) != 0 {
                            self.d2("Process found.");
                            found = RETURN_FOUND;
                        } else {
                            self.d2("Process not found.");
                        }
                        eng.append_msg(msg1024(cat(&[b" Process: ", value])));
                    }
                    #[cfg(windows)]
                    2 => {
                        let (key, entry) = get_pattern(value);
                        let (entry, pattern) = match entry {
                            Some(e) => {
                                let (e, p) = get_pattern(e);
                                (Some(e), p)
                            }
                            None => (None, None),
                        };
                        found = eng.is_registry(key, entry, pattern, exp);
                        eng.append_msg(msg1024(cat(&[b" Registry: ", key])));
                    }
                    _ => {}
                }
                if found != RETURN_INVALID {
                    found ^= negated;
                }
                self.d1(cat(&[b"Result for rule '", rule, b"': ", found.to_string().as_bytes()]));
                if (condition & WM_SCA_COND_ALL != 0 && found == RETURN_NOT_FOUND)
                    || (condition & WM_SCA_COND_ANY != 0 && found == RETURN_FOUND)
                    || (condition & WM_SCA_COND_NON != 0 && found == RETURN_FOUND)
                {
                    g_found = found;
                    self.d1(cat(&[b"Breaking from rule aggregator '", cond, b"' with found = ", g_found.to_string().as_bytes()]));
                    break;
                }
                if found == RETURN_INVALID {
                    g_found = found;
                    self.d1("Rule evaluation returned INVALID. Continuing.");
                }
            }
            if condition & WM_SCA_COND_NON != 0 && g_found != RETURN_INVALID {
                g_found = (g_found == 0) as i32;
            }
            self.d1(cat(&[b"Result for check ", check_id_str.as_bytes(), b" '", title, b"' -> ", g_found.to_string().as_bytes()]));
            if g_found != RETURN_INVALID {
                eng.reason = None;
            }
            if requirements_scan {
                return if g_found == RETURN_INVALID { 1 } else { (g_found == 0) as i32 };
            }
            let message: &str = if g_found == RETURN_NOT_FOUND {
                summary[1] += 1;
                "failed"
            } else if g_found == RETURN_FOUND {
                summary[0] += 1;
                "passed"
            } else {
                summary[2] += 1;
                if eng.reason.is_none() {
                    eng.reason = Some(b"Unknown reason".to_vec());
                    self.d1("A check returned INVALID for an unknown reason.");
                }
                ""
            };
            match self.build_event(check, policy, &eng.alert_msg, id, message, eng.reason.as_deref()) {
                Some(event) => {
                    if st.for_hash.len() <= check_count {
                        st.for_hash.resize(check_count + 1, None);
                    }
                    if self.check_hash(st, message, check, &event, check_count) && !first_scan {
                        self.send_alert(&event);
                    }
                    check_count += 1;
                }
                None => {
                    self.error(cat(&[b"Error constructing event for check: ", title, b". Set debug mode for more information."]));
                    ret_val = 1;
                }
            }
            eng.alert_msg.clear();
            eng.reason = None;
        }
        *checks_number = check_count as i32;
        ret_val
    }

    /// `wm_sca_build_event`
    fn build_event(&self, check: &Json, policy: &Json, alert_msg: &[Vec<u8>], id: i32, result: &str, reason: Option<&[u8]>) -> Option<Json> {
        let mut alert = Json::object();
        alert.add("type", Json::string("check"));
        alert.add("id", Json::number(id as f64));
        let name = policy.get("name").and_then(|n| n.as_bytes()).unwrap_or(b"");
        let policy_id = policy.get("id");
        alert.add("policy", Json::string(name));
        let mut info = Json::object();
        let Some(pm_id) = check.get("id") else {
            self.d1("No 'id' field found on check.");
            return None;
        };
        let Some(pm) = pm_id.as_i32().filter(|_| pm_id.is_number()) else {
            self.d1("Field 'id' must be a number.");
            return None;
        };
        info.add("id", Json::number(pm as f64));
        match check.get("title") {
            Some(t) => match t.as_bytes() {
                Some(b) => {
                    info.add("title", Json::string(b));
                }
                None => {
                    self.d1("Field 'title' must be a string.");
                    return None;
                }
            },
            None => {
                self.d1(format!("No 'title' field found on check '{pm}'"));
                return None;
            }
        }
        let Some(policy_id) = policy_id else {
            self.d1("No 'id' field found on policy.");
            return None;
        };
        for f in ["description", "rationale", "remediation"] {
            if let Some(v) = check.get(f) {
                let Some(b) = v.as_bytes() else {
                    self.d1(format!("Field '{f}' must be a string."));
                    return None;
                };
                info.add(f, Json::string(b));
            }
        }
        if let Some(compliances) = check.get("compliance") {
            let mut add = Json::object();
            for compliance in compliances.children() {
                // compliance->child: its first member; arrays have no key
                let Json::Object(m) = compliance else { continue };
                let Some((key, _)) = m.first() else { continue };
                let mut value: Option<Vec<u8>> = None;
                if let Some(versions) = compliance.get_bytes(key) {
                    for version in versions.children() {
                        match version.as_bytes() {
                            Some(v) => strcat(&mut value, v, b','),
                            None => {
                                let pid = policy_id.as_bytes().unwrap_or(b"(null)");
                                self.warn(cat(&[b"Invalid compliance format in policy: ", pid, b" (check ", pm.to_string().as_bytes(), b")"]));
                            }
                        }
                    }
                }
                if let Some(v) = value {
                    add.add(key, Json::string(v));
                }
            }
            info.add("compliance", add);
        }
        if let Some(rules) = check.get("rules") {
            info.add("rules", rules.clone());
        }
        let Some(condition) = check.get("condition") else {
            self.d1("No 'condition' field found on check.");
            return None;
        };
        let Some(condition) = condition.as_bytes() else {
            self.d1("Field 'condition' must be a string.");
            return None;
        };
        info.add("condition", Json::string(condition));
        if let Some(references) = check.get("references") {
            let mut list = None;
            for r in references.children() {
                if let Some(b) = r.as_bytes() {
                    strcat(&mut list, b, b',');
                }
            }
            if let Some(l) = list {
                info.add("references", Json::string(l));
            }
        }
        // the File / Directory / Process / Registry / Command of the rules
        let mut finals: [Option<Vec<u8>>; 5] = Default::default();
        let find = |h: &[u8], n: &[u8]| h.windows(n.len()).position(|w| w == n);
        for m in alert_msg.iter().take(255) {
            let (slot, skip) = if let Some(i) = find(m, b"File:") {
                (0, i + 6)
            } else if let Some(i) = find(m, b"Directory:") {
                (1, i + 11)
            } else if let Some(i) = find(m, b"Process:") {
                (2, i + 9)
            } else if let Some(i) = find(m, b"Registry:") {
                (3, i + 10)
            } else if let Some(i) = find(m, b"Command:") {
                (4, i + 9)
            } else {
                continue;
            };
            let v = m.get(skip..).unwrap_or(b"");
            strcat(&mut finals[slot], v, b',');
        }
        for (slot, key) in ["file", "directory", "process", "registry", "command"].iter().enumerate() {
            if let Some(v) = finals[slot].take() {
                info.add(key, Json::string(v));
            }
        }
        if result.is_empty() {
            info.add("status", Json::string("Not applicable"));
            if let Some(r) = reason {
                info.add("reason", Json::string(r));
            }
        } else {
            info.add("result", Json::string(result));
        }
        let Some(pid) = policy_id.as_bytes() else {
            self.d1("Field 'id' must be a string.");
            return None;
        };
        alert.add("policy_id", Json::string(pid));
        alert.add("check", info);
        Some(alert)
    }

    /// `wm_sca_check_hash`: true when the result changed (or is new).
    fn check_hash(&self, st: &mut PolicyDb, result: &str, check: &Json, event: &Json, check_index: usize) -> bool {
        let Some(pm_id) = check.get("id").filter(|c| c.is_number()) else { return false };
        let (double, int) = match pm_id {
            Json::Number { double, int } => (*double, *int),
            _ => return false,
        };
        let key = if double == int as f64 { int.to_string() } else { format!("{double:.6}") };
        let elem = Arc::new(Elem { id: int, result: result.to_string(), event: event.clone() });
        let alert = match st.db.get(&key) {
            Some(old) => old.result != elem.result,
            None => true,
        };
        st.db.insert(key, Arc::clone(&elem));
        st.for_hash[check_index] = Some(elem);
        alert
    }

    /// `wm_sca_hash_integrity`: sorts the results by id and hashes them.
    fn hash_integrity(&self, st: &mut PolicyDb) -> Option<String> {
        let n = st.prefix();
        st.for_hash[..n].sort_by_key(|e| e.as_ref().map(|e| e.id));
        self.d2("Concatenating check results:");
        let mut s: Option<Vec<u8>> = None;
        for e in st.for_hash[..n].iter().flatten() {
            self.d2(format!("ID: {}; Result: '{}'", e.id, e.result));
            strcat(&mut s, e.result.as_bytes(), b':');
        }
        s.map(|s| hex(&Sha256::digest(&s)))
    }

    /// `wm_sca_send_summary`
    #[allow(clippy::too_many_arguments)]
    fn send_summary(&self, st: &mut PolicyDb, scan_id: i32, s: [u32; 3], policy: &Json, start: i64, end: i64, hash: &str, hash_file: &str, first_scan: bool, checks_number: i32) {
        let b = |k: &str| policy.get(k).and_then(|v| v.as_bytes()).unwrap_or(b"").to_vec();
        let mut j = Json::object();
        j.add("type", Json::string("summary"));
        j.add("scan_id", Json::number(scan_id as f64));
        j.add("name", Json::string(b("name")));
        j.add("policy_id", Json::string(b("id")));
        j.add("file", Json::string(b("file")));
        if let Some(d) = policy.get("description").and_then(|d| d.as_bytes()) {
            j.add("description", Json::string(d));
        }
        if let Some(refs) = policy.get("references") {
            let mut r = None;
            for x in refs.children() {
                if let Some(v) = x.as_bytes() {
                    strcat(&mut r, v, b',');
                }
            }
            if let Some(r) = r {
                j.add("references", Json::string(r));
            }
        }
        let (passed, failed, invalid) = (s[0], s[1], s[2]);
        j.add("passed", Json::number(passed as f64));
        j.add("failed", Json::number(failed as f64));
        j.add("invalid", Json::number(invalid as f64));
        // float score = (passedf / (failedf + passedf)) * 100
        let mut score = (passed as f32 / (failed as f32 + passed as f32)) * 100.0;
        if passed == 0 && failed == 0 {
            score = 0.0;
        }
        j.add("total_checks", Json::number(checks_number as f64));
        j.add("score", Json::number(score as f64));
        j.add("start_time", Json::number(start as i32 as f64));
        j.add("end_time", Json::number(end as i32 as f64));
        j.add("hash", Json::string(hash));
        j.add("hash_file", Json::string(hash_file));
        if first_scan {
            j.add("first_scan", Json::number(1.0));
        }
        self.d1(cat(&[b"Sending summary event for file: '", &b("file"), b"'"]));
        st.last_summary = Some(j.clone());
        self.send_alert(&j);
    }

    /// `wm_sca_dump_db_thread`
    fn dump_db_thread(self: Arc<Self>, rx: Receiver<(usize, i32)>) {
        while let Ok((idx, first)) = rx.recv() {
            let rt = self.rt();
            let path = &self.cfg.policies[idx].path;
            let mut random = scan_random();
            random = ((random as u32) % rt.request_db_interval.max(1)) as i32;
            if random == 0 {
                random += 5;
            }
            if first != 0 {
                std::thread::sleep(Duration::from_secs(2));
                self.d1(format!("Sending first scan results for policy '{path}'"));
            } else {
                self.info(format!("Integration checksum failed for policy '{path}'. Resending scan results in {random} seconds."));
                std::thread::sleep(Duration::from_secs(random as u32 as u64));
            }
            self.d1(format!("Dumping results to SCA DB for policy '{path}' (Policy index: {idx})"));
            let mut db = self.db.lock();
            let st = &mut db[idx];
            let mut scan_id = -1;
            let n = st.prefix();
            for e in st.for_hash[..n].iter().flatten() {
                if scan_id == -1 {
                    if let Some(i) = e.event.get("id").and_then(|i| i.as_i32()) {
                        scan_id = i;
                    }
                }
                self.send_alert(&e.event);
            }
            std::thread::sleep(Duration::from_secs(5));
            let policy_id = self.ids.lock()[idx].clone().unwrap_or_default();
            self.d1("Sending end of dump control event.");
            let mut d = Json::object();
            d.add("type", Json::string("dump_end"));
            d.add("policy_id", Json::string(&policy_id));
            d.add("elements_sent", Json::number(n as f64));
            d.add("scan_id", Json::number(scan_id as f64));
            self.send_alert(&d);
            std::thread::sleep(Duration::from_secs(2));
            if first != 0 {
                if let Some(mut s) = st.last_summary.take() {
                    s.remove("first_scan");
                    s.add("force_alert", Json::string("1"));
                    self.send_alert(&s);
                    st.last_summary = Some(s);
                }
            }
            self.d1(format!("Finished dumping scan results to SCA DB for policy '{policy_id}' ({idx}) ({first})"));
        }
    }

    /// `wm_sca_push_request_win` (and the Unix request thread's parsing).
    pub fn push_request(&self, msg: &[u8]) {
        let Some(rt) = self.rt.get() else { return };
        let Some(colon) = msg.iter().position(|&c| c == b':') else { return };
        if !msg.starts_with(DB_DUMP.as_bytes()) {
            return;
        }
        let db = &msg[colon + 1..];
        let Some(c2) = db.iter().position(|&c| c == b':') else {
            self.d1("First scan flag missing.");
            return;
        };
        let (mut db, first_scan) = (&db[..c2], &db[c2 + 1..]);
        let ids = self.ids.lock();
        for (i, p) in self.cfg.policies.iter().enumerate() {
            if !p.enabled {
                continue;
            }
            let Some(id) = &ids[i] else { continue };
            if let Some(e) = db.iter().position(|&c| c == b'\n') {
                db = &db[..e];
            }
            if crate::check::cs(db) == id.as_bytes() {
                match rt.requests.try_send((i, crt::atoi(first_scan))) {
                    Ok(()) => {}
                    Err(TrySendError::Full(_)) | Err(TrySendError::Disconnected(_)) => self.d1("Could not push policy index to queue."),
                }
                break;
            }
        }
    }
}

/// Lowercase hex (`OS_SHA256_String`).
fn hex(d: &[u8]) -> String {
    d.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn helpers() {
        assert_eq!(get_value(b"!f:/etc/x -> r:a"), Some((1, &b"/etc/x -> r:a"[..])));
        assert_eq!(get_value(b"x:/a"), None);
        assert_eq!(str_replace(b"$a/$a", b"$a", b"x"), b"x/x");
        let v = Json::Object(vec![(b"$a".to_vec(), Json::string("1")), (b"$abc".to_vec(), Json::string("2")), (b"$ab".to_vec(), Json::string("3"))]);
        assert_eq!(sort_variables(Some(&v)).unwrap(), vec![b"$abc".to_vec(), b"$ab".to_vec(), b"$a".to_vec()]);
    }
}
