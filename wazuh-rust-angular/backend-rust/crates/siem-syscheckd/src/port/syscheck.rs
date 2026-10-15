//! `syscheckd/src/syscheck.c` (`read_internal`, the configuration part of
//! `Start_win32_Syscheck`) and `syscheckd/src/syscom.c` (`syscom_dispatch`,
//! `syscom_getconfig`).

use parking_lot::RwLock;
use siem_config::{ConfigContext, ConfigHandler, Result as CResult, Section};
use siem_xml::{OsXml, XmlNode};
use siem_log::WLog;

use super::config::*;

/// `OSSECCONF`, `AGENTCONFIG`
#[cfg(windows)]
pub const OSSECCONF: &str = "ossec.conf";
#[cfg(windows)]
pub const AGENTCONFIG: &str = "shared/agent.conf";
#[cfg(unix)]
pub const OSSECCONF: &str = "etc/ossec.conf";
#[cfg(unix)]
pub const AGENTCONFIG: &str = "etc/shared/agent.conf";

/// The `<syscheck>` sections of a read.
pub struct Handler<'a> {
    pub sc: &'a mut SyscheckConfig,
    pub agent_config: bool,
}

impl ConfigHandler for Handler<'_> {
    fn section(&mut self, ctx: &mut ConfigContext, xml: &OsXml, section: Section, _node: &XmlNode, children: Option<&[XmlNode]>) -> CResult<()> {
        if section == Section::Syscheck {
            read_syscheck(ctx, xml, children, self.sc, self.agent_config)?;
        }
        Ok(())
    }
}

/// What the agent passes in: its internal options and how config messages are logged.
pub struct Env<'a> {
    pub log: &'a WLog,
    /// `getDefine_Int` (exits on an invalid value)
    pub define_int: &'a dyn Fn(&str, &str, i32, i32) -> i32,
    /// Logs the messages a `ReadConfig` collected.
    pub flush: &'a dyn Fn(&mut ConfigContext),
    pub platform: siem_config::Platform,
    pub agent: siem_config::AgentIdentity,
    /// `agent.remote_conf`
    pub remote_conf: bool,
}

/// The module state the requests read (`syscheck` global, `sys_debug_level`).
pub struct Syscheck {
    pub cfg: RwLock<SyscheckConfig>,
    pub sys_debug_level: i32,
    /// `rootcheck.tsleep`
    pub rootcheck_sleep: i32,
    /// The rootcheck configuration (`rootcheck` global)
    #[cfg(windows)]
    pub rootcheck: std::sync::Arc<super::rootcheck::RkConfig>,
}

/// `read_internal(0)`
fn read_internal(env: &Env, sc: &mut SyscheckConfig) -> i32 {
    sc.rt_delay = (env.define_int)("syscheck", "rt_delay", 0, 1000);
    sc.max_depth = (env.define_int)("syscheck", "default_max_depth", 1, 320);
    sc.file_max_size = (env.define_int)("syscheck", "file_max_size", 0, 4095) as usize * 1024 * 1024;
    sc.sym_checker_interval = (env.define_int)("syscheck", "symlink_scan_interval", 1, 2592000);
    #[cfg(unix)]
    {
        sc.max_audit_entries = (env.define_int)("syscheck", "max_audit_entries", 1, 4096);
    }
    let level = (env.define_int)("syscheck", "debug", 0, 2);
    for _ in 0..level {
        env.log.now_debug();
    }
    level
}

/// `Read_Syscheck_Config(cfgfile)`: < 0 on error, 1 when nothing is configured.
fn read_syscheck_config(env: &Env, sc: &mut SyscheckConfig) -> i32 {
    use siem_config::modules::{CAGENT_CONFIG, CSYSCHECK};
    env.log.debug1(format!("(6287): Reading configuration file: '{OSSECCONF}'"));
    let mut ctx = ConfigContext::new(env.platform);
    ctx.agent = env.agent.clone();
    let r = siem_config::read_config(&mut ctx, CSYSCHECK, OSSECCONF, None, &mut Handler { sc, agent_config: false });
    (env.flush)(&mut ctx);
    if r.is_err() {
        return -1;
    }
    if env.platform.client {
        env.log.debug1(format!("(6208): Reading Client Configuration [{OSSECCONF}]"));
        let mut ctx = ConfigContext::new(env.platform);
        ctx.agent = env.agent.clone();
        let _ = siem_config::read_config(&mut ctx, CSYSCHECK | CAGENT_CONFIG, AGENTCONFIG, Some(env.remote_conf), &mut Handler { sc, agent_config: true });
        (env.flush)(&mut ctx);
    }
    // getDefine_Int runs only when something is configured (after the early return)
    let pre = {
        let no_registry = sc.registry.as_ref().map(|r| r.is_empty()).unwrap_or(true);
        sc.directories.is_empty() && no_registry && sc.wildcards.is_none()
    };
    let max_fd = if cfg!(windows) && !pre { (env.define_int)("syscheck", "max_fd_win_rt", 1, 1024) as u32 } else { 0 };
    let r = finish_config(sc, max_fd);
    if cfg!(windows) && sc.registry.is_none() {
        sc.registry = Some(Vec::new()); // REGISTRY_EMPTY
    }
    r
}

/// The configuration part of `Start_win32_Syscheck` (up to `fim_initialize`):
/// reads the options and logs what will be monitored.
pub fn start_config(env: &Env) -> Syscheck {
    let mut sc = SyscheckConfig::default();
    let sys_debug_level = read_internal(env, &mut sc);
    if std::fs::metadata(OSSECCONF).is_err() {
        env.log.critical(format!("(1239): Configuration file not found: '{OSSECCONF}'."));
        siem_log::cexit::fatal_exit();
    }
    let r = read_syscheck_config(env, &mut sc);
    if r < 0 {
        env.log.warn(format!("(1207): syscheck remote configuration in '{OSSECCONF}' is corrupted."));
        sc.disabled = 1;
    } else if r == 1 || sc.disabled == 1 {
        env.log.info("(6678): No directory provided for syscheck to monitor.");
        sc.directories.clear();
        // os_free(ignore[0]): the list reads as empty
        sc.ignore = Some(Vec::new());
        sc.registry = Some(Vec::new());
        env.log.info("(6001): File integrity monitoring disabled.");
    }
    // Rootcheck config: syscheck.rootcheck says whether its thread scans
    #[cfg(windows)]
    let (rk, rootcheck_sleep) = {
        let (rk, r) = super::rootcheck::rootcheck_init(env);
        sc.rootcheck = (r == 0) as i32;
        let sleep = rk.tsleep;
        (std::sync::Arc::new(rk), sleep)
    };
    #[cfg(unix)]
    let rootcheck_sleep = (env.define_int)("rootcheck", "sleep", 0, 1000);
    if sc.disabled == 0 {
        for r in sc.registry.iter().flatten() {
            env.log.info(format!(
                "(6002): Monitoring registry entry: '{}{}', with options '{}'",
                r.entry,
                if r.arch == ARCH_64BIT { " [x64]" } else { "" },
                syscheck_opts2str(r.opts)
            ));
            if sc.file_size_enabled {
                env.log.debug1(format!("(6356): Maximum file size limit to generate diff information configured to '{} KB' for '{}'.", r.diff_size_limit, r.entry));
            }
        }
        for d in &sc.directories {
            env.log.info(format!("(6003): Monitoring path: '{}', with options '{}'.", d.path, syscheck_opts2str(d.options)));
            if let Some(t) = &d.tag {
                env.log.debug2(format!("(6206): Adding tag '{t}' to directory '{}'", d.path));
            }
            if d.options & CHECK_SEECHANGES != 0 && sc.file_size_enabled {
                env.log.debug2(format!("(6356): Maximum file size limit to generate diff information configured to '{} KB' for '{}'.", d.diff_size_limit, d.path));
            }
        }
        if !sc.file_size_enabled {
            env.log.info("(6042): File size limit disabled.");
        }
        if sc.disk_quota_enabled {
            env.log.debug2(format!("(6357): Maximum disk quota size limit configured to '{} KB'.", sc.disk_quota_limit));
        } else {
            env.log.info("(6043): Disk quota limit disabled.");
        }
        for e in sc.ignore.iter().flatten() {
            env.log.info(format!("(6206): Ignore 'file' entry '{e}'"));
        }
        for m in sc.ignore_regex.iter().flatten() {
            env.log.info(format!("(6207): Ignore 'file' sregex '{}'", m.raw()));
        }
        for e in sc.key_ignore.iter().flatten() {
            env.log.info(format!("(6206): Ignore 'registry' entry '{}'", e.entry));
        }
        for m in sc.key_ignore_regex.iter().flatten() {
            env.log.info(format!("(6207): Ignore 'registry' sregex '{}'", m.regex.raw()));
        }
        for e in sc.value_ignore.iter().flatten() {
            env.log.info(format!("(6206): Ignore 'value' entry '{}'", e.entry));
        }
        for m in sc.value_ignore_regex.iter().flatten() {
            env.log.info(format!("(6207): Ignore 'value' sregex '{}'", m.regex.raw()));
        }
        for e in sc.registry_nodiff.iter().flatten() {
            env.log.info(format!("(6044): Option nodiff enabled for registry value '{}'.", e.entry));
        }
        for m in sc.registry_nodiff_regex.iter().flatten() {
            env.log.info(format!("(6044): Option nodiff enabled for registry sregex '{}'.", m.regex.raw()));
        }
        for e in sc.nodiff.iter().flatten() {
            env.log.info(format!("(6004): No diff for file: '{e}'"));
        }
        env.log.info(format!("Started (pid: {}).", std::process::id()));
    }
    Syscheck {
        cfg: RwLock::new(sc),
        sys_debug_level,
        rootcheck_sleep,
        #[cfg(windows)]
        rootcheck: rk,
    }
}

impl Syscheck {
    /// `syscom_getconfig`
    fn getconfig(&self, log: &WLog, section: &str) -> Vec<u8> {
        let cfg = match section {
            "syscheck" => get_syscheck_config(&self.cfg.read_recursive()),
            "internal" => Some(get_syscheck_internal_options(&self.cfg.read_recursive(), self.sys_debug_level, self.rootcheck_sleep)),
            #[cfg(windows)]
            "rootcheck" => Some(super::rootcheck::get_rootcheck_config(&self.rootcheck)),
            _ => None,
        };
        match cfg {
            Some(c) => {
                let mut out = b"ok ".to_vec();
                out.extend_from_slice(&c.print_unformatted());
                out
            }
            None => {
                log.debug1(format!("(6283): At SYSCOM getconfig: Could not get '{section}' section."));
                b"err Could not get requested section".to_vec()
            }
        }
    }

    /// `syscom_dispatch`: the reply (empty when the C returns 0 bytes).
    pub fn dispatch(&self, log: &WLog, command: &[u8]) -> Vec<u8> {
        let cmd = String::from_utf8_lossy(command).into_owned();
        for p in ["fim_file ", "fim_registry ", "fim_registry_key ", "fim_registry_value "] {
            if cmd.starts_with(p) {
                if let Some(db) = super::fimdb::instance() {
                    db.push_message(command);
                }
                return Vec::new();
            }
        }
        if cmd.starts_with("syscheck ") || cmd.starts_with("getconfig") || cmd.starts_with("restart") {
            let comm = cmd.strip_prefix("syscheck ").unwrap_or(&cmd);
            let (comm, args) = match comm.find(' ') {
                Some(i) => (&comm[..i], Some(&comm[i + 1..])),
                None => (comm, None),
            };
            if comm == "getconfig" {
                let Some(args) = args else {
                    log.debug1("(6281): SYSCOM getconfig needs arguments.");
                    return b"err SYSCOM getconfig needs arguments".to_vec();
                };
                return self.getconfig(log, args);
            } else if comm == "restart" {
                // os_set_restart_syscheck: syscheck and rootcheck
                super::run_check::RESTART_SYSCHECK.store(true, std::sync::atomic::Ordering::SeqCst);
                #[cfg(windows)]
                super::rootcheck::RESTART_ROOTCHECK.store(true, std::sync::atomic::Ordering::SeqCst);
                return Vec::new();
            }
        }
        log.debug1(format!("(6282): SYSCOM Unrecognized command '{cmd}'"));
        b"err Unrecognized command".to_vec()
    }
}

/// The rest of `Start_win32_Syscheck`: `realtime_start`, `fim_initialize`, `start_daemon`.
#[cfg(windows)]
pub fn start(sk: std::sync::Arc<Syscheck>, send: Box<dyn Fn(u8, &str, &[u8]) -> i32 + Send + Sync>) {
    let fim = std::sync::Arc::new(super::create_db::Fim::new(sk, send));
    {
        let c = fim.sk.cfg.read_recursive();
        if c.disabled == 0 {
            let rt = |d: &[Directory]| d.iter().any(|d| d.options & REALTIME_ACTIVE != 0);
            if rt(&c.directories) || rt(c.wildcards.as_deref().unwrap_or(&[])) {
                super::realtime::realtime_start();
            }
        }
    }
    super::run_check::fim_initialize(&fim);
    let _ = FIM.set(fim.clone());
    super::run_check::start_daemon(&fim);
}

/// The running module (for the syscom `fim_*` and `restart` requests).
#[cfg(windows)]
pub static FIM: std::sync::OnceLock<std::sync::Arc<super::create_db::Fim>> = std::sync::OnceLock::new();
