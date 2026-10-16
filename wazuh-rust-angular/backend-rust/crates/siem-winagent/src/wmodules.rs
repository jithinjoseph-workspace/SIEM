//! The modules of `wazuh-agent.exe` (wazuh_modules/wmodules.c, wmcom.c and
//! config/wmodules-config.c as the Windows agent builds them): `wm_config`,
//! `wm_check`, the module threads, `modulesSync` and `wmcom_dispatch`.
//!
//! Ported modules: agent-upgrade, syscollector, SCA, command, osquery. The other
//! wodles the C agent can run (open-scap, cis-cat) are read as the C reads
//! unknown-but-valid ones: they are skipped until their ports land.

use std::sync::{Arc, OnceLock};

use siem_agentd::Agentd;
use siem_cjson::Json;
use siem_config::{read_config, ConfigContext, ConfigError, ConfigHandler, Platform, Result as CResult, Section};
use siem_log::WLog;
use siem_syscollector::port::syscollector::LogLevel;
use siem_syscollector::port::wm::{self as wmsys, Env, WmSys, WmSysModule};
use siem_xml::{OsXml, XmlNode};

/// `OSSECCONF`, `AGENTCONFIG` (Windows)
const OSSECCONF: &str = "ossec.conf";
const AGENTCONFIG: &str = "shared\\agent.conf";
/// `WM_MAX_ATTEMPTS`, `WM_MAX_WAIT` (usleep: microseconds)
const WM_MAX_ATTEMPTS: i32 = 3;
const WM_MAX_WAIT: u64 = 500;

/// A configured module (`wmodule`), in configuration order.
enum Module {
    Upgrade(Arc<crate::upgrade::Config>),
    Syscollector(Arc<WmSysModule>),
    Sca(Arc<siem_sca::wm::Sca>),
    /// The module tag (`command:<tag>`; None when `<tag>` was missing) and the command.
    Command(Option<String>, crate::wm_command::WmCommand),
    Osquery(crate::wm_osquery::WmOsquery),
}

impl Module {
    fn tag(&self) -> Option<&str> {
        match self {
            Module::Upgrade(_) => Some(crate::upgrade::NAME),
            Module::Syscollector(_) => Some(wmsys::NAME),
            Module::Sca(_) => Some(siem_sca::wm::NAME),
            Module::Command(t, _) => t.as_deref(),
            Module::Osquery(_) => Some(crate::wm_osquery::NAME),
        }
    }
}

/// The `command` wodles read so far, in order: (module tag, command).
type Commands = Vec<(Option<String>, crate::wm_command::WmCommand)>;

/// `wmodules` and the internal options `wm_config` reads.
pub struct WModules {
    modules: Vec<Module>,
    task_nice: i32,
    max_eps: i32,
    kill_timeout: i32,
    /// `wazuh_command.remote_commands`
    remote_commands: bool,
    /// `agent.remote_conf` (osquery reads the labels of agent.conf)
    remote_conf: bool,
    log: Arc<WLog>,
    sys_env: OnceLock<Arc<Env>>,
}

/// `Test_WModule`: the module readers into throw-away configurations.
pub struct WModuleTest {
    sys: Option<WmSys>,
    sca: Option<siem_sca::wm::WmSca>,
    up: crate::upgrade::Config,
    log: Arc<WLog>,
    order: Vec<&'static str>,
    commands: Commands,
    osquery: Option<crate::wm_osquery::WmOsquery>,
}

impl WModuleTest {
    pub fn new(log: Arc<WLog>) -> Self {
        Self { sys: None, sca: None, up: Default::default(), log, order: Vec::new(), commands: Vec::new(), osquery: None }
    }
}

impl ConfigHandler for WModuleTest {
    fn section(&mut self, ctx: &mut ConfigContext, xml: &OsXml, section: Section, node: &XmlNode, children: Option<&[XmlNode]>) -> CResult<()> {
        let mut h = Handler { sys: &mut self.sys, sca: &mut self.sca, up: &mut self.up, log: &self.log, order: &mut self.order, commands: &mut self.commands, osquery: &mut self.osquery, agent_cfg: true };
        h.section(ctx, xml, section, node, children)
    }
}

/// The `<wodle>` sections (`Read_WModule`).
struct Handler<'a> {
    sys: &'a mut Option<WmSys>,
    sca: &'a mut Option<siem_sca::wm::WmSca>,
    up: &'a mut crate::upgrade::Config,
    log: &'a WLog,
    order: &'a mut Vec<&'static str>,
    commands: &'a mut Commands,
    osquery: &'a mut Option<crate::wm_osquery::WmOsquery>,
    /// Reading agent.conf (`modules & CAGENT_CONFIG`).
    agent_cfg: bool,
}

impl ConfigHandler for Handler<'_> {
    fn section(&mut self, ctx: &mut ConfigContext, xml: &OsXml, section: Section, node: &XmlNode, children: Option<&[XmlNode]>) -> CResult<()> {
        if section == Section::Sca {
            // Read_SCA: one module, every <sca> block read into it
            if !self.order.contains(&siem_sca::wm::NAME) {
                self.order.push(siem_sca::wm::NAME);
            }
            if children.is_none() {
                ctx.debug1(format!("Empty configuration for module '{}'", node.element));
            }
            let sca = self.sca.get_or_insert_with(Default::default);
            return siem_sca::wm::wm_sca_read(self.log, xml, children, sca).map_err(|_| ConfigError::new(""));
        }
        if section == Section::AgentUpgrade {
            // Read_AgentUpgrade: the default module, read again
            if children.is_none() {
                ctx.debug1(format!("Empty configuration for module '{}'", node.element));
            }
            return crate::upgrade::read(ctx, self.log, Some(xml), children, self.up).map_err(|_| ConfigError::new(""));
        }
        if section != Section::Wodle {
            return Ok(());
        }
        let Some(attr) = node.attributes.first() else {
            return Err(ConfigError::new("No such attribute 'name' at module."));
        };
        if attr != "name" {
            return Err(ConfigError::new("Module attribute is not 'name'"));
        }
        let name = node.values.first().cloned().unwrap_or_default();
        if children.is_none() {
            ctx.debug1(format!("Empty configuration for module '{name}'"));
        }
        match name.as_str() {
            "syscollector" => {
                if !self.order.contains(&wmsys::NAME) {
                    self.order.push(wmsys::NAME);
                }
                let sys = self.sys.get_or_insert_with(WmSys::default);
                let mut log = Vec::new();
                let r = wmsys::wm_syscollector_read(xml, children, sys, &mut log);
                for (lv, m) in log {
                    if lv == "WARNING" {
                        ctx.warn(m);
                    } else {
                        ctx.error(m);
                    }
                }
                r.map_err(ConfigError::new)?;
            }
            "command" => {
                // Read_WModule reuses a module whose tag equals the wodle name ("command": an empty <tag>)
                let reuse = self.commands.iter().position(|(t, _)| t.as_deref() == Some(crate::wm_command::NAME));
                let mut tag = reuse.and_then(|i| self.commands[i].0.clone());
                let c = crate::wm_command::read(self.log, children, self.agent_cfg, &mut tag).map_err(|_| ConfigError::new(""))?;
                match reuse {
                    Some(i) => self.commands[i] = (tag, c),
                    None => {
                        self.order.push(crate::wm_command::NAME);
                        self.commands.push((tag, c));
                    }
                }
            }
            "osquery" => {
                // Read_WModule reuses the module tagged "osquery": a new configuration replaces it
                if !self.order.contains(&crate::wm_osquery::NAME) {
                    self.order.push(crate::wm_osquery::NAME);
                }
                *self.osquery = Some(crate::wm_osquery::read(self.log, children).map_err(|_| ConfigError::new(""))?);
            }
            // Read by modules not ported yet (no message in the C either)
            "open-scap" | "cis-cat" => {}
            "aws-s3" | "aws-cloudtrail" => ctx.warn(format!("The '{name}' module is not available on Windows systems. Ignoring.")),
            "docker-listener" => ctx.warn(format!("The '{name}' module is not available on Windows systems. Ignoring it.")),
            "vulnerability-detector" | "azure-logs" | "agent-key-polling" => ctx.warn(format!("The '{name}' module only works for the manager")),
            _ => ctx.error(format!("Unknown module '{name}'")),
        }
        Ok(())
    }
}

/// `taggedLogFunction` for a module tag.
fn tagged(log: &Arc<WLog>, tag: &'static str) -> Arc<dyn Fn(LogLevel, &str) + Send + Sync> {
    let log = log.clone();
    Arc::new(move |lv: LogLevel, m: &str| {
        let l = match lv {
            LogLevel::Error | LogLevel::ErrorExit => "ERROR",
            LogLevel::Info => "INFO",
            LogLevel::Warning => "WARNING",
            LogLevel::Debug => "DEBUG",
            LogLevel::DebugVerbose => "DEBUG2",
        };
        log.tagged(tag, l, m);
        if lv == LogLevel::ErrorExit {
            siem_log::cexit::fatal_exit();
        }
    })
}

/// The `<labels>` of a read.
struct LabelsHandler<'a>(&'a mut Vec<siem_config::labels::Label>);

impl ConfigHandler for LabelsHandler<'_> {
    fn section(&mut self, ctx: &mut ConfigContext, _xml: &OsXml, section: Section, _node: &XmlNode, children: Option<&[XmlNode]>) -> CResult<()> {
        if section == Section::Labels {
            siem_config::labels::read_labels(ctx, children.unwrap_or(&[]), self.0)?;
        }
        Ok(())
    }
}

/// Logs what a `ReadConfig` collected.
fn flush_log(log: &WLog, ctx: &mut ConfigContext) {
    use siem_config::LogLevel as L;
    for (lv, m) in ctx.log.drain(..) {
        match lv {
            L::Debug1 => log.debug1(m),
            L::Debug2 => log.debug2(m),
            L::Info => log.info(m),
            L::Warn => log.warn(m),
            L::Error => log.error(m),
        }
    }
}

/// `ReadConfig(CLABELS, OSSECCONF)` then `ReadConfig(CLABELS | CAGENT_CONFIG, AGENTCONFIG)`.
fn read_labels(log: &WLog, remote_conf: bool) -> std::result::Result<Vec<siem_config::labels::Label>, ()> {
    use siem_config::modules::{CAGENT_CONFIG, CLABELS};
    let mut labels = Vec::new();
    let mut ctx = ConfigContext::new(Platform::AGENT);
    let r = read_config(&mut ctx, CLABELS, OSSECCONF, None, &mut LabelsHandler(&mut labels));
    flush_log(log, &mut ctx);
    r.map_err(|_| ())?;
    let mut ctx = ConfigContext::new(Platform::AGENT);
    ctx.agent = siem_agentd::config::agent_identity();
    let _ = read_config(&mut ctx, CLABELS | CAGENT_CONFIG, AGENTCONFIG, Some(remote_conf), &mut LabelsHandler(&mut labels));
    flush_log(log, &mut ctx);
    Ok(labels)
}

/// `WM_SYS_LOGTAG` (ARGV0 ":syscollector")
const WM_SYS_LOGTAG: &str = "wazuh-agent:syscollector";

impl WModules {
    /// `wm_config()`: Err on a configuration error (the agent exits).
    pub fn config(ag: &Agentd) -> Result<WModules, ()> {
        let task_nice = ag.define_int("wazuh_modules", "task_nice", -20, 19);
        siem_execd::wm_exec::WM_TASK_NICE.store(task_nice, std::sync::atomic::Ordering::Relaxed);
        let max_eps = ag.define_int("wazuh_modules", "max_eps", 1, 1000);
        let kill_timeout = ag.define_int("wazuh_modules", "kill_timeout", 0, 3600);
        let mut sys: Option<WmSys> = None;
        let mut sca: Option<siem_sca::wm::WmSca> = None;
        let mut ctx = ConfigContext::new(Platform::AGENT);
        // wm_initialize_default_modules: agent-upgrade
        let mut up = crate::upgrade::Config::default();
        let mut order: Vec<&'static str> = vec![crate::upgrade::NAME];
        if crate::upgrade::read(&mut ctx, &ag.log, None, None, &mut up).is_err() {
            siem_agentd::config::flush_ctx(ag, &mut ctx);
            return Err(());
        }
        let mut commands: Commands = Vec::new();
        let mut osquery: Option<crate::wm_osquery::WmOsquery> = None;
        let r = read_config(&mut ctx, siem_config::modules::CWMODULE, OSSECCONF, None, &mut Handler { sys: &mut sys, sca: &mut sca, up: &mut up, log: &ag.log, order: &mut order, commands: &mut commands, osquery: &mut osquery, agent_cfg: false });
        siem_agentd::config::flush_ctx(ag, &mut ctx);
        if r.is_err() {
            return Err(());
        }
        // agent.conf (errors do not stop the agent)
        let mut ctx = ConfigContext::new(Platform::AGENT);
        ctx.agent = siem_agentd::config::agent_identity();
        let remote = Some(ag.define_int("agent", "remote_conf", 0, 1) != 0);
        let _ = read_config(
            &mut ctx,
            siem_config::modules::CWMODULE | siem_config::modules::CAGENT_CONFIG,
            AGENTCONFIG,
            remote,
            &mut Handler { sys: &mut sys, sca: &mut sca, up: &mut up, log: &ag.log, order: &mut order, commands: &mut commands, osquery: &mut osquery, agent_cfg: true },
        );
        siem_agentd::config::flush_ctx(ag, &mut ctx);
        let mut modules = Vec::new();
        let mut commands = commands.into_iter();
        for tag in order {
            if tag == crate::wm_command::NAME {
                if let Some((t, c)) = commands.next() {
                    modules.push(Module::Command(t, c));
                }
                continue;
            }
            if tag == crate::wm_osquery::NAME {
                if let Some(o) = osquery.take() {
                    modules.push(Module::Osquery(o));
                }
                continue;
            }
            if tag == crate::upgrade::NAME {
                modules.push(Module::Upgrade(Arc::new(up.clone())));
            } else if tag == wmsys::NAME {
                if let Some(s) = sys.take() {
                    modules.push(Module::Syscollector(WmSysModule::new(s)));
                }
            } else if tag == siem_sca::wm::NAME {
                if let Some(s) = sca.take() {
                    let env = siem_sca::wm::Env {
                        log: ag.log.clone(),
                        // wm_sendmsg(.., WM_SCA_STAMP, SCA_MQ) -> SendMSG
                        send: Box::new(|m| siem_ipc::mq_op::send_msg(0, m, siem_sca::wm::WM_SCA_STAMP, siem_sca::wm::SCA_MQ)),
                        define_int: {
                            // getDefine_Int: exits on an invalid option
                            let (o, l) = (ag.opts.clone(), ag.log.clone());
                            Box::new(move |s, n, lo, hi| match o.get_int(s, n, lo, hi) {
                                Ok(v) => v,
                                Err(e) => {
                                    l.critical(e.0);
                                    siem_log::cexit::fatal_exit()
                                }
                            })
                        },
                        max_eps,
                        client: true,
                    };
                    modules.push(Module::Sca(siem_sca::wm::Sca::new(s, env)));
                }
            }
        }
        // getDefine_Int("wazuh_command", "remote_commands", 0, 1), read by each command thread in C
        let remote_commands = modules.iter().any(|m| matches!(m, Module::Command(..))) && ag.define_int("wazuh_command", "remote_commands", 0, 1) != 0;
        let remote_conf = ag.define_int("agent", "remote_conf", 0, 1) != 0;
        Ok(WModules { modules, task_nice, max_eps, kill_timeout, remote_commands, remote_conf, log: ag.log.clone(), sys_env: OnceLock::new() })
    }

    /// `wm_check()`: false when no module is configured.
    pub fn check(&self) -> bool {
        !self.modules.is_empty()
    }

    /// The module threads (`w_create_thread(cur_module->context->start, ...)`).
    pub fn start(self: &Arc<Self>) {
        for m in &self.modules {
            match m {
                Module::Upgrade(c) => {
                    let (c, log, eps) = (c.clone(), self.log.clone(), self.max_eps);
                    let _ = std::thread::Builder::new().name("wm_agent_upgrade_main".into()).spawn(move || crate::upgrade::main(&c, &log, eps));
                }
                Module::Sca(s) => {
                    let s = s.clone();
                    let _ = std::thread::Builder::new().name("wm_sca_main".into()).spawn(move || s.main());
                }
                Module::Command(_, c) => {
                    let (c, log, eps, remote) = (c.clone(), self.log.clone(), self.max_eps, self.remote_commands);
                    let _ = std::thread::Builder::new().name("wm_command_main".into()).spawn(move || crate::wm_command::main(c, log, eps, remote));
                }
                Module::Osquery(o) => {
                    let (l, remote) = (self.log.clone(), self.remote_conf);
                    let env = crate::wm_osquery::Env { log: self.log.clone(), max_eps: self.max_eps, read_labels: Box::new(move || read_labels(&l, remote)) };
                    let o = o.clone();
                    let _ = std::thread::Builder::new().name("wm_osquery_main".into()).spawn(move || crate::wm_osquery::main(o, env));
                }
                Module::Syscollector(sys) => {
                    let log = tagged(&self.log, WM_SYS_LOGTAG);
                    let l2 = log.clone();
                    let env = Arc::new(Env {
                        // wm_sendmsg_ex: Sleep(usec / 1000), then SendMSGPredicated
                        send: Box::new(|usec, msg, loc, stop| {
                            std::thread::sleep(std::time::Duration::from_millis((usec / 1000).max(0) as u64));
                            if siem_ipc::mq_op::send_msg_predicated(0, msg, wmsys::WM_SYS_LOCATION, loc, stop) < 0 {
                                -1
                            } else {
                                0
                            }
                        }),
                        reconnect: Box::new(|_| 0),
                        log: Box::new(move |lv, m| l2(lv, m)),
                        default_queue: "queue/sockets/queue".into(),
                        peer: "wazuh-agentd",
                    });
                    let _ = self.sys_env.set(env.clone());
                    let s = sys.clone();
                    let _ = std::thread::Builder::new().name("wm_sys_main".into()).spawn(move || {
                        let info: Arc<dyn siem_syscollector::port::syscollector::SysInfoSource> = Arc::new(siem_sysinfo::SysInfo);
                        s.main(env, info, log);
                    });
                }
            }
        }
    }

    /// `stop_wmodules`: the modules' `stop` callbacks (only syscollector has one on Windows).
    pub fn stop_wmodules(&self) {
        for m in &self.modules {
            if let Module::Syscollector(s) = m {
                if let Some(env) = self.sys_env.get() {
                    s.stop(env);
                }
            }
        }
    }

    /// `wm_sca_push_request_win(msg)`
    pub fn sca_push(&self, msg: &[u8]) {
        for m in &self.modules {
            if let Module::Sca(s) = m {
                s.push_request(msg);
            }
        }
    }

    /// `modulesSync(args)`
    pub fn modules_sync(&self, args: &str) -> i32 {
        let mut ret = -1;
        let mut retry = 0;
        let mut cur: Option<&Module> = None;
        loop {
            if retry > 0 {
                std::thread::sleep(std::time::Duration::from_micros(retry as u64 * WM_MAX_WAIT));
                self.log.debug1(format!("WModules is not ready. Retry {retry}"));
            }
            cur = None;
            for m in &self.modules {
                if m.tag().is_some_and(|t| args.contains(t)) {
                    cur = Some(m);
                    ret = 0;
                    if args.contains("dbsync") {
                        ret = match m {
                            Module::Syscollector(s) => s.sync_message(args),
                            Module::Sca(_) | Module::Upgrade(_) | Module::Command(..) | Module::Osquery(_) => -1,
                        };
                    }
                    break;
                }
            }
            retry += 1;
            if retry > WM_MAX_ATTEMPTS || ret == 0 {
                break;
            }
        }
        if ret != 0 {
            self.log.error(format!("At modulesSync(): Unable to sync module '{}': ({ret})", cur.and_then(|m| m.tag()).unwrap_or("")));
        }
        ret
    }

    /// `wmcom_sync(buffer)`
    pub fn wmcom_sync(&self, buffer: &str) -> i32 {
        let ret = self.modules_sync(buffer);
        if ret != 0 {
            self.log.debug1(format!("At WMCOM sync: Could not sync '{buffer}' buffer"));
        }
        ret
    }

    /// `getModulesConfig()`
    fn modules_config(&self) -> Json {
        let mut arr = Json::array();
        for m in &self.modules {
            match m {
                Module::Upgrade(c) => {
                    arr.push(crate::upgrade::dump(c));
                }
                Module::Syscollector(s) => {
                    arr.push(wmsys::wm_sys_dump(&s.sys.lock()));
                }
                Module::Sca(s) => {
                    arr.push(siem_sca::wm::wm_sca_dump(&s.cfg));
                }
                Module::Command(_, c) => {
                    arr.push(crate::wm_command::dump(c));
                }
                Module::Osquery(o) => {
                    arr.push(crate::wm_osquery::dump(o));
                }
            }
        }
        let mut root = Json::object();
        root.add("wmodules", arr);
        root
    }

    /// `getModulesInternalOptions()` (`wm_debug_level` is never set in the agent)
    fn internal_options(&self) -> Json {
        let mut i = Json::object();
        i.add("wazuh_modules.task_nice", Json::number(self.task_nice as f64));
        i.add("wazuh_modules.max_eps", Json::number(self.max_eps as f64));
        i.add("wazuh_modules.kill_timeout", Json::number(self.kill_timeout as f64));
        i.add("wazuh_modules.debug", Json::number(0.0));
        let mut root = Json::object();
        root.add("internal_options", i);
        root
    }

    /// `wmcom_dispatch(command, &output)`
    pub fn dispatch(&self, command: &[u8]) -> Vec<u8> {
        let cmd = String::from_utf8_lossy(command).into_owned();
        if cmd.starts_with("getconfig") {
            let Some(sp) = cmd.find(' ') else {
                self.log.debug1("WMCOM getconfig needs arguments.");
                return b"err WMCOM getconfig needs arguments".to_vec();
            };
            let section = &cmd[sp + 1..];
            let cfg = match section {
                "wmodules" => Some(self.modules_config()),
                "internal_options" => Some(self.internal_options()),
                _ => None,
            };
            return match cfg {
                Some(c) => {
                    let mut out = b"ok ".to_vec();
                    out.extend_from_slice(&c.print_unformatted());
                    out
                }
                None => {
                    self.log.debug1(format!("At WMCOM getconfig: Could not get '{section}' section"));
                    b"err Could not get requested section".to_vec()
                }
            };
        }
        if let Some(q) = cmd.strip_prefix("query ") {
            // wm_module_query: no ported module supports queries
            let Some(sp) = q.find(' ') else {
                return br#"err {"error":1,"message":"Module query needs arguments"}"#.to_vec();
            };
            let name = &q[..sp];
            return if self.modules.iter().any(|m| m.tag() == Some(name)) {
                br#"err {"error":3,"message":"This module does not support queries"}"#.to_vec()
            } else {
                br#"err {"error":2,"message":"Module not found or not configured"}"#.to_vec()
            };
        }
        if self.wmcom_sync(&cmd) == 0 {
            return Vec::new();
        }
        self.log.debug1(format!("WMCOM Unrecognized command '{cmd}'."));
        b"err Unrecognized command".to_vec()
    }
}
