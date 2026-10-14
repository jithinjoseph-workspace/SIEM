//! The modules of `wazuh-agent.exe` (wazuh_modules/wmodules.c, wmcom.c and
//! config/wmodules-config.c as the Windows agent builds them): `wm_config`,
//! `wm_check`, the module threads, `modulesSync` and `wmcom_dispatch`.
//!
//! Ported modules: syscollector. The other wodles the C agent can run
//! (command, osquery, open-scap, cis-cat, SCA, agent-upgrade) are read as the
//! C reads unknown-but-valid ones: they are skipped until their ports land.

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
    Syscollector(Arc<WmSysModule>),
}

impl Module {
    fn tag(&self) -> &'static str {
        match self {
            Module::Syscollector(_) => wmsys::NAME,
        }
    }
}

/// `wmodules` and the internal options `wm_config` reads.
pub struct WModules {
    modules: Vec<Module>,
    task_nice: i32,
    max_eps: i32,
    kill_timeout: i32,
    log: Arc<WLog>,
    sys_env: OnceLock<Arc<Env>>,
}

/// The `<wodle>` sections (`Read_WModule`).
struct Handler<'a> {
    sys: &'a mut Option<WmSys>,
    order: &'a mut Vec<&'static str>,
}

impl ConfigHandler for Handler<'_> {
    fn section(&mut self, ctx: &mut ConfigContext, xml: &OsXml, section: Section, node: &XmlNode, children: Option<&[XmlNode]>) -> CResult<()> {
        if section != Section::Wodle {
            // <sca> (and the agent-upgrade section): their modules are not ported yet
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
            // Read by modules not ported yet (no message in the C either)
            "command" | "osquery" | "open-scap" | "cis-cat" => {}
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

/// `WM_SYS_LOGTAG` (ARGV0 ":syscollector")
const WM_SYS_LOGTAG: &str = "wazuh-agent:syscollector";

impl WModules {
    /// `wm_config()`: Err on a configuration error (the agent exits).
    pub fn config(ag: &Agentd) -> Result<WModules, ()> {
        let task_nice = ag.define_int("wazuh_modules", "task_nice", -20, 19);
        siem_execd::wm_exec::WM_TASK_NICE.store(task_nice, std::sync::atomic::Ordering::Relaxed);
        let max_eps = ag.define_int("wazuh_modules", "max_eps", 1, 1000);
        let kill_timeout = ag.define_int("wazuh_modules", "kill_timeout", 0, 3600);
        // wm_initialize_default_modules: agent-upgrade (not ported yet)
        let mut sys: Option<WmSys> = None;
        let mut order: Vec<&'static str> = Vec::new();
        let mut ctx = ConfigContext::new(Platform::AGENT);
        let r = read_config(&mut ctx, siem_config::modules::CWMODULE, OSSECCONF, None, &mut Handler { sys: &mut sys, order: &mut order });
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
            &mut Handler { sys: &mut sys, order: &mut order },
        );
        siem_agentd::config::flush_ctx(ag, &mut ctx);
        let mut modules = Vec::new();
        for tag in order {
            if tag == wmsys::NAME {
                if let Some(s) = sys.take() {
                    modules.push(Module::Syscollector(WmSysModule::new(s)));
                }
            }
        }
        Ok(WModules { modules, task_nice, max_eps, kill_timeout, log: ag.log.clone(), sys_env: OnceLock::new() })
    }

    /// `wm_check()`: false when no module is configured.
    pub fn check(&self) -> bool {
        !self.modules.is_empty()
    }

    /// The module threads (`w_create_thread(cur_module->context->start, ...)`).
    pub fn start(self: &Arc<Self>) {
        for m in &self.modules {
            match m {
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
                if args.contains(m.tag()) {
                    cur = Some(m);
                    ret = 0;
                    if args.contains("dbsync") {
                        ret = match m {
                            Module::Syscollector(s) => s.sync_message(args),
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
            self.log.error(format!("At modulesSync(): Unable to sync module '{}': ({ret})", cur.map(|m| m.tag()).unwrap_or("")));
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
                Module::Syscollector(s) => {
                    arr.push(wmsys::wm_sys_dump(&s.sys.lock()));
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
            return if self.modules.iter().any(|m| m.tag() == name) {
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
