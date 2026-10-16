//! The in-process components of `wazuh-agent.exe` besides agentd and
//! logcollector.
//!
//! * execd (`WinExecdStart`): ported (`siem-execd`). agentd pushes `execd`
//!   messages to its queue, runs `ExecdTimeoutRun` from its main loop and
//!   sends the `com` requests to `wcom_dispatch`.
//! * syscheck + rootcheck (`skthread`), the modules (`wmodules`) and the
//!   agent-upgrade commands: the `syscheck`, `wmodules` and `upgrade`
//!   request targets.

use std::sync::{Arc, OnceLock};

use siem_agentd::{Agentd, WinHooks};
use siem_execd::execd::ExecQueue;
use siem_execd::Execd;

static EXECD: OnceLock<(Arc<Execd>, Arc<ExecQueue>)> = OnceLock::new();

/// `WinExecdStart`: true when active response runs.
pub fn win_execd_start(ag: &Agentd) -> bool {
    let ex = Arc::new(Execd::new(Arc::clone(&ag.log), ag.opts.clone()));
    let q = Arc::new(ExecQueue::new());
    let _ = EXECD.set((Arc::clone(&ex), Arc::clone(&q)));
    siem_execd::execd::win_execd_start(&ex, &q)
}

static SYSCHECK: OnceLock<Arc<siem_syscheckd::port::syscheck::Syscheck>> = OnceLock::new();

/// The `skthread` (`Start_win32_Syscheck`): FIM (files, registry, report_changes,
/// realtime, whodata) and rootcheck.
pub fn start_syscheck(ag: &Agentd) {
    let opts = ag.opts.clone();
    let log = Arc::clone(&ag.log);
    let remote_conf = ag.define_int("agent", "remote_conf", 0, 1) != 0;
    let _ = std::thread::Builder::new().name("skthread".into()).spawn(move || {
        let l2 = Arc::clone(&log);
        let define_int = move |s: &str, n: &str, lo: i32, hi: i32| match opts.get_int(s, n, lo, hi) {
            Ok(v) => v,
            Err(e) => {
                l2.critical(e.0);
                siem_log::cexit::fatal_exit()
            }
        };
        let l3 = Arc::clone(&log);
        let flush = move |ctx: &mut siem_config::ConfigContext| {
            for (lv, m) in ctx.log.drain(..) {
                match lv {
                    siem_config::LogLevel::Debug1 => l3.debug1(m),
                    siem_config::LogLevel::Debug2 => l3.debug2(m),
                    siem_config::LogLevel::Info => l3.info(m),
                    siem_config::LogLevel::Warn => l3.warn(m),
                    siem_config::LogLevel::Error => l3.error(m),
                }
            }
        };
        let env = siem_syscheckd::port::syscheck::Env {
            log: &log,
            define_int: &define_int,
            flush: &flush,
            platform: siem_config::Platform::AGENT,
            agent: siem_agentd::config::agent_identity(),
            remote_conf,
        };
        siem_syscheckd::port::set_log(Arc::clone(&log));
        let sk = Arc::new(siem_syscheckd::port::syscheck::start_config(&env));
        let _ = SYSCHECK.set(Arc::clone(&sk));
        // fim_send_msg: SendMSGPredicated(syscheck.queue, msg, location, mq, fim_shutdown_process_on)
        let send = Box::new(|mq: u8, loc: &str, msg: &[u8]| {
            siem_ipc::mq_op::send_msg_predicated(0, msg, loc, mq, &siem_syscheckd::port::syscheck::fim_shutdown_process_on)
        });
        siem_syscheckd::port::syscheck::start(sk, send);
    });
}

static WMODULES: OnceLock<Arc<crate::wmodules::WModules>> = OnceLock::new();

/// `wm_children_pool_init` + `wm_config` + the module threads.
pub fn start_wmodules(ag: &Agentd) {
    siem_execd::wm_exec::wm_children_pool_init();
    match crate::wmodules::WModules::config(ag) {
        Ok(w) => {
            let w = Arc::new(w);
            let _ = WMODULES.set(w.clone());
            if w.check() {
                w.start();
            }
        }
        // mlerror_exit(LOGLEVEL_ERROR, CONFIG_ERROR, cfg)
        Err(()) => ag.exit_error("(1202): Configuration error at 'ossec.conf'."),
    }
}

/// What the service stop runs (`OssecServiceCtrlHandler`, SERVICE_CONTROL_STOP):
/// `wm_kill_children(); stop_wmodules(); is_fim_shutdown = true; fim_db_teardown();`
pub fn on_service_stop() {
    siem_execd::wm_exec::wm_kill_children();
    if let Some(w) = WMODULES.get() {
        w.stop_wmodules();
    }
    siem_syscheckd::port::syscheck::shutdown();
}

/// The dispatchers and queues of these components.
pub fn register_hooks(_ag: &Agentd, hooks: &mut WinHooks) {
    // req_receiver: "syscheck" -> syscom_dispatch
    let sklog = Arc::clone(&_ag.log);
    hooks.dispatch.push((
        "syscheck",
        Box::new(move |b: &[u8]| match SYSCHECK.get() {
            Some(s) => s.dispatch(&sklog, b),
            None => b"err Could not get requested section".to_vec(),
        }),
    ));
    // req_receiver: "wmodules" -> wmcom_dispatch; receiver: syscollector dbsync -> wmcom_sync
    hooks.dispatch.push((
        "wmodules",
        Box::new(|b: &[u8]| match WMODULES.get() {
            Some(w) => w.dispatch(b),
            None => b"err Unrecognized command".to_vec(),
        }),
    ));
    // req_receiver: "upgrade" -> wm_agent_upgrade_process_command
    let (uplog, opts) = (Arc::clone(&_ag.log), _ag.opts.clone());
    hooks.dispatch.push((
        "upgrade",
        Box::new(move |b: &[u8]| {
            let define_int = |s: &str, n: &str, lo: i32, hi: i32| match opts.get_int(s, n, lo, hi) {
                Ok(v) => v,
                Err(e) => {
                    uplog.critical(e.0);
                    siem_log::cexit::fatal_exit()
                }
            };
            crate::upgrade::process_command(&uplog, &define_int, b)
        }),
    ));
    // receiver: sca-dump -> wm_sca_push_request_win
    hooks.sca_push = Some(Box::new(|b: &[u8]| {
        if let Some(w) = WMODULES.get() {
            w.sca_push(b);
        }
    }));
    hooks.wmcom_sync = Some(Box::new(|b: &[u8]| {
        if let Some(w) = WMODULES.get() {
            w.wmcom_sync(&String::from_utf8_lossy(b));
        }
    }));
    if let Some((ex, q)) = EXECD.get() {
        let (e1, e2, q1) = (Arc::clone(ex), Arc::clone(ex), Arc::clone(q));
        // queue_push_ex(winexec_queue, strdup(msg))
        hooks.execd_push = Some(Box::new(move |m: &[u8]| {
            q1.push(m);
        }));
        hooks.execd_timeout_run = Some(Box::new(move || {
            siem_execd::execd::execd_timeout_run(&e1);
        }));
        // req_receiver: "com" -> wcom_dispatch
        hooks.dispatch.push(("com", Box::new(move |b: &[u8]| siem_execd::wcom::wcom_dispatch(&e2, b))));
    }
}
