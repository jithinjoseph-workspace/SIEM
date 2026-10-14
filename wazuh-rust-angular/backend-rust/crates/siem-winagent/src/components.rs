//! The in-process components of `wazuh-agent.exe` besides agentd and
//! logcollector.
//!
//! * execd (`WinExecdStart`): ported (`siem-execd`). agentd pushes `execd`
//!   messages to its queue, runs `ExecdTimeoutRun` from its main loop and
//!   sends the `com` requests to `wcom_dispatch`.
//! * syscheck + rootcheck and the modules: their ports are the next step;
//!   until then `local_start` sees them as the C code sees them when they
//!   are disabled (no thread, no `syscheck` / `wmodules` / `upgrade`
//!   request targets).

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

/// The `skthread` (`Start_win32_Syscheck`).
pub fn start_syscheck(_ag: &Agentd) {}

static WMODULES: OnceLock<Arc<crate::wmodules::WModules>> = OnceLock::new();

/// `wm_children_pool_init` + `wm_config` + the module threads.
pub fn start_wmodules(ag: &Agentd) {
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

/// The dispatchers and queues of these components.
pub fn register_hooks(_ag: &Agentd, hooks: &mut WinHooks) {
    // req_receiver: "wmodules" -> wmcom_dispatch; receiver: syscollector dbsync -> wmcom_sync
    hooks.dispatch.push((
        "wmodules",
        Box::new(|b: &[u8]| match WMODULES.get() {
            Some(w) => w.dispatch(b),
            None => b"err Unrecognized command".to_vec(),
        }),
    ));
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
