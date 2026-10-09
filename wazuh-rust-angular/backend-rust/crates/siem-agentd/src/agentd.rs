//! `client-agent/agentd.c` (`AgentdStart`): start-up, the worker threads
//! and the main loop that multiplexes the manager socket and the local
//! event queue, plus the SIGUSR1 configuration reload.

use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};

use siem_config::labels::Label;
use siem_config::modules::*;
use siem_ipc::mq_op::{os_delwait, os_setwait, start_mq, READ, WRITE};

use crate::state::Update;
use crate::*;

/// The daemon, for the C-style signal and exit hooks.
static AGENTD: OnceLock<Arc<Agentd>> = OnceLock::new();
/// Set by the SIGUSR1 handler.
static SIGUSR1_PENDING: AtomicBool = AtomicBool::new(false);

extern "C" fn reload_handler(_sig: libc::c_int) {
    SIGUSR1_PENDING.store(true, Ordering::SeqCst);
}

/// `atexit(send_agent_stopped_message)`
extern "C" fn stopped_hook() {
    if let Some(ag) = AGENTD.get() {
        crate::start_agent::send_agent_stopped_message(ag);
    }
}

fn spawn(name: &str, ag: &Arc<Agentd>, f: fn(&Agentd)) {
    let a = Arc::clone(ag);
    let _ = std::thread::Builder::new().name(name.to_string()).spawn(move || f(&a));
}

/// `w_seconds_to_time_value` / `w_seconds_to_time_unit(s, TRUE)`
fn time_value_unit(s: i64) -> (i64, &'static str) {
    const W: i64 = 604800;
    const D: i64 = 86400;
    const H: i64 = 3600;
    const M: i64 = 60;
    if s < 0 {
        (-1, "invalid")
    } else if s >= W {
        (s / W, "week(s)")
    } else if s >= D {
        (s / D, "day(s)")
    } else if s >= H {
        (s / H, "hour(s)")
    } else if s >= M {
        (s / M, "minute(s)")
    } else {
        (s, "second(s)")
    }
}

/// `AgentdStart`
pub fn agentd_start(ag: Arc<Agentd>, home: &Path, user: &str, group: &str, run_foreground: bool) -> ! {
    let _ = AGENTD.set(Arc::clone(&ag));
    ag.available_server.store(0, Ordering::SeqCst);

    if !run_foreground {
        ag.log.now_daemon();
        siem_daemon::go_daemon(&ag.log);
    }

    if let Err(e) = siem_daemon::privsep(user, group, home, false) {
        ag.exit_critical(e);
    }

    let enrollment = ag.cfg.read().unwrap().enrollment.enabled;
    if enrollment {
        // With auto-enrollment the agent may start without a valid key.
        ag.keys.lock().unwrap().pass_empty_keyfile = true;
    } else if !crate::keys::check_keys(&ag) {
        ag.exit_critical(AG_NOKEYS_EXIT);
    }

    ag.log.info(ENC_READ);
    crate::keys::read_keys(&ag);

    let (notify_time, max_reconnect, force) = {
        let c = ag.cfg.read().unwrap();
        (c.notify_time, c.max_time_reconnect_try, c.force_reconnect_interval)
    };
    ag.log.info(format!("Using notify time: {notify_time} and max time to reconnect: {max_reconnect}"));
    if force != 0 {
        let (v, u) = time_value_unit(force);
        ag.log.info(format!("Using force reconnect interval, Wazuh Agent will reconnect every {v} {u}"));
    }
    ag.log.info(format!("Version detected -> {}", siem_fileop::version_op::getuname()));

    os_setwait();

    let q = start_mq(DEFAULTQUEUE, READ, 0);
    if q < 0 {
        ag.exit_critical(format!("(1210): Queue '{DEFAULTQUEUE}' not accessible: '{}'", strerror(errno())));
    }
    ag.m_queue.store(q, Ordering::SeqCst);
    ag.sock.store(-1, Ordering::SeqCst);

    if siem_daemon::create_pid(ARGV0, std::process::id(), &ag.log).is_err() {
        ag.exit_critical(PID_ERROR);
    }
    ag.log.info(startup_msg(std::process::id()));

    // SAFETY: installing signal dispositions with valid handlers.
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_IGN);
        let mut act: libc::sigaction = std::mem::zeroed();
        act.sa_sigaction = reload_handler as extern "C" fn(libc::c_int) as libc::sighandler_t;
        act.sa_flags = libc::SA_RESTART;
        libc::sigaction(libc::SIGUSR1, &act, std::ptr::null_mut());
    }
    // The handler only sets a flag; this thread logs it like reload_handler.
    {
        let a = Arc::clone(&ag);
        let _ = std::thread::Builder::new().name("sigusr1".into()).spawn(move || loop {
            if SIGUSR1_PENDING.swap(false, Ordering::SeqCst) {
                // SAFETY: strsignal returns a static string.
                let name = unsafe { std::ffi::CStr::from_ptr(libc::strsignal(libc::SIGUSR1)) }.to_string_lossy().into_owned();
                a.log.info(format!("SIGNAL [({})-({name})] Received. Reload agentd.", libc::SIGUSR1));
                a.needs_config_reload.store(true, Ordering::SeqCst);
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        });
    }

    let rotate = ag.define_int("monitord", "rotate_log", 0, 1);
    ag.ints.rotate_log.store(rotate, Ordering::SeqCst);
    if rotate != 0 {
        spawn("rotate_log", &ag, crate::rotate_log::rotate_log_thread);
    }

    if ag.buffer_enabled() {
        crate::buffer::buffer_init(&ag);
        spawn("dispatch_buffer", &ag, crate::buffer::dispatch_buffer);
    } else {
        ag.log.info(DISABLED_BUFFER);
    }

    crate::state::init(&ag);
    spawn("state_main", &ag, |a| crate::state::state_main(a));

    crate::start_agent::start_agent(&ag, true);
    os_delwait();
    ag.state.update(Update::Status(AgentStatus::Active));

    crate::request::req_init(&ag);
    spawn("req_receiver", &ag, crate::request::req_receiver);

    // SAFETY: registering an extern "C" hook.
    unsafe { libc::atexit(stopped_hook) };

    crate::notify::run_notify(&ag);

    loop {
        crate::notify::run_notify(&ag);

        let sock = ag.sock();
        let mq = ag.m_queue.load(Ordering::SeqCst);
        let maxfd = sock.max(mq) + 1;
        // SAFETY: fd_set manipulation and select on our own descriptors.
        let (rc, sock_ready, mq_ready) = unsafe {
            let mut set: libc::fd_set = std::mem::zeroed();
            let mut tv = libc::timeval { tv_sec: 1, tv_usec: 0 };
            let mut rc;
            loop {
                libc::FD_ZERO(&mut set);
                if sock >= 0 {
                    libc::FD_SET(sock, &mut set);
                }
                libc::FD_SET(mq, &mut set);
                rc = libc::select(maxfd, &mut set, std::ptr::null_mut(), std::ptr::null_mut(), &mut tv);
                if !(rc < 0 && errno() == libc::EINTR) {
                    break;
                }
            }
            (rc, sock >= 0 && libc::FD_ISSET(sock, &set), libc::FD_ISSET(mq, &set))
        };
        if rc == -1 {
            ag.exit_critical(select_error(errno()));
        } else if rc == 0 {
            continue;
        }

        if ag.needs_config_reload.swap(false, Ordering::SeqCst) {
            reload_config(&ag);
        }

        if ag.execdq.load(Ordering::SeqCst) <= 0 {
            let q = start_mq(EXECQUEUE, WRITE, 1);
            if q < 0 {
                ag.log.debug1("Unable to connect to the active response queue (disabled).");
                ag.execdq.store(-1, Ordering::SeqCst);
            } else {
                ag.execdq.store(q, Ordering::SeqCst);
            }
        }

        if sock_ready && crate::receiver::receive_msg(&ag) < 0 {
            ag.state.update(Update::Status(AgentStatus::NActive));
            ag.log.error(LOST_ERROR);
            os_setwait();
            crate::start_agent::start_agent(&ag, false);
            ag.log.info(SERVER_UP);
            os_delwait();
            ag.state.update(Update::Status(AgentStatus::Active));
        }

        if mq_ready {
            crate::sendmsg::event_forward(&ag);
        }
    }
}

/// The `needs_config_reload` block of the main loop.
fn reload_config(ag: &Agentd) {
    let q = ag.execdq.swap(-1, Ordering::SeqCst);
    // SAFETY: closing our own descriptor (C closes it unconditionally).
    unsafe { libc::close(q) };

    let (current_capacity, current_flag) = {
        let c = ag.cfg.read().unwrap();
        (c.buflength, c.buffer)
    };
    ag.log.debug2(format!("Buffer pre-update, enable: {} size: {current_capacity} ", i32::from(current_flag)));

    let mut agent = ag.cfg.read().unwrap().clone();
    let mut labels: Vec<Label> = Vec::new();
    let mut pu = ag.package_uninstallation.load(Ordering::SeqCst);
    if crate::config::read(ag, CLABELS | CBUFFER, OSSECCONF, &mut agent, &mut labels, &mut pu).is_err() {
        ag.exit_error(CLIENT_ERROR);
    }
    if ag.remote_conf_flag.load(Ordering::SeqCst) {
        let _ = crate::config::read(ag, CLABELS | CBUFFER | CAGENT_CONFIG, AGENTCONFIG, &mut agent, &mut labels, &mut pu);
        ag.log.info(format!("Buffer agent.conf updated, enable: {} size: {} ", i32::from(agent.buffer), agent.buflength));
    }
    let (new_flag, new_len) = (agent.buffer, agent.buflength);
    *ag.cfg.write().unwrap() = agent;
    *ag.labels.write().unwrap() = Arc::new(labels);

    if !new_flag && current_flag {
        crate::buffer::buffer_free(ag, current_capacity as u32);
    } else if !current_flag && new_flag {
        crate::buffer::buffer_init(ag);
        let a = AGENTD.get().cloned();
        if let Some(a) = a {
            spawn("dispatch_buffer", &a, crate::buffer::dispatch_buffer);
        }
    } else if new_flag {
        crate::buffer::buffer_resize(ag, current_capacity as u32, new_len as u32);
    }
    let c = ag.cfg.read().unwrap();
    ag.log.debug2(format!("Buffer updated, enable: {} size: {} ", i32::from(c.buffer), c.buflength));
}
