//! `wazuh-agent.exe` (`win32/win_agent.c`, `win32/win_utils.c`): the
//! Windows agent. One process runs what Unix splits into daemons: agentd
//! (the main thread, `receiver_messages`), logcollector, and the other
//! components, as threads started by `local_start`.
//!
//! The components not ported yet (execd, syscheck/rootcheck and the modules)
//! are reached through [`siem_agentd::WinHooks`]; until they are, local
//! start-up treats them as their C code does when they are disabled or
//! fail to start.

#[cfg(not(windows))]
fn main() {
    eprintln!("wazuh-agent: the Windows agent runs on Windows only.");
    std::process::exit(1);
}

#[cfg(windows)]
mod service;

#[cfg(windows)]
fn main() {
    win::main();
}

#[cfg(windows)]
mod win {
    use std::path::Path;
    use std::sync::atomic::Ordering;
    use std::sync::{Arc, OnceLock};

    use siem_agentd::state::Update;
    use siem_agentd::{Agentd, AgentStatus, WinHooks};
    use siem_config::client::validate_address;
    use siem_config::internal_options::InternalOptions;
    use siem_log::WLog;
    use siem_logcollector::Lc;

    use crate::service;

    /// `ARGV0`
    const ARGV0: &str = "wazuh-agent";
    /// `OSSECCONF`
    const OSSECCONF: &str = "ossec.conf";

    static LOG: OnceLock<Arc<WLog>> = OnceLock::new();
    static AGENT: OnceLock<Arc<Agentd>> = OnceLock::new();

    fn log() -> &'static Arc<WLog> {
        LOG.get().expect("logger")
    }

    /// `agent_help`
    fn agent_help() -> ! {
        siem_log::crt_print(&format!(
            "\nWazuh {ARGV0} v4.14.7 .\n\
             Available options:\n\
             \t/?                This help message.\n\
             \t-h                This help message.\n\
             \thelp              This help message.\n\
             \tinstall-service   Installs as a service\n\
             \tuninstall-service Uninstalls as a service\n\
             \tstart             Manually starts (not from services)\n"
        ));
        siem_log::cexit::exit_process(1);
    }

    pub fn main() {
        let args: Vec<String> = std::env::args().collect();
        // Find where we are: the directory of argv[0]
        let argv0 = args.first().cloned().unwrap_or_default();
        let (mypath, myfile) = match argv0.rfind('\\') {
            Some(p) => (argv0[..p].to_string(), argv0[p + 1..].to_string()),
            None => (".".to_string(), argv0.clone()),
        };
        let log = Arc::new(WLog::new(ARGV0, Path::new("")));
        let _ = LOG.set(Arc::clone(&log));
        siem_ipc::os_net::set_logger(Arc::clone(&log));
        siem_fileop::set_logger(Arc::clone(&log));
        service::set_logger(Arc::clone(&log));
        if let Err(e) = std::env::set_current_dir(&mypath) {
            let n = e.raw_os_error().unwrap_or(0);
            log.plain(
                "CRITICAL",
                format!("(1133): Unable to chdir to directory '{mypath}' due to [({n})-({})].", siem_ipc::os_net::strerror(n)),
            );
            siem_log::cexit::fatal_exit();
        }
        let cwd = std::env::current_dir().map(|p| p.display().to_string()).unwrap_or_default();
        let myfinalpath = format!("\"{cwd}\\{myfile}\"");

        // The *_exit log functions stop the service first (WinSetError)
        siem_log::cexit::set_fatal_hook(Box::new(service::win_set_error));

        if let Some(a) = args.get(1) {
            match a.as_str() {
                "install-service" => siem_log::cexit::exit_process(service::install_service(&myfinalpath)),
                "uninstall-service" => siem_log::cexit::exit_process(service::uninstall_service()),
                "start" => {
                    local_start();
                }
                "/?" | "-h" | "help" => agent_help(),
                _ => {
                    log.plain("ERROR", format!("Unknown option: {a}"));
                    siem_log::cexit::exit_process(1);
                }
            }
        }

        // Start it
        if service::os_win_main(Box::new(|| local_start())) == 0 {
            log.plain("CRITICAL", "Unable to start WinMain.");
            siem_log::cexit::fatal_exit();
        }
        siem_log::cexit::exit_process(0);
    }

    /// `atexit(DeleteState)`: `<name>.state` in the install directory.
    extern "C" fn delete_state() {
        let _ = std::fs::remove_file(format!("{ARGV0}.state"));
    }

    /// `atexit(send_agent_stopped_message)`
    extern "C" fn stopped_hook() {
        if let Some(ag) = AGENT.get() {
            siem_agentd::start_agent::send_agent_stopped_message(ag);
        }
    }

    /// `w_create_thread`: a detached thread with the default stack.
    fn thread(name: &str, f: impl FnOnce() + Send + 'static) {
        let _ = std::thread::Builder::new().name(name.to_string()).spawn(f);
    }

    /// `local_start`
    fn local_start() -> ! {
        let log = Arc::clone(log());
        let cfg = OSSECCONF;
        let opts = InternalOptions::windows_agent(Path::new(""));

        // This must be always the first instruction
        crate::dll_verify::enable_dll_verification(&log);

        let ag = Arc::new(Agentd::new(Arc::clone(&log), opts.clone()));
        let _ = AGENT.set(Arc::clone(&ag));
        let win_debug_level = ag.define_int("windows", "debug", 0, 2);
        ag.win_debug_level.store(win_debug_level, Ordering::SeqCst);
        for _ in 0..win_debug_level {
            log.now_debug();
        }

        // w_logging_init()
        if let Err(_e) = log.init() {
            siem_log::cexit::fatal_exit();
        }

        // Start Winsock
        if siem_ipc::os_net::wsa_startup() != 0 {
            ag.exit_critical("WSAStartup() failed");
        }

        // Configuration file not present
        if std::fs::metadata(cfg).is_err() {
            ag.exit_critical(format!("Configuration file '{cfg}' not found"));
        }

        // Read agent config
        log.debug1("Reading agent configuration.");
        if siem_agentd::config::client_conf(&ag, cfg).is_err() {
            ag.exit_error(siem_agentd::CLIENT_ERROR);
        }
        let servers = ag.cfg.read().unwrap().server.clone();
        if servers.first().map(|s| s.rip.is_empty()).unwrap_or(true) {
            log.error(siem_agentd::AG_INV_IP);
            ag.exit_error(siem_agentd::CLIENT_ERROR);
        }
        if !validate_address(&servers) {
            log.error(format!("(4112): Invalid server address found: '{}'", servers[0].rip));
            ag.exit_error(siem_agentd::CLIENT_ERROR);
        }
        if !siem_agentd::config::validate_ipv6_link_local_interface(&ag, &servers) {
            log.error(siem_agentd::AG_INV_INT);
            ag.exit_error(siem_agentd::CLIENT_ERROR);
        }
        {
            let mut c = ag.cfg.write().unwrap();
            if c.notify_time == 0 {
                c.notify_time = siem_agentd::NOTIFY_TIME;
            }
            if c.max_time_reconnect_try == 0 {
                c.max_time_reconnect_try = siem_agentd::RECONNECT_TIME;
            }
            if c.max_time_reconnect_try <= c.notify_time {
                c.max_time_reconnect_try = c.notify_time * 3;
                log.info(format!(
                    "Max time to reconnect can't be less than notify_time({}), using notify_time*3 ({})",
                    c.notify_time, c.max_time_reconnect_try
                ));
            }
        }

        // Initialize sender (send_mutex is part of Agentd)
        let enrollment = ag.cfg.read().unwrap().enrollment.enabled;
        if enrollment {
            // If autoenrollment is enabled, we will avoid exit if there is no valid key
            ag.keys.lock().unwrap().pass_empty_keyfile = true;
        } else if !siem_agentd::keys::check_keys(&ag) {
            ag.exit_critical(siem_agentd::AG_NOKEYS_EXIT);
        }

        log.info(siem_agentd::ENC_READ);
        siem_agentd::keys::read_keys(&ag);

        let (notify_time, max_reconnect, force) = {
            let c = ag.cfg.read().unwrap();
            (c.notify_time, c.max_time_reconnect_try, c.force_reconnect_interval)
        };
        log.info(format!("Using notify time: {notify_time} and max time to reconnect: {max_reconnect}"));
        if force != 0 {
            let (v, u) = siem_agentd::time_value_unit(force);
            log.info(format!("Using force reconnect interval, Wazuh Agent will reconnect every {v} {u}"));
        }

        // Start execd thread (WinExecdStart: not ported yet, as disabled)
        if !crate::components::win_execd_start(&ag) {
            ag.execdq.store(-1, Ordering::SeqCst);
        }

        // Start mutex
        log.debug1("Creating thread mutex.");
        let a = Arc::clone(&ag);
        siem_ipc::mq_op::set_send_action(Box::new(move |m, l, q| siem_agentd::win::send_msg_action(&a, m, l, q)));

        // Set wait lock before starting threads
        siem_ipc::mq_op::os_setwait();

        // Initialize buffer before starting threads that may use it
        if ag.buffer_enabled() {
            siem_agentd::buffer::buffer_init(&ag);
        } else {
            log.info(siem_agentd::DISABLED_BUFFER);
        }

        // Start syscheck thread
        crate::components::start_syscheck(&ag);

        // Read logcollector config file
        log.debug1("Reading logcollector configuration.");
        let lc = Arc::new(Lc::new(Arc::clone(&log), opts.clone()));
        siem_logcollector::output::hash_queues_init(&lc);
        if siem_logcollector::config::log_collector_config(&lc, cfg) < 0 {
            ag.exit_error(format!("(1202): Configuration error at '{cfg}'."));
        }
        if lc.files.read().unwrap().logff.is_empty() {
            log.info("(1905): No file configured to monitor.");
        }

        // The components agentd calls in this process
        let lcd = Arc::clone(&lc);
        let mut hooks = WinHooks::default();
        hooks.dispatch.push(("logcollector", Box::new(move |b: &[u8]| siem_logcollector::lccom::lccom_dispatch(&lcd, b))));
        crate::components::register_hooks(&ag, &mut hooks);
        let _ = ag.hooks.set(hooks);

        // Start logcollector thread
        let lct = Arc::clone(&lc);
        thread("logcollector", move || siem_logcollector::collector::log_collector_start(lct));

        // Modules (wm_children_pool_init, wm_config, the module threads)
        crate::components::start_wmodules(&ag);

        // Socket connection
        ag.sock.store(-1, Ordering::SeqCst);

        // Initialize random numbers
        siem_agentd::keys::srandom_init();
        siem_agentd::keys::os_random();

        // Launch rotation thread
        let rotate = ag.define_int("monitord", "rotate_log", 0, 1);
        ag.ints.rotate_log.store(rotate, Ordering::SeqCst);
        if rotate != 0 {
            let a = Arc::clone(&ag);
            thread("rotate_log", move || siem_agentd::rotate_log::rotate_log_thread(&a));
        }

        // Launch dispatch thread
        if ag.buffer_enabled() {
            let a = Arc::clone(&ag);
            thread("dispatch_buffer", move || siem_agentd::buffer::dispatch_buffer(&a));
        }

        // Configure and start statistics
        siem_agentd::state::init(&ag);
        let a = Arc::clone(&ag);
        thread("state_main", move || siem_agentd::state::state_main(&a));

        siem_agentd::start_agent::start_agent(&ag, true);

        siem_ipc::mq_op::os_delwait();
        ag.state.update(Update::Status(AgentStatus::Active));

        // Start request module
        siem_agentd::request::req_init(&ag);
        let a = Arc::clone(&ag);
        thread("req_receiver", move || siem_agentd::request::req_receiver(&a));

        // Delete agent state file at exit
        siem_log::cexit::register(delete_state);
        // Send agent stopped message at exit
        siem_log::cexit::register(stopped_hook);

        // Start receiver -- main process here
        siem_agentd::win::receiver_messages(&ag)
    }
}

#[cfg(windows)]
mod components;
#[cfg(windows)]
mod dll_verify;
#[cfg(windows)]
mod upgrade;
#[cfg(windows)]
mod wmodules;
