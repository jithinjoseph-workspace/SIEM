//! `os_execd/config.c`: `ExecdConfig` (`<active-response><disabled>` and
//! `<repeated_offenders>`), `getARConfig`, `getExecdInternalOptions` and
//! `getClusterConfig`.

use std::sync::atomic::Ordering;

use siem_cjson::Json;
use siem_xml::OsXml;

use crate::*;

/// `ExecdConfig`: 1 when active response is disabled, 0 when enabled, -1 on
/// a configuration error.
pub fn execd_config(ex: &Execd, cfgfile: &str) -> i32 {
    ex.is_disabled.store(0, Ordering::SeqCst);
    let mut xml = match OsXml::read_file(cfgfile, false) {
        Ok(x) => x,
        Err(e) => ex.exit_critical(format!("(1226): Error reading XML file '{cfgfile}': {} (line {}).", e.message, e.line)),
    };

    // We do not validate the xml in here. It is done by other processes.
    if let Some(d) = xml.get_one_content_for_element(&["ossec_config", "active-response", "disabled"]) {
        match d.as_str() {
            "yes" => ex.is_disabled.store(1, Ordering::SeqCst),
            "no" => ex.is_disabled.store(0, Ordering::SeqCst),
            _ => {
                ex.log.error(format!("(1235): Invalid value for element 'disabled': {d}."));
                return -1;
            }
        }
    }

    // The first <repeated_offenders> of any <active-response> block
    let mut repeated_t: Option<String> = None;
    'outer: for node in xml.get_elements_by_node(None).unwrap_or_default() {
        for child in xml.get_elements_by_node(Some(&node)).unwrap_or_default() {
            if child.element == "active-response" {
                for attr in xml.get_elements_by_node(Some(&child)).unwrap_or_default() {
                    if attr.element == "repeated_offenders" {
                        repeated_t = Some(attr.content.clone().unwrap_or_default());
                        break 'outer;
                    }
                }
            }
        }
    }

    if let Some(rt) = repeated_t {
        let Some(parts) = siem_regex::str_break(',', &rt, 5) else {
            ex.log.error(format!("(1235): Invalid value for element 'repeated_offenders': {rt}."));
            return -1;
        };
        let mut rot = ex.repeated_offenders_timeout.lock().unwrap();
        let mut j = 0;
        for p in parts {
            let t = p.trim_start_matches([' ', '\t']);
            if t.is_empty() {
                continue;
            }
            rot[j] = siem_config::util::atoi(t);
            ex.log.info(format!("Adding offenders timeout: {} (for #{})", rot[j], j + 1));
            j += 1;
            rot[j] = 0;
            if j >= 6 {
                break;
            }
        }
    }
    ex.is_disabled.load(Ordering::SeqCst)
}

/// `getARConfig`
pub fn get_ar_config(ex: &Execd) -> Json {
    let mut ar = Json::object();
    ar.add("disabled", Json::string(if ex.is_disabled() { "yes" } else { "no" }));
    let rot = *ex.repeated_offenders_timeout.lock().unwrap();
    if rot[0] != 0 {
        let mut a = Json::array();
        for v in rot.iter().take_while(|&&v| v != 0) {
            a.push(Json::number(*v as f64));
        }
        ar.add("repeated_offenders", a);
    }
    let mut root = Json::object();
    root.add("active-response", ar);
    root
}

/// `getExecdInternalOptions`
pub fn get_internal_options(ex: &Execd) -> Json {
    let mut e = Json::object();
    e.add("request_timeout", Json::number(ex.req_timeout.load(Ordering::SeqCst) as f64));
    e.add("max_restart_lock", Json::number(ex.max_restart_lock.load(Ordering::SeqCst) as f64));
    let mut internals = Json::object();
    internals.add("execd", e);
    let mut root = Json::object();
    root.add("internal", internals);
    root
}

/// `getClusterConfig` (no cluster on Windows)
#[cfg(windows)]
pub fn get_cluster_config(_ex: &Execd) -> Option<Json> {
    None
}

/// `getClusterConfig`: `get_config` through the cluster socket.
#[cfg(unix)]
pub fn get_cluster_config(ex: &Execd) -> Option<Json> {
    use siem_ipc::os_net;
    /// `WAZUH_IPC_TIMEOUT`
    const WAZUH_IPC_TIMEOUT: i64 = 600;
    let sock = os_net::external_socket_connect(CLUSTER_SOCK, WAZUH_IPC_TIMEOUT);
    if sock < 0 {
        let e = errno();
        ex.log.error(format!("At getClusterConfig(): Could not connect to socket '{CLUSTER_SOCK}': {} ({e}).", strerror(e)));
        return None;
    }
    // OS_SendSecureTCPCluster(sock, "get_config", "", 0)
    if crate::wcom::send_secure_tcp_cluster(sock, b"get_config", b"") != 0 {
        ex.log.error(format!("send(): {}", strerror(errno())));
        os_net::close_fd(sock);
        return None;
    }
    let mut buffer = Vec::new();
    let r = crate::wcom::recv_secure_cluster_tcp(sock, &mut buffer, OS_MAXSTR);
    os_net::close_fd(sock);
    match r {
        -2 => {
            ex.log.error("Cluster error detected");
            return None;
        }
        -1 => {
            ex.log.error(format!("At wcom_main(): OS_RecvSecureClusterTCP(): {}", strerror(errno())));
            return None;
        }
        0 => {
            ex.log.debug1("Empty message from local client.");
            return None;
        }
        _ => {}
    }
    // the buffer is calloc'd: the text ends at the first NUL
    if let Some(z) = buffer.iter().position(|&c| c == 0) {
        buffer.truncate(z);
    }
    match siem_cjson::parse_with_opts(&buffer, false) {
        Ok((j, _)) => Some(j),
        Err(_) => {
            ex.log.debug1(format!("Error parsing JSON event. {}", String::from_utf8_lossy(&buffer)));
            None
        }
    }
}
