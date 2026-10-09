//! `shared/enrollment_op.c` (`w_enrollment_request_key`) with the parts of
//! `os_auth/ssl.c` (`os_ssl_keys`) and `os_auth/check_cert.c`
//! (`check_x509_cert`) it uses: the agent asks authd (TLS, port 1515) for
//! a key and stores the reply in `etc/client.keys`.
//!
//! OpenSSL is used directly so the cipher list, protocol options and
//! certificate checks behave as in the C agent.

use std::io::Write;
use std::os::unix::io::FromRawFd;
use std::sync::Arc;

use openssl::error::ErrorStack;
use openssl::nid::Nid;
use openssl::ssl::{ErrorCode, HandshakeError, Ssl, SslContext, SslFiletype, SslMethod, SslOptions, SslStream, SslVerifyMode};
use openssl::x509::X509Ref;

use siem_config::client::EnrollmentConfig;
use siem_ipc::os_net;

use crate::*;

/// `OS_SIZE_65536 + OS_SIZE_4096`
const BUF_SIZE: usize = 65536 + 4096;
/// `DNS_MAX_LABELS` / `DNS_MAX_LABEL_LEN`
const DNS_MAX_LABELS: usize = 127;
const DNS_MAX_LABEL_LEN: usize = 63;
const VALID_AGENT_NAME_CHARS: &str = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_.-";

/// `ERR_print_errors_fp(stderr)`
fn print_errors(e: &ErrorStack) {
    for err in e.errors() {
        eprintln!("{err}");
    }
}

/// `OS_IsValidName`
pub fn is_valid_name(n: &str) -> bool {
    let b = n.as_bytes();
    if b.len() < 2 || b.len() > 128 || b[0] == b'.' {
        return false;
    }
    b.iter().all(|&c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_' || c == b'.')
}

/// `OS_IsValidID`
pub fn is_valid_id(id: &str) -> bool {
    id.len() <= 8 && id.bytes().all(|c| c.is_ascii_digit())
}

/// `OS_ConvertToValidAgentName`: drop every invalid character.
pub fn convert_to_valid_agent_name(n: &str) -> String {
    n.chars().filter(|c| VALID_AGENT_NAME_CHARS.contains(*c)).collect()
}

/// `os_ssl_keys(0, NULL, ciphers, cert, key, ca_cert, auto_method)`
fn os_ssl_keys(ag: &Agentd, cfg: &EnrollmentConfig) -> Option<SslContext> {
    let c = &cfg.cert;
    // get_ssl_context
    let mut b = SslContext::builder(SslMethod::tls()).ok()?;
    if !c.auto_method {
        b.set_options(SslOptions::NO_SSLV3 | SslOptions::NO_TLSV1 | SslOptions::NO_TLSV1_1);
    }
    if b.set_cipher_list(&c.ciphers).is_err() {
        return None;
    }
    if let Some(ca) = &c.ca_cert {
        ag.log.debug1("Peer verification requested.");
        if b.set_ca_file(ca).is_err() {
            ag.log.error(format!("Unable to read CA certificate file \"{ca}\""));
            return None;
        }
        let log = Arc::clone(&ag.log);
        b.set_verify_callback(SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT, move |ok, store| {
            if !ok {
                let depth = store.error_depth();
                let err = store.error();
                log.error(format!("Problem with certificate at depth {depth}"));
                if let Some(cert) = store.current_cert() {
                    log.error(format!("issuer =  {}", name_oneline(cert.issuer_name())));
                    log.error(format!("subject =  {}", name_oneline(cert.subject_name())));
                }
                log.error(format!("{}:{}", err.as_raw(), err.error_string()));
            }
            ok
        });
    }
    if let (Some(cert), Some(key)) = (&c.agent_cert, &c.agent_key) {
        if !load_cert_and_key(ag, &mut b, cert, key) {
            return None;
        }
    }
    ag.log.debug1("Returning CTX for client.");
    Some(b.build())
}

/// `X509_NAME_oneline`: "/C=ES/CN=name"
fn name_oneline(n: &openssl::x509::X509NameRef) -> String {
    let mut s = String::new();
    for e in n.entries() {
        let key = e.object().nid().short_name().unwrap_or("UNDEF");
        s.push('/');
        s.push_str(key);
        s.push('=');
        s.push_str(&String::from_utf8_lossy(e.data().as_slice()));
    }
    s
}

/// `load_cert_and_key`
fn load_cert_and_key(ag: &Agentd, b: &mut openssl::ssl::SslContextBuilder, cert: &str, key: &str) -> bool {
    let mtime_ok = std::fs::metadata(cert)
        .ok()
        .and_then(|m| m.modified().ok())
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs() > 0)
        .unwrap_or(false);
    if !mtime_ok {
        ag.log.error(format!("Unable to read certificate file (not found): {cert}"));
        return false;
    }
    if let Err(e) = b.set_certificate_chain_file(cert) {
        ag.log.error(format!("Unable to read certificate file: {cert}"));
        print_errors(&e);
        return false;
    }
    if let Err(e) = b.set_private_key_file(key, SslFiletype::PEM) {
        ag.log.error(format!("Unable to read private key file: {key}"));
        print_errors(&e);
        return false;
    }
    if let Err(e) = b.check_private_key() {
        ag.log.error("Unable to verify private key file");
        print_errors(&e);
        return false;
    }
    true
}

/// `label` of check_cert.c
struct Label {
    text: Vec<u8>,
}

/// `label_array`: `None` is VERIFY_FALSE (0 labels or a bad label).
fn label_array(name: &[u8]) -> Option<Vec<Label>> {
    let mut out = Vec::new();
    for part in name.split(|&c| c == b'.') {
        if out.len() == DNS_MAX_LABELS || part.len() > DNS_MAX_LABEL_LEN {
            return None;
        }
        out.push(Label { text: part.to_vec() });
    }
    // A trailing empty label (FQDN) is ignored
    if out.last().map(|l| l.text.is_empty()).unwrap_or(false) {
        out.pop();
    }
    Some(out)
}

/// `label_valid`
fn label_valid(l: &Label) -> bool {
    let t = &l.text;
    !t.is_empty()
        && t.len() <= DNS_MAX_LABEL_LEN
        && t[t.len() - 1].is_ascii_alphanumeric()
        && t.iter().all(|&c| c.is_ascii_alphanumeric() || c == b'-')
}

/// `check_hostname`
fn check_hostname(cert_name: &[u8], manager: &str) -> bool {
    // asn1_to_cstr
    if cert_name.is_empty() || cert_name.contains(&0) {
        return false;
    }
    let (Some(c), Some(m)) = (label_array(cert_name), label_array(manager.as_bytes())) else { return false };
    if m.is_empty() || c.is_empty() || m.len() != c.len() {
        return false;
    }
    let wildcard = usize::from(label_valid(&m[0]) && c[0].text == b"*");
    for i in wildcard..m.len() {
        if !label_valid(&m[i]) || !m[i].text.eq_ignore_ascii_case(&c[i].text) {
            return false;
        }
    }
    true
}

/// `check_ipaddr`
fn check_ipaddr(cert_ip: &[u8], manager: &str) -> bool {
    if let Ok(v4) = manager.parse::<std::net::Ipv4Addr>() {
        return cert_ip.len() == 4 && cert_ip == v4.octets();
    }
    if let Ok(v6) = manager.parse::<std::net::Ipv6Addr>() {
        return cert_ip.len() == 16 && cert_ip == v6.octets();
    }
    false
}

/// `check_x509_cert`: VERIFY_TRUE (1), VERIFY_FALSE (0), VERIFY_ERROR (-1).
fn check_x509_cert(ag: &Agentd, cert: Option<&X509Ref>, manager: &str) -> i32 {
    let Some(cert) = cert else { return -1 };
    ag.log.debug1("Checking certificate's subject alternative names.");
    let mut verified = false;
    if let Some(names) = cert.subject_alt_names() {
        for n in names.iter() {
            if verified {
                break;
            }
            if let Some(d) = n.dnsname() {
                verified = check_hostname(d.as_bytes(), manager);
            } else if let Some(ip) = n.ipaddress() {
                verified = check_ipaddr(ip, manager);
            }
        }
    }
    if !verified {
        ag.log.debug1("No matching subject alternative names found. Checking common name.");
        for e in cert.subject_name().entries_by_nid(Nid::COMMONNAME) {
            if check_hostname(e.data().as_slice(), manager) {
                verified = true;
                break;
            }
        }
    }
    i32::from(verified)
}

/// `w_enrollment_connect`: the TLS session, or `None` (-1 / -2 in C).
fn connect(ag: &Agentd, cfg: &EnrollmentConfig, server_address: &str, iface: u32) -> Option<SslStream<std::net::TcpStream>> {
    let ip_address = match server_address.find('/') {
        Some(p) => Some(server_address[p + 1..].to_string()),
        None => os_net::get_host(server_address, 3),
    };
    let Some(ip_address) = ip_address else {
        ag.log.error(format!("Could not resolve hostname: {server_address}\n"));
        return None;
    };
    let Some(ctx) = os_ssl_keys(ag, cfg) else {
        ag.log.error("Could not set up SSL connection! Check certification configuration.");
        return None;
    };
    let port = cfg.target.port;
    let sock = os_net::connect_tcp(port as u16, &ip_address, ip_address.contains(':'), iface);
    if sock < 0 {
        ag.log.error(format!("(1208): Unable to connect to enrollment service at '[{ip_address}]:{port}'"));
        return None;
    }
    if os_net::set_recv_timeout(sock, cfg.recv_timeout as i64, 0) < 0 {
        let e = errno();
        ag.log.warn(format!("(1339) Cannot set timeout: {} ({e}).", strerror(e)));
    }
    // SAFETY: `sock` is a connected socket we own; the stream closes it.
    let stream = unsafe { std::net::TcpStream::from_raw_fd(sock) };
    let ssl = Ssl::new(&ctx).ok()?;
    let tls = match ssl.connect(stream) {
        Ok(s) => s,
        Err(HandshakeError::Failure(mid)) | Err(HandshakeError::WouldBlock(mid)) => {
            let code = mid.error().code().as_raw();
            ag.log.error(format!(
                "SSL error ({code}). Connection refused by the manager. Maybe the port specified is incorrect."
            ));
            if let Some(st) = mid.error().ssl_error() {
                print_errors(st);
            }
            return None;
        }
        Err(HandshakeError::SetupFailure(e)) => {
            ag.log.error("SSL error (1). Connection refused by the manager. Maybe the port specified is incorrect.");
            print_errors(&e);
            return None;
        }
    };
    ag.log.debug1(format!("(1209): Connected to enrollment service at '[{ip_address}]:{port}'"));

    // w_enrollment_verify_ca_certificate
    if cfg.cert.ca_cert.is_none() {
        ag.log.debug1("Registering agent to unverified manager");
    } else {
        ag.log.info("Verifying manager's certificate");
        let peer = tls.ssl().peer_certificate();
        if check_x509_cert(ag, peer.as_deref(), server_address) != 1 {
            ag.log.error("Unable to verify server certificate");
            return None;
        }
        ag.log.info("Manager has been verified successfully");
    }
    Some(tls)
}

/// `w_enrollment_extract_agent_name`
fn extract_agent_name(ag: &Agentd, cfg: &EnrollmentConfig) -> Option<String> {
    let name = match &cfg.target.agent_name {
        Some(n) => n.clone(),
        None => {
            let mut buf = vec![0u8; 513];
            // SAFETY: gethostname into a 512-byte buffer.
            if unsafe { libc::gethostname(buf.as_mut_ptr().cast(), 511) } != 0 {
                ag.log.error("Unable to extract hostname. Custom agent name not set.");
                return None;
            }
            convert_to_valid_agent_name(&String::from_utf8_lossy(crate::keys::cstr(&buf)))
        }
    };
    if !cfg.allow_localhost && name == "localhost" {
        ag.log.error(format!("(4104): Invalid hostname: '{name}'."));
        return None;
    }
    if !is_valid_name(&name) {
        ag.log.error(format!("Invalid agent name \"{name}\". Please pick a valid name."));
        return None;
    }
    Some(name)
}

/// `w_enrollment_load_pass`
fn load_pass(ag: &Agentd, cfg: &mut EnrollmentConfig) {
    if cfg.cert.authpass.is_some() {
        return;
    }
    if let Ok(data) = std::fs::read(&cfg.cert.authpass_file) {
        // fgets(buf, 4095, fp)
        let line = data.split_inclusive(|&c| c == b'\n').next().unwrap_or(&[]);
        let line = &line[..line.len().min(4094)];
        let line = crate::keys::cstr(line);
        if line.len() > 2 {
            let l = line.strip_suffix(b"\n").unwrap_or(line);
            cfg.cert.authpass = Some(String::from_utf8_lossy(l).into_owned());
        }
        ag.log.info(format!("Using password specified on file: {}", cfg.cert.authpass_file));
    }
    if cfg.cert.authpass.is_none() {
        ag.log.info("No authentication password provided");
    }
}

/// `w_enrollment_send_message`
fn send_message(ag: &Agentd, cfg: &EnrollmentConfig, tls: &mut SslStream<std::net::TcpStream>) -> i32 {
    let Some(name) = extract_agent_name(ag, cfg) else { return -1 };
    ag.log.info(format!("Using agent name as: {name}"));

    let mut buf = match &cfg.cert.authpass {
        Some(p) => format!("OSSEC PASS: {p} OSSEC A:'{name}'"),
        None => format!("OSSEC A:'{name}'"),
    }
    .into_bytes();
    buf.truncate(2047);
    // w_enrollment_concat_agent_version: snprintf(opt, 32, " V:'%s'")
    let mut v = format!(" V:'{}'", cfg.agent_version).into_bytes();
    v.truncate(31);
    buf.extend_from_slice(&v);
    if let Some(g) = &cfg.target.centralized_group {
        let mut g = format!(" G:'{g}'").into_bytes();
        g.truncate(65535);
        buf.extend_from_slice(&g);
    }
    // w_enrollment_concat_src_ip
    match (&cfg.target.sender_ip, cfg.target.use_src_ip) {
        (Some(ip), false) => {
            if siem_regex::is_valid_ip(ip).0 != 0 {
                let mut o = format!(" IP:'{ip}'").into_bytes();
                o.truncate(253);
                buf.extend_from_slice(&o);
            } else {
                ag.log.error("Invalid IP address provided for sender IP.");
                return -1;
            }
        }
        (None, true) => buf.extend_from_slice(b" IP:'src'"),
        (Some(_), true) => {
            ag.log.error("Incompatible sender_ip options: Forcing IP while using use_source_ip flag.");
            return -1;
        }
        (None, false) => {}
    }
    // w_enrollment_concat_key: SHA1(id + name + raw_key)
    if let Some(e) = ag.keys.lock().unwrap().entry.as_ref() {
        let hash = siem_crypto::hashes::sha1_str(&format!("{}{}{}", e.id, e.name, e.key.raw_key));
        buf.extend_from_slice(format!(" K:'{hash}'").as_bytes());
    }
    buf.truncate(BUF_SIZE - 1);
    buf.push(b'\n');

    if let Err(e) = tls.ssl_write(&buf) {
        ag.log.error("SSL write error (unable to send message.)");
        ag.log.error("If Agent verification is enabled, agent key and certificates are required!");
        if let Some(st) = e.ssl_error() {
            print_errors(st);
        }
        return -1;
    }
    ag.log.debug1("Request sent to manager");
    0
}

/// `w_enrollment_store_key_entry`
fn store_key_entry(ag: &Agentd, keys: &str) -> i32 {
    use std::os::unix::fs::PermissionsExt;
    // TempFile(&file, KEYS_FILE, 0)
    let mut template = format!("{KEYS_FILE}.XXXXXX\0").into_bytes();
    // SAFETY: umask/mkstemp on a NUL-terminated template we own.
    let fd = unsafe {
        let old = libc::umask(0o177);
        let fd = libc::mkstemp(template.as_mut_ptr().cast());
        libc::umask(old);
        fd
    };
    if fd < 0 {
        ag.log.error(fopen_error(KEYS_FILE, errno()));
        return -1;
    }
    template.pop();
    let tmp = String::from_utf8_lossy(&template).into_owned();
    // SAFETY: fd comes from mkstemp and is owned by the File.
    let mut f = unsafe { std::fs::File::from_raw_fd(fd) };
    match std::fs::metadata(KEYS_FILE) {
        Ok(m) => {
            let _ = f.set_permissions(m.permissions());
        }
        Err(e) => {
            let n = e.raw_os_error().unwrap_or(0);
            ag.log.debug1(format!(
                "(1118): Could not retrieve information of file '{KEYS_FILE}' due to [({n})-({})].",
                strerror(n)
            ));
        }
    }
    if let Err(e) = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o640)) {
        let n = e.raw_os_error().unwrap_or(0);
        ag.log.error(format!("(1127): Could not chmod object '{tmp}' due to [({n})-({})].", strerror(n)));
        drop(f);
        let _ = std::fs::remove_file(&tmp);
        return -1;
    }
    let _ = writeln!(f, "{keys}");
    drop(f);
    // OS_MoveFile
    if let Err(e) = std::fs::rename(&tmp, KEYS_FILE) {
        ag.log.debug1(format!("Couldn't rename {KEYS_FILE}: {}", strerror(e.raw_os_error().unwrap_or(0))));
        let data = match std::fs::read(&tmp) {
            Ok(d) => d,
            Err(_) => {
                ag.log.error(format!("Couldn't open file '{tmp}'"));
                return -1;
            }
        };
        if std::fs::write(KEYS_FILE, data).is_err() {
            ag.log.error(format!("Couldn't open file '{KEYS_FILE}'"));
            let _ = std::fs::remove_file(&tmp);
            return -1;
        }
        let _ = std::fs::remove_file(&tmp);
    }
    0
}

/// `w_enrollment_process_agent_key`: `buffer` starts with "OSSEC K:'".
fn process_agent_key(ag: &Agentd, buffer: &[u8]) -> i32 {
    let keys = &buffer[9..];
    let Some(end) = keys.iter().position(|&c| c == b'\'') else {
        ag.log.error("Invalid keys format received.");
        return -1;
    };
    let keys = String::from_utf8_lossy(&keys[..end]).into_owned();
    // OS_StrBreak(' ', keys, 4)
    let entries = siem_regex::str_break(' ', &keys, 4).unwrap_or_default();
    let ok = entries.len() == 4
        && is_valid_id(&entries[0])
        && is_valid_name(&entries[1])
        && siem_regex::is_valid_ip(&entries[2]).0 != 0
        && is_valid_name(&entries[3]);
    if !ok {
        ag.log.error("One of the received key parameters does not have a valid format");
        return -1;
    }
    if store_key_entry(ag, &keys) == 0 {
        ag.log.info("Valid key received");
        return 0;
    }
    -1
}

/// `w_enrollment_process_response`
fn process_response(ag: &Agentd, tls: &mut SslStream<std::net::TcpStream>) -> i32 {
    let mut status = -1;
    let mut manager_error = false;
    let mut buf = vec![0u8; BUF_SIZE];
    ag.log.info("Waiting for server reply");
    let end = loop {
        match tls.ssl_read(&mut buf) {
            Ok(0) => break Ok(()),
            Ok(n) => {
                let msg = crate::keys::cstr(&buf[..n]).to_vec();
                if msg.len() > 7 && msg.starts_with(b"ERROR: ") {
                    if let Some(sp) = msg.iter().position(|&c| c == b' ') {
                        let rest = &msg[sp + 1..];
                        if !rest.is_empty() {
                            ag.log.error(format!("{} (from manager)", String::from_utf8_lossy(rest)));
                            manager_error = true;
                        }
                    }
                } else if msg.starts_with(b"OSSEC K:'") {
                    status = process_agent_key(ag, &msg);
                    break Ok(());
                }
            }
            Err(e) => break Err(e),
        }
    };
    match end {
        Ok(()) => ag.log.debug1("Connection closed."),
        Err(e) if e.code() == ErrorCode::ZERO_RETURN => ag.log.debug1("Connection closed."),
        Err(_) => {
            if !manager_error {
                ag.log.error("SSL read (unable to receive message)");
                ag.log.error("If Agent verification is enabled, agent key and certificates may be incorrect!");
            }
        }
    }
    status
}

/// `w_enrollment_request_key`: 0 when a key was received and stored.
pub fn request_key(ag: &Agentd, server_address: &str, network_interface: u32) -> i32 {
    let mut cfg = ag.cfg.read().unwrap().enrollment.clone();
    let (addr, iface) = if server_address.is_empty() {
        (cfg.target.manager_name.clone().unwrap_or_default(), cfg.target.network_interface)
    } else {
        (server_address.to_string(), network_interface)
    };
    ag.log.info(format!("Requesting a key from server: {addr}"));
    let Some(mut tls) = connect(ag, &cfg, &addr, iface) else { return -1 };
    load_pass(ag, &mut cfg);
    // The password read from the file is kept for the next requests.
    ag.cfg.write().unwrap().enrollment.cert.authpass = cfg.cert.authpass.clone();
    let mut ret = -1;
    if send_message(ag, &cfg, &mut tls) == 0 {
        ret = process_response(ag, &mut tls);
    }
    // OS_CloseSocket: shutdown, then close when the stream is dropped
    let _ = tls.get_ref().shutdown(std::net::Shutdown::Both);
    ret
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_and_ids() {
        assert!(is_valid_name("web-01.example"));
        assert!(!is_valid_name("a"));
        assert!(!is_valid_name(".hidden"));
        assert!(!is_valid_name("bad name"));
        assert!(is_valid_id("001"));
        assert!(!is_valid_id("123456789"));
        assert_eq!(convert_to_valid_agent_name("my host!"), "myhost");
    }

    #[test]
    fn hostname_matching() {
        assert!(check_hostname(b"manager.example.com", "manager.example.com"));
        assert!(check_hostname(b"*.example.com", "manager.example.com"));
        assert!(!check_hostname(b"*.example.com", "example.com"));
        assert!(check_hostname(b"Manager.Example.com.", "manager.example.com"));
        assert!(!check_hostname(b"other.example.com", "manager.example.com"));
        assert!(check_ipaddr(&[10, 0, 0, 1], "10.0.0.1"));
    }
}
