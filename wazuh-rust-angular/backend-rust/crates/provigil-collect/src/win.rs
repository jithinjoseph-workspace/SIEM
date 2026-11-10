//! Processes, connections and services through `windows-sys`: shared by the agent's inventory
//! and the live-response program, so that small program does not link the whole agent.

use super::{nonempty, tcp_state, PortInfo, ProcessInfo, ServiceInfo};
use std::ffi::c_void;
use std::mem::{offset_of, size_of, zeroed};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::ptr::{null, null_mut};

use windows_sys::core::BOOL;
use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, ERROR_INSUFFICIENT_BUFFER, ERROR_MORE_DATA, ERROR_SUCCESS, FILETIME, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    GetExtendedTcpTable, GetExtendedUdpTable, MIB_TCP6ROW_OWNER_PID, MIB_TCP6TABLE_OWNER_PID, MIB_TCPROW_OWNER_PID,
    MIB_TCPTABLE_OWNER_PID, MIB_UDP6ROW_OWNER_PID, MIB_UDP6TABLE_OWNER_PID, MIB_UDPROW_OWNER_PID, MIB_UDPTABLE_OWNER_PID,
    TCP_TABLE_OWNER_PID_ALL, UDP_TABLE_OWNER_PID,
};
use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};
use windows_sys::Win32::System::ProcessStatus::{K32GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS};
use windows_sys::Win32::System::RemoteDesktop::ProcessIdToSessionId;
use windows_sys::Win32::System::Services::{
    CloseServiceHandle, EnumServicesStatusExW, OpenSCManagerW, OpenServiceW, QueryServiceConfig2W, QueryServiceConfigW,
    ENUM_SERVICE_STATUS_PROCESSW, QUERY_SERVICE_CONFIGW, SC_ENUM_PROCESS_INFO, SC_HANDLE, SC_MANAGER_CONNECT,
    SC_MANAGER_ENUMERATE_SERVICE, SERVICE_AUTO_START, SERVICE_CONFIG_DESCRIPTION, SERVICE_DEMAND_START,
    SERVICE_DESCRIPTIONW, SERVICE_DISABLED, SERVICE_QUERY_CONFIG, SERVICE_RUNNING, SERVICE_STATE_ALL, SERVICE_STOPPED,
    SERVICE_WIN32,
};
use windows_sys::Win32::System::Threading::{GetProcessTimes, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};

// ---------------------------------------------------------------------------------------
// Small helpers (also used by the agent's other collectors)
// ---------------------------------------------------------------------------------------

pub fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// The text up to the first NUL of a wide-character buffer.
pub fn from_wide(buf: &[u16]) -> String {
    let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    String::from_utf16_lossy(&buf[..end])
}

/// The text a NUL-terminated wide-string pointer points to; `None` for null or empty.
///
/// # Safety
///
/// `p` is null or points to a NUL-terminated UTF-16 string.
pub unsafe fn pwstr(p: *const u16) -> Option<String> {
    if p.is_null() {
        return None;
    }
    let mut n = 0;
    while *p.add(n) != 0 {
        n += 1;
    }
    nonempty(&String::from_utf16_lossy(std::slice::from_raw_parts(p, n)))
}

pub fn last_error() -> u32 {
    unsafe { GetLastError() }
}

/// A 100-ns FILETIME as one number.
fn filetime(t: FILETIME) -> u64 {
    (u64::from(t.dwHighDateTime) << 32) | u64::from(t.dwLowDateTime)
}

// ---------------------------------------------------------------------------------------
// Processes
// ---------------------------------------------------------------------------------------

pub fn processes() -> Result<Vec<ProcessInfo>, String> {
    let snap = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    if snap.is_null() || snap == INVALID_HANDLE_VALUE {
        return Err(format!("process snapshot failed (error {})", last_error()));
    }
    let mut out = Vec::new();
    let mut e: PROCESSENTRY32W = unsafe { zeroed() };
    e.dwSize = size_of::<PROCESSENTRY32W>() as u32;
    let mut more = unsafe { Process32FirstW(snap, &mut e) } != 0;
    while more {
        out.push(process_info(&e));
        more = unsafe { Process32NextW(snap, &mut e) } != 0;
    }
    unsafe { CloseHandle(snap) };
    Ok(out)
}

fn process_info(e: &PROCESSENTRY32W) -> ProcessInfo {
    let pid = e.th32ProcessID;
    let mut p = ProcessInfo {
        pid,
        name: from_wide(&e.szExeFile),
        command_line: None,
        owner: None,
        parent_pid: e.th32ParentProcessID,
        memory_mb: 0,
        cpu_time_ms: 0,
        start_time: 0,
        priority: e.pcPriClassBase,
        threads: e.cntThreads,
        virtual_kb: None,
        session_id: None,
    };
    let mut session = 0u32;
    if unsafe { ProcessIdToSessionId(pid, &mut session) } != 0 {
        p.session_id = Some(session);
    }
    let h = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if h.is_null() {
        return p;
    }
    let mut pmc: PROCESS_MEMORY_COUNTERS = unsafe { zeroed() };
    pmc.cb = size_of::<PROCESS_MEMORY_COUNTERS>() as u32;
    if unsafe { K32GetProcessMemoryInfo(h, &mut pmc, pmc.cb) } != 0 {
        p.memory_mb = pmc.WorkingSetSize as u64 / (1024 * 1024);
        p.virtual_kb = Some(pmc.PagefileUsage as u64 / 1024);
    }
    let (mut created, mut exited, mut kernel, mut user) =
        (FILETIME::default(), FILETIME::default(), FILETIME::default(), FILETIME::default());
    if unsafe { GetProcessTimes(h, &mut created, &mut exited, &mut kernel, &mut user) } != 0 {
        p.cpu_time_ms = (filetime(kernel) + filetime(user)) / 10_000;
        // 100-ns ticks since 1601 → seconds since 1970
        p.start_time = (filetime(created) / 10_000_000).saturating_sub(11_644_473_600);
    }
    unsafe { CloseHandle(h) };
    p
}

// ---------------------------------------------------------------------------------------
// Ports
// ---------------------------------------------------------------------------------------

/// Calls an IP Helper "fill this table" function until the buffer is big enough.
fn ip_table(what: &str, get: impl Fn(*mut c_void, *mut u32) -> u32) -> Result<Vec<u64>, String> {
    let mut size = 16 * 1024u32;
    for _ in 0..5 {
        let mut buf = vec![0u64; (size as usize).div_ceil(8)];
        let mut len = (buf.len() * 8) as u32;
        match get(buf.as_mut_ptr().cast(), &mut len) {
            ERROR_SUCCESS => return Ok(buf),
            // the table can grow between the calls: some room to spare
            ERROR_INSUFFICIENT_BUFFER => size = len.saturating_add(4096),
            rc => return Err(format!("{what} table not read (error {rc})")),
        }
    }
    Err(format!("{what} table not read (kept growing)"))
}

/// The rows of an IP Helper table (a row count, then the rows from `offset`).
///
/// Safety: `buf` was filled by the table function whose rows are `R`.
unsafe fn rows<R: Copy>(buf: &[u64], offset: usize) -> Vec<R> {
    let base = buf.as_ptr() as *const u8;
    let n = (base as *const u32).read() as usize;
    let fit = (buf.len() * 8).saturating_sub(offset) / size_of::<R>();
    std::slice::from_raw_parts(base.add(offset) as *const R, n.min(fit)).to_vec()
}

/// A port number kept in network byte order in the low bytes of a DWORD.
fn port(p: u32) -> u16 {
    let b = p.to_ne_bytes();
    u16::from_be_bytes([b[0], b[1]])
}

/// An IPv4 address kept in network byte order in a DWORD.
fn v4(a: u32) -> IpAddr {
    IpAddr::V4(Ipv4Addr::from(a.to_ne_bytes()))
}

fn tcp(protocol: &str, local: (IpAddr, u32), remote: (IpAddr, u32), state: u32, pid: u32) -> PortInfo {
    let listening = state == 2;
    PortInfo {
        protocol: protocol.into(),
        local_ip: local.0.to_string(),
        local_port: port(local.1),
        remote_ip: (!listening).then(|| remote.0.to_string()),
        remote_port: (!listening).then(|| port(remote.1)),
        state: Some(tcp_state(state).into()),
        pid,
        process: None,
    }
}

fn udp(protocol: &str, local: (IpAddr, u32), pid: u32) -> PortInfo {
    PortInfo {
        protocol: protocol.into(),
        local_ip: local.0.to_string(),
        local_port: port(local.1),
        remote_ip: None,
        remote_port: None,
        state: None,
        pid,
        process: None,
    }
}

pub fn ports() -> Result<Vec<PortInfo>, String> {
    let (inet, inet6) = (u32::from(AF_INET), u32::from(AF_INET6));
    let mut out = Vec::new();

    let t4 = ip_table("tcp", |p, n| unsafe { GetExtendedTcpTable(p, n, 1, inet, TCP_TABLE_OWNER_PID_ALL, 0) })?;
    for r in unsafe { rows::<MIB_TCPROW_OWNER_PID>(&t4, offset_of!(MIB_TCPTABLE_OWNER_PID, table)) } {
        out.push(tcp("tcp", (v4(r.dwLocalAddr), r.dwLocalPort), (v4(r.dwRemoteAddr), r.dwRemotePort), r.dwState, r.dwOwningPid));
    }
    let t6 = ip_table("tcp6", |p, n| unsafe { GetExtendedTcpTable(p, n, 1, inet6, TCP_TABLE_OWNER_PID_ALL, 0) })?;
    for r in unsafe { rows::<MIB_TCP6ROW_OWNER_PID>(&t6, offset_of!(MIB_TCP6TABLE_OWNER_PID, table)) } {
        let (l, rm) = (IpAddr::V6(Ipv6Addr::from(r.ucLocalAddr)), IpAddr::V6(Ipv6Addr::from(r.ucRemoteAddr)));
        out.push(tcp("tcp6", (l, r.dwLocalPort), (rm, r.dwRemotePort), r.dwState, r.dwOwningPid));
    }
    let u4 = ip_table("udp", |p, n| unsafe { GetExtendedUdpTable(p, n, 1, inet, UDP_TABLE_OWNER_PID, 0) })?;
    for r in unsafe { rows::<MIB_UDPROW_OWNER_PID>(&u4, offset_of!(MIB_UDPTABLE_OWNER_PID, table)) } {
        out.push(udp("udp", (v4(r.dwLocalAddr), r.dwLocalPort), r.dwOwningPid));
    }
    let u6 = ip_table("udp6", |p, n| unsafe { GetExtendedUdpTable(p, n, 1, inet6, UDP_TABLE_OWNER_PID, 0) })?;
    for r in unsafe { rows::<MIB_UDP6ROW_OWNER_PID>(&u6, offset_of!(MIB_UDP6TABLE_OWNER_PID, table)) } {
        out.push(udp("udp6", (IpAddr::V6(Ipv6Addr::from(r.ucLocalAddr)), r.dwLocalPort), r.dwOwningPid));
    }
    Ok(out)
}

// ---------------------------------------------------------------------------------------
// Services
// ---------------------------------------------------------------------------------------

/// A service manager or service handle, closed when dropped.
struct ScHandle(SC_HANDLE);

impl Drop for ScHandle {
    fn drop(&mut self) {
        unsafe { CloseServiceHandle(self.0) };
    }
}

/// Calls a "fill this buffer" API twice: for the size, then for the data.
fn query_buf(f: impl Fn(*mut u8, u32, *mut u32) -> BOOL) -> Option<Vec<u64>> {
    let mut need = 0u32;
    f(null_mut(), 0, &mut need);
    if need == 0 {
        return None;
    }
    let mut buf = vec![0u64; (need as usize).div_ceil(8)];
    (f(buf.as_mut_ptr().cast(), (buf.len() * 8) as u32, &mut need) != 0).then_some(buf)
}

pub fn services() -> Result<Vec<ServiceInfo>, String> {
    let scm = unsafe { OpenSCManagerW(null(), null(), SC_MANAGER_CONNECT | SC_MANAGER_ENUMERATE_SERVICE) };
    if scm.is_null() {
        return Err(format!("service manager not opened (error {})", last_error()));
    }
    let scm = ScHandle(scm);
    let mut out = Vec::new();
    let mut resume = 0u32;
    let mut buf = vec![0u64; 32 * 1024];
    loop {
        let (mut needed, mut count) = (0u32, 0u32);
        let ok = unsafe {
            EnumServicesStatusExW(
                scm.0,
                SC_ENUM_PROCESS_INFO,
                SERVICE_WIN32,
                SERVICE_STATE_ALL,
                buf.as_mut_ptr().cast(),
                (buf.len() * 8) as u32,
                &mut needed,
                &mut count,
                &mut resume,
                null(),
            )
        };
        let err = if ok == 0 { last_error() } else { ERROR_SUCCESS };
        if ok == 0 && err != ERROR_MORE_DATA {
            return Err(format!("EnumServicesStatusExW failed (error {err})"));
        }
        let items = unsafe { std::slice::from_raw_parts(buf.as_ptr() as *const ENUM_SERVICE_STATUS_PROCESSW, count as usize) };
        out.extend(items.iter().map(|s| service(&scm, s)));
        if ok != 0 {
            break;
        }
        if count == 0 {
            // not even one entry fitted
            if (needed as usize) <= buf.len() * 8 {
                return Err("EnumServicesStatusExW returned nothing".into());
            }
            buf = vec![0u64; (needed as usize).div_ceil(8)];
        }
    }
    Ok(out)
}

fn service(scm: &ScHandle, s: &ENUM_SERVICE_STATUS_PROCESSW) -> ServiceInfo {
    let st = &s.ServiceStatusProcess;
    let mut info = ServiceInfo {
        name: unsafe { pwstr(s.lpServiceName) }.unwrap_or_default(),
        display_name: unsafe { pwstr(s.lpDisplayName) }.unwrap_or_default(),
        state: match st.dwCurrentState {
            SERVICE_RUNNING => "running",
            SERVICE_STOPPED => "stopped",
            _ => "other",
        }
        .into(),
        startup_type: String::new(),
        account: None,
        path: None,
        pid: (st.dwProcessId != 0).then_some(st.dwProcessId),
        description: None,
    };
    let h = unsafe { OpenServiceW(scm.0, wide(&info.name).as_ptr(), SERVICE_QUERY_CONFIG) };
    if h.is_null() {
        return info;
    }
    let h = ScHandle(h);
    if let Some(buf) = query_buf(|p, n, need| unsafe { QueryServiceConfigW(h.0, p.cast(), n, need) }) {
        let c = unsafe { &*(buf.as_ptr() as *const QUERY_SERVICE_CONFIGW) };
        info.startup_type = match c.dwStartType {
            SERVICE_AUTO_START => "automatic",
            SERVICE_DEMAND_START => "manual",
            SERVICE_DISABLED => "disabled",
            _ => "other",
        }
        .into();
        unsafe {
            info.path = pwstr(c.lpBinaryPathName);
            info.account = pwstr(c.lpServiceStartName);
        }
    }
    if let Some(buf) = query_buf(|p, n, need| unsafe { QueryServiceConfig2W(h.0, SERVICE_CONFIG_DESCRIPTION, p, n, need) }) {
        let d = unsafe { &*(buf.as_ptr() as *const SERVICE_DESCRIPTIONW) };
        info.description = unsafe { pwstr(d.lpDescription) };
    }
    info
}
