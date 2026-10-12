//! `SysInfo::getPorts()` with `WindowsPortWrapper` (portWindowsWrapper.h)
//! and `PortImpl::buildPortData` (portImpl.h).

use std::collections::BTreeMap;

use windows_sys::Win32::Foundation::{ERROR_INSUFFICIENT_BUFFER, NO_ERROR};
use windows_sys::Win32::NetworkManagement::IpHelper::*;
use windows_sys::Win32::Networking::WinSock::{WSAAddressToStringA, AF_INET, AF_INET6, IN_ADDR, IN_ADDR_0, SOCKADDR, SOCKADDR_IN6};

use super::{enc, processes, Error};
use crate::json::{i, s, Obj, Value};
use crate::UNKNOWN_VALUE;

/// `getIpV6Address` (WSAAddressToStringA of a sockaddr_in6)
fn ipv6_address(addr: &[u8; 16]) -> String {
    // SAFETY: a zeroed sockaddr_in6 with the address copied in.
    unsafe {
        let mut sa6: SOCKADDR_IN6 = std::mem::zeroed();
        sa6.sin6_family = AF_INET6;
        std::ptr::copy_nonoverlapping(addr.as_ptr(), &mut sa6.sin6_addr as *mut _ as *mut u8, 16);
        let mut buf = [0u8; 65];
        let mut len = buf.len() as u32;
        if WSAAddressToStringA(&sa6 as *const _ as *const SOCKADDR, std::mem::size_of::<SOCKADDR_IN6>() as u32, std::ptr::null(), buf.as_mut_ptr(), &mut len) != 0 {
            return String::new();
        }
        String::from_utf8_lossy(&buf[..buf.iter().position(|&c| c == 0).unwrap_or(0)]).into_owned()
    }
}

/// `getIpV4Address`
fn ipv4_address(addr: u32) -> String {
    let a = IN_ADDR { S_un: IN_ADDR_0 { S_addr: addr } };
    let mut buf = vec![0u8; 1025];
    // SAFETY: an in_addr and a buffer of the given size.
    let p = unsafe { windows_sys::Win32::Networking::WinSock::inet_ntop(AF_INET as i32, (&a as *const IN_ADDR).cast(), buf.as_mut_ptr(), buf.len()) };
    if p.is_null() {
        return String::new();
    }
    String::from_utf8_lossy(&buf[..buf.iter().position(|&c| c == 0).unwrap_or(0)]).into_owned()
}

fn state_name(st: u32) -> &'static str {
    match st {
        5 => "established",
        3 => "syn_sent",
        4 => "syn_recv",
        6 => "fin_wait1",
        7 => "fin_wait2",
        11 => "time_wait",
        1 => "close",
        8 => "close_wait",
        9 => "last_ack",
        2 => "listening",
        10 => "closing",
        12 => "delete_tcp",
        _ => UNKNOWN_VALUE,
    }
}

/// `getProcessName` (then converted to UTF-8 by `processName()`)
fn process_name(list: &BTreeMap<i32, Vec<u8>>, pid: u32) -> Vec<u8> {
    let pid = pid as i32;
    let raw: Vec<u8> = match pid {
        0 => b"System Idle Process".to_vec(),
        4 => b"System".to_vec(),
        _ => list.get(&pid).cloned().unwrap_or_else(|| UNKNOWN_VALUE.as_bytes().to_vec()),
    };
    enc::ansi_to_utf8(&raw)
}

fn ntohs(p: u32) -> i32 {
    u16::from_be(p as u16) as i32
}

#[allow(clippy::too_many_arguments)]
fn port(protocol: &str, local_ip: String, local_port: i32, remote_ip: String, remote_port: i32, state: u32, pid: u32, name: Vec<u8>) -> Value {
    let mut o = Obj::new();
    o.set("protocol", s(protocol));
    o.set("local_ip", s(local_ip));
    o.set("local_port", i(local_port as i64));
    o.set("remote_ip", s(remote_ip));
    o.set("remote_port", i(remote_port as i64));
    o.set("tx_queue", i(0));
    o.set("rx_queue", i(0));
    o.set("inode", i(0));
    o.set("state", s(state_name(state)));
    o.set("pid", i(pid as i32 as i64));
    o.set("process", s(name));
    o.into_value()
}

/// `getTablePorts`: the table bytes, None when the first call does not
/// ask for a buffer; Err when the second call fails.
fn table(f: impl Fn(*mut core::ffi::c_void, *mut u32) -> u32) -> Result<Option<Vec<u64>>, Error> {
    let mut size = 0u32;
    if f(std::ptr::null_mut(), &mut size) != ERROR_INSUFFICIENT_BUFFER {
        return Ok(None);
    }
    let mut buf = vec![0u64; (size as usize).div_ceil(8).max(1)];
    if f(buf.as_mut_ptr().cast(), &mut size) != NO_ERROR {
        return Err(Error("Error when get table information".into()));
    }
    Ok(Some(buf))
}

/// `SysInfo::getPorts()`
pub fn get_ports() -> Result<Value, Error> {
    let mut list: BTreeMap<i32, Vec<u8>> = BTreeMap::new();
    processes::fill_processes_data(|pe| {
        list.insert(pe.pid as i32, pe.exe_file.clone());
    })?;
    let mut ports: Vec<Value> = Vec::new();
    // SAFETY: each buffer holds the table the API wrote.
    unsafe {
        if let Some(b) = table(|p, sz| GetExtendedTcpTable(p, sz, 1, AF_INET as u32, TCP_TABLE_OWNER_PID_ALL, 0))? {
            let t = &*(b.as_ptr() as *const MIB_TCPTABLE_OWNER_PID);
            let rows = std::slice::from_raw_parts(t.table.as_ptr(), t.dwNumEntries as usize);
            for r in rows {
                ports.push(port(
                    "tcp",
                    ipv4_address(r.dwLocalAddr),
                    ntohs(r.dwLocalPort),
                    ipv4_address(r.dwRemoteAddr),
                    ntohs(r.dwRemotePort),
                    r.dwState,
                    r.dwOwningPid,
                    process_name(&list, r.dwOwningPid),
                ));
            }
        }
        if let Some(b) = table(|p, sz| GetExtendedTcpTable(p, sz, 1, AF_INET6 as u32, TCP_TABLE_OWNER_PID_ALL, 0))? {
            let t = &*(b.as_ptr() as *const MIB_TCP6TABLE_OWNER_PID);
            let rows = std::slice::from_raw_parts(t.table.as_ptr(), t.dwNumEntries as usize);
            for r in rows {
                ports.push(port(
                    "tcp6",
                    ipv6_address(&r.ucLocalAddr),
                    ntohs(r.dwLocalPort),
                    ipv6_address(&r.ucRemoteAddr),
                    ntohs(r.dwRemotePort),
                    r.dwState,
                    r.dwOwningPid,
                    process_name(&list, r.dwOwningPid),
                ));
            }
        }
        if let Some(b) = table(|p, sz| GetExtendedUdpTable(p, sz, 1, AF_INET as u32, UDP_TABLE_OWNER_PID, 0))? {
            let t = &*(b.as_ptr() as *const MIB_UDPTABLE_OWNER_PID);
            let rows = std::slice::from_raw_parts(t.table.as_ptr(), t.dwNumEntries as usize);
            for r in rows {
                ports.push(port("udp", ipv4_address(r.dwLocalAddr), ntohs(r.dwLocalPort), String::new(), 0, 0, r.dwOwningPid, process_name(&list, r.dwOwningPid)));
            }
        }
        if let Some(b) = table(|p, sz| GetExtendedUdpTable(p, sz, 1, AF_INET6 as u32, UDP_TABLE_OWNER_PID, 0))? {
            let t = &*(b.as_ptr() as *const MIB_UDP6TABLE_OWNER_PID);
            let rows = std::slice::from_raw_parts(t.table.as_ptr(), t.dwNumEntries as usize);
            for r in rows {
                ports.push(port("udp6", ipv6_address(&r.ucLocalAddr), ntohs(r.dwLocalPort), String::new(), 0, 0, r.dwOwningPid, process_name(&list, r.dwOwningPid)));
            }
        }
    }
    Ok(if ports.is_empty() { Value::Null } else { Value::Array(ports) })
}
