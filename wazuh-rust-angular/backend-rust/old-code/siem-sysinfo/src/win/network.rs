//! `SysInfo::getNetworks()` with `NetworkWindowsInterface`
//! (networkWindowsWrapper.h) and `WindowsNetworkImpl`
//! (networkInterfaceWindows.cpp).
//!
//! The Windows XP branches (`!isVistaOrLater()`: GetAdaptersInfo, GetIfEntry)
//! are not reachable: Rust binaries do not run on Windows XP.

use windows_sys::Win32::Foundation::NO_ERROR;
use windows_sys::Win32::NetworkManagement::IpHelper::*;
use windows_sys::Win32::Networking::WinSock::{inet_ntop, inet_pton, AF_INET, AF_INET6, AF_UNSPEC, IN6_ADDR, IN_ADDR, SOCKADDR_IN, SOCKADDR_IN6};

use super::{enc, helpers, Error};
use crate::json::{s, u, Obj, Value};
use crate::UNKNOWN_VALUE;

const WORKING_ADAPTERS_INFO_BUFFER_SIZE: u32 = 15000;
const MAX_ADAPTERS_INFO_TRIES: i32 = 3;
const NI_MAXHOST: usize = 1025;

/// `getAdapterAddresses` + `getAdapters`: the adapter list buffer.
fn get_adapters() -> Result<Vec<u64>, Error> {
    let flags = GAA_FLAG_INCLUDE_PREFIX | GAA_FLAG_INCLUDE_GATEWAYS;
    let mut len = WORKING_ADAPTERS_INFO_BUFFER_SIZE;
    let mut attempts = 0;
    loop {
        let mut buf = vec![0u64; (len as usize).div_ceil(8)];
        // SAFETY: the buffer holds `len` bytes.
        let r = unsafe { GetAdaptersAddresses(AF_UNSPEC as u32, flags, std::ptr::null(), buf.as_mut_ptr().cast(), &mut len) };
        attempts += 1;
        if r == windows_sys::Win32::Foundation::ERROR_BUFFER_OVERFLOW && attempts < MAX_ADAPTERS_INFO_TRIES {
            continue;
        }
        if r != NO_ERROR {
            return Err(Error("Error reading network adapter addresses".into()));
        }
        return Ok(buf);
    }
}

/// `IAddressToString(family, in_addr / in6_addr)` (inet_ntop)
fn address_to_string(family: u16, addr: *const core::ffi::c_void) -> String {
    let mut buf = vec![0u8; NI_MAXHOST];
    // SAFETY: the address points at an in_addr / in6_addr of that family.
    let p = unsafe { inet_ntop(family as i32, addr, buf.as_mut_ptr(), NI_MAXHOST) };
    if p.is_null() {
        return String::new();
    }
    String::from_utf8_lossy(&buf[..buf.iter().position(|&c| c == 0).unwrap_or(0)]).into_owned()
}

/// `broadcastAddress(ip, netmask)`
fn broadcast_address(ip: &str, netmask: &str) -> String {
    let mut host = IN_ADDR { S_un: unsafe { std::mem::zeroed() } };
    let mut mask = IN_ADDR { S_un: unsafe { std::mem::zeroed() } };
    let ipz = enc::az(ip.as_bytes());
    let mz = enc::az(netmask.as_bytes());
    // SAFETY: valid strings and out structs.
    unsafe {
        if inet_pton(AF_INET as i32, ipz.as_ptr(), (&mut host as *mut IN_ADDR).cast()) == 1
            && inet_pton(AF_INET as i32, mz.as_ptr(), (&mut mask as *mut IN_ADDR).cast()) == 1
        {
            let b = IN_ADDR { S_un: windows_sys::Win32::Networking::WinSock::IN_ADDR_0 { S_addr: host.S_un.S_addr | !mask.S_un.S_addr } };
            return address_to_string(AF_INET, (&b as *const IN_ADDR).cast());
        }
    }
    String::new()
}

struct Iface<'a> {
    a: &'a IP_ADAPTER_ADDRESSES_LH,
    uni: Option<&'a IP_ADAPTER_UNICAST_ADDRESS_LH>,
}

impl Iface<'_> {
    fn adapter_family(&self) -> u16 {
        // SAFETY: lpSockaddr of a unicast entry is valid.
        self.uni.map(|u| unsafe { (*u.Address.lpSockaddr).sa_family }).unwrap_or(AF_UNSPEC)
    }

    fn wide(p: *const u16) -> Vec<u16> {
        if p.is_null() {
            return Vec::new();
        }
        let mut n = 0;
        // SAFETY: a NUL-terminated wide string from the adapter list.
        unsafe {
            while *p.add(n) != 0 {
                n += 1;
            }
            std::slice::from_raw_parts(p, n).to_vec()
        }
    }

    /// `getAdapterEncodedUTF8`
    fn encoded(p: *const u16) -> Vec<u8> {
        let v = enc::wstring_to_utf8(&Self::wide(p));
        if v.is_empty() {
            b" ".to_vec()
        } else {
            v
        }
    }

    fn name(&self) -> Vec<u8> {
        Self::encoded(self.a.FriendlyName)
    }

    fn adapter(&self) -> Vec<u8> {
        Self::encoded(self.a.Description)
    }

    fn address(&self) -> String {
        match self.uni {
            // SAFETY: an AF_INET sockaddr.
            Some(u) => unsafe {
                let sin = u.Address.lpSockaddr as *const SOCKADDR_IN;
                address_to_string(self.adapter_family(), (&(*sin).sin_addr as *const IN_ADDR).cast())
            },
            None => String::new(),
        }
    }

    fn address_v6(&self) -> String {
        match self.uni {
            // SAFETY: an AF_INET6 sockaddr.
            Some(u) => unsafe {
                let sin6 = u.Address.lpSockaddr as *const SOCKADDR_IN6;
                address_to_string(self.adapter_family(), (&(*sin6).sin6_addr as *const IN6_ADDR).cast())
            },
            None => String::new(),
        }
    }

    fn netmask(&self) -> String {
        let Some(u) = self.uni else { return String::new() };
        let mut mask: u32 = 0;
        // SAFETY: out pointer.
        if unsafe { ConvertLengthToIpv4Mask(u.OnLinkPrefixLength as u32, &mut mask) } == NO_ERROR {
            return address_to_string(self.adapter_family(), (&mask as *const u32).cast());
        }
        String::new()
    }

    fn netmask_v6(&self) -> String {
        self.uni.map(|u| helpers::ipv6_netmask(u.OnLinkPrefixLength)).unwrap_or_default()
    }

    fn broadcast(&self) -> String {
        let address = self.address();
        let netmask = self.netmask();
        if !address.is_empty() && !netmask.is_empty() {
            let b = broadcast_address(&address, &netmask);
            return if b.is_empty() { UNKNOWN_VALUE.into() } else { b };
        }
        UNKNOWN_VALUE.into()
    }

    fn gateway(&self) -> String {
        let mut ret = String::new();
        let mut g = self.a.FirstGatewayAddress;
        // SAFETY: the gateway list of the adapter.
        unsafe {
            while !g.is_null() {
                let sa = (*g).Address.lpSockaddr;
                let fam = (*sa).sa_family;
                if fam == AF_INET {
                    ret += &address_to_string(fam, (&(*(sa as *const SOCKADDR_IN)).sin_addr as *const IN_ADDR).cast());
                    ret += ",";
                } else if fam == AF_INET6 {
                    ret += &address_to_string(fam, (&(*(sa as *const SOCKADDR_IN6)).sin6_addr as *const IN6_ADDR).cast());
                    ret += ",";
                }
                g = (*g).Next;
            }
        }
        if ret.is_empty() {
            UNKNOWN_VALUE.into()
        } else {
            ret.pop();
            ret
        }
    }

    fn flags(&self) -> u32 {
        // SAFETY: the Flags member of the union.
        unsafe { self.a.Anonymous2.Flags }
    }

    fn dhcp(&self) -> String {
        const IP_ADAPTER_DHCP_ENABLED: u32 = 0x4;
        const IP_ADAPTER_IPV4_ENABLED: u32 = 0x80;
        const IP_ADAPTER_IPV6_ENABLED: u32 = 0x100;
        let fl = self.flags();
        match self.adapter_family() {
            AF_INET => if fl & IP_ADAPTER_DHCP_ENABLED != 0 && fl & IP_ADAPTER_IPV4_ENABLED != 0 { "enabled" } else { "disabled" }.into(),
            AF_INET6 => if fl & IP_ADAPTER_DHCP_ENABLED != 0 && fl & IP_ADAPTER_IPV6_ENABLED != 0 { "enabled" } else { "disabled" }.into(),
            _ => UNKNOWN_VALUE.into(),
        }
    }

    fn if_type(&self) -> &'static str {
        match self.a.IfType {
            6 => "ethernet",
            9 => "token ring",
            23 => "point-to-point",
            37 => "ATM",
            71 => "wireless",
            131 => "tunnel",
            144 => "firewire",
            _ => UNKNOWN_VALUE,
        }
    }

    fn state(&self) -> &'static str {
        match self.a.OperStatus {
            1 => "up",
            2 => "down",
            3 => "testing",
            4 => "unknown",
            5 => "dormant",
            6 => "notpresent",
            7 => "lowerlayerdown",
            _ => UNKNOWN_VALUE,
        }
    }

    fn mac(&self) -> String {
        if self.a.PhysicalAddressLength == 6 {
            let p = &self.a.PhysicalAddress[..6];
            p.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(":")
        } else {
            "00:00:00:00:00:00".into()
        }
    }

    /// `statsVistaOrLater` (unsigned int fields: 64-bit counters truncate)
    fn stats(&self) -> [u32; 8] {
        let mut ret = [0u32; 8];
        // SAFETY: a zeroed MIB_IF_ROW2 with its index set.
        unsafe {
            let mut row: MIB_IF_ROW2 = std::mem::zeroed();
            row.InterfaceIndex = if self.a.Anonymous1.Anonymous.IfIndex != 0 { self.a.Anonymous1.Anonymous.IfIndex } else { self.a.Ipv6IfIndex };
            if row.InterfaceIndex != 0 && GetIfEntry2(&mut row) == NO_ERROR {
                ret = [
                    (row.OutUcastPkts.wrapping_add(row.OutNUcastPkts)) as u32,
                    (row.InUcastPkts.wrapping_add(row.InNUcastPkts)) as u32,
                    row.OutOctets as u32,
                    row.InOctets as u32,
                    row.OutErrors as u32,
                    row.InErrors as u32,
                    row.OutDiscards as u32,
                    row.InDiscards as u32,
                ];
            }
        }
        ret
    }
}

fn push(o: &mut Obj, key: &str, v: Value) {
    let mut arr = match o.0.remove(key.as_bytes()) {
        Some(Value::Array(a)) => a,
        _ => Vec::new(),
    };
    arr.push(v);
    o.set(key, Value::Array(arr));
}

/// `SysInfo::getNetworks()`
pub fn get_networks() -> Result<Value, Error> {
    let buf = get_adapters()?;
    let mut ifaces: Vec<Value> = Vec::new();
    let mut p = buf.as_ptr() as *const IP_ADAPTER_ADDRESSES_LH;
    // SAFETY: the linked list lives in `buf`.
    unsafe {
        while !p.is_null() {
            let a = &*p;
            let if_index = a.Anonymous1.Anonymous.IfIndex;
            if a.IfType != IF_TYPE_SOFTWARE_LOOPBACK || if_index != 0 || a.Ipv6IfIndex != 0 {
                let mut net = Obj::new();
                let mut uni = a.FirstUnicastAddress;
                while !uni.is_null() {
                    let sa = (*uni).Address.lpSockaddr;
                    if !sa.is_null() {
                        let it = Iface { a, uni: Some(&*uni) };
                        match (*sa).sa_family {
                            AF_INET => {
                                let address = it.address();
                                if address.is_empty() {
                                    return Err(Error("Invalid IpV4 address.".into()));
                                }
                                let mut v4 = Obj::new();
                                v4.set("address", s(&address));
                                v4.set("netmask", s(it.netmask()));
                                v4.set("broadcast", s(it.broadcast()));
                                v4.set("metric", s(a.Ipv4Metric.to_string()));
                                v4.set("dhcp", s(it.dhcp()));
                                push(&mut net, "IPv4", v4.into_value());
                            }
                            AF_INET6 => {
                                let address = it.address_v6();
                                if address.is_empty() {
                                    return Err(Error("Invalid IpV6 address.".into()));
                                }
                                let mut v6 = Obj::new();
                                v6.set("address", s(&address));
                                v6.set("netmask", s(it.netmask_v6()));
                                v6.set("broadcast", s(UNKNOWN_VALUE));
                                v6.set("metric", s(a.Ipv6Metric.to_string()));
                                v6.set("dhcp", s(it.dhcp()));
                                push(&mut net, "IPv6", v6.into_value());
                            }
                            _ => {}
                        }
                    }
                    uni = (*uni).Next;
                }
                // Common data (no current unicast address)
                let it = Iface { a, uni: None };
                net.set("name", s(it.name()));
                net.set("adapter", s(it.adapter()));
                net.set("state", s(it.state()));
                net.set("type", s(it.if_type()));
                net.set("mac", s(it.mac()));
                let st = it.stats();
                net.set("tx_packets", u(st[0] as u64));
                net.set("rx_packets", u(st[1] as u64));
                net.set("tx_bytes", u(st[2] as u64));
                net.set("rx_bytes", u(st[3] as u64));
                net.set("tx_errors", u(st[4] as u64));
                net.set("rx_errors", u(st[5] as u64));
                net.set("tx_dropped", u(st[6] as u64));
                net.set("rx_dropped", u(st[7] as u64));
                net.set("mtu", u(a.Mtu as u64));
                net.set("gateway", s(it.gateway()));
                ifaces.push(net.into_value());
            }
            p = a.Next;
        }
    }
    let mut networks = Obj::new();
    if !ifaces.is_empty() {
        networks.set("iface", Value::Array(ifaces));
    }
    Ok(if networks.0.is_empty() { Value::Null } else { networks.into_value() })
}
