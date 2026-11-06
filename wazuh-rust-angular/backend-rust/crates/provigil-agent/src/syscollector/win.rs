//! The Windows side of the inventory, through `windows-sys`: the registry, toolhelp process
//! snapshots, the IP Helper tables, the service control manager, the local account API and
//! the SMBIOS firmware table. Each function returns what it read, or why it could not.

use super::{
    appx_package, board_serial_from_smbios, file_name, if_address, npm_packages, python_packages, select_packages, subdirs,
    GroupInfo, Hardware, NetworkAdapter, PackageInfo, Profile, RawPackage, UserInfo,
};
pub use provigil_collect::win::{ports, processes, services};
use super::nonempty;
use provigil_collect::win::{from_wide, last_error, pwstr, wide};
use std::ffi::c_void;
use std::mem::{size_of, zeroed};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::ptr::{null, null_mut};

use windows_sys::core::PWSTR;
use windows_sys::Win32::Foundation::{
    LocalFree, ERROR_BUFFER_OVERFLOW, ERROR_MORE_DATA,
    ERROR_NO_DATA, ERROR_NO_MORE_ITEMS, ERROR_SUCCESS, HLOCAL,
};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    GetAdaptersAddresses, GetIfEntry2, GAA_FLAG_INCLUDE_GATEWAYS,
    GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_DNS_SERVER, GAA_FLAG_SKIP_MULTICAST, IF_TYPE_ETHERNET_CSMACD, IF_TYPE_IEEE80211,
    IF_TYPE_SOFTWARE_LOOPBACK, IF_TYPE_TUNNEL, IP_ADAPTER_ADDRESSES_LH, IP_ADAPTER_DHCP_ENABLED, MIB_IF_ROW2,
};
use windows_sys::Win32::NetworkManagement::Ndis::IfOperStatusUp;
use windows_sys::Win32::NetworkManagement::NetManagement::{
    NetApiBufferFree, NetLocalGroupEnum, NetLocalGroupGetMembers, NetUserEnum, NetUserGetInfo, NetUserGetLocalGroups,
    FILTER_NORMAL_ACCOUNT, LG_INCLUDE_INDIRECT, LOCALGROUP_INFO_1, LOCALGROUP_MEMBERS_INFO_3, LOCALGROUP_USERS_INFO_0,
    MAX_PREFERRED_LENGTH, NERR_Success, UF_ACCOUNTDISABLE, USER_INFO_0, USER_INFO_23, USER_INFO_4,
};
use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6, AF_UNSPEC, SOCKADDR_IN, SOCKADDR_IN6, SOCKET_ADDRESS};
use windows_sys::Win32::Security::Authorization::{ConvertSidToStringSidW, ConvertStringSidToSidW};
use windows_sys::Win32::Security::{LookupAccountNameW, LookupAccountSidW, PSID};
use windows_sys::Win32::System::Environment::ExpandEnvironmentStringsW;
use windows_sys::Win32::System::Registry::{
    RegCloseKey, RegEnumKeyExW, RegOpenKeyExW, RegQueryValueExW, HKEY, HKEY_LOCAL_MACHINE, HKEY_USERS, KEY_READ,
    KEY_WOW64_32KEY, KEY_WOW64_64KEY, REG_DWORD, REG_EXPAND_SZ, REG_QWORD, REG_SZ,
};
use windows_sys::Win32::System::SystemInformation::{GetSystemFirmwareTable, GlobalMemoryStatusEx, MEMORYSTATUSEX, RSMB};
use windows_sys::Win32::System::Threading::{
    GetActiveProcessorCount, ALL_PROCESSOR_GROUPS,
};

// ---------------------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------------------

/// `%SystemDrive%\Users\x` → `C:\Users\x`.
fn expand(s: &str) -> String {
    if !s.contains('%') {
        return s.to_string();
    }
    let src = wide(s);
    let n = unsafe { ExpandEnvironmentStringsW(src.as_ptr(), null_mut(), 0) };
    if n == 0 {
        return s.to_string();
    }
    let mut buf = vec![0u16; n as usize];
    let m = unsafe { ExpandEnvironmentStringsW(src.as_ptr(), buf.as_mut_ptr(), n) };
    if m == 0 || m > n {
        return s.to_string();
    }
    from_wide(&buf)
}

// ---------------------------------------------------------------------------------------
// Registry
// ---------------------------------------------------------------------------------------

/// An open registry key, closed when dropped.
struct Key(HKEY);

impl Drop for Key {
    fn drop(&mut self) {
        unsafe { RegCloseKey(self.0) };
    }
}

impl Key {
    /// Opens `path` under `parent` for reading; `view` is 0 or a 32/64-bit view flag.
    fn open(parent: HKEY, path: &str, view: u32) -> Result<Key, u32> {
        let mut h: HKEY = null_mut();
        let rc = unsafe { RegOpenKeyExW(parent, wide(path).as_ptr(), 0, KEY_READ | view, &mut h) };
        if rc == ERROR_SUCCESS {
            Ok(Key(h))
        } else {
            Err(rc)
        }
    }

    fn subkeys(&self) -> Vec<String> {
        let mut out = Vec::new();
        let mut buf = [0u16; 256]; // key names are at most 255 characters
        let mut i = 0;
        loop {
            let mut len = buf.len() as u32;
            let rc = unsafe {
                RegEnumKeyExW(self.0, i, buf.as_mut_ptr(), &mut len, null(), null_mut(), null_mut(), null_mut())
            };
            match rc {
                ERROR_SUCCESS => out.push(String::from_utf16_lossy(&buf[..len as usize])),
                ERROR_NO_MORE_ITEMS => break,
                _ => {} // skip a name that does not fit or cannot be read
            }
            i += 1;
            if i > 1_000_000 {
                break;
            }
        }
        out
    }

    /// A value's type and bytes.
    fn value(&self, name: &str) -> Option<(u32, Vec<u8>)> {
        let n = wide(name);
        let (mut ty, mut len) = (0u32, 0u32);
        if unsafe { RegQueryValueExW(self.0, n.as_ptr(), null(), &mut ty, null_mut(), &mut len) } != ERROR_SUCCESS {
            return None;
        }
        for _ in 0..4 {
            let mut buf = vec![0u8; len as usize + 2];
            let mut got = buf.len() as u32;
            match unsafe { RegQueryValueExW(self.0, n.as_ptr(), null(), &mut ty, buf.as_mut_ptr(), &mut got) } {
                ERROR_SUCCESS => {
                    buf.truncate(got as usize);
                    return Some((ty, buf));
                }
                ERROR_MORE_DATA => len = got,
                _ => return None,
            }
        }
        None
    }

    /// A text value (a number value as its decimal text); `None` when missing or empty.
    fn string(&self, name: &str) -> Option<String> {
        let (ty, data) = self.value(name)?;
        match ty {
            REG_SZ | REG_EXPAND_SZ => {
                let w: Vec<u16> = data.as_chunks::<2>().0.iter().map(|c| u16::from_le_bytes(*c)).collect();
                nonempty(&from_wide(&w))
            }
            REG_DWORD | REG_QWORD => self.number(name).map(|n| n.to_string()),
            _ => None,
        }
    }

    /// A number value (a text value holding a number counts too).
    fn number(&self, name: &str) -> Option<u64> {
        let (ty, data) = self.value(name)?;
        match ty {
            REG_DWORD => Some(u64::from(u32::from_le_bytes(data.get(..4)?.try_into().ok()?))),
            REG_QWORD => Some(u64::from_le_bytes(data.get(..8)?.try_into().ok()?)),
            REG_SZ => self.string(name)?.parse().ok(),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------------------
// Accounts and SIDs
// ---------------------------------------------------------------------------------------

/// Safety: `sid` is a valid SID.
unsafe fn sid_string(sid: PSID) -> Option<String> {
    if sid.is_null() {
        return None;
    }
    let mut p: PWSTR = null_mut();
    if ConvertSidToStringSidW(sid, &mut p) == 0 {
        return None;
    }
    let s = pwstr(p);
    LocalFree(p as HLOCAL);
    s
}

/// The SID of an account or group name.
fn sid_of(account: &str) -> Option<String> {
    let name = wide(account);
    let mut sid = [0u32; 17]; // SECURITY_MAX_SID_SIZE (68 bytes), aligned
    let mut sid_len = size_of::<[u32; 17]>() as u32;
    let mut domain = [0u16; 256];
    let mut domain_len = domain.len() as u32;
    let mut kind = 0;
    let ok = unsafe {
        LookupAccountNameW(
            null(),
            name.as_ptr(),
            sid.as_mut_ptr().cast(),
            &mut sid_len,
            domain.as_mut_ptr(),
            &mut domain_len,
            &mut kind,
        )
    };
    if ok == 0 {
        return None;
    }
    unsafe { sid_string(sid.as_mut_ptr().cast()) }
}

/// The account name of a SID text.
fn account_of(sid: &str) -> Option<String> {
    let mut psid: PSID = null_mut();
    if unsafe { ConvertStringSidToSidW(wide(sid).as_ptr(), &mut psid) } == 0 {
        return None;
    }
    let (mut name, mut domain) = ([0u16; 256], [0u16; 256]);
    let (mut name_len, mut domain_len, mut kind) = (256u32, 256u32, 0);
    let ok = unsafe {
        LookupAccountSidW(null(), psid, name.as_mut_ptr(), &mut name_len, domain.as_mut_ptr(), &mut domain_len, &mut kind)
    };
    unsafe { LocalFree(psid as HLOCAL) };
    if ok == 0 {
        None
    } else {
        nonempty(&from_wide(&name))
    }
}

/// A buffer the network management API allocated, freed when dropped.
struct NetBuf(*mut u8);

impl Drop for NetBuf {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { NetApiBufferFree(self.0 as *const c_void) };
        }
    }
}

impl NetBuf {
    fn new() -> Self {
        NetBuf(null_mut())
    }

    /// The first `n` entries of the buffer.
    ///
    /// Safety: the buffer holds at least `n` entries of type `T`.
    unsafe fn items<T>(&self, n: u32) -> &[T] {
        if self.0.is_null() || n == 0 {
            &[]
        } else {
            std::slice::from_raw_parts(self.0 as *const T, n as usize)
        }
    }
}

/// Every user profile on the machine except the service accounts' (SYSTEM, LOCAL SERVICE,
/// NETWORK SERVICE).
pub fn user_profiles() -> Result<Vec<Profile>, String> {
    let list = Key::open(HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList", 0)
        .map_err(|e| format!("profile list not readable (error {e})"))?;
    Ok(list
        .subkeys()
        .into_iter()
        .filter(|sid| !matches!(sid.as_str(), "S-1-5-18" | "S-1-5-19" | "S-1-5-20"))
        .filter_map(|sid| {
            let path = Key::open(list.0, &sid, 0).ok()?.string("ProfileImagePath")?;
            let home = PathBuf::from(expand(&path));
            let user = account_of(&sid).unwrap_or_else(|| file_name(&home));
            Some(Profile { sid, user, home })
        })
        .collect())
}

pub fn users(profiles: &[Profile]) -> Result<Vec<UserInfo>, String> {
    let mut names = Vec::new();
    let mut resume = 0u32;
    loop {
        let mut buf = NetBuf::new();
        let (mut read, mut total) = (0u32, 0u32);
        let rc = unsafe {
            NetUserEnum(null(), 0, FILTER_NORMAL_ACCOUNT, &mut buf.0, MAX_PREFERRED_LENGTH, &mut read, &mut total, &mut resume)
        };
        if rc != NERR_Success && rc != ERROR_MORE_DATA {
            return Err(format!("NetUserEnum failed (error {rc})"));
        }
        names.extend(unsafe { buf.items::<USER_INFO_0>(read) }.iter().filter_map(|u| unsafe { pwstr(u.usri0_name) }));
        if rc == NERR_Success || read == 0 {
            break;
        }
    }
    Ok(names.iter().map(|n| user(n, profiles)).collect())
}

fn user(name: &str, profiles: &[Profile]) -> UserInfo {
    let w = wide(name);
    let mut u = UserInfo {
        name: name.to_string(),
        full_name: None,
        sid: None,
        home: None,
        disabled: false,
        last_logon: None,
        groups: local_groups_of(&w),
    };
    let mut buf = NetBuf::new();
    if unsafe { NetUserGetInfo(null(), w.as_ptr(), 4, &mut buf.0) } == NERR_Success && !buf.0.is_null() {
        let i = unsafe { &*(buf.0 as *const USER_INFO_4) };
        unsafe {
            u.full_name = pwstr(i.usri4_full_name);
            u.sid = sid_string(i.usri4_user_sid);
            u.home = pwstr(i.usri4_home_dir);
        }
        u.disabled = i.usri4_flags & UF_ACCOUNTDISABLE != 0;
        u.last_logon = (i.usri4_last_logon != 0)
            .then(|| chrono::DateTime::from_timestamp(i64::from(i.usri4_last_logon), 0))
            .flatten()
            .map(|t| t.to_rfc3339());
    } else {
        // level 4 can be refused; level 23 still has the name, flags and SID
        let mut buf = NetBuf::new();
        if unsafe { NetUserGetInfo(null(), w.as_ptr(), 23, &mut buf.0) } == NERR_Success && !buf.0.is_null() {
            let i = unsafe { &*(buf.0 as *const USER_INFO_23) };
            unsafe {
                u.full_name = pwstr(i.usri23_full_name);
                u.sid = sid_string(i.usri23_user_sid);
            }
            u.disabled = i.usri23_flags & UF_ACCOUNTDISABLE != 0;
        } else {
            u.sid = sid_of(name);
        }
    }
    if u.home.is_none() {
        u.home = u.sid.as_ref().and_then(|s| profiles.iter().find(|p| &p.sid == s)).map(|p| p.home.display().to_string());
    }
    u
}

/// The local groups an account is in (directly or through a domain group).
fn local_groups_of(user: &[u16]) -> Vec<String> {
    let mut buf = NetBuf::new();
    let (mut read, mut total) = (0u32, 0u32);
    let rc = unsafe {
        NetUserGetLocalGroups(null(), user.as_ptr(), 0, LG_INCLUDE_INDIRECT, &mut buf.0, MAX_PREFERRED_LENGTH, &mut read, &mut total)
    };
    if rc != NERR_Success {
        return Vec::new();
    }
    unsafe { buf.items::<LOCALGROUP_USERS_INFO_0>(read) }.iter().filter_map(|g| unsafe { pwstr(g.lgrui0_name) }).collect()
}

pub fn groups() -> Result<Vec<GroupInfo>, String> {
    let mut out = Vec::new();
    let mut resume = 0usize;
    loop {
        let mut buf = NetBuf::new();
        let (mut read, mut total) = (0u32, 0u32);
        let rc = unsafe { NetLocalGroupEnum(null(), 1, &mut buf.0, MAX_PREFERRED_LENGTH, &mut read, &mut total, &mut resume) };
        if rc != NERR_Success && rc != ERROR_MORE_DATA {
            return Err(format!("NetLocalGroupEnum failed (error {rc})"));
        }
        for g in unsafe { buf.items::<LOCALGROUP_INFO_1>(read) } {
            let Some(name) = (unsafe { pwstr(g.lgrpi1_name) }) else { continue };
            out.push(GroupInfo {
                sid: sid_of(&name),
                description: unsafe { pwstr(g.lgrpi1_comment) },
                members: members_of(&name),
                name,
            });
        }
        if rc == NERR_Success || read == 0 {
            break;
        }
    }
    Ok(out)
}

/// The members of a local group as `DOMAIN\name`.
fn members_of(group: &str) -> Vec<String> {
    let g = wide(group);
    let mut out = Vec::new();
    let mut resume = 0usize;
    loop {
        let mut buf = NetBuf::new();
        let (mut read, mut total) = (0u32, 0u32);
        let rc = unsafe {
            NetLocalGroupGetMembers(null(), g.as_ptr(), 3, &mut buf.0, MAX_PREFERRED_LENGTH, &mut read, &mut total, &mut resume)
        };
        if rc != NERR_Success && rc != ERROR_MORE_DATA {
            break;
        }
        out.extend(
            unsafe { buf.items::<LOCALGROUP_MEMBERS_INFO_3>(read) }.iter().filter_map(|m| unsafe { pwstr(m.lgrmi3_domainandname) }),
        );
        if rc == NERR_Success || read == 0 {
            break;
        }
    }
    out
}

// ---------------------------------------------------------------------------------------
// Hardware
// ---------------------------------------------------------------------------------------

pub fn hardware() -> (Hardware, Vec<String>) {
    let mut hw = Hardware::default();
    let mut errors = Vec::new();
    match Key::open(HKEY_LOCAL_MACHINE, r"HARDWARE\DESCRIPTION\System\CentralProcessor\0", 0) {
        Ok(k) => {
            hw.cpu_name = k.string("ProcessorNameString");
            hw.cpu_mhz = k.number("~MHz").and_then(|n| u32::try_from(n).ok());
        }
        Err(e) => errors.push(format!("processor key not readable (error {e})")),
    }
    let cores = unsafe { GetActiveProcessorCount(ALL_PROCESSOR_GROUPS) };
    hw.cpu_cores = (cores > 0).then_some(cores);

    let mut m: MEMORYSTATUSEX = unsafe { zeroed() };
    m.dwLength = size_of::<MEMORYSTATUSEX>() as u32;
    if unsafe { GlobalMemoryStatusEx(&mut m) } != 0 {
        hw.ram_total_kb = Some(m.ullTotalPhys / 1024);
        hw.ram_free_kb = Some(m.ullAvailPhys / 1024);
        hw.ram_usage_percent = Some(m.dwMemoryLoad);
    } else {
        errors.push(format!("memory status not read (error {})", last_error()));
    }

    match smbios() {
        Ok(raw) => hw.board_serial = board_serial_from_smbios(&raw),
        Err(e) => errors.push(e),
    }
    (hw, errors)
}

/// The raw SMBIOS table.
fn smbios() -> Result<Vec<u8>, String> {
    let n = unsafe { GetSystemFirmwareTable(RSMB, 0, null_mut(), 0) };
    if n == 0 {
        return Err(format!("SMBIOS table not readable (error {})", last_error()));
    }
    let mut buf = vec![0u8; n as usize];
    let got = unsafe { GetSystemFirmwareTable(RSMB, 0, buf.as_mut_ptr(), n) };
    if got == 0 || got > n {
        return Err(format!("SMBIOS table not readable (error {})", last_error()));
    }
    buf.truncate(got as usize);
    Ok(buf)
}

// ---------------------------------------------------------------------------------------
// Packages
// ---------------------------------------------------------------------------------------

const UNINSTALL: &str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";

/// The architecture of the machine's native (64-bit view) packages.
fn native_arch() -> &'static str {
    match std::env::consts::ARCH {
        "x86_64" => "x64",
        "aarch64" => "arm64",
        _ => "x86",
    }
}

fn read_uninstall(
    key: &Key,
    view: u32,
    source: &str,
    user_sid: Option<&str>,
    arch: Option<&str>,
    out: &mut Vec<RawPackage>,
) {
    for name in key.subkeys() {
        let Ok(k) = Key::open(key.0, &name, view) else { continue };
        out.push(RawPackage {
            display_name: k.string("DisplayName"),
            version: k.string("DisplayVersion"),
            publisher: k.string("Publisher"),
            install_date: k.string("InstallDate"),
            size_kb: k.number("EstimatedSize"),
            location: k.string("InstallLocation"),
            comments: k.string("Comments"),
            system_component: k.number("SystemComponent") == Some(1),
            parent_key_name: k.string("ParentKeyName"),
            source: source.to_string(),
            user_sid: user_sid.map(str::to_string),
            architecture: arch.map(str::to_string),
        });
    }
}

/// Every Microsoft Store package on the machine, for all users (the AppX package repository).
fn appx_packages() -> Vec<PackageInfo> {
    const REPOSITORY: &str = r"SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\PackageRepository\Packages";
    let Ok(repo) = Key::open(HKEY_LOCAL_MACHINE, REPOSITORY, 0) else { return Vec::new() };
    repo.subkeys()
        .into_iter()
        .filter_map(|full| {
            let mut p = appx_package(&full)?;
            p.location = Key::open(repo.0, &full, 0).ok().and_then(|k| k.string("Path"));
            Some(p)
        })
        .collect()
}

/// The folders under `dir` whose name starts with `Python` (any case).
fn python_dirs(dir: &Path) -> Vec<PathBuf> {
    subdirs(dir).into_iter().filter(|d| file_name(d).to_ascii_lowercase().starts_with("python")).collect()
}

/// The `site-packages` folders of the installed Pythons, with the owning user's SID: the
/// registered ones (`SOFTWARE\Python\<company>\<tag>\InstallPath`), the usual install folders
/// and each user's per-user site.
fn python_sites(profiles: &[Profile]) -> Vec<(PathBuf, Option<String>)> {
    let mut roots: Vec<(PathBuf, Option<String>)> = Vec::new();
    let mut registered = |hive: HKEY, path: &str, view: u32, sid: Option<&str>| {
        let Ok(py) = Key::open(hive, path, view) else { return };
        for company in py.subkeys() {
            let Ok(c) = Key::open(py.0, &company, view) else { continue };
            for tag in c.subkeys() {
                if let Some(dir) = Key::open(c.0, &format!(r"{tag}\InstallPath"), view).ok().and_then(|k| k.string("")) {
                    roots.push((PathBuf::from(dir), sid.map(Into::into)));
                }
            }
        }
    };
    registered(HKEY_LOCAL_MACHINE, r"SOFTWARE\Python", KEY_WOW64_64KEY, None);
    registered(HKEY_LOCAL_MACHINE, r"SOFTWARE\Python", KEY_WOW64_32KEY, None);
    for p in profiles {
        registered(HKEY_USERS, &format!(r"{}\SOFTWARE\Python", p.sid), 0, Some(&p.sid));
    }
    let env = |var: &str| std::env::var(var).ok();
    // `C:` alone is the current folder of drive C, not its root
    for dir in [env("SystemDrive").map(|d| format!(r"{d}\")), env("ProgramFiles"), env("ProgramFiles(x86)")].into_iter().flatten() {
        roots.extend(python_dirs(Path::new(&dir)).into_iter().map(|d| (d, None)));
    }
    for p in profiles {
        let local = p.home.join(r"AppData\Local\Programs\Python");
        roots.extend(python_dirs(&local).into_iter().map(|d| (d, Some(p.sid.clone()))));
    }
    let mut sites: Vec<(PathBuf, Option<String>)> = roots.into_iter().map(|(r, sid)| (r.join(r"Lib\site-packages"), sid)).collect();
    for p in profiles {
        let roaming = p.home.join(r"AppData\Roaming\Python");
        sites.extend(python_dirs(&roaming).into_iter().map(|d| (d.join("site-packages"), Some(p.sid.clone()))));
    }
    let mut seen = std::collections::HashSet::new();
    sites.retain(|(s, _)| s.is_dir() && seen.insert(s.display().to_string().to_lowercase()));
    sites
}

/// The global npm package folders: Node.js's own and each user's `npm` prefix.
fn npm_roots(profiles: &[Profile]) -> Vec<(PathBuf, Option<String>)> {
    let mut roots: Vec<(PathBuf, Option<String>)> =
        std::env::var_os("ProgramFiles").map(|v| (PathBuf::from(v).join(r"nodejs\node_modules"), None)).into_iter().collect();
    roots.extend(profiles.iter().map(|p| (p.home.join(r"AppData\Roaming\npm\node_modules"), Some(p.sid.clone()))));
    roots
}

pub fn packages(profiles: &[Profile]) -> Result<Vec<PackageInfo>, String> {
    let mut out = registry_packages()?;
    out.extend(appx_packages());
    for (site, sid) in python_sites(profiles) {
        out.extend(python_packages(&site, sid.as_deref()));
    }
    for (root, sid) in npm_roots(profiles) {
        out.extend(npm_packages(&root, sid.as_deref()));
    }
    Ok(out)
}

fn registry_packages() -> Result<Vec<PackageInfo>, String> {
    let mut raw = Vec::new();
    let mut machine_errors = Vec::new();
    for (view, source, arch) in [(KEY_WOW64_64KEY, "machine", native_arch()), (KEY_WOW64_32KEY, "machine_x86", "x86")] {
        match Key::open(HKEY_LOCAL_MACHINE, UNINSTALL, view) {
            Ok(k) => read_uninstall(&k, view, source, None, Some(arch), &mut raw),
            Err(e) => machine_errors.push(format!("{source} uninstall key not readable (error {e})")),
        }
    }
    if machine_errors.len() == 2 {
        return Err(machine_errors.join("; "));
    }
    // every loaded user hive
    if let Ok(users) = Key::open(HKEY_USERS, "", 0) {
        for sid in users.subkeys() {
            if sid.ends_with("_Classes") || sid.eq_ignore_ascii_case(".DEFAULT") {
                continue;
            }
            if let Ok(k) = Key::open(HKEY_USERS, &format!(r"{sid}\{UNINSTALL}"), 0) {
                read_uninstall(&k, 0, "user", Some(&sid), None, &mut raw);
            }
        }
    }
    Ok(select_packages(raw))
}

// ---------------------------------------------------------------------------------------
// Network interfaces
// ---------------------------------------------------------------------------------------

fn sockaddr_ip(sa: &SOCKET_ADDRESS) -> Option<IpAddr> {
    if sa.lpSockaddr.is_null() {
        return None;
    }
    unsafe {
        match (*sa.lpSockaddr).sa_family {
            AF_INET => {
                let s = &*(sa.lpSockaddr as *const SOCKADDR_IN);
                Some(IpAddr::V4(Ipv4Addr::from(s.sin_addr.S_un.S_addr.to_ne_bytes())))
            }
            AF_INET6 => {
                let s = &*(sa.lpSockaddr as *const SOCKADDR_IN6);
                Some(IpAddr::V6(Ipv6Addr::from(s.sin6_addr.u.Byte)))
            }
            _ => None,
        }
    }
}

pub fn interfaces() -> Result<Vec<NetworkAdapter>, String> {
    let flags = GAA_FLAG_INCLUDE_GATEWAYS | GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;
    let mut size = 16 * 1024u32;
    let mut buf = Vec::new();
    for attempt in 0..5 {
        buf = vec![0u64; (size as usize).div_ceil(8)];
        let mut len = (buf.len() * 8) as u32;
        match unsafe { GetAdaptersAddresses(u32::from(AF_UNSPEC), flags, null(), buf.as_mut_ptr().cast(), &mut len) } {
            ERROR_SUCCESS => break,
            ERROR_NO_DATA => return Ok(Vec::new()),
            ERROR_BUFFER_OVERFLOW if attempt < 4 => size = len.saturating_add(4096),
            rc => return Err(format!("GetAdaptersAddresses failed (error {rc})")),
        }
    }
    let mut out = Vec::new();
    let mut a = buf.as_ptr() as *const IP_ADAPTER_ADDRESSES_LH;
    while !a.is_null() {
        let ad = unsafe { &*a };
        out.push(adapter(ad));
        a = ad.Next;
    }
    Ok(out)
}

fn adapter(ad: &IP_ADAPTER_ADDRESSES_LH) -> NetworkAdapter {
    let mut addresses = Vec::new();
    let mut u = ad.FirstUnicastAddress;
    while !u.is_null() {
        let ua = unsafe { &*u };
        if let Some(ip) = sockaddr_ip(&ua.Address) {
            addresses.push(if_address(ip, Some(ua.OnLinkPrefixLength)));
        }
        u = ua.Next;
    }
    let mut gateway = None;
    let mut g = ad.FirstGatewayAddress;
    while !g.is_null() {
        let ga = unsafe { &*g };
        if let Some(ip @ IpAddr::V4(_)) = sockaddr_ip(&ga.Address) {
            gateway = Some(ip.to_string());
            break;
        }
        g = ga.Next;
    }
    let mac_len = (ad.PhysicalAddressLength as usize).min(ad.PhysicalAddress.len());
    let mac = (mac_len > 0)
        .then(|| ad.PhysicalAddress[..mac_len].iter().map(|b| format!("{b:02X}")).collect::<Vec<_>>().join(":"));
    let if_type = match ad.IfType {
        IF_TYPE_ETHERNET_CSMACD => "ethernet",
        IF_TYPE_IEEE80211 => "wireless",
        IF_TYPE_SOFTWARE_LOOPBACK => "loopback",
        IF_TYPE_TUNNEL => "tunnel",
        _ => "other",
    };
    let dhcp = unsafe { ad.Anonymous2.Flags } & IP_ADAPTER_DHCP_ENABLED != 0;

    let mut row: MIB_IF_ROW2 = unsafe { zeroed() };
    row.InterfaceLuid = ad.Luid;
    let stats = (unsafe { GetIfEntry2(&mut row) } == ERROR_SUCCESS).then_some(row);
    // u64::MAX: the speed is not known
    let speed = if ad.TransmitLinkSpeed == u64::MAX { 0 } else { ad.TransmitLinkSpeed / 1_000_000 };

    NetworkAdapter {
        name: unsafe { pwstr(ad.FriendlyName) }.unwrap_or_default(),
        mac_address: mac,
        ipv4: addresses.iter().filter(|a| a.family == "ipv4").map(|a| a.address.clone()).collect(),
        ipv6: addresses.iter().filter(|a| a.family == "ipv6").map(|a| a.address.clone()).collect(),
        rx_bytes: stats.map_or(0, |s| s.InOctets),
        tx_bytes: stats.map_or(0, |s| s.OutOctets),
        rx_packets: stats.map_or(0, |s| s.InUcastPkts + s.InNUcastPkts),
        tx_packets: stats.map_or(0, |s| s.OutUcastPkts + s.OutNUcastPkts),
        speed_mbps: u32::try_from(speed).unwrap_or(u32::MAX),
        if_type: Some(if_type.into()),
        state: Some(if ad.OperStatus == IfOperStatusUp { "up" } else { "down" }.into()),
        // the loopback reports no limit (all bits set)
        mtu: (ad.Mtu != u32::MAX).then_some(ad.Mtu),
        rx_errors: stats.map(|s| s.InErrors),
        tx_errors: stats.map(|s| s.OutErrors),
        rx_dropped: stats.map(|s| s.InDiscards),
        tx_dropped: stats.map(|s| s.OutDiscards),
        gateway,
        dhcp: Some(if dhcp { "enabled" } else { "disabled" }.into()),
        metric: Some(ad.Ipv4Metric),
        addresses,
    }
}

