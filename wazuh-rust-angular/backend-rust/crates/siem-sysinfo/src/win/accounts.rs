//! Users and groups: `UsersHelper` (users_utils_wrapper.cpp), `GroupsHelper`
//! (groups_utils_wrapper.cpp), `UserGroupsProvider` (user_groups_windows.cpp),
//! `UsersProvider` (users_windows.cpp), `GroupsProvider` (groups_windows.cpp),
//! `LoggedInUsersProvider` (logged_in_users_win.cpp) and the mappings of
//! `SysInfo::getGroups()` / `getUsers()`.
//!
//! The helpers' caches are per thread and valid for 60 seconds, and each
//! batch of 100 lookups sleeps 250 ms, like the C++.

use std::cell::RefCell;
use std::collections::{BTreeSet, HashMap};
use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::{GetLastError, LocalFree, ERROR_INSUFFICIENT_BUFFER, ERROR_MORE_DATA, ERROR_SUCCESS};
use windows_sys::Win32::NetworkManagement::NetManagement::*;
use windows_sys::Win32::Security::Authorization::{ConvertSidToStringSidW, ConvertStringSidToSidA};
use windows_sys::Win32::Security::*;
use windows_sys::Win32::System::Registry::*;
use windows_sys::Win32::System::RemoteDesktop::*;

use super::enc;
use crate::json::{as_str, i, s, u, Obj, Value, PRIMARY_ARRAY_SEPARATOR, SECONDARY_ARRAY_SEPARATOR};
use crate::UNKNOWN_VALUE;

const BATCH_SIZE: usize = 100;
const BATCH_DELAY: Duration = Duration::from_millis(250);
const CACHE_TIMEOUT: Duration = Duration::from_secs(60);
const REG_PROFILE_KEY: &str = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList";
const WELL_KNOWN_SIDS: [&str; 17] = [
    "S-1-5-1", "S-1-5-2", "S-1-5-3", "S-1-5-4", "S-1-5-6", "S-1-5-7", "S-1-5-8", "S-1-5-9", "S-1-5-10", "S-1-5-11", "S-1-5-12", "S-1-5-13",
    "S-1-5-18", "S-1-5-19", "S-1-5-20", "S-1-5-21", "S-1-5-32",
];
const MAX_PREFERRED_LENGTH: u32 = u32::MAX;
const NERR_SUCCESS: u32 = 0;

/// `std::cerr << ...`
fn cerr(m: String) {
    eprintln!("{m}");
}

/// `User`
#[derive(Clone, Debug)]
pub struct User {
    pub uid: u32,
    pub gid: u32,
    pub sid: String,
    pub username: String,
    pub description: String,
    pub r#type: String,
    pub directory: String,
}

impl Default for User {
    fn default() -> Self {
        User { uid: u32::MAX, gid: u32::MAX, sid: String::new(), username: String::new(), description: String::new(), r#type: String::new(), directory: String::new() }
    }
}

/// `Group`
#[derive(Clone, Debug)]
pub struct Group {
    pub gid: u32,
    pub sid: String,
    pub groupname: String,
    pub comment: String,
}

#[derive(Default)]
struct UsersCache {
    local: Vec<User>,
    roaming: Vec<User>,
    at: Option<Instant>,
    valid: bool,
}

#[derive(Default)]
struct GroupsCache {
    groups: Vec<Group>,
    at: Option<Instant>,
    valid: bool,
}

#[derive(Default)]
struct UserGroupsCache {
    map: HashMap<String, Vec<String>>,
    at: Option<Instant>,
    valid: bool,
    api_calls: usize,
}

thread_local! {
    static USERS: RefCell<UsersCache> = RefCell::new(UsersCache::default());
    static GROUPS: RefCell<GroupsCache> = RefCell::new(GroupsCache::default());
    static USER_GROUPS: RefCell<UserGroupsCache> = RefCell::new(UserGroupsCache::default());
}

fn expired(valid: bool, at: Option<Instant>) -> bool {
    valid && at.map(|t| t.elapsed() >= CACHE_TIMEOUT).unwrap_or(true)
}

fn wstr(p: *const u16) -> Vec<u16> {
    if p.is_null() {
        return Vec::new();
    }
    let mut n = 0;
    // SAFETY: NUL-terminated wide strings from the APIs.
    unsafe {
        while *p.add(n) != 0 {
            n += 1;
        }
        std::slice::from_raw_parts(p, n).to_vec()
    }
}

fn utf8(p: *const u16) -> String {
    String::from_utf8_lossy(&enc::wstring_to_utf8(&wstr(p))).into_owned()
}

fn wz_of(v: &[u16]) -> Vec<u16> {
    let mut z = v.to_vec();
    z.push(0);
    z
}

/// A NetApi buffer freed on drop.
struct NetBuf(*mut u8);

impl Drop for NetBuf {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: a buffer the NetApi allocated.
            unsafe { NetApiBufferFree(self.0.cast()) };
        }
    }
}

/// `getSidFromAccountName`: the SID buffer, or None.
pub fn sid_from_account_name(name: &[u16]) -> Option<Vec<u8>> {
    if name.is_empty() || name[0] == 0 {
        cerr("No account name provided".into());
        return None;
    }
    let z = wz_of(name);
    let disp = || String::from_utf8_lossy(&enc::wstring_to_utf8(name)).into_owned();
    // SAFETY: size query, then sized buffers.
    unsafe {
        let (mut sid_size, mut dom_size) = (0u32, 0u32);
        let mut use_ = 0;
        let r = LookupAccountNameW(std::ptr::null(), z.as_ptr(), std::ptr::null_mut(), &mut sid_size, std::ptr::null_mut(), &mut dom_size, &mut use_);
        if r == 0 && GetLastError() != ERROR_INSUFFICIENT_BUFFER {
            cerr(format!("Failed to lookup account name {} with {}", disp(), GetLastError()));
            return None;
        }
        let mut sid = vec![0u8; sid_size as usize];
        let mut dom = vec![0u16; dom_size as usize];
        let r = LookupAccountNameW(std::ptr::null(), z.as_ptr(), sid.as_mut_ptr().cast(), &mut sid_size, dom.as_mut_ptr(), &mut dom_size, &mut use_);
        if r == 0 {
            cerr(format!("Failed to lookup account name {} with {}", disp(), GetLastError()));
            return None;
        }
        if IsValidSid(sid.as_mut_ptr().cast()) == 0 {
            cerr(format!("The SID for {} is invalid.", disp()));
        }
        Some(sid)
    }
}

/// `psidToString`
pub fn psid_to_string(sid: PSID) -> String {
    let mut out: *mut u16 = std::ptr::null_mut();
    // SAFETY: the string is LocalFree'd.
    unsafe {
        if ConvertSidToStringSidW(sid, &mut out) == 0 {
            cerr(format!("ConvertSidToStringW failed with {}", GetLastError()));
            return String::new();
        }
        let r = utf8(out);
        LocalFree(out.cast());
        r
    }
}

/// `getRidFromSid`
pub fn rid_from_sid(sid: PSID) -> u32 {
    // SAFETY: a SID the APIs returned.
    unsafe {
        let count = *GetSidSubAuthorityCount(sid);
        *GetSidSubAuthority(sid, (count as u32).wrapping_sub(1))
    }
}

fn open_key(sub: &str) -> Option<HKEY> {
    let z = enc::wz(sub);
    let mut h: HKEY = std::ptr::null_mut();
    // SAFETY: valid name and out pointer; 32-bit view like the agent.
    (unsafe { RegOpenKeyExW(HKEY_LOCAL_MACHINE, z.as_ptr(), 0, KEY_READ | KEY_WOW64_32KEY, &mut h) } == ERROR_SUCCESS).then_some(h)
}

/// `getUserHomeDir(sid)`
fn user_home_dir(sid: &str) -> String {
    let Some(h) = open_key(&format!("{REG_PROFILE_KEY}\\{sid}")) else { return String::new() };
    // SAFETY: sizes from RegQueryInfoKeyW; the key is closed below.
    let r = unsafe {
        let (mut values, mut max_len) = (0u32, 0u32);
        let ret = RegQueryInfoKeyW(
            h,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut values,
            std::ptr::null_mut(),
            &mut max_len,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        );
        if ret != ERROR_SUCCESS || values == 0 {
            String::new()
        } else {
            let mut data = vec![0u16; (max_len / 2) as usize];
            let mut len = max_len;
            let mut ty = 0u32;
            let name = enc::wz("ProfileImagePath");
            let ret = RegQueryValueExW(h, name.as_ptr(), std::ptr::null(), &mut ty, data.as_mut_ptr().cast(), &mut len);
            if ret != ERROR_SUCCESS || !(ty == REG_SZ || ty == REG_MULTI_SZ || ty == REG_EXPAND_SZ) {
                String::new()
            } else {
                let mut w = data[..((len / 2) as usize).min(data.len())].to_vec();
                if let Some(p) = w.iter().position(|&c| c == 0) {
                    w.truncate(p);
                }
                String::from_utf8_lossy(&enc::wstring_to_utf8(&w)).into_owned()
            }
        }
    };
    // SAFETY: the key opened above.
    unsafe { RegCloseKey(h) };
    r
}

/// `getGidFromUsername`
fn gid_from_username(name: &[u16]) -> Option<u32> {
    let z = wz_of(name);
    // SAFETY: NetApi buffers freed by NetBuf.
    unsafe {
        let mut buf: *mut u8 = std::ptr::null_mut();
        let (mut read, mut total) = (0u32, 0u32);
        let ret = NetUserGetLocalGroups(std::ptr::null(), z.as_ptr(), 0, 0, &mut buf, MAX_PREFERRED_LENGTH, &mut read, &mut total);
        let b = NetBuf(buf);
        if ret == NERR_SUCCESS && !b.0.is_null() {
            let info = &*(b.0 as *const LOCALGROUP_USERS_INFO_0);
            let mut gid = None;
            if let Some(mut sid) = sid_from_account_name(&wstr(info.lgrui0_name)) {
                gid = Some(rid_from_sid(sid.as_mut_ptr().cast()));
            }
            return gid;
        }
        drop(b);
        let mut buf: *mut u8 = std::ptr::null_mut();
        let ret = NetUserGetInfo(std::ptr::null(), z.as_ptr(), 3, &mut buf);
        let b = NetBuf(buf);
        if ret == NERR_SUCCESS {
            return Some((*(b.0 as *const USER_INFO_3)).usri3_primary_group_id);
        }
    }
    None
}

/// `getRoamingProfileSids`: None on an error.
fn roaming_profile_sids() -> Option<Vec<String>> {
    let h = open_key(REG_PROFILE_KEY)?;
    let mut out = Vec::new();
    // SAFETY: the key is closed on every path.
    let ok = unsafe {
        let mut count = 0u32;
        let mut max_name = 0u32;
        let ret = RegQueryInfoKeyW(
            h,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null(),
            &mut count,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut max_name,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        );
        if ret != ERROR_SUCCESS {
            false
        } else {
            let mut name = vec![0u16; 255];
            let mut ok = true;
            for i in 0..count {
                if RegEnumKeyW(h, i, name.as_mut_ptr(), 255) != ERROR_SUCCESS {
                    ok = false;
                    break;
                }
                out.push(String::from_utf8_lossy(&enc::wstring_to_utf8(enc::wide_cstr(&name))).into_owned());
            }
            ok
        }
    };
    // SAFETY: the key opened above.
    unsafe { RegCloseKey(h) };
    ok.then_some(out)
}

/// `UsersHelper::loadUsers`
fn load_users(processed: &mut BTreeSet<String>) {
    let valid = USERS.with(|c| {
        let mut c = c.borrow_mut();
        if expired(c.valid, c.at) {
            c.local.clear();
            c.roaming.clear();
            c.valid = false;
        }
        c.valid
    });
    if valid {
        return;
    }
    let mut users: Vec<User> = Vec::new();
    let mut resume: u32 = 0;
    // SAFETY: NetApi buffers freed by NetBuf.
    unsafe {
        loop {
            let mut buf: *mut u8 = std::ptr::null_mut();
            let (mut read, mut total) = (0u32, 0u32);
            let mut ret = NetUserEnum(std::ptr::null(), 0, FILTER_NORMAL_ACCOUNT, &mut buf, MAX_PREFERRED_LENGTH, &mut read, &mut total, &mut resume);
            let b = NetBuf(buf);
            if ret != NERR_SUCCESS && ret != ERROR_MORE_DATA {
                break;
            }
            if b.0.is_null() {
                break;
            }
            let list = std::slice::from_raw_parts(b.0 as *const USER_INFO_0, read as usize);
            for u0 in list {
                let mut buf4: *mut u8 = std::ptr::null_mut();
                ret = NetUserGetInfo(std::ptr::null(), u0.usri0_name, 4, &mut buf4);
                let b4 = NetBuf(buf4);
                if ret != NERR_SUCCESS || b4.0.is_null() {
                    continue;
                }
                let u4 = &*(b4.0 as *const USER_INFO_4);
                let sid = u4.usri4_user_sid;
                let sid_string = psid_to_string(sid);
                processed.insert(sid_string.clone());
                let mut nu = User { username: utf8(u4.usri4_name), uid: rid_from_sid(sid), ..Default::default() };
                nu.gid = gid_from_username(&wstr(u4.usri4_name)).unwrap_or(nu.uid);
                nu.description = utf8(u4.usri4_comment);
                nu.directory = user_home_dir(&sid_string);
                nu.r#type = "local".into();
                nu.sid = sid_string;
                users.push(nu);
                if users.len() % BATCH_SIZE == 0 {
                    std::thread::sleep(BATCH_DELAY);
                }
            }
            if ret != ERROR_MORE_DATA {
                break;
            }
        }
    }
    USERS.with(|c| c.borrow_mut().local = users);
    let Some(sids) = roaming_profile_sids() else {
        USERS.with(|c| {
            let mut c = c.borrow_mut();
            c.at = Some(Instant::now());
            c.valid = true;
        });
        return;
    };
    let mut roaming: Vec<User> = Vec::new();
    for profile_sid in sids {
        if processed.contains(&profile_sid) {
            continue;
        }
        let mut nu = User {
            sid: profile_sid.clone(),
            r#type: if WELL_KNOWN_SIDS.contains(&profile_sid.as_str()) { "special" } else { "roaming" }.into(),
            ..Default::default()
        };
        let mut psid: PSID = std::ptr::null_mut();
        let ps = enc::az(profile_sid.as_bytes());
        // SAFETY: the SID is freed after use.
        unsafe {
            if ConvertStringSidToSidA(ps.as_ptr(), &mut psid) == 0 {
                continue;
            }
            nu.uid = rid_from_sid(psid);
            nu.directory = user_home_dir(&profile_sid);
            let mut account = [0u16; 256];
            let mut domain = [0u16; 15];
            let (mut alen, mut dlen) = (256u32, 15u32);
            let mut use_ = 0;
            let ok = LookupAccountSidW(std::ptr::null(), psid, account.as_mut_ptr(), &mut alen, domain.as_mut_ptr(), &mut dlen, &mut use_);
            FreeSid(psid);
            let acc = enc::wide_cstr(&account).to_vec();
            if ok != 0 {
                nu.username = String::from_utf8_lossy(&enc::wstring_to_utf8(&acc)).into_owned();
                nu.gid = gid_from_username(&acc).unwrap_or(nu.uid);
            } else {
                nu.gid = u32::MAX;
            }
            let mut b2: *mut u8 = std::ptr::null_mut();
            let accz = wz_of(&acc);
            let r = NetUserGetInfo(std::ptr::null(), accz.as_ptr(), 2, &mut b2);
            let b2 = NetBuf(b2);
            if r == NERR_SUCCESS && !b2.0.is_null() {
                nu.description = utf8((*(b2.0 as *const USER_INFO_2)).usri2_comment);
            }
        }
        roaming.push(nu);
        if roaming.len() % BATCH_SIZE == 0 {
            std::thread::sleep(BATCH_DELAY);
        }
        processed.insert(profile_sid);
    }
    USERS.with(|c| {
        let mut c = c.borrow_mut();
        c.roaming = roaming;
        c.at = Some(Instant::now());
        c.valid = true;
    });
}

/// `processLocalAccounts`
fn process_local_accounts(processed: &mut BTreeSet<String>) -> Vec<User> {
    load_users(processed);
    let local = USERS.with(|c| c.borrow().local.clone());
    for u in &local {
        processed.insert(u.sid.clone());
    }
    local
}

/// `processRoamingProfiles`
fn process_roaming_profiles(processed: &mut BTreeSet<String>) -> Vec<User> {
    load_users(processed);
    USERS.with(|c| c.borrow().roaming.clone())
}

/// `GroupsHelper::processLocalGroups`
fn process_local_groups() -> Vec<Group> {
    let cached = GROUPS.with(|c| {
        let mut c = c.borrow_mut();
        if expired(c.valid, c.at) {
            c.groups.clear();
            c.valid = false;
        }
        c.valid.then(|| c.groups.clone())
    });
    if let Some(g) = cached {
        return g;
    }
    let mut groups: Vec<Group> = Vec::new();
    // SAFETY: NetApi buffers freed by NetBuf.
    unsafe {
        loop {
            let mut buf: *mut u8 = std::ptr::null_mut();
            let (mut read, mut total) = (0u32, 0u32);
            let ret = NetLocalGroupEnum(std::ptr::null(), 1, &mut buf, MAX_PREFERRED_LENGTH, &mut read, &mut total, std::ptr::null_mut());
            let b = NetBuf(buf);
            if ret != NERR_SUCCESS && ret != ERROR_MORE_DATA {
                break;
            }
            if b.0.is_null() {
                break;
            }
            let list = std::slice::from_raw_parts(b.0 as *const LOCALGROUP_INFO_1, read as usize);
            for g in list {
                let Some(mut sid) = sid_from_account_name(&wstr(g.lgrpi1_name)) else { continue };
                let p: PSID = sid.as_mut_ptr().cast();
                groups.push(Group { sid: psid_to_string(p), comment: utf8(g.lgrpi1_comment), gid: rid_from_sid(p), groupname: utf8(g.lgrpi1_name) });
                if groups.len() % BATCH_SIZE == 0 {
                    std::thread::sleep(BATCH_DELAY);
                }
            }
            if ret != ERROR_MORE_DATA {
                break;
            }
        }
    }
    GROUPS.with(|c| {
        let mut c = c.borrow_mut();
        c.groups = groups.clone();
        c.at = Some(Instant::now());
        c.valid = true;
    });
    groups
}

fn ug_validate() {
    USER_GROUPS.with(|c| {
        let mut c = c.borrow_mut();
        if expired(c.valid, c.at) {
            c.map.clear();
            c.valid = false;
            c.api_calls = 0;
        }
    });
}

fn ug_update() {
    USER_GROUPS.with(|c| {
        let mut c = c.borrow_mut();
        c.at = Some(Instant::now());
        c.valid = true;
    });
}

/// `UserGroupsProvider::getLocalUsers`
fn get_local_users(uids: &BTreeSet<u32>) -> Vec<User> {
    let mut processed = BTreeSet::new();
    process_local_accounts(&mut processed)
        .into_iter()
        .filter(|u| (uids.is_empty() || uids.contains(&u.uid)) && !matches!(u.username.as_str(), "LOCAL SERVICE" | "SYSTEM" | "NETWORK SERVICE"))
        .collect()
}

/// `getLocalGroupNamesForUser`
fn local_group_names_for_user(username: &str) -> Vec<String> {
    if let Some(v) = USER_GROUPS.with(|c| c.borrow().map.get(username).cloned()) {
        return v;
    }
    let calls = USER_GROUPS.with(|c| c.borrow().api_calls);
    if calls > 0 && calls % BATCH_SIZE == 0 {
        std::thread::sleep(BATCH_DELAY);
    }
    USER_GROUPS.with(|c| c.borrow_mut().api_calls += 1);
    let w = wz_of(&enc::utf8_to_wstring(username.as_bytes()));
    let mut names = Vec::new();
    // SAFETY: NetApi buffer freed by NetBuf.
    unsafe {
        let mut buf: *mut u8 = std::ptr::null_mut();
        let (mut read, mut total) = (0u32, 0u32);
        let ret = NetUserGetLocalGroups(std::ptr::null(), w.as_ptr(), 0, 1, &mut buf, MAX_PREFERRED_LENGTH, &mut read, &mut total);
        let b = NetBuf(buf);
        if ret == NERR_SUCCESS && !b.0.is_null() {
            for g in std::slice::from_raw_parts(b.0 as *const LOCALGROUP_USERS_INFO_0, read as usize) {
                names.push(utf8(g.lgrui0_name));
            }
        }
    }
    USER_GROUPS.with(|c| c.borrow_mut().map.insert(username.to_string(), names.clone()));
    names
}

/// `getGroupNamesByUid({uid})` (one uid: an array)
fn group_names_by_uid(uid: u32) -> Vec<String> {
    ug_validate();
    let users = get_local_users(&BTreeSet::from([uid]));
    let _groups = process_local_groups();
    let mut out = Vec::new();
    for u in users {
        out.extend(local_group_names_for_user(&u.username));
    }
    ug_update();
    out
}

/// `getUserNamesByGid({gid})` (one gid: an array)
fn user_names_by_gid(gid: u32) -> Vec<String> {
    ug_validate();
    let users = get_local_users(&BTreeSet::new());
    let groups = process_local_groups();
    let mut out = Vec::new();
    for u in &users {
        for gname in local_group_names_for_user(&u.username) {
            if let Some(g) = groups.iter().find(|g| g.groupname == gname) {
                if g.gid == gid {
                    out.push(u.username.clone());
                }
            }
        }
    }
    ug_update();
    out
}

/// `SysInfo::getGroups()`
pub fn get_groups() -> Value {
    let mut result = Vec::new();
    for g in process_local_groups() {
        let mut o = Obj::new();
        o.set("group_id", u(g.gid as u64));
        o.set("group_name", s(if g.groupname.is_empty() { UNKNOWN_VALUE } else { &g.groupname }));
        o.set("group_description", s(&g.comment));
        o.set("group_id_signed", i(g.gid as i32 as i64));
        o.set("group_uuid", s(&g.sid));
        o.set("group_is_hidden", i(0));
        // static_cast<std::uint32_t>(group["gid"].get<int>())
        let users = user_names_by_gid(g.gid as i32 as u32);
        o.set("group_users", s(if users.is_empty() { UNKNOWN_VALUE.to_string() } else { users.join(SECONDARY_ARRAY_SEPARATOR) }));
        result.push(o.into_value());
    }
    if result.is_empty() {
        Value::Null
    } else {
        Value::Array(result)
    }
}

/// `WTSCLIENTA`, which the C++ reads a `WTSClientInfo` (wide) buffer through.
#[repr(C)]
struct WtsClientA {
    client_name: [u8; 21],
    domain: [u8; 18],
    user_name: [u8; 21],
    work_directory: [u8; 261],
    initial_program: [u8; 261],
    encryption_level: u8,
    client_address_family: u32,
    client_address: [u16; 31],
}

/// One `LoggedInUsersProvider::collect()` entry.
struct LoggedIn {
    user: String,
    r#type: String,
    tty: String,
    time: u64,
    host: Option<String>,
    pid: Option<i32>,
}

/// `LoggedInUsersProvider::collect()`
fn logged_in_users() -> Vec<LoggedIn> {
    let mut results = Vec::new();
    // SAFETY: WTS buffers freed with WTSFreeMemory.
    unsafe {
        let mut info: *mut WTS_SESSION_INFOW = std::ptr::null_mut();
        let mut count = 0u32;
        if WTSEnumerateSessionsW(std::ptr::null_mut(), 0, 1, &mut info, &mut count) == 0 {
            return results;
        }
        let sessions = std::slice::from_raw_parts(info, count as usize);
        for si in sessions {
            if si.State != WTSActive || si.SessionId == 0 {
                continue;
            }
            let mut sbuf: *mut u16 = std::ptr::null_mut();
            let mut bytes = 0u32;
            if WTSQuerySessionInformationW(std::ptr::null_mut(), si.SessionId, WTSSessionInfo, &mut sbuf, &mut bytes) == 0 || sbuf.is_null() {
                cerr(format!("Error querying WTS session information ({})", GetLastError()));
                continue;
            }
            let ws = &*(sbuf as *const WTSINFOW);
            let user = String::from_utf8_lossy(&enc::wstring_to_utf8(enc::wide_cstr(&ws.UserName))).into_owned();
            let state = match si.State {
                0 => "active",
                1 => "connected",
                2 => "connectquery",
                3 => "shadow",
                4 => "disconnected",
                5 => "idle",
                6 => "listen",
                7 => "reset",
                8 => "down",
                _ => "init",
            };
            let tty = if si.pWinStationName.is_null() { String::new() } else { utf8(si.pWinStationName) };
            let ct = ws.ConnectTime as u64;
            let time = if ct != 0 { ct.wrapping_sub(116444736000000000) / 10_000_000 } else { 0 };
            let mut entry = LoggedIn { user, r#type: state.into(), tty, time, host: None, pid: None };
            let mut cbuf: *mut u16 = std::ptr::null_mut();
            bytes = 0;
            if WTSQuerySessionInformationW(std::ptr::null_mut(), si.SessionId, WTSClientInfo, &mut cbuf, &mut bytes) == 0 || cbuf.is_null() {
                cerr(format!("Error querying WTS session information ({})", GetLastError()));
                // no "host" and no "pid": the C pushes the entry as it is
                results.push(entry);
                WTSFreeMemory(sbuf.cast());
                continue;
            }
            let wc = &*(cbuf as *const WtsClientA);
            let mut host = String::new();
            match wc.client_address_family as u16 {
                windows_sys::Win32::Networking::WinSock::AF_INET => {
                    host = format!("{}.{}.{}.{}", wc.client_address[0], wc.client_address[1], wc.client_address[2], wc.client_address[3]);
                }
                windows_sys::Win32::Networking::WinSock::AF_INET6 => {
                    let raw = std::slice::from_raw_parts(wc.client_address.as_ptr() as *const u8, 30);
                    host = String::from_utf8_lossy(raw).into_owned();
                }
                windows_sys::Win32::Networking::WinSock::AF_UNSPEC => {
                    let mut nbuf: *mut u16 = std::ptr::null_mut();
                    if WTSQuerySessionInformationW(std::ptr::null_mut(), si.SessionId, WTSClientName, &mut nbuf, &mut bytes) == 0 || nbuf.is_null() {
                        cerr(format!("Error querying WTS clientName information ({})", GetLastError()));
                    } else {
                        host = utf8(nbuf);
                    }
                    if !nbuf.is_null() {
                        WTSFreeMemory(nbuf.cast());
                    }
                }
                _ => {}
            }
            entry.host = Some(host);
            entry.pid = Some(-1);
            WTSFreeMemory(cbuf.cast());
            // (the SID lookup of DOMAIN\\user only fills "sid"/"registry_hive")
            let mut du: Vec<u16> = enc::wide_cstr(&ws.Domain).to_vec();
            du.extend("\\".encode_utf16());
            du.extend_from_slice(enc::wide_cstr(&ws.UserName));
            WTSFreeMemory(sbuf.cast());
            if sid_from_account_name(&du).is_none() {
                cerr("Error converting username to SID".into());
            }
            results.push(entry);
        }
        WTSFreeMemory(info.cast());
    }
    results
}

/// `SysInfo::getUsers()`
pub fn get_users() -> Result<Value, super::Error> {
    let mut processed = BTreeSet::new();
    let mut users = process_local_accounts(&mut processed);
    users.extend(process_roaming_profiles(&mut processed));
    let logged = logged_in_users();
    let mut result = Vec::new();
    for user in users {
        let username = if user.username.is_empty() { UNKNOWN_VALUE.to_string() } else { user.username.clone() };
        let mut o = Obj::new();
        o.set("user_id", u(user.uid as u64));
        o.set("user_full_name", s(&user.description));
        o.set("user_home", s(&user.directory));
        o.set("user_name", s(&username));
        o.set("user_shell", s("C:\\Windows\\system32\\cmd.exe"));
        o.set("user_uid_signed", i(user.uid as i32 as i64));
        o.set("user_group_id_signed", i(user.gid as i32 as i64));
        o.set("user_group_id", u(user.gid as u64));
        let groups = group_names_by_uid(user.uid as i32 as u32);
        o.set("user_groups", s(if groups.is_empty() { UNKNOWN_VALUE.to_string() } else { groups.join(SECONDARY_ARRAY_SEPARATOR) }));
        o.set("user_type", s(&user.r#type));
        o.set("user_uuid", s(&user.sid));
        o.set("user_is_remote", i(0));
        o.set("user_is_hidden", i(0));
        o.set("user_created", i(0));
        o.set("user_auth_failed_count", i(0));
        o.set("user_auth_failed_timestamp", i(0));
        let mut matched = false;
        let mut last_login: i32 = 0;
        o.set("host_ip", s(UNKNOWN_VALUE));
        for item in &logged {
            o.set("login_status", i(0));
            if item.user == username {
                matched = true;
                o.set("login_status", i(1));
                let new_date = item.time as i32;
                if new_date > last_login {
                    last_login = new_date;
                    o.set("user_last_login", i(new_date as i64));
                    o.set("login_tty", s(&item.tty));
                    o.set("login_type", s(&item.r#type));
                    // item["pid"].get<int32_t>() on a missing key (null) throws
                    let Some(pid) = item.pid else {
                        return Err(super::Error("[json.exception.type_error.302] type must be number, but is null".into()));
                    };
                    o.set("process_pid", i(pid as i64));
                }
                let Some(host) = item.host.clone() else {
                    return Err(super::Error("[json.exception.type_error.303] incompatible ReferenceType for get_ref, actual type is null".into()));
                };
                if !host.is_empty() {
                    let cur = as_str(o.get("host_ip"));
                    o.set("host_ip", s(if cur == UNKNOWN_VALUE { host } else { format!("{cur}{PRIMARY_ARRAY_SEPARATOR}{host}") }));
                }
            }
        }
        if !matched {
            o.set("login_status", i(0));
            o.set("login_tty", s(UNKNOWN_VALUE));
            o.set("login_type", s(UNKNOWN_VALUE));
            o.set("process_pid", i(0));
            o.set("user_last_login", i(0));
        }
        o.set("user_password_expiration_date", i(0));
        o.set("user_password_hash_algorithm", s(UNKNOWN_VALUE));
        o.set("user_password_inactive_days", i(0));
        o.set("user_password_last_change", i(0));
        o.set("user_password_max_days_between_changes", i(0));
        o.set("user_password_min_days_between_changes", i(0));
        o.set("user_password_status", s(UNKNOWN_VALUE));
        o.set("user_password_warning_days_before_expiration", i(0));
        result.push(o.into_value());
    }
    Ok(if result.is_empty() { Value::Null } else { Value::Array(result) })
}
