//! The processes of `sysInfoWin.cpp` (`SysInfoProcess`, `getProcessInfo`,
//! `fillProcessesData`) and `parseProcessCommandLine` (utilsWrapperWin.cpp).

use std::collections::BTreeMap;
use std::sync::Mutex;

use windows_sys::Wdk::System::Threading::NtQueryInformationProcess;
use windows_sys::Win32::Foundation::{CloseHandle, LocalFree, FILETIME, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Storage::FileSystem::{GetLogicalDriveStringsA, QueryDosDeviceA};
use windows_sys::Win32::System::Diagnostics::ToolHelp::*;
use windows_sys::Win32::System::ProcessStatus::{GetProcessImageFileNameA, GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS};
use windows_sys::Win32::System::RemoteDesktop::ProcessIdToSessionId;
use windows_sys::Win32::System::Threading::{GetProcessTimes, OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ};
use windows_sys::Win32::UI::Shell::CommandLineToArgvW;

use super::{enc, helpers, Error};
use crate::json::{i, s, u, Obj, Value};
use crate::strings;

const OS_MAXSTR: usize = 65536;
const OS_SIZE_32768: usize = 32768;
/// `ProcessCommandLineInformation`
const PROCESS_COMMAND_LINE_INFORMATION: i32 = 60;
const STATUS_INFO_LENGTH_MISMATCH: i32 = 0xC0000004u32 as i32;
const STATUS_BUFFER_OVERFLOW: i32 = 0x80000005u32 as i32;
const STATUS_BUFFER_TOO_SMALL: i32 = 0xC0000023u32 as i32;

/// A `PROCESSENTRY32` (ANSI) as the callbacks see it.
pub struct ProcessEntry {
    pub pid: u32,
    pub ppid: u32,
    pub threads: u32,
    pub pri_class_base: i32,
    /// `szExeFile` (ANSI bytes)
    pub exe_file: Vec<u8>,
}

/// `fillProcessesData`
pub fn fill_processes_data(mut f: impl FnMut(&ProcessEntry)) -> Result<(), Error> {
    // SAFETY: a snapshot handle closed on every path.
    unsafe {
        let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snap == INVALID_HANDLE_VALUE {
            return Err(Error("Unable to create process snapshot.".into()));
        }
        let mut pe: PROCESSENTRY32 = std::mem::zeroed();
        pe.dwSize = std::mem::size_of::<PROCESSENTRY32>() as u32;
        if Process32First(snap, &mut pe) == 0 {
            CloseHandle(snap);
            return Err(Error("Unable to retrieve process information from the snapshot.".into()));
        }
        loop {
            let name: Vec<u8> = pe.szExeFile.iter().take_while(|&&c| c != 0).map(|&c| c as u8).collect();
            f(&ProcessEntry { pid: pe.th32ProcessID, ppid: pe.th32ParentProcessID, threads: pe.cntThreads, pri_class_base: pe.pcPriClassBase, exe_file: name });
            if Process32Next(snap, &mut pe) == 0 {
                break;
            }
        }
        CloseHandle(snap);
    }
    Ok(())
}

type DrivesMap = BTreeMap<Vec<u8>, Vec<u8>>;

static DRIVES: Mutex<Option<DrivesMap>> = Mutex::new(None);

fn cbuf(b: &[u8]) -> Vec<u8> {
    b[..b.iter().position(|&c| c == 0).unwrap_or(b.len())].to_vec()
}

/// `getNtWin32DrivesMap`
fn nt_win32_drives_map() -> DrivesMap {
    let mut ret = DrivesMap::new();
    let mut logical = vec![0u8; OS_MAXSTR];
    // SAFETY: buffers sized as passed.
    unsafe {
        let res = GetLogicalDriveStringsA((OS_MAXSTR - 1) as u32, logical.as_mut_ptr());
        if res == 0 || res as usize > OS_MAXSTR {
            // std::system_error out of the static initializer
            return ret;
        }
        let drives = strings::split_null_terminated(&logical);
        let mut dos = vec![0u8; OS_MAXSTR];
        for d in &drives {
            let norm = if d.last() == Some(&b'\\') { &d[..d.len() - 1] } else { &d[..] };
            let n = enc::az(norm);
            if QueryDosDeviceA(n.as_ptr(), dos.as_mut_ptr(), OS_MAXSTR as u32) != 0 {
                ret.insert(cbuf(&dos), d.clone());
            }
        }
        if drives.len() != ret.len() {
            let mut phys = vec![0u8; OS_SIZE_32768];
            if QueryDosDeviceA(std::ptr::null(), phys.as_mut_ptr(), OS_SIZE_32768 as u32) != 0 {
                let tokens = strings::split_null_terminated(&phys);
                let mut dos = vec![0u8; OS_SIZE_32768];
                for t in tokens {
                    if !drives.iter().any(|d| !d.is_empty() && d.len() >= t.len() && d.starts_with(&t)) {
                        continue;
                    }
                    let tz = enc::az(&t);
                    if QueryDosDeviceA(tz.as_ptr(), dos.as_mut_ptr(), OS_SIZE_32768 as u32) != 0 {
                        let key = cbuf(&dos);
                        if !ret.contains_key(&key) {
                            let mut v = t.clone();
                            v.push(b'\\');
                            ret.insert(key, v);
                            if drives.len() == ret.len() {
                                break;
                            }
                        }
                    }
                }
            }
        }
    }
    ret
}

/// `fillOutput`
fn fill_output(map: &DrivesMap, nt: &[u8]) -> Option<Vec<u8>> {
    let (k, v) = map.iter().find(|(k, _)| !nt.is_empty() && nt.len() >= k.len() && nt.starts_with(k))?;
    let mut out = v.clone();
    // ntPath.substr(key.size() + 1): out_of_range past the end
    let from = k.len() + 1;
    if from <= nt.len() {
        out.extend_from_slice(&nt[from..]);
    }
    Some(out)
}

/// `ntPath2Win32Path`
fn nt_path_to_win32(nt: &[u8]) -> Vec<u8> {
    let mut g = DRIVES.lock().unwrap();
    let map = g.get_or_insert_with(nt_win32_drives_map);
    if let Some(o) = fill_output(map, nt) {
        return o;
    }
    *map = nt_win32_drives_map();
    fill_output(map, nt).unwrap_or_else(|| nt.to_vec())
}

/// `SysInfoProcess`
struct Process {
    pid: u32,
    h: HANDLE,
    creation: u64,
    kernel: u64,
    user: u64,
    page_file_usage: u32,
    virtual_size: u32,
}

impl Process {
    fn new(pid: u32, h: HANDLE) -> Process {
        let mut p = Process { pid, h, creation: 0, kernel: 0, user: 0, page_file_usage: 0, virtual_size: 0 };
        let ft = |f: &FILETIME| ((f.dwHighDateTime as u64) << 32) | f.dwLowDateTime as u64;
        // SAFETY: valid handle and out structs.
        unsafe {
            let z = FILETIME { dwLowDateTime: 0, dwHighDateTime: 0 };
            let (mut c, mut e, mut k, mut us) = (z, z, z, z);
            if GetProcessTimes(h, &mut c, &mut e, &mut k, &mut us) != 0 {
                p.kernel = ft(&k) / 10_000_000;
                p.user = ft(&us) / 10_000_000;
                p.creation = ft(&c) / 10_000_000;
            }
            let mut mc: PROCESS_MEMORY_COUNTERS = std::mem::zeroed();
            if GetProcessMemoryInfo(h, &mut mc, std::mem::size_of::<PROCESS_MEMORY_COUNTERS>() as u32) != 0 {
                // DWORD members (SIZE_T is 32 bits in the 32-bit agent)
                p.page_file_usage = mc.PagefileUsage as u32;
                p.virtual_size = (mc.WorkingSetSize as u32).wrapping_add(mc.PagefileUsage as u32);
            }
        }
        p
    }

    /// `cmd()`: the image path as a Win32 path (ANSI bytes).
    fn cmd(&self) -> Vec<u8> {
        let mut buf = vec![0u8; OS_MAXSTR];
        // SAFETY: the buffer holds OS_MAXSTR bytes.
        let n = unsafe { GetProcessImageFileNameA(self.h, buf.as_mut_ptr(), OS_MAXSTR as u32) };
        if n == 0 {
            return Vec::new();
        }
        nt_path_to_win32(&cbuf(&buf))
    }

    /// `cmdLineW()`
    fn cmd_line_w(&self) -> Vec<u16> {
        let mut size: u32 = 0;
        // SAFETY: size query, then a buffer of that size.
        unsafe {
            let st = NtQueryInformationProcess(self.h, PROCESS_COMMAND_LINE_INFORMATION, std::ptr::null_mut(), 0, &mut size);
            if st != STATUS_INFO_LENGTH_MISMATCH && st != STATUS_BUFFER_OVERFLOW && st != STATUS_BUFFER_TOO_SMALL {
                return Vec::new();
            }
            // UNICODE_STRING alignment
            let mut buf = vec![0u64; (size as usize).div_ceil(8).max(1)];
            let st = NtQueryInformationProcess(self.h, PROCESS_COMMAND_LINE_INFORMATION, buf.as_mut_ptr().cast(), size, &mut size);
            if st >= 0 {
                #[repr(C)]
                struct UnicodeString {
                    length: u16,
                    maximum_length: u16,
                    buffer: *const u16,
                }
                let us = &*(buf.as_ptr() as *const UnicodeString);
                if !us.buffer.is_null() && us.length > 0 {
                    return std::slice::from_raw_parts(us.buffer, (us.length / 2) as usize).to_vec();
                }
            }
        }
        Vec::new()
    }

    /// `creationTime()`: seconds since 1601 minus the epoch difference (ULONGLONG).
    fn creation_time(&self) -> u64 {
        self.creation.wrapping_sub(helpers::WINDOWS_UNIX_EPOCH_DIFF_SECONDS)
    }

    fn session_id(&self) -> u32 {
        let mut ret = 0u32;
        // SAFETY: out pointer.
        unsafe { ProcessIdToSessionId(self.pid, &mut ret) };
        ret
    }
}

/// `parseProcessCommandLine`: (cmd, argvs) in UTF-8.
pub fn parse_process_command_line(w: &[u16]) -> (Vec<u8>, Vec<u8>) {
    if w.is_empty() {
        return (Vec::new(), Vec::new());
    }
    let cmd = enc::wstring_to_utf8(w);
    let mut argvs: Vec<u8> = Vec::new();
    let mut z = w.to_vec();
    z.push(0);
    let mut argc = 0i32;
    // SAFETY: NUL-terminated input; the array is freed with LocalFree.
    unsafe {
        let argv = CommandLineToArgvW(z.as_ptr(), &mut argc);
        if !argv.is_null() {
            if argc > 1 {
                for k in 1..argc as usize {
                    let p = *argv.add(k);
                    let mut len = 0;
                    while *p.add(len) != 0 {
                        len += 1;
                    }
                    let arg = enc::wstring_to_utf8(std::slice::from_raw_parts(p, len));
                    // an argument converting to nothing is skipped (argSize > 0 counts the NUL)
                    if !argvs.is_empty() {
                        argvs.push(b' ');
                    }
                    argvs.extend_from_slice(&arg);
                }
            }
            LocalFree(argv as _);
        }
    }
    (cmd, argvs)
}

fn is_system_process(pid: u32) -> bool {
    pid == 0 || pid == 4
}

/// `processName`
fn process_name(pe: &ProcessEntry) -> Vec<u8> {
    match pe.pid {
        0 => b"System Idle Process".to_vec(),
        4 => b"System".to_vec(),
        _ => pe.exe_file.clone(),
    }
}

/// `getProcessInfo`: None when the process cannot be opened.
fn get_process_info(pe: &ProcessEntry) -> Option<Value> {
    // SAFETY: closed below.
    let h = unsafe { OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, 0, pe.pid) };
    if h.is_null() {
        return None;
    }
    let p = Process::new(pe.pid, h);
    let mut o = Obj::new();
    o.set("name", s(enc::ansi_to_utf8(&process_name(pe))));
    o.set("stime", u(p.kernel));
    o.set("size", u(p.page_file_usage as u64));
    o.set("ppid", u(pe.ppid as u64));
    o.set("priority", i(pe.pri_class_base as i64));
    o.set("pid", s(pe.pid.to_string()));
    o.set("session", u(p.session_id() as u64));
    o.set("nlwp", u(pe.threads as u64));
    o.set("utime", u(p.user));
    o.set("vm_size", u(p.virtual_size as u64));
    o.set("start_time", u(p.creation_time()));
    if is_system_process(pe.pid) {
        o.set("cmd", s("none"));
        o.set("argvs", s(""));
    } else {
        let (cmd, argvs) = parse_process_command_line(&p.cmd_line_w());
        if !cmd.is_empty() {
            o.set("cmd", s(cmd));
            o.set("argvs", s(argvs));
        } else {
            o.set("cmd", s(enc::ansi_to_utf8(&p.cmd())));
            o.set("argvs", s(""));
        }
    }
    // SAFETY: the handle opened above.
    unsafe { CloseHandle(h) };
    Some(o.into_value())
}

/// `SysInfo::getProcessesInfo(callback)`
pub fn get_processes_info(mut cb: impl FnMut(Value)) -> Result<(), Error> {
    fill_processes_data(|pe| {
        if let Some(v) = get_process_info(pe) {
            cb(v);
        }
    })
}
