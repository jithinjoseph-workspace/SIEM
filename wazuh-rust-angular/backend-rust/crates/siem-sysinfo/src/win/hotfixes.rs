//! `SysInfo::getHotfixes()`: WMI (`QueryWMIHotFixes`), the Windows Update
//! Agent history (`QueryWUHotFixes`) and the registry readers of
//! `packagesWindowsParserHelper.h`.

use std::collections::BTreeSet;

use windows::core::{BSTR, GUID, PCWSTR};
use windows::Win32::System::Com::*;
use windows::Win32::System::UpdateAgent::IUpdateSearcher;
use windows::Win32::System::Variant::{VariantClear, VARIANT, VT_BSTR};
use windows::Win32::System::Wmi::*;

use super::enc;
use super::registry::*;
use crate::json::{s, Obj, Value};
use crate::strings;

const WIN_REG_HOTFIX: &str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\Packages";
const VISTA_REG_HOTFIX: &str = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\HotFix";
const WIN_REG_PRODUCT_HOTFIX: &str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products";
const WIN_REG_WOW_HOTFIX: &str = r"SOFTWARE\WOW6432Node\Microsoft\Updates";

/// `CLSID_UpdateSearcher`. utilsWrapperWin.hpp writes `DEFINE_GUID(CLSID_UpdateSearcher,
/// 0x5A2A5E6E, ...)`, but without `INITGUID` that only declares the symbol:
/// the agent links libuuid's definition, the real UpdateSearcher class.
const CLSID_UPDATE_SEARCHER: GUID = windows::Win32::System::UpdateAgent::UpdateSearcher;

/// `BstrToString`
fn bstr_to_string(b: &BSTR) -> String {
    String::from_utf8_lossy(&enc::codecvt_utf8(b)).into_owned()
}

/// `QueryWMIHotFixes`
unsafe fn query_wmi(set: &mut BTreeSet<String>) -> windows::core::Result<()> {
    unsafe {
        let loc: IWbemLocator = CoCreateInstance(&WbemLocator, None, CLSCTX_INPROC_SERVER)?;
        let svc = loc.ConnectServer(&BSTR::from("ROOT\\CIMV2"), &BSTR::new(), &BSTR::new(), &BSTR::new(), 0, &BSTR::new(), None)?;
        CoSetProxyBlanket(&svc, 10, 0, PCWSTR::null(), RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, None, EOAC_NONE)?;
        let en = svc.ExecQuery(
            &BSTR::from("WQL"),
            &BSTR::from("SELECT * FROM Win32_QuickFixEngineering"),
            WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
            None,
        )?;
        loop {
            let mut objs = [None];
            let mut ret = 0u32;
            let _ = en.Next(WBEM_INFINITE, &mut objs, &mut ret);
            if ret == 0 {
                break;
            }
            let Some(obj) = objs[0].take() else { break };
            let mut v = VARIANT::default();
            if obj.Get(windows::core::w!("HotFixID"), 0, &mut v, None, None).is_ok() && v.Anonymous.Anonymous.vt == VT_BSTR {
                let b: &BSTR = &v.Anonymous.Anonymous.Anonymous.bstrVal;
                set.insert(bstr_to_string(b));
            }
            let _ = VariantClear(&mut v);
        }
    }
    Ok(())
}

/// `QueryWUHotFixes`
unsafe fn query_wu(set: &mut BTreeSet<String>) -> windows::core::Result<()> {
    unsafe {
        let searcher: IUpdateSearcher = CoCreateInstance(&CLSID_UPDATE_SEARCHER, None, CLSCTX_INPROC_SERVER)?;
        let count = searcher.GetTotalHistoryCount()?;
        let history = searcher.QueryHistory(0, count)?;
        let n = history.Count().unwrap_or(0);
        let re = regex::Regex::new("KB[0-9]+").unwrap();
        for i in 0..n {
            let Ok(entry) = history.get_Item(i) else { continue };
            let title = entry.Title().map(|t| bstr_to_string(&t)).unwrap_or_default();
            if let Some(m) = re.find(&title) {
                set.insert(m.as_str().to_string());
            }
        }
    }
    Ok(())
}

/// `extractHFValue`: the first "KB+[0-9]{6,}" of the upper-cased text.
fn extract_hf_value(input: &str) -> String {
    static RE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    let re = RE.get_or_init(|| regex::Regex::new("(KB+[0-9]{6,})").unwrap());
    let up = strings::to_upper(input);
    re.find(&up).map(|m| m.as_str().to_string()).unwrap_or_default()
}

const ACCESS: u32 = KEY_WOW64_64KEY | KEY_ENUMERATE_SUB_KEYS | KEY_READ;

/// `getHotFixFromReg`
fn from_reg(sub: &str, set: &mut BTreeSet<String>) {
    let _ = (|| -> R<()> {
        let root = Registry::open(HKEY_LOCAL_MACHINE, sub, ACCESS)?;
        root.enumerate_cb(|package| {
            if strings::starts_with(package, "Package_") {
                let hf = extract_hf_value(package);
                if !hf.is_empty() {
                    set.insert(hf);
                } else if package.contains("RollupFix") {
                    let reg = Registry::open(HKEY_LOCAL_MACHINE, &format!("{sub}\\{package}"), KEY_WOW64_64KEY | KEY_READ)?;
                    if let Some(v) = reg.string_opt_s("InstallLocation") {
                        let r = extract_hf_value(&v);
                        if !r.is_empty() {
                            set.insert(r);
                        }
                    }
                }
            }
            Ok(())
        })
    })();
}

/// `getHotFixFromRegNT`
fn from_reg_nt(sub: &str, set: &mut BTreeSet<String>) {
    let _ = (|| -> R<()> {
        Registry::open(HKEY_LOCAL_MACHINE, sub, ACCESS)?.enumerate_cb(|package| {
            let hf = extract_hf_value(package);
            if !hf.is_empty() {
                set.insert(hf);
            }
            Ok(())
        })
    })();
}

/// `getHotFixFromRegWOW`
fn from_reg_wow(sub: &str, set: &mut BTreeSet<String>) {
    let _ = (|| -> R<()> {
        Registry::open(HKEY_LOCAL_MACHINE, sub, ACCESS)?.enumerate_cb(|package_key| {
            Registry::open(HKEY_LOCAL_MACHINE, &format!("{sub}\\{package_key}"), ACCESS)?.enumerate_cb(|package| {
                let hf = extract_hf_value(package);
                if !hf.is_empty() {
                    set.insert(hf);
                }
                Ok(())
            })
        })
    })();
}

/// `getHotFixFromRegProduct`
fn from_reg_product(sub: &str, set: &mut BTreeSet<String>) {
    let _ = (|| -> R<()> {
        Registry::open(HKEY_LOCAL_MACHINE, sub, ACCESS)?.enumerate_cb(|package_key| {
            let base = format!("{sub}\\{package_key}");
            Registry::open(HKEY_LOCAL_MACHINE, &base, ACCESS)?.enumerate_cb(|package| {
                if strings::starts_with(package, "InstallProperties") {
                    let reg = Registry::open(HKEY_LOCAL_MACHINE, &format!("{base}\\{package}"), ACCESS)?;
                    if let Some(v) = reg.string_opt_s("DisplayName") {
                        let hf = extract_hf_value(&v);
                        if !hf.is_empty() {
                            set.insert(hf);
                        }
                    }
                } else if strings::starts_with(package, "Patches") {
                    let pbase = format!("{base}\\{package}");
                    Registry::open(HKEY_LOCAL_MACHINE, &pbase, ACCESS)?.enumerate_cb(|patch| {
                        let reg = Registry::open(HKEY_LOCAL_MACHINE, &format!("{pbase}\\{patch}"), ACCESS)?;
                        if let Some(v) = reg.string_opt_s("DisplayName") {
                            let hf = extract_hf_value(&v);
                            if !hf.is_empty() {
                                set.insert(hf);
                            }
                        }
                        Ok(())
                    })?;
                }
                Ok(())
            })
        })
    })();
}

/// `SysInfo::getHotfixes()`
pub fn get_hotfixes() -> Value {
    let mut set: BTreeSet<String> = BTreeSet::new();
    // SAFETY: COM initialised and uninitialised on this thread.
    unsafe {
        if CoInitializeEx(None, COINIT_MULTITHREADED).is_ok() {
            let a = query_wmi(&mut set);
            let b = query_wu(&mut set);
            if std::env::var_os("SIEM_SYSINFO_DEBUG").is_some() {
                eprintln!("wmi: {a:?} wu: {b:?}");
            }
            CoUninitialize();
        }
    }
    from_reg(WIN_REG_HOTFIX, &mut set);
    from_reg_nt(VISTA_REG_HOTFIX, &mut set);
    from_reg_wow(WIN_REG_WOW_HOTFIX, &mut set);
    from_reg_product(WIN_REG_PRODUCT_HOTFIX, &mut set);
    let arr: Vec<Value> = set
        .into_iter()
        .filter(|h| !h.is_empty())
        .map(|h| {
            let mut o = Obj::new();
            o.set("hotfix", s(h));
            o.into_value()
        })
        .collect();
    if arr.is_empty() {
        Value::Null
    } else {
        Value::Array(arr)
    }
}
