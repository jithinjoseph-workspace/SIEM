//! `SysInfo::getBrowserExtensions()`: `chrome::ChromeExtensionsProvider`
//! (chrome.cpp), `FirefoxAddonsProvider` (firefox.cpp) and
//! `IEExtensionsProvider` (ie_explorer.cpp), with the Windows
//! `BrowserExtensionsWrapper` and the `filesystemHelper.h` functions.
//!
//! nlohmann exceptions a provider lets out end the collection, as the C++'s
//! single `try` around the three providers does.

use sha2::{Digest, Sha256};
use siem_njson::Value as J;
use windows_sys::Win32::Foundation::{LocalFree, ERROR_NO_MORE_ITEMS, ERROR_SUCCESS};
use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidA;
use windows_sys::Win32::Security::LookupAccountNameA;
use windows_sys::Win32::Storage::FileSystem::{GetFileVersionInfoSizeW, GetFileVersionInfoW, VerQueryValueW, VS_FIXEDFILEINFO};
use windows_sys::Win32::System::Registry::*;

use super::{enc, fsx};
use crate::json::{i, s, Obj, Value};
use crate::{strings, UNKNOWN_VALUE};

const MAX_PATH_LENGTH: usize = 4096;
/// An exception (`what()`).
type E = String;

// ---------------------------------------------------------------- helpers

/// `Utils::existsDir` (`stat` + S_IFDIR)
fn exists_dir(p: &str) -> bool {
    std::fs::metadata(p).map(|m| m.is_dir()).unwrap_or(false)
}

/// `Utils::existsRegular`
fn exists_regular(p: &str) -> bool {
    std::fs::metadata(p).map(|m| m.is_file()).unwrap_or(false)
}

/// `Utils::enumerateDir` (opendir/readdir: "." and ".." included)
fn enumerate_dir(p: &str) -> Vec<String> {
    match std::fs::read_dir(p) {
        Ok(rd) => {
            let mut v = vec![".".to_string(), "..".to_string()];
            v.extend(rd.flatten().map(|e| e.file_name().to_string_lossy().into_owned()));
            v
        }
        Err(_) => Vec::new(),
    }
}

/// `Utils::joinPaths` (Windows)
fn join_paths(base: &str, relative: &str) -> String {
    if base.is_empty() {
        return relative.to_string();
    }
    if relative.is_empty() {
        return base.to_string();
    }
    let rel = relative.replace('/', "\\");
    let start = rel.bytes().take_while(|&c| c == b'\\').count();
    let b = base.trim_end_matches('\\');
    if b.is_empty() {
        return if start < rel.len() { rel[start..].to_string() } else { rel };
    }
    format!("{b}\\{}", &rel[start..])
}

/// `Utils::isAbsolutePath` (Windows)
fn is_absolute_path(p: &str) -> bool {
    let b = p.as_bytes();
    b.len() >= 2 && ((b[0].is_ascii_alphabetic() && b[1] == b':') || (b[0] == b'\\' && b[1] == b'\\'))
}

/// `Utils::getFilename`
fn get_filename(p: &str) -> &str {
    match p.rfind(['/', '\\']) {
        Some(i) => &p[i + 1..],
        None => p,
    }
}

/// `nlohmann::json::parse(std::ifstream)` (text mode, strict)
fn parse_file(p: &str) -> Result<J, E> {
    let text = fsx::read_text(p).unwrap_or_default();
    siem_njson::parse(&text).map_err(|e| String::from_utf8_lossy(&e).into_owned())
}

fn ty(v: &J) -> &'static str {
    v.type_name()
}

fn err_type(v: &J, want: &str) -> E {
    format!("[json.exception.type_error.302] type must be {want}, but is {}", ty(v))
}

/// `j.get<std::string>()`
fn get_string(v: &J) -> Result<String, E> {
    match v {
        J::Str(b) => Ok(String::from_utf8_lossy(b).into_owned()),
        other => Err(err_type(other, "string")),
    }
}

/// `j.get<bool>()`
fn get_bool(v: &J) -> Result<bool, E> {
    match v {
        J::Bool(b) => Ok(*b),
        other => Err(err_type(other, "boolean")),
    }
}

/// `j.get<int>()` (numbers and booleans convert)
fn get_int(v: &J) -> Result<i64, E> {
    match v {
        J::Bool(b) => Ok(*b as i64),
        J::Int(n) => Ok(*n),
        J::UInt(n) => Ok(*n as i64),
        J::Float(f) => Ok(siem_njson::f64_to_i64(*f)),
        other => Err(err_type(other, "number")),
    }
}

/// `j.contains(key)` (objects only)
fn contains(v: &J, k: &str) -> bool {
    v.find(k.as_bytes()).is_some()
}

/// `j[key]` on a value already checked with `contains`.
fn at<'a>(v: &'a J, k: &str) -> &'a J {
    v.find(k.as_bytes()).unwrap_or(&J::Null)
}

// ---------------------------------------------------------------- chrome

const CHROME_PATHS: [(&str, &str); 13] = [
    ("chrome", r"AppData\Local\Google\Chrome\User Data"),
    ("chrome_beta", r"AppData\Local\Google\Chrome Beta\User Data"),
    ("chrome_dev", r"AppData\Local\Google\Chrome Dev\User Data"),
    ("chrome_canary", r"AppData\Local\Google\Chrome SxS\User Data"),
    ("brave", r"AppData\Roaming\brave"),
    ("brave", r"AppData\Local\BraveSoftware\Brave-Browser\User Data"),
    ("chromium", r"AppData\Local\Chromium"),
    ("yandex", r"AppData\Local\Yandex\YandexBrowser\User Data"),
    ("edge", r"AppData\Local\Microsoft\Edge\User Data"),
    ("edge_beta", r"AppData\Local\Microsoft\Edge Beta\User Data"),
    ("opera", r"AppData\Roaming\Opera Software\Opera Stable"),
    ("vivaldi", r"AppData\Local\Vivaldi\User Data"),
    ("comet", r"AppData\Local\Perplexity\Comet\User Data"),
];

#[derive(Default, Clone)]
struct ChromeExt {
    browser_type: String,
    uid: String,
    name: String,
    profile: String,
    profile_path: String,
    referenced_identifier: String,
    identifier: String,
    version: String,
    description: String,
    default_locale: String,
    current_locale: String,
    update_url: String,
    author: String,
    persistent: String,
    path: String,
    permissions: String,
    optional_permissions: String,
    manifest_hash: String,
    referenced: String,
    from_webstore: String,
    state: String,
    install_time: String,
    install_timestamp: String,
    key: String,
}

/// `BrowserExtensionsWrapper::getUserId` (the RID of the account's SID)
fn get_user_id(user: &str) -> String {
    let name = enc::az(user.as_bytes());
    let mut sid = [0u8; 68];
    let mut sid_size = sid.len() as u32;
    let mut dom = [0u8; 256];
    let mut dom_size = dom.len() as u32;
    let mut use_ = 0;
    // SAFETY: sized buffers; the string SID is LocalFree'd.
    unsafe {
        if LookupAccountNameA(std::ptr::null(), name.as_ptr(), sid.as_mut_ptr().cast(), &mut sid_size, dom.as_mut_ptr(), &mut dom_size, &mut use_) != 0 {
            let mut out: *mut u8 = std::ptr::null_mut();
            if ConvertSidToStringSidA(sid.as_mut_ptr().cast(), &mut out) != 0 {
                let mut n = 0;
                while *out.add(n) != 0 {
                    n += 1;
                }
                let str_sid = String::from_utf8_lossy(std::slice::from_raw_parts(out, n)).into_owned();
                LocalFree(out.cast());
                return strings::split(&str_sid, '-').last().cloned().unwrap_or_default();
            }
        }
    }
    String::new()
}

fn is_valid_chrome_profile(p: &str) -> bool {
    if p.is_empty() || p.contains("..") || p.len() > MAX_PATH_LENGTH {
        return false;
    }
    exists_regular(&join_paths(p, "Preferences")) || exists_regular(&join_paths(p, "Secure Preferences"))
}

/// `jsonArrayToString` (range-for over the value)
fn json_array_to_string(v: &J) -> String {
    let mut r = String::new();
    for item in v.iter() {
        if let J::Str(b) = item {
            r.push_str(&String::from_utf8_lossy(b));
            r.push_str(", ");
        }
    }
    if r.ends_with(' ') {
        r.pop();
        if r.ends_with(',') {
            r.pop();
        }
    }
    r
}

fn is_snake_case(s: &str) -> bool {
    if s.is_empty() || s.starts_with('_') || s.ends_with('_') {
        return false;
    }
    let (mut has, mut last) = (false, false);
    for c in s.bytes() {
        if c == b'_' {
            if last {
                return false;
            }
            has = true;
            last = true;
        } else {
            if !c.is_ascii_alphanumeric() {
                return false;
            }
            last = false;
        }
    }
    has
}

/// `localizeParameters`
fn localize_parameters(ext: &mut ChromeExt) -> Result<(), E> {
    let messages = join_paths(&join_paths(&join_paths(&ext.path, "_locales"), &ext.default_locale), "messages.json");
    if exists_regular(&messages) {
        let mut name_key = strings::right_trim(strings::left_trim(&ext.name, "__MSG_"), "__").to_string();
        let mut desc_key = strings::right_trim(strings::left_trim(&ext.description, "__MSG_"), "__").to_string();
        if is_snake_case(&name_key) {
            name_key = name_key.to_ascii_lowercase();
        }
        if is_snake_case(&desc_key) {
            desc_key = desc_key.to_ascii_lowercase();
        }
        let mj = parse_file(&messages)?;
        if contains(&mj, &name_key) {
            ext.name = get_string(at(at(&mj, &name_key), "message"))?;
        }
        if contains(&mj, &desc_key) {
            ext.description = get_string(at(at(&mj, &desc_key), "message"))?;
        }
    }
    Ok(())
}

fn base64_decode(input: &str) -> Vec<u8> {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut t = [-1i32; 256];
    for (i, &c) in CHARS.iter().enumerate() {
        t[c as usize] = i as i32;
    }
    let mut out = Vec::new();
    let (mut val, mut valb) = (0i32, -8i32);
    for &c in input.as_bytes() {
        if t[c as usize] == -1 {
            break;
        }
        val = (val << 6).wrapping_add(t[c as usize]);
        valb += 6;
        if valb >= 0 {
            out.push(((val >> valb) & 0xFF) as u8);
            valb -= 8;
        }
    }
    out
}

/// `generateIdentifier`
fn generate_identifier(key: &str) -> String {
    let d = base64_decode(key);
    if d.is_empty() {
        return String::new();
    }
    let h = Sha256::digest(&d);
    let mut r = String::with_capacity(64);
    for b in h.iter() {
        r.push((b'a' + (b >> 4)) as char);
        r.push((b'a' + (b & 0x0F)) as char);
    }
    r[..32].to_string()
}

fn sha256_file(p: &str) -> String {
    match std::fs::read(p) {
        Ok(b) => Sha256::digest(&b).iter().map(|x| format!("{x:02x}")).collect(),
        Err(_) => String::new(),
    }
}

fn webkit_to_unix_time(t: &str) -> String {
    if t.is_empty() || !t.bytes().all(|c| c.is_ascii_digit()) {
        return String::new();
    }
    let Ok(ts) = t.parse::<i64>() else { return String::new() };
    if !(11644473600000000..=253402300799000000).contains(&ts) {
        return String::new();
    }
    ((ts - 11644473600000000) / 1000000).to_string()
}

/// `parseManifest`
fn parse_manifest(m: &J, ext: &mut ChromeExt) -> Result<(), E> {
    let opt = |k: &str| -> Result<String, E> { if contains(m, k) { get_string(at(m, k)) } else { Ok(String::new()) } };
    ext.name = opt("name")?;
    ext.update_url = opt("update_url")?;
    ext.version = opt("version")?;
    ext.author = if contains(m, "author") && matches!(at(m, "author"), J::Str(_)) { get_string(at(m, "author"))? } else { String::new() };
    ext.default_locale = opt("default_locale")?;
    ext.current_locale = opt("current_locale")?;
    ext.persistent = if contains(m, "background") && contains(at(m, "background"), "persistent") {
        if get_bool(at(at(m, "background"), "persistent"))? { "1" } else { "0" }.into()
    } else {
        "0".into()
    };
    ext.description = opt("description")?;
    ext.permissions = if contains(m, "permissions") { json_array_to_string(at(m, "permissions")) } else { String::new() };
    ext.optional_permissions = if contains(m, "optional_permissions") { json_array_to_string(at(m, "optional_permissions")) } else { String::new() };
    ext.key = opt("key")?;
    localize_parameters(ext)
}

/// `parsePreferenceSettings`
fn parse_preference_settings(ext: &mut ChromeExt, key: &str, v: &J) -> Result<(), E> {
    ext.state = if contains(v, "state") { (get_int(at(v, "state"))? as i32).to_string() } else { "1".into() };
    ext.from_webstore = if contains(v, "from_webstore") { if get_bool(at(v, "from_webstore"))? { "1" } else { "0" }.into() } else { "0".into() };
    ext.install_time = if contains(v, "first_install_time") { get_string(at(v, "first_install_time"))? } else { String::new() };
    ext.install_timestamp = webkit_to_unix_time(&ext.install_time);
    ext.referenced_identifier = key.to_string();
    Ok(())
}

struct Chrome {
    browser_type: String,
    uid: String,
}

impl Chrome {
    fn common(&self, ext: &mut ChromeExt, manifest: &str) {
        ext.browser_type = self.browser_type.clone();
        ext.uid = self.uid.clone();
        ext.manifest_hash = sha256_file(manifest);
    }

    /// `getExtensionsFromPreferences`
    fn from_preferences(&self, profile_path: &str, prefs: &str, profile_name: &str) -> Result<Vec<ChromeExt>, E> {
        if !exists_regular(prefs) {
            return Ok(Vec::new());
        }
        let Ok(mut pj) = parse_file(prefs) else { return Ok(Vec::new()) };
        // preferencesJson["extensions"]["settings"] (non-const: inserts nulls)
        let settings = {
            let ext = pj.index_mut(b"extensions").map_err(|e| String::from_utf8_lossy(&e).into_owned())?;
            ext.index_mut(b"settings").map_err(|e| String::from_utf8_lossy(&e).into_owned())?.clone()
        };
        let mut out = Vec::new();
        for (key, value) in settings.items() {
            if !contains(value, "path") {
                continue;
            }
            let mut ext_path = get_string(at(value, "path"))?;
            if !is_absolute_path(&ext_path) {
                if ext_path.contains("..") || ext_path.contains("//") || ext_path.is_empty() || ext_path.len() > MAX_PATH_LENGTH {
                    return Ok(Vec::new());
                }
                ext_path = join_paths(&join_paths(profile_path, "Extensions"), &ext_path);
            }
            let manifest = join_paths(&ext_path, "manifest.json");
            if exists_dir(&ext_path) && exists_regular(&manifest) {
                let mut e = ChromeExt { profile: profile_name.into(), profile_path: profile_path.into(), path: ext_path, referenced: "1".into(), ..Default::default() };
                self.common(&mut e, &manifest);
                parse_preference_settings(&mut e, &String::from_utf8_lossy(&key), value)?;
                let Ok(m) = parse_file(&manifest) else { continue };
                parse_manifest(&m, &mut e)?;
                e.identifier = generate_identifier(&e.key);
                out.push(e);
            }
        }
        Ok(out)
    }

    /// `getProfileFromPreferences`
    fn profile_name(&self, prefs: &str, secure: &str) -> Result<String, E> {
        if !exists_regular(prefs) || !exists_regular(secure) {
            return Ok(String::new());
        }
        let Ok(pj) = parse_file(prefs) else { return Ok(String::new()) };
        let Ok(sj) = parse_file(secure) else { return Ok(String::new()) };
        if contains(&pj, "profile") && contains(at(&pj, "profile"), "name") {
            get_string(at(at(&pj, "profile"), "name"))
        } else if contains(&sj, "profile") && contains(at(&sj, "profile"), "name") {
            get_string(at(at(&sj, "profile"), "name"))
        } else {
            Ok(String::new())
        }
    }

    fn referenced(&self, profile_path: &str) -> Result<Vec<ChromeExt>, E> {
        let prefs = join_paths(profile_path, "Preferences");
        let secure = join_paths(profile_path, "Secure Preferences");
        let name = self.profile_name(&prefs, &secure)?;
        let mut a = self.from_preferences(profile_path, &prefs, &name)?;
        let b = self.from_preferences(profile_path, &secure, &name)?;
        for e in b {
            if !a.iter().any(|x| x.path == e.path) {
                a.push(e);
            }
        }
        Ok(a)
    }

    fn unreferenced(&self, profile_path: &str) -> Result<Vec<ChromeExt>, E> {
        let ext_dir = join_paths(profile_path, "Extensions");
        if !exists_dir(&ext_dir) {
            return Ok(Vec::new());
        }
        let prefs = join_paths(profile_path, "Preferences");
        let secure = join_paths(profile_path, "Secure Preferences");
        if !exists_regular(&prefs) || !exists_regular(&secure) {
            return Ok(Vec::new());
        }
        let name = self.profile_name(&prefs, &secure)?;
        let mut out = Vec::new();
        for sub in enumerate_dir(&ext_dir) {
            let sub = join_paths(&ext_dir, &sub);
            if !exists_dir(&sub) {
                continue;
            }
            for subsub in enumerate_dir(&sub) {
                let subsub = join_paths(&sub, &subsub);
                if !exists_dir(&subsub) {
                    continue;
                }
                let manifest = join_paths(&subsub, "manifest.json");
                if exists_regular(&manifest) {
                    let mut e = ChromeExt { profile: name.clone(), profile_path: profile_path.into(), path: subsub, referenced: "0".into(), ..Default::default() };
                    self.common(&mut e, &manifest);
                    let Ok(m) = parse_file(&manifest) else { return Ok(Vec::new()) };
                    parse_manifest(&m, &mut e)?;
                    e.identifier = generate_identifier(&e.key);
                    out.push(e);
                }
            }
        }
        Ok(out)
    }

    fn from_path(&self, out: &mut Vec<ChromeExt>, path: &str) -> Result<(), E> {
        let referenced = self.referenced(path)?;
        out.extend(referenced.iter().cloned());
        for e in self.unreferenced(path)? {
            if !referenced.iter().any(|r| r.path == e.path) {
                out.push(e);
            }
        }
        Ok(())
    }
}

/// `ChromeExtensionsProvider::collect()`
fn chrome_collect() -> Result<Vec<ChromeExt>, E> {
    let home = r"C:\Users";
    let mut out = Vec::new();
    for user in enumerate_dir(home) {
        if user.starts_with('.') {
            continue;
        }
        let uid = get_user_id(&user);
        let user_home = join_paths(home, &user);
        for (bt, suffix) in CHROME_PATHS {
            let profile_path = join_paths(&user_home, suffix);
            if !exists_dir(&profile_path) {
                continue;
            }
            let c = Chrome { browser_type: bt.into(), uid: uid.clone() };
            if is_valid_chrome_profile(&profile_path) {
                c.from_path(&mut out, &profile_path)?;
            } else {
                for sub in enumerate_dir(&profile_path) {
                    let sub = join_paths(&profile_path, &sub);
                    if exists_dir(&sub) && is_valid_chrome_profile(&sub) {
                        c.from_path(&mut out, &sub)?;
                    }
                }
            }
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------- firefox

#[derive(Default)]
struct FirefoxAddon {
    active: bool,
    autoupdate: bool,
    creator: String,
    description: String,
    disabled: bool,
    identifier: String,
    location: String,
    name: String,
    path: String,
    source_url: String,
    r#type: String,
    uid: String,
    version: String,
    visible: bool,
}

fn ff_valid_path(p: &str) -> bool {
    !(p.is_empty() || p.contains("..") || p.contains("//") || p.len() > MAX_PATH_LENGTH)
}

/// `FirefoxAddonsProvider::getAddons()`
fn firefox_collect() -> Result<Vec<FirefoxAddon>, E> {
    let home = r"C:\Users";
    let mut out = Vec::new();
    if !ff_valid_path(home) {
        return Ok(out);
    }
    for user in enumerate_dir(home) {
        if user.starts_with('.') {
            continue;
        }
        let user_home = join_paths(home, &user);
        if !exists_dir(&user_home) || !ff_valid_path(&user_home) {
            continue;
        }
        let username = get_filename(&user_home).to_string();
        let inst = join_paths(&user_home, r"AppData\Roaming\Mozilla\Firefox\Profiles");
        if !exists_dir(&inst) || !ff_valid_path(&inst) {
            continue;
        }
        for entity in enumerate_dir(&inst) {
            let entity = join_paths(&inst, &entity);
            if !exists_dir(&entity) || !ff_valid_path(&entity) {
                continue;
            }
            let fname = get_filename(&entity);
            if fname == "Crash Reports" || fname == "Pending Pings" {
                continue;
            }
            if !exists_regular(&join_paths(&entity, "extensions.json")) {
                continue;
            }
            let ext_file = join_paths(&entity, "extensions.json");
            if !ff_valid_path(&ext_file) || std::fs::File::open(&ext_file).is_err() {
                continue;
            }
            let Ok(ej) = parse_file(&ext_file) else { continue };
            if !contains(&ej, "addons") || !matches!(at(&ej, "addons"), J::Array(_)) {
                continue;
            }
            for (_, a) in at(&ej, "addons").items() {
                let mut fa = FirefoxAddon { uid: get_user_id(&username), ..Default::default() };
                let flag = |k: &str| -> Result<bool, E> { Ok(contains(a, k) && !at(a, k).is_null() && get_bool(at(a, k))?) };
                fa.disabled = flag("softDisable")? || flag("appDisabled")? || flag("userDisabled")?;
                let sopt = |v: &J, k: &str| -> Result<String, E> { if !contains(v, k) || at(v, k).is_null() { Ok(String::new()) } else { get_string(at(v, k)) } };
                if !contains(a, "defaultLocale") || at(a, "defaultLocale").is_null() {
                    fa.name.clear();
                    fa.creator.clear();
                    fa.description.clear();
                } else {
                    let dl = at(a, "defaultLocale");
                    fa.name = sopt(dl, "name")?;
                    fa.creator = sopt(dl, "creator")?;
                    fa.description = sopt(dl, "description")?;
                }
                fa.identifier = sopt(a, "id")?;
                fa.r#type = sopt(a, "type")?;
                fa.version = sopt(a, "version")?;
                fa.source_url = sopt(a, "sourceURI")?;
                fa.visible = if !contains(a, "visible") || at(a, "visible").is_null() { false } else { get_bool(at(a, "visible"))? };
                fa.active = if !contains(a, "active") || at(a, "active").is_null() { false } else { get_bool(at(a, "active"))? };
                fa.autoupdate = if !contains(a, "applyBackgroundUpdates") || at(a, "applyBackgroundUpdates").is_null() {
                    false
                } else {
                    // get<int8_t>()
                    (get_int(at(a, "applyBackgroundUpdates"))? as i8) != 0
                };
                fa.location = sopt(a, "location")?;
                fa.path = sopt(a, "path")?;
                out.push(fa);
            }
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------- IE

const CLSIDS_KEYS: [&str; 3] = [
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects",
    r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects",
    r"SOFTWARE\Microsoft\Internet Explorer\URLSearchHooks",
];
const EXECUTABLES_BASE_KEY: &str = r"SOFTWARE\Classes\CLSID";
const CLASS_EXECUTABLES_SUBKEYS: [&str; 9] =
    ["InProcServer", "InProcServer32", "InProcServer64", "InProcHandler", "InProcHandler32", "InProcHandler64", "LocalServer", "LocalServer32", "LocalServer64"];

/// `RegOpenKeyExA(hive, key, 0, KEY_READ)` from the 32-bit agent.
fn open_a(hive: HKEY, key: &[u8]) -> Option<HKEY> {
    let z = enc::az(key);
    let mut h: HKEY = std::ptr::null_mut();
    // SAFETY: valid name and out pointer.
    (unsafe { RegOpenKeyExA(hive, z.as_ptr(), 0, KEY_READ | KEY_WOW64_32KEY, &mut h) } == ERROR_SUCCESS).then_some(h)
}

fn close(h: HKEY) {
    // SAFETY: a key opened by open_a.
    unsafe { RegCloseKey(h) };
}

fn cbytes(b: &[u8]) -> Vec<u8> {
    b[..b.iter().position(|&c| c == 0).unwrap_or(b.len())].to_vec()
}

/// `getValueFromHKey`: the name of the first value.
fn value_from_hkey(h: HKEY) -> Vec<u8> {
    let mut name = vec![0u8; 16384];
    let mut nsize = name.len() as u32;
    let mut ty = 0u32;
    let mut data = vec![0u8; 1048576];
    let mut dsize = data.len() as u32;
    // SAFETY: sized buffers.
    let r = unsafe { RegEnumValueA(h, 0, name.as_mut_ptr(), &mut nsize, std::ptr::null(), &mut ty, data.as_mut_ptr(), &mut dsize) };
    if r == ERROR_SUCCESS {
        if (nsize as usize) < name.len() {
            name[nsize as usize] = 0;
        }
        return cbytes(&name);
    }
    if r != ERROR_NO_MORE_ITEMS {
        eprintln!("Failed to enumerate values. Error: {r}");
    }
    Vec::new()
}

/// `getDefaultValueFromHKey` (REG_SZ only)
fn default_value_from_hkey(h: HKEY) -> Vec<u8> {
    let mut data = vec![0u8; 1048576];
    let mut dsize = data.len() as u32;
    let mut ty = 0u32;
    let empty = [0u8];
    // SAFETY: sized buffer.
    let r = unsafe { RegQueryValueExA(h, empty.as_ptr(), std::ptr::null(), &mut ty, data.as_mut_ptr(), &mut dsize) };
    if r == ERROR_SUCCESS && ty == REG_SZ && dsize > 0 && (dsize as usize) <= data.len() {
        if (dsize as usize) < data.len() {
            data[dsize as usize] = 0;
        }
        return cbytes(&data);
    }
    Vec::new()
}

/// `RegEnumKeyExA(h, index)`: the name, or the error code.
fn enum_key(h: HKEY, index: u32) -> Result<Vec<u8>, u32> {
    let mut name = vec![0u8; 256];
    let mut size = 256u32;
    let mut ft = windows_sys::Win32::Foundation::FILETIME { dwLowDateTime: 0, dwHighDateTime: 0 };
    // SAFETY: sized buffer.
    let r = unsafe { RegEnumKeyExA(h, index, name.as_mut_ptr(), &mut size, std::ptr::null(), std::ptr::null_mut(), std::ptr::null_mut(), &mut ft) };
    if r == ERROR_SUCCESS {
        if (size as usize) < name.len() {
            name[size as usize] = 0;
        }
        Ok(cbytes(&name))
    } else {
        Err(r)
    }
}

fn subkey_name_from_hkey(h: HKEY) -> Vec<u8> {
    match enum_key(h, 0) {
        Ok(n) => n,
        Err(r) => {
            if r != ERROR_NO_MORE_ITEMS {
                eprintln!("Failed to enumerate subkeys. Error: {r}");
            }
            Vec::new()
        }
    }
}

fn hkey_to_string(h: HKEY) -> &'static str {
    if h == HKEY_CLASSES_ROOT {
        "HKEY_CLASSES_ROOT"
    } else if h == HKEY_LOCAL_MACHINE {
        "HKEY_LOCAL_MACHINE"
    } else if h == HKEY_USERS {
        "HKEY_USERS"
    } else {
        "UNKNOWN_HKEY"
    }
}

/// `listSubKeys(HKEY_USERS)`
fn list_user_subkeys() -> Vec<Vec<u8>> {
    let mut v = Vec::new();
    let mut i = 0;
    while let Ok(n) = enum_key(HKEY_USERS, i) {
        v.push(n);
        i += 1;
    }
    v
}

fn cat(parts: &[&[u8]]) -> Vec<u8> {
    let mut v = Vec::new();
    for (k, p) in parts.iter().enumerate() {
        if k > 0 {
            v.push(b'\\');
        }
        v.extend_from_slice(p);
    }
    v
}

fn registry_paths_from_keys(hive: HKEY, keys: &[Vec<u8>], out: &mut Vec<Vec<u8>>) {
    for k in keys {
        if let Some(h) = open_a(hive, k) {
            let sub = subkey_name_from_hkey(h);
            let clsid = if sub.is_empty() { value_from_hkey(h) } else { sub };
            let p = cat(&[hkey_to_string(hive).as_bytes(), k, &clsid]);
            if !out.contains(&p) {
                out.push(p);
            }
            close(h);
        }
    }
}

fn extract_clsid(p: &[u8]) -> Vec<u8> {
    match p.iter().rposition(|&c| c == b'\\') {
        Some(i) => p[i + 1..].to_vec(),
        None => p.to_vec(),
    }
}

/// `GetFileVersion` (the path widened byte by byte, as `char` is signed)
fn file_version(path: &[u8]) -> String {
    let mut w: Vec<u16> = path.iter().map(|&b| b as i8 as i16 as u16).collect();
    w.push(0);
    let mut handle = 0u32;
    // SAFETY: sized buffer; the fixed info points into it.
    unsafe {
        let size = GetFileVersionInfoSizeW(w.as_ptr(), &mut handle);
        if size == 0 {
            return "No version info".into();
        }
        let mut buf = vec![0u8; size as usize];
        if GetFileVersionInfoW(w.as_ptr(), handle, size, buf.as_mut_ptr().cast()) == 0 {
            return "Failed to get version info".into();
        }
        let mut fi: *mut core::ffi::c_void = std::ptr::null_mut();
        let mut len = 0u32;
        let root = enc::wz("\\");
        if VerQueryValueW(buf.as_ptr().cast(), root.as_ptr(), &mut fi, &mut len) == 0 {
            return "Failed to query version value".into();
        }
        if fi.is_null() {
            return "Unknown version".into();
        }
        let f = &*(fi as *const VS_FIXEDFILEINFO);
        format!("{}.{}.{}.{}", f.dwFileVersionMS >> 16, f.dwFileVersionMS & 0xFFFF, f.dwFileVersionLS >> 16, f.dwFileVersionLS & 0xFFFF)
    }
}

struct IeExt {
    name: Vec<u8>,
    path: Vec<u8>,
    registry_path: Vec<u8>,
    version: String,
}

/// `IEExtensionsProvider::collect()`
fn ie_collect() -> Vec<IeExt> {
    let users = list_user_subkeys();
    let clsid_keys: Vec<Vec<u8>> = CLSIDS_KEYS.iter().map(|k| k.as_bytes().to_vec()).collect();
    let expanded: Vec<Vec<u8>> = clsid_keys.iter().flat_map(|k| users.iter().map(move |u| cat(&[u, k]))).collect();
    let mut reg_paths = Vec::new();
    registry_paths_from_keys(HKEY_LOCAL_MACHINE, &clsid_keys, &mut reg_paths);
    registry_paths_from_keys(HKEY_USERS, &expanded, &mut reg_paths);
    let user_exec_keys: Vec<Vec<u8>> = users.iter().map(|u| cat(&[u, EXECUTABLES_BASE_KEY.as_bytes()])).collect();
    let mut out = Vec::new();
    for rp in reg_paths {
        let clsid = extract_clsid(&rp);
        let mut execs: Vec<Vec<u8>> = Vec::new();
        let mut get = |hive: HKEY, key: Vec<u8>| {
            if let Some(h) = open_a(hive, &key) {
                let e = default_value_from_hkey(h);
                close(h);
                if !e.is_empty() {
                    execs.push(e);
                }
            }
        };
        for sub in CLASS_EXECUTABLES_SUBKEYS {
            get(HKEY_LOCAL_MACHINE, cat(&[EXECUTABLES_BASE_KEY.as_bytes(), &clsid, sub.as_bytes()]));
            for uk in &user_exec_keys {
                get(HKEY_USERS, cat(&[uk, &clsid, sub.as_bytes()]));
            }
        }
        for exec in execs {
            let es = String::from_utf8_lossy(&exec);
            if es.is_empty() || es.contains("..") || es.contains("//") || exec.len() > MAX_PATH_LENGTH {
                continue;
            }
            let name = match open_a(HKEY_CLASSES_ROOT, &cat(&[b"CLSID", &clsid])) {
                Some(h) => {
                    let n = default_value_from_hkey(h);
                    close(h);
                    n
                }
                None => Vec::new(),
            };
            out.push(IeExt { name, version: file_version(&exec), path: exec, registry_path: rp.clone() });
        }
    }
    out
}

// ---------------------------------------------------------------- mapping

/// `SysInfo::getBrowserExtensions()`
pub fn get_browser_extensions() -> Value {
    let mut result: Vec<Value> = Vec::new();
    let unk = || s(UNKNOWN_VALUE);
    let ne = |v: &str| if v.is_empty() { unk() } else { s(v) };
    let r = (|| -> Result<(), E> {
        for e in chrome_collect()? {
            // stringToInt: stoi of the string, 0 when empty or invalid
            let to_int = |v: &str| if v.is_empty() { 0 } else { strings::stoi(v).map(|x| x.0).unwrap_or(0) };
            let mut o = Obj::new();
            o.set("browser_name", ne(&e.browser_type));
            o.set("user_id", ne(&e.uid));
            o.set("package_name", ne(&e.name));
            o.set("package_id", s(&e.identifier));
            o.set("package_version", ne(&e.version));
            o.set("package_description", s(&e.description));
            o.set("package_vendor", s(&e.author));
            o.set("package_build_version", unk());
            o.set("package_path", s(&e.path));
            o.set("browser_profile_name", ne(&e.profile));
            o.set("browser_profile_path", ne(&e.profile_path));
            o.set("package_reference", s(&e.update_url));
            o.set("package_permissions", s(&e.permissions));
            o.set("package_type", unk());
            o.set("package_enabled", i(if e.state == "1" { 1 } else { 0 }));
            o.set("package_visible", i(0));
            o.set("package_autoupdate", i(0));
            o.set("package_persistent", i(to_int(&e.persistent) as i64));
            o.set("package_from_webstore", i(to_int(&e.from_webstore) as i64));
            o.set("browser_profile_referenced", i(to_int(&e.referenced) as i64));
            o.set("package_installed", s(&e.install_timestamp));
            o.set("file_hash_sha256", s(&e.manifest_hash));
            result.push(o.into_value());
        }
        for e in firefox_collect()? {
            let mut o = Obj::new();
            o.set("browser_name", s("firefox"));
            o.set("user_id", ne(&e.uid));
            o.set("package_name", ne(&e.name));
            o.set("package_id", s(&e.identifier));
            o.set("package_version", ne(&e.version));
            o.set("package_description", s(&e.description));
            o.set("package_vendor", s(&e.creator));
            o.set("package_build_version", unk());
            o.set("package_path", s(&e.path));
            o.set("browser_profile_name", unk());
            o.set("browser_profile_path", unk());
            o.set("package_reference", s(&e.source_url));
            o.set("package_permissions", unk());
            o.set("package_type", s(&e.r#type));
            o.set("package_enabled", i(if e.disabled { 0 } else { 1 }));
            o.set("package_visible", i(e.visible as i64));
            o.set("package_autoupdate", i(e.autoupdate as i64));
            o.set("package_persistent", i(0));
            o.set("package_from_webstore", i(0));
            o.set("browser_profile_referenced", i(0));
            o.set("package_installed", unk());
            o.set("file_hash_sha256", unk());
            let _ = (e.active, &e.location);
            result.push(o.into_value());
        }
        for e in ie_collect() {
            let mut o = Obj::new();
            o.set("browser_name", s("ie"));
            o.set("user_id", unk());
            o.set("package_name", if e.name.is_empty() { unk() } else { s(&e.name) });
            o.set("package_id", unk());
            o.set("package_version", ne(&e.version));
            o.set("package_description", unk());
            o.set("package_vendor", unk());
            o.set("package_build_version", unk());
            o.set("package_path", s(&e.path));
            o.set("browser_profile_name", unk());
            o.set("browser_profile_path", if e.registry_path.is_empty() { unk() } else { s(&e.registry_path) });
            o.set("package_reference", s(&e.registry_path));
            o.set("package_permissions", unk());
            o.set("package_type", unk());
            o.set("package_enabled", i(1));
            o.set("package_visible", i(0));
            o.set("package_autoupdate", i(0));
            o.set("package_persistent", i(0));
            o.set("package_from_webstore", i(0));
            o.set("browser_profile_referenced", i(0));
            o.set("package_installed", unk());
            o.set("file_hash_sha256", unk());
            result.push(o.into_value());
        }
        Ok(())
    })();
    let _ = r;
    Value::Array(result)
}
