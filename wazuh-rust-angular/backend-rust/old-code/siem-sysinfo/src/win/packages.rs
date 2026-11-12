//! `SysInfo::getPackages()`: the Uninstall registry keys
//! (`getPackagesFromReg`), the Store apps (`getStorePackages` with
//! `AppxWindowsWrapper`, appxWindowsWrapper.h) and the Python / Node.js
//! packages (packagesPYPI.hpp, packagesNPM.hpp).

use std::collections::{BTreeSet, VecDeque};

use super::registry::*;
use super::{fsx, helpers, Error};

/// The C++ `std::function<void(nlohmann::json&)>`: Err is an exception it throws.
pub type Cb<'a> = &'a mut dyn FnMut(Value) -> Result<(), String>;
use crate::json::{i, s, Obj, Value};
use crate::{strings, UNKNOWN_VALUE};

const UNINSTALL_REGISTRY: &str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";
const APPLICATION_STORE_REGISTRY: &str = r"SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\Repository\Packages";
const APPLICATION_INSTALL_TIME_REGISTRY: &str = r"SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\Repository\Families";
const APPLICATION_VENDOR_REGISTRY: &str = r"SOFTWARE\Classes";
const FILE_ASSOCIATIONS_REGISTRY: &str = r"\Capabilities\FileAssociations";
const URL_ASSOCIATIONS_REGISTRY: &str = r"\Capabilities\URLAssociations";
const CACHE_NAME_REGISTRY: &str = r"SOFTWARE\Classes\Local Settings\MrtCache";
const STORE_APPLICATION_DATABASE: &str = r"C:\Program Files\WindowsApps";
const PREFIX_LOCALIZATION: &str = "@{";
const KEY_QUERY_VALUE: u32 = 0x0001;

fn str_of(v: Option<Vec<u8>>) -> Option<String> {
    v.map(|b| String::from_utf8_lossy(&b).into_owned())
}

/// `getPackagesFromReg`
fn packages_from_reg(key: HKEY, sub_key: &str, access: u32, cb: Cb<'_>) {
    let _ = (|| -> R<()> {
        let root = Registry::open(key, sub_key, access | KEY_ENUMERATE_SUB_KEYS | KEY_READ)?;
        root.enumerate_cb(|package| {
            let reg = Registry::open(key, &format!("{sub_key}\\{package}"), access | KEY_READ)?;
            let name = str_of(reg.string_opt("DisplayName")).unwrap_or_default();
            let version = str_of(reg.string_opt("DisplayVersion")).unwrap_or_default();
            let vendor = str_of(reg.string_opt("Publisher")).unwrap_or_default();
            let install_time = match str_of(reg.string_opt("InstallDate")) {
                Some(v) => helpers::normalize_timestamp(&v, &reg.key_modification_date()).unwrap_or_else(|_| reg.key_modification_date()),
                None => reg.key_modification_date(),
            };
            let location = str_of(reg.string_opt("InstallLocation")).unwrap_or_else(|| UNKNOWN_VALUE.into());
            if !name.is_empty() {
                let architecture = if access & KEY_WOW64_32KEY != 0 {
                    "i686"
                } else if access & KEY_WOW64_64KEY != 0 {
                    "x86_64"
                } else {
                    UNKNOWN_VALUE
                };
                let unk = |v: &str| if v.is_empty() { UNKNOWN_VALUE.to_string() } else { v.to_string() };
                let mut o = Obj::new();
                o.set("name", s(&name));
                o.set("description", s(UNKNOWN_VALUE));
                o.set("version", s(unk(&version)));
                o.set("groups", s(UNKNOWN_VALUE));
                o.set("priority", s(UNKNOWN_VALUE));
                o.set("size", i(0));
                o.set("vendor", s(unk(&vendor)));
                o.set("source", s(UNKNOWN_VALUE));
                o.set("install_time", s(unk(&install_time)));
                o.set("location", s(unk(&location)));
                o.set("architecture", s(architecture));
                o.set("format", s("win"));
                // an exception ends the enumeration (caught by the catch(...))
                cb(o.into_value()).map_err(RegError)?;
            }
            Ok(())
        })
    })();
}

/// `AppxWindowsWrapper`
struct Appx<'a> {
    key: HKEY,
    user: &'a str,
    app: &'a str,
    cache: &'a BTreeSet<String>,
    name: String,
    version: String,
    vendor: String,
    architecture: String,
    location: String,
    install_time: String,
}

impl<'a> Appx<'a> {
    fn new(key: HKEY, user: &'a str, app: &'a str, cache: &'a BTreeSet<String>) -> R<Appx<'a>> {
        let mut a = Appx {
            key,
            user,
            app,
            cache,
            name: String::new(),
            version: String::new(),
            vendor: String::new(),
            architecture: String::new(),
            location: String::new(),
            install_time: String::new(),
        };
        a.get_information_packages()?;
        Ok(a)
    }

    fn store_path(&self) -> String {
        format!("{}\\{APPLICATION_STORE_REGISTRY}\\{}", self.user, self.app)
    }

    fn get_information_packages(&mut self) -> R<()> {
        // isRegistryValid
        let valid = !Registry::open(self.key, &self.store_path(), KEY_READ | KEY_ENUMERATE_SUB_KEYS)?.enumerate()?.is_empty();
        if valid {
            let fields = strings::split(self.app, '_');
            if fields.len() >= 5 {
                let package_reg = Registry::read(self.key, &self.store_path())?;
                self.version = fields[1].clone();
                self.architecture = match fields[2].as_str() {
                    "x64" => "x86_64",
                    "x86" => "i686",
                    _ => UNKNOWN_VALUE,
                }
                .into();
                self.location = str_of(package_reg.string_opt("PackageRootFolder")).unwrap_or_else(|| UNKNOWN_VALUE.into());
                self.install_time = self.get_install_time(&fields[0], &fields[4]);
                self.name = self.get_name(&fields[0], &package_reg);
                self.vendor = self.get_vendor(&package_reg);
            }
            if !self.location.contains(STORE_APPLICATION_DATABASE) {
                self.name.clear();
                self.vendor.clear();
                self.architecture.clear();
                self.version.clear();
                self.location.clear();
            }
        }
        Ok(())
    }

    fn get_install_time(&self, name: &str, uuid: &str) -> String {
        let path = format!("{}\\{APPLICATION_INSTALL_TIME_REGISTRY}\\{name}_{uuid}\\{}", self.user, self.app);
        match Registry::read(self.key, &path).and_then(|r| r.qword("InstallTime")) {
            Ok(Some(v)) => helpers::build_timestamp(v),
            _ => UNKNOWN_VALUE.into(),
        }
    }

    fn get_name(&self, full_name: &str, registry: &Registry) -> String {
        let parts = strings::split(full_name, '.');
        let key_name = parts.last().cloned().unwrap_or_default();
        let r = (|| -> R<String> {
            let mut name = String::new();
            for folder in registry.enumerate()? {
                let reg = Registry::read(self.key, &format!("{}\\{folder}\\Capabilities", self.store_path()))?;
                if let Some(v) = str_of(reg.string_opt("ApplicationName")) {
                    name = v;
                    break;
                }
            }
            if strings::starts_with(&name, PREFIX_LOCALIZATION) {
                name = self.search_name_from_cache(&key_name, &name)?;
            }
            Ok(name)
        })();
        r.unwrap_or_default()
    }

    fn get_vendor(&self, registry: &Registry) -> String {
        let r = (|| -> R<String> {
            let mut vendor = String::new();
            for folder in registry.enumerate()? {
                let file_reg = Registry::open(self.key, &format!("{}\\{folder}{FILE_ASSOCIATIONS_REGISTRY}", self.store_path()), KEY_READ | KEY_QUERY_VALUE)?;
                vendor = self.search_publisher(&file_reg)?;
                if vendor.is_empty() {
                    let url_reg = Registry::open(self.key, &format!("{}\\{folder}{URL_ASSOCIATIONS_REGISTRY}", self.store_path()), KEY_READ | KEY_QUERY_VALUE)?;
                    vendor = self.search_publisher(&url_reg)?;
                }
                if !vendor.is_empty() {
                    break;
                }
            }
            Ok(vendor)
        })();
        r.unwrap_or_default()
    }

    fn search_name_from_cache(&self, app_name: &str, name_key: &str) -> R<String> {
        let mut name = String::new();
        if let Some(folder) = self.cache.iter().find(|f| f.contains(app_name)) {
            if !folder.is_empty() {
                name = self.search_key_on_sub_registries(&format!("{}\\{CACHE_NAME_REGISTRY}\\{folder}", self.user), name_key)?;
            }
        }
        Ok(if strings::starts_with(&name, PREFIX_LOCALIZATION) { String::new() } else { name })
    }

    fn search_key_on_sub_registries(&self, path: &str, key: &str) -> R<String> {
        let reg = Registry::read(self.key, path)?;
        let mut value = String::new();
        match str_of(reg.string_opt(key)) {
            Some(v) => value = v,
            None => {
                for folder in Registry::read(self.key, path)?.enumerate()? {
                    value = self.search_key_on_sub_registries(&format!("{path}\\{folder}"), key)?;
                    if !value.is_empty() {
                        break;
                    }
                }
            }
        }
        Ok(value)
    }

    fn search_publisher(&self, registry: &Registry) -> R<String> {
        for value in registry.enumerate_value_key()? {
            let vendor_registry = str_of(registry.string_opt(&value)).unwrap_or_default();
            let pub_reg = Registry::read(self.key, &format!("{}\\{APPLICATION_VENDOR_REGISTRY}\\{vendor_registry}\\Application", self.user))?;
            if let Some(data) = str_of(pub_reg.string_opt("ApplicationCompany")) {
                if !strings::starts_with(&data, PREFIX_LOCALIZATION) {
                    return Ok(data);
                }
            }
        }
        Ok(String::new())
    }

    /// `WindowsPackageImpl::buildPackageData`
    fn build(&self) -> Obj {
        let mut o = Obj::new();
        o.set("name", s(&self.name));
        o.set("version", s(&self.version));
        o.set("vendor", s(&self.vendor));
        o.set("install_time", s(&self.install_time));
        o.set("location", s(&self.location));
        o.set("architecture", s(&self.architecture));
        o.set("groups", s(UNKNOWN_VALUE));
        o.set("description", s(UNKNOWN_VALUE));
        o.set("size", i(0));
        o.set("priority", s(UNKNOWN_VALUE));
        o.set("source", s(UNKNOWN_VALUE));
        o.set("format", s("win"));
        o
    }
}

/// `getStorePackages`
fn store_packages(key: HKEY, user: &str, cb: Cb<'_>) {
    let _ = (|| -> R<()> {
        let cache: BTreeSet<String> =
            Registry::open(key, &format!("{user}\\{CACHE_NAME_REGISTRY}"), KEY_READ | KEY_ENUMERATE_SUB_KEYS)?.enumerate()?.into_iter().collect();
        let root = Registry::open(key, &format!("{user}\\{APPLICATION_STORE_REGISTRY}"), KEY_READ | KEY_ENUMERATE_SUB_KEYS)?;
        root.enumerate_cb(|app| {
            let o = Appx::new(key, user, app, &cache)?.build();
            if !crate::json::as_str(o.get("name")).is_empty() {
                cb(o.into_value()).map_err(RegError)?;
            }
            Ok(())
        })
    })();
}

/// `expandFromRegistry`
fn expand_from_registry(key: HKEY, sub_key: &str, field: &str, mut post: impl FnMut(String)) {
    let mut paths = Vec::new();
    let _ = expand_registry_path(key, sub_key, &mut paths);
    for p in paths {
        if let Ok(reg) = Registry::open(key, &p, KEY_READ | KEY_WOW64_64KEY) {
            // string(field): the raw value (no code page conversion)
            if let Ok(dir) = reg.string_raw(field) {
                post(String::from_utf8_lossy(&dir).into_owned());
            }
        }
    }
}

fn python_directories() -> BTreeSet<String> {
    let mut set = BTreeSet::new();
    let mut post = |d: String| {
        set.insert(format!("{d}Lib\\site-packages"));
        set.insert(format!("{d}Lib\\dist-packages"));
    };
    expand_from_registry(HKEY_USERS, r"*\SOFTWARE\Python\PythonCore\*\InstallPath", "", &mut post);
    expand_from_registry(HKEY_LOCAL_MACHINE, r"SOFTWARE\Python\PythonCore\*\InstallPath", "", &mut post);
    set
}

fn node_directories() -> BTreeSet<String> {
    let mut set = BTreeSet::new();
    let mut post = |d: String| {
        set.insert(d);
    };
    expand_from_registry(HKEY_USERS, r"*\SOFTWARE\Node.js", "InstallPath", &mut post);
    expand_from_registry(HKEY_LOCAL_MACHINE, r"SOFTWARE\Node.js", "InstallPath", &mut post);
    set.insert(r"C:\Users\*\AppData\Roaming\npm".into());
    set.insert(r"C:\Users\*".into());
    set
}

/// `PYPI::parseMetadata`
fn pypi_parse_metadata(path: &str, cb: Cb<'_>) -> Result<(), String> {
    // "Author: ", "Home-page: ", "Name: ", "Summary: ", "Version: " (map order)
    const FIELDS: [(&str, &str); 5] = [("Author: ", "vendor"), ("Home-page: ", "source"), ("Name: ", "name"), ("Summary: ", "description"), ("Version: ", "version")];
    let mut o = Obj::new();
    o.set("groups", s(UNKNOWN_VALUE));
    o.set("description", s(UNKNOWN_VALUE));
    o.set("architecture", s(UNKNOWN_VALUE));
    o.set("format", s("pypi"));
    o.set("source", s(UNKNOWN_VALUE));
    o.set("location", s(path));
    o.set("priority", s(UNKNOWN_VALUE));
    o.set("size", i(0));
    o.set("vendor", s(UNKNOWN_VALUE));
    o.set("install_time", s(UNKNOWN_VALUE));
    let text = fsx::read_text(path).ok_or_else(|| "Could not open file".to_string())?;
    for line in fsx::lines(&text) {
        let line_s = String::from_utf8_lossy(line);
        if let Some((k, v)) = FIELDS.iter().find(|(k, _)| strings::starts_with(&line_s, k)) {
            if !o.contains(v) {
                let rest = &line[k.len()..];
                o.set(v, s(strings::trim_bytes(rest, b"\r")));
            }
        }
    }
    if o.contains("name") && o.contains("version") {
        cb(o.into_value())?;
    }
    Ok(())
}

/// `PYPI::getPackages`
fn pypi_packages(roots: &BTreeSet<String>, cb: Cb<'_>) {
    for root in roots {
        let mut expanded = VecDeque::new();
        if fsx::expand_absolute_path(root, &mut expanded).is_err() {
            continue;
        }
        for p in expanded {
            let _ = (|| -> Result<(), String> {
                if fsx::exists(&p)? && fsx::is_directory(&p) {
                    for (path, filename) in fsx::dir_entries(&p)? {
                        // findCorrectPath: "dist-info" -> METADATA, "egg-info" -> PKG-INFO
                        for (key, value) in [("dist-info", "METADATA"), ("egg-info", "PKG-INFO")] {
                            if filename.contains(key) {
                                let correct = if fsx::is_regular_file(&path) {
                                    path.clone()
                                } else if fsx::is_directory(&path) {
                                    fsx::join(&path, value)
                                } else {
                                    String::new()
                                };
                                if let Err(e) = pypi_parse_metadata(&correct, cb) {
                                    eprintln!("Error parsing PYPI package: {path}, {e}");
                                    break;
                                }
                            }
                        }
                    }
                }
                Ok(())
            })();
        }
    }
}

/// `NPM::parsePackage`
fn npm_parse_package(folder: &str, cb: Cb<'_>) {
    let path = fsx::join(folder, "package.json");
    let r = (|| -> Result<(), String> {
        if fsx::exists(&path)? {
            let raw = std::fs::read(&path).map_err(|_| "Could not open file".to_string())?;
            let pj = siem_njson::parse_stream(&raw).map_err(|e| String::from_utf8_lossy(&e).into_owned())?;
            let mut o = Obj::new();
            o.set("groups", s(UNKNOWN_VALUE));
            o.set("description", s(UNKNOWN_VALUE));
            o.set("architecture", s(UNKNOWN_VALUE));
            o.set("format", s("npm"));
            o.set("source", s(UNKNOWN_VALUE));
            o.set("location", s(&path));
            o.set("priority", s(UNKNOWN_VALUE));
            o.set("size", i(0));
            o.set("vendor", s(UNKNOWN_VALUE));
            o.set("install_time", s(UNKNOWN_VALUE));
            // NPM_FIELDS in map order: description, homepage, name, version
            for (key, value) in [("description", "description"), ("homepage", "source"), ("name", "name"), ("version", "version")] {
                if let Some(v @ Value::Str(_)) = pj.find(key.as_bytes()) {
                    o.set(value, v.clone());
                }
            }
            if o.contains("name") && o.contains("version") {
                cb(o.into_value())?;
            }
        }
        Ok(())
    })();
    if let Err(e) = r {
        eprintln!("Error reading NPM package: {path}, {e}");
    }
}

/// `NPM::getPackages`
fn npm_packages(roots: &BTreeSet<String>, cb: Cb<'_>) {
    for root in roots {
        let mut expanded = VecDeque::new();
        if fsx::expand_absolute_path(root, &mut expanded).is_err() {
            continue;
        }
        for p in expanded {
            let _ = (|| -> Result<(), String> {
                let node_modules = fsx::join(&p, "node_modules");
                if fsx::exists(&node_modules)? {
                    for (path, _) in fsx::dir_entries(&node_modules)? {
                        if fsx::is_directory(&path) {
                            npm_parse_package(&path, cb);
                        }
                    }
                }
                Ok(())
            })();
        }
    }
}

/// `SysInfo::getPackages(callback)`
pub fn get_packages(cb: Cb<'_>) -> Result<(), Error> {
    let mut seen: BTreeSet<String> = BTreeSet::new();
    {
        let mut fill = |v: Value| -> Result<(), String> {
            let k = format!(
                "{}{}",
                String::from_utf8_lossy(v.find(b"name").and_then(|x| x.get_str().ok()).unwrap_or(b"")),
                String::from_utf8_lossy(v.find(b"version").and_then(|x| x.get_str().ok()).unwrap_or(b""))
            );
            if seen.insert(k) {
                cb(v)?;
            }
            Ok(())
        };
        packages_from_reg(HKEY_LOCAL_MACHINE, UNINSTALL_REGISTRY, KEY_WOW64_64KEY, &mut fill);
        packages_from_reg(HKEY_LOCAL_MACHINE, UNINSTALL_REGISTRY, KEY_WOW64_32KEY, &mut fill);
        let users = Registry::open(HKEY_USERS, "", KEY_READ | KEY_ENUMERATE_SUB_KEYS)?.enumerate()?;
        for user in users {
            packages_from_reg(HKEY_USERS, &format!("{user}\\{UNINSTALL_REGISTRY}"), 0, &mut fill);
            store_packages(HKEY_USERS, &user, &mut fill);
        }
    }
    let python = python_directories();
    let node = node_directories();
    pypi_packages(&python, cb);
    npm_packages(&node, cb);
    Ok(())
}
