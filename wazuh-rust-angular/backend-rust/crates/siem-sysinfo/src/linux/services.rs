use crate::json::{s, Obj, Value};

pub fn get_services() -> Value {
    let mut services: Vec<Value> = Vec::new();

    let service_dirs = ["/etc/systemd/system", "/lib/systemd/system", "/usr/lib/systemd/system"];
    for dir in service_dirs {
        if let Ok(entries) = std::fs::read_dir(dir) {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().to_string();
                if name.ends_with(".service") {
                    let mut o = Obj::new();
                    o.set("name", s(&name));
                    let path_str = entry.path().to_string_lossy().into_owned();
                    o.set("path", s(&path_str));
                    o.set("state", s("active"));
                    services.push(o.into_value());
                }
            }
        }
    }

    if services.is_empty() {
        Value::Null
    } else {
        Value::Array(services)
    }
}
