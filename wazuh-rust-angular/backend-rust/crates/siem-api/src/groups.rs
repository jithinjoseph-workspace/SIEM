//! Agent groups: Wazuh's `etc/shared/<group>/agent.conf` plus each agent's
//! membership in wazuh-db (remoted sends the group's merged.mg on the next
//! keepalive). Group names are per tenant: tenant `acm`'s group `web` is the
//! manager group `acm.web`. `default` is shared by every tenant and only the
//! platform admin edits it.

use axum::{
    extract::{Path, State},
    http::{header, StatusCode},
    response::{IntoResponse, Response},
    Extension, Json,
};
use serde::Deserialize;
use tracing::info;

use crate::tenancy::{self, AuthCtx};
use crate::{wazuh_manager, AppState};

/// `etc/agent.conf` of the Wazuh sources (installed as `shared/agent-template.conf`).
const TEMPLATE: &str = "<agent_config>\n\n  <!-- Shared agent configuration here -->\n\n</agent_config>\n";

/// Largest agent.conf accepted (Wazuh API `max_upload_size` default).
const MAX_CONF: usize = 10 * 1024 * 1024;

fn err(code: StatusCode, msg: &str) -> Response {
    (code, Json(serde_json::json!({ "status": "error", "message": msg }))).into_response()
}

/// Wazuh API `InputValidator.group`: `^(?!^(\.{1,2}|all)$)[\w\.\-]+$`, at most 255 chars.
fn valid_group(g: &str) -> bool {
    !g.is_empty()
        && g.len() <= 255
        && !matches!(g, "." | ".." | "all")
        && g.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'))
}

/// The manager group of `tenant`'s group `g`.
pub fn manager_name(tenant: &str, g: &str) -> Option<String> {
    if g == "default" {
        return Some(g.to_string());
    }
    // the first '.' splits tenant and group, so a tenant id must not contain one
    if tenant.is_empty() || !tenant.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-')) {
        return None;
    }
    let m = format!("{tenant}.{g}");
    (valid_group(g) && m.len() <= 255).then_some(m)
}

/// `tenant`'s name for the manager group `m` (None: another tenant's group).
pub fn display_name(tenant: &str, m: &str) -> Option<String> {
    if m == "default" {
        return Some(m.to_string());
    }
    m.strip_prefix(tenant)?.strip_prefix('.').map(str::to_string)
}

fn group_dir(m: &str) -> std::path::PathBuf {
    wazuh_manager::home().join("etc/shared").join(m)
}

/// `tenant`'s group names (`default` first).
pub fn tenant_groups(tenant: &str) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(wazuh_manager::home().join("etc/shared"))
        .map(|rd| rd.flatten().filter(|e| e.path().is_dir()).filter_map(|e| display_name(tenant, &e.file_name().to_string_lossy())).collect())
        .unwrap_or_default();
    names.sort_by(|a, b| (a != "default", a).cmp(&(b != "default", b)));
    names
}

/// `tenant`'s names of the groups of an enrolled agent.
pub fn tenant_agent_groups(tenant: &str, csv: &str) -> Vec<String> {
    agent_groups(csv).iter().filter_map(|m| display_name(tenant, m)).collect()
}

/// The groups of an enrolled agent (`default` when none was set).
pub fn agent_groups(csv: &str) -> Vec<String> {
    let v: Vec<String> = csv.split(',').map(str::trim).filter(|g| !g.is_empty()).map(str::to_string).collect();
    if v.is_empty() {
        vec!["default".to_string()]
    } else {
        v
    }
}

/// `tenant`'s group names -> existing manager groups, in order, without
/// repeats (`default` when empty). Err: the message for the first bad name.
pub fn resolve(tenant: &str, groups: &[String]) -> Result<Vec<String>, String> {
    let mut out: Vec<String> = Vec::new();
    for g in groups.iter().map(|g| g.trim()).filter(|g| !g.is_empty()) {
        let m = manager_name(tenant, g).filter(|m| group_dir(m).is_dir()).ok_or_else(|| format!("Invalid group: {g}"))?;
        if !out.contains(&m) {
            out.push(m);
        }
    }
    if out.len() > siem_authd::groups::MAX_GROUPS_PER_MULTIGROUP {
        return Err(format!("Maximum multigroup reached: Limit is {}", siem_authd::groups::MAX_GROUPS_PER_MULTIGROUP));
    }
    if out.is_empty() {
        out.push("default".to_string());
    }
    Ok(out)
}

/// `ReadConfig` callbacks of the agent's `Test_Localfile`; other sections are only checked by name.
struct LocalfileCheck(siem_config::localfile::LogreaderConfig);

impl siem_config::ConfigHandler for LocalfileCheck {
    fn section(
        &mut self,
        ctx: &mut siem_config::ConfigContext,
        _xml: &siem_xml::OsXml,
        section: siem_config::Section,
        _node: &siem_xml::XmlNode,
        children: Option<&[siem_xml::XmlNode]>,
    ) -> siem_config::Result<()> {
        let ch = children.unwrap_or(&[]);
        match section {
            siem_config::Section::Localfile => siem_config::localfile::read_localfile(ctx, ch, &mut self.0),
            siem_config::Section::LogcollectorSocket => siem_config::socket::read_socket(ch, &mut self.0.socket_list),
            _ => Ok(()),
        }
    }
}

/// What an agent checks before it applies a received agent.conf (`verifyRemoteConf`):
/// well-formed `<agent_config>` blocks, known sections, valid `<localfile>`s.
/// shortcut: the syscheck/rootcheck/wodle option readers are not run (the agent skips them too); run them here once the agent does.
fn verify_agent_conf(text: &str) -> Result<(), String> {
    use siem_config::modules::*;
    let xml = siem_xml::OsXml::read_string(text, false).map_err(|e| format!("XML error (line {}): {}", e.line, e.message))?;
    let mut ctx = siem_config::ConfigContext::new(siem_config::Platform::MANAGER);
    let mods = CAGENT_CONFIG | CSYSCHECK | CROOTCHECK | CLOCALFILE | CLGCSOCKET | CCLIENT | CBUFFER | CWMODULE | CLABELS;
    let r = siem_config::read_config_xml(&mut ctx, mods, &xml, "agent.conf", &mut LocalfileCheck(Default::default()));
    r.map_err(|e| {
        let errors: Vec<String> = ctx.log.iter().filter(|(l, _)| matches!(l, siem_config::LogLevel::Error)).map(|(_, m)| m.clone()).collect();
        if errors.is_empty() { e.0 } else { errors.join(" ") }
    })
}

fn manager_ready() -> Option<Response> {
    (!wazuh_manager::enabled()).then(|| err(StatusCode::SERVICE_UNAVAILABLE, "The Wazuh manager is not running"))
}

/// Whether the caller may change group `g` of `tenant`.
fn can_edit(ctx: &AuthCtx, tenant: &str, g: &str) -> bool {
    if g == "default" {
        ctx.is_super()
    } else {
        ctx.can_manage(tenant)
    }
}

/// `GET /api/v1/groups`: the tenant's groups, with their agent counts.
pub async fn list_groups(State(state): State<AppState>, Extension(ctx): Extension<AuthCtx>) -> Response {
    if !ctx.has_permission("siem-agents") {
        return tenancy::forbidden();
    }
    if let Some(r) = manager_ready() {
        return r;
    }
    let tenant = ctx.scope();
    let names = tenant_groups(&tenant);
    let enrolled = state.enrolled.read().unwrap();
    let mine: Vec<(&String, Vec<String>)> = enrolled.iter().filter(|(_, e)| e.tenant == tenant).map(|(id, e)| (id, agent_groups(&e.groups))).collect();
    let items: Vec<_> = names
        .iter()
        .map(|g| {
            let ids: Vec<&String> = mine.iter().filter(|(_, gs)| gs.contains(g)).map(|(id, _)| *id).collect();
            serde_json::json!({
                "name": g,
                "agents": ids.len(),
                "agent_ids": ids,
                "editable": can_edit(&ctx, &tenant, g),
            })
        })
        .collect();
    Json(serde_json::json!({ "status": "ok", "groups": items })).into_response()
}

#[derive(Deserialize)]
pub struct NewGroup {
    pub name: String,
}

/// `POST /api/v1/groups` (Wazuh `create_group`): the folder and the template agent.conf.
pub async fn create_group(Extension(ctx): Extension<AuthCtx>, Json(p): Json<NewGroup>) -> Response {
    let tenant = ctx.scope();
    if !ctx.can_manage(&tenant) {
        return tenancy::forbidden();
    }
    if let Some(r) = manager_ready() {
        return r;
    }
    let name = p.name.trim();
    if name.eq_ignore_ascii_case("default") {
        return err(StatusCode::CONFLICT, "Group 'default' already exists");
    }
    let Some(m) = manager_name(&tenant, name) else {
        return err(StatusCode::BAD_REQUEST, "Invalid group name (letters, digits, '_', '.', '-'; not 'all')");
    };
    let dir = group_dir(&m);
    if dir.exists() {
        return err(StatusCode::CONFLICT, &format!("Group '{name}' already exists"));
    }
    let made = std::fs::create_dir(&dir).and_then(|_| std::fs::write(dir.join("agent.conf"), TEMPLATE));
    if let Err(e) = made {
        let _ = std::fs::remove_dir_all(&dir);
        return err(StatusCode::INTERNAL_SERVER_ERROR, &format!("Could not create group: {e}"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(dir.join("agent.conf"), std::fs::Permissions::from_mode(0o660));
        let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700));
    }
    if !wazuh_manager::sync_group(&m, true).await {
        let _ = std::fs::remove_dir_all(&dir);
        return err(StatusCode::SERVICE_UNAVAILABLE, "wazuh-db did not accept the group");
    }
    info!("Agent group '{m}' created by {}", ctx.username);
    Json(serde_json::json!({ "status": "ok", "message": format!("Group '{name}' created.") })).into_response()
}

/// Moves `tenant`'s agents off group `g` (display name); returns (id, new groups) to send to wazuh-db.
fn drop_group_from_agents(state: &AppState, tenant: &str, g: &str) -> Vec<(String, Vec<String>)> {
    let mut changed = Vec::new();
    let mut enrolled = state.enrolled.write().unwrap();
    for (id, e) in enrolled.iter_mut().filter(|(_, e)| e.tenant == tenant) {
        let gs = agent_groups(&e.groups);
        if gs.iter().any(|x| x == g) {
            let left: Vec<String> = gs.into_iter().filter(|x| x != g).collect();
            e.groups = left.join(",");
            crate::persist_registry(state, id, tenant, Some(e), false);
            changed.push((id.clone(), left));
        }
    }
    changed
}

/// `DELETE /api/v1/groups/:name` (Wazuh `delete_groups`): the folder goes,
/// and the group's agents keep their other groups (or fall back to `default`).
pub async fn delete_group(State(state): State<AppState>, Extension(ctx): Extension<AuthCtx>, Path(name): Path<String>) -> Response {
    let tenant = ctx.scope();
    if name == "default" {
        return err(StatusCode::BAD_REQUEST, "The 'default' group cannot be deleted");
    }
    if !ctx.can_manage(&tenant) {
        return tenancy::forbidden();
    }
    if let Some(r) = manager_ready() {
        return r;
    }
    let Some(m) = manager_name(&tenant, &name).filter(|m| group_dir(m).is_dir()) else {
        return err(StatusCode::NOT_FOUND, "Group not found");
    };
    if let Err(e) = std::fs::remove_dir_all(group_dir(&m)) {
        return err(StatusCode::INTERNAL_SERVER_ERROR, &format!("Could not delete group: {e}"));
    }
    wazuh_manager::sync_group(&m, false).await;
    for (id, left) in drop_group_from_agents(&state, &tenant, &name) {
        let left = resolve(&tenant, &left).unwrap_or_else(|_| vec!["default".to_string()]);
        wazuh_manager::set_agent_groups(&id, &left).await;
    }
    info!("Agent group '{m}' deleted by {}", ctx.username);
    Json(serde_json::json!({ "status": "ok", "message": format!("Group '{name}' deleted.") })).into_response()
}

/// `GET /api/v1/groups/:name/agent.conf`
pub async fn get_agent_conf(Extension(ctx): Extension<AuthCtx>, Path(name): Path<String>) -> Response {
    if !ctx.has_permission("siem-agents") {
        return tenancy::forbidden();
    }
    if let Some(r) = manager_ready() {
        return r;
    }
    let Some(m) = manager_name(&ctx.scope(), &name).filter(|m| group_dir(m).is_dir()) else {
        return err(StatusCode::NOT_FOUND, "Group not found");
    };
    match std::fs::read_to_string(group_dir(&m).join("agent.conf")) {
        Ok(t) => ([(header::CONTENT_TYPE, "text/plain; charset=utf-8")], t).into_response(),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => ([(header::CONTENT_TYPE, "text/plain; charset=utf-8")], String::new()).into_response(),
        Err(e) => err(StatusCode::INTERNAL_SERVER_ERROR, &format!("Could not read agent.conf: {e}")),
    }
}

/// `PUT /api/v1/groups/:name/agent.conf` (Wazuh `upload_group_file`): checked, then replaced in one rename.
pub async fn put_agent_conf(Extension(ctx): Extension<AuthCtx>, Path(name): Path<String>, body: String) -> Response {
    let tenant = ctx.scope();
    if !can_edit(&ctx, &tenant, &name) {
        return tenancy::forbidden();
    }
    if let Some(r) = manager_ready() {
        return r;
    }
    let Some(m) = manager_name(&tenant, &name).filter(|m| group_dir(m).is_dir()) else {
        return err(StatusCode::NOT_FOUND, "Group not found");
    };
    if body.trim().is_empty() || body.len() > MAX_CONF {
        return err(StatusCode::BAD_REQUEST, "agent.conf must not be empty or larger than 10 MB");
    }
    if let Err(e) = verify_agent_conf(&body) {
        return err(StatusCode::BAD_REQUEST, &format!("Invalid agent.conf: {e}"));
    }
    let dir = group_dir(&m);
    let tmp = dir.join(".agent.conf.tmp");
    // remoted rescans the folder on its own; a rename means it never reads half a file
    let r = std::fs::write(&tmp, body.as_bytes()).and_then(|_| std::fs::rename(&tmp, dir.join("agent.conf")));
    if let Err(e) = r {
        let _ = std::fs::remove_file(&tmp);
        return err(StatusCode::INTERNAL_SERVER_ERROR, &format!("Could not save agent.conf: {e}"));
    }
    info!("agent.conf of group '{m}' updated by {}", ctx.username);
    Json(serde_json::json!({ "status": "ok", "message": "agent.conf saved; agents get it on their next keepalive" })).into_response()
}

#[derive(Deserialize)]
pub struct AgentGroups {
    pub groups: Vec<String>,
}

/// `PUT /api/v1/agents/:id/groups`: the agent's full group list (Wazuh
/// `set-agent-groups` override; an empty list means `default`).
pub async fn put_agent_groups(
    State(state): State<AppState>,
    Extension(ctx): Extension<AuthCtx>,
    Path(id): Path<String>,
    Json(p): Json<AgentGroups>,
) -> Response {
    let tenant = ctx.scope();
    if !ctx.can_manage(&tenant) || !crate::agent_in_scope(&state, &ctx, &id) {
        return tenancy::forbidden();
    }
    if id == "000" {
        return err(StatusCode::BAD_REQUEST, "The manager has no groups");
    }
    if let Some(r) = manager_ready() {
        return r;
    }
    let groups = match resolve(&tenant, &p.groups) {
        Ok(g) => g,
        Err(e) => return err(StatusCode::BAD_REQUEST, &e),
    };
    if !wazuh_manager::set_agent_groups(&id, &groups).await {
        return err(StatusCode::SERVICE_UNAVAILABLE, "wazuh-db did not accept the groups");
    }
    let shown: Vec<String> = groups.iter().filter_map(|m| display_name(&tenant, m)).collect();
    if let Some(e) = state.enrolled.write().unwrap().get_mut(&id) {
        e.groups = shown.join(",");
        crate::persist_registry(&state, &id, &tenant, Some(e), false);
    }
    info!("Agent {id} groups set to {} by {}", groups.join(","), ctx.username);
    Json(serde_json::json!({ "status": "ok", "groups": shown })).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_are_per_tenant() {
        assert_eq!(manager_name("acm", "web").as_deref(), Some("acm.web"));
        assert_eq!(manager_name("acm", "default").as_deref(), Some("default"));
        assert_eq!(manager_name("acm", ".."), None);
        assert_eq!(manager_name("acm", "all"), None);
        assert_eq!(manager_name("acm", "a/b"), None);
        assert_eq!(manager_name("a.b", "web"), None);
        assert_eq!(display_name("acm", "acm.web.eu").as_deref(), Some("web.eu"));
        assert_eq!(display_name("acm", "acme.web"), None);
        assert_eq!(display_name("acm", "default").as_deref(), Some("default"));
        assert_eq!(agent_groups(" "), vec!["default"]);
    }

    #[test]
    fn agent_conf_check() {
        assert!(verify_agent_conf(TEMPLATE).is_ok());
        assert!(verify_agent_conf("<agent_config os=\"Windows\"><localfile><location>Security</location><log_format>eventchannel</log_format></localfile></agent_config>").is_ok());
        assert!(verify_agent_conf("<agent_config><localfile>").is_err());
        assert!(verify_agent_conf("<agent_config><bogus/></agent_config>").is_err());
        assert!(verify_agent_conf("<ossec_config></ossec_config>").is_err());
    }
}
