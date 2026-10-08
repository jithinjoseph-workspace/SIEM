use clickhouse::Client;
use bcrypt;
use serde::{Serialize, Deserialize};
use serde_json::json;



#[derive(Debug, Serialize, clickhouse::Row)]
pub struct NdrEvent {
    pub timestamp:    u32,
    pub source:       String,
    pub src_ip:       String,
    pub dst_ip:       String,
    pub src_port:     u16,
    pub dst_port:     u16,
    pub proto:        String,
    pub event_type:   String,
    pub community_id: String,
    pub raw:          String,
    pub tenant_id:    String,
    pub sensor_id:    String,
}

#[derive(Debug, Serialize, clickhouse::Row)]
pub struct NdrHit {
    pub timestamp:          u32,
    pub community_id:       String,
    pub src_ip:             String,
    pub dst_ip:             String,
    pub score:              f32,
    pub severity:           String,
    pub tags:               Vec<String>,
    pub sigma_hits:         Vec<String>,
    pub threat_intel:       u8,
    pub src_country:        String,
    pub dst_country:        String,
    pub tenant_id:          String,
    pub correlation_status: String,
    pub agent_z_details:    String,
    pub agent_s_details:    String,
    pub corroborated_at:    u32,
    pub agent_s_rule_id:    String,
    pub agent_s_category:   String,
    pub updated_at:         u32,
    pub sensor_id:          String,
}

#[derive(Debug, Serialize, Deserialize, clickhouse::Row)]
#[allow(dead_code)]
pub struct TopIp {
    pub ip:    String,
    pub count: u64,
}

#[derive(Debug, Serialize, clickhouse::Row)]
pub struct RetroScanRow {
    pub id:           String,
    pub rule_id:      String,
    pub rule_name:    String,
    pub rule_content: String,
    pub hours_back:   u32,
    pub status:       String,
    pub started_at:   u32,
    pub completed_at: u32,
    pub match_count:  u64,
    pub matches:      String,
    pub tenant_id:    String,
    pub updated_at:   u32,
}

#[derive(Debug, Deserialize, clickhouse::Row)]
pub struct RetroScanReadRow {
    pub id:           String,
    pub rule_id:      String,
    pub rule_name:    String,
    pub rule_content: String,
    pub hours_back:   u32,
    pub status:       String,
    pub started_at:   u32,
    pub completed_at: u32,
    pub match_count:  u64,
    pub matches:      String,
}


#[derive(Debug, Serialize, Deserialize, clickhouse::Row)]
pub struct NetworkPair {
    pub src_ip:      String,
    pub dst_ip:      String,
    pub connections: u64,
    pub protocols:   Vec<String>,
}


#[derive(Debug, Serialize, Deserialize, clickhouse::Row)]
#[allow(dead_code)]
pub struct RecentEvent {
    pub timestamp:    u32,
    pub source:       String,
    pub src_ip:       String,
    pub dst_ip:       String,
    pub proto:        String,
    pub event_type:   String,
    pub community_id: String,
}
#[derive(Debug, Serialize, Deserialize, clickhouse::Row)]
#[allow(dead_code)]
pub struct RecentHit {
    pub timestamp:    u32,
    pub community_id: String,
    pub src_ip:       String,
    pub dst_ip:       String,
    pub score:        f32,
    pub severity:     String,
    pub threat_intel: u8,
    pub src_country:  String,
    pub dst_country:  String,
}

#[derive(Debug, Serialize, Deserialize, clickhouse::Row)]
#[allow(dead_code)]
pub struct RecentHitDetail {
    pub timestamp:          u32,
    pub community_id:       String,
    pub src_ip:             String,
    pub dst_ip:             String,
    pub score:              f32,
    pub severity:           String,
    pub tags:               Vec<String>,
    pub sigma_hits:         Vec<String>,
    pub threat_intel:       u8,
    pub src_country:        String,
    pub dst_country:        String,
    pub correlation_status: String,
    pub agent_s_rule_id:    String,
    pub corroborated_at:    u32,
    pub sensor_id:          String,
}

#[derive(Debug, Serialize, Deserialize, clickhouse::Row)]
pub struct ThreatIntelHit {
    pub src_ip:    String,
    pub dst_ip:    String,
    pub hits:      u64,
    pub last_seen: u32,
}

#[derive(Debug, Serialize, Deserialize, clickhouse::Row)]
pub struct PcapSessionRow {
    pub session_id:   String,
    pub community_id: String,
    pub src_ip:       String,
    pub dst_ip:       String,
    pub src_port:     u16,
    pub dst_port:     u16,
    pub proto:        String,
    pub start_time:   String,
    pub end_time:     String,
    pub bytes:        u64,
    pub packets:      u64,
    pub arkime_url:   String,
    pub sensor_host:  String,
    pub file_path:    String,
}

#[derive(Debug, Serialize, Deserialize, clickhouse::Row)]
pub struct SensorKeyRow {
    pub id: String,
    pub key_prefix: String,
    pub tenant_id: String,
    pub name: String,
    pub hostname: String,
    pub interface_name: String,
    pub os_name: String,
    pub agent_z_status: String,
    pub agent_s_status: String,
    pub vector_status: String,
    pub arkime_status: String,
    pub arkime_url: String,
    pub arkime_pass: String,
    pub active: u8,
    pub created_at: String,
    pub last_seen: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, clickhouse::Row)]
pub struct AssetRow {
    pub ip: String,
    pub mac: String,
    pub hostname: String,
    pub vendor: String,
    pub os_guess: String,
    pub device_type: String,
    pub custom_name: String,
    pub tenant_id: String,
    pub first_seen: u32,
    pub last_seen: u32,
    pub ip_history: String,
    pub trusted: u8,
    pub threat_flagged: u8,
    pub role: String,
    pub criticality: u8,
    pub open_ports: String,
    pub subnet_role: String,
    pub ja3_os: String,
}

#[derive(Debug, Serialize, Deserialize, clickhouse::Row)]
pub struct AnnouncementRow {
    pub id: String,
    pub title: String,
    pub message: String,
    pub announcement_type: String,
    pub audience: String,
    pub status: String,
    pub target_roles: Vec<String>,
    pub target_tenants: Vec<String>,
    pub starts_at: String,
    pub ends_at: String,
    pub created_by: String,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Serialize, Deserialize, clickhouse::Row)]
pub struct AnnouncementReadRow {
    pub announcement_id: String,
}

#[derive(clickhouse::Row, serde::Deserialize)]
pub struct SupportMessageRow {
    pub id: String,
    pub tenant_id: String,
    pub sender_username: String,
    pub sender_role: String,
    pub subject: String,
    pub category: String,
    pub message: String,
    pub status: String,
    pub admin_reply: String,
    pub replied_by: String,
    pub forwarded: u8,
    pub forwarded_by: String,
    pub deleted: u8,
    pub created_at: String,
    pub updated_at: String,
    pub replied_at: String,
    pub forwarded_at: String,
}

fn support_message_to_json(row: SupportMessageRow) -> serde_json::Value {
    json!({
        "id": row.id,
        "tenant_id": row.tenant_id,
        "sender_username": row.sender_username,
        "sender_role": row.sender_role,
        "subject": row.subject,
        "category": row.category,
        "message": row.message,
        "status": row.status,
        "admin_reply": row.admin_reply,
        "replied_by": row.replied_by,
        "forwarded": row.forwarded,
        "forwarded_by": row.forwarded_by,
        "deleted": row.deleted,
        "created_at": row.created_at,
        "updated_at": row.updated_at,
        "replied_at": row.replied_at,
        "forwarded_at": row.forwarded_at,
    })
}

#[derive(Clone)]
pub struct ClickhouseStorage {
    pub(crate) client: Client,
}

/// Columns added to tenant tables after their first release. The startup migration replays
/// init.sql per tenant, but `CREATE TABLE IF NOT EXISTS` skips tables that already exist, so an
/// existing tenant database never got them (creating a SOAR case failed with "No such column
/// case_number in table ndr_<tenant>.soar_cases"). `{db}` is the tenant database.
const TENANT_COLUMN_MIGRATIONS: &[&str] = &[
    "ALTER TABLE {db}.soar_cases ADD COLUMN IF NOT EXISTS case_number String DEFAULT ''",
    "ALTER TABLE {db}.soar_cases ADD COLUMN IF NOT EXISTS priority String DEFAULT 'P2'",
    "ALTER TABLE {db}.sigma_rules ADD COLUMN IF NOT EXISTS source String DEFAULT 'custom'",
];

pub(crate) fn sql_escape(value: &str) -> String {
    // The clickhouse crate (0.11) treats EVERY `?` in the query text as a bind placeholder and
    // panics ("unbound query argument") when none is bound; there is no `??` escape. A value
    // such as a URL with a query string, a hostname or a rule text therefore killed the task
    // running the query. `\x3F` is ClickHouse's own escape for `?` inside a string literal.
    value.replace('\\', "\\\\").replace('\'', "\\'").replace('?', "\\x3F")
}

fn sql_array_literal(values: &[String]) -> String {
    if values.is_empty() {
        return "CAST([], 'Array(String)')".to_string();
    }

    let items = values
        .iter()
        .map(|value| format!("'{}'", sql_escape(value)))
        .collect::<Vec<_>>()
        .join(",");
    format!("[{}]", items)
}

fn tenant_db(tenant_id: &str) -> String {
    if tenant_id == "default" {
        "ndr".to_string()
    } else {
        format!("ndr_{}", tenant_id.replace("-", "_"))
    }
}

pub fn tenant_db_pub(tenant_id: &str) -> String {
    tenant_db(tenant_id)
}

/// Every suppression that applies to `tenant_id`, as a subquery to put in a FROM.
///
/// save_ai_suppression() writes a tenant's suppressions to that tenant's own
/// database (`ndr_<tenant>.ai_suppressions`), but the alert list, the
/// suppression list endpoint and the report counts all read the global
/// `ndr.ai_suppressions` instead. For every tenant except `default` (whose
/// database IS `ndr`) the row was saved and then never found, so a suppressed
/// alert reappeared on the next page load - the click only hid it in the
/// browser. Reading the tenant's table (plus any global rows with an empty
/// tenant_id, which apply to everyone) fixes that. Columns are listed
/// explicitly so the UNION does not depend on column order across tables.
/// FINAL is applied inside, so callers must not add it again.
pub fn suppressions_source(tenant_id: &str) -> String {
    let db = tenant_db(tenant_id);
    const COLS: &str = "suppress_ip, signature_name, community_id, suppress_scope, active, expires_at, tenant_id";
    if db == "ndr" {
        format!("(SELECT {COLS} FROM ndr.ai_suppressions FINAL)")
    } else {
        format!(
            "(SELECT {COLS} FROM {db}.ai_suppressions FINAL \
              UNION ALL \
              SELECT {COLS} FROM ndr.ai_suppressions FINAL WHERE tenant_id = '')"
        )
    }
}

pub fn sql_escape_pub(value: &str) -> String {
    sql_escape(value)
}

fn get_base_domain(domain: &str) -> String {
    let parts: Vec<&str> = domain.split('.').collect();
    if parts.len() <= 2 {
        return domain.to_string();
    }
    let second_to_last = parts[parts.len() - 2];
    let short_tlds = ["co", "com", "org", "net", "gov", "ac", "edu"];
    if second_to_last.len() <= 3 && short_tlds.contains(&second_to_last) {
        if parts.len() >= 3 {
            return format!("{}.{}.{}", parts[parts.len()-3], parts[parts.len()-2], parts[parts.len()-1]);
        }
    }
    format!("{}.{}", parts[parts.len()-2], parts[parts.len()-1])
}

#[allow(dead_code)]
impl ClickhouseStorage {


// ── User auth ──────────────────────────────────────────────────────────────
// All writes to ndr.users use `SETTINGS mutations_sync=1` so ALTER TABLE UPDATE
// is synchronous. A FINAL read here always reflects the actual current state.
pub async fn verify_user(
    &self,
    username: &str,
    password: &str,
) -> anyhow::Result<Option<serde_json::Value>> {
    let rows = self.client
        .query(
            "SELECT id, username, password_hash, role, tenant_id, permissions, active, gmail, secret_code \
             FROM ndr.users \
             WHERE username = ? \
             ORDER BY created_at DESC LIMIT 1"
        )
        .bind(username)
        .fetch_all::<(String, String, String, String, String, String, u8, String, String)>()
        .await?;

    let Some(row) = rows.first() else {
        return Ok(None); // user not found
    };

    // Disabled accounts are blocked before password check.
    // Returns a typed sentinel so the caller shows a specific error message.
    if row.6 != 1 {
        return Ok(Some(json!({ "__disabled__": true })));
    }

    if !bcrypt::verify(password, &row.2).unwrap_or(false) {
        return Ok(None); // wrong password — same response as user-not-found to prevent enumeration
    }

    Ok(Some(json!({
        "id":          row.0,
        "username":    row.1,
        "role":        row.3,
        "tenant_id":   row.4,
        "permissions": row.5,
        "gmail":       row.7,
        "secret_code": row.8,
    })))
}


pub async fn get_users(
    &self
) -> anyhow::Result<Vec<serde_json::Value>> {
    let result = self.client
        .query("SELECT id, username, role, tenant_id, permissions, active, toString(created_at) FROM ndr.users FINAL ORDER BY created_at")
        .fetch_all::<(String,String,String,String,String,u8,String)>()
        .await?;
    Ok(result.iter().map(|r| json!({
        "id": r.0,
        "username": r.1,
        "role": r.2,
        "tenant_id": r.3,
        "permissions": r.4,
        "active": r.5 == 1,
        "created_at": r.6
    })).collect())
}

pub async fn get_users_by_tenant(
    &self,
    tenant_id: &str,
) -> anyhow::Result<Vec<serde_json::Value>> {
    let result = self.client
        .query(
            "SELECT id, username, role, tenant_id, permissions, active, toString(created_at)
             FROM ndr.users FINAL
             WHERE tenant_id = ?
             ORDER BY created_at"
        )
        .bind(tenant_id)
        .fetch_all::<(String,String,String,String,String,u8,String)>()
        .await?;
    Ok(result.iter().map(|r| json!({
        "id": r.0,
        "username": r.1,
        "role": r.2,
        "tenant_id": r.3,
        "permissions": r.4,
        "active": r.5 == 1,
        "created_at": r.6
    })).collect())
}

pub async fn get_user_identity(
    &self,
    id: &str,
) -> anyhow::Result<Option<(String, String, String)>> {
    let result = self.client
        .query(
            "SELECT username, role, tenant_id
             FROM ndr.users
             WHERE id = ?
             ORDER BY created_at DESC LIMIT 1"
        )
        .bind(id)
        .fetch_all::<(String, String, String)>()
        .await?;
    Ok(result.first().cloned())
}

pub async fn get_user_by_id(
    &self,
    id: &str,
) -> anyhow::Result<Option<serde_json::Value>> {
    let result = self.client
        .query(
            "SELECT id, username, role, tenant_id, permissions, toString(created_at)
             FROM ndr.users
             WHERE id = ?
             ORDER BY created_at DESC LIMIT 1"
        )
        .bind(id)
        .fetch_all::<(String, String, String, String, String, String)>()
        .await?;

    Ok(result.first().map(|r| json!({
        "id": r.0,
        "username": r.1,
        "role": r.2,
        "tenant_id": r.3,
        "permissions": r.4,
        "created_at": r.5
    })))
}

pub async fn get_user_by_username(
    &self,
    username: &str,
) -> anyhow::Result<Option<serde_json::Value>> {
    let result = self.client
        .query(
            "SELECT id, username, role, tenant_id, permissions, toString(created_at), \
                    gmail, secret_code
             FROM ndr.users
             WHERE username = ?
             ORDER BY created_at DESC LIMIT 1"
        )
        .bind(username)
        .fetch_all::<(String, String, String, String, String, String, String, String)>()
        .await?;

    Ok(result.first().map(|r| json!({
        "id":          r.0,
        "username":    r.1,
        "role":        r.2,
        "tenant_id":   r.3,
        "permissions": r.4,
        "created_at":  r.5,
        "gmail":       r.6,
        "secret_code": r.7
    })))
}

pub async fn create_user(
    &self,
    username: &str,
    password_hash: &str,
    role: &str,
    tenant_id: &str,
    permissions: &str,
    gmail: &str,
    secret_code: &str,
) -> anyhow::Result<()> {
    self.client
        .query(
            "INSERT INTO ndr.users \
             (username, password_hash, role, tenant_id, permissions, active, gmail, secret_code) \
             VALUES (?, ?, ?, ?, ?, 1, ?, ?)"
        )
        .bind(username)
        .bind(password_hash)
        .bind(role)
        .bind(tenant_id)
        .bind(permissions)
        .bind(gmail)
        .bind(secret_code)
        .execute()
        .await?;
    Ok(())
}

pub async fn update_user_permissions(
    &self,
    id: &str,
    permissions: &str,
) -> anyhow::Result<()> {
    // mutations_sync=1: wait until mutation is applied on disk before returning.
    self.client
        .query(
            "ALTER TABLE ndr.users UPDATE permissions = ? WHERE id = ? SETTINGS mutations_sync=1"
        )
        .bind(permissions)
        .bind(id)
        .execute()
        .await?;
    Ok(())
}

pub async fn update_user(
    &self,
    id: &str,
    role: &str,
    tenant_id: &str,
    permissions: &str,
    active: bool,
    password_hash: Option<&str>,
) -> anyhow::Result<()> {
    let active_flag: u8 = if active { 1 } else { 0 };

    // mutations_sync=1: block until the mutation is applied on disk.
    // Without this, ALTER TABLE UPDATE is async — a disabled user could still
    // log in for seconds/minutes until ClickHouse applies the background mutation.
    match password_hash {
        Some(hash) => {
            self.client
                .query(
                    "ALTER TABLE ndr.users \
                     UPDATE role = ?, tenant_id = ?, permissions = ?, \
                     active = ?, password_hash = ? \
                     WHERE id = ? \
                     SETTINGS mutations_sync=1"
                )
                .bind(role)
                .bind(tenant_id)
                .bind(permissions)
                .bind(active_flag)
                .bind(hash)
                .bind(id)
                .execute()
                .await?;
        }
        None => {
            self.client
                .query(
                    "ALTER TABLE ndr.users \
                     UPDATE role = ?, tenant_id = ?, permissions = ?, active = ? \
                     WHERE id = ? \
                     SETTINGS mutations_sync=1"
                )
                .bind(role)
                .bind(tenant_id)
                .bind(permissions)
                .bind(active_flag)
                .bind(id)
                .execute()
                .await?;
        }
    }
    Ok(())
}

pub async fn set_user_active(
    &self,
    id: &str,
    active: bool,
) -> anyhow::Result<()> {
    let active_flag: u8 = if active { 1 } else { 0 };
    // mutations_sync=1: force synchronous mutation so the active flag is
    // immediately enforced on the next query. Without this, ALTER TABLE UPDATE
    // is a background operation — disabled users could still log in for
    // seconds or minutes after being disabled.
    self.client
        .query(
            "ALTER TABLE ndr.users UPDATE active = ? WHERE id = ? SETTINGS mutations_sync=1"
        )
        .bind(active_flag)
        .bind(id)
        .execute()
        .await?;
    Ok(())
}

/// Check whether a specific user account is enabled.
/// Returns `true` (allow) if the user is not found (fail-open for unknown users;
/// the JWT would already be invalid in that case).
/// Returns `false` only when the row exists AND `active = 0`.
pub async fn is_user_active(
    &self,
    username: &str,
) -> anyhow::Result<bool> {
    let rows = self.client
        .query(
            "SELECT active FROM ndr.users \
             WHERE username = ? ORDER BY created_at DESC LIMIT 1"
        )
        .bind(username)
        .fetch_all::<u8>()
        .await?;

    // No row → user not in DB; JWT verification already failed earlier, so allow
    Ok(rows.first().map(|active| *active == 1).unwrap_or(true))
}

pub async fn set_user_password(
    &self,
    id: &str,
    password_hash: &str,
) -> anyhow::Result<()> {
    self.client
        .query("ALTER TABLE ndr.users UPDATE password_hash = ? WHERE id = ? SETTINGS mutations_sync=1")
        .bind(password_hash)
        .bind(id)
        .execute()
        .await?;
    Ok(())
}


pub async fn delete_user(
    &self, id: &str
) -> anyhow::Result<()> {
    self.client
        .query("ALTER TABLE ndr.users DELETE WHERE id = ? SETTINGS mutations_sync=1")
        .bind(id)
        .execute()
        .await?;
    Ok(())
}

// ── Password-reset recovery helpers ─────────────────────────────────────────

/// Validate a tenant admin's secret code.
/// Returns Some(gmail) if the username exists, role = tenant_admin, and the
/// secret_code matches; returns None otherwise.
pub async fn verify_tenant_admin_secret(
    &self,
    username: &str,
    secret_code: &str,
) -> anyhow::Result<Option<String>> {
    let rows = self.client
        .query(
            "SELECT gmail FROM ndr.users \
             WHERE username = ? AND role = 'tenant_admin' \
             AND secret_code = ? AND active = 1 \
             ORDER BY created_at DESC LIMIT 1"
        )
        .bind(username)
        .bind(secret_code)
        .fetch_all::<String>()
        .await?;
    Ok(rows.into_iter().next())
}

/// Return the stored gmail for a tenant admin (used to cross-check OTP step).
pub async fn get_gmail_for_user(
    &self,
    username: &str,
) -> anyhow::Result<Option<String>> {
    let rows = self.client
        .query(
            "SELECT gmail FROM ndr.users \
             WHERE username = ? AND role = 'tenant_admin' AND active = 1 \
             ORDER BY created_at DESC LIMIT 1"
        )
        .bind(username)
        .fetch_all::<String>()
        .await?;
    Ok(rows.into_iter().next())
}

/// Get the gmail of the tenant_admin for a given tenant so we can notify them of new logins.
pub async fn get_tenant_admin_gmail(
    &self,
    tenant_id: &str,
) -> anyhow::Result<Option<String>> {
    let rows = self.client
        .query(
            "SELECT gmail FROM ndr.users \
             WHERE tenant_id = ? AND role = 'tenant_admin' AND active = 1 \
             AND gmail != '' \
             ORDER BY created_at DESC LIMIT 1"
        )
        .bind(tenant_id)
        .fetch_all::<String>()
        .await?;
    Ok(rows.into_iter().next())
}

/// Update the password hash for a user identified by username.
/// Used by the forgot-password reset endpoint.
pub async fn reset_password_by_username_direct(
    &self,
    username: &str,
    new_hash: &str,
) -> anyhow::Result<()> {
    self.client
        .query(
            "ALTER TABLE ndr.users \
             UPDATE password_hash = ? \
             WHERE username = ? \
             SETTINGS mutations_sync=1"
        )
        .bind(new_hash)
        .bind(username)
        .execute()
        .await?;
    Ok(())
}

/// Update the gmail address for a user by id.
pub async fn update_user_gmail(
    &self,
    id: &str,
    gmail: &str,
) -> anyhow::Result<()> {
    self.client
        .query(
            "ALTER TABLE ndr.users \
             UPDATE gmail = ? \
             WHERE id = ? \
             SETTINGS mutations_sync=1"
        )
        .bind(gmail)
        .bind(id)
        .execute()
        .await?;
    Ok(())
}

pub async fn update_user_secret_code(
    &self,
    id: &str,
    code: &str,
) -> anyhow::Result<()> {
    self.client
        .query(
            "ALTER TABLE ndr.users \
             UPDATE secret_code = ? \
             WHERE id = ? \
             SETTINGS mutations_sync=1"
        )
        .bind(code)
        .bind(id)
        .execute()
        .await?;
    Ok(())
}


pub async fn get_tenants(
    &self
) -> anyhow::Result<Vec<serde_json::Value>> {
    let result = self.client
        .query("SELECT id, name, active, ai_enabled, features FROM ndr.tenants FINAL ORDER BY created_at")
        .fetch_all::<(String,String,u8,u8,String)>()
        .await?;
    Ok(result.iter().map(|r| {
        let features: Vec<&str> = r.4.split(',').filter(|s| !s.is_empty()).collect();
        json!({
            "id":         r.0,
            "name":       r.1,
            "active":     r.2 == 1,
            "ai_enabled": r.3 == 1,
            "features":   features,
        })
    }).collect())
}

pub async fn get_tenant_features(&self, tenant_id: &str) -> Vec<String> {
    self.client
        .query("SELECT features FROM ndr.tenants FINAL WHERE id = ? LIMIT 1")
        .bind(tenant_id)
        .fetch_all::<String>()
        .await
        .unwrap_or_default()
        .first()
        .map(|v| v.split(',').filter(|s| !s.is_empty()).map(|s| s.to_string()).collect())
        .unwrap_or_else(|| vec!["ndr".to_string(), "ai".to_string()])
}

pub async fn set_tenant_features(&self, tenant_id: &str, features: &[String]) -> anyhow::Result<()> {
    let features_str = features.join(",");
    self.client
        .query(&format!(
            "INSERT INTO ndr.tenants (id, name, active, ai_enabled, features, updated_at, created_at) \
             SELECT id, name, active, ai_enabled, '{}', now(), created_at \
             FROM ndr.tenants FINAL WHERE id = '{}'",
            sql_escape(&features_str),
            sql_escape(tenant_id)
        ))
        .execute()
        .await?;
    Ok(())
}


pub async fn get_tenant_ai_enabled(&self, tenant_id: &str) -> bool {
    self.client
        .query("SELECT ai_enabled FROM ndr.tenants FINAL WHERE id = ? LIMIT 1")
        .bind(tenant_id)
        .fetch_all::<u8>()
        .await
        .unwrap_or_default()
        .first()
        .map(|v| *v == 1)
        .unwrap_or(true)
}

pub async fn set_tenant_ai_enabled(&self, tenant_id: &str, enabled: bool) -> anyhow::Result<()> {
    let val: u8 = if enabled { 1 } else { 0 };
    self.client
        .query(
            "INSERT INTO ndr.tenants (id, name, active, ai_enabled, updated_at, created_at) \
             SELECT id, name, active, ?, now(), created_at \
             FROM ndr.tenants FINAL WHERE id = ?"
        )
        .bind(val)
        .bind(tenant_id)
        .execute()
        .await?;
    Ok(())
}

pub async fn get_all_tenants(
    &self,
) -> anyhow::Result<Vec<String>> {
    let result = self.client
        .query("SELECT id FROM ndr.tenants FINAL WHERE active = 1")
        .fetch_all::<String>()
        .await?;
    Ok(result)
}

pub async fn is_tenant_active(
    &self,
    id: &str,
) -> anyhow::Result<bool> {
    let rows = self.client
        .query(
            "SELECT active FROM ndr.tenants WHERE id = ? ORDER BY updated_at DESC LIMIT 1"
        )
        .bind(id)
        .fetch_all::<u8>()
        .await?;

    Ok(rows.first().map(|active| *active == 1).unwrap_or(true))
}

pub async fn create_tenant(
    &self,
    id: &str,
    name: &str,
) -> anyhow::Result<()> {
    // 1. Insert into main tenants table
    self.client
        .query(
            "INSERT INTO ndr.tenants (id, name, active, updated_at) VALUES (?, ?, 1, now())"
        )
        .bind(id)
        .bind(name)
        .execute()
        .await?;

    // 2. Create dedicated database for tenant on all cluster nodes
    let db_name = format!("ndr_{}", id.replace("-", "_"));
    self.client.query(&format!(
        "CREATE DATABASE IF NOT EXISTS {} ON CLUSTER ndr_cluster", db_name
    )).execute().await?;

    // 3. Load init.sql and create tables in the tenant DB namespace dynamically
    let install_dir = std::env::var("INSTALL_DIR")
        .unwrap_or_else(|_| ".".to_string());
    let paths = vec![
        "/app/config/clickhouse/init.sql".to_string(),
        format!("{}/config/clickhouse/init.sql", install_dir),
        "./config/clickhouse/init.sql".to_string(),
    ];

    let mut sql_content = None;
    for sql_path in &paths {
        if let Ok(sql) = std::fs::read_to_string(sql_path) {
            sql_content = Some(sql);
            break;
        }
    }

    if let Some(sql) = sql_content {
        for stmt in sql.split(';') {
            let stmt = stmt.trim()
                .lines()
                .filter(|l| !l.trim().starts_with("--"))
                .collect::<Vec<_>>()
                .join("\n")
                .trim()
                .to_string();

            if stmt.is_empty() {
                continue;
            }

            // Skip global-only tables not needed inside individual tenant databases
            if stmt.contains("CREATE DATABASE IF NOT EXISTS ndr")
                || stmt.contains("ndr.users")
                || stmt.contains("ndr.tenants")
                || stmt.contains("ndr.announcements")
                || stmt.contains("ndr.announcement_reads")
                || stmt.contains("ndr.rules_state")
                || stmt.contains("ndr.shared_iocs")
            {
                continue;
            }

            // Replace database namespace with tenant DB and set its default tenant_id
            let mut tenant_stmt = stmt.replace("ndr.", &format!("{}.", db_name));
            // Fix ZooKeeper path: /clickhouse/tables/{shard}/ndr/ → /clickhouse/tables/{shard}/<tenant_db>/
            // The dot-replace above only fixes the SQL table prefix, not the ZooKeeper path inside ENGINE=
            tenant_stmt = tenant_stmt.replace(
                "/clickhouse/tables/{shard}/ndr/",
                &format!("/clickhouse/tables/{{shard}}/{}/", db_name),
            );
            tenant_stmt = tenant_stmt.replace("DEFAULT 'default'", &format!("DEFAULT '{}'", id));

            if let Err(e) = self.client
                .query(&tenant_stmt)
                .execute().await {
                tracing::warn!(
                    "Dynamic table creation warning for tenant DB {}: {}. Error: {}", 
                    db_name, tenant_stmt, e
                );
            }
        }
        tracing::info!(
            "✅ Tenant DB created and schema dynamically initialized from init.sql: {}", db_name
        );
    } else {
        tracing::warn!("init.sql not found while provisioning tenant DB {}!", db_name);
    }

    Ok(())
}

pub async fn update_tenant(
    &self,
    id: &str,
    name: &str,
    active: bool,
) -> anyhow::Result<()> {
    let esc_id   = sql_escape(id);
    let esc_name = sql_escape(name);
    self.client.query(&format!(
        "INSERT INTO ndr.tenants (id, name, active, ai_enabled, updated_at, created_at) \
         SELECT id, '{name}', {active}, ai_enabled, now(), created_at \
         FROM ndr.tenants FINAL WHERE id = '{id}'",
        name   = esc_name,
        active = if active { 1 } else { 0 },
        id     = esc_id,
    )).execute().await?;
    Ok(())
}

pub async fn set_tenant_active(
    &self,
    id: &str,
    active: bool,
) -> anyhow::Result<()> {
    let id = sql_escape(id);
    self.client.query(&format!(
        "INSERT INTO ndr.tenants (id, name, active, ai_enabled, updated_at, created_at) \
         SELECT id, name, {active}, ai_enabled, now(), created_at \
         FROM ndr.tenants FINAL WHERE id = '{id}'",
        active = if active { 1 } else { 0 },
        id     = id,
    )).execute().await?;
    Ok(())
}

pub async fn create_announcement(
    &self,
    id: &str,
    title: &str,
    message: &str,
    announcement_type: &str,
    audience: &str,
    status: &str,
    target_roles: &[String],
    target_tenants: &[String],
    start_at: Option<&str>,
    end_at: Option<&str>,
    created_by: &str,
) -> anyhow::Result<()> {
    let start_expr = start_at
        .filter(|value| !value.trim().is_empty())
        .map(|value| format!("parseDateTimeBestEffort('{}')", sql_escape(value)))
        .unwrap_or_else(|| "now()".to_string());
    let end_expr = end_at
        .filter(|value| !value.trim().is_empty())
        .map(|value| format!("parseDateTimeBestEffort('{}')", sql_escape(value)))
        .unwrap_or_else(|| "CAST(NULL, 'Nullable(DateTime)')".to_string());
    let query = format!(
        "INSERT INTO ndr.announcements \
         (id, title, message, announcement_type, audience, status, target_roles, target_tenants, start_at, end_at, created_by, updated_at) \
         VALUES ('{}','{}','{}','{}','{}','{}',{},{},{},{},'{}',now())",
        sql_escape(id),
        sql_escape(title),
        sql_escape(message),
        sql_escape(announcement_type),
        sql_escape(audience),
        sql_escape(status),
        sql_array_literal(target_roles),
        sql_array_literal(target_tenants),
        start_expr,
        end_expr,
        sql_escape(created_by),
    );
    self.client.query(&query).execute().await?;
    Ok(())
}

pub async fn get_announcements(
    &self,
) -> anyhow::Result<Vec<serde_json::Value>> {
    let result = self.client
        .query(
            "SELECT id, title, message, announcement_type, audience, status, target_roles, target_tenants, \
             toString(start_at) AS starts_at, ifNull(toString(end_at), '') AS ends_at, created_by, \
             toString(created_at) AS created_at, toString(updated_at) AS updated_at \
             FROM ndr.announcements FINAL \
             ORDER BY updated_at DESC"
        )
        .fetch_all::<AnnouncementRow>()
        .await?;

    Ok(result.iter().map(|r| json!({
        "id": r.id,
        "title": r.title,
        "message": r.message,
        "type": r.announcement_type,
        "audience": r.audience,
        "status": r.status,
        "active": r.status == "active",
        "target_roles": r.target_roles,
        "target_tenants": r.target_tenants,
        "start_at": r.starts_at,
        "starts_at": r.starts_at,
        "end_at": r.ends_at,
        "ends_at": r.ends_at,
        "created_by": r.created_by,
        "created_at": r.created_at,
        "updated_at": r.updated_at
    })).collect())
}

pub async fn get_active_announcements(
    &self,
    role: &str,
    tenant_id: &str,
    username: &str,
) -> anyhow::Result<Vec<serde_json::Value>> {
    let role = sql_escape(role);
    let role_alias = if role == "tenant_admin" {
        "tenant_admins".to_string()
    } else {
        role.clone()
    };
    let tenant_id = sql_escape(tenant_id);
    let username = sql_escape(username);
    let query = format!(
        "SELECT id, title, message, announcement_type, audience, status, target_roles, target_tenants, \
         toString(start_at) AS starts_at, ifNull(toString(end_at), '') AS ends_at, created_by, \
         toString(created_at) AS created_at, toString(updated_at) AS updated_at \
         FROM ndr.announcements FINAL \
         WHERE status = 'active' \
           AND start_at <= now() \
           AND (isNull(end_at) OR end_at >= now()) \
           AND (length(target_roles) = 0 OR has(target_roles, 'all') OR has(target_roles, '{}') OR has(target_roles, '{}')) \
           AND (length(target_tenants) = 0 OR has(target_tenants, 'all') OR has(target_tenants, '{}')) \
         ORDER BY start_at DESC, updated_at DESC",
        role,
        role_alias,
        tenant_id,
    );
    let result = self.client
        .query(&query)
        .fetch_all::<AnnouncementRow>()
        .await?;
    let read_query = format!(
        "SELECT announcement_id FROM ndr.announcement_reads FINAL WHERE username = '{}'",
        username
    );
    let read_ids = self.client
        .query(&read_query)
        .fetch_all::<AnnouncementReadRow>()
        .await
        .unwrap_or_default()
        .into_iter()
        .map(|row| row.announcement_id)
        .collect::<std::collections::HashSet<_>>();

    Ok(result.iter().map(|r| json!({
        "id": r.id,
        "title": r.title,
        "message": r.message,
        "type": r.announcement_type,
        "audience": r.audience,
        "status": r.status,
        "active": r.status == "active",
        "read": read_ids.contains(&r.id),
        "target_roles": r.target_roles,
        "target_tenants": r.target_tenants,
        "start_at": r.starts_at,
        "starts_at": r.starts_at,
        "end_at": r.ends_at,
        "ends_at": r.ends_at,
        "created_by": r.created_by,
        "created_at": r.created_at,
        "updated_at": r.updated_at
    })).collect())
}

pub async fn mark_announcement_read(
    &self,
    announcement_id: &str,
    username: &str,
) -> anyhow::Result<()> {
    let announcement_id = sql_escape(announcement_id);
    let username = sql_escape(username);
    let query = format!(
        "INSERT INTO ndr.announcement_reads (announcement_id, username, read_at) \
         VALUES ('{}','{}',now())",
        announcement_id,
        username
    );
    self.client.query(&query).execute().await?;
    Ok(())
}

pub async fn update_announcement(
    &self,
    id: &str,
    title: &str,
    message: &str,
    announcement_type: &str,
    audience: &str,
    status: &str,
    target_roles: &[String],
    target_tenants: &[String],
    start_at: Option<&str>,
    end_at: Option<&str>,
) -> anyhow::Result<()> {
    let now_literal = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S").to_string();
    let start_expr = start_at
        .filter(|value| !value.trim().is_empty())
        .map(|value| format!("parseDateTimeBestEffort('{}')", sql_escape(value)))
        .unwrap_or_else(|| format!("toDateTime('{}')", now_literal));
    let end_expr = end_at
        .filter(|value| !value.trim().is_empty())
        .map(|value| format!("parseDateTimeBestEffort('{}')", sql_escape(value)))
        .unwrap_or_else(|| "CAST(NULL, 'Nullable(DateTime)')".to_string());
    // INSERT SELECT: ReplacingMergeTree(updated_at) forbids ALTER TABLE UPDATE on the version key.
    // Insert a new row copying immutable fields (created_by, created_at) from the existing row.
    let query = format!(
        "INSERT INTO ndr.announcements \
         (id, title, message, announcement_type, audience, status, \
          target_roles, target_tenants, start_at, end_at, created_by, created_at, updated_at) \
         SELECT id, '{title}', '{message}', '{atype}', '{audience}', '{status}', \
                {roles}, {tenants}, {start_expr}, {end_expr}, \
                created_by, created_at, now() \
         FROM ndr.announcements FINAL WHERE id = '{id}'",
        title      = sql_escape(title),
        message    = sql_escape(message),
        atype      = sql_escape(announcement_type),
        audience   = sql_escape(audience),
        status     = sql_escape(status),
        roles      = sql_array_literal(target_roles),
        tenants    = sql_array_literal(target_tenants),
        start_expr = start_expr,
        end_expr   = end_expr,
        id         = sql_escape(id),
    );
    self.client.query(&query).execute().await?;
    Ok(())
}

pub async fn delete_announcement(
    &self,
    id: &str,
) -> anyhow::Result<()> {
    let query = format!(
        "ALTER TABLE ndr.announcements DELETE WHERE id = '{}' SETTINGS mutations_sync=1",
        sql_escape(id)
    );
    self.client.query(&query).execute().await?;
    Ok(())
}
    pub fn new() -> Self {
        let cfg = provigil_common::clickhouse::ClickHouseConfig::from_env();
        Self { client: cfg.build_client() }
    }

    pub async fn health_check(&self) -> bool {
        self.client
            .query("SELECT 1")
            .fetch_one::<u8>()
            .await
            .is_ok()
    }

    pub async fn init_tables(&self) {
    let install_dir = std::env::var("INSTALL_DIR")
        .unwrap_or_else(|_| ".".to_string());
    
    // Try Docker path first, then local path
    let paths = vec![
        "/app/config/clickhouse/init.sql".to_string(),
        format!("{}/config/clickhouse/init.sql", install_dir),
        "./config/clickhouse/init.sql".to_string(),
    ];
    
    for sql_path in &paths {
        if let Ok(sql) = std::fs::read_to_string(sql_path) {
           for stmt in sql.split(';') {
    let stmt = stmt.trim()
        .lines()
        .filter(|l| !l.trim().starts_with("--"))
        .collect::<Vec<_>>()
        .join("\n")
        .trim()
        .to_string();
    if stmt.is_empty() { continue; }
    // Skip INSERT statements — initial data is seeded by install.sh.
    // Running INSERTs here would create duplicate rows on every engine restart.
    if stmt.trim_start().to_uppercase().starts_with("INSERT") { continue; }
    if let Err(e) = self.client
        .query(&stmt)
        .execute()
        .await {
        tracing::debug!(
            "SQL init stmt skipped: {}", e
        );
    }
}
            tracing::info!(
                "✅ ClickHouse tables initialized from {}", 
                sql_path
            );
            
            let announcements_table = "
                CREATE TABLE IF NOT EXISTS ndr.announcements
                (
                    id             String,
                    title          String,
                    message        String,
                    announcement_type String DEFAULT 'info',
                    audience       String DEFAULT 'all',
                    status         String DEFAULT 'draft',
                    target_roles   Array(String),
                    target_tenants Array(String),
                    start_at       DateTime DEFAULT now(),
                    end_at         Nullable(DateTime),
                    created_by     String,
                    created_at     DateTime DEFAULT now(),
                    updated_at     DateTime DEFAULT now()
                )
                ENGINE = ReplacingMergeTree(updated_at)
                ORDER BY id
            ";
            if let Err(e) = self.client
                .query(announcements_table)
                .execute()
                .await {
                tracing::debug!("Announcements table init skipped: {}", e);
            }

            let announcement_reads_table = "
                CREATE TABLE IF NOT EXISTS ndr.announcement_reads
                (
                    announcement_id String,
                    username        String,
                    read_at         DateTime DEFAULT now()
                )
                ENGINE = ReplacingMergeTree(read_at)
                ORDER BY (announcement_id, username)
            ";
            if let Err(e) = self.client
                .query(announcement_reads_table)
                .execute()
                .await {
                tracing::debug!("Announcement reads table init skipped: {}", e);
            }

            // Ensure tenant_id columns exist
            for alter in &[
                "ALTER TABLE ndr.ndr_events ADD COLUMN IF NOT EXISTS tenant_id String DEFAULT 'default'",
                "ALTER TABLE ndr.ndr_hits ADD COLUMN IF NOT EXISTS tenant_id String DEFAULT 'default'",
                "ALTER TABLE ndr.ndr_hits ADD COLUMN IF NOT EXISTS correlation_status String DEFAULT 'agent_z_only'",
                "ALTER TABLE ndr.ndr_hits ADD COLUMN IF NOT EXISTS agent_z_details String DEFAULT '{}'",
                "ALTER TABLE ndr.ndr_hits ADD COLUMN IF NOT EXISTS agent_s_details String DEFAULT '{}'",
                "ALTER TABLE ndr.ndr_hits ADD COLUMN IF NOT EXISTS corroborated_at DateTime DEFAULT toDateTime(0)",
                "ALTER TABLE ndr.ndr_hits ADD COLUMN IF NOT EXISTS agent_s_rule_id String DEFAULT ''",
                "ALTER TABLE ndr.ndr_hits ADD COLUMN IF NOT EXISTS agent_s_category String DEFAULT ''",
                "ALTER TABLE ndr.ndr_hits ADD COLUMN IF NOT EXISTS updated_at DateTime DEFAULT now()",
                "ALTER TABLE ndr.ndr_hits ADD COLUMN IF NOT EXISTS sensor_id String DEFAULT ''",
                "ALTER TABLE ndr.ndr_events ADD COLUMN IF NOT EXISTS sensor_id String DEFAULT ''",
                "CREATE TABLE IF NOT EXISTS ndr.user_sensor_assignments (user_id String, sensor_id String, tenant_id String, created_at DateTime DEFAULT now()) ENGINE = ReplacingMergeTree(created_at) ORDER BY (tenant_id, user_id, sensor_id)",
                "ALTER TABLE ndr.soar_integrations ADD COLUMN IF NOT EXISTS tenant_id String DEFAULT 'default'",
                "ALTER TABLE ndr.soar_playbooks ADD COLUMN IF NOT EXISTS tenant_id String DEFAULT 'default'",
                "ALTER TABLE ndr.soar_config ADD COLUMN IF NOT EXISTS tenant_id String DEFAULT 'default'",
                "ALTER TABLE ndr.rules_state ADD COLUMN IF NOT EXISTS tenant_id String DEFAULT 'default'",
                "ALTER TABLE ndr.sigma_rules ADD COLUMN IF NOT EXISTS tenant_id String DEFAULT 'default'",
                "ALTER TABLE ndr.sigma_rules ADD COLUMN IF NOT EXISTS source String DEFAULT 'custom'",
                "ALTER TABLE ndr.users ADD COLUMN IF NOT EXISTS permissions String DEFAULT 'dashboard,alerts'",
                "ALTER TABLE ndr.users ADD COLUMN IF NOT EXISTS active UInt8 DEFAULT 1",
                "ALTER TABLE ndr.tenants ADD COLUMN IF NOT EXISTS updated_at DateTime DEFAULT now()",
                "ALTER TABLE ndr.tenants ADD COLUMN IF NOT EXISTS features String DEFAULT 'ndr,ai'",
                "ALTER TABLE ndr.sensor_keys ADD COLUMN IF NOT EXISTS hostname String DEFAULT ''",
                "ALTER TABLE ndr.sensor_keys ADD COLUMN IF NOT EXISTS interface_name String DEFAULT ''",
                "ALTER TABLE ndr.sensor_keys ADD COLUMN IF NOT EXISTS os_name String DEFAULT ''",
                "ALTER TABLE ndr.sensor_keys ADD COLUMN IF NOT EXISTS agent_z_status String DEFAULT 'unknown'",
                "ALTER TABLE ndr.sensor_keys ADD COLUMN IF NOT EXISTS agent_s_status String DEFAULT 'unknown'",
                "ALTER TABLE ndr.sensor_keys ADD COLUMN IF NOT EXISTS vector_status String DEFAULT 'unknown'",
                "ALTER TABLE ndr.sensor_commands ADD COLUMN IF NOT EXISTS sensor_id String DEFAULT ''",
                "ALTER TABLE ndr.announcements ADD COLUMN IF NOT EXISTS announcement_type String DEFAULT 'info'",
                "ALTER TABLE ndr.announcements ADD COLUMN IF NOT EXISTS audience String DEFAULT 'all'",
                "ALTER TABLE ndr.announcements ADD COLUMN IF NOT EXISTS target_tenants Array(String) DEFAULT []",
                "CREATE TABLE IF NOT EXISTS ndr.ndr_baselines (tenant_id String, src_ip String, metric String, value_f Float64 DEFAULT 0, value_s String DEFAULT '', window_ts DateTime, updated_at DateTime DEFAULT now()) ENGINE = ReplacingMergeTree(updated_at) ORDER BY (tenant_id, src_ip, metric, window_ts) TTL window_ts + INTERVAL 35 DAY",
                "ALTER TABLE ndr.ndr_events ADD INDEX IF NOT EXISTS idx_sensor_id sensor_id TYPE bloom_filter GRANULARITY 1",
                "ALTER TABLE ndr.ndr_events ADD PROJECTION IF NOT EXISTS proj_by_sensor (SELECT * ORDER BY (tenant_id, sensor_id, timestamp))",
                "ALTER TABLE ndr.ndr_hits MODIFY SETTING deduplicate_merge_projection_mode = 'rebuild'",
                "ALTER TABLE ndr.ndr_hits ADD INDEX IF NOT EXISTS idx_sensor_id sensor_id TYPE bloom_filter GRANULARITY 1",
                "ALTER TABLE ndr.ndr_hits ADD PROJECTION IF NOT EXISTS proj_by_sensor (SELECT * ORDER BY (tenant_id, sensor_id, timestamp))",
                "ALTER TABLE ndr.ai_suppressions ADD COLUMN IF NOT EXISTS expires_at Nullable(DateTime) DEFAULT NULL",
                "ALTER TABLE ndr.ai_suppressions ADD COLUMN IF NOT EXISTS suppress_scope String DEFAULT 'individual'",
                "CREATE TABLE IF NOT EXISTS ndr.doh_providers \
                 (ip String, provider_name String DEFAULT '', enabled UInt8 DEFAULT 1, \
                  created_at DateTime DEFAULT now()) \
                 ENGINE = ReplacingMergeTree(created_at) ORDER BY ip",
                "ALTER TABLE ndr.users ADD COLUMN IF NOT EXISTS gmail String DEFAULT ''",
                "ALTER TABLE ndr.users ADD COLUMN IF NOT EXISTS secret_code String DEFAULT ''",
                "ALTER TABLE ndr.soar_cases ADD COLUMN IF NOT EXISTS case_number String DEFAULT ''",
                "ALTER TABLE ndr.soar_cases ADD COLUMN IF NOT EXISTS priority String DEFAULT 'P2'",
                "CREATE TABLE IF NOT EXISTS ndr.retro_scans (id String, rule_id String DEFAULT '', rule_name String DEFAULT '', rule_content String DEFAULT '', hours_back UInt32 DEFAULT 24, status String DEFAULT 'pending', started_at UInt32 DEFAULT 0, completed_at UInt32 DEFAULT 0, match_count UInt64 DEFAULT 0, matches String DEFAULT '[]', tenant_id String DEFAULT 'default', updated_at UInt32 DEFAULT 0) ENGINE = ReplacingMergeTree(updated_at) ORDER BY (tenant_id, id)",
                "CREATE TABLE IF NOT EXISTS ndr.client_errors (id String DEFAULT generateUUIDv4(), message String, stack String DEFAULT '', url String DEFAULT '', username String DEFAULT '', tenant_id String DEFAULT '', user_agent String DEFAULT '', occurred_at DateTime DEFAULT now()) ENGINE = MergeTree() ORDER BY occurred_at TTL occurred_at + INTERVAL 30 DAY",
            ] {
                if let Err(e) = self.client
                    .query(alter)
                    .execute().await {
                    tracing::debug!("Column add skipped: {}", e);
                }
            }
            tracing::info!("✅ tenant_id columns verified");

            // --- AUTO-MIGRATE EXISTING TENANTS ---
            if let Ok(sql) = std::fs::read_to_string(sql_path) {
                if let Ok(tenant_ids) = self.get_all_tenants().await {
                    for tenant_id in tenant_ids {
                        if tenant_id == "default" { continue; }
                        let db_name = format!("ndr_{}", tenant_id.replace("-", "_"));
                        tracing::info!("Auto-migrating tenant DB: {}", db_name);

                        for stmt in sql.split(';') {
                            let stmt = stmt.trim()
                                .lines()
                                .filter(|l| !l.trim().starts_with("--"))
                                .collect::<Vec<_>>()
                                .join("\n")
                                .trim()
                                .to_string();

                            if stmt.is_empty() { continue; }
                            if stmt.contains("CREATE DATABASE IF NOT EXISTS ndr")
                                || stmt.contains("ndr.users")
                                || stmt.contains("ndr.tenants")
                                || stmt.contains("ndr.announcements")
                                || stmt.contains("ndr.announcement_reads")
                                || stmt.contains("ndr.rules_state")
                            {
                                continue;
                            }

                            if stmt.trim_start().to_uppercase().starts_with("INSERT") { continue; }

                            let mut tenant_stmt = stmt.replace("ndr.", &format!("{}.", db_name));
                            tenant_stmt = tenant_stmt.replace(
                                "/clickhouse/tables/{shard}/ndr/",
                                &format!("/clickhouse/tables/{{shard}}/{}/", db_name),
                            );
                            tenant_stmt = tenant_stmt.replace("DEFAULT 'default'", &format!("DEFAULT '{}'", tenant_id));

                            if let Err(e) = self.client.query(&tenant_stmt).execute().await {
                                tracing::debug!("Auto-migrate statement skipped for {}: {}", db_name, e);
                            }
                        }
                        // CREATE TABLE IF NOT EXISTS above does nothing for tables that already exist,
                        // so columns added to init.sql later never reached existing tenants.
                        self.migrate_tenant_columns(&db_name).await;
                    }
                }
            }
            // -------------------------------------

            return;
        }
    }
    tracing::warn!("init.sql not found!");
}





    /// Adds the columns in TENANT_COLUMN_MIGRATIONS to one tenant database (idempotent).
    pub async fn migrate_tenant_columns(&self, db_name: &str) {
        for template in TENANT_COLUMN_MIGRATIONS {
            let stmt = template.replace("{db}", db_name);
            if let Err(e) = self.client.query(&stmt).execute().await {
                tracing::warn!("Tenant column migration failed for {}: {} ({})", db_name, stmt, e);
            }
        }
    }

    pub async fn get_threat_intel_hits_by_tenant(&self, tenant_id: &str, sensor_ids: &[String]) -> anyhow::Result<Vec<serde_json::Value>> {
    let db_name = tenant_db(tenant_id);
    let sf = Self::sensor_filter(sensor_ids);
    let query = format!("
        SELECT
            src_ip,
            dst_ip,
            count() as hits,
            max(timestamp) as last_seen
        FROM {}.ndr_hits
        WHERE threat_intel = 1{}
        GROUP BY src_ip, dst_ip
        ORDER BY hits DESC
        LIMIT 50
    ", db_name, sf);
    let hits = self.client.query(&query)
        .fetch_all::<ThreatIntelHit>()
        .await
        .unwrap_or_default();

    Ok(hits.iter().map(|h| serde_json::json!({
        "src_ip":    h.src_ip,
        "dst_ip":    h.dst_ip,
        "hits":      h.hits,
        "last_seen": h.last_seen,
    })).collect())
}

pub async fn get_threat_intel_hits(&self) -> anyhow::Result<Vec<serde_json::Value>> {
    self.get_threat_intel_hits_by_tenant("default", &[]).await
}

    // ── Insert methods ────────────────────────────────────────────────────

    pub async fn insert_event(&self, event: NdrEvent) -> anyhow::Result<()> {
        let mut insert = self.client.insert("ndr_events")?;
        insert.write(&event).await?;
        insert.end().await?;
        Ok(())
    }

    pub async fn insert_event_for_tenant(&self, event: NdrEvent, tenant_id: &str) -> anyhow::Result<()> {
        let db_name = tenant_db(tenant_id);
        let table_name = format!("{}.ndr_events", db_name);
        let mut insert = self.client.insert(&table_name)?;
        insert.write(&event).await?;
        insert.end().await?;
        Ok(())
    }

    pub async fn batch_insert_events_for_tenant(&self, events: Vec<NdrEvent>, tenant_id: &str) -> anyhow::Result<()> {
        if events.is_empty() { return Ok(()); }
        let db_name = tenant_db(tenant_id);
        let table_name = format!("{}.ndr_events", db_name);
        let mut insert = self.client.insert(&table_name)?;
        for event in &events {
            insert.write(event).await?;
        }
        insert.end().await?;
        Ok(())
    }

    pub async fn insert_hit(&self, hit: NdrHit) -> anyhow::Result<()> {
        let mut insert = self.client.insert("ndr_hits")?;
        insert.write(&hit).await?;
        insert.end().await?;
        Ok(())
    }

    pub async fn insert_hit_for_tenant(&self, hit: NdrHit, tenant_id: &str) -> anyhow::Result<()> {
        // Gate 1: drop suppressed hits before they reach the DB.
        // CRITICAL hits (score ≥ 90) bypass suppression — a real threat is never hidden.
        if hit.score < 90.0 {
            // Load ALL active group suppressions for this src_ip in one query, then
            // check every tag in memory. Replaces the previous N+1 pattern (1 query
            // per tag) which issued up to 11 round-trips for a hit with 10 Sigma rules.
            let suppressed = self.get_active_group_suppressions(tenant_id, &hit.src_ip).await;
            if !suppressed.is_empty() {
                let primary = hit.tags.first().map(String::as_str).unwrap_or("");
                if suppressed.contains(primary)
                    || hit.sigma_hits.iter().any(|r| suppressed.contains(r.as_str()))
                {
                    return Ok(());
                }
            }
        }
        let db_name = tenant_db(tenant_id);
        let table_name = format!("{}.ndr_hits", db_name);
        let mut insert = self.client.insert(&table_name)?;
        insert.write(&hit).await?;
        insert.end().await?;
        Ok(())
    }

    /// Enrich an existing zeek-only hit with Suricata data.
    /// Inserts a new row with correlation_status='corroborated' and a newer updated_at.
    /// ReplacingMergeTree keeps the newer row, deduplicating the original zeek-only row.
    pub async fn enrich_hit_with_suricata(
        &self,
        tenant_id:        &str,
        community_id:     &str,
        src_ip:           &str,
        dst_ip:           &str,
        combined_score:   f32,
        severity:         &str,
        tags:             Vec<String>,
        sigma_hits:       Vec<String>,
        threat_intel:     u8,
        src_country:      &str,
        dst_country:      &str,
        agent_z_details:  &str,
        agent_s_details:  &str,
        agent_s_rule_id:  &str,
        agent_s_category: &str,
    ) -> anyhow::Result<()> {
        let now = chrono::Utc::now().timestamp() as u32;
        let hit = NdrHit {
            timestamp:          now,
            community_id:       community_id.to_string(),
            src_ip:             src_ip.to_string(),
            dst_ip:             dst_ip.to_string(),
            score:              combined_score,
            severity:           severity.to_string(),
            tags,
            sigma_hits,
            threat_intel,
            src_country:        src_country.to_string(),
            dst_country:        dst_country.to_string(),
            tenant_id:          tenant_id.to_string(),
            correlation_status: "corroborated".to_string(),
            agent_z_details:    agent_z_details.to_string(),
            agent_s_details:    agent_s_details.to_string(),
            corroborated_at:    now,
            agent_s_rule_id:    agent_s_rule_id.to_string(),
            agent_s_category:   agent_s_category.to_string(),
            updated_at:         now,
            sensor_id:          String::new(),
        };
        self.insert_hit_for_tenant(hit, tenant_id).await
    }

    // ── Query methods ─────────────────────────────────────────────────────

    pub async fn get_stats(&self) -> anyhow::Result<serde_json::Value> {
        // Two queries replace six: countIf collapses all per-table stats into one pass each.
        let (events_total, events_1h, zeek_count, suricata_count) = self.client
            .query("SELECT count(), \
                    countIf(timestamp > now() - INTERVAL 1 HOUR), \
                    countIf(source = 'agent-z'), \
                    countIf(source = 'agent-s') \
                    FROM ndr_events")
            .fetch_one::<(u64, u64, u64, u64)>()
            .await
            .unwrap_or((0, 0, 0, 0));

        let (hits_total, hits_1h) = self.client
            .query("SELECT count(), \
                    countIf(timestamp > now() - INTERVAL 1 HOUR) \
                    FROM ndr_hits")
            .fetch_one::<(u64, u64)>()
            .await
            .unwrap_or((0, 0));

        Ok(serde_json::json!({
            "events_total":   events_total,
            "hits_total":     hits_total,
            "events_1h":      events_1h,
            "hits_1h":        hits_1h,
            "agent_z_events": zeek_count,
            "agent_s_events": suricata_count,
        }))
    }
    
    pub async fn set_rule_enabled(&self, id: &str, enabled: bool, tenant_id: &str) -> anyhow::Result<()> {
        self.client.query("INSERT INTO ndr.rules_state (id, enabled, tenant_id, updated) VALUES (?, ?, ?, now())")
            .bind(id)
            .bind(enabled as u8)
            .bind(tenant_id)
            .execute().await?;
        Ok(())
    }

    pub async fn get_disabled_rules(&self, tenant_id: &str) -> anyhow::Result<Vec<String>> {
        let ids = self.client
            .query(
                "SELECT id FROM ndr.rules_state
                 FINAL
                 WHERE enabled = 0 AND tenant_id = ?"
            )
            .bind(tenant_id)
            .fetch_all::<String>()
            .await
            .unwrap_or_default();
        Ok(ids)
    }

    // ── Sensor filter helper ─────────────────────────────────────────────────

    /// Returns SQL fragment " AND sensor_id IN ('a','b')" or "" if unrestricted.
    fn sensor_filter(sensor_ids: &[String]) -> String {
        if sensor_ids.is_empty() {
            String::new()
        } else {
            let list = sensor_ids.iter().map(|s| format!("'{}'", sql_escape(s))).collect::<Vec<_>>().join(",");
            format!(" AND sensor_id IN ({})", list)
        }
    }

    // ── Sensor assignment functions ───────────────────────────────────────────

    /// Real tenant owner of a user account, or None if it doesn't exist.
    /// Used to verify a tenant_admin isn't assigning sensor access to (or
    /// removing it from) a user outside their own tenant.
    pub async fn get_user_tenant(&self, user_id: &str) -> anyhow::Result<Option<String>> {
        let rows = self.client
            .query("SELECT tenant_id FROM ndr.users FINAL WHERE id = ? LIMIT 1")
            .bind(user_id)
            .fetch_all::<String>()
            .await?;
        Ok(rows.into_iter().next())
    }

    /// Real tenant owner of a sensor key (looked up by key_prefix, which is
    /// what SensorAssignment.sensor_id actually stores), or None if it
    /// doesn't exist. Same purpose as get_user_tenant() above.
    pub async fn get_sensor_key_tenant(&self, key_prefix: &str) -> anyhow::Result<Option<String>> {
        let rows = self.client
            .query("SELECT tenant_id FROM ndr.sensor_keys FINAL WHERE key_prefix = ? LIMIT 1")
            .bind(key_prefix)
            .fetch_all::<String>()
            .await?;
        Ok(rows.into_iter().next())
    }

    /// Persists a real frontend error report so it's queryable later
    /// instead of vanishing in a browser console nobody is watching.
    pub async fn insert_client_error(
        &self, message: &str, stack: &str, url: &str, username: &str, tenant_id: &str, user_agent: &str,
    ) -> anyhow::Result<()> {
        self.client
            .query("INSERT INTO ndr.client_errors (message, stack, url, username, tenant_id, user_agent) VALUES (?, ?, ?, ?, ?, ?)")
            .bind(message)
            .bind(stack)
            .bind(url)
            .bind(username)
            .bind(tenant_id)
            .bind(user_agent)
            .execute().await?;
        Ok(())
    }

    /// Most recent captured frontend errors — read path for insert_client_error,
    /// so reports land somewhere a human can actually see them instead of just
    /// aging out silently after the table's 30-day TTL.
    pub async fn list_client_errors(&self, limit: u32) -> anyhow::Result<Vec<serde_json::Value>> {
        #[derive(clickhouse::Row, serde::Deserialize)]
        struct Row {
            id: String, message: String, stack: String, url: String,
            username: String, tenant_id: String, user_agent: String,
            occurred_at: String,
        }
        let rows = self.client
            .query(
                "SELECT id, message, stack, url, username, tenant_id, user_agent, \
                 toString(occurred_at) AS occurred_at \
                 FROM ndr.client_errors ORDER BY occurred_at DESC LIMIT ?"
            )
            .bind(limit.min(500))
            .fetch_all::<Row>()
            .await?;
        Ok(rows.into_iter().map(|r| json!({
            "id": r.id, "message": r.message, "stack": r.stack, "url": r.url,
            "username": r.username, "tenant_id": r.tenant_id,
            "user_agent": r.user_agent, "occurred_at": r.occurred_at,
        })).collect())
    }

    pub async fn assign_sensor_to_user(&self, user_id: &str, sensor_id: &str, tenant_id: &str) -> anyhow::Result<()> {
        self.client
            .query("INSERT INTO ndr.user_sensor_assignments (user_id, sensor_id, tenant_id, created_at) VALUES (?, ?, ?, now())")
            .bind(user_id)
            .bind(sensor_id)
            .bind(tenant_id)
            .execute().await?;
        Ok(())
    }

    pub async fn remove_sensor_assignment(&self, user_id: &str, sensor_id: &str, tenant_id: &str) -> anyhow::Result<()> {
        // mutations_sync=1: block until applied, so the API's "removed" response
        // is only sent once a follow-up list call would actually reflect it
        // (found via TC-065: the async default left a brief window where a
        // freshly "removed" assignment still showed up).
        self.client
            .query("ALTER TABLE ndr.user_sensor_assignments DELETE WHERE user_id = ? AND sensor_id = ? AND tenant_id = ? SETTINGS mutations_sync=1")
            .bind(user_id)
            .bind(sensor_id)
            .bind(tenant_id)
            .execute().await?;
        Ok(())
    }

    /// All assignments for a tenant — returns (user_id, sensor_id) pairs.
    pub async fn get_sensor_assignments(&self, tenant_id: &str) -> anyhow::Result<Vec<(String, String)>> {
        let rows = self.client
            .query("SELECT user_id, sensor_id FROM ndr.user_sensor_assignments FINAL WHERE tenant_id = ?")
            .bind(tenant_id)
            .fetch_all::<(String, String)>()
            .await
            .unwrap_or_default();
        Ok(rows)
    }

    /// Sensor IDs assigned to a specific user. Empty = no restriction (sees all).
    pub async fn get_user_sensor_ids(&self, user_id: &str, tenant_id: &str) -> anyhow::Result<Vec<String>> {
        let rows = self.client
            .query("SELECT sensor_id FROM ndr.user_sensor_assignments FINAL WHERE user_id = ? AND tenant_id = ?")
            .bind(user_id)
            .bind(tenant_id)
            .fetch_all::<String>()
            .await
            .unwrap_or_default();
        Ok(rows)
    }

    /// Returns all per-tenant disabled overrides from rules_state.
    /// Key = tenant_id, Value = set of rule IDs that tenant has disabled.
    /// Used by DetectionEngine to skip community rules a tenant has disabled.
    pub async fn get_all_disabled_overrides(
        &self,
    ) -> anyhow::Result<std::collections::HashMap<String, std::collections::HashSet<String>>> {
        #[derive(clickhouse::Row, serde::Deserialize)]
        struct OverrideRow { id: String, tenant_id: String }
        let rows = self.client
            .query("SELECT id, tenant_id FROM ndr.rules_state FINAL WHERE enabled = 0")
            .fetch_all::<OverrideRow>()
            .await
            .unwrap_or_default();
        let mut out: std::collections::HashMap<String, std::collections::HashSet<String>> =
            std::collections::HashMap::new();
        for row in rows {
            out.entry(row.tenant_id).or_default().insert(row.id);
        }
        Ok(out)
    }

    pub async fn delete_rule_state(&self, id: &str, tenant_id: &str) -> anyhow::Result<()> {
        self.client
            .query("ALTER TABLE ndr.rules_state DELETE WHERE id = ? AND tenant_id = ? SETTINGS mutations_sync=1")
            .bind(id)
            .bind(tenant_id)
            .execute()
            .await?;
        Ok(())
    }
    pub async fn get_sigma_rules(&self, tenant_id: &str) -> anyhow::Result<Vec<(String, String)>> {
        let db = tenant_db(tenant_id);
        let result = self.client
            .query(&format!("SELECT id, content FROM {}.sigma_rules FINAL WHERE enabled = 1", db))
            .fetch_all::<(String, String)>()
            .await?;
        Ok(result)
    }

    /// Returns (id, content, tenant_id) for all enabled rules across all active tenants.
    pub async fn get_all_enabled_sigma_rules(&self) -> anyhow::Result<Vec<(String, String, String)>> {
        let mut all: Vec<(String, String, String)> = Vec::new();

        // Community rules (global, tenant_id='*') always come from ndr.sigma_rules
        let community: Vec<(String, String)> = self.client
            .query("SELECT id, content FROM ndr.sigma_rules FINAL WHERE tenant_id='*' AND enabled=1")
            .fetch_all::<(String, String)>()
            .await
            .unwrap_or_default();
        for (id, content) in community {
            all.push((id, content, "*".to_string()));
        }

        // Per-tenant custom rules
        let tenant_ids: Vec<String> = {
            let mut ids: Vec<String> = self.client
                .query("SELECT id FROM ndr.tenants FINAL WHERE active = 1")
                .fetch_all::<String>()
                .await
                .unwrap_or_default();
            ids.push("default".to_string());
            let mut seen = std::collections::HashSet::new();
            ids.retain(|id| seen.insert(id.clone()));
            ids
        };

        for tid in &tenant_ids {
            let db = tenant_db(tid);
            let rows: Vec<(String, String)> = self.client
                .query(&format!(
                    "SELECT id, content FROM {}.sigma_rules FINAL WHERE enabled=1 AND tenant_id != '*'",
                    db
                ))
                .fetch_all::<(String, String)>()
                .await
                .unwrap_or_default();
            for (id, content) in rows {
                all.push((id, content, tid.clone()));
            }
        }

        Ok(all)
    }

    /// Insert or update a community rule in the global ndr.sigma_rules table.
    /// Returns the set of all community rule IDs already in the DB.
    /// Used by the updater to skip re-inserting existing rules (preserves enabled/disabled state).
    pub async fn get_community_rule_ids(&self) -> anyhow::Result<std::collections::HashSet<String>> {
        #[derive(clickhouse::Row, serde::Deserialize)]
        struct IdRow { id: String }
        let rows = self.client
            .query("SELECT DISTINCT id FROM ndr.sigma_rules FINAL WHERE source='community'")
            .fetch_all::<IdRow>()
            .await
            .unwrap_or_default();
        Ok(rows.into_iter().map(|r| r.id).collect())
    }

    /// Community rules have tenant_id='*' and source='community'.
    /// ReplacingMergeTree deduplicates on id — re-inserting updates the content.
    pub async fn save_community_rule(&self, id: &str, name: &str, content: &str) -> anyhow::Result<()> {
        self.client
            .query("INSERT INTO ndr.sigma_rules (id, name, content, tenant_id, source, enabled, created_at, updated_at) VALUES (?, ?, ?, '*', 'community', 1, now(), now())")
            .bind(id)
            .bind(name)
            .bind(content)
            .execute()
            .await?;
        Ok(())
    }

    /// Permanently remove a community rule from the DB (used by startup blocklist cleanup).
    pub async fn delete_community_rule(&self, id: &str) -> anyhow::Result<()> {
        // ReplacingMergeTree doesn't support DELETE natively — disable it instead.
        // The engine will skip disabled rules; the updater blocklist prevents re-import.
        self.client
            .query("INSERT INTO ndr.sigma_rules (id, name, content, tenant_id, source, enabled, updated_at) \
                    SELECT id, name, content, tenant_id, source, 0, now() \
                    FROM ndr.sigma_rules FINAL WHERE id = ? LIMIT 1")
            .bind(id)
            .execute().await?;
        Ok(())
    }

    pub async fn save_sigma_rule(&self, id: &str, name: &str, content: &str, tenant_id: &str) -> anyhow::Result<()> {
        let db = tenant_db(tenant_id);
        self.client
            .query(&format!("INSERT INTO {}.sigma_rules (id, name, content, tenant_id, enabled, created_at, updated_at) VALUES (?, ?, ?, ?, 1, now(), now())", db))
            .bind(id)
            .bind(name)
            .bind(content)
            .bind(tenant_id)
            .execute()
            .await?;
        Ok(())
    }

    pub async fn delete_sigma_rule(&self, id: &str, tenant_id: &str) -> anyhow::Result<()> {
        let db = tenant_db(tenant_id);
        self.client
            .query(&format!("ALTER TABLE {}.sigma_rules DELETE WHERE id = ? SETTINGS mutations_sync=1", db))
            .bind(id)
            .execute()
            .await?;
        Ok(())
    }

    /// Returns `true` if the rule is a community rule (tenant_id='*'), `false` if custom.
    /// Bug 5 fix: caller uses the return value to decide whether to also write rules_state,
    /// avoiding a redundant dual-write for custom rules.
    pub async fn toggle_sigma_rule(&self, id: &str, enabled: bool, tenant_id: &str) -> anyhow::Result<bool> {
        let is_community = self.client
            .query("SELECT count() FROM ndr.sigma_rules FINAL WHERE id = ? AND tenant_id = '*'")
            .bind(id)
            .fetch_one::<u64>()
            .await
            .unwrap_or(0) > 0;

        if is_community {
            return Ok(true);
        }

        // Custom rule — update enabled flag directly in the tenant's sigma_rules table.
        let db = tenant_db(tenant_id);
        let query = format!(
            "INSERT INTO {db}.sigma_rules (id, name, content, tenant_id, enabled, updated_at) \
             SELECT id, name, content, tenant_id, ?, now() FROM {db}.sigma_rules FINAL WHERE id = ?"
        );
        self.client.query(&query).bind(enabled as u8).bind(id).execute().await?;
        Ok(false)
    }

    pub async fn get_sigma_rule_by_id(&self, id: &str, tenant_id: &str) -> anyhow::Result<Option<(String, String, String, String, u8)>> {
        let db = tenant_db(tenant_id);
        let result = self.client
            .query(&format!("SELECT id, name, content, tenant_id, enabled FROM {}.sigma_rules FINAL WHERE id = ? LIMIT 1", db))
            .bind(id)
            .fetch_all::<(String, String, String, String, u8)>()
            .await?;
        Ok(result.first().cloned())
    }

    /// Returns all rules visible to a tenant: community rules (tenant_id='*') + their custom rules.
    /// Returns (id, name, content, tenant_id, enabled, source).
    pub async fn get_all_sigma_rules(&self, tenant_id: &str) -> anyhow::Result<Vec<(String, String, String, String, u8, String)>> {
        let mut result: Vec<(String, String, String, String, u8, String)> = Vec::new();

        // Community rules — always from ndr.sigma_rules where tenant_id='*'
        let community = self.client
            .query("SELECT id, name, content, tenant_id, enabled FROM ndr.sigma_rules FINAL WHERE tenant_id='*'")
            .fetch_all::<(String, String, String, String, u8)>()
            .await
            .unwrap_or_default();
        for (id, name, content, tid, enabled) in community {
            result.push((id, name, content, tid, enabled, "community".to_string()));
        }

        // Tenant custom rules
        let db = tenant_db(tenant_id);
        let custom = self.client
            .query(&format!("SELECT id, name, content, tenant_id, enabled FROM {}.sigma_rules FINAL WHERE tenant_id != '*'", db))
            .fetch_all::<(String, String, String, String, u8)>()
            .await
            .unwrap_or_default();
        for (id, name, content, tid, enabled) in custom {
            result.push((id, name, content, tid, enabled, "custom".to_string()));
        }

        Ok(result)
    }

//soar integrations

pub async fn get_integrations_by_tenant(
    &self, tenant_id: &str
) -> anyhow::Result<Vec<serde_json::Value>> {
    let db = tenant_db(tenant_id);
    let query = format!("
        SELECT id, name, type, config, enabled
        FROM {}.soar_integrations
        FINAL
        ORDER BY created_at
    ", db);
    let result = self.client
        .query(&query)
        .fetch_all::<(String,String,String,String,u8)>()
        .await?;
    Ok(result.iter().map(|r| {
        let config: serde_json::Value =
            serde_json::from_str(&r.3)
                .unwrap_or(serde_json::json!({}));
        serde_json::json!({
            "id":      r.0,
            "name":    r.1,
            "type":    r.2,
            "config":  config,
            "enabled": r.4 == 1
        })
    }).collect())
}

pub async fn get_integrations(&self) -> anyhow::Result<Vec<serde_json::Value>> {
    self.get_integrations_by_tenant("default").await
}

pub async fn save_integration(
    &self,
    id: &str,
    name: &str,
    int_type: &str,
    config: &str,
    tenant_id: &str,
) -> anyhow::Result<()> {
    let db = tenant_db(tenant_id);
    let query = format!(
        "INSERT INTO {}.soar_integrations \
         (id, name, type, config, enabled, tenant_id) \
         VALUES ('{}','{}','{}','{}',1,'{}')",
        db, sql_escape(id), sql_escape(name), sql_escape(int_type),
        sql_escape(config), sql_escape(tenant_id)
    );
    self.client.query(&query).execute().await?;
    Ok(())
}

pub async fn toggle_integration(
    &self, id: &str, enabled: bool, tenant_id: &str
) -> anyhow::Result<()> {
    let db = tenant_db(tenant_id);
    let query = format!(
        "INSERT INTO {}.soar_integrations \
         (id, name, type, config, enabled, tenant_id) \
         SELECT id, name, type, config, {}, tenant_id \
         FROM {}.soar_integrations \
         WHERE id = '{}'",
        db, if enabled { 1 } else { 0 }, db, sql_escape(id)
    );
    self.client.query(&query).execute().await?;
    Ok(())
}

pub async fn delete_integration(
    &self, id: &str, tenant_id: &str
) -> anyhow::Result<()> {
    let db = tenant_db(tenant_id);
    let query = format!(
        "ALTER TABLE {}.soar_integrations \
         DELETE WHERE id = '{}'",
        db, sql_escape(id)
    );
    self.client.query(&query).execute().await?;
    Ok(())
}

pub async fn update_integration(
    &self,
    id: &str,
    name: &str,
    int_type: &str,
    config: &str,
    tenant_id: &str,
) -> anyhow::Result<()> {
    let db = tenant_db(tenant_id);
    // Re-INSERT with same id — ReplacingMergeTree will deduplicate on next merge.
    // We preserve the existing enabled flag by SELECTing it from the current row.
    let query = format!(
        "INSERT INTO {}.soar_integrations \
         (id, name, type, config, enabled, tenant_id) \
         SELECT '{}', '{}', '{}', '{}', enabled, '{}' \
         FROM {}.soar_integrations \
         WHERE id = '{}' \
         LIMIT 1",
        db,
        sql_escape(id),
        sql_escape(name),
        sql_escape(int_type),
        sql_escape(config),
        sql_escape(tenant_id),
        db,
        sql_escape(id)
    );
    self.client.query(&query).execute().await?;
    Ok(())
}


//save soar config
#[cfg(feature = "soar")]
pub async fn save_soar_config_by_tenant(
    &self, key: &str, value: &str, tenant_id: &str
) -> anyhow::Result<()> {
    let db = tenant_db(tenant_id);
    let query = format!(
        "INSERT INTO {}.soar_config (key, value, tenant_id) \
         VALUES ('{}', '{}', '{}')",
        db, sql_escape(key), sql_escape(value), sql_escape(tenant_id)
    );
    self.client.query(&query).execute().await?;
    Ok(())
}

#[cfg(feature = "soar")]
pub async fn save_soar_config(&self, key: &str, value: &str) -> anyhow::Result<()> {
    self.save_soar_config_by_tenant(key, value, "default").await
}


//get soar config
#[cfg(feature = "soar")]
pub async fn get_soar_config_by_tenant(
    &self, tenant_id: &str
) -> anyhow::Result<serde_json::Value> {
    let db = tenant_db(tenant_id);
    let query = format!("
        SELECT key, value
        FROM {}.soar_config
        FINAL
        ORDER BY key
    ", db);
    let result = self.client
        .query(&query)
        .fetch_all::<(String, String)>()
        .await?;
    let mut map = serde_json::Map::new();
    for (key, val) in result {
        map.insert(key, serde_json::json!(val));
    }
    Ok(serde_json::Value::Object(map))
}

#[cfg(feature = "soar")]
pub async fn get_soar_config(&self) -> anyhow::Result<serde_json::Value> {
    self.get_soar_config_by_tenant("default").await
}


//soar playbooks
#[cfg(feature = "soar")]
pub async fn get_soar_playbooks_by_tenant(
    &self, tenant_id: &str
) -> anyhow::Result<Vec<serde_json::Value>> {
    let db = tenant_db(tenant_id);
    let query = format!("
        SELECT id, name, description,
               trigger, action_type,
               config, enabled, runs
        FROM {}.soar_playbooks
        FINAL
        ORDER BY created_at
    ", db);
    let result = self.client
        .query(&query)
        .fetch_all::<(
            String, String, String,
            String, String, String,
            u8, u64
        )>()
        .await?;
    Ok(result.iter().map(|r| serde_json::json!({
        "id":          r.0,
        "name":        r.1,
        "description": r.2,
        "trigger":     r.3,
        "action_type": r.4,
        "config":      r.5,
        "enabled":     r.6 == 1,
        "runs":        r.7
    })).collect())
}

#[cfg(feature = "soar")]
pub async fn get_soar_playbooks(&self) -> anyhow::Result<Vec<serde_json::Value>> {
    self.get_soar_playbooks_by_tenant("default").await
}

//enable/disable playbook
#[cfg(feature = "soar")]
pub async fn update_playbook_enabled(
    &self, id: &str, enabled: bool, tenant_id: &str
) -> anyhow::Result<()> {
    let db = tenant_db(tenant_id);
    let query = format!(
        "INSERT INTO {}.soar_playbooks \
         (id, name, description, trigger, \
          action_type, enabled, tenant_id) \
         SELECT id, name, description, trigger, \
                action_type, {}, tenant_id \
         FROM {}.soar_playbooks \
         WHERE id = '{}'",
        db, if enabled { 1 } else { 0 }, db, sql_escape(id)
    );
    self.client.query(&query).execute().await?;
    Ok(())
}

#[cfg(feature = "soar")]
pub async fn create_playbook(
    &self,
    id: &str,
    name: &str,
    description: &str,
    trigger: &str,
    action_type: &str,
    config: &str,
    tenant_id: &str,
) -> anyhow::Result<()> {
    let db = tenant_db(tenant_id);
    let query = format!(
        "INSERT INTO {}.soar_playbooks \
         (id, name, description, trigger, \
          action_type, config, enabled, tenant_id) \
         VALUES ('{}','{}','{}','{}','{}','{}',1,'{}')",
        db, sql_escape(id), sql_escape(name), sql_escape(description),
        sql_escape(trigger), sql_escape(action_type), sql_escape(config), sql_escape(tenant_id)
    );
    self.client.query(&query).execute().await?;
    Ok(())
}


//get settings

pub async fn get_settings_by_tenant(&self, tenant_id: &str) -> anyhow::Result<serde_json::Value> {
    let db = tenant_db(tenant_id);
    let query = format!("
        SELECT key, value
        FROM {}.settings
        FINAL
        ORDER BY key
    ", db);
    let result = self.client
        .query(&query)
        .fetch_all::<(String, String)>()
        .await?;
    let mut map = serde_json::Map::new();
    for (key, val) in result {
        if let Ok(n) = val.parse::<f64>() {
            map.insert(key, serde_json::json!(n));
        } else {
            map.insert(key, serde_json::json!(val));
        }
    }
    Ok(serde_json::Value::Object(map))
}

pub async fn get_settings(&self) -> anyhow::Result<serde_json::Value> {
    self.get_settings_by_tenant("default").await
}

/// Read a single global setting value by key. Returns None if not found.
pub async fn get_global_setting(&self, key: &str) -> Option<String> {
    self.client
        .query(&format!(
            "SELECT value FROM ndr.settings FINAL WHERE key = '{}' LIMIT 1",
            sql_escape(key)
        ))
        .fetch_one::<String>()
        .await
        .ok()
        .filter(|v| !v.is_empty())
}

pub async fn set_global_setting(&self, key: &str, value: &str) -> anyhow::Result<()> {
    self.client
        .query(&format!(
            "INSERT INTO ndr.settings (key, value, updated_at) VALUES ('{}', '{}', now())",
            sql_escape(key),
            sql_escape(value)
        ))
        .execute()
        .await
        .map_err(|e| anyhow::anyhow!("set_global_setting failed: {}", e))
}

/// Returns top dst IPs with high hit counts and zero threat_intel — ASN lookup done by caller.
pub async fn get_high_volume_clean_dst_ips(
    &self,
    tenant_id: &str,
    hours: u32,
    min_hits: u64,
) -> anyhow::Result<Vec<(String, u64)>> {
    let db = tenant_db(tenant_id);
    self.client
        .query(&format!(
            "SELECT dst_ip, count() as cnt
             FROM {db}.ndr_events
             WHERE timestamp > now() - INTERVAL {hours} HOUR
               AND source = 'agent-z'
               AND dst_ip != ''
               AND dst_ip NOT LIKE '10.%'
               AND dst_ip NOT LIKE '192.168.%'
               AND dst_ip NOT LIKE '172.16.%'
               AND dst_ip NOT LIKE '172.17.%'
               AND dst_ip NOT LIKE '172.18.%'
               AND dst_ip NOT LIKE '172.19.%'
               AND dst_ip NOT LIKE '172.2%.%'
               AND dst_ip NOT LIKE '172.3%.%'
               AND dst_ip NOT LIKE '127.%'
               AND dst_ip NOT IN (
                   SELECT DISTINCT src_ip FROM {db}.ndr_hits FINAL
                   WHERE timestamp > now() - INTERVAL {hours} HOUR
                   AND threat_intel = 1
               )
             GROUP BY dst_ip
             HAVING cnt >= {min_hits}
             ORDER BY cnt DESC
             LIMIT 100",
            db = db, hours = hours, min_hits = min_hits
        ))
        .fetch_all::<(String, u64)>()
        .await
        .map_err(|e| anyhow::anyhow!("{}", e))
}

/// Returns (src_ip, dst_ip, Vec<unix_timestamp_secs>) for pairs that have
/// >= min_conns connections in the last `hours` hours, excluding private→private
/// and excluding known-malicious dst IPs (threat_intel hits).
pub async fn get_entity_scores(
    &self,
    tenant_id: &str,
    limit:     u32,
) -> anyhow::Result<Vec<serde_json::Value>> {
    let db  = tenant_db(tenant_id);
    let tid = sql_escape(tenant_id);

    #[derive(clickhouse::Row, serde::Deserialize)]
    struct Row {
        src_ip:            String,
        accumulated_score: f64,
        alert_count:       u64,
        top_severity:      String,
        top_tags:          Vec<String>,
        last_seen:         u32,
    }

    let rows = self.client.query(&format!(
        "SELECT src_ip, accumulated_score, alert_count, top_severity, top_tags,
                toUnixTimestamp(last_seen) AS last_seen
         FROM {db}.entity_scores FINAL
         WHERE tenant_id = '{tid}'
         ORDER BY accumulated_score DESC
         LIMIT {limit}",
        db = db, tid = tid, limit = limit,
    )).fetch_all::<Row>().await?;

    Ok(rows.into_iter().map(|r| serde_json::json!({
        "src_ip":            r.src_ip,
        "accumulated_score": r.accumulated_score,
        "alert_count":       r.alert_count,
        "top_severity":      r.top_severity,
        "top_tags":          r.top_tags,
        "last_seen":         r.last_seen,
    })).collect())
}

pub async fn get_beacon_candidates(
    &self,
    tenant_id: &str,
    hours:     u32,
    min_conns: u64,
) -> anyhow::Result<Vec<(String, String, Vec<i64>)>> {
    let db = tenant_db(tenant_id);

    #[derive(clickhouse::Row, serde::Deserialize)]
    struct PairRow { src_ip: String, dst_ip: String, cnt: u64 }

    // Step 1: find (src, dst) pairs with enough connections
    let pairs = self.client.query(&format!(
        "SELECT src_ip, dst_ip, count() as cnt
         FROM {db}.ndr_events
         WHERE timestamp > now() - INTERVAL {hours} HOUR
           AND source = 'agent-z'
           AND src_ip != '' AND dst_ip != ''
           AND NOT (src_ip LIKE '10.%' AND dst_ip LIKE '10.%')
           AND NOT (src_ip LIKE '192.168.%' AND dst_ip LIKE '192.168.%')
           AND NOT (src_ip LIKE '172.%' AND dst_ip LIKE '172.%')
         GROUP BY src_ip, dst_ip
         HAVING cnt >= {min_conns}
         ORDER BY cnt DESC
         LIMIT 200",
        db = db, hours = hours, min_conns = min_conns
    )).fetch_all::<PairRow>().await.map_err(|e| anyhow::anyhow!("{}", e))?;

    if pairs.is_empty() { return Ok(vec![]); }

    // Bulk-fetch timestamps for all pairs in one query instead of N individual queries.
    // ClickHouse IN-tuple filter: (src_ip, dst_ip) IN ((a,b),(c,d),...)
    let tuple_list = pairs.iter()
        .map(|p| format!("('{}','{}')", sql_escape(&p.src_ip), sql_escape(&p.dst_ip)))
        .collect::<Vec<_>>()
        .join(",");

    #[derive(clickhouse::Row, serde::Deserialize)]
    struct TsRow { src_ip: String, dst_ip: String, ts: i64 }

    let all_ts = self.client.query(&format!(
        "SELECT src_ip, dst_ip, toUnixTimestamp(timestamp) AS ts
         FROM {db}.ndr_events
         WHERE timestamp > now() - INTERVAL {hours} HOUR
           AND source = 'agent-z'
           AND (src_ip, dst_ip) IN ({tuples})
         ORDER BY src_ip, dst_ip, timestamp ASC
         LIMIT 100000",
        db = db, hours = hours, tuples = tuple_list,
    )).fetch_all::<TsRow>().await.unwrap_or_default();

    // Group timestamps by (src_ip, dst_ip) in memory
    let mut ts_map: std::collections::HashMap<(String, String), Vec<i64>> =
        std::collections::HashMap::new();
    for r in all_ts {
        ts_map.entry((r.src_ip, r.dst_ip)).or_default().push(r.ts);
    }

    let result = pairs.into_iter()
        .filter_map(|p| {
            let key   = (p.src_ip.clone(), p.dst_ip.clone());
            let ts_vec = ts_map.remove(&key).unwrap_or_default();
            if ts_vec.len() >= min_conns as usize {
                Some((p.src_ip, p.dst_ip, ts_vec))
            } else {
                None
            }
        })
        .collect();
    Ok(result)
}

// ── AI Provider registry ───────────────────────────────────────────────────

fn _esc_ai(s: &str) -> String {
    s.replace('\\', "\\\\").replace('\'', "\\'")
}

/// Load enabled providers for a use_case ('threat'|'chat'), sorted by priority.
pub async fn get_ai_providers(&self, use_case: &str) -> anyhow::Result<Vec<crate::ai::provider::AiProvider>> {
    #[derive(clickhouse::Row, serde::Deserialize)]
    struct Row {
        name: String, provider_type: String, api_key: String,
        model: String, base_url: String, endpoint_path: String,
        msg_format: String, priority: u8,
    }
    let rows = self.client.query(&format!(
        "SELECT name, provider_type, api_key, model, base_url, endpoint_path, \
         msg_format, priority \
         FROM ndr.ai_providers FINAL \
         WHERE enabled = 1 AND (use_case = 'all' OR use_case = '{}') \
         ORDER BY priority ASC LIMIT 10",
        Self::_esc_ai(use_case)
    )).fetch_all::<Row>().await.unwrap_or_default();

    Ok(rows.into_iter().map(|r| crate::ai::provider::AiProvider {
        name: r.name, provider_type: r.provider_type, api_key: r.api_key,
        model: r.model, base_url: r.base_url, endpoint_path: r.endpoint_path,
        msg_format: r.msg_format, priority: r.priority,
    }).collect())
}

/// List all providers for the settings UI (api_key masked).
pub async fn list_ai_providers(&self) -> anyhow::Result<Vec<serde_json::Value>> {
    #[derive(clickhouse::Row, serde::Deserialize)]
    struct Row {
        name: String, provider_type: String, model: String,
        base_url: String, endpoint_path: String, msg_format: String,
        use_case: String, priority: u8, enabled: u8, key_set: u8,
    }
    let rows = self.client.query(
        "SELECT name, provider_type, model, base_url, endpoint_path, msg_format, use_case, priority, enabled, \
         if(length(api_key) > 0, 1, 0) as key_set \
         FROM ndr.ai_providers FINAL ORDER BY priority ASC"
    ).fetch_all::<Row>().await.unwrap_or_default();

    Ok(rows.into_iter().map(|r| serde_json::json!({
        "name": r.name, "provider_type": r.provider_type, "model": r.model,
        "base_url": r.base_url, "endpoint_path": r.endpoint_path, "msg_format": r.msg_format,
        "use_case": r.use_case, "priority": r.priority,
        "enabled": r.enabled == 1, "key_set": r.key_set == 1,
    })).collect())
}

/// Upsert a provider (ReplacingMergeTree deduplicates by name).
pub async fn save_ai_provider(
    &self, name: &str, provider_type: &str, api_key: &str,
    model: &str, base_url: &str, endpoint_path: &str,
    msg_format: &str, use_case: &str, priority: u8, enabled: bool,
) -> anyhow::Result<()> {
    self.client.query(&format!(
        "INSERT INTO ndr.ai_providers \
         (name,provider_type,api_key,model,base_url,endpoint_path,msg_format,use_case,priority,enabled) \
         VALUES ('{}','{}','{}','{}','{}','{}','{}','{}',{},{})",
        Self::_esc_ai(name), Self::_esc_ai(provider_type), Self::_esc_ai(api_key), Self::_esc_ai(model),
        Self::_esc_ai(base_url), Self::_esc_ai(endpoint_path), Self::_esc_ai(msg_format),
        Self::_esc_ai(use_case), priority, if enabled { 1 } else { 0 }
    )).execute().await?;
    Ok(())
}

/// Hard-delete a provider by name.
pub async fn delete_ai_provider(&self, name: &str) -> anyhow::Result<()> {
    self.client.query(&format!(
        "ALTER TABLE ndr.ai_providers DELETE WHERE name = '{}' SETTINGS mutations_sync=1", Self::_esc_ai(name)
    )).execute().await?;
    Ok(())
}

/// Get the raw API key for an existing provider (used when updating without re-entering key).
pub async fn get_ai_provider_key(&self, name: &str) -> anyhow::Result<String> {
    #[derive(clickhouse::Row, serde::Deserialize)]
    struct Row { api_key: String }
    let rows = self.client.query(&format!(
        "SELECT api_key FROM ndr.ai_providers FINAL WHERE name = '{}' LIMIT 1", Self::_esc_ai(name)
    )).fetch_all::<Row>().await.unwrap_or_default();
    Ok(rows.into_iter().next().map(|r| r.api_key).unwrap_or_default())
}

// ── Legacy single-config helpers ───────────────────────────────────────────

/// Returns full AiConfig built from tenant settings.
pub async fn get_ai_config_full(&self, tenant_id: &str) -> crate::ai::AiConfig {
    let settings = self.get_settings_by_tenant(tenant_id).await
        .unwrap_or_default();
    crate::ai::AiConfig::from_settings(&settings)
}

pub async fn save_setting_by_tenant(
    &self, key: &str, value: &str, tenant_id: &str
) -> anyhow::Result<()> {
    let db = tenant_db(tenant_id);
    let query = format!(
        "INSERT INTO {}.settings (key, value) \
         VALUES ('{}', '{}')",
        db, sql_escape(key), sql_escape(value)
    );
    self.client.query(&query).execute().await?;
    Ok(())
}

pub async fn save_setting(
    &self, key: &str, value: &str
) -> anyhow::Result<()> {
    self.save_setting_by_tenant(key, value, "default").await
}

pub async fn get_global_smtp_settings(&self) -> anyhow::Result<(String, String, String, String)> {
    let settings = self.get_settings_by_tenant("default").await.unwrap_or_else(|_| serde_json::json!({}));
    let host = settings["global_smtp_host"].as_str().unwrap_or("smtp.gmail.com").to_string();
    let port = settings["global_smtp_port"].as_str().unwrap_or("587").to_string();
    let user = settings["global_smtp_user"].as_str().unwrap_or("").to_string();
    let password = settings["global_smtp_password"].as_str().unwrap_or("").to_string();
    Ok((host, port, user, password))
}


    //recent hits
    pub async fn get_recent_hits(&self, limit: u64) -> anyhow::Result<Vec<RecentHit>> {
    let hits = self.client
        .query("SELECT timestamp, community_id, src_ip, dst_ip, score, severity, threat_intel, src_country, dst_country FROM ndr_hits ORDER BY timestamp DESC LIMIT ?")
        .bind(limit)
        .fetch_all::<RecentHit>()
        .await
        .unwrap_or_default();
    Ok(hits)
    }
    
    pub async fn get_recent_events(&self, limit: u64) -> anyhow::Result<Vec<RecentEvent>> {
        let events = self.client
            .query("SELECT timestamp, source, src_ip, dst_ip, proto, event_type, community_id FROM ndr_events ORDER BY timestamp DESC LIMIT ?")
            .bind(limit)
            .fetch_all::<RecentEvent>()
            .await
            .unwrap_or_default();
        Ok(events)
    }

    //top src ips
    pub async fn get_top_src_ips(&self, limit: u64) -> anyhow::Result<Vec<TopIp>> {
        let ips = self.client
            .query("SELECT src_ip as ip, count() as count FROM ndr_events WHERE src_ip != '' GROUP BY src_ip ORDER BY count DESC LIMIT ?")
            .bind(limit)
            .fetch_all::<TopIp>()
            .await
            .unwrap_or_default();
        Ok(ips)
    }

    //top dst ips
    pub async fn get_top_dst_ips(&self, limit: u64) -> anyhow::Result<Vec<TopIp>> {
        let ips = self.client
            .query("SELECT dst_ip as ip, count() as count FROM ndr_events WHERE dst_ip != '' GROUP BY dst_ip ORDER BY count DESC LIMIT ?")
            .bind(limit)
            .fetch_all::<TopIp>()
            .await
            .unwrap_or_default();
        Ok(ips)
    }

//network map
pub async fn get_network_map(&self) -> anyhow::Result<serde_json::Value> {
    // Get top communication pairs
    let pairs = self.client
        .query("
            SELECT 
                src_ip,
                dst_ip,
                count() as connections,
                groupArray(DISTINCT proto) as protocols
            FROM ndr_events 
            WHERE src_ip != '' 
              AND dst_ip != ''
              AND timestamp > now() - INTERVAL 1 HOUR
            GROUP BY src_ip, dst_ip
            ORDER BY connections DESC
            LIMIT 100
        ")
        .fetch_all::<NetworkPair>()
        .await
        .unwrap_or_default();

    // Build nodes and edges for graph
    let mut nodes: std::collections::HashMap<String, serde_json::Value> = 
        std::collections::HashMap::new();
    let mut edges: Vec<serde_json::Value> = Vec::new();

    for pair in &pairs {
        // Add source node
        nodes.entry(pair.src_ip.clone()).or_insert(json!({
            "id":    pair.src_ip,
            "label": pair.src_ip,
            "type":  if pair.src_ip.starts_with("10.") || 
                        pair.src_ip.starts_with("192.168.") || 
                        pair.src_ip.starts_with("172.") 
                     { "internal" } else { "external" }
        }));

        // Add destination node
        nodes.entry(pair.dst_ip.clone()).or_insert(json!({
            "id":    pair.dst_ip,
            "label": pair.dst_ip,
            "type":  if pair.dst_ip.starts_with("10.") || 
                        pair.dst_ip.starts_with("192.168.") || 
                        pair.dst_ip.starts_with("172.") 
                     { "internal" } else { "external" }
        }));

        // Add edge
        edges.push(json!({
            "source":      pair.src_ip,
            "target":      pair.dst_ip,
            "connections": pair.connections,
            "protocols":   pair.protocols,
            "weight":      pair.connections,
        }));
    }

    Ok(json!({
        "nodes": nodes.values().collect::<Vec<_>>(),
        "edges": edges,
        "total_nodes": nodes.len(),
        "total_edges": edges.len(),
    }))
}


    pub async fn get_severity_breakdown(&self) -> anyhow::Result<serde_json::Value> {
        // Single GROUP BY with a 30-day time filter replaces 4 sequential full-table scans.
        // The time predicate lets ClickHouse use the primary key for a range scan;
        // GROUP BY severity returns all four buckets in one pass.
        #[derive(clickhouse::Row, serde::Deserialize)]
        struct Row { severity: String, cnt: u64 }
        let rows = self.client
            .query("SELECT severity, count() AS cnt \
                    FROM ndr_hits \
                    WHERE timestamp > now() - INTERVAL 30 DAY \
                    GROUP BY severity")
            .fetch_all::<Row>().await.unwrap_or_default();

        let mut critical = 0u64;
        let mut high     = 0u64;
        let mut medium   = 0u64;
        let mut low      = 0u64;
        for r in rows {
            match r.severity.to_lowercase().as_str() {
                "critical" => critical = r.cnt,
                "high"     => high     = r.cnt,
                "medium"   => medium   = r.cnt,
                "low"      => low      = r.cnt,
                _          => {}
            }
        }
        Ok(serde_json::json!({
            "critical": critical,
            "high":     high,
            "medium":   medium,
            "low":      low,
        }))
    }

    pub async fn get_stats_by_tenant(
        &self, tenant_id: &str, sensor_ids: &[String]
    ) -> anyhow::Result<serde_json::Value> {
        let db_name = tenant_db(tenant_id);
        let sf = Self::sensor_filter(sensor_ids);
        // Run queries independently — a failure in one returns zeros for that metric
        // rather than making the entire dashboard blank.
        let events_row = self.client.query(&format!(
                "SELECT count() as events_total, \
                 countIf(timestamp > now() - INTERVAL 1 HOUR) as events_1h, \
                 countIf(source='agent-z') as agent_z_events, \
                 countIf(source='agent-s') as agent_s_events \
                 FROM {db}.ndr_events WHERE 1=1{sf}",
                db = db_name, sf = sf))
                .fetch_one::<(u64, u64, u64, u64)>()
                .await
                .unwrap_or((0, 0, 0, 0));

        let hits_row = self.client.query(&format!(
                "SELECT count() as hits_total, \
                 countIf(timestamp > now() - INTERVAL 1 HOUR) as hits_1h \
                 FROM {db}.ndr_hits FINAL WHERE 1=1{sf}",
                db = db_name, sf = sf))
                .fetch_one::<(u64, u64)>()
                .await
                .unwrap_or((0, 0));

        Ok(serde_json::json!({
            "events_total": events_row.0, "hits_total": hits_row.0,
            "events_1h": events_row.1,   "hits_1h": hits_row.1,
            "agent_z_events": events_row.2,  "agent_s_events": events_row.3
        }))
    }

    /// Platform-wide event/hit totals — sums get_stats_by_tenant() across
    /// every active tenant's own database (see get_severity_all_tenants for
    /// why this loops instead of a single cross-database query).
    pub async fn get_stats_all_tenants(&self) -> anyhow::Result<serde_json::Value> {
        let tenant_ids = self.get_all_tenants().await.unwrap_or_default();
        // Bounded concurrency (crate::threat::tenant_scan_concurrency) instead
        // of one tenant at a time - this backs a super_admin dashboard widget
        // polled every 10s; at real tenant counts, sequential per-tenant
        // queries here would take far longer than the poll interval itself.
        let sem = std::sync::Arc::new(tokio::sync::Semaphore::new(crate::threat::tenant_scan_concurrency()));
        let mut handles = Vec::with_capacity(tenant_ids.len());
        for tid in tenant_ids {
            let this = self.clone();
            let sem2 = std::sync::Arc::clone(&sem);
            handles.push(tokio::spawn(async move {
                let _permit = sem2.acquire().await;
                this.get_stats_by_tenant(&tid, &[]).await.ok()
            }));
        }
        let (mut events_total, mut hits_total, mut events_1h, mut hits_1h) = (0u64, 0u64, 0u64, 0u64);
        let (mut agent_z, mut agent_s) = (0u64, 0u64);
        for handle in futures_util::future::join_all(handles).await {
            if let Ok(Some(s)) = handle {
                events_total += s["events_total"].as_u64().unwrap_or(0);
                hits_total   += s["hits_total"].as_u64().unwrap_or(0);
                events_1h    += s["events_1h"].as_u64().unwrap_or(0);
                hits_1h      += s["hits_1h"].as_u64().unwrap_or(0);
                agent_z      += s["agent_z_events"].as_u64().unwrap_or(0);
                agent_s      += s["agent_s_events"].as_u64().unwrap_or(0);
            }
        }
        Ok(serde_json::json!({
            "events_total": events_total, "hits_total": hits_total,
            "events_1h": events_1h,       "hits_1h": hits_1h,
            "agent_z_events": agent_z,    "agent_s_events": agent_s,
        }))
    }

    /// Real per-sensor event counts for the last `hours` — used to show each
    /// sensor's actual ingestion rate (keyed by sensor_id, which is the
    /// sensor key's key_prefix) instead of a placeholder online/offline flag.
    pub async fn get_sensor_event_counts_by_tenant(
        &self, tenant_id: &str, hours: u32,
    ) -> anyhow::Result<std::collections::HashMap<String, u64>> {
        let db_name = tenant_db(tenant_id);
        let rows = self.client.query(&format!(
            "SELECT sensor_id, count() as cnt FROM {db}.ndr_events \
             WHERE sensor_id != '' AND timestamp >= now() - INTERVAL {hours} HOUR \
             GROUP BY sensor_id",
            db = db_name, hours = hours))
            .fetch_all::<(String, u64)>().await.unwrap_or_default();
        Ok(rows.into_iter().collect())
    }

    /// Real IP most recently seen from each sensor's own captured traffic.
    /// There is no stored IP column on sensor_keys, so this is the honest
    /// substitute: the latest src_ip that sensor actually reported.
    pub async fn get_sensor_recent_ips_by_tenant(
        &self, tenant_id: &str,
    ) -> anyhow::Result<std::collections::HashMap<String, String>> {
        let db_name = tenant_db(tenant_id);
        let rows = self.client.query(&format!(
            "SELECT sensor_id, argMax(src_ip, timestamp) as ip FROM {db}.ndr_events \
             WHERE sensor_id != '' AND src_ip != '' \
             GROUP BY sensor_id",
            db = db_name))
            .fetch_all::<(String, String)>().await.unwrap_or_default();
        Ok(rows.into_iter().collect())
    }

    /// Real per-minute event counts for the last `minutes` — a genuine
    /// history for an ingestion sparkline, not a simulated/randomized one.
    /// Always returns exactly `minutes` values, oldest first, zero-filled
    /// for minutes with no events.
    pub async fn get_events_per_minute_by_tenant(
        &self, tenant_id: &str, minutes: u32,
    ) -> anyhow::Result<Vec<u64>> {
        let db_name = tenant_db(tenant_id);
        #[derive(clickhouse::Row, serde::Deserialize)]
        struct MinuteRow { minute: u32, cnt: u64 }
        let rows = self.client.query(&format!(
            "SELECT toUnixTimestamp(toStartOfMinute(timestamp)) as minute, count() as cnt \
             FROM {db}.ndr_events \
             WHERE timestamp >= now() - INTERVAL {minutes} MINUTE \
             GROUP BY minute ORDER BY minute",
            db = db_name, minutes = minutes))
            .fetch_all::<MinuteRow>().await.unwrap_or_default();

        let now = chrono::Utc::now().timestamp() as u32;
        let start = now - now % 60 - (minutes - 1) * 60;
        let mut buckets = vec![0u64; minutes as usize];
        for row in rows {
            if row.minute < start { continue; }
            let idx = ((row.minute - start) / 60) as usize;
            if idx < buckets.len() { buckets[idx] = row.cnt; }
        }
        Ok(buckets)
    }

    pub async fn get_recent_events_by_tenant(
        &self, limit: u64, tenant_id: &str, sensor_ids: &[String]
    ) -> anyhow::Result<Vec<serde_json::Value>> {
        let db_name = tenant_db(tenant_id);
        let sf = Self::sensor_filter(sensor_ids);
        let rows = self.client.query(&format!(
            "SELECT src_ip, dst_ip, proto, source, event_type, toUInt32(timestamp) \
             FROM {db}.ndr_events \
             WHERE 1=1{sf} \
             ORDER BY timestamp DESC LIMIT {limit}",
             db = db_name, sf = sf, limit = limit))
            .fetch_all::<(String, String, String, String, String, u32)>()
            .await.unwrap_or_default();
        Ok(rows.iter().map(|r| serde_json::json!({
            "src_ip":     r.0,
            "dst_ip":     r.1,
            "proto":      r.2,
            "source":     r.3,
            "event_type": r.4,
            "timestamp":  r.5
        })).collect())
    }

    pub async fn export_events_by_tenant(
        &self, tenant_id: &str, hours: u32, limit: u64, sensor_ids: &[String]
    ) -> anyhow::Result<Vec<serde_json::Value>> {
        let db_name = tenant_db(tenant_id);
        let sf = Self::sensor_filter(sensor_ids);
        let rows = self.client.query(&format!(
            "SELECT src_ip, dst_ip, proto, source, event_type, toUInt32(timestamp) \
             FROM {db}.ndr_events \
             WHERE timestamp >= now() - INTERVAL {hours} HOUR{sf} \
             ORDER BY timestamp DESC LIMIT {limit}",
             db = db_name, hours = hours, sf = sf, limit = limit))
            .fetch_all::<(String, String, String, String, String, u32)>()
            .await.unwrap_or_default();
        Ok(rows.iter().map(|r| serde_json::json!({
            "src_ip":     r.0,
            "dst_ip":     r.1,
            "proto":      r.2,
            "source":     r.3,
            "event_type": r.4,
            "timestamp":  r.5
        })).collect())
    }

    pub async fn get_top_protocols_by_tenant(
        &self, limit: u64, tenant_id: &str, sensor_ids: &[String]
    ) -> anyhow::Result<Vec<serde_json::Value>> {
        let db_name = tenant_db(tenant_id);
        let sf = Self::sensor_filter(sensor_ids);
        let mut rows = self.client.query(&format!(
            "SELECT proto, count() as cnt FROM {db}.ndr_events \
             WHERE proto != '' AND timestamp >= now() - INTERVAL 24 HOUR{sf} \
             GROUP BY proto ORDER BY cnt DESC LIMIT {limit}",
            db = db_name, sf = sf, limit = limit))
            .fetch_all::<(String, u64)>().await.unwrap_or_default();
        if rows.is_empty() {
            rows = self.client.query(&format!(
                "SELECT proto, count() as cnt FROM {db}.ndr_events \
                 WHERE proto != ''{sf} \
                 GROUP BY proto ORDER BY cnt DESC LIMIT {limit}",
                db = db_name, sf = sf, limit = limit))
                .fetch_all::<(String, u64)>().await.unwrap_or_default();
        }
        Ok(rows.iter().map(|r| serde_json::json!({ "proto": r.0, "count": r.1 })).collect())
    }

    pub async fn get_top_src_ips_by_tenant(
        &self, limit: u64, tenant_id: &str, sensor_ids: &[String]
    ) -> anyhow::Result<Vec<serde_json::Value>> {
        let db_name = tenant_db(tenant_id);
        let sf = Self::sensor_filter(sensor_ids);
        let rows = self.client.query(&format!(
            "SELECT src_ip, count() as cnt FROM {db}.ndr_events \
             WHERE src_ip != '' AND timestamp >= now() - INTERVAL 24 HOUR{sf} \
             GROUP BY src_ip ORDER BY cnt DESC LIMIT {limit}",
            db = db_name, sf = sf, limit = limit))
            .fetch_all::<(String, u64)>().await.unwrap_or_default();
        Ok(rows.iter().map(|r| serde_json::json!({ "ip": r.0, "count": r.1 })).collect())
    }

    pub async fn get_top_dst_ips_by_tenant(
        &self, limit: u64, tenant_id: &str, sensor_ids: &[String]
    ) -> anyhow::Result<Vec<serde_json::Value>> {
        let db_name = tenant_db(tenant_id);
        let sf = Self::sensor_filter(sensor_ids);
        let rows = self.client.query(&format!(
            "SELECT dst_ip, count() as cnt FROM {db}.ndr_events \
             WHERE dst_ip != '' AND timestamp >= now() - INTERVAL 24 HOUR{sf} \
             GROUP BY dst_ip ORDER BY cnt DESC LIMIT {limit}",
            db = db_name, sf = sf, limit = limit))
            .fetch_all::<(String, u64)>().await.unwrap_or_default();
        Ok(rows.iter().map(|r| serde_json::json!({ "ip": r.0, "count": r.1 })).collect())
    }

    pub async fn get_top_external_src_ips_by_tenant(
        &self, limit: u64, tenant_id: &str, sensor_ids: &[String]
    ) -> anyhow::Result<Vec<(String, u64)>> {
        let db_name = tenant_db(tenant_id);
        let sf = Self::sensor_filter(sensor_ids);
        // Exclude RFC-1918 and loopback ranges at the DB level for efficiency
        let rows = self.client.query(&format!(
            "SELECT src_ip, count() as cnt FROM {db}.ndr_events \
             WHERE src_ip != '' \
               AND NOT match(src_ip, '^(10\\.|172\\.(1[6-9]|2[0-9]|3[01])\\.|192\\.168\\.|127\\.|0\\.|169\\.254\\.)') \
               AND timestamp >= now() - INTERVAL 24 HOUR{sf} \
             GROUP BY src_ip ORDER BY cnt DESC LIMIT {limit}",
            db = db_name, sf = sf, limit = limit))
            .fetch_all::<(String, u64)>().await.unwrap_or_default();
        Ok(rows)
    }

    // ── Platform-wide (all-tenant) aggregates for the Super Admin Overview ──
    // Each pulls a generous per-tenant slice, sums/merges by key across every
    // tenant's own database, then truncates to the requested limit — so a
    // count that's only a top offender in one tenant isn't lost before merge.

    pub async fn get_top_protocols_all_tenants(&self, limit: u64) -> anyhow::Result<Vec<serde_json::Value>> {
        let tenant_ids = self.get_all_tenants().await.unwrap_or_default();
        let sem = std::sync::Arc::new(tokio::sync::Semaphore::new(crate::threat::tenant_scan_concurrency()));
        let mut handles = Vec::with_capacity(tenant_ids.len());
        for tid in tenant_ids {
            let this = self.clone();
            let sem2 = std::sync::Arc::clone(&sem);
            handles.push(tokio::spawn(async move {
                let _permit = sem2.acquire().await;
                this.get_top_protocols_by_tenant(50, &tid, &[]).await.unwrap_or_default()
            }));
        }
        let mut totals: std::collections::HashMap<String, u64> = std::collections::HashMap::new();
        for handle in futures_util::future::join_all(handles).await {
            let Ok(rows) = handle else { continue };
            for row in rows {
                let proto = row["proto"].as_str().unwrap_or("").to_string();
                let cnt   = row["count"].as_u64().unwrap_or(0);
                if proto.is_empty() { continue; }
                *totals.entry(proto).or_insert(0) += cnt;
            }
        }
        let mut merged: Vec<(String, u64)> = totals.into_iter().collect();
        merged.sort_by(|a, b| b.1.cmp(&a.1));
        merged.truncate(limit as usize);
        Ok(merged.into_iter().map(|(proto, count)| serde_json::json!({ "proto": proto, "count": count })).collect())
    }

    pub async fn get_top_src_ips_all_tenants(&self, limit: u64) -> anyhow::Result<Vec<serde_json::Value>> {
        let tenant_ids = self.get_all_tenants().await.unwrap_or_default();
        let sem = std::sync::Arc::new(tokio::sync::Semaphore::new(crate::threat::tenant_scan_concurrency()));
        let mut handles = Vec::with_capacity(tenant_ids.len());
        for tid in tenant_ids {
            let this = self.clone();
            let sem2 = std::sync::Arc::clone(&sem);
            handles.push(tokio::spawn(async move {
                let _permit = sem2.acquire().await;
                this.get_top_src_ips_by_tenant(100, &tid, &[]).await.unwrap_or_default()
            }));
        }
        let mut totals: std::collections::HashMap<String, u64> = std::collections::HashMap::new();
        for handle in futures_util::future::join_all(handles).await {
            let Ok(rows) = handle else { continue };
            for row in rows {
                let ip  = row["ip"].as_str().unwrap_or("").to_string();
                let cnt = row["count"].as_u64().unwrap_or(0);
                if ip.is_empty() { continue; }
                *totals.entry(ip).or_insert(0) += cnt;
            }
        }
        let mut merged: Vec<(String, u64)> = totals.into_iter().collect();
        merged.sort_by(|a, b| b.1.cmp(&a.1));
        merged.truncate(limit as usize);
        Ok(merged.into_iter().map(|(ip, count)| serde_json::json!({ "ip": ip, "count": count })).collect())
    }

    pub async fn get_top_dst_ips_all_tenants(&self, limit: u64) -> anyhow::Result<Vec<serde_json::Value>> {
        let tenant_ids = self.get_all_tenants().await.unwrap_or_default();
        let sem = std::sync::Arc::new(tokio::sync::Semaphore::new(crate::threat::tenant_scan_concurrency()));
        let mut handles = Vec::with_capacity(tenant_ids.len());
        for tid in tenant_ids {
            let this = self.clone();
            let sem2 = std::sync::Arc::clone(&sem);
            handles.push(tokio::spawn(async move {
                let _permit = sem2.acquire().await;
                this.get_top_dst_ips_by_tenant(100, &tid, &[]).await.unwrap_or_default()
            }));
        }
        let mut totals: std::collections::HashMap<String, u64> = std::collections::HashMap::new();
        for handle in futures_util::future::join_all(handles).await {
            let Ok(rows) = handle else { continue };
            for row in rows {
                let ip  = row["ip"].as_str().unwrap_or("").to_string();
                let cnt = row["count"].as_u64().unwrap_or(0);
                if ip.is_empty() { continue; }
                *totals.entry(ip).or_insert(0) += cnt;
            }
        }
        let mut merged: Vec<(String, u64)> = totals.into_iter().collect();
        merged.sort_by(|a, b| b.1.cmp(&a.1));
        merged.truncate(limit as usize);
        Ok(merged.into_iter().map(|(ip, count)| serde_json::json!({ "ip": ip, "count": count })).collect())
    }

    pub async fn get_top_external_src_ips_all_tenants(&self, limit: u64) -> anyhow::Result<Vec<(String, u64)>> {
        let tenant_ids = self.get_all_tenants().await.unwrap_or_default();
        let sem = std::sync::Arc::new(tokio::sync::Semaphore::new(crate::threat::tenant_scan_concurrency()));
        let mut handles = Vec::with_capacity(tenant_ids.len());
        for tid in tenant_ids {
            let this = self.clone();
            let sem2 = std::sync::Arc::clone(&sem);
            handles.push(tokio::spawn(async move {
                let _permit = sem2.acquire().await;
                this.get_top_external_src_ips_by_tenant(100, &tid, &[]).await.unwrap_or_default()
            }));
        }
        let mut totals: std::collections::HashMap<String, u64> = std::collections::HashMap::new();
        for handle in futures_util::future::join_all(handles).await {
            let Ok(rows) = handle else { continue };
            for (ip, cnt) in rows {
                *totals.entry(ip).or_insert(0) += cnt;
            }
        }
        let mut merged: Vec<(String, u64)> = totals.into_iter().collect();
        merged.sort_by(|a, b| b.1.cmp(&a.1));
        merged.truncate(limit as usize);
        Ok(merged)
    }

    pub async fn get_country_attack_tags_all_tenants(&self) -> anyhow::Result<std::collections::HashMap<String, Vec<(String, u64)>>> {
        let tenant_ids = self.get_all_tenants().await.unwrap_or_default();
        let sem = std::sync::Arc::new(tokio::sync::Semaphore::new(crate::threat::tenant_scan_concurrency()));
        let mut handles = Vec::with_capacity(tenant_ids.len());
        for tid in tenant_ids {
            let this = self.clone();
            let sem2 = std::sync::Arc::clone(&sem);
            handles.push(tokio::spawn(async move {
                let _permit = sem2.acquire().await;
                this.get_country_attack_tags(&tid, &[]).await.ok()
            }));
        }
        let mut totals: std::collections::HashMap<String, std::collections::HashMap<String, u64>> = std::collections::HashMap::new();
        for handle in futures_util::future::join_all(handles).await {
            if let Ok(Some(per_country)) = handle {
                for (code, tags) in per_country {
                    let entry = totals.entry(code).or_default();
                    for (tag, cnt) in tags {
                        *entry.entry(tag).or_insert(0) += cnt;
                    }
                }
            }
        }
        Ok(totals.into_iter().map(|(code, tags)| {
            let mut v: Vec<(String, u64)> = tags.into_iter().collect();
            v.sort_by(|a, b| b.1.cmp(&a.1));
            (code, v)
        }).collect())
    }

    pub async fn get_threat_intel_hits_all_tenants(&self) -> anyhow::Result<Vec<serde_json::Value>> {
        let tenant_ids = self.get_all_tenants().await.unwrap_or_default();
        let sem = std::sync::Arc::new(tokio::sync::Semaphore::new(crate::threat::tenant_scan_concurrency()));
        let mut handles = Vec::with_capacity(tenant_ids.len());
        for tid in tenant_ids {
            let this = self.clone();
            let sem2 = std::sync::Arc::clone(&sem);
            handles.push(tokio::spawn(async move {
                let _permit = sem2.acquire().await;
                this.get_threat_intel_hits_by_tenant(&tid, &[]).await.unwrap_or_default()
            }));
        }
        // Keyed by (src_ip, dst_ip): sum hits, keep the latest last_seen.
        let mut totals: std::collections::HashMap<(String, String), (u64, String)> = std::collections::HashMap::new();
        for handle in futures_util::future::join_all(handles).await {
            let Ok(rows) = handle else { continue };
            for row in rows {
                let src = row["src_ip"].as_str().unwrap_or("").to_string();
                let dst = row["dst_ip"].as_str().unwrap_or("").to_string();
                let hits = row["hits"].as_u64().unwrap_or(0);
                let last_seen = row["last_seen"].as_str().unwrap_or("").to_string();
                let entry = totals.entry((src, dst)).or_insert((0, String::new()));
                entry.0 += hits;
                if last_seen > entry.1 { entry.1 = last_seen; }
            }
        }
        let mut merged: Vec<((String, String), (u64, String))> = totals.into_iter().collect();
        merged.sort_by(|a, b| b.1.0.cmp(&a.1.0));
        merged.truncate(50);
        Ok(merged.into_iter().map(|((src_ip, dst_ip), (hits, last_seen))| serde_json::json!({
            "src_ip": src_ip, "dst_ip": dst_ip, "hits": hits, "last_seen": last_seen,
        })).collect())
    }

    pub async fn get_public_threat_intel_ip_counts(&self) -> anyhow::Result<Vec<(String, u64)>> {
        #[derive(clickhouse::Row, serde::Deserialize)]
        struct Row {
            ioc_value: String,
            cnt: u64,
        }

        let rows = self.client
            .query(
                "SELECT ioc_value, count() AS cnt \
                 FROM ndr.threat_intel \
                 WHERE ioc_type = 'ip' \
                   AND ioc_value != '' \
                   AND NOT match(ioc_value, '^(10\\.|172\\.(1[6-9]|2[0-9]|3[01])\\.|192\\.168\\.|127\\.|169\\.254\\.)') \
                 GROUP BY ioc_value \
                 ORDER BY cnt DESC \
                 LIMIT 500"
            )
            .fetch_all::<Row>()
            .await
            .unwrap_or_default();

        Ok(rows.into_iter().map(|r| (r.ioc_value, r.cnt)).collect())
    }

    pub async fn get_threat_intel_summary(&self) -> anyhow::Result<serde_json::Value> {
        #[derive(clickhouse::Row, serde::Deserialize)]
        struct Row {
            unique_ips: u64,
            unique_hashes: u64,
            unique_domains: u64,
            unique_public_ips: u64,
            ip_rows: u64,
            hash_rows: u64,
            domain_rows: u64,
            public_ip_rows: u64,
            total_rows: u64,
            last_refresh: String,
        }

        let rows = self.client
            .query(
                "SELECT \
                    uniqExactIf(ioc_value, ioc_type = 'ip' AND ioc_value != '') AS unique_ips, \
                    uniqExactIf(ioc_value, ioc_type = 'hash' AND ioc_value != '') AS unique_hashes, \
                    uniqExactIf(ioc_value, ioc_type = 'domain' AND ioc_value != '') AS unique_domains, \
                    uniqExactIf(ioc_value, ioc_type = 'ip' AND ioc_value != '' AND NOT match(ioc_value, '^(10\\.|172\\.(1[6-9]|2[0-9]|3[01])\\.|192\\.168\\.|127\\.|169\\.254\\.)')) AS unique_public_ips, \
                    countIf(ioc_type = 'ip' AND ioc_value != '') AS ip_rows, \
                    countIf(ioc_type = 'hash' AND ioc_value != '') AS hash_rows, \
                    countIf(ioc_type = 'domain' AND ioc_value != '') AS domain_rows, \
                    countIf(ioc_type = 'ip' AND ioc_value != '' AND NOT match(ioc_value, '^(10\\.|172\\.(1[6-9]|2[0-9]|3[01])\\.|192\\.168\\.|127\\.|169\\.254\\.)')) AS public_ip_rows, \
                    count() AS total_rows, \
                    formatDateTime(max(collected_at), '%Y-%m-%d %H:%i UTC') AS last_refresh \
                 FROM ndr.threat_intel \
                 WHERE expires_at > now()"
            )
            .fetch_all::<Row>()
            .await
            .unwrap_or_default();

        Ok(rows.into_iter().next().map(|r| {
            serde_json::json!({
                "unique_ips": r.unique_ips,
                "unique_hashes": r.unique_hashes,
                "unique_domains": r.unique_domains,
                "unique_public_ips": r.unique_public_ips,
                "ip_rows": r.ip_rows,
                "hash_rows": r.hash_rows,
                "domain_rows": r.domain_rows,
                "public_ip_rows": r.public_ip_rows,
                "total_rows": r.total_rows,
                "last_refresh": r.last_refresh,
            })
        }).unwrap_or_else(|| serde_json::json!({
            "unique_ips": 0,
            "unique_hashes": 0,
            "unique_domains": 0,
            "unique_public_ips": 0,
            "ip_rows": 0,
            "hash_rows": 0,
            "domain_rows": 0,
            "public_ip_rows": 0,
            "total_rows": 0,
            "last_refresh": "never",
        })))
    }

    pub async fn get_threat_intel_feed_sources(&self) -> anyhow::Result<Vec<serde_json::Value>> {
        #[derive(clickhouse::Row, serde::Deserialize)]
        struct Row {
            source: String,
            ioc_type: String,
            rows: u64,
            unique_values: u64,
        }

        let rows = self.client
            .query(
                "SELECT \
                    source, \
                    ioc_type, \
                    count() AS rows, \
                    uniqExact(ioc_value) AS unique_values \
                 FROM ndr.threat_intel \
                 WHERE expires_at > now() \
                 GROUP BY source, ioc_type \
                 ORDER BY rows DESC \
                 LIMIT 50"
            )
            .fetch_all::<Row>()
            .await
            .unwrap_or_default();

        Ok(rows.into_iter().map(|r| serde_json::json!({
            "source": r.source,
            "ioc_type": r.ioc_type,
            "rows": r.rows,
            "unique_values": r.unique_values,
        })).collect())
    }

    pub async fn get_country_attack_tags(
        &self, tenant_id: &str, sensor_ids: &[String]
    ) -> anyhow::Result<std::collections::HashMap<String, Vec<(String, u64)>>> {
        let db_name = tenant_db(tenant_id);
        let sf = Self::sensor_filter(sensor_ids);

        #[derive(clickhouse::Row, serde::Deserialize)]
        struct Row { src_country: String, tag: String, cnt: u64 }

        // arrayConcat merges detection tags + sigma rule names so countries with
        // empty tags[] but populated sigma_hits[] still produce breakdown rows.
        let rows = self.client.query(&format!(
            "SELECT src_country, arrayJoin(arrayConcat(tags, sigma_hits)) as tag, count() as cnt \
             FROM {db}.ndr_hits FINAL \
             WHERE src_country != '' \
               AND timestamp >= now() - INTERVAL 24 HOUR \
               AND (notEmpty(tags) OR notEmpty(sigma_hits)) \
               {sf} \
             GROUP BY src_country, tag \
             ORDER BY cnt DESC \
             LIMIT 300",
            db = db_name, sf = sf
        )).fetch_all::<Row>().await.unwrap_or_default();

        let mut map: std::collections::HashMap<String, Vec<(String, u64)>> = Default::default();
        for r in rows {
            map.entry(r.src_country).or_default().push((r.tag, r.cnt));
        }
        for v in map.values_mut() {
            v.sort_by(|a, b| b.1.cmp(&a.1));
            v.truncate(5);
        }
        Ok(map)
    }

    pub async fn get_recent_hits_by_tenant(
        &self, limit: u64, tenant_id: &str, sensor_ids: &[String], hours: u32, ip_filter: Option<&str>,
    ) -> anyhow::Result<Vec<serde_json::Value>> {
        let db_name = tenant_db(tenant_id);
        let time_filter = if ip_filter.is_some() {
            // Searching by IP: skip time window so all historical hits are visible
            String::new()
        } else if hours == 0 {
            "AND timestamp > now() - INTERVAL 30 DAY".to_string()
        } else {
            format!("AND timestamp > now() - INTERVAL {} HOUR", hours)
        };
        let sensor_filter = if sensor_ids.is_empty() {
            String::new()
        } else {
            let list = sensor_ids.iter().map(|s| format!("'{}'", sql_escape(s))).collect::<Vec<_>>().join(",");
            format!("AND sensor_id IN ({})", list)
        };
        let ip_filter_sql = if let Some(ip) = ip_filter {
            format!("AND (src_ip = '{}' OR dst_ip = '{}')", sql_escape(ip), sql_escape(ip))
        } else {
            String::new()
        };
        // Pre-fetch active group suppressions (src_ip + tag) to build ARM 2 filter.
        // ClickHouse does not support correlated subqueries, so we resolve them in Rust
        // and inject as SQL literals into the main query.
        #[derive(clickhouse::Row, serde::Deserialize)]
        struct GroupSup { suppress_ip: String, signature_name: String }
        let group_sups: Vec<GroupSup> = self.client.query(&format!(
            "SELECT suppress_ip, signature_name \
             FROM {src} \
             WHERE active = 1 AND community_id = '' AND suppress_ip != '' \
               AND (expires_at IS NULL OR expires_at > now()) \
               AND (tenant_id = '{tid}' OR tenant_id = '')",
            src = suppressions_source(tenant_id),
            tid = sql_escape(tenant_id)
        )).fetch_all::<GroupSup>().await.unwrap_or_default();

        let group_filter = if group_sups.is_empty() {
            String::new()
        } else {
            let conds: Vec<String> = group_sups.iter().map(|s| {
                if s.signature_name == "alert" {
                    // 'alert' is the fallback for hits with no detection tags.
                    // Suppress all untagged hits from this src_ip.
                    format!("(src_ip = '{}' AND empty(tags) AND empty(sigma_hits))",
                        sql_escape(&s.suppress_ip))
                } else {
                    format!("(src_ip = '{}' AND (hasAny(tags, ['{name}']) OR hasAny(sigma_hits, ['{name}'])))",
                        sql_escape(&s.suppress_ip),
                        name = sql_escape(&s.signature_name))
                }
            }).collect();
            format!("AND NOT ({})", conds.join(" OR "))
        };

        let rows = self.client.query(&format!(
            "SELECT \
                toUInt32(timestamp) AS timestamp, \
                community_id, src_ip, dst_ip, score, severity, \
                tags, sigma_hits, threat_intel, src_country, dst_country, \
                correlation_status, agent_s_rule_id, toUInt32(corroborated_at) AS corroborated_at, \
                sensor_id \
             FROM {db}.ndr_hits FINAL \
             WHERE 1=1 \
               {tf} \
               {sf} \
               {ipf} \
               AND community_id NOT IN ( \
                 SELECT community_id FROM {src} \
                 WHERE active = 1 AND community_id != '' \
                   AND (expires_at IS NULL OR expires_at > now()) \
                   AND (tenant_id = '{tid}' OR tenant_id = '') \
               ) \
               {gf} \
             ORDER BY timestamp DESC, score DESC LIMIT {lim}",
            db  = db_name,
            tf  = time_filter,
            sf  = sensor_filter,
            ipf = ip_filter_sql,
            src = suppressions_source(tenant_id),
            tid = sql_escape(tenant_id),
            gf  = group_filter,
            lim = limit))
            .fetch_all::<RecentHitDetail>()
            .await.unwrap_or_default();

        // Bulk asset lookup for src/dst IPs
        let unique_ips: Vec<String> = rows.iter()
            .flat_map(|r| [r.src_ip.clone(), r.dst_ip.clone()])
            .filter(|ip| !ip.is_empty())
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();
        let mut asset_map: std::collections::HashMap<String, serde_json::Value> = std::collections::HashMap::new();
        if !unique_ips.is_empty() {
            let ip_list = unique_ips.iter().map(|ip| format!("'{}'", sql_escape(ip))).collect::<Vec<_>>().join(",");
            if let Ok(assets) = self.client.query(&format!(
                "SELECT ip, hostname, mac, vendor, device_type, trusted, threat_flagged, custom_name \
                 FROM {db}.assets FINAL WHERE ip IN ({ip_list}) AND tenant_id = '{tid}'",
                db = db_name, ip_list = ip_list, tid = sql_escape(tenant_id)
            )).fetch_all::<(String,String,String,String,String,u8,u8,String)>().await {
                for (ip, hostname, mac, vendor, device_type, trusted, threat_flagged, custom_name) in assets {
                    asset_map.insert(ip, serde_json::json!({
                        "custom_name": custom_name, "hostname": hostname,
                        "mac": mac, "vendor": vendor,
                        "device_type": device_type,
                        "trusted": trusted != 0, "threat_flagged": threat_flagged != 0
                    }));
                }
            }
        }

        // Passive-DNS domain lookup for destination IPs not in the asset map
        // (public IPs never appear in assets; use SNI-derived passive_dns entries instead)
        let mut pdns_map: std::collections::HashMap<String, String> = std::collections::HashMap::new();
        {
            let public_dst_ips: Vec<String> = rows.iter()
                .map(|r| r.dst_ip.clone())
                .filter(|ip| !ip.is_empty() && !asset_map.contains_key(ip))
                .collect::<std::collections::HashSet<_>>()
                .into_iter()
                .collect();
            if !public_dst_ips.is_empty() {
                let ip_list = public_dst_ips.iter()
                    .map(|ip| format!("'{}'", sql_escape(ip)))
                    .collect::<Vec<_>>().join(",");
                if let Ok(dns_rows) = self.client.query(&format!(
                    "SELECT ip, domain FROM ndr.passive_dns FINAL \
                     WHERE ip IN ({ip_list}) ORDER BY last_seen DESC",
                    ip_list = ip_list
                )).fetch_all::<(String, String)>().await {
                    for (ip, domain) in dns_rows {
                        pdns_map.entry(ip).or_insert(domain);
                    }
                }
            }
        }

        // rDNS fallback — for public dst IPs still missing a domain, use
        // `getent hosts <ip>` (system resolver PTR lookup) in a blocking task.
        {
            let missing: Vec<String> = rows.iter()
                .map(|r| r.dst_ip.clone())
                .filter(|ip| !ip.is_empty() && !pdns_map.contains_key(ip))
                .collect::<std::collections::HashSet<_>>()
                .into_iter()
                .collect();

            if !missing.is_empty() {
                // Run each getent lookup concurrently instead of sequentially
                // to avoid holding a blocking thread for O(N * DNS_timeout).
                let handles: Vec<_> = missing.into_iter().map(|ip_str| {
                    tokio::task::spawn_blocking(move || {
                        if let Ok(result) = std::process::Command::new("getent")
                            .args(["hosts", &ip_str])
                            .output()
                        {
                            let text = String::from_utf8_lossy(&result.stdout);
                            if let Some(name) = text.split_whitespace().nth(1) {
                                return Some((ip_str, name.to_string()));
                            }
                        }
                        None
                    })
                }).collect();

                for handle in handles {
                    if let Ok(Some((ip, name))) = handle.await {
                        pdns_map.entry(ip).or_insert(name);
                    }
                }
            }
        }

        Ok(rows.iter().map(|r| {
            let src_asset  = asset_map.get(&r.src_ip).cloned().unwrap_or(serde_json::Value::Null);
            let dst_asset  = asset_map.get(&r.dst_ip).cloned().unwrap_or(serde_json::Value::Null);
            let dst_domain = pdns_map.get(&r.dst_ip).cloned().unwrap_or_default();
            serde_json::json!({
                "timestamp":          r.timestamp,
                "community_id":       r.community_id,
                "src_ip":             r.src_ip,
                "dst_ip":             r.dst_ip,
                "score":              r.score,
                "severity":           r.severity,
                "tags":               r.tags,
                "sigma_hits":         r.sigma_hits,
                "threat_intel":       r.threat_intel != 0,
                "src_country":        r.src_country,
                "dst_country":        r.dst_country,
                "correlation_status": r.correlation_status,
                "corroborated":       r.correlation_status == "corroborated",
                "agent_s_rule_id":    r.agent_s_rule_id,
                "corroborated_at":    r.corroborated_at,
                "sensor_id":          r.sensor_id,
                "src_asset":          src_asset,
                "dst_asset":          dst_asset,
                "dst_domain":         dst_domain,
            })
        }).collect())
    }

    pub async fn get_rule_hit_counts(&self, tenant_id: &str, sensor_ids: &[String]) -> anyhow::Result<std::collections::HashMap<String, u64>> {
        let db_name = tenant_db(tenant_id);
        let sf = Self::sensor_filter(sensor_ids);
        #[derive(clickhouse::Row, serde::Deserialize)]
        struct RuleCount { rule_name: String, cnt: u64 }
        let rows = self.client
            .query(&format!(
                "SELECT arrayJoin(sigma_hits) AS rule_name, count() AS cnt \
                 FROM {db}.ndr_hits FINAL \
                 WHERE length(sigma_hits) > 0{sf} \
                 GROUP BY rule_name ORDER BY cnt DESC",
                db = db_name, sf = sf
            ))
            .fetch_all::<RuleCount>().await.unwrap_or_default();
        Ok(rows.into_iter().map(|r| (r.rule_name, r.cnt)).collect())
    }

    pub async fn get_events_by_community_id(
        &self, community_id: &str, tenant_id: &str, sensor_ids: &[String]
    ) -> anyhow::Result<serde_json::Value> {
        let db_name = tenant_db(tenant_id);
        let cid = sql_escape(community_id);
        let sf = Self::sensor_filter(sensor_ids);
        let rows = self.client
            .query(&format!(
                "SELECT source, event_type, src_ip, dst_ip, \
                        src_port, dst_port, proto, \
                        toUnixTimestamp(toDateTime(timestamp)) AS ts \
                 FROM {}.ndr_events \
                 WHERE community_id = '{}'{} \
                 ORDER BY timestamp DESC LIMIT 50",
                db_name, cid, sf
            ))
            .fetch_all::<(String, String, String, String, u16, u16, String, u32)>()
            .await
            .unwrap_or_default();

        Ok(serde_json::json!(rows.iter().map(|r| serde_json::json!({
            "source":     r.0,
            "event_type": r.1,
            "src_ip":     r.2,
            "dst_ip":     r.3,
            "src_port":   r.4,
            "dst_port":   r.5,
            "proto":      r.6,
            "ts":         r.7,
        })).collect::<Vec<_>>()))
    }

    pub async fn get_severity_by_tenant(
        &self, tenant_id: &str, sensor_ids: &[String], hours: u32,
    ) -> anyhow::Result<serde_json::Value> {
        let db_name = tenant_db(tenant_id);
        let sf = Self::sensor_filter(sensor_ids);
        // When hours > 0 (report mode): use FINAL, apply time window, exclude suppressed hits.
        // When hours == 0 (dashboard/WS): fast all-time count without FINAL.
        let (table, time_filter, sup_filter) = if hours > 0 {
            let tf = format!("AND timestamp > now() - INTERVAL {} HOUR", hours);
            let sf_sup = format!(
                "AND community_id NOT IN ( \
                   SELECT community_id FROM {src} \
                   WHERE active = 1 AND community_id != '' \
                     AND (expires_at IS NULL OR expires_at > now()) \
                     AND (tenant_id = '{tid}' OR tenant_id = '') \
                 )",
                src = suppressions_source(tenant_id),
                tid = sql_escape(tenant_id)
            );
            (format!("{db}.ndr_hits FINAL", db = db_name), tf, sf_sup)
        } else {
            (format!("{db}.ndr_hits", db = db_name), String::new(), String::new())
        };
        let row = self.client.query(&format!(
            "SELECT \
             countIf(lower(severity)='critical') as critical, \
             countIf(lower(severity)='high') as high, \
             countIf(lower(severity)='medium') as medium, \
             countIf(lower(severity)='low') as low \
             FROM {tbl} WHERE 1=1{sf}{tf}{supf}",
            tbl = table, sf = sf, tf = time_filter, supf = sup_filter))
            .fetch_one::<(u64, u64, u64, u64)>()
            .await.unwrap_or((0, 0, 0, 0));
        Ok(serde_json::json!({
            "critical": row.0, "high": row.1,
            "medium": row.2,   "low": row.3
        }))
    }

    /// Platform-wide severity totals for the Super Admin Overview — sums
    /// countIf(severity=...) across every active tenant's own ndr_hits
    /// table (each tenant has a dedicated ndr_<tenant_id> database; the
    /// default tenant uses the base `ndr` database). A tenant whose DB/table
    /// isn't provisioned yet (e.g. a partially-created tenant) just
    /// contributes 0 rather than failing the whole aggregate.
    pub async fn get_severity_all_tenants(&self) -> anyhow::Result<serde_json::Value> {
        let tenant_ids = self.get_all_tenants().await.unwrap_or_default();
        let (mut critical, mut high, mut medium, mut low) = (0u64, 0u64, 0u64, 0u64);
        let mut tenants_reporting = 0u32;

        for tid in &tenant_ids {
            let db = tenant_db(tid);
            let query = format!(
                "SELECT \
                 countIf(lower(severity)='critical') as critical, \
                 countIf(lower(severity)='high') as high, \
                 countIf(lower(severity)='medium') as medium, \
                 countIf(lower(severity)='low') as low \
                 FROM {db}.ndr_hits",
                db = db
            );
            if let Ok(row) = self.client.query(&query).fetch_one::<(u64, u64, u64, u64)>().await {
                critical += row.0;
                high += row.1;
                medium += row.2;
                low += row.3;
                tenants_reporting += 1;
            }
        }

        Ok(serde_json::json!({
            "critical": critical, "high": high,
            "medium": medium,     "low": low,
            "tenants_total": tenant_ids.len(),
            "tenants_reporting": tenants_reporting,
        }))
    }

    pub async fn insert_passive_dns(&self, ip: &str, domain: &str) -> anyhow::Result<()> {
        if ip.is_empty() || domain.is_empty() { return Ok(()); }
        let query = format!(
            "INSERT INTO ndr.passive_dns (ip, domain, hit_count, first_seen, last_seen) VALUES ('{}', '{}', 1, now(), now())",
            sql_escape(ip), sql_escape(domain)
        );
        self.client.query(&query).execute().await?;
        Ok(())
    }

    /// Batch-insert multiple (ip, domain) passive DNS mappings in one HTTP request.
    /// All five columns are set explicitly — passive_dns uses AggregatingMergeTree
    /// with SimpleAggregateFunction columns whose DEFAULT may not apply in native INSERT.
    pub async fn batch_insert_passive_dns(&self, entries: &[(String, String)]) -> anyhow::Result<()> {
        if entries.is_empty() { return Ok(()); }
        #[derive(clickhouse::Row, serde::Serialize)]
        struct Row { ip: String, domain: String, hit_count: u64, first_seen: u32, last_seen: u32 }
        let now = chrono::Utc::now().timestamp() as u32;
        let mut insert = self.client.insert("ndr.passive_dns")?;
        for (ip, domain) in entries {
            if !ip.is_empty() && !domain.is_empty() {
                insert.write(&Row {
                    ip: ip.clone(), domain: domain.clone(),
                    hit_count: 1, first_seen: now, last_seen: now,
                }).await?;
            }
        }
        insert.end().await?;
        Ok(())
    }

    pub async fn get_network_map_by_tenant(
        &self, tenant_id: &str, mode: Option<&str>, limit: Option<usize>, sensor_ids: &[String]
    ) -> anyhow::Result<serde_json::Value> {
        let db_name = tenant_db(tenant_id);
        let sf = Self::sensor_filter(sensor_ids);
        let recent_query = format!("
            SELECT src_ip, dst_ip,
                count() as connections,
                groupArray(DISTINCT proto) as protocols
            FROM {db_name}.ndr_events
            WHERE tenant_id = '{tenant_escaped}' AND src_ip != '' AND dst_ip != ''
              AND timestamp >= (SELECT subtractHours(max(timestamp), 1) FROM {db_name}.ndr_events WHERE tenant_id = '{tenant_escaped}'){sf}
            GROUP BY src_ip, dst_ip
            ORDER BY connections DESC
            LIMIT 1000", db_name=db_name, tenant_escaped=sql_escape(tenant_id), sf=sf);
        let fallback_query = format!("
            SELECT src_ip, dst_ip,
                count() as connections,
                groupArray(DISTINCT proto) as protocols
            FROM {db_name}.ndr_events
            WHERE tenant_id = '{tenant_escaped}' AND src_ip != '' AND dst_ip != ''{sf}
            GROUP BY src_ip, dst_ip
            ORDER BY connections DESC
            LIMIT 1000", db_name=db_name, tenant_escaped=sql_escape(tenant_id), sf=sf);

        let mut pairs = self.client.query(&recent_query).fetch_all::<NetworkPair>().await.unwrap_or_default();
        if pairs.is_empty() {
            pairs = self.client.query(&fallback_query).fetch_all::<NetworkPair>().await.unwrap_or_default();
        }

        let mut asset_map: std::collections::HashMap<String, AssetRow> = std::collections::HashMap::new();
        let mut historical_to_active: std::collections::HashMap<String, String> = std::collections::HashMap::new();

        if let Ok(assets) = self.get_assets_by_tenant(tenant_id).await {
            for asset in assets {
                asset_map.insert(asset.ip.clone(), asset.clone());
                if !asset.ip_history.is_empty() && asset.ip_history != "[]" {
                    if let Ok(history) = serde_json::from_str::<Vec<serde_json::Value>>(&asset.ip_history) {
                        for h in history {
                            if let Some(old_ip) = h.get("ip").and_then(|v| v.as_str()) {
                                historical_to_active.insert(old_ip.to_string(), asset.ip.clone());
                            }
                        }
                    }
                }
            }
        }

        let resolve_ip = |raw_ip: &String| -> String {
            historical_to_active.get(raw_ip).cloned().unwrap_or_else(|| raw_ip.clone())
        };

        let mut pair_map: std::collections::HashMap<(String, String), NetworkPair> = std::collections::HashMap::new();
        for p in pairs {
            let src = resolve_ip(&p.src_ip);
            let dst = resolve_ip(&p.dst_ip);
            if src == dst { continue; }
            let entry = pair_map.entry((src.clone(), dst.clone())).or_insert_with(|| NetworkPair {
                src_ip: src, dst_ip: dst, connections: 0, protocols: Vec::new()
            });
            entry.connections += p.connections;
            for proto in p.protocols {
                if !entry.protocols.contains(&proto) { entry.protocols.push(proto); }
            }
        }
        let pairs: Vec<NetworkPair> = pair_map.into_values().collect();

        let is_internal_fn = |ip: &str| -> bool {
            if ip.starts_with("10.") || ip.starts_with("192.168.") { return true; }
            if ip.starts_with("172.") {
                let parts: Vec<&str> = ip.split('.').collect();
                if parts.len() >= 2 {
                    if let Ok(second) = parts[1].parse::<u8>() {
                        return second >= 16 && second <= 31;
                    }
                }
            }
            false
        };

        let is_top_mode = mode.unwrap_or("") == "top";
        let mut top_ips = std::collections::HashSet::new();

        if is_top_mode {
            let limit_n = limit.unwrap_or(25);
            let mut ip_counts: std::collections::HashMap<String, u64> = std::collections::HashMap::new();
            for p in &pairs {
                *ip_counts.entry(p.src_ip.clone()).or_insert(0) += p.connections;
                *ip_counts.entry(p.dst_ip.clone()).or_insert(0) += p.connections;
            }
            let mut ip_list: Vec<_> = ip_counts.into_iter().collect();
            ip_list.sort_by(|a, b| b.1.cmp(&a.1));
            top_ips = ip_list.into_iter().take(limit_n).map(|(ip, _)| ip).collect();
        }

        let mut internal_members = std::collections::HashSet::new();
        let mut external_members = std::collections::HashSet::new();

        let mut external_ips: Vec<String> = Vec::new();
        for pair in &pairs {
            if !is_internal_fn(&pair.src_ip) { external_ips.push(pair.src_ip.clone()); }
            if !is_internal_fn(&pair.dst_ip) { external_ips.push(pair.dst_ip.clone()); }
        }

        #[derive(clickhouse::Row, serde::Deserialize)]
        struct PassiveDnsRow {
            ip: String,
            primary_domain: String,
            all_domains: Vec<String>,
        }
        let mut passive_dns_map: std::collections::HashMap<String, PassiveDnsRow> = std::collections::HashMap::new();

        if !external_ips.is_empty() {
            let items = external_ips.iter().map(|v| format!("'{}'", sql_escape(v))).collect::<Vec<_>>().join(",");
            let dns_query = format!("
                SELECT ip,
                    argMax(domain, total_hits) AS primary_domain,
                    groupUniqArray(domain) AS all_domains
                FROM (
                    SELECT ip, domain, sum(hit_count) AS total_hits
                    FROM ndr.passive_dns
                    WHERE ip IN ({}) AND last_seen > now() - INTERVAL 30 DAY
                    GROUP BY ip, domain
                )
                GROUP BY ip
            ", items);
            if let Ok(dns_rows) = self.client.query(&dns_query).fetch_all::<PassiveDnsRow>().await {
                for r in dns_rows {
                    passive_dns_map.insert(r.ip.clone(), r);
                }
            }
        }

        struct DomainGroup {
            base_domain: String,
            observed_domains: std::collections::HashSet<String>,
            member_ips: std::collections::HashSet<String>,
        }
        let mut domain_groups: std::collections::HashMap<String, DomainGroup> = std::collections::HashMap::new();

        let mut remap_ip = |ip: &String| -> String {
            if is_internal_fn(ip) {
                if is_top_mode && !top_ips.contains(ip) {
                    internal_members.insert(ip.clone());
                    return "cluster:internal".to_string();
                }
                return ip.clone();
            } else {
                let group_id = if let Some(dns) = passive_dns_map.get(ip) {
                    let base = get_base_domain(&dns.primary_domain);
                    let gid = format!("domain:{}", base);
                    let group = domain_groups.entry(gid.clone()).or_insert_with(|| DomainGroup {
                        base_domain: base.clone(),
                        observed_domains: std::collections::HashSet::new(),
                        member_ips: std::collections::HashSet::new(),
                    });
                    group.member_ips.insert(ip.clone());
                    group.observed_domains.insert(dns.primary_domain.clone());
                    for d in &dns.all_domains { group.observed_domains.insert(d.clone()); }
                    gid
                } else {
                    ip.clone()
                };
                if is_top_mode && !top_ips.contains(ip) {
                    external_members.insert(group_id.clone());
                    return "cluster:external".to_string();
                }
                return group_id;
            }
        };

        let mut clustered_pairs: std::collections::HashMap<(String, String), (u64, std::collections::HashSet<String>)> = std::collections::HashMap::new();
        for pair in &pairs {
            let src = remap_ip(&pair.src_ip);
            let dst = remap_ip(&pair.dst_ip);
            if src == dst { continue; }
            let entry = clustered_pairs.entry((src.clone(), dst.clone())).or_insert_with(|| (0, std::collections::HashSet::new()));
            entry.0 += pair.connections;
            for p in &pair.protocols { entry.1.insert(p.clone()); }
        }

        let mut nodes: std::collections::HashMap<String, serde_json::Value> = std::collections::HashMap::new();
        let mut edges: Vec<serde_json::Value> = Vec::new();

        let enrich_node = |id: &str| -> serde_json::Value {
            let is_internal = is_internal_fn(id);
            if id == "cluster:internal" {
                return serde_json::json!({"id": id, "label": format!("{} more internal hosts", internal_members.len()), "type": "cluster", "is_internal": true, "member_ips": internal_members.iter().collect::<Vec<_>>()});
            } else if id == "cluster:external" {
                return serde_json::json!({"id": id, "label": format!("{} more external hosts", external_members.len()), "type": "cluster", "is_internal": false, "member_ips": external_members.iter().collect::<Vec<_>>()});
            }
            if id.starts_with("domain:") {
                if let Some(group) = domain_groups.get(id) {
                    return serde_json::json!({"id": id, "label": group.base_domain, "type": "domain", "is_internal": false, "primary_domain": group.base_domain, "all_domains": group.observed_domains.iter().collect::<Vec<_>>(), "member_ips": group.member_ips.iter().collect::<Vec<_>>()});
                }
            }
            if let Some(asset) = asset_map.get(id) {
                let label = if !asset.custom_name.is_empty() { asset.custom_name.clone() } else if !asset.hostname.is_empty() { asset.hostname.clone() } else { id.to_string() };
                serde_json::json!({"id": id, "label": label, "active_ip": id, "ip_history": asset.ip_history, "mac": asset.mac, "type": asset.device_type, "vendor": asset.vendor, "os_guess": asset.os_guess, "is_internal": is_internal})
            } else {
                serde_json::json!({"id": id, "label": id, "active_ip": id, "ip_history": "[]", "type": if is_internal { "unknown" } else { "external" }, "is_internal": is_internal, "primary_domain": null, "all_domains": []})
            }
        };

        for ((src, dst), (conn, protos)) in clustered_pairs {
            nodes.entry(src.clone()).or_insert_with(|| enrich_node(&src));
            nodes.entry(dst.clone()).or_insert_with(|| enrich_node(&dst));
            edges.push(serde_json::json!({"source": src, "target": dst, "connections": conn, "protocols": protos.into_iter().collect::<Vec<_>>()}));
        }

        let total_nodes = nodes.len();
        let total_edges = edges.len();
        Ok(serde_json::json!({"nodes": nodes.values().collect::<Vec<_>>(), "edges": edges, "total_nodes": total_nodes, "total_edges": total_edges}))
    }

    pub async fn get_network_map_node(
        &self, tenant_id: &str, target_ip: &str, sensor_ids: &[String]
    ) -> anyhow::Result<serde_json::Value> {
        let db_name = tenant_db(tenant_id);
        let safe_ip = sql_escape(target_ip);
        let sf = Self::sensor_filter(sensor_ids);
        let query = format!("
            SELECT src_ip, dst_ip,
                count() as connections,
                groupArray(DISTINCT proto) as protocols
            FROM {db}.ndr_events
            WHERE tenant_id = '{tenant}' AND (src_ip = '{ip}' OR dst_ip = '{ip}')
              AND src_ip != '' AND dst_ip != ''{sf}
            GROUP BY src_ip, dst_ip
            ORDER BY connections DESC
            LIMIT 500",
            db = db_name, tenant = sql_escape(tenant_id), ip = safe_ip, sf = sf);

        let pairs = self.client.query(&query).fetch_all::<NetworkPair>().await.unwrap_or_default();

        let mut asset_map: std::collections::HashMap<String, AssetRow> = std::collections::HashMap::new();
        let mut historical_to_active: std::collections::HashMap<String, String> = std::collections::HashMap::new();

        if let Ok(assets) = self.get_assets_by_tenant(tenant_id).await {
            for asset in assets {
                asset_map.insert(asset.ip.clone(), asset.clone());
                if !asset.ip_history.is_empty() && asset.ip_history != "[]" {
                    if let Ok(history) = serde_json::from_str::<Vec<serde_json::Value>>(&asset.ip_history) {
                        for h in history {
                            if let Some(old_ip) = h.get("ip").and_then(|v| v.as_str()) {
                                historical_to_active.insert(old_ip.to_string(), asset.ip.clone());
                            }
                        }
                    }
                }
            }
        }

        let resolve_ip = |raw_ip: &String| -> String {
            historical_to_active.get(raw_ip).cloned().unwrap_or_else(|| raw_ip.clone())
        };

        let mut pair_map: std::collections::HashMap<(String, String), NetworkPair> = std::collections::HashMap::new();
        for p in pairs {
            let src = resolve_ip(&p.src_ip);
            let dst = resolve_ip(&p.dst_ip);
            if src == dst { continue; }
            let entry = pair_map.entry((src.clone(), dst.clone())).or_insert_with(|| NetworkPair {
                src_ip: src, dst_ip: dst, connections: 0, protocols: Vec::new()
            });
            entry.connections += p.connections;
            for proto in p.protocols {
                if !entry.protocols.contains(&proto) { entry.protocols.push(proto); }
            }
        }
        let pairs: Vec<NetworkPair> = pair_map.into_values().collect();

        let is_internal_fn = |ip: &str| -> bool {
            if ip.starts_with("10.") || ip.starts_with("192.168.") { return true; }
            if ip.starts_with("172.") {
                let parts: Vec<&str> = ip.split('.').collect();
                if parts.len() >= 2 {
                    if let Ok(second) = parts[1].parse::<u8>() {
                        return second >= 16 && second <= 31;
                    }
                }
            }
            false
        };

        let mut nodes: std::collections::HashMap<String, serde_json::Value> = std::collections::HashMap::new();
        let mut edges: Vec<serde_json::Value> = Vec::new();

        let enrich_node = |ip: &str| -> serde_json::Value {
            let is_internal = is_internal_fn(ip);
            if let Some(asset) = asset_map.get(ip) {
                let label = if !asset.custom_name.is_empty() { asset.custom_name.clone() } else if !asset.hostname.is_empty() { asset.hostname.clone() } else { ip.to_string() };
                serde_json::json!({"id": ip, "label": label, "active_ip": ip, "ip_history": asset.ip_history, "mac": asset.mac, "type": asset.device_type, "vendor": asset.vendor, "os_guess": asset.os_guess, "is_internal": is_internal})
            } else {
                serde_json::json!({"id": ip, "label": ip, "active_ip": ip, "ip_history": "[]", "type": if is_internal { "unknown" } else { "external" }, "is_internal": is_internal})
            }
        };

        for pair in pairs {
            nodes.entry(pair.src_ip.clone()).or_insert_with(|| enrich_node(&pair.src_ip));
            nodes.entry(pair.dst_ip.clone()).or_insert_with(|| enrich_node(&pair.dst_ip));
            edges.push(serde_json::json!({"source": pair.src_ip, "target": pair.dst_ip, "connections": pair.connections, "protocols": pair.protocols}));
        }

        Ok(serde_json::json!({"nodes": nodes.values().collect::<Vec<_>>(), "edges": edges, "total_nodes": nodes.len(), "total_edges": edges.len()}))
    }

    pub async fn search_network_map(
        &self, tenant_id: &str, q: &str, sensor_ids: &[String]
    ) -> anyhow::Result<Vec<String>> {
        #[derive(clickhouse::Row, serde::Deserialize)]
        struct SearchRow { ip: String }

        let db_name = tenant_db(tenant_id);
        let safe_q = sql_escape(q);
        let sf = Self::sensor_filter(sensor_ids);
        let sensor_subquery = if sf.is_empty() {
            String::new()
        } else {
            format!(
                " AND ip IN (SELECT DISTINCT arrayJoin([src_ip, dst_ip]) FROM {db}.ndr_events WHERE 1=1{sf})",
                db = db_name, sf = sf
            )
        };
        let query = format!("
            SELECT ip FROM (
                SELECT DISTINCT ip FROM {db}.assets
                WHERE (ip ILIKE '%{q}%' OR hostname ILIKE '%{q}%' OR custom_name ILIKE '%{q}%' OR ip_history ILIKE '%{q}%'){sub}
                UNION ALL
                SELECT DISTINCT ip FROM ndr.passive_dns
                WHERE domain ILIKE '%{q}%'{sub}
            ) LIMIT 50",
            db = db_name, q = safe_q, sub = sensor_subquery);

        let rows = self.client.query(&query).fetch_all::<SearchRow>().await.unwrap_or_default();
        Ok(rows.into_iter().map(|r| r.ip).collect())
    }

pub async fn create_sensor_key(
    &self,
    tenant_id: &str,
    name: &str,
    key_hash: &str,
    key_prefix: &str,
) -> anyhow::Result<String> {
    let id = uuid::Uuid::new_v4().to_string();
    let query = format!(
        "INSERT INTO ndr.sensor_keys \
         (id, key_hash, key_prefix, tenant_id, name) \
         VALUES ('{}','{}','{}','{}','{}')",
        sql_escape(&id), sql_escape(key_hash), sql_escape(key_prefix), sql_escape(tenant_id), sql_escape(name)
    );
    self.client.query(&query).execute().await?;
    Ok(id)
}

pub async fn validate_sensor_key(
    &self,
    key: &str,
) -> anyhow::Result<Option<String>> {
    // Extract prefix (first 16 chars)
    if key.len() < 16 { return Ok(None); }
    let prefix = &key[..16];
    
    // local-central is a local-only sensor — it writes directly via Vector/Kafka
    // and must never authenticate via the HTTP API key path
    if prefix == "local-central" {
        return Ok(None);
    }

    let result = self.client
        .query(&format!(
            "SELECT key_hash, tenant_id, active \
             FROM ndr.sensor_keys FINAL \
             WHERE key_prefix = '{}' \
             AND active = 1 \
             LIMIT 1", sql_escape(prefix)
        ))
        .fetch_all::<(String, String, u8)>()
        .await?;

    if let Some((hash, tenant_id, _)) = result.first() {
        // bcrypt is ~50 ms of pure CPU: run it on the blocking pool so it can
        // never stall the async worker threads that serve every other request.
        let (k, h) = (key.to_string(), hash.clone());
        let ok = tokio::task::spawn_blocking(move || bcrypt::verify(k, &h).unwrap_or(false))
            .await
            .unwrap_or(false);
        if ok {
            return Ok(Some(tenant_id.clone()));
        }
    }
    Ok(None)
}

/// True when `key` matches (bcrypt) a sensor key that has been revoked.
pub async fn is_revoked_sensor_key(&self, key: &str) -> anyhow::Result<bool> {
    if key.len() < 16 { return Ok(false); }
    let prefix = &key[..16];
    let rows = self.client
        .query(&format!(
            "SELECT key_hash FROM ndr.sensor_keys FINAL \
             WHERE key_prefix = '{}' AND active = 0 LIMIT 1",
            sql_escape(prefix)
        ))
        .fetch_all::<String>()
        .await?;
    let Some(hash) = rows.first().cloned() else { return Ok(false) };
    let k = key.to_string();
    Ok(tokio::task::spawn_blocking(move || bcrypt::verify(k, &hash).unwrap_or(false))
        .await
        .unwrap_or(false))
}

pub async fn get_sensor_keys(
    &self,
    tenant_id: &str,
) -> anyhow::Result<Vec<serde_json::Value>> {
    let filter = if tenant_id == "all" {
        "1=1".to_string()
    } else {
        format!("tenant_id='{}'", sql_escape(tenant_id))
    };
    
    let result = self.client
        .query(&format!(
            "SELECT id, key_prefix, tenant_id, \
                    name, hostname, interface_name, \
                    os_name, agent_z_status, agent_s_status, \
                    vector_status, arkime_status, arkime_url, arkime_pass, \
                    active, toString(created_at), \
                    toString(last_seen) \
             FROM ndr.sensor_keys FINAL \
             WHERE {} \
             ORDER BY created_at DESC", filter
        ))
        .fetch_all::<SensorKeyRow>()
        .await?;
    
    Ok(result.iter().map(|r| serde_json::json!({
        "id": r.id,
        "key_prefix": r.key_prefix,
        "tenant_id": r.tenant_id,
        "name": r.name,
        "hostname": r.hostname,
        "interface": r.interface_name,
        "os": r.os_name,
        "agent-z": r.agent_z_status,
        "agent-s": r.agent_s_status,
        "vector": r.vector_status,
        "arkime": r.arkime_status,
        "arkime_url": r.arkime_url,
        "active": r.active == 1,
        "created_at": r.created_at,
        "last_seen": r.last_seen
    })).collect())
}

pub async fn update_sensor_registration(
    &self,
    key_prefix: &str,
    hostname: &str,
    interface_name: &str,
    os_name: &str,
) -> anyhow::Result<()> {
    let key_prefix = sql_escape(key_prefix);
    let hostname = sql_escape(hostname);
    let interface_name = sql_escape(interface_name);
    let os_name = sql_escape(os_name);
    let query = format!(
        "INSERT INTO ndr.sensor_keys \
         (id, key_hash, key_prefix, tenant_id, name, hostname, interface_name, \
          os_name, agent_z_status, agent_s_status, vector_status, active, created_at, last_seen) \
         SELECT id, key_hash, key_prefix, tenant_id, name, '{}', '{}', '{}', \
                agent_z_status, agent_s_status, vector_status, active, created_at, now() \
         FROM ndr.sensor_keys FINAL \
         WHERE key_prefix = '{}' AND active = 1",
        hostname, interface_name, os_name, key_prefix
    );
    self.client.query(&query).execute().await?;
    Ok(())
}

pub async fn update_sensor_heartbeat(
    &self,
    key_prefix: &str,
    agent_z_status: &str,
    agent_s_status: &str,
    vector_status: &str,
    arkime_status: &str,
    arkime_url: &str,
    arkime_pass: &str,
) -> anyhow::Result<()> {
    let key_prefix = sql_escape(key_prefix);
    let agent_z_status = sql_escape(agent_z_status);
    let agent_s_status = sql_escape(agent_s_status);
    let vector_status = sql_escape(vector_status);
    let arkime_status = sql_escape(arkime_status);
    let arkime_url = sql_escape(arkime_url);
    let arkime_pass_esc = sql_escape(arkime_pass);
    let update_pass = if arkime_pass.is_empty() {
        "arkime_pass".to_string()
    } else {
        format!("'{}'", arkime_pass_esc)
    };
    let query = format!(
        "INSERT INTO ndr.sensor_keys \
         (id, key_hash, key_prefix, tenant_id, name, hostname, interface_name, \
          os_name, agent_z_status, agent_s_status, vector_status, \
          arkime_status, arkime_url, arkime_pass, active, created_at, last_seen) \
         SELECT id, key_hash, key_prefix, tenant_id, name, hostname, interface_name, \
                os_name, '{}', '{}', '{}', '{}', '{}', {}, active, created_at, now() \
         FROM ndr.sensor_keys FINAL \
         WHERE key_prefix = '{}' AND active = 1",
        agent_z_status, agent_s_status, vector_status,
        arkime_status, arkime_url, update_pass, key_prefix
    );
    self.client.query(&query).execute().await?;
    Ok(())
}

pub async fn get_arkime_creds(
    &self,
    tenant_id: &str,
) -> anyhow::Result<(String, String)> {
    let tenant_id_esc = sql_escape(tenant_id);

    // Query sensor_keys — ignore errors (e.g. arkime_pass column not yet migrated)
    // so the env var fallback below is always reachable
    let db_creds = self.client
        .query(&format!(
            "SELECT arkime_url, arkime_pass FROM ndr.sensor_keys FINAL \
             WHERE tenant_id = '{}' AND active = 1 AND arkime_url != '' \
             ORDER BY last_seen DESC LIMIT 1",
            tenant_id_esc
        ))
        .fetch_all::<(String, String)>()
        .await
        .unwrap_or_default();

    if let Some(creds) = db_creds.into_iter().next() {
        if !creds.0.is_empty() {
            return Ok(creds);
        }
    }

    // On-premise fallback: read from environment (set by install.sh for default tenant)
    if tenant_id == "default" {
        let url  = std::env::var("ARKIME_URL").unwrap_or_default();
        let pass = std::env::var("ARKIME_PASS").unwrap_or_default();
        if !url.is_empty() {
            return Ok((url, pass));
        }
    }

    Ok((String::new(), String::new()))
}

pub async fn get_arkime_url(
    &self,
    tenant_id: &str,
) -> anyhow::Result<String> {
    let tenant_id = sql_escape(tenant_id);
    let result = self.client
        .query(&format!(
            "SELECT arkime_url FROM ndr.sensor_keys FINAL \
             WHERE tenant_id = '{}' AND active = 1 AND arkime_url != '' \
             ORDER BY last_seen DESC LIMIT 1",
            tenant_id
        ))
        .fetch_all::<String>()
        .await?;
    Ok(result.into_iter().next().unwrap_or_default())
}

pub async fn save_arkime_url(
    &self,
    tenant_id: &str,
    arkime_url: &str,
) -> anyhow::Result<()> {
    let tenant_id = sql_escape(tenant_id);
    let arkime_url = sql_escape(arkime_url);
    self.client
        .query(&format!(
            "ALTER TABLE ndr.sensor_keys \
             UPDATE arkime_url = '{}' \
             WHERE tenant_id = '{}' AND active = 1",
            arkime_url, tenant_id
        ))
        .execute()
        .await?;
    Ok(())
}

pub async fn get_pcap_sessions(
    &self,
    tenant_id: &str,
    community_id: Option<&str>,
    src_ip: Option<&str>,
    limit: u32,
    sensor_ids: &[String],
) -> anyhow::Result<Vec<serde_json::Value>> {
    let db = tenant_db(tenant_id);
    let tenant_id_esc = sql_escape(tenant_id);
    let mut conditions = format!("tenant_id = '{}'", tenant_id_esc);
    if let Some(cid) = community_id {
        conditions.push_str(&format!(" AND community_id = '{}'", sql_escape(cid)));
    }
    if let Some(ip) = src_ip {
        let ip = sql_escape(ip);
        conditions.push_str(&format!(" AND (src_ip = '{}' OR dst_ip = '{}')", ip, ip));
    }
    if !sensor_ids.is_empty() {
        let list = sensor_ids.iter().map(|s| format!("'{}'", sql_escape(s))).collect::<Vec<_>>().join(",");
        conditions.push_str(&format!(" AND sensor_host IN ({})", list));
    }
    let query = format!(
        "SELECT session_id, any(community_id), any(src_ip), any(dst_ip), \
                any(src_port), any(dst_port), any(proto), \
                toString(any(start_time)), toString(any(end_time)), \
                any(bytes), any(packets), any(arkime_url), any(sensor_host), any(file_path) \
         FROM {}.pcap_sessions \
         WHERE {} \
         GROUP BY session_id \
         ORDER BY any(start_time) DESC \
         LIMIT {}",
        db, conditions, limit
    );
    let rows = self.client
        .query(&query)
        .fetch_all::<PcapSessionRow>()
        .await?;
    Ok(rows.iter().map(|r| json!({
        "session_id":   r.session_id,
        "community_id": r.community_id,
        "src_ip":       r.src_ip,
        "dst_ip":       r.dst_ip,
        "src_port":     r.src_port,
        "dst_port":     r.dst_port,
        "proto":        r.proto,
        "start_time":   r.start_time,
        "end_time":     r.end_time,
        "bytes":        r.bytes,
        "packets":      r.packets,
        "arkime_url":   r.arkime_url,
        "sensor_host":  r.sensor_host,
        "file_path":    r.file_path
    })).collect())
}

pub async fn save_pcap_session(
    &self,
    tenant_id: &str,
    session_id: &str,
    community_id: &str,
    src_ip: &str,
    dst_ip: &str,
    src_port: u16,
    dst_port: u16,
    proto: &str,
    bytes: u64,
    arkime_url: &str,
    file_path: &str,
    sensor_host: &str,
) -> anyhow::Result<()> {
    let db = tenant_db(tenant_id);
    // Skip insert if this session_id is already stored (prevents duplicate rows
    // from repeated Arkime live-queries on the same sessions)
    let exists_query = format!(
        "SELECT count() FROM {}.pcap_sessions \
         WHERE session_id = '{}' AND tenant_id = '{}'",
        db, sql_escape(session_id), sql_escape(tenant_id)
    );
    let count: Vec<u64> = self.client.query(&exists_query).fetch_all().await?;
    if count.into_iter().next().unwrap_or(0) > 0 {
        return Ok(());
    }

    let query = format!(
        "INSERT INTO {}.pcap_sessions \
         (session_id, community_id, src_ip, dst_ip, src_port, dst_port, \
          proto, start_time, end_time, bytes, packets, arkime_url, \
          tenant_id, sensor_host, file_path) \
         VALUES ('{}', '{}', '{}', '{}', {}, {}, '{}', now(), now(), \
                 {}, 0, '{}', '{}', '{}', '{}')",
        db,
        sql_escape(session_id), sql_escape(community_id),
        sql_escape(src_ip), sql_escape(dst_ip),
        src_port, dst_port, sql_escape(proto),
        bytes, sql_escape(arkime_url), sql_escape(tenant_id),
        sql_escape(sensor_host), sql_escape(file_path)
    );
    self.client.query(&query).execute().await?;
    Ok(())
}

/// Re-insert all pcap_sessions rows matching community_id with file_path set.
/// ReplacingMergeTree keeps the row with the latest start_time, so inserting
/// now() makes the updated row win after the next FINAL merge.
pub async fn update_pcap_file_path_by_community_id(
    &self,
    tenant_id: &str,
    community_id: &str,
    file_path: &str,
) -> anyhow::Result<()> {
    let db = tenant_db(tenant_id);
    #[derive(clickhouse::Row, serde::Deserialize)]
    struct Row {
        session_id:  String,
        community_id: String,
        src_ip:      String,
        dst_ip:      String,
        src_port:    u16,
        dst_port:    u16,
        proto:       String,
        bytes:       u64,
        packets:     u64,
        arkime_url:  String,
        sensor_host: String,
    }
    let rows = self.client.query(&format!(
        "SELECT session_id, community_id, src_ip, dst_ip, src_port, dst_port, \
                proto, bytes, packets, arkime_url, sensor_host \
         FROM {}.pcap_sessions FINAL \
         WHERE tenant_id = '{}' AND community_id = '{}' AND file_path = ''",
        db, sql_escape(tenant_id), sql_escape(community_id)
    )).fetch_all::<Row>().await?;

    for r in rows {
        let q = format!(
            "INSERT INTO {}.pcap_sessions \
             (session_id, community_id, src_ip, dst_ip, src_port, dst_port, \
              proto, start_time, end_time, bytes, packets, arkime_url, \
              tenant_id, sensor_host, file_path) \
             VALUES ('{}','{}','{}','{}',{},{},'{}',now(),now(),{},{},'{}','{}','{}','{}')",
            db,
            sql_escape(&r.session_id), sql_escape(&r.community_id),
            sql_escape(&r.src_ip), sql_escape(&r.dst_ip),
            r.src_port, r.dst_port, sql_escape(&r.proto),
            r.bytes, r.packets,
            sql_escape(&r.arkime_url), sql_escape(tenant_id),
            sql_escape(&r.sensor_host), sql_escape(file_path)
        );
        let _ = self.client.query(&q).execute().await;
    }
    Ok(())
}

pub async fn get_pcap_file_path(
    &self,
    tenant_id: &str,
    session_id: &str,
) -> anyhow::Result<String> {
    let db = tenant_db(tenant_id);
    let result = self.client
        .query(&format!(
            "SELECT file_path FROM {}.pcap_sessions \
             WHERE session_id = '{}' AND tenant_id = '{}' \
             LIMIT 1",
            db, sql_escape(session_id), sql_escape(tenant_id)
        ))
        .fetch_all::<String>()
        .await?;
    Ok(result.into_iter().next().unwrap_or_default())
}

pub async fn queue_pcap_request(
    &self,
    tenant_id: &str,
    community_id: &str,
) -> anyhow::Result<()> {
    // Only valid network community IDs (format: "1:<base64>=")
    if !community_id.starts_with("1:") {
        return Ok(());
    }

    let db = tenant_db(tenant_id);
    #[derive(clickhouse::Row, serde::Deserialize)]
    struct CntRow { cnt: u64 }
    let rows = self.client.query(&format!(
        "SELECT count() as cnt FROM {}.pcap_pending FINAL \
         WHERE community_id = '{}' AND tenant_id = '{}' \
         AND requested_at > now() - INTERVAL 24 HOUR",
        db, sql_escape(community_id), sql_escape(tenant_id)
    )).fetch_all::<CntRow>().await.unwrap_or_default();
    if rows.first().map(|r| r.cnt).unwrap_or(0) > 0 {
        return Ok(());
    }

    self.client
        .query(&format!(
            "INSERT INTO {}.pcap_pending \
             (community_id, tenant_id, fulfilled) VALUES \
             ('{}', '{}', 0)",
            db, sql_escape(community_id), sql_escape(tenant_id)
        ))
        .execute()
        .await?;
    Ok(())
}

pub async fn get_pending_pcap_requests(
    &self,
    tenant_id: &str,
) -> anyhow::Result<Vec<String>> {
    let db = tenant_db(tenant_id);
    let rows = self.client
        .query(&format!(
            "SELECT community_id FROM {}.pcap_pending FINAL \
             WHERE tenant_id = '{}' AND fulfilled = 0 \
             AND requested_at > now() - INTERVAL 1 DAY",
            db, sql_escape(tenant_id)
        ))
        .fetch_all::<String>()
        .await
        .unwrap_or_default();
    Ok(rows)
}

pub async fn mark_pcap_fulfilled(
    &self,
    tenant_id: &str,
    community_id: &str,
) -> anyhow::Result<()> {
    // INSERT a new row with fulfilled=1 and requested_at=now().
    // ReplacingMergeTree(requested_at) keeps the row with the largest
    // requested_at — this row wins over the original request row, so
    // FINAL queries immediately see fulfilled=1 without waiting for
    // async ALTER TABLE mutations to complete.
    let db = tenant_db(tenant_id);
    self.client
        .query(&format!(
            "INSERT INTO {}.pcap_pending \
             (community_id, tenant_id, requested_at, fulfilled, fulfilled_at) \
             VALUES ('{}', '{}', now(), 1, now())",
            db, sql_escape(community_id), sql_escape(tenant_id)
        ))
        .execute()
        .await?;
    Ok(())
}

pub async fn revoke_sensor_key(
    &self,
    id: &str,
) -> anyhow::Result<()> {
    // mutations_sync=1: block until applied - found via TC-070 re-test that
    // a revoke reported success while a follow-up list call still showed
    // active=true for a few moments after.
    self.client
        .query(&format!(
            "ALTER TABLE ndr.sensor_keys \
             UPDATE active = 0 \
             WHERE id = '{}' SETTINGS mutations_sync=1", sql_escape(id)
        ))
        .execute().await?;
    Ok(())
}

/// Fetch the key_prefix for a sensor key by its UUID id.
/// Used to invalidate the Redis cache immediately on revocation,
/// since plain api_keys are never stored (only bcrypt hashes).
pub async fn get_sensor_key_prefix_by_id(
    &self,
    id: &str,
) -> anyhow::Result<Option<String>> {
    #[derive(clickhouse::Row, serde::Deserialize)]
    struct Row { key_prefix: String }

    let rows = self.client
        .query(&format!(
            "SELECT key_prefix FROM ndr.sensor_keys FINAL \
             WHERE id = '{}' LIMIT 1",
            sql_escape(id)
        ))
        .fetch_all::<Row>()
        .await?;

    Ok(rows.into_iter().next().map(|r| r.key_prefix))
}

/// Owning tenant of a sensor key by its UUID id — lets a caller confirm a
/// tenant_admin only ever acts on their own tenant's key (TC-070: revoking
/// used to be super_admin-only with no creator/tenant exception at all).
pub async fn get_sensor_key_tenant_by_id(
    &self,
    id: &str,
) -> anyhow::Result<Option<String>> {
    #[derive(clickhouse::Row, serde::Deserialize)]
    struct Row { tenant_id: String }

    let rows = self.client
        .query(&format!(
            "SELECT tenant_id FROM ndr.sensor_keys FINAL \
             WHERE id = '{}' LIMIT 1",
            sql_escape(id)
        ))
        .fetch_all::<Row>()
        .await?;

    Ok(rows.into_iter().next().map(|r| r.tenant_id))
}

pub async fn reactivate_sensor_key(
    &self,
    id: &str,
) -> anyhow::Result<()> {
    self.client
        .query(&format!(
            "ALTER TABLE ndr.sensor_keys \
             UPDATE active = 1 \
             WHERE id = '{}'", sql_escape(id)
        ))
        .execute().await?;
    Ok(())
}

pub async fn active_sensor_exists(
    &self,
    tenant_id: &str,
    sensor_id: &str,
) -> anyhow::Result<bool> {
    let tenant_id = sql_escape(tenant_id);
    let sensor_id = sql_escape(sensor_id);
    let result = self.client
        .query(&format!(
            "SELECT id FROM ndr.sensor_keys FINAL \
             WHERE tenant_id = '{}' \
             AND key_prefix = '{}' \
             AND active = 1 \
             LIMIT 1",
            tenant_id, sensor_id
        ))
        .fetch_all::<String>()
        .await?;

    Ok(!result.is_empty())
}

pub async fn set_sensor_command(
    &self,
    tenant_id: &str,
    sensor_id: &str,
    command: &str,
) -> anyhow::Result<()> {
    let db = tenant_db(tenant_id);
    let id = uuid::Uuid::new_v4().to_string();
    let tenant_id = sql_escape(tenant_id);
    let sensor_id = sql_escape(sensor_id);
    let command = sql_escape(command);
    let query = format!(
        "INSERT INTO {}.sensor_commands \
         (id, tenant_id, sensor_id, command, status) \
         VALUES ('{}', '{}', '{}', '{}', 'pending')",
        db, id, tenant_id, sensor_id, command
    );
    self.client.query(&query).execute().await?;
    Ok(())
}

pub async fn get_sensor_command(
    &self,
    tenant_id: &str,
    sensor_id: &str,
) -> anyhow::Result<(String, String)> {
    let db = tenant_db(tenant_id);
    let tenant_id = sql_escape(tenant_id);
    let sensor_id = sql_escape(sensor_id);
    let result = self.client
        .query(&format!(
            "SELECT command, sensor_id FROM {}.sensor_commands FINAL \
             WHERE tenant_id = '{}' \
             AND (sensor_id = '{}' OR sensor_id = '') \
             AND status = 'pending' \
             ORDER BY if(sensor_id = '{}', 0, 1), created_at DESC \
             LIMIT 1",
            db, tenant_id, sensor_id, sensor_id
        ))
        .fetch_all::<(String, String)>()
        .await?;

    Ok(result.first()
        .map(|r| (r.0.clone(), r.1.clone()))
        .unwrap_or_default())
}

pub async fn clear_sensor_command(
    &self,
    tenant_id: &str,
    sensor_id: &str,
) -> anyhow::Result<()> {
    let db = tenant_db(tenant_id);
    let tenant_id = sql_escape(tenant_id);
    let sensor_id = sql_escape(sensor_id);
    self.client
        .query(&format!(
            "ALTER TABLE {}.sensor_commands \
             UPDATE status = 'done' \
             WHERE tenant_id = '{}' \
             AND sensor_id = '{}' \
             AND status = 'pending'",
            db, tenant_id, sensor_id
        ))
        .execute().await?;
    Ok(())
}

    // ── AI suppressions ──────────────────────────────────────────────────

    /// Returns true if src_ip has ANY confirmed threat-intel hit in the last 24h.
    /// Used to hard-block suppression for compromised hosts — code enforcement,
    /// not AI prompt rules which LLMs can silently ignore.
    /// How many alerts in the last 24 h involving `ip` matched a threat-intelligence feed, and up to
    /// five of the peer addresses, so the AI can be given the facts instead of a verdict.
    pub async fn host_threat_intel_summary(&self, tenant_id: &str, ip: &str) -> (u64, Vec<String>) {
        let db = tenant_db(tenant_id);
        let safe_ip = sql_escape(ip);
        #[derive(clickhouse::Row, serde::Deserialize)]
        struct TiRow { n: u64, peers: Vec<String> }
        self.client
            .query(&format!(
                "SELECT count() AS n, groupUniqArray(5)(if(src_ip = '{ip}', dst_ip, src_ip)) AS peers \
                 FROM {db}.ndr_hits FINAL \
                 WHERE (src_ip = '{ip}' OR dst_ip = '{ip}') \
                 AND threat_intel = 1 \
                 AND timestamp > now() - INTERVAL 24 HOUR",
                db = db, ip = safe_ip
            ))
            .fetch_one::<TiRow>()
            .await
            .map(|r| (r.n, r.peers))
            .unwrap_or((0, Vec::new()))
    }

    /// Names an address was seen under in DNS traffic (newest first).
    pub async fn passive_dns_names_for_ip(&self, ip: &str, limit: usize) -> Vec<String> {
        self.client
            .query(&format!(
                "SELECT domain FROM ndr.passive_dns FINAL WHERE ip = '{}' ORDER BY last_seen DESC LIMIT {}",
                sql_escape(ip), limit
            ))
            .fetch_all::<String>()
            .await
            .unwrap_or_default()
    }

    pub async fn host_has_threat_intel_hit(&self, tenant_id: &str, ip: &str) -> bool {
        let db = tenant_db(tenant_id);
        let safe_ip = sql_escape(ip);
        let count: u64 = self.client
            .query(&format!(
                "SELECT count() FROM {}.ndr_hits FINAL \
                 WHERE (src_ip = '{}' OR dst_ip = '{}') \
                 AND threat_intel = 1 \
                 AND timestamp > now() - INTERVAL 24 HOUR",
                db, safe_ip, safe_ip
            ))
            .fetch_one::<u64>()
            .await
            .unwrap_or(0);
        count > 0
    }

    pub async fn save_ai_suppression(
        &self,
        tenant_id:      &str,
        sig_id:         u64,
        sig_name:       &str,
        suppress_type:  &str,        // "by_dst" | "by_src" | "by_sid"
        suppress_ip:    &str,
        src_ip:         &str,
        dst_ip:         &str,
        community_id:   &str,
        ai_reason:      &str,
        ai_confidence:  u8,
        sensor_id:      &str,
        expires_at:     Option<u32>, // Unix timestamp; None = no explicit expiry (table TTL applies)
        suppress_scope: &str,        // "individual" | "group"
    ) -> anyhow::Result<()> {
        let db = tenant_db(tenant_id);
        let expires_expr = match expires_at {
            Some(ts) => format!("toDateTime({})", ts),
            None     => "NULL".to_string(),
        };
        self.client.query(&format!(
            "INSERT INTO {db}.ai_suppressions \
             (id, tenant_id, signature_id, signature_name, suppress_type, suppress_ip, \
              src_ip, dst_ip, community_id, ai_reason, ai_confidence, sensor_id, active, \
              expires_at, suppress_scope) \
             VALUES ('{id}','{tid}',{sig_id},'{sig_name}','{stype}','{sip}',\
                     '{src}','{dst}','{cid}','{reason}',{conf},'{sensor}',1,\
                     {exp},'{scope}')",
            db       = db,
            id       = uuid::Uuid::new_v4(),
            tid      = sql_escape(tenant_id),
            sig_id   = sig_id,
            sig_name = sql_escape(sig_name),
            stype    = sql_escape(suppress_type),
            sip      = sql_escape(suppress_ip),
            src      = sql_escape(src_ip),
            dst      = sql_escape(dst_ip),
            cid      = sql_escape(community_id),
            reason   = sql_escape(ai_reason),
            conf     = ai_confidence,
            sensor   = sql_escape(sensor_id),
            exp      = expires_expr,
            scope    = sql_escape(suppress_scope),
        )).execute().await?;
        // Force immediate deduplication so FINAL queries see the new row without
        // waiting for the background merge (table is tiny so this is cheap).
        let _ = self.client.query(&format!("OPTIMIZE TABLE {db}.ai_suppressions FINAL"))
            .execute().await;
        Ok(())
    }

    /// Returns true if src_ip has an active group suppression matching primary_tag.
    /// Used by Gate 1 in insert_hit_for_tenant to drop suppressed hits before DB write.
    /// Load all active group-suppression signature names for a given src_ip in one query.
    /// Called once per `insert_hit_for_tenant`; results are checked in-memory.
    pub async fn get_active_group_suppressions(
        &self,
        tenant_id: &str,
        src_ip:    &str,
    ) -> std::collections::HashSet<String> {
        if src_ip.is_empty() { return Default::default(); }
        let db  = tenant_db(tenant_id);
        let ip  = sql_escape(src_ip);
        let tid = sql_escape(tenant_id);
        #[derive(clickhouse::Row, serde::Deserialize)]
        struct Row { signature_name: String }
        self.client.query(&format!(
            "SELECT signature_name FROM {db}.ai_suppressions FINAL \
             WHERE active = 1 AND community_id = '' AND suppress_ip = '{ip}' \
               AND (expires_at IS NULL OR expires_at > now()) \
               AND (tenant_id = '{tid}' OR tenant_id = '')",
            db = db, ip = ip, tid = tid,
        )).fetch_all::<Row>().await
          .unwrap_or_default()
          .into_iter()
          .map(|r| r.signature_name)
          .collect()
    }

    pub async fn is_group_suppressed(&self, tenant_id: &str, src_ip: &str, primary_tag: &str) -> bool {
        if src_ip.is_empty() || primary_tag.is_empty() { return false; }
        let db = tenant_db(tenant_id);
        #[derive(clickhouse::Row, serde::Deserialize)]
        struct Cnt { cnt: u64 }
        self.client.query(&format!(
            "SELECT count() as cnt FROM {db}.ai_suppressions FINAL \
             WHERE active = 1 AND community_id = '' AND suppress_ip != '' \
               AND suppress_ip = '{ip}' AND signature_name = '{tag}' \
               AND (expires_at IS NULL OR expires_at > now()) \
               AND (tenant_id = '{tid}' OR tenant_id = '')",
            db  = db,
            ip  = sql_escape(src_ip),
            tag = sql_escape(primary_tag),
            tid = sql_escape(tenant_id),
        )).fetch_all::<Cnt>().await.unwrap_or_default()
          .first().map(|x| x.cnt > 0).unwrap_or(false)
    }

    pub async fn deactivate_ai_suppression(&self, tenant_id: &str, id: &str) -> anyhow::Result<()> {
        let db = tenant_db(tenant_id);
        self.client.query(&format!(
            "ALTER TABLE {}.ai_suppressions UPDATE active = 0 \
             WHERE id = '{}' AND tenant_id = '{}' SETTINGS mutations_sync=1",
            db, sql_escape(id), sql_escape(tenant_id)
        )).execute().await?;
        Ok(())
    }

    pub async fn delete_ai_suppression(&self, tenant_id: &str, id: &str) -> anyhow::Result<()> {
        let db = tenant_db(tenant_id);
        self.client.query(&format!(
            "ALTER TABLE {}.ai_suppressions DELETE \
             WHERE id = '{}' AND tenant_id = '{}' SETTINGS mutations_sync=1",
            db, sql_escape(id), sql_escape(tenant_id)
        )).execute().await?;
        Ok(())
    }

    pub async fn is_ai_suppressed(
        &self,
        tenant_id: &str,
        sig_id:    u64,
        src_ip:    &str,
        dst_ip:    &str,
    ) -> bool {
        let db = tenant_db(tenant_id);
        #[derive(clickhouse::Row, serde::Deserialize)]
        struct Cnt { cnt: u64 }
        let r = self.client.query(&format!(
            "SELECT count() as cnt FROM {}.ai_suppressions FINAL \
             WHERE tenant_id = '{}' AND active = 1 \
             AND (expires_at IS NULL OR expires_at > now()) \
             AND signature_id = {} \
             AND (suppress_type = 'by_sid' \
               OR (suppress_type = 'by_dst' AND suppress_ip = '{}') \
               OR (suppress_type = 'by_src' AND suppress_ip = '{}'))",
            db, sql_escape(tenant_id), sig_id,
            sql_escape(dst_ip), sql_escape(src_ip)
        )).fetch_all::<Cnt>().await.unwrap_or_default();
        r.first().map(|x| x.cnt > 0).unwrap_or(false)
    }

    pub async fn list_ai_suppressions(
        &self,
        tenant_id: &str,
    ) -> anyhow::Result<Vec<serde_json::Value>> {
        let db = tenant_db(tenant_id);
        #[derive(clickhouse::Row, serde::Deserialize)]
        struct Row {
            id: String, sig_id: u64, sig_name: String,
            suppress_type: String, suppress_ip: String,
            src_ip: String, dst_ip: String,
            ai_reason: String, ai_confidence: u8,
            active: u8, created_at: String,
        }
        let rows = self.client.query(&format!(
            "SELECT id, signature_id as sig_id, signature_name as sig_name, \
             suppress_type, suppress_ip, src_ip, dst_ip, \
             ai_reason, ai_confidence, active, toString(created_at) as created_at \
             FROM {}.ai_suppressions FINAL \
             WHERE tenant_id = '{}' \
             ORDER BY created_at DESC LIMIT 100",
            db, sql_escape(tenant_id)
        )).fetch_all::<Row>().await.unwrap_or_default();
        Ok(rows.iter().map(|r| json!({
            "id": r.id, "signature_id": r.sig_id, "signature_name": r.sig_name,
            "suppress_type": r.suppress_type, "suppress_ip": r.suppress_ip,
            "src_ip": r.src_ip, "dst_ip": r.dst_ip,
            "ai_reason": r.ai_reason, "ai_confidence": r.ai_confidence,
            "active": r.active == 1, "created_at": r.created_at
        })).collect())
    }

    //support messages
    pub async fn create_support_message(
        &self,
        tenant_id: &str,
        sender_username: &str,
        sender_role: &str,
        subject: &str,
        category: &str,
        message: &str,
    ) -> anyhow::Result<String> {
        let id = uuid::Uuid::new_v4().to_string();
        self.client
            .query(
                "INSERT INTO ndr.support_messages
                 (id, tenant_id, sender_username, sender_role, subject, category, message)
                 VALUES (?, ?, ?, ?, ?, ?, ?)"
            )
            .bind(&id)
            .bind(tenant_id)
            .bind(sender_username)
            .bind(sender_role)
            .bind(subject)
            .bind(category)
            .bind(message)
            .execute()
            .await?;
        Ok(id)
    }

    pub async fn get_support_messages_for_user(
        &self,
        tenant_id: &str,
        sender_username: &str,
    ) -> anyhow::Result<Vec<serde_json::Value>> {
        let rows = self.client
            .query(
                "SELECT
                    id, tenant_id, sender_username, sender_role, subject, category, message,
                    status, admin_reply, replied_by, forwarded, forwarded_by, deleted,
                    toString(created_at) AS created_at,
                    toString(updated_at) AS updated_at,
                    if(isNull(replied_at), '', toString(assumeNotNull(replied_at))) AS replied_at,
                    if(isNull(forwarded_at), '', toString(assumeNotNull(forwarded_at))) AS forwarded_at
                 FROM ndr.support_messages FINAL
                 WHERE tenant_id = ? AND sender_username = ? AND deleted = 0
                 ORDER BY updated_at DESC"
            )
            .bind(tenant_id)
            .bind(sender_username)
            .fetch_all::<SupportMessageRow>()
            .await?;
        Ok(rows.into_iter().map(support_message_to_json).collect())
    }

    pub async fn get_support_messages_for_tenant(
        &self,
        tenant_id: &str,
    ) -> anyhow::Result<Vec<serde_json::Value>> {
        let rows = self.client
            .query(
                "SELECT
                    id, tenant_id, sender_username, sender_role, subject, category, message,
                    status, admin_reply, replied_by, forwarded, forwarded_by, deleted,
                    toString(created_at) AS created_at,
                    toString(updated_at) AS updated_at,
                    if(isNull(replied_at), '', toString(assumeNotNull(replied_at))) AS replied_at,
                    if(isNull(forwarded_at), '', toString(assumeNotNull(forwarded_at))) AS forwarded_at
                 FROM ndr.support_messages FINAL
                 WHERE tenant_id = ? AND deleted = 0
                 ORDER BY updated_at DESC"
            )
            .bind(tenant_id)
            .fetch_all::<SupportMessageRow>()
            .await?;
        Ok(rows.into_iter().map(support_message_to_json).collect())
    }

    pub async fn get_support_messages_for_super_admin(&self) -> anyhow::Result<Vec<serde_json::Value>> {
        let rows = self.client
            .query(
                "SELECT
                    id, tenant_id, sender_username, sender_role, subject, category, message,
                    status, admin_reply, replied_by, forwarded, forwarded_by, deleted,
                    toString(created_at) AS created_at,
                    toString(updated_at) AS updated_at,
                    if(isNull(replied_at), '', toString(assumeNotNull(replied_at))) AS replied_at,
                    if(isNull(forwarded_at), '', toString(assumeNotNull(forwarded_at))) AS forwarded_at
                 FROM ndr.support_messages FINAL
                 WHERE deleted = 0 AND (forwarded = 1 OR tenant_id = 'default')
                 ORDER BY updated_at DESC"
            )
            .fetch_all::<SupportMessageRow>()
            .await?;
        Ok(rows.into_iter().map(support_message_to_json).collect())
    }

    pub async fn get_support_message_scope(
        &self,
        id: &str,
    ) -> anyhow::Result<Option<(String, String, u8)>> {
        let rows = self.client
            .query(
                "SELECT tenant_id, sender_username, forwarded
                 FROM ndr.support_messages FINAL
                 WHERE id = ? AND deleted = 0
                 LIMIT 1"
            )
            .bind(id)
            .fetch_all::<(String, String, u8)>()
            .await?;
        Ok(rows.into_iter().next())
    }

    pub async fn update_support_status(&self, id: &str, status: &str) -> anyhow::Result<()> {
        self.client
            .query(
                "ALTER TABLE ndr.support_messages
                 UPDATE status = ?
                 WHERE id = ?
                 SETTINGS mutations_sync=1"
            )
            .bind(status)
            .bind(id)
            .execute()
            .await?;
        Ok(())
    }

    pub async fn reply_support_message(
        &self,
        id: &str,
        reply: &str,
        replied_by: &str,
        status: &str,
    ) -> anyhow::Result<()> {
        let now = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S").to_string();
        self.client
            .query(&format!(
                "ALTER TABLE ndr.support_messages
                 UPDATE admin_reply = ?, replied_by = ?, replied_at = toDateTime('{now}'),
                        status = ?
                 WHERE id = ?
                 SETTINGS mutations_sync=1"
            ))
            .bind(reply)
            .bind(replied_by)
            .bind(status)
            .bind(id)
            .execute()
            .await?;
        Ok(())
    }

    pub async fn forward_support_message(&self, id: &str, forwarded_by: &str) -> anyhow::Result<()> {
        let now = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S").to_string();
        self.client
            .query(&format!(
                "ALTER TABLE ndr.support_messages
                 UPDATE forwarded = 1, forwarded_by = ?, forwarded_at = toDateTime('{now}'),
                        status = 'forwarded'
                 WHERE id = ?
                 SETTINGS mutations_sync=1"
            ))
            .bind(forwarded_by)
            .bind(id)
            .execute()
            .await?;
        Ok(())
    }

    pub async fn delete_support_message(&self, id: &str) -> anyhow::Result<()> {
        self.client
            .query(
                "ALTER TABLE ndr.support_messages
                 UPDATE deleted = 1, status = 'deleted'
                 WHERE id = ?
                 SETTINGS mutations_sync=1"
            )
            .bind(id)
            .execute()
            .await?;
        Ok(())
    }

#[cfg(feature = "soar")]
    pub async fn get_native_playbooks(&self, tenant_id: &str) -> anyhow::Result<Vec<crate::soar::SoarNativePlaybook>> {
        let db = tenant_db(tenant_id);
        #[derive(clickhouse::Row, serde::Deserialize)]
        struct PlaybookRow {
            id: String,
            name: String,
            description: String,
            enabled: u8,
            cond_field: String,
            cond_op: String,
            cond_value: String,
            action_type: String,
            action_config: String,
            run_count: u64,
            last_run_ts: Option<u32>,
            created_at_ts: u32,
            updated_at_ts: u32,
        }
        let result = self.client
            .query(&format!("SELECT id, name, description, enabled, cond_field, cond_op, cond_value, action_type, action_config, run_count, toUnixTimestamp(last_run) as last_run_ts, toUnixTimestamp(created_at) as created_at_ts, toUnixTimestamp(updated_at) as updated_at_ts FROM {}.soar_native_playbooks FINAL", db))
            .fetch_all::<PlaybookRow>()
            .await?;
        let tid = tenant_id.to_string();
        Ok(result.into_iter().map(|r| crate::soar::SoarNativePlaybook {
            id: r.id,
            name: r.name,
            description: r.description,
            enabled: r.enabled,
            cond_field: r.cond_field,
            cond_op: r.cond_op,
            cond_value: r.cond_value,
            action_type: r.action_type,
            action_config: r.action_config,
            run_count: r.run_count,
            last_run: r.last_run_ts.map(|t| t.to_string()),
            created_at: r.created_at_ts.to_string(),
            updated_at: r.updated_at_ts.to_string(),
            tenant_id: tid.clone(),
        }).collect())
    }

    pub async fn get_next_case_number(&self, tenant_id: &str) -> String {
        let db = tenant_db(tenant_id);
        let year = chrono::Utc::now().format("%Y").to_string().parse::<u32>().unwrap_or(2026);
        let count = self.client
            .query(&format!(
                "SELECT count() + 1 FROM {}.soar_cases FINAL WHERE toYear(created_at) = {}",
                db, year
            ))
            .fetch_one::<u64>()
            .await
            .unwrap_or(1);
        format!("INC-{}-{:04}", year, count)
    }

    /// Find an existing open case for the same src/dst pair (within last 7 days).
    /// Returns (id, case_number, severity, priority) if one exists.
    pub async fn find_open_case_by_src_dst(
        &self,
        src_ip: &str,
        dst_ip: &str,
        tenant_id: &str,
    ) -> Option<(String, String, String, String)> {
        let db = tenant_db(tenant_id);
        #[derive(clickhouse::Row, serde::Deserialize)]
        struct OpenCaseRow {
            id: String,
            case_number: String,
            severity: String,
            priority: String,
        }
        let query = format!(
            "SELECT id, case_number, severity, priority FROM {db}.soar_cases FINAL \
             WHERE src_ip = '{src}' AND dst_ip = '{dst}' \
             AND status NOT IN ('Closed', 'Resolved', 'False Positive') \
             AND created_at >= now() - INTERVAL 7 DAY \
             ORDER BY created_at DESC LIMIT 1",
            db = db,
            src = sql_escape(src_ip),
            dst = sql_escape(dst_ip),
        );
        self.client.query(&query).fetch_one::<OpenCaseRow>().await.ok()
            .map(|r| (r.id, r.case_number, r.severity, r.priority))
    }

    /// Escalate a case's severity and priority to a higher level.
    pub async fn escalate_case_severity(
        &self,
        id: &str,
        severity: &str,
        priority: &str,
        tenant_id: &str,
    ) -> anyhow::Result<()> {
        let db = tenant_db(tenant_id);
        // INSERT SELECT to avoid "Cannot UPDATE key column updated_at" on ReplacingMergeTree.
        let query = format!(
            "INSERT INTO {db}.soar_cases \
             (id, case_number, title, description, severity, priority, status, assigned_to, \
              src_ip, dst_ip, community_id, tags, tenant_id, created_at, updated_at, closed_at) \
             SELECT id, case_number, title, description, '{sev}', '{pri}', \
                    status, assigned_to, src_ip, dst_ip, community_id, tags, tenant_id, \
                    created_at, now(), closed_at \
             FROM {db}.soar_cases FINAL WHERE id = '{id}'",
            db  = db,
            sev = sql_escape(severity),
            pri = sql_escape(priority),
            id  = sql_escape(id),
        );
        self.client.query(&query).execute().await?;
        Ok(())
    }

#[cfg(feature = "soar")]
    pub async fn insert_soar_case(
        &self,
        id: &str,
        case_number: &str,
        title: &str,
        description: &str,
        severity: &str,
        priority: &str,
        status: &str,
        assigned_to: &str,
        src_ip: &str,
        dst_ip: &str,
        community_id: &str,
        tags: &[String],
        tenant_id: &str,
    ) -> anyhow::Result<()> {
        let db = tenant_db(tenant_id);
        let tags_str = sql_array_literal(tags);
        let query = format!(
            "INSERT INTO {}.soar_cases \
             (id, case_number, title, description, severity, priority, status, assigned_to, src_ip, dst_ip, community_id, tags, tenant_id) \
             VALUES ('{}','{}','{}','{}','{}','{}','{}','{}','{}','{}','{}',{},'{}')",
            db,
            sql_escape(id), sql_escape(case_number), sql_escape(title), sql_escape(description),
            sql_escape(severity), sql_escape(priority), sql_escape(status), sql_escape(assigned_to),
            sql_escape(src_ip), sql_escape(dst_ip), sql_escape(community_id),
            tags_str, sql_escape(tenant_id)
        );
        self.client.query(&query).execute().await?;
        Ok(())
    }

#[cfg(feature = "soar")]
    pub async fn update_soar_case_fields(
        &self,
        id: &str,
        title: &str,
        description: &str,
        assigned_to: &str,
        priority: &str,
        severity: &str,
        tenant_id: &str,
    ) -> anyhow::Result<()> {
        let db = tenant_db(tenant_id);
        // INSERT SELECT to avoid "Cannot UPDATE key column updated_at" on ReplacingMergeTree.
        let query = format!(
            "INSERT INTO {db}.soar_cases \
             (id, case_number, title, description, severity, priority, status, assigned_to, \
              src_ip, dst_ip, community_id, tags, tenant_id, created_at, updated_at, closed_at) \
             SELECT id, case_number, '{title}', '{desc}', '{sev}', '{pri}', \
                    status, '{assigned}', src_ip, dst_ip, community_id, tags, tenant_id, \
                    created_at, now(), closed_at \
             FROM {db}.soar_cases FINAL WHERE id = '{id}'",
            db       = db,
            title    = sql_escape(title),
            desc     = sql_escape(description),
            sev      = sql_escape(severity),
            pri      = sql_escape(priority),
            assigned = sql_escape(assigned_to),
            id       = sql_escape(id),
        );
        self.client.query(&query).execute().await?;
        Ok(())
    }

#[cfg(feature = "soar")]
    pub async fn insert_soar_playbook_run(
        &self,
        run: &crate::soar::SoarPlaybookRun,
    ) -> anyhow::Result<()> {
        let db = tenant_db(&run.tenant_id);
        let query = format!(
            "INSERT INTO {}.soar_playbook_runs \
             (id, playbook_id, playbook_name, hit_id, status, detail, tenant_id) \
             VALUES ('{}','{}','{}','{}','{}','{}','{}')",
            db,
            sql_escape(&run.id), sql_escape(&run.playbook_id), sql_escape(&run.playbook_name),
            sql_escape(&run.hit_id), sql_escape(&run.status), sql_escape(&run.detail),
            sql_escape(&run.tenant_id)
        );
        self.client.query(&query).execute().await?;

        let now = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S").to_string();
        let update = format!(
            "ALTER TABLE {}.soar_native_playbooks \
             UPDATE run_count = run_count + 1, last_run = toDateTime('{}') \
             WHERE id = '{}'",
            db, now, sql_escape(&run.playbook_id)
        );
        let _ = self.client.query(&update).execute().await;
        Ok(())
    }

#[cfg(feature = "soar")]
    pub async fn get_soar_cases(&self, tenant_id: &str, sensor_ids: &[String]) -> anyhow::Result<Vec<serde_json::Value>> {
        let db = tenant_db(tenant_id);
        let sensor_where = if sensor_ids.is_empty() {
            String::new()
        } else {
            let sf = Self::sensor_filter(sensor_ids);
            format!(" WHERE community_id IN (SELECT DISTINCT community_id FROM {db}.ndr_hits FINAL WHERE 1=1{sf})", db = db, sf = sf)
        };
        #[derive(clickhouse::Row, serde::Deserialize)]
        struct CaseRow {
            id: String,
            case_number: String,
            title: String,
            description: String,
            severity: String,
            priority: String,
            status: String,
            assigned_to: String,
            src_ip: String,
            dst_ip: String,
            community_id: String,
            tags: Vec<String>,
            created_at_ts: u32,
            updated_at_ts: u32,
            closed_at_ts: Option<u32>,
        }
        let result = self.client
            .query(&format!("SELECT id, case_number, title, description, severity, priority, status, assigned_to, src_ip, dst_ip, community_id, tags, toUnixTimestamp(created_at) as created_at_ts, toUnixTimestamp(updated_at) as updated_at_ts, toUnixTimestamp(closed_at) as closed_at_ts FROM {db}.soar_cases FINAL{sensor_where} ORDER BY created_at DESC", db = db, sensor_where = sensor_where))
            .fetch_all::<CaseRow>()
            .await?;
        Ok(result.into_iter().map(|r| json!({
            "id": r.id, "case_number": r.case_number, "title": r.title, "description": r.description,
            "severity": r.severity, "priority": r.priority, "status": r.status,
            "assigned_to": r.assigned_to, "src_ip": r.src_ip, "dst_ip": r.dst_ip,
            "community_id": r.community_id, "tags": r.tags, "created_at": r.created_at_ts,
            "updated_at": r.updated_at_ts, "closed_at": r.closed_at_ts
        })).collect())
    }

#[cfg(feature = "soar")]
    pub async fn update_soar_case_status(&self, id: &str, status: &str, tenant_id: &str) -> anyhow::Result<()> {
        let db = tenant_db(tenant_id);
        // INSERT SELECT: ReplacingMergeTree(updated_at) forbids ALTER TABLE UPDATE on the version key.
        // Insert a new row with updated status/closed_at; the engine deduplicates on next merge.
        let closed_at_expr = match status {
            "Resolved" | "Closed" | "False Positive" => "now()".to_string(),
            _ => "closed_at".to_string(),
        };
        let query = format!(
            "INSERT INTO {db}.soar_cases \
             (id, case_number, title, description, severity, priority, status, assigned_to, \
              src_ip, dst_ip, community_id, tags, tenant_id, created_at, updated_at, closed_at) \
             SELECT id, case_number, title, description, severity, priority, \
                    '{status}', assigned_to, src_ip, dst_ip, community_id, tags, tenant_id, \
                    created_at, now(), {closed_at_expr} \
             FROM {db}.soar_cases FINAL WHERE id = '{id}'",
            db         = db,
            status     = sql_escape(status),
            closed_at_expr = closed_at_expr,
            id         = sql_escape(id),
        );
        self.client.query(&query).execute().await?;
        Ok(())
    }

#[cfg(feature = "soar")]
    pub async fn get_soar_case_comments(&self, case_id: &str, tenant_id: &str) -> anyhow::Result<Vec<serde_json::Value>> {
        let db = tenant_db(tenant_id);
        let result = self.client
            .query(&format!("SELECT id, case_id, author, comment, toUnixTimestamp(created_at) FROM {}.soar_case_comments WHERE case_id = ? ORDER BY created_at ASC", db))
            .bind(case_id)
            .fetch_all::<(String, String, String, String, u32)>()
            .await?;
        Ok(result.into_iter().map(|r| json!({
            "id": r.0, "case_id": r.1, "author": r.2, "comment": r.3, "created_at": r.4
        })).collect())
    }

#[cfg(feature = "soar")]
    pub async fn insert_soar_case_comment(&self, case_id: &str, author: &str, comment: &str, tenant_id: &str) -> anyhow::Result<()> {
        let db = tenant_db(tenant_id);
        let id = uuid::Uuid::new_v4().to_string();
        let query = format!(
            "INSERT INTO {}.soar_case_comments (id, case_id, author, comment, tenant_id) VALUES ('{}','{}','{}','{}','{}')",
            db, sql_escape(&id), sql_escape(case_id), sql_escape(author), sql_escape(comment), sql_escape(tenant_id)
        );
        self.client.query(&query).execute().await?;
        Ok(())
    }

#[cfg(feature = "soar")]
    pub async fn insert_native_playbook(&self, pb: &crate::soar::SoarNativePlaybook) -> anyhow::Result<()> {
        let db = tenant_db(&pb.tenant_id);
        let query = format!(
            "INSERT INTO {}.soar_native_playbooks (id, name, description, enabled, cond_field, cond_op, cond_value, action_type, action_config, tenant_id) VALUES ('{}','{}','{}',{},'{}','{}','{}','{}','{}','{}')",
            db,
            sql_escape(&pb.id), sql_escape(&pb.name), sql_escape(&pb.description), pb.enabled,
            sql_escape(&pb.cond_field), sql_escape(&pb.cond_op), sql_escape(&pb.cond_value),
            sql_escape(&pb.action_type), sql_escape(&pb.action_config), sql_escape(&pb.tenant_id)
        );
        self.client.query(&query).execute().await?;
        Ok(())
    }

#[cfg(feature = "soar")]
    pub async fn update_native_playbook(&self, id: &str, name: &str, description: &str, enabled: u8, cond_field: &str, cond_op: &str, cond_value: &str, action_type: &str, action_config: &str, tenant_id: &str) -> anyhow::Result<()> {
        let db = tenant_db(tenant_id);
        // INSERT SELECT preserves run_count/last_run/created_at and sets updated_at = now().
        // ReplacingMergeTree deduplicates on next merge keeping the latest updated_at row.
        // This avoids "Cannot UPDATE key column `updated_at`" from ALTER TABLE UPDATE.
        let query = format!(
            "INSERT INTO {db}.soar_native_playbooks \
             (id, name, description, enabled, cond_field, cond_op, cond_value, \
              action_type, action_config, run_count, last_run, created_at, updated_at, tenant_id) \
             SELECT id, '{name}', '{desc}', {enabled}, '{cf}', '{co}', '{cv}', '{at}', '{ac}', \
                    run_count, last_run, created_at, now(), tenant_id \
             FROM {db}.soar_native_playbooks FINAL \
             WHERE id = '{id}' AND tenant_id = '{tid}'",
            db  = db,
            name = sql_escape(name),
            desc = sql_escape(description),
            enabled = enabled,
            cf  = sql_escape(cond_field),
            co  = sql_escape(cond_op),
            cv  = sql_escape(cond_value),
            at  = sql_escape(action_type),
            ac  = sql_escape(action_config),
            id  = sql_escape(id),
            tid = sql_escape(tenant_id),
        );
        self.client.query(&query).execute().await?;
        Ok(())
    }

#[cfg(feature = "soar")]
    pub async fn delete_native_playbook(&self, id: &str, tenant_id: &str) -> anyhow::Result<()> {
        let db = tenant_db(tenant_id);
        let query = format!(
            "ALTER TABLE {}.soar_native_playbooks DELETE WHERE id = '{}' SETTINGS mutations_sync=1",
            db, sql_escape(id)
        );
        self.client.query(&query).execute().await?;
        Ok(())
    }

#[cfg(feature = "soar")]
    pub async fn get_soar_playbook_runs(&self, tenant_id: &str, sensor_ids: &[String]) -> anyhow::Result<Vec<serde_json::Value>> {
        let db = tenant_db(tenant_id);
        let hit_filter = if sensor_ids.is_empty() {
            String::new()
        } else {
            let sf = Self::sensor_filter(sensor_ids);
            format!(" WHERE hit_id IN (SELECT DISTINCT community_id FROM {db}.ndr_hits FINAL WHERE 1=1{sf})", db = db, sf = sf)
        };
        let result = self.client
            .query(&format!("SELECT id, playbook_id, playbook_name, hit_id, status, detail, toUnixTimestamp(created_at) FROM {db}.soar_playbook_runs{hit_filter} ORDER BY created_at DESC LIMIT 100", db = db, hit_filter = hit_filter))
            .fetch_all::<(String, String, String, String, String, String, u32)>()
            .await?;
        Ok(result.into_iter().map(|r| json!({
            "id": r.0, "playbook_id": r.1, "playbook_name": r.2, "hit_id": r.3,
            "status": r.4, "detail": r.5, "created_at": r.6
        })).collect())
    }





// ---- EVIDENCE LOG ----

pub async fn log_evidence_action(
    &self,
    tenant_id: &str,
    community_id: &str,
    bundle_id: &str,
    action: &str,
    performed_by: &str,
    severity: &str,
    src_ip: &str,
    dst_ip: &str,
    notes: &str,
    requester_ip: &str,
) -> anyhow::Result<()> {
    let db = tenant_db(tenant_id);
    self.client.query(&format!(
        "INSERT INTO {}.evidence_log
         (community_id,bundle_id,action,performed_by,
          severity,src_ip,dst_ip,notes,ip_address)
         VALUES ('{}','{}','{}','{}','{}','{}','{}','{}','{}')",
        db, community_id, bundle_id, action,
        performed_by, severity, src_ip, dst_ip,
        notes, requester_ip
    )).execute().await?;
    Ok(())
}

pub async fn get_evidence_log(
    &self,
    tenant_id: &str,
    community_id: &str,
) -> anyhow::Result<Vec<serde_json::Value>> {
    #[derive(clickhouse::Row, serde::Deserialize)]
    struct EvidenceLogRow {
        id:           String,
        community_id: String,
        bundle_id:    String,
        action:       String,
        performed_by: String,
        performed_at: String,
        severity:     String,
        src_ip:       String,
        dst_ip:       String,
        notes:        String,
        ip_address:   String,
    }
    let db = tenant_db(tenant_id);
    let rows = self.client.query(&format!(
        "SELECT id, community_id, bundle_id, action,
         performed_by, toString(performed_at) as performed_at,
         severity, src_ip, dst_ip, notes, ip_address
         FROM {}.evidence_log
         WHERE community_id = '{}'
         ORDER BY performed_at DESC",
        db, sql_escape(community_id)
    )).fetch_all::<EvidenceLogRow>().await?;
    Ok(rows.iter().map(|r| serde_json::json!({
        "id": r.id, "community_id": r.community_id, "bundle_id": r.bundle_id,
        "action": r.action, "performed_by": r.performed_by,
        "performed_at": r.performed_at, "severity": r.severity,
        "src_ip": r.src_ip, "dst_ip": r.dst_ip,
        "notes": r.notes, "ip_address": r.ip_address
    })).collect())
}

// ---- EVIDENCE BUNDLES ----

pub async fn save_evidence_bundle(
    &self,
    tenant_id: &str,
    id: &str,
    community_id: &str,
    file_path: &str,
    sha256: &str,
    size_bytes: u64,
    auto_captured: u8,
    expires_days: u32,
    src_ip: &str,
    dst_ip: &str,
    severity: &str,
    alert_id: &str,
) -> anyhow::Result<()> {
    let db = tenant_db(tenant_id);

    // Skip insert if a bundle already exists for this community_id — prevents
    // duplicate entries when the same alert is downloaded more than once.
    #[derive(clickhouse::Row, serde::Deserialize)]
    struct Count { n: u64 }
    let existing: Vec<Count> = self.client
        .query(&format!(
            "SELECT count() as n FROM {}.evidence_bundles FINAL \
             WHERE community_id = '{}'",
            db, sql_escape(community_id)
        ))
        .fetch_all::<Count>()
        .await
        .unwrap_or_default();
    if existing.first().map(|r| r.n).unwrap_or(0) > 0 {
        return Ok(());
    }

    self.client.query(&format!(
        "INSERT INTO {}.evidence_bundles
         (id,community_id,file_path,sha256,size_bytes,
          auto_captured,expires_at,src_ip,dst_ip,
          severity,alert_id)
         VALUES ('{}','{}','{}','{}',{},
          {},now() + INTERVAL {} DAY,'{}','{}','{}','{}')",
        db, sql_escape(id), sql_escape(community_id), sql_escape(file_path), sql_escape(sha256),
        size_bytes, auto_captured, expires_days,
        sql_escape(src_ip), sql_escape(dst_ip), sql_escape(severity), sql_escape(alert_id)
    )).execute().await?;
    Ok(())
}

pub async fn get_evidence_bundle(
    &self,
    tenant_id: &str,
    bundle_id: &str,
) -> anyhow::Result<Option<serde_json::Value>> {
    #[derive(clickhouse::Row, serde::Deserialize)]
    struct EvidenceBundleRow {
        id:             String,
        community_id:   String,
        file_path:      String,
        sha256:         String,
        size_bytes:     u64,
        auto_captured:  u8,
        captured_at:    String,
        expires_at:     String,
        status:         String,
        legal_hold:     u8,
        hold_reason:    String,
        src_ip:         String,
        dst_ip:         String,
        severity:       String,
    }
    let db = tenant_db(tenant_id);
    let rows = self.client.query(&format!(
        "SELECT id, community_id, file_path, sha256,
         size_bytes, auto_captured,
         formatDateTime(captured_at, '%Y-%m-%dT%H:%i:%SZ') as captured_at,
         formatDateTime(expires_at, '%Y-%m-%dT%H:%i:%SZ') as expires_at,
         status, legal_hold, hold_reason,
         src_ip, dst_ip, severity
         FROM {}.evidence_bundles FINAL
         WHERE id = '{}' LIMIT 1",
        db, sql_escape(bundle_id)
    )).fetch_all::<EvidenceBundleRow>().await?;
    Ok(rows.first().map(|r| serde_json::json!({
        "id": r.id, "community_id": r.community_id, "file_path": r.file_path,
        "sha256": r.sha256, "size_bytes": r.size_bytes,
        "auto_captured": r.auto_captured == 1,
        "captured_at": r.captured_at, "expires_at": r.expires_at,
        "status": r.status, "legal_hold": r.legal_hold == 1,
        "hold_reason": r.hold_reason,
        "src_ip": r.src_ip, "dst_ip": r.dst_ip, "severity": r.severity
    })))
}

pub async fn list_evidence_bundles(
    &self,
    tenant_id: &str,
    limit: u32,
    sensor_ids: &[String],
) -> anyhow::Result<Vec<serde_json::Value>> {
    #[derive(clickhouse::Row, serde::Deserialize)]
    struct EvidenceBundleListRow {
        id:                 String,
        community_id:       String,
        sha256:             String,
        size_bytes:         u64,
        auto_captured:      u8,
        captured_at:        String,
        expires_at:         String,
        status:             String,
        legal_hold:         u8,
        src_ip:             String,
        dst_ip:             String,
        severity:           String,
        correlation_status: String,
    }
    let db = tenant_db(tenant_id);
    let sensor_where = if sensor_ids.is_empty() {
        String::new()
    } else {
        let sf = Self::sensor_filter(sensor_ids);
        format!(" WHERE eb.community_id IN (SELECT DISTINCT community_id FROM {db}.ndr_hits FINAL WHERE 1=1{sf})", db = db, sf = sf)
    };
    // LEFT JOIN ndr_hits to pull the best correlation_status per community_id.
    // argMax picks the row with the latest updated_at so "corroborated" wins over
    // the earlier "agent_z_only" row for the same CID.
    let rows = self.client.query(&format!(
        "SELECT eb.id, eb.community_id, eb.sha256, eb.size_bytes,
         eb.auto_captured,
         formatDateTime(eb.captured_at, '%Y-%m-%dT%H:%i:%SZ') as captured_at,
         formatDateTime(eb.expires_at, '%Y-%m-%dT%H:%i:%SZ') as expires_at,
         eb.status, eb.legal_hold, eb.src_ip, eb.dst_ip, eb.severity,
         coalesce(nh.correlation_status, 'agent_z_only') as correlation_status
         FROM (SELECT * FROM {db}.evidence_bundles FINAL) AS eb
         LEFT JOIN (
           SELECT community_id, argMax(correlation_status, updated_at) AS correlation_status
           FROM {db}.ndr_hits FINAL
           GROUP BY community_id
         ) AS nh ON eb.community_id = nh.community_id
         {sensor_where}
         ORDER BY eb.captured_at DESC LIMIT {limit}",
        db = db, sensor_where = sensor_where, limit = limit
    )).fetch_all::<EvidenceBundleListRow>().await?;
    Ok(rows.iter().map(|r| {
        let corroborated = r.correlation_status == "corroborated";
        serde_json::json!({
            "id": r.id, "community_id": r.community_id, "sha256": r.sha256,
            "size_bytes": r.size_bytes, "auto_captured": r.auto_captured == 1,
            "captured_at": r.captured_at, "expires_at": r.expires_at,
            "status": r.status, "legal_hold": r.legal_hold == 1,
            "src_ip": r.src_ip, "dst_ip": r.dst_ip, "severity": r.severity,
            "correlation_status": r.correlation_status,
            "corroborated": corroborated,
        })
    }).collect())
}

pub async fn set_legal_hold(
    &self,
    tenant_id: &str,
    bundle_id: &str,
    hold: u8,
    reason: &str,
    set_by: &str,
) -> anyhow::Result<()> {
    let db = tenant_db(tenant_id);
    self.client.query(&format!(
        "ALTER TABLE {}.evidence_bundles
         UPDATE legal_hold={}, hold_reason='{}',
         hold_set_by='{}'
         WHERE id='{}'",
        db, hold, sql_escape(reason), sql_escape(set_by), sql_escape(bundle_id)
    )).execute().await?;
    Ok(())
}

pub async fn add_evidence_annotation(
    &self,
    tenant_id: &str,
    bundle_id: &str,
    community_id: &str,
    author: &str,
    note: &str,
    tag: &str,
) -> anyhow::Result<()> {
    let db = tenant_db(tenant_id);
    self.client.query(&format!(
        "INSERT INTO {}.evidence_annotations
         (bundle_id,community_id,author,note,tag)
         VALUES ('{}','{}','{}','{}','{}')",
        db, sql_escape(bundle_id), sql_escape(community_id), sql_escape(author), sql_escape(note), sql_escape(tag)
    )).execute().await?;
    Ok(())
}

pub async fn get_annotations(
    &self,
    tenant_id: &str,
    bundle_id: &str,
) -> anyhow::Result<Vec<serde_json::Value>> {
    let db = tenant_db(tenant_id);
    let rows = self.client.query(&format!(
        "SELECT id, author, note, tag,
         toString(created_at) as created_at
         FROM {}.evidence_annotations
         WHERE bundle_id='{}'
         ORDER BY created_at DESC",
        db, sql_escape(bundle_id)
    )).fetch_all::<(String,String,String,String,String)>().await?;
    Ok(rows.iter().map(|r| serde_json::json!({
        "id": r.0, "author": r.1, "note": r.2,
        "tag": r.3, "created_at": r.4
    })).collect())
}

/// Save an AI investigation verdict for a community_id.
/// Stored in evidence_annotations with tag='aria_verdict'.
/// Multiple calls for the same community_id are additive — the newest is always read.
pub async fn save_aria_verdict(
    &self,
    tenant_id:    &str,
    community_id: &str,
    verdict_json: &str,
) -> anyhow::Result<()> {
    let db  = tenant_db(tenant_id);
    let cid = sql_escape(community_id);
    let note = sql_escape(verdict_json);

    // Resolve bundle_id for this community_id (empty string if not found)
    let bundle_id: String = self.client.query(&format!(
        "SELECT id FROM {db}.evidence_bundles FINAL \
         WHERE community_id = '{cid}' LIMIT 1",
        db = db, cid = cid
    )).fetch_one::<String>().await.unwrap_or_default();

    self.client.query(&format!(
        "INSERT INTO {db}.evidence_annotations \
         (bundle_id, community_id, author, note, tag) \
         VALUES ('{bid}', '{cid}', 'aria', '{note}', 'aria_verdict')",
        db = db,
        bid  = sql_escape(&bundle_id),
        cid  = cid,
        note = note
    )).execute().await?;
    Ok(())
}

/// Retrieve the most recent AI verdict for a community_id.
/// Returns None if no investigation has been run yet.
pub async fn get_aria_verdict(
    &self,
    tenant_id:    &str,
    community_id: &str,
) -> Option<serde_json::Value> {
    let db  = tenant_db(tenant_id);
    let cid = sql_escape(community_id);

    let rows: Vec<String> = self.client.query(&format!(
        "SELECT note FROM {db}.evidence_annotations \
         WHERE community_id = '{cid}' AND tag = 'aria_verdict' \
         ORDER BY created_at DESC LIMIT 1",
        db = db, cid = cid
    )).fetch_all::<String>().await.unwrap_or_default();

    rows.into_iter().next()
        .and_then(|s| serde_json::from_str(&s).ok())
}

pub async fn get_all_ai_annotations(
    &self,
    tenant_id: &str,
    sensor_ids: &[String],
) -> anyhow::Result<Vec<serde_json::Value>> {
    let db = tenant_db(tenant_id);
    let sensor_cid_filter = if sensor_ids.is_empty() {
        String::new()
    } else {
        let sf = Self::sensor_filter(sensor_ids);
        format!(" AND ea.community_id IN (SELECT DISTINCT community_id FROM {db}.ndr_hits FINAL WHERE 1=1{sf})", db = db, sf = sf)
    };
    // One row per community_id — most recent comprehensive analysis
    let rows = self.client.query(&format!(
        "SELECT
             argMax(ea.id,         ea.created_at) as id,
             argMax(ea.bundle_id,  ea.created_at) as bundle_id,
             ea.community_id,
             argMax(ea.note,       ea.created_at) as analysis,
             toString(max(ea.created_at))          as created_at,
             argMax(if(eb.severity != '' AND eb.severity != 'UNKNOWN', eb.severity, ''),
                    ea.created_at)                 as severity,
             argMax(if(eb.src_ip  != '' AND eb.src_ip  != 'UNKNOWN', eb.src_ip,  ''),
                    ea.created_at)                 as src_ip,
             argMax(if(eb.dst_ip  != '' AND eb.dst_ip  != 'UNKNOWN', eb.dst_ip,  ''),
                    ea.created_at)                 as dst_ip
         FROM {db}.evidence_annotations ea
         LEFT JOIN {db}.evidence_bundles eb ON ea.bundle_id = eb.id
         WHERE ea.tag = 'ai_analysis'{scf}
         GROUP BY ea.community_id
         ORDER BY max(ea.created_at) DESC
         LIMIT 50",
        db = db, scf = sensor_cid_filter
    )).fetch_all::<(String,String,String,String,String,String,String,String)>().await.unwrap_or_default();

    // Bulk asset lookup for all unique IPs that appear in these analyses
    let unique_ips: Vec<String> = rows.iter()
        .flat_map(|r| [r.6.clone(), r.7.clone()])
        .filter(|ip| !ip.is_empty())
        .collect::<std::collections::HashSet<_>>()
        .into_iter()
        .collect();
    let mut asset_map: std::collections::HashMap<String, serde_json::Value> = std::collections::HashMap::new();
    if !unique_ips.is_empty() {
        let ip_list = unique_ips.iter().map(|ip| format!("'{}'", sql_escape(ip))).collect::<Vec<_>>().join(",");
        if let Ok(assets) = self.client.query(&format!(
            "SELECT ip, hostname, mac, vendor, device_type, trusted, threat_flagged \
             FROM {db}.assets FINAL WHERE ip IN ({ip_list}) AND tenant_id = '{tid}'",
            db = db, ip_list = ip_list, tid = sql_escape(tenant_id)
        )).fetch_all::<(String,String,String,String,String,u8,u8)>().await {
            for (ip, hostname, mac, vendor, device_type, trusted, threat_flagged) in assets {
                asset_map.insert(ip, serde_json::json!({
                    "hostname": hostname, "mac": mac, "vendor": vendor,
                    "device_type": device_type,
                    "trusted": trusted != 0, "threat_flagged": threat_flagged != 0
                }));
            }
        }
    }

    Ok(rows.iter().map(|r| {
        let src_asset = asset_map.get(&r.6).cloned().unwrap_or(serde_json::Value::Null);
        let dst_asset = asset_map.get(&r.7).cloned().unwrap_or(serde_json::Value::Null);
        serde_json::json!({
            "id": r.0, "bundle_id": r.1, "community_id": r.2,
            "analysis": r.3, "created_at": r.4,
            "severity": r.5, "src_ip": r.6, "dst_ip": r.7,
            "src_asset": src_asset, "dst_asset": dst_asset
        })
    }).collect())
}

/// Returns all evidence bundles for a given community_id (used for grouped AI analysis).
pub async fn get_bundles_for_cid(
    &self,
    tenant_id: &str,
    community_id: &str,
) -> anyhow::Result<Vec<serde_json::Value>> {
    let db = tenant_db(tenant_id);
    let rows = self.client.query(&format!(
        "SELECT id, severity, src_ip, dst_ip, alert_id,
         toString(captured_at) as captured_at
         FROM {}.evidence_bundles FINAL
         WHERE community_id = '{}'
         ORDER BY captured_at DESC LIMIT 30",
        db, sql_escape(community_id)
    )).fetch_all::<(String,String,String,String,String,String)>().await.unwrap_or_default();
    Ok(rows.iter().map(|r| serde_json::json!({
        "id": r.0, "severity": r.1, "src_ip": r.2,
        "dst_ip": r.3, "alert_id": r.4, "captured_at": r.5
    })).collect())
}

/// Deletes old ai_analysis annotations for a community_id before saving a fresh one.
pub async fn delete_ai_annotations_for_cid(
    &self,
    tenant_id: &str,
    community_id: &str,
) -> anyhow::Result<()> {
    let db = tenant_db(tenant_id);
    self.client.query(&format!(
        "ALTER TABLE {}.evidence_annotations DELETE
         WHERE community_id = '{}' AND tag = 'ai_analysis' SETTINGS mutations_sync=1",
        db, sql_escape(community_id)
    )).execute().await?;
    Ok(())
}

// ---- SHARED IOCs ----

pub async fn upsert_shared_ioc(
    &self,
    ioc_value: &str,
    ioc_type: &str,
    confidence: u8,
    tenant_hash: &str,
    tags: &str,
    description: &str,
) -> anyhow::Result<()> {
    self.client.query(&format!(
        "INSERT INTO ndr.shared_iocs
         (ioc_value,ioc_type,confidence,
          tenant_hash,tags,description)
         VALUES ('{}','{}',{},'{}','{}','{}')",
        sql_escape(ioc_value), sql_escape(ioc_type), confidence,
        sql_escape(tenant_hash), sql_escape(tags), sql_escape(description)
    )).execute().await?;
    Ok(())
}

pub async fn check_shared_ioc(
    &self,
    ioc_value: &str,
) -> anyhow::Result<Option<serde_json::Value>> {
    let rows = self.client.query(&format!(
        "SELECT ioc_value, ioc_type, confidence,
         toString(first_seen) as first_seen,
         toString(last_seen) as last_seen,
         tags, description
         FROM ndr.shared_iocs FINAL
         WHERE ioc_value='{}' LIMIT 1",
        sql_escape(ioc_value)
    )).fetch_all::<(String,String,u8,String,
        String,String,String)>().await?;
    Ok(rows.first().map(|r| serde_json::json!({
        "ioc_value": r.0, "ioc_type": r.1,
        "confidence": r.2, "first_seen": r.3,
        "last_seen": r.4, "tags": r.5,
        "description": r.6
    })))
}



pub async fn get_hit_by_community_id(
    &self,
    tenant_id: &str,
    community_id: &str,
) -> anyhow::Result<Option<serde_json::Value>> {
    #[derive(clickhouse::Row, serde::Deserialize)]
    struct HitRow {
        community_id: String,
        src_ip:       String,
        dst_ip:       String,
        timestamp:    String,
        severity:     String,
    }
    #[derive(clickhouse::Row, serde::Deserialize)]
    struct EventRow {
        src_port: u16,
        dst_port: u16,
        proto:    String,
    }
    let db = tenant_db(tenant_id);
    let hits = self.client.query(&format!(
        "SELECT community_id, src_ip, dst_ip,
         formatDateTime(toDateTime(timestamp), '%Y-%m-%dT%H:%i:%SZ') as timestamp, severity
         FROM {}.ndr_hits FINAL
         WHERE community_id = '{}'
         ORDER BY timestamp DESC LIMIT 1",
        db, sql_escape(community_id)
    )).fetch_all::<HitRow>().await?;

    let Some(hit) = hits.first() else { return Ok(None); };

    // Pull ports and proto from ndr_events (ndr_hits doesn't store them)
    let events = self.client.query(&format!(
        "SELECT src_port, dst_port, proto
         FROM {}.ndr_events
         WHERE community_id = '{}' AND src_port > 0
         ORDER BY timestamp DESC LIMIT 1",
        db, sql_escape(community_id)
    )).fetch_all::<EventRow>().await.unwrap_or_default();
    let (src_port, dst_port, proto) = events.first()
        .map(|e| (e.src_port, e.dst_port, e.proto.clone()))
        .unwrap_or((0, 0, "tcp".to_string()));

    Ok(Some(serde_json::json!({
        "community_id": hit.community_id,
        "src_ip":       hit.src_ip,
        "dst_ip":       hit.dst_ip,
        "src_port":     src_port,
        "dst_port":     dst_port,
        "proto":        proto,
        "timestamp":    hit.timestamp,
        "severity":     hit.severity,
    })))
}

pub async fn get_related_hits_by_ip(
    &self,
    tenant_id: &str,
    src_ip: &str,
    around_time: &str,
    window_minutes: i64,
) -> anyhow::Result<Vec<serde_json::Value>> {
    let db = tenant_db(tenant_id);
    let rows = self.client.query(&format!(
        "SELECT community_id, src_ip, dst_ip,
         formatDateTime(toDateTime(timestamp), '%Y-%m-%dT%H:%i:%SZ') as timestamp,
         severity, arrayElement(sigma_hits, 1) as rule_name
         FROM {}.ndr_hits
         WHERE src_ip = '{}'
         AND community_id LIKE '1:%'
         AND timestamp BETWEEN
             parseDateTimeBestEffort('{}') - INTERVAL {} MINUTE
             AND parseDateTimeBestEffort('{}') + INTERVAL {} MINUTE
         ORDER BY timestamp ASC
         LIMIT 20",
        db, sql_escape(src_ip), sql_escape(around_time), window_minutes,
        sql_escape(around_time), window_minutes
    )).fetch_all::<(String,String,String,String,String,String)>()
    .await?;
    Ok(rows.iter().map(|r| serde_json::json!({
        "community_id": r.0, "src_ip": r.1, "dst_ip": r.2,
        "timestamp": r.3, "severity": r.4, "rule_name": r.5
    })).collect())
}

pub async fn get_rule_hits_by_community_id(
    &self,
    tenant_id: &str,
    community_id: &str,
) -> anyhow::Result<Vec<serde_json::Value>> {
    let db = tenant_db(tenant_id);
    let rows = self.client.query(&format!(
        "SELECT arrayElement(sigma_hits, 1) as rule_name, severity,
         formatDateTime(toDateTime(timestamp), '%Y-%m-%dT%H:%i:%SZ') as timestamp,
         src_ip, dst_ip
         FROM {}.ndr_hits
         WHERE community_id = '{}'
         ORDER BY timestamp DESC
         LIMIT 50",
        db, sql_escape(community_id)
    )).fetch_all::<(String,String,String,String,String)>()
    .await?;
    Ok(rows.iter().map(|r| serde_json::json!({
        "rule_name": r.0,
        "severity":  r.1,
        "timestamp": r.2,
        "src_ip":    r.3,
        "dst_ip":    r.4,
    })).collect())
}

pub async fn get_pcap_file_path_by_community_id(
    &self,
    tenant_id: &str,
    community_id: &str,
) -> anyhow::Result<Option<String>> {
    #[derive(clickhouse::Row, serde::Deserialize)]
    struct PcapPathRow {
        file_path: String,
    }
    let db = tenant_db(tenant_id);
    let rows = self.client.query(&format!(
        "SELECT file_path FROM {}.pcap_sessions
         WHERE community_id = '{}'
         AND file_path != ''
         ORDER BY start_time DESC LIMIT 1",
        db, sql_escape(community_id)
    )).fetch_all::<PcapPathRow>().await?;
    Ok(rows.first().map(|r| r.file_path.clone()).filter(|s| !s.is_empty()))
}


/// Get recent hits for ARIA context
pub async fn get_recent_hits_for_aria(
    &self,
    tenant_id: &str,
    limit: u32,
) -> anyhow::Result<Vec<serde_json::Value>> {
    let db = tenant_db(tenant_id);
    // Use a struct to avoid tuple field limit
    #[derive(clickhouse::Row, serde::Deserialize)]
    struct HitRow {
        community_id: String,
        src_ip: String,
        dst_ip: String,
        severity: String,
        score: f64,
        tags: String,
        timestamp: String,
    }
    let rows = self.client.query(&format!(
        "SELECT community_id, src_ip, dst_ip,
         severity, score, tags,
         formatDateTime(toDateTime(timestamp), '%Y-%m-%dT%H:%i:%SZ') as timestamp
         FROM {}.ndr_hits
         ORDER BY timestamp DESC LIMIT {}",
        db, limit
    )).fetch_all::<HitRow>().await?;

    Ok(rows.iter().map(|r| serde_json::json!({
        "community_id": r.community_id,
        "src_ip": r.src_ip,
        "dst_ip": r.dst_ip,
        "severity": r.severity,
        "score": r.score,
        "tags": r.tags,
        "timestamp": r.timestamp
    })).collect())
}

/// Returns the latest CRITICAL-only hit — used by aria_status to drive proactive bot alerts.
pub async fn get_latest_critical_hit_for_aria(
    &self,
    tenant_id: &str,
    sensor_ids: &[String],
) -> anyhow::Result<Option<serde_json::Value>> {
    let db = tenant_db(tenant_id);
    let sf = Self::sensor_filter(sensor_ids);
    #[derive(clickhouse::Row, serde::Deserialize)]
    struct HitRow {
        community_id: String,
        src_ip:       String,
        dst_ip:       String,
        rule_name:    String,
        score:        f64,
        timestamp:    String,
    }
    let rows = self.client.query(&format!(
        "SELECT community_id, src_ip, dst_ip, arrayElement(sigma_hits, 1) as rule_name, score,
         formatDateTime(toDateTime(timestamp), '%Y-%m-%dT%H:%i:%SZ') as timestamp
         FROM {db}.ndr_hits
         WHERE severity = 'CRITICAL'{sf}
         ORDER BY timestamp DESC LIMIT 1",
        db = db, sf = sf
    )).fetch_all::<HitRow>().await?;

    Ok(rows.first().map(|r| serde_json::json!({
        "community_id": r.community_id,
        "src_ip":       r.src_ip,
        "dst_ip":       r.dst_ip,
        "severity":     "CRITICAL",
        "rule_name":    r.rule_name,
        "score":        r.score,
        "timestamp":    r.timestamp
    })))
}

/// Returns the latest rising CRITICAL/HIGH prediction — used by aria_status for proactive prediction alerts.
pub async fn get_rising_critical_prediction(
    &self,
    tenant_id: &str,
) -> anyhow::Result<Option<serde_json::Value>> {
    let db = tenant_db(tenant_id);
    #[derive(clickhouse::Row, serde::Deserialize)]
    struct Row {
        id:          String,
        attack_type: String,
        probability: f32,
        alert_level: String,
        trend:       String,
        explanation: String,
        predicted_at: String,
    }
    let rows = self.client.query(&format!(
        "SELECT id, attack_type, probability, alert_level, trend, explanation,
         toString(predicted_at) as predicted_at
         FROM {db}.threat_predictions
         WHERE trend = 'rising'
         AND alert_level IN ('critical', 'high')
         AND predicted_at >= now() - INTERVAL 7 HOUR
         ORDER BY probability DESC, predicted_at DESC
         LIMIT 1",
        db = db
    )).fetch_all::<Row>().await?;

    Ok(rows.first().map(|r| serde_json::json!({
        "id":           r.id,
        "attack_type":  r.attack_type,
        "probability":  r.probability,
        "alert_level":  r.alert_level,
        "trend":        r.trend,
        "explanation":  r.explanation,
        "predicted_at": r.predicted_at,
    })))
}

/// Count hits by severity last 24h
pub async fn count_hits_by_severity_aria(
    &self,
    tenant_id: &str,
    severity: &str,
    sensor_ids: &[String],
) -> anyhow::Result<u64> {
    let db = tenant_db(tenant_id);
    let sf = Self::sensor_filter(sensor_ids);
    #[derive(clickhouse::Row, serde::Deserialize)]
    struct CountRow { cnt: u64 }
    let rows = self.client.query(&format!(
        "SELECT count() as cnt
         FROM {db}.ndr_hits
         WHERE severity = '{sev}'
         AND timestamp >= now() - INTERVAL 24 HOUR{sf}",
        db = db, sev = sql_escape(severity), sf = sf
    )).fetch_all::<CountRow>().await?;
    Ok(rows.first().map(|r| r.cnt).unwrap_or(0))
}

/// Count evidence bundles for tenant
pub async fn count_evidence_bundles_aria(
    &self,
    tenant_id: &str,
    sensor_ids: &[String],
) -> anyhow::Result<u64> {
    let db = tenant_db(tenant_id);
    #[derive(clickhouse::Row, serde::Deserialize)]
    struct CountRow { cnt: u64 }
    let where_clause = if sensor_ids.is_empty() {
        String::new()
    } else {
        let sf = Self::sensor_filter(sensor_ids);
        format!(" WHERE community_id IN (SELECT DISTINCT community_id FROM {db}.ndr_hits FINAL WHERE 1=1{sf})", db = db, sf = sf)
    };
    let rows = self.client.query(&format!(
        "SELECT count() as cnt FROM {db}.evidence_bundles FINAL{wc}",
        db = db, wc = where_clause
    )).fetch_all::<CountRow>().await?;
    Ok(rows.first().map(|r| r.cnt).unwrap_or(0))
}

/// Fetches real tenant data relevant to the user's question for ARIA chat.
/// Detects keywords in the message and queries matching data from the tenant DB.
/// Returns a formatted string injected into the system prompt — no hallucination possible.
pub async fn fetch_aria_context(
    &self,
    tenant_id: &str,
    user_message: &str,
    sensor_ids: &[String],
) -> String {
    let db = tenant_db(tenant_id);
    let sf = Self::sensor_filter(sensor_ids);
    let bundle_where = if sensor_ids.is_empty() {
        String::new()
    } else {
        format!(" WHERE community_id IN (SELECT DISTINCT community_id FROM {db}.ndr_hits FINAL WHERE 1=1{sf})", db = db, sf = sf)
    };
    let msg = user_message.to_lowercase();
    let mut ctx = String::new();

    // ── Always: recent 15 hits with full detail ──────────────────────────────
    #[derive(clickhouse::Row, serde::Deserialize)]
    struct HitRow {
        community_id: String,
        src_ip:       String,
        dst_ip:       String,
        severity:     String,
        score:        f64,
        tags:         String,
        rule_name:    String,
        timestamp:    String,
    }
    if let Ok(hits) = self.client.query(&format!(
        "SELECT community_id, src_ip, dst_ip, severity, score,
         arrayStringConcat(tags, ', ') as tags,
         arrayElement(sigma_hits, 1) as rule_name,
         formatDateTime(toDateTime(timestamp), '%Y-%m-%dT%H:%i:%SZ') as timestamp
         FROM {db}.ndr_hits
         WHERE 1=1{sf}
         ORDER BY timestamp DESC LIMIT 15",
        db = db, sf = sf
    )).fetch_all::<HitRow>().await {
        ctx.push_str("=== RECENT ALERTS (last 15, newest first) ===\n");
        if hits.is_empty() {
            ctx.push_str("No alerts found.\n");
        }
        for h in &hits {
            ctx.push_str(&format!(
                "[{}] {} {} -> {} score={:.0} tags={} rule={}\n",
                h.timestamp, h.severity, h.src_ip, h.dst_ip,
                h.score, h.tags, h.rule_name
            ));
        }
        ctx.push('\n');
    }

    // ── IP-specific: if user mentions an IP ─────────────────────────────────
    let ip_re = regex::Regex::new(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b").unwrap();
    if let Some(cap) = ip_re.captures(&msg) {
        let ip = cap[1].to_string();
        if let Ok(ip_hits) = self.client.query(&format!(
            "SELECT community_id, src_ip, dst_ip, severity, score,
             arrayStringConcat(tags, ', ') as tags,
             arrayElement(sigma_hits, 1) as rule_name,
             formatDateTime(toDateTime(timestamp), '%Y-%m-%dT%H:%i:%SZ') as timestamp
             FROM {db}.ndr_hits
             WHERE (src_ip='{ip}' OR dst_ip='{ip}'){sf}
             ORDER BY timestamp DESC LIMIT 20",
            db = db, ip = ip, sf = sf
        )).fetch_all::<HitRow>().await {
            ctx.push_str(&format!("=== ALERTS INVOLVING IP {} ===\n", ip));
            if ip_hits.is_empty() {
                ctx.push_str(&format!("No alerts found for IP {}.\n", ip));
            }
            for h in &ip_hits {
                ctx.push_str(&format!(
                    "[{}] {} {} -> {} score={:.0} tags={} rule={}\n",
                    h.timestamp, h.severity, h.src_ip, h.dst_ip,
                    h.score, h.tags, h.rule_name
                ));
            }
            ctx.push('\n');
        }
    }

    // ── Lateral movement ────────────────────────────────────────────────────
    if msg.contains("lateral") || msg.contains("spread") || msg.contains("movement") {
        if let Ok(lat) = self.client.query(&format!(
            "SELECT community_id, src_ip, dst_ip, severity, score,
             arrayStringConcat(tags, ', ') as tags,
             arrayElement(sigma_hits, 1) as rule_name,
             formatDateTime(toDateTime(timestamp), '%Y-%m-%dT%H:%i:%SZ') as timestamp
             FROM {db}.ndr_hits
             WHERE (arrayExists(x -> lower(x) LIKE '%lateral%', tags)
                    OR arrayExists(x -> lower(x) LIKE '%lateral%', sigma_hits)){sf}
             ORDER BY timestamp DESC LIMIT 10",
            db = db, sf = sf
        )).fetch_all::<HitRow>().await {
            ctx.push_str("=== LATERAL MOVEMENT ALERTS ===\n");
            if lat.is_empty() {
                ctx.push_str("No lateral movement alerts found in this tenant's data.\n");
            }
            for h in &lat {
                ctx.push_str(&format!(
                    "[{}] {} {} -> {} rule={}\n",
                    h.timestamp, h.severity, h.src_ip, h.dst_ip, h.rule_name
                ));
            }
            ctx.push('\n');
        }
    }

    // ── Evidence bundles ────────────────────────────────────────────────────
    if msg.contains("evidence") || msg.contains("bundle") || msg.contains("pcap") {
        if let Ok(bundles) = self.client.query(&format!(
            "SELECT id, community_id, src_ip, dst_ip, severity,
             formatDateTime(captured_at, '%Y-%m-%dT%H:%i:%SZ') as captured_at
             FROM {db}.evidence_bundles FINAL{bw}
             ORDER BY captured_at DESC LIMIT 10",
            db = db, bw = bundle_where
        )).fetch_all::<(String,String,String,String,String,String)>().await {
            ctx.push_str("=== EVIDENCE BUNDLES ===\n");
            if bundles.is_empty() {
                ctx.push_str("No evidence bundles found.\n");
            }
            for b in &bundles {
                ctx.push_str(&format!(
                    "[{}] {} {} -> {} bundle_id={}\n",
                    b.5, b.4, b.2, b.3, b.0
                ));
            }
            ctx.push('\n');
        }
    }

    // ── Suppression decisions ────────────────────────────────────────────────
    if msg.contains("suppress") || msg.contains("false positive") || msg.contains("whitelist") {
        if let Ok(sups) = self.client.query(&format!(
            "SELECT signature_name, suppress_type, suppress_ip, src_ip, dst_ip, ai_confidence,
             toString(created_at) as created_at
             FROM {db}.ai_suppressions FINAL
             ORDER BY created_at DESC LIMIT 10",
            db = db
        )).fetch_all::<(String,String,String,String,String,u8,String)>().await {
            ctx.push_str("=== SUPPRESSION DECISIONS ===\n");
            if sups.is_empty() {
                ctx.push_str("No suppression decisions found.\n");
            }
            for s in &sups {
                ctx.push_str(&format!(
                    "[{}] {} suppress_type={} target={} confidence={}%\n",
                    s.6, s.0, s.1, s.2, s.5
                ));
            }
            ctx.push('\n');
        }
    }

    // ── Critical/High detail on demand ──────────────────────────────────────
    if msg.contains("critical") || msg.contains("high") || msg.contains("severe") {
        let sev = if msg.contains("critical") { "CRITICAL" } else { "HIGH" };
        if let Ok(sev_hits) = self.client.query(&format!(
            "SELECT community_id, src_ip, dst_ip, severity, score,
             arrayStringConcat(tags, ', ') as tags,
             arrayElement(sigma_hits, 1) as rule_name,
             formatDateTime(toDateTime(timestamp), '%Y-%m-%dT%H:%i:%SZ') as timestamp
             FROM {db}.ndr_hits
             WHERE severity='{sev}' AND timestamp >= now() - INTERVAL 24 HOUR{sf}
             ORDER BY timestamp DESC LIMIT 10",
            db = db, sev = sev, sf = sf
        )).fetch_all::<HitRow>().await {
            ctx.push_str(&format!("=== {} ALERTS (last 24h) ===\n", sev));
            if sev_hits.is_empty() {
                ctx.push_str(&format!("No {} alerts in the last 24 hours.\n", sev));
            }
            for h in &sev_hits {
                ctx.push_str(&format!(
                    "[{}] {} -> {} score={:.0} rule={}\n",
                    h.timestamp, h.src_ip, h.dst_ip, h.score, h.rule_name
                ));
            }
            ctx.push('\n');
        }
    }

    ctx
}

/// Write a permanent IOC hit record — immutable, never updated or deleted.
/// Called at detection time so the match is preserved even if the feed changes later.
pub async fn write_ioc_hit(
    &self,
    tenant_id: &str,
    community_id: &str,
    src_ip: &str,
    dst_ip: &str,
    matched_ip: &str,
    feed_source: &str,
) -> anyhow::Result<()> {
    let db = tenant_db(tenant_id);
    self.client.query(&format!(
        "INSERT INTO {}.ioc_hits \
         (timestamp, community_id, src_ip, dst_ip, matched_ip, ioc_type, feed_source) \
         VALUES (now(), '{}', '{}', '{}', '{}', 'ip', '{}')",
        db,
        sql_escape(community_id),
        sql_escape(src_ip),
        sql_escape(dst_ip),
        sql_escape(matched_ip),
        sql_escape(feed_source),
    )).execute().await?;
    Ok(())
}

/// Query permanent IOC hits for a community_id (for evidence investigation).
pub async fn get_ioc_hits(
    &self,
    tenant_id: &str,
    community_id: &str,
) -> anyhow::Result<Vec<serde_json::Value>> {
    let db = tenant_db(tenant_id);
    #[derive(clickhouse::Row, serde::Deserialize)]
    struct IocHitRow {
        timestamp:    String,
        community_id: String,
        src_ip:       String,
        dst_ip:       String,
        matched_ip:   String,
        ioc_type:     String,
        feed_source:  String,
    }
    let rows = self.client.query(&format!(
        "SELECT formatDateTime(toDateTime(timestamp), '%Y-%m-%dT%H:%i:%SZ') as timestamp, community_id, \
         src_ip, dst_ip, matched_ip, ioc_type, feed_source \
         FROM {}.ioc_hits \
         WHERE community_id = '{}' \
         ORDER BY timestamp ASC",
        db,
        sql_escape(community_id),
    ))
    .fetch_all::<IocHitRow>().await.unwrap_or_default();

    Ok(rows.into_iter().map(|r| serde_json::json!({
        "timestamp":    r.timestamp,
        "community_id": r.community_id,
        "src_ip":       r.src_ip,
        "dst_ip":       r.dst_ip,
        "matched_ip":   r.matched_ip,
        "ioc_type":     r.ioc_type,
        "feed_source":  r.feed_source,
    })).collect())
}

    // ── Asset Management ──────────────────────────────────────────────────────

    pub async fn upsert_asset(&self, asset: &AssetRow) -> anyhow::Result<()> {
        let db = tenant_db(&asset.tenant_id);
        let safe_history = sql_escape(&asset.ip_history);
        let query = format!(
            "INSERT INTO {}.assets \
             (ip, mac, hostname, vendor, os_guess, device_type, custom_name, tenant_id, \
              first_seen, last_seen, ip_history, trusted, threat_flagged, \
              role, criticality, open_ports, subnet_role, ja3_os) \
             VALUES ('{}', '{}', '{}', '{}', '{}', '{}', '{}', '{}', \
                     toDateTime({}), toDateTime({}), '{}', {}, {}, \
                     '{}', {}, '{}', '{}', '{}')",
            db,
            sql_escape(&asset.ip), sql_escape(&asset.mac), sql_escape(&asset.hostname),
            sql_escape(&asset.vendor), sql_escape(&asset.os_guess), sql_escape(&asset.device_type),
            sql_escape(&asset.custom_name), sql_escape(&asset.tenant_id),
            asset.first_seen, asset.last_seen,
            safe_history,
            asset.trusted, asset.threat_flagged,
            sql_escape(&asset.role), asset.criticality,
            sql_escape(&asset.open_ports), sql_escape(&asset.subnet_role), sql_escape(&asset.ja3_os)
        );
        self.client.query(&query).execute().await?;
        Ok(())
    }

    pub async fn update_asset_os(&self, ip: &str, os_name: &str, tenant_id: &str) -> anyhow::Result<()> {
        let db = tenant_db(tenant_id);
        let query = format!(
            "ALTER TABLE {}.assets UPDATE os_guess = '{}' WHERE tenant_id = '{}' AND ip = '{}' SETTINGS mutations_sync=1",
            db, sql_escape(os_name), sql_escape(tenant_id), sql_escape(ip)
        );
        self.client.query(&query).execute().await?;
        Ok(())
    }

    pub async fn get_assets_by_tenant(&self, tenant_id: &str) -> anyhow::Result<Vec<AssetRow>> {
        let db = tenant_db(tenant_id);
        let query = format!(
            "SELECT ip, mac, hostname, vendor, os_guess, device_type, custom_name, tenant_id, \
             toUnixTimestamp(first_seen) as first_seen, \
             toUnixTimestamp(last_seen) as last_seen, \
             ip_history, trusted, threat_flagged, \
             role, criticality, open_ports, subnet_role, ja3_os \
             FROM {}.assets FINAL WHERE tenant_id = '{}' \
             ORDER BY ip ASC",
            db, sql_escape(tenant_id)
        );
        let rows = self.client.query(&query).fetch_all::<AssetRow>().await?;
        Ok(rows)
    }

    pub async fn get_asset_by_mac(&self, tenant_id: &str, mac: &str) -> anyhow::Result<Option<AssetRow>> {
        if mac.is_empty() { return Ok(None); }
        let db = tenant_db(tenant_id);
        let query = format!(
            "SELECT ip, mac, hostname, vendor, os_guess, device_type, custom_name, tenant_id, \
             toUnixTimestamp(first_seen) as first_seen, toUnixTimestamp(last_seen) as last_seen, \
             ip_history, trusted, threat_flagged, \
             role, criticality, open_ports, subnet_role, ja3_os \
             FROM {}.assets WHERE tenant_id = '{}' AND mac = '{}' ORDER BY last_seen DESC LIMIT 1",
            db, sql_escape(tenant_id), sql_escape(mac)
        );
        let result = self.client.query(&query).fetch_optional::<AssetRow>().await?;
        Ok(result)
    }

    pub async fn get_assets_with_counts_by_tenant(&self, tenant_id: &str, sensor_ids: &[String]) -> anyhow::Result<Vec<serde_json::Value>> {
        let db = tenant_db(tenant_id);
        let sf = Self::sensor_filter(sensor_ids);

        let assets = self.get_assets_by_tenant(tenant_id).await?;

        // When restricted to specific sensors, only show assets that those sensors have seen
        let filtered_assets: Vec<_> = if !sensor_ids.is_empty() {
            #[derive(clickhouse::Row, serde::Deserialize)]
            struct IpRow { ip: String }
            let visible_q = format!(
                "SELECT DISTINCT arrayJoin([src_ip, dst_ip]) as ip \
                 FROM {db}.ndr_events \
                 WHERE tenant_id = '{tenant}' AND timestamp > now() - INTERVAL 7 DAY{sf}",
                db = db, tenant = sql_escape(tenant_id), sf = sf
            );
            let visible: std::collections::HashSet<String> = self.client
                .query(&visible_q).fetch_all::<IpRow>().await.unwrap_or_default()
                .into_iter().map(|r| r.ip).collect();
            assets.into_iter().filter(|a| visible.contains(&a.ip)).collect()
        } else {
            assets
        };

        let q_conns = format!(
            "SELECT arrayJoin([src_ip, dst_ip]) as ip, count() as c \
             FROM {db}.ndr_events WHERE tenant_id = '{tenant}' AND timestamp > now() - INTERVAL 1 DAY{sf} GROUP BY ip",
            db = db, tenant = sql_escape(tenant_id), sf = sf
        );
        let conns: Vec<(String, u64)> = self.client.query(&q_conns).fetch_all().await.unwrap_or_default();
        let mut conn_map = std::collections::HashMap::new();
        for (ip, c) in conns { conn_map.insert(ip, c); }

        let q_hits = format!(
            "SELECT arrayJoin([src_ip, dst_ip]) as ip, count() as c \
             FROM {db}.ndr_hits WHERE tenant_id = '{tenant}' AND timestamp > now() - INTERVAL 1 DAY{sf} GROUP BY ip",
            db = db, tenant = sql_escape(tenant_id), sf = sf
        );
        let hits: Vec<(String, u64)> = self.client.query(&q_hits).fetch_all().await.unwrap_or_default();
        let mut hit_map = std::collections::HashMap::new();
        for (ip, c) in hits { hit_map.insert(ip, c); }

        let mut result = Vec::new();
        for a in filtered_assets {
            let mut val = serde_json::to_value(&a).unwrap();
            if let Some(obj) = val.as_object_mut() {
                obj.insert("connections_24h".into(), serde_json::json!(conn_map.get(&a.ip).unwrap_or(&0)));
                obj.insert("alerts_24h".into(),      serde_json::json!(hit_map.get(&a.ip).unwrap_or(&0)));
            }
            result.push(val);
        }
        Ok(result)
    }

    pub async fn get_asset_by_ip(&self, tenant_id: &str, ip: &str) -> anyhow::Result<Option<AssetRow>> {
        let db = tenant_db(tenant_id);
        let query = format!(
            "SELECT ip, mac, hostname, vendor, os_guess, device_type, custom_name, tenant_id, \
             toUnixTimestamp(first_seen) as first_seen, toUnixTimestamp(last_seen) as last_seen, \
             ip_history, trusted, threat_flagged, \
             role, criticality, open_ports, subnet_role, ja3_os \
             FROM {}.assets FINAL WHERE tenant_id = '{}' AND ip = '{}' LIMIT 1",
            db, sql_escape(tenant_id), sql_escape(ip)
        );
        let asset = self.client.query(&query).fetch_optional::<AssetRow>().await?;
        Ok(asset)
    }

    pub async fn update_asset_name(&self, tenant_id: &str, ip: &str, custom_name: &str) -> anyhow::Result<()> {
        if let Ok(Some(mut asset)) = self.get_asset_by_ip(tenant_id, ip).await {
            asset.custom_name = custom_name.to_string();
            asset.last_seen   = chrono::Utc::now().timestamp() as u32;
            self.upsert_asset(&asset).await?;
        }
        Ok(())
    }

    /// Returns IPs of assets marked as trusted by the user for a tenant.
    pub async fn get_trusted_asset_ips(&self, tenant_id: &str) -> Vec<String> {
        let db = tenant_db(tenant_id);
        let query = format!(
            "SELECT ip FROM {}.assets FINAL WHERE tenant_id = '{}' AND trusted = 1",
            db, sql_escape(tenant_id)
        );
        #[derive(clickhouse::Row, serde::Deserialize)]
        struct Row { ip: String }
        self.client.query(&query).fetch_all::<Row>().await
            .unwrap_or_default().into_iter().map(|r| r.ip).collect()
    }

    /// Mark a list of IPs as threat_flagged for a tenant (called after prediction).
    pub async fn mark_assets_threat_flagged(&self, tenant_id: &str, ips: &[String]) -> anyhow::Result<()> {
        if ips.is_empty() { return Ok(()); }
        let db = tenant_db(tenant_id);
        let ip_list = ips.iter().map(|ip| format!("'{}'", sql_escape(ip))).collect::<Vec<_>>().join(",");
        let query = format!(
            "ALTER TABLE {}.assets UPDATE threat_flagged = 1 \
             WHERE tenant_id = '{}' AND ip IN ({}) SETTINGS mutations_sync=0",
            db, sql_escape(tenant_id), ip_list
        );
        self.client.query(&query).execute().await?;
        Ok(())
    }

    /// Toggle the trusted flag on an asset (0→1 or 1→0).
    /// Get per-IP traffic profile from ndr_events for asset intelligence enrichment.
    pub async fn get_asset_traffic_profile(
        &self,
        tenant_id: &str,
        ip:        &str,
        hours:     u32,
    ) -> anyhow::Result<crate::enrichment::asset_intel::AssetTrafficProfile> {
        let db = tenant_db(tenant_id);
        let escaped_ip = sql_escape(ip);

        // Total connections where this IP appears
        let total: u64 = self.client
            .query(&format!(
                "SELECT count() FROM {db}.ndr_events \
                 WHERE (src_ip = '{escaped_ip}' OR dst_ip = '{escaped_ip}') \
                 AND timestamp > now() - INTERVAL {hours} HOUR",
                db = db, escaped_ip = escaped_ip, hours = hours
            ))
            .fetch_one::<u64>().await.unwrap_or(0);

        // Inbound: connections where this IP is the destination
        #[derive(clickhouse::Row, serde::Deserialize)]
        struct InboundRow { cnt: u64, unique_srcs: u64, ports: Vec<u16> }

        let inbound = self.client
            .query(&format!(
                "SELECT count() as cnt, uniqExact(src_ip) as unique_srcs, \
                 groupUniqArray(dst_port) as ports \
                 FROM {db}.ndr_events \
                 WHERE dst_ip = '{escaped_ip}' \
                 AND dst_port > 0 \
                 AND timestamp > now() - INTERVAL {hours} HOUR",
                db = db, escaped_ip = escaped_ip, hours = hours
            ))
            .fetch_optional::<InboundRow>().await
            .unwrap_or(None);

        let (inbound_cnt, unique_src_ips, mut open_ports) = inbound
            .map(|r| (r.cnt, r.unique_srcs, r.ports))
            .unwrap_or((0, 0, vec![]));

        // Keep only well-known service ports (< 32768) and deduplicate
        open_ports.retain(|&p| p > 0 && p < 32768);
        open_ports.sort_unstable();
        open_ports.dedup();
        open_ports.truncate(20);

        // Unique protocol count
        let proto_count: u64 = self.client
            .query(&format!(
                "SELECT uniqExact(log_type) FROM {db}.ndr_events \
                 WHERE (src_ip = '{escaped_ip}' OR dst_ip = '{escaped_ip}') \
                 AND timestamp > now() - INTERVAL {hours} HOUR",
                db = db, escaped_ip = escaped_ip, hours = hours
            ))
            .fetch_one::<u64>().await.unwrap_or(0);

        Ok(crate::enrichment::asset_intel::AssetTrafficProfile {
            total_conn_count:   total,
            inbound_conn_count: inbound_cnt,
            unique_src_ips,
            protocol_count:     proto_count,
            open_ports,
        })
    }

    /// Get the most common JA3 fingerprint for an IP and map it to an OS label.
    pub async fn get_ja3_os_for_ip(&self, tenant_id: &str, ip: &str) -> String {
        let db = tenant_db(tenant_id);
        let escaped = sql_escape(ip);
        let ja3: Option<String> = self.client
            .query(&format!(
                "SELECT JSONExtractString(raw, 'ja3') as ja3h \
                 FROM {db}.ndr_events \
                 WHERE src_ip = '{escaped}' \
                 AND log_type = 'ssl' \
                 AND JSONExtractString(raw, 'ja3') != '' \
                 AND timestamp > now() - INTERVAL 7 DAY \
                 GROUP BY ja3h ORDER BY count() DESC LIMIT 1",
                db = db, escaped = escaped
            ))
            .fetch_optional::<String>().await
            .unwrap_or(None);

        ja3.and_then(|h| crate::enrichment::asset_intel::ja3_lookup(&h).map(String::from))
            .unwrap_or_default()
    }

    /// Update asset intelligence fields computed by the enrichment task.
    pub async fn update_asset_intel(
        &self,
        tenant_id:   &str,
        ip:          &str,
        role:        &str,
        criticality: u8,
        open_ports:  &str,
        subnet_role: &str,
        ja3_os:      &str,
    ) -> anyhow::Result<()> {
        if let Ok(Some(mut asset)) = self.get_asset_by_ip(tenant_id, ip).await {
            if !role.is_empty()        { asset.role        = role.to_string(); }
            if criticality != 0        { asset.criticality = criticality; }
            if open_ports != "[]" && !open_ports.is_empty() { asset.open_ports = open_ports.to_string(); }
            if !subnet_role.is_empty() { asset.subnet_role = subnet_role.to_string(); }
            if !ja3_os.is_empty()      { asset.ja3_os      = ja3_os.to_string(); }
            // last_seen intentionally not updated — enrichment is not a network observation
            self.upsert_asset(&asset).await?;
        }
        Ok(())
    }

    /// Read subnet → role mappings from settings (stored as JSON array).
    pub async fn get_subnet_roles(&self, _tenant_id: &str) -> Vec<(String, String)> {
        let raw = self.get_global_setting("asset_subnet_roles").await.unwrap_or_default();
        if raw.is_empty() { return vec![]; }
        serde_json::from_str::<Vec<serde_json::Value>>(&raw)
            .unwrap_or_default()
            .into_iter()
            .filter_map(|v| {
                let cidr = v["cidr"].as_str()?.to_string();
                let role = v["role"].as_str()?.to_string();
                Some((cidr, role))
            })
            .collect()
    }

    /// Save subnet → role mappings to settings.
    pub async fn set_subnet_roles(&self, json: &str) -> anyhow::Result<()> {
        self.set_global_setting("asset_subnet_roles", json).await
    }

    pub async fn set_asset_trusted(&self, tenant_id: &str, ip: &str, trusted: bool) -> anyhow::Result<()> {
        if let Ok(Some(mut asset)) = self.get_asset_by_ip(tenant_id, ip).await {
            asset.trusted = if trusted { 1 } else { 0 };
            if trusted { asset.threat_flagged = 0; }
            asset.last_seen = chrono::Utc::now().timestamp() as u32;
            self.upsert_asset(&asset).await?;
        }
        Ok(())
    }

    pub async fn upsert_ipam_subnet(
        &self,
        tenant_id: &str,
        interface: &str,
        cidr: &str,
        local_ip: &str,
        gateway: &str,
        sensor_id: &str,
    ) -> anyhow::Result<()> {
        let db = tenant_db(tenant_id);
        let query = format!(
            "INSERT INTO {}.ipam_subnets \
             (tenant_id, interface, cidr, local_ip, gateway, sensor_id, first_seen, last_seen) \
             VALUES ('{}','{}','{}','{}','{}','{}', now(), now())",
            db,
            sql_escape(tenant_id), sql_escape(interface), sql_escape(cidr),
            sql_escape(local_ip), sql_escape(gateway), sql_escape(sensor_id)
        );
        self.client.query(&query).execute().await?;
        Ok(())
    }

    pub async fn get_ipam_subnets(&self, tenant_id: &str, sensor_ids: &[String]) -> anyhow::Result<Vec<serde_json::Value>> {
        let db = tenant_db(tenant_id);
        let assets = self.get_assets_by_tenant(tenant_id).await.unwrap_or_default();
        let sf = Self::sensor_filter(sensor_ids);

        let query = format!(
            "SELECT interface, cidr, local_ip, gateway, sensor_id, \
             toUnixTimestamp(min(first_seen)) as first_seen, toUnixTimestamp(max(last_seen)) as last_seen \
             FROM {db}.ipam_subnets WHERE tenant_id = '{tenant}'{sf} \
             GROUP BY interface, cidr, local_ip, gateway, sensor_id ORDER BY cidr",
            db = db, tenant = sql_escape(tenant_id), sf = sf
        );

        #[derive(clickhouse::Row, serde::Deserialize)]
        struct SubnetRow {
            interface:  String,
            cidr:       String,
            local_ip:   String,
            gateway:    String,
            sensor_id:  String,
            first_seen: u32,
            last_seen:  u32,
        }

        let rows = self.client.query(&query).fetch_all::<SubnetRow>().await.unwrap_or_default();

        let mut result = Vec::new();
        for row in rows {
            // Count confirmed assets (have MAC) whose IP falls inside this subnet
            let used: Vec<&AssetRow> = assets.iter().filter(|a| {
                !a.mac.is_empty() && is_ip_in_cidr(&a.ip, &row.cidr)
            }).collect();

            // Calculate total IPs in subnet
            let total_ips = cidr_host_count(&row.cidr);

            result.push(serde_json::json!({
                "interface":  row.interface,
                "cidr":       row.cidr,
                "local_ip":   row.local_ip,
                "gateway":    row.gateway,
                "sensor_id":  row.sensor_id,
                "first_seen": row.first_seen,
                "last_seen":  row.last_seen,
                "used_ips":   used.len(),
                "total_ips":  total_ips,
                "free_ips":   total_ips.saturating_sub(used.len()),
            }));
        }
        Ok(result)
    }

    /// Migrate existing tenant DBs: create ipam_subnets if not present.
    pub async fn migrate_ipam_subnets(&self) {
        if let Ok(tenants) = self.get_all_tenants().await {
            for tenant in &tenants {
                let db = tenant_db(tenant);
                let q = format!(
                    "CREATE TABLE IF NOT EXISTS {}.ipam_subnets \
                     (tenant_id String DEFAULT '{}', interface String DEFAULT '', \
                      cidr String, local_ip String DEFAULT '', gateway String DEFAULT '', \
                      sensor_id String DEFAULT '', \
                      first_seen DateTime DEFAULT now(), last_seen DateTime DEFAULT now()) \
                     ENGINE = ReplacingMergeTree(last_seen) ORDER BY (tenant_id, cidr)",
                    db, tenant
                );
                if let Err(e) = self.client.query(&q).execute().await {
                    tracing::debug!("ipam_subnets migrate {}: {}", tenant, e);
                }
            }
        }
    }

    // ── Active Blocks ─────────────────────────────────────────────────────────

#[cfg(feature = "soar")]
    pub async fn insert_active_block(&self, b: &crate::soar::ActiveBlock) -> anyhow::Result<()> {
        let q = format!(
            "INSERT INTO ndr.active_blocks \
             (id, src_ip, src_port, dst_ip, dst_port, community_id, triggered_by, \
              sensor_id, firewall_type, firewall_rule_id, rst_injected, duration_hours, \
              expires_at, status, reason, tenant_id) \
             VALUES ('{}','{}',{},'{}'  ,{} ,'{}','{}','{}','{}','{}',{},{},\
                     toDateTime('{}'),'{}','{}','{}')",
            sql_escape(&b.id), sql_escape(&b.src_ip), b.src_port,
            sql_escape(&b.dst_ip), b.dst_port,
            sql_escape(&b.community_id), sql_escape(&b.triggered_by),
            sql_escape(&b.sensor_id), sql_escape(&b.firewall_type),
            sql_escape(&b.firewall_rule_id), b.rst_injected, b.duration_hours,
            sql_escape(&b.expires_at), sql_escape(&b.status),
            sql_escape(&b.reason), sql_escape(&b.tenant_id),
        );
        self.client.query(&q).execute().await?;
        Ok(())
    }

#[cfg(feature = "soar")]
    pub async fn list_active_blocks(&self, tenant_id: &str) -> anyhow::Result<Vec<crate::soar::ActiveBlock>> {
        let where_clause = if tenant_id == "superadmin" {
            "1=1".to_string()
        } else {
            format!("tenant_id = '{}'", sql_escape(tenant_id))
        };
        let q = format!(
            "SELECT id, src_ip, src_port, dst_ip, dst_port, community_id, triggered_by, \
             sensor_id, firewall_type, firewall_rule_id, rst_injected, duration_hours, \
             toString(expires_at) AS expires_at, status, reason, tenant_id, \
             toString(created_at) AS created_at \
             FROM ndr.active_blocks FINAL \
             WHERE {} ORDER BY created_at DESC LIMIT 200",
            where_clause
        );
        #[derive(clickhouse::Row, serde::Deserialize)]
        struct Row {
            id: String, src_ip: String, src_port: u16, dst_ip: String, dst_port: u16,
            community_id: String, triggered_by: String, sensor_id: String,
            firewall_type: String, firewall_rule_id: String, rst_injected: u8,
            duration_hours: u16, expires_at: String, status: String, reason: String,
            tenant_id: String, created_at: String,
        }
        let rows = self.client.query(&q).fetch_all::<Row>().await?;
        Ok(rows.into_iter().map(|r| crate::soar::ActiveBlock {
            id: r.id, src_ip: r.src_ip, src_port: r.src_port,
            dst_ip: r.dst_ip, dst_port: r.dst_port,
            community_id: r.community_id, triggered_by: r.triggered_by,
            sensor_id: r.sensor_id, firewall_type: r.firewall_type,
            firewall_rule_id: r.firewall_rule_id, rst_injected: r.rst_injected,
            duration_hours: r.duration_hours, expires_at: r.expires_at,
            status: r.status, reason: r.reason,
            tenant_id: r.tenant_id, created_at: r.created_at,
        }).collect())
    }

#[cfg(feature = "soar")]
    pub async fn revoke_active_block(&self, id: &str, tenant_id: &str) -> anyhow::Result<Option<crate::soar::ActiveBlock>> {
        // Fetch the block first (need firewall_rule_id, firewall_type, src_ip for cleanup)
        let blocks = self.list_active_blocks(tenant_id).await?;
        let block  = blocks.into_iter().find(|b| b.id == id).map(|b| b.clone());

        let where_clause = if tenant_id == "superadmin" {
            format!("id = '{}'", sql_escape(id))
        } else {
            format!("id = '{}' AND tenant_id = '{}'", sql_escape(id), sql_escape(tenant_id))
        };
        let q = format!(
            "ALTER TABLE ndr.active_blocks UPDATE status = 'revoked' WHERE {} SETTINGS mutations_sync=1",
            where_clause
        );
        self.client.query(&q).execute().await?;
        Ok(block)
    }

    // ── Device isolations ──────────────────────────────────────────────────

#[cfg(feature = "soar")]
    pub async fn insert_isolation(&self, iso: &crate::soar::DeviceIsolation) -> anyhow::Result<()> {
        let q = format!(
            "INSERT INTO ndr.device_isolations \
             (id, tenant_id, target_ip, gateway_ip, method, enforcement, \
              enforcement_detail, triggered_by, sensor_id, reason, status) \
             VALUES ('{}','{}','{}','{}','{}','{}','{}','{}','{}','{}','{}')",
            sql_escape(&iso.id),     sql_escape(&iso.tenant_id),
            sql_escape(&iso.target_ip), sql_escape(&iso.gateway_ip),
            sql_escape(&iso.method), sql_escape(&iso.enforcement),
            sql_escape(&iso.enforcement_detail), sql_escape(&iso.triggered_by),
            sql_escape(&iso.sensor_id), sql_escape(&iso.reason),
            sql_escape(&iso.status),
        );
        self.client.query(&q).execute().await?;
        Ok(())
    }

#[cfg(feature = "soar")]
    pub async fn list_isolations(&self, tenant_id: &str) -> anyhow::Result<Vec<crate::soar::DeviceIsolation>> {
        let where_clause = if tenant_id == "superadmin" {
            "status = 'active'".to_string()
        } else {
            format!("tenant_id = '{}' AND status = 'active'", sql_escape(tenant_id))
        };
        let q = format!(
            "SELECT id, tenant_id, target_ip, gateway_ip, method, enforcement, \
             enforcement_detail, triggered_by, sensor_id, reason, status, \
             toString(created_at) AS created_at, toString(updated_at) AS updated_at \
             FROM ndr.device_isolations FINAL \
             WHERE {} ORDER BY created_at DESC LIMIT 200",
            where_clause
        );
        #[derive(clickhouse::Row, serde::Deserialize)]
        struct Row {
            id: String, tenant_id: String, target_ip: String, gateway_ip: String,
            method: String, enforcement: String, enforcement_detail: String,
            triggered_by: String, sensor_id: String, reason: String, status: String,
            created_at: String, updated_at: String,
        }
        let rows = self.client.query(&q).fetch_all::<Row>().await?;
        Ok(rows.into_iter().map(|r| crate::soar::DeviceIsolation {
            id: r.id, tenant_id: r.tenant_id, target_ip: r.target_ip,
            gateway_ip: r.gateway_ip, method: r.method, enforcement: r.enforcement,
            enforcement_detail: r.enforcement_detail, triggered_by: r.triggered_by,
            sensor_id: r.sensor_id, reason: r.reason, status: r.status,
            created_at: r.created_at, updated_at: r.updated_at,
        }).collect())
    }

    /// Persist a manual IOC to the ioc_watchlist table so it survives restarts.
    // ── Incident (attack story) storage ─────────────────────────────────────

    pub async fn save_incident(
        &self,
        tenant_id:    &str,
        id:           &str,
        title:        &str,
        severity:     &str,
        affected_ips: &[String],
        attack_chain: &str,
        alert_ids:    &[String],
        first_seen:   i64,
        last_seen:    i64,
    ) -> anyhow::Result<()> {
        let ips_arr = affected_ips.iter()
            .map(|s| format!("'{}'", sql_escape(s)))
            .collect::<Vec<_>>().join(",");
        let ids_arr = alert_ids.iter()
            .map(|s| format!("'{}'", sql_escape(s)))
            .collect::<Vec<_>>().join(",");
        self.client.query(&format!(
            "INSERT INTO ndr.ndr_incidents \
             (id, tenant_id, title, severity, status, affected_ips, attack_chain, \
              alert_ids, first_seen, last_seen) VALUES \
             ('{id}', '{tid}', '{title}', '{sev}', 'active', [{ips}], '{chain}', [{aids}], \
              fromUnixTimestamp({fs}), fromUnixTimestamp({ls}))",
            id    = sql_escape(id),
            tid   = sql_escape(tenant_id),
            title = sql_escape(title),
            sev   = sql_escape(severity),
            ips   = ips_arr,
            chain = sql_escape(attack_chain),
            aids  = ids_arr,
            fs    = first_seen,
            ls    = last_seen,
        )).execute().await?;
        Ok(())
    }

    pub async fn get_incidents(&self, tenant_id: &str) -> anyhow::Result<Vec<serde_json::Value>> {
        #[derive(clickhouse::Row, serde::Deserialize)]
        struct Row {
            id:           String,
            title:        String,
            severity:     String,
            status:       String,
            affected_ips: Vec<String>,
            attack_chain: String,
            alert_ids:    Vec<String>,
            first_seen:   u32,
            last_seen:    u32,
        }
        let rows = self.client.query(&format!(
            "SELECT id, title, severity, status, affected_ips, attack_chain, alert_ids, \
                    toUnixTimestamp(first_seen), toUnixTimestamp(last_seen) \
             FROM ndr.ndr_incidents FINAL \
             WHERE tenant_id = '{}' \
             ORDER BY last_seen DESC \
             LIMIT 200",
            sql_escape(tenant_id)
        )).fetch_all::<Row>().await?;

        Ok(rows.iter().map(|r| serde_json::json!({
            "id":           r.id,
            "title":        r.title,
            "severity":     r.severity,
            "status":       r.status,
            "affected_ips": r.affected_ips,
            "attack_chain": serde_json::from_str::<serde_json::Value>(&r.attack_chain)
                                .unwrap_or(serde_json::json!([])),
            "alert_ids":    r.alert_ids,
            "first_seen":   r.first_seen,
            "last_seen":    r.last_seen,
        })).collect())
    }

    pub async fn incident_exists_for_alerts(&self, tenant_id: &str, alert_ids: &[String]) -> bool {
        if alert_ids.is_empty() { return false; }
        let ids = alert_ids.iter()
            .map(|s| format!("'{}'", sql_escape(s)))
            .collect::<Vec<_>>().join(",");
        self.client.query(&format!(
            "SELECT count() FROM ndr.ndr_incidents FINAL \
             WHERE tenant_id = '{}' AND hasAny(alert_ids, [{}])",
            sql_escape(tenant_id), ids
        )).fetch_one::<u64>().await.map(|n| n > 0).unwrap_or(false)
    }

    pub async fn update_incident_status(
        &self,
        tenant_id: &str,
        id:        &str,
        status:    &str,
    ) -> anyhow::Result<()> {
        self.client.query(&format!(
            "INSERT INTO ndr.ndr_incidents (id, tenant_id, status, last_seen) \
             VALUES ('{}', '{}', '{}', now())",
            sql_escape(id), sql_escape(tenant_id), sql_escape(status)
        )).execute().await?;
        Ok(())
    }

    /// Ensure the built-in local sensor always appears in the sensor_keys table.
    /// local-central connects via Vector→Kafka (no API key), so it is never written
    /// by normal registration. After a DB wipe this would leave 0 sensors in the UI.
    pub async fn seed_local_sensor(&self) {
        let tenant_id  = std::env::var("TENANT_ID").unwrap_or_else(|_| "default".to_string());
        let sensor_id  = std::env::var("LOCAL_SENSOR_ID").unwrap_or_else(|_| "local-central".to_string());
        let fixed_id   = "00000000-0000-0000-0000-000000000001";

        // Check if the row already exists
        let exists: bool = self.client
            .query(&format!(
                "SELECT count() FROM ndr.sensor_keys FINAL WHERE id = '{}'", fixed_id
            ))
            .fetch_one::<u64>().await
            .map(|n| n > 0)
            .unwrap_or(false);

        if exists { return; }

        let q = format!(
            "INSERT INTO ndr.sensor_keys \
             (id, key_hash, key_prefix, tenant_id, name, active) \
             VALUES ('{}', '', '{}', '{}', 'Local Sensor', 1)",
            fixed_id,
            sql_escape(&sensor_id),
            sql_escape(&tenant_id),
        );
        if let Err(e) = self.client.query(&q).execute().await {
            tracing::warn!("seed_local_sensor: failed — {}", e);
        } else {
            tracing::info!("seed_local_sensor: inserted local sensor '{}' for tenant '{}'", sensor_id, tenant_id);
        }
    }

    pub async fn save_watchlist_ioc(
        &self,
        tenant_id:      &str,
        ioc_type:       &str,
        value:          &str,
        attacker_group: &str,
    ) -> anyhow::Result<()> {
        self.client.query(&format!(
            "INSERT INTO ndr.ioc_watchlist \
             (tenant_id, ioc_type, ioc_value, source, attacker_group, active) \
             VALUES ('{}', '{}', '{}', 'manual', '{}', 1)",
            sql_escape(tenant_id), sql_escape(ioc_type), sql_escape(value), sql_escape(attacker_group)
        )).execute().await?;
        Ok(())
    }

    /// List manual IOCs for a specific tenant (for the UI watchlist view).
    pub async fn get_watchlist_iocs_by_tenant(&self, tenant_id: &str) -> anyhow::Result<Vec<serde_json::Value>> {
        #[derive(clickhouse::Row, serde::Deserialize)]
        struct Row { ioc_type: String, ioc_value: String, attacker_group: String, created_at: u32 }
        let rows = self.client
            .query(&format!(
                "SELECT ioc_type, ioc_value, attacker_group, toUnixTimestamp(added_at) as created_at \
                 FROM ndr.ioc_watchlist FINAL \
                 WHERE tenant_id = '{}' AND active = 1 AND expires_at > now() \
                 ORDER BY created_at DESC",
                sql_escape(tenant_id)
            ))
            .fetch_all::<Row>().await?;
        Ok(rows.into_iter().map(|r| serde_json::json!({
            "type":           r.ioc_type,
            "value":          r.ioc_value,
            "attacker_group": r.attacker_group,
            "added_at":       r.created_at,
            "source":         "manual"
        })).collect())
    }

    /// Soft-delete a manual IOC from the watchlist.
    pub async fn delete_watchlist_ioc(&self, tenant_id: &str, value: &str) -> anyhow::Result<()> {
        // Do not touch updated_at — it may be a ReplacingMergeTree key column.
        self.client.query(&format!(
            "ALTER TABLE ndr.ioc_watchlist UPDATE active = 0 \
             WHERE tenant_id = '{}' AND ioc_value = '{}' SETTINGS mutations_sync=1",
            sql_escape(tenant_id), sql_escape(value)
        )).execute().await?;
        Ok(())
    }

    /// Load all active, non-expired watchlist IOCs — called at startup to
    /// seed the in-memory threat-intel store from persisted manual additions.
    pub async fn load_watchlist_iocs(&self) -> anyhow::Result<Vec<(String, String)>> {
        #[derive(clickhouse::Row, serde::Deserialize)]
        struct Row { ioc_type: String, ioc_value: String }
        let rows = self.client
            .query(
                "SELECT ioc_type, ioc_value FROM ndr.ioc_watchlist FINAL \
                 WHERE active = 1 AND expires_at > now()"
            )
            .fetch_all::<Row>().await?;
        Ok(rows.into_iter().map(|r| (r.ioc_type, r.ioc_value)).collect())
    }

#[cfg(feature = "soar")]
    pub async fn restore_isolation(&self, id: &str, tenant_id: &str) -> anyhow::Result<Option<crate::soar::DeviceIsolation>> {
        let isolations = self.list_isolations(tenant_id).await?;
        let iso = isolations.into_iter().find(|i| i.id == id);

        if let Some(ref i) = iso {
            // INSERT a new row with status='restored' — ReplacingMergeTree(updated_at)
            // picks this up immediately under FINAL, no async mutation needed.
            let q = format!(
                "INSERT INTO ndr.device_isolations \
                 (id, tenant_id, target_ip, gateway_ip, method, enforcement, \
                  enforcement_detail, triggered_by, sensor_id, reason, status, updated_at) \
                 VALUES ('{}','{}','{}','{}','{}','{}','{}','{}','{}','{}','restored', now())",
                sql_escape(&i.id), sql_escape(&i.tenant_id),
                sql_escape(&i.target_ip), sql_escape(&i.gateway_ip),
                sql_escape(&i.method), sql_escape(&i.enforcement),
                sql_escape(&i.enforcement_detail), sql_escape(&i.triggered_by),
                sql_escape(&i.sensor_id), sql_escape(&i.reason),
            );
            self.client.query(&q).execute().await?;
        }
        Ok(iso)
    }

    // ── DoH Providers ────────────────────────────────────────────────────────

    /// Seed the doh_providers table with well-known public DoH resolver IPs.
    /// Idempotent — skips if any rows already exist.
    pub async fn seed_doh_providers(&self) {
        #[derive(clickhouse::Row, serde::Deserialize)]
        struct Cnt { cnt: u64 }
        let cnt: u64 = self.client
            .query("SELECT count() AS cnt FROM ndr.doh_providers")
            .fetch_one::<Cnt>().await
            .map(|r| r.cnt)
            .unwrap_or(0);
        if cnt > 0 { return; }

        let providers = [
            ("1.1.1.1",           "Cloudflare"),
            ("1.0.0.1",           "Cloudflare"),
            ("8.8.8.8",           "Google"),
            ("8.8.4.4",           "Google"),
            ("9.9.9.9",           "Quad9"),
            ("149.112.112.112",   "Quad9"),
            ("208.67.222.222",    "OpenDNS"),
            ("208.67.220.220",    "OpenDNS"),
            ("94.140.14.14",      "AdGuard"),
            ("94.140.15.15",      "AdGuard"),
            ("185.228.168.168",   "CleanBrowsing"),
            ("185.228.169.168",   "CleanBrowsing"),
            ("76.76.2.0",         "Alternate DNS"),
            ("76.76.10.0",        "Alternate DNS"),
        ];
        for (ip, name) in &providers {
            let q = format!(
                "INSERT INTO ndr.doh_providers (ip, provider_name, enabled) \
                 VALUES ('{}', '{}', 1)",
                sql_escape(ip), sql_escape(name)
            );
            let _ = self.client.query(&q).execute().await;
        }
        tracing::info!("seed_doh_providers: seeded {} entries", providers.len());
    }

    /// Load all enabled DoH provider IPs into a HashSet for fast lookup.
    pub async fn load_doh_providers(&self) -> anyhow::Result<std::collections::HashSet<String>> {
        #[derive(clickhouse::Row, serde::Deserialize)]
        struct Row { ip: String }
        let rows = self.client
            .query("SELECT ip FROM ndr.doh_providers FINAL WHERE enabled = 1")
            .fetch_all::<Row>().await?;
        Ok(rows.into_iter().map(|r| r.ip).collect())
    }

    /// Return all DoH providers as JSON for the admin API.
    pub async fn list_doh_providers(&self) -> anyhow::Result<Vec<serde_json::Value>> {
        #[derive(clickhouse::Row, serde::Deserialize)]
        struct Row { ip: String, provider_name: String, enabled: u8 }
        let rows = self.client
            .query("SELECT ip, provider_name, enabled FROM ndr.doh_providers FINAL ORDER BY ip")
            .fetch_all::<Row>().await?;
        Ok(rows.into_iter().map(|r| serde_json::json!({
            "ip": r.ip, "provider_name": r.provider_name, "enabled": r.enabled == 1
        })).collect())
    }

    pub async fn add_doh_provider(&self, ip: &str, provider_name: &str) -> anyhow::Result<()> {
        self.client.query(&format!(
            "INSERT INTO ndr.doh_providers (ip, provider_name, enabled) VALUES ('{}', '{}', 1)",
            sql_escape(ip), sql_escape(provider_name)
        )).execute().await?;
        Ok(())
    }

    pub async fn remove_doh_provider(&self, ip: &str) -> anyhow::Result<()> {
        self.client.query(&format!(
            "INSERT INTO ndr.doh_providers (ip, provider_name, enabled) VALUES ('{}', '', 0)",
            sql_escape(ip)
        )).execute().await?;
        Ok(())
    }

    /// Called at startup when a verified license is present.
    /// Creates the tenant row in ndr.tenants if it does not already exist,
    /// then sets its features from the license claims.
    /// Called at startup when a verified license is present for a non-default tenant.
    /// 1. Creates the tenant row if missing and syncs features from license.
    /// 2. If CUSTOMER_ADMIN_USER + CUSTOMER_ADMIN_PASS are set in env (written by install-customer.sh),
    ///    creates a super_admin user for this tenant, deactivates the default seed accounts
    ///    (admin / tenant-admin), and clears the plaintext password from the .env file.
    pub async fn ensure_license_tenant(
        &self,
        tenant_id:   &str,
        tenant_name: &str,
        features:    &[String],
    ) {
        // 1. Create tenant row if missing
        let exists: bool = self.client
            .query(&format!(
                "SELECT count() FROM ndr.tenants FINAL WHERE id = '{}'",
                sql_escape(tenant_id)
            ))
            .fetch_one::<u64>().await
            .map(|n| n > 0)
            .unwrap_or(false);

        if !exists {
            tracing::info!("License tenant '{}' not found — creating", tenant_id);
            if let Err(e) = self.create_tenant(tenant_id, tenant_name).await {
                tracing::warn!("ensure_license_tenant create failed: {}", e);
            }
        }

        // 2. Sync features from license (source of truth)
        let features_str = features.join(",");
        let _ = self.client.query(&format!(
            "INSERT INTO ndr.tenants (id, name, active, ai_enabled, features, updated_at, created_at) \
             SELECT id, name, active, ai_enabled, '{}', now(), created_at \
             FROM ndr.tenants FINAL WHERE id = '{}'",
            sql_escape(&features_str),
            sql_escape(tenant_id),
        )).execute().await;

        // 3. Tenant admin provisioning (one-time, driven by install-customer.sh)
        //    TENANT_ADMIN_USER / TENANT_ADMIN_PASS set by the install script.
        let admin_user = std::env::var("TENANT_ADMIN_USER").unwrap_or_default();
        let admin_pass = std::env::var("TENANT_ADMIN_PASS").unwrap_or_default();

        if !admin_user.trim().is_empty() && !admin_pass.trim().is_empty() {
            let user_exists: bool = self.client
                .query(&format!(
                    "SELECT count() FROM ndr.users FINAL WHERE username = '{}' AND active = 1",
                    sql_escape(admin_user.trim())
                ))
                .fetch_one::<u64>().await
                .map(|n| n > 0)
                .unwrap_or(false);

            if !user_exists {
                // Build permissions from the licensed features
                let mut perms = vec![
                    "dashboard", "alerts", "logs", "live",
                    "network-map", "intel", "health", "users", "evidence", "assets",
                ];
                if features.iter().any(|f| f == "ndr") {
                    perms.extend_from_slice(&["rules", "sensors"]);
                }
                if features.iter().any(|f| f == "ai") {
                    perms.extend_from_slice(&["ai-activity", "ai-report"]);
                }
                if features.iter().any(|f| f == "soar") {
                    perms.push("soar");
                }
                let permissions = perms.join(",");

                match bcrypt::hash(admin_pass.trim(), 12) {
                    Ok(hash) => {
                        let id = uuid::Uuid::new_v4().to_string();
                        let _ = self.client.query(&format!(
                            "INSERT INTO ndr.users \
                             (id, username, password_hash, role, tenant_id, permissions, active) \
                             VALUES ('{}', '{}', '{}', 'tenant_admin', '{}', '{}', 1)",
                            sql_escape(&id),
                            sql_escape(admin_user.trim()),
                            sql_escape(&hash),
                            sql_escape(tenant_id),
                            sql_escape(&permissions),
                        )).execute().await;
                        tracing::info!(
                            "tenant_admin '{}' created for '{}' — permissions: {}",
                            admin_user.trim(), tenant_id, permissions
                        );

                        // Permanently delete seed accounts — known credentials from init.sql.
                        // mutations_sync=1: these are known/public default credentials being
                        // removed for security — must be gone immediately, not eventually.
                        let _ = self.client.query(
                            "ALTER TABLE ndr.users DELETE \
                             WHERE username IN ('admin', 'tenant-admin') AND tenant_id = 'default' \
                             SETTINGS mutations_sync=1"
                        ).execute().await;

                        // Delete the 'default' tenant row — not needed on licensed installs
                        let _ = self.client.query(
                            "ALTER TABLE ndr.tenants DELETE WHERE id = 'default' SETTINGS mutations_sync=1"
                        ).execute().await;

                        // Clear plaintext password from .env after use
                        let env_path = format!(
                            "{}/.env",
                            std::env::var("INSTALL_DIR").unwrap_or_else(|_| ".".to_string())
                        );
                        if let Ok(content) = std::fs::read_to_string(&env_path) {
                            let cleaned = content.lines()
                                .map(|l| if l.starts_with("TENANT_ADMIN_PASS=") { "TENANT_ADMIN_PASS=" } else { l })
                                .collect::<Vec<_>>()
                                .join("\n");
                            let _ = std::fs::write(&env_path, cleaned + "\n");
                        }
                    }
                    Err(e) => tracing::warn!("bcrypt hash failed: {}", e),
                }
            } else {
                tracing::info!("tenant_admin '{}' already exists — skipping", admin_user.trim());
            }
        }

        tracing::info!("License tenant '{}' ready — features: {:?}", tenant_id, features);
    }

    pub async fn ensure_licenses_table(&self) {
        let _ = self.client.query(
            "CREATE TABLE IF NOT EXISTS ndr.licenses (
                id          String,
                tenant_id   String,
                tenant_name String,
                features    String,
                max_sensors UInt32,
                admin_user  String DEFAULT '',
                issued_at   DateTime DEFAULT now(),
                expires_at  DateTime,
                token       String
            ) ENGINE = ReplacingMergeTree(issued_at)
            ORDER BY (tenant_id, id)"
        ).execute().await;
        // Add column to existing tables that were created before this field existed
        let _ = self.client.query(
            "ALTER TABLE ndr.licenses ADD COLUMN IF NOT EXISTS admin_user String DEFAULT ''"
        ).execute().await;
    }

    pub async fn insert_license(
        &self,
        tenant_id:    &str,
        tenant_name:  &str,
        features:     &[String],
        max_sensors:  u32,
        expires_days: u32,
        admin_user:   &str,
        token:        &str,
    ) -> anyhow::Result<()> {
        let id = uuid::Uuid::new_v4().to_string();
        let features_str = features.join(",");
        self.client.query(&format!(
            "INSERT INTO ndr.licenses (id, tenant_id, tenant_name, features, max_sensors, admin_user, issued_at, expires_at, token) \
             VALUES ('{}', '{}', '{}', '{}', {}, '{}', now(), now() + INTERVAL {} DAY, '{}')",
            sql_escape(&id),
            sql_escape(tenant_id),
            sql_escape(tenant_name),
            sql_escape(&features_str),
            max_sensors,
            sql_escape(admin_user),
            expires_days,
            sql_escape(token),
        )).execute().await?;
        Ok(())
    }

    pub async fn list_licenses(&self, tenant_id: Option<&str>) -> anyhow::Result<Vec<serde_json::Value>> {
        let where_clause = tenant_id
            .map(|id| format!("WHERE tenant_id = '{}'", sql_escape(id)))
            .unwrap_or_default();
        let rows = self.client
            .query(&format!(
                "SELECT id, tenant_id, tenant_name, features, max_sensors, admin_user, \
                 formatDateTime(issued_at, '%Y-%m-%dT%H:%i:%SZ') as issued_at, \
                 formatDateTime(expires_at, '%Y-%m-%dT%H:%i:%SZ') as expires_at, \
                 token \
                 FROM ndr.licenses FINAL \
                 {} ORDER BY issued_at DESC LIMIT 200",
                where_clause
            ))
            .fetch_all::<(String, String, String, String, u32, String, String, String, String)>()
            .await?;
        Ok(rows.into_iter().map(|r| {
            let features: Vec<&str> = r.3.split(',').filter(|s| !s.is_empty()).collect();
            serde_json::json!({
                "id":          r.0,
                "tenant_id":   r.1,
                "tenant_name": r.2,
                "features":    features,
                "max_sensors": r.4,
                "admin_user":  r.5,
                "issued_at":   r.6,
                "expires_at":  r.7,
                "token":       r.8,
            })
        }).collect())
    }

    pub async fn delete_license(&self, id: &str) -> anyhow::Result<()> {
        self.client
            .query(&format!(
                "ALTER TABLE ndr.licenses DELETE WHERE id = '{}' SETTINGS mutations_sync=1",
                sql_escape(id)
            ))
            .execute()
            .await?;
        Ok(())
    }

    // ── Honeypots ─────────────────────────────────────────────────────────────

    pub async fn ensure_honeypots_table(&self) {
        let _ = self.client.query(
            "CREATE TABLE IF NOT EXISTS ndr.honeypots (
                id          String,
                tenant_id   String,
                name        String,
                cidr        String,
                description String DEFAULT '',
                active      UInt8 DEFAULT 1,
                created_at  DateTime DEFAULT now()
            ) ENGINE = ReplacingMergeTree(created_at)
            ORDER BY (tenant_id, id)"
        ).execute().await;
    }

    pub async fn get_honeypots(&self, tenant_id: &str) -> anyhow::Result<Vec<serde_json::Value>> {
        let rows = self.client
            .query(&format!(
                "SELECT id, tenant_id, name, cidr, description, active, \
                 formatDateTime(created_at, '%Y-%m-%dT%H:%i:%SZ') \
                 FROM ndr.honeypots FINAL \
                 WHERE active = 1 AND tenant_id = '{}' \
                 ORDER BY created_at DESC",
                sql_escape(tenant_id)
            ))
            .fetch_all::<(String, String, String, String, String, u8, String)>()
            .await?;
        Ok(rows.into_iter().map(|r| serde_json::json!({
            "id":          r.0,
            "tenant_id":   r.1,
            "name":        r.2,
            "cidr":        r.3,
            "description": r.4,
            "active":      r.5 == 1,
            "created_at":  r.6,
        })).collect())
    }

    pub async fn get_all_honeypots(&self) -> anyhow::Result<Vec<serde_json::Value>> {
        let rows = self.client
            .query(
                "SELECT id, tenant_id, name, cidr, description, active, \
                 formatDateTime(created_at, '%Y-%m-%dT%H:%i:%SZ') \
                 FROM ndr.honeypots FINAL \
                 WHERE active = 1 \
                 ORDER BY tenant_id, created_at DESC"
            )
            .fetch_all::<(String, String, String, String, String, u8, String)>()
            .await?;
        Ok(rows.into_iter().map(|r| serde_json::json!({
            "id":          r.0,
            "tenant_id":   r.1,
            "name":        r.2,
            "cidr":        r.3,
            "description": r.4,
            "active":      r.5 == 1,
            "created_at":  r.6,
        })).collect())
    }

    pub async fn add_honeypot(
        &self,
        id:          &str,
        tenant_id:   &str,
        name:        &str,
        cidr:        &str,
        description: &str,
    ) -> anyhow::Result<()> {
        self.client.query(&format!(
            "INSERT INTO ndr.honeypots (id, tenant_id, name, cidr, description, active) \
             VALUES ('{}', '{}', '{}', '{}', '{}', 1)",
            sql_escape(id),
            sql_escape(tenant_id),
            sql_escape(name),
            sql_escape(cidr),
            sql_escape(description),
        )).execute().await?;
        Ok(())
    }

    pub async fn delete_honeypot(&self, id: &str, tenant_id: &str) -> anyhow::Result<()> {
        self.client.query(&format!(
            "ALTER TABLE ndr.honeypots UPDATE active = 0 \
             WHERE id = '{}' AND tenant_id = '{}' \
             SETTINGS mutations_sync = 1",
            sql_escape(id),
            sql_escape(tenant_id),
        )).execute().await?;
        Ok(())
    }

    /// Returns Vec<(cidr, tenant_id)> for all active honeypots across all tenants.
    pub async fn get_all_honeypot_cidrs(&self) -> anyhow::Result<Vec<(String, String)>> {
        let rows = self.client
            .query(
                "SELECT cidr, tenant_id FROM ndr.honeypots FINAL WHERE active = 1"
            )
            .fetch_all::<(String, String)>()
            .await?;
        Ok(rows)
    }

    // ── Retrospective Detection ───────────────────────────────────────────────

    pub async fn get_events_for_retrospective(
        &self,
        tenant_id: &str,
        hours_back: u32,
        limit: u32,
    ) -> anyhow::Result<Vec<serde_json::Value>> {
        let safe_limit = limit.min(100_000);
        let db = tenant_db(tenant_id);
        // Query ndr_hits (detection alerts) — not ndr_events (raw flows).
        // ReplicatedMergeTree does not support FINAL, so omit it.
        let rows = self.client
            .query(&format!(
                "SELECT src_ip, dst_ip, toString(score), severity, \
                 arrayStringConcat(sigma_hits, ','), community_id, toString(timestamp) \
                 FROM {}.ndr_hits \
                 WHERE timestamp > now() - INTERVAL {} HOUR \
                 ORDER BY timestamp DESC \
                 LIMIT {}",
                db, hours_back, safe_limit
            ))
            .fetch_all::<(String, String, String, String, String, String, String)>()
            .await?;
        Ok(rows.into_iter().map(|r| serde_json::json!({
            "src_ip":           r.0,
            "dst_ip":           r.1,
            "score":            r.2,
            "severity":         r.3,
            "alert_signature":  r.4,   // sigma_hits joined — contains rule SIDs
            "community_id":     r.5,
            "ts":               r.6,
            "tenant_id":        tenant_id,
        })).collect())
    }

    pub async fn save_retro_scan(
        &self,
        id: &str, rule_id: &str, rule_name: &str, rule_content: &str,
        hours_back: u32, status: &str,
        started_at: u32, completed_at: u32,
        match_count: usize, matches_json: String, tenant_id: &str,
    ) -> anyhow::Result<()> {
        let row = RetroScanRow {
            id:           id.to_string(),
            rule_id:      rule_id.to_string(),
            rule_name:    rule_name.to_string(),
            rule_content: rule_content.to_string(),
            hours_back,
            status:       status.to_string(),
            started_at,
            completed_at,
            match_count:  match_count as u64,
            matches:      matches_json,
            tenant_id:    tenant_id.to_string(),
            updated_at:   chrono::Utc::now().timestamp() as u32,
        };
        let mut ins = self.client.insert("ndr.retro_scans")?;
        ins.write(&row).await?;
        ins.end().await?;
        Ok(())
    }

    pub async fn list_retro_scans_for_tenant(
        &self,
        tenant_id: &str,
    ) -> anyhow::Result<Vec<RetroScanReadRow>> {
        Ok(self.client
            .query(&format!(
                "SELECT id, rule_id, rule_name, rule_content, hours_back, status, \
                 started_at, completed_at, match_count, matches \
                 FROM ndr.retro_scans FINAL \
                 WHERE tenant_id = '{}' ORDER BY started_at DESC LIMIT 200",
                sql_escape(tenant_id)
            ))
            .fetch_all::<RetroScanReadRow>()
            .await?)
    }

    pub async fn get_retro_scan_by_id(
        &self,
        tenant_id: &str,
        id: &str,
    ) -> anyhow::Result<Option<RetroScanReadRow>> {
        let rows = self.client
            .query(&format!(
                "SELECT id, rule_id, rule_name, rule_content, hours_back, status, \
                 started_at, completed_at, match_count, matches \
                 FROM ndr.retro_scans FINAL \
                 WHERE tenant_id = '{}' AND id = '{}' LIMIT 1",
                sql_escape(tenant_id),
                sql_escape(id)
            ))
            .fetch_all::<RetroScanReadRow>()
            .await?;
        Ok(rows.into_iter().next())
    }

    /// Returns distinct rule names that have actually fired, with hit counts and top severity.
    /// Covers both Agent-S (Suricata) alert strings and Sigma rule UUIDs stored in sigma_hits.
    pub async fn get_fired_rules(
        &self,
        tenant_id: &str,
    ) -> anyhow::Result<Vec<(String, u64, String)>> {
        let db = tenant_db(tenant_id);
        let rows = self.client
            .query(&format!(
                "SELECT arrayJoin(sigma_hits) as rule_name, \
                 toUInt64(count()) as cnt, \
                 any(severity) as sev \
                 FROM {}.ndr_hits \
                 WHERE notEmpty(sigma_hits) \
                 GROUP BY rule_name \
                 ORDER BY cnt DESC \
                 LIMIT 500",
                db
            ))
            .fetch_all::<(String, u64, String)>()
            .await?;
        Ok(rows)
    }

    // ── JARM fingerprint observations ─────────────────────────────────────────

    pub async fn jarm_already_seen(&self, tenant_id: &str, server_ip: &str, server_port: u16) -> bool {
        self.client
            .query("SELECT count() FROM ndr.jarm_observations WHERE tenant_id = ? AND server_ip = ? AND server_port = ?")
            .bind(tenant_id)
            .bind(server_ip)
            .bind(server_port)
            .fetch_one::<u64>()
            .await
            .unwrap_or(0) > 0
    }

    pub async fn store_jarm_observation(
        &self,
        tenant_id:   &str,
        server_ip:   &str,
        server_port: u16,
        fingerprint: &str,
        c2_match:    &str,
    ) -> anyhow::Result<()> {
        self.client
            .query(
                "INSERT INTO ndr.jarm_observations \
                 (tenant_id, server_ip, server_port, fingerprint, c2_match) \
                 VALUES (?, ?, ?, ?, ?)"
            )
            .bind(tenant_id)
            .bind(server_ip)
            .bind(server_port)
            .bind(fingerprint)
            .bind(c2_match)
            .execute()
            .await?;
        Ok(())
    }

    pub async fn get_jarm_c2_hits(&self, tenant_id: &str) -> anyhow::Result<Vec<serde_json::Value>> {
        let rows = self.client
            .query(
                "SELECT server_ip, server_port, fingerprint, c2_match, toString(first_seen) \
                 FROM ndr.jarm_observations \
                 WHERE tenant_id = ? AND c2_match != '' \
                 ORDER BY first_seen DESC \
                 LIMIT 500"
            )
            .bind(tenant_id)
            .fetch_all::<(String, u16, String, String, String)>()
            .await?;

        Ok(rows.into_iter().map(|(ip, port, fp, c2, seen)| serde_json::json!({
            "server_ip":   ip,
            "server_port": port,
            "fingerprint": fp,
            "c2_match":    c2,
            "first_seen":  seen,
        })).collect())
    }

    /// Return all active server IPs and ports seen in recent traffic (last 24 h),
    /// one row per unique (tenant_id, server_ip, server_port).
    pub async fn get_active_tls_servers(&self, tenant_id: &str) -> anyhow::Result<Vec<(String, u16)>> {
        let rows = self.client
            .query(
                "SELECT DISTINCT dst_ip, dst_port \
                 FROM ndr.network_logs \
                 WHERE tenant_id = ? \
                   AND timestamp > now() - INTERVAL 24 HOUR \
                   AND dst_port IN (443, 8443, 8080, 4443, 9443, 2083, 2087, 2096, 7443) \
                 LIMIT 5000"
            )
            .bind(tenant_id)
            .fetch_all::<(String, u16)>()
            .await
            .unwrap_or_default();
        Ok(rows)
    }

    pub async fn get_all_tenant_ids_with_ndr(&self) -> Vec<String> {
        #[derive(clickhouse::Row, serde::Deserialize)]
        struct TenantRow { tenant_id: String }
        self.client
            .query(
                "SELECT tenant_id FROM ndr.tenants \
                 WHERE active = 1 AND positionCaseInsensitive(features, 'ndr') > 0"
            )
            .fetch_all::<TenantRow>()
            .await
            .unwrap_or_default()
            .into_iter()
            .map(|r| r.tenant_id)
            .collect()
    }
}

fn is_ip_in_cidr(ip: &str, cidr: &str) -> bool {
    let parts: Vec<&str> = cidr.split('/').collect();
    if parts.len() != 2 { return false; }
    let prefix_len: u32 = match parts[1].parse() { Ok(v) => v, Err(_) => return false };
    let net_ip: u32 = match ip_to_u32(parts[0]) { Some(v) => v, None => return false };
    let host_ip: u32 = match ip_to_u32(ip) { Some(v) => v, None => return false };
    if prefix_len == 0 { return true; }
    let mask = !((1u32 << (32 - prefix_len)) - 1);
    (net_ip & mask) == (host_ip & mask)
}

fn ip_to_u32(ip: &str) -> Option<u32> {
    let parts: Vec<u8> = ip.split('.').filter_map(|p| p.parse().ok()).collect();
    if parts.len() != 4 { return None; }
    Some(((parts[0] as u32) << 24) | ((parts[1] as u32) << 16) | ((parts[2] as u32) << 8) | parts[3] as u32)
}

fn cidr_host_count(cidr: &str) -> usize {
    let parts: Vec<&str> = cidr.split('/').collect();
    if parts.len() != 2 { return 0; }
    let prefix_len: u32 = match parts[1].parse() { Ok(v) => v, Err(_) => return 0 };
    if prefix_len >= 32 { return 1; }
    ((1u32 << (32 - prefix_len)) as usize).saturating_sub(2) // exclude network + broadcast
}

// ── SoarStore — bridge between provigil-common SOAR execution and ndr-engine storage ──

#[cfg(feature = "soar")]
use provigil_common::soar::{SoarStore, ActiveBlock, SoarPlaybookRun};

#[cfg(feature = "soar")]
#[async_trait::async_trait]
impl SoarStore for ClickhouseStorage {
    async fn soar_get_integrations(&self, tenant_id: &str) -> Vec<serde_json::Value> {
        self.get_integrations_by_tenant(tenant_id).await.unwrap_or_default()
    }

    async fn soar_find_open_case(&self, src: &str, dst: &str, tenant_id: &str) -> Option<(String, String, String, String)> {
        self.find_open_case_by_src_dst(src, dst, tenant_id).await
    }

    async fn soar_add_comment(&self, case_id: &str, author: &str, comment: &str, tenant_id: &str) {
        let _ = self.insert_soar_case_comment(case_id, author, comment, tenant_id).await;
    }

    async fn soar_escalate_case(&self, case_id: &str, severity: &str, priority: &str, tenant_id: &str) {
        let _ = self.escalate_case_severity(case_id, severity, priority, tenant_id).await;
    }

    async fn soar_next_case_number(&self, tenant_id: &str) -> String {
        self.get_next_case_number(tenant_id).await
    }

    async fn soar_create_case(
        &self, id: &str, case_number: &str, title: &str, description: &str,
        severity: &str, priority: &str, status: &str, assigned_to: &str,
        src_ip: &str, dst_ip: &str, community_id: &str, tags: &[String], tenant_id: &str,
    ) -> anyhow::Result<()> {
        self.insert_soar_case(id, case_number, title, description, severity, priority, status, assigned_to, src_ip, dst_ip, community_id, tags, tenant_id).await
    }

    async fn soar_get_pcap_sessions(&self, tenant_id: &str, cid: &str, limit: usize) -> Vec<serde_json::Value> {
        self.get_pcap_sessions(tenant_id, Some(cid), None, limit as u32, &[]).await.unwrap_or_default()
    }

    async fn soar_get_events(&self, community_id: &str, tenant_id: &str) -> serde_json::Value {
        self.get_events_by_community_id(community_id, tenant_id, &[]).await.unwrap_or_default()
    }

    async fn soar_insert_block(&self, block: &ActiveBlock) -> anyhow::Result<()> {
        self.insert_active_block(block).await
    }

    async fn soar_insert_run(&self, run: &SoarPlaybookRun) -> anyhow::Result<()> {
        self.insert_soar_playbook_run(run).await
    }
}

// ── ThreatCollectorStore — bridges provigil-common collector to ndr-engine storage ──

use provigil_common::threat_intel::{ThreatCollectorStore, ThreatIntelEntry};

#[async_trait::async_trait]
impl ThreatCollectorStore for ClickhouseStorage {
    async fn fetch_existing_iocs(&self) -> std::collections::HashSet<(String, String)> {
        #[derive(clickhouse::Row, serde::Deserialize)]
        struct Row { source: String, ioc_value: String }

        self.client
            .query("SELECT source, ioc_value FROM ndr.threat_intel FINAL WHERE expires_at > now()")
            .fetch_all::<Row>()
            .await
            .unwrap_or_default()
            .into_iter()
            .map(|r| (r.source, r.ioc_value))
            .collect()
    }

    async fn get_api_keys(&self) -> (String, String) {
        let settings = self.get_settings_by_tenant("default").await.unwrap_or_default();
        let abuseipdb = settings["abuseipdb_api_key"].as_str().unwrap_or("").to_string();
        let otx       = settings["otx_api_key"].as_str().unwrap_or("").to_string();
        (abuseipdb, otx)
    }

    async fn insert_ioc_entries(
        &self,
        existing: &std::collections::HashSet<(String, String)>,
        entries: Vec<ThreatIntelEntry>,
    ) -> usize {
        let mut saved = 0;
        for e in entries {
            if existing.contains(&(e.source.clone(), e.ioc_value.clone())) { continue; }
            let q = format!(
                "INSERT INTO ndr.threat_intel \
                 (source, attack_type, severity, ioc_type, ioc_value, description, threat_pattern) \
                 VALUES ('{}','{}','{}','{}','{}','{}','{}')",
                sql_escape(&e.source), sql_escape(&e.attack_type), sql_escape(&e.severity),
                sql_escape(&e.ioc_type), sql_escape(&e.ioc_value), sql_escape(&e.description), sql_escape(&e.threat_pattern)
            );
            if self.client.query(&q).execute().await.is_ok() { saved += 1; }
        }
        saved
    }
}

impl ClickhouseStorage {
    pub async fn persist_threat_intel_entries(&self, entries: Vec<ThreatIntelEntry>) -> anyhow::Result<usize> {
        let existing = self.fetch_existing_iocs().await;
        let mut saved = 0usize;

        for e in entries {
            if existing.contains(&(e.source.clone(), e.ioc_value.clone())) { continue; }
            let q = format!(
                "INSERT INTO ndr.threat_intel \
                 (source, attack_type, severity, ioc_type, ioc_value, description, threat_pattern) \
                 VALUES ('{}','{}','{}','{}','{}','{}','{}')",
                sql_escape(&e.source), sql_escape(&e.attack_type), sql_escape(&e.severity),
                sql_escape(&e.ioc_type), sql_escape(&e.ioc_value), sql_escape(&e.description), sql_escape(&e.threat_pattern)
            );
            if self.client.query(&q).execute().await.is_ok() { saved += 1; }
        }

        Ok(saved)
    }
}


#[cfg(test)]
mod sql_escape_tests {
    use super::*;

    #[test]
    fn question_marks_never_reach_the_query_text() {
        assert_eq!(sql_escape("http://x/a?b=1"), "http://x/a\\x3Fb=1");
        assert!(!sql_escape("what?? ?fields").contains('?'));
        assert_eq!(sql_escape("it's"), "it\\'s");
        assert_eq!(sql_escape("a\\b"), "a\\\\b");
    }

    // Against a real ClickHouse: the escaped value must come back exactly as it went in.
    // Run: CLICKHOUSE_URL=... CLICKHOUSE_USER=... CLICKHOUSE_PASSWORD=... \
    //      cargo test -p ndr-engine sql_escape -- --ignored
    #[tokio::test]
    #[ignore]
    async fn escaped_value_round_trips_through_a_real_clickhouse() {
        let client = clickhouse::Client::default()
            .with_url(std::env::var("CLICKHOUSE_URL").unwrap_or_else(|_| "http://127.0.0.1:8123".into()))
            .with_user(std::env::var("CLICKHOUSE_USER").unwrap_or_else(|_| "default".into()))
            .with_password(std::env::var("CLICKHOUSE_PASSWORD").unwrap_or_default());
        for original in ["http://evil.example/a?b=1&c=?", "plain", "it's a ? and a \\ and ?fields", "??"] {
            let got: String = client
                .query(&format!("SELECT '{}'", sql_escape(original)))
                .fetch_one()
                .await
                .expect("query must not panic or fail");
            assert_eq!(got, original);
        }
    }
}


#[cfg(test)]
mod tenant_column_migration_tests {
    use super::*;

    // Against a real ClickHouse (a throwaway database that is dropped at the end):
    //   CLICKHOUSE_URL=... CLICKHOUSE_USER=... CLICKHOUSE_PASSWORD=... \
    //   cargo test -p ndr-engine tenant_column -- --ignored
    #[tokio::test]
    #[ignore]
    async fn an_old_tenant_table_gets_the_missing_columns_and_accepts_a_case() {
        let ch = ClickhouseStorage::new();
        let db = "ndr_zz_migtest";
        let _ = ch.client.query(&format!("DROP DATABASE IF EXISTS {db}")).execute().await;
        ch.client.query(&format!("CREATE DATABASE {db}")).execute().await.unwrap();
        // the OLD shapes: no case_number / priority / source
        ch.client.query(&format!(
            "CREATE TABLE {db}.soar_cases (id String, title String, updated_at DateTime DEFAULT now()) \
             ENGINE = ReplacingMergeTree(updated_at) ORDER BY id")).execute().await.unwrap();
        ch.client.query(&format!(
            "CREATE TABLE {db}.sigma_rules (id String, name String, updated_at DateTime DEFAULT now()) \
             ENGINE = ReplacingMergeTree(updated_at) ORDER BY id")).execute().await.unwrap();

        // what the SOAR code does today fails on an old table
        let before = ch.client.query(&format!(
            "INSERT INTO {db}.soar_cases (id, case_number, title) VALUES ('a', 'C-1', 't')")).execute().await;
        assert!(before.is_err(), "an old table must reject case_number (this is the reported bug)");

        ch.migrate_tenant_columns(db).await;
        ch.migrate_tenant_columns(db).await; // idempotent

        ch.client.query(&format!(
            "INSERT INTO {db}.soar_cases (id, case_number, title, priority) VALUES ('a', 'C-1', 't', 'P1')"))
            .execute().await.expect("the case insert works after the migration");
        let got: String = ch.client
            .query(&format!("SELECT concat(case_number, '/', priority) FROM {db}.soar_cases WHERE id = 'a'"))
            .fetch_one().await.unwrap();
        assert_eq!(got, "C-1/P1");
        ch.client.query(&format!("SELECT source FROM {db}.sigma_rules")).fetch_all::<String>().await
            .expect("sigma_rules.source exists after the migration");
        let _ = ch.client.query(&format!("DROP DATABASE IF EXISTS {db}")).execute().await;
    }
}
