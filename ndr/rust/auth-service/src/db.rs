use anyhow::Result;
use clickhouse::Client;
use serde::Deserialize;

/// Row from the users table — column names match the real ClickHouse schema.
#[derive(Debug, Clone, Deserialize, clickhouse::Row)]
pub struct UserRow {
    pub id:            String,   // primary key
    pub username:      String,
    pub password_hash: String,
    pub role:          String,
    pub tenant_id:     String,
    pub permissions:   String,   // comma-separated page permissions
    pub active:        u8,
    pub gmail:         String,
    pub secret_code:   String,
}

pub struct AuthDb {
    client: Client,
}

impl AuthDb {
    pub async fn new(_url: &str) -> Result<Self> {
        let cfg = provigil_common::clickhouse::ClickHouseConfig::from_env();
        Ok(Self { client: cfg.build_client() })
    }

    /// Fetch a user by username within a tenant.
    pub async fn get_user(&self, username: &str, tenant_id: &str) -> Result<Option<UserRow>> {
        let tenant_clause = if tenant_id.is_empty() {
            String::new()
        } else {
            format!("AND tenant_id = '{}'", escape(tenant_id))
        };
        let q = format!(
            "SELECT id, username, password_hash, role, tenant_id, permissions,
                    active, coalesce(gmail,'') AS gmail, coalesce(secret_code,'') AS secret_code
             FROM users FINAL
             WHERE username = '{u}'
             {tenant_clause}
             LIMIT 1",
            u = escape(username),
        );
        let mut cur = self.client.query(&q).fetch::<UserRow>()?;
        Ok(cur.next().await?)
    }

    /// Fetch a user by username across ALL tenants (used by check_username to resolve tenant).
    pub async fn get_user_any_tenant(&self, username: &str) -> Result<Option<UserRow>> {
        let q = format!(
            "SELECT id, username, password_hash, role, tenant_id, permissions,
                    active, coalesce(gmail,'') AS gmail, coalesce(secret_code,'') AS secret_code
             FROM users FINAL
             WHERE username = '{u}'
             LIMIT 1",
            u = escape(username),
        );
        let mut cur = self.client.query(&q).fetch::<UserRow>()?;
        Ok(cur.next().await?)
    }

    /// Fetch a user by internal id (used in MFA second step).
    pub async fn get_user_by_id(&self, id: &str) -> Result<Option<UserRow>> {
        let q = format!(
            "SELECT id, username, password_hash, role, tenant_id, permissions,
                    active, coalesce(gmail,'') AS gmail, coalesce(secret_code,'') AS secret_code
             FROM users
             WHERE id = '{}'
             LIMIT 1",
            escape(id)
        );
        let mut cur = self.client.query(&q).fetch::<UserRow>()?;
        Ok(cur.next().await?)
    }

    /// Check whether a tenant is active.
    pub async fn is_tenant_active(&self, tenant_id: &str) -> Result<bool> {
        #[derive(Deserialize, clickhouse::Row)]
        struct Row { active: u8 }
        let q = format!(
            "SELECT active FROM tenants WHERE id = '{}' LIMIT 1",
            escape(tenant_id)
        );
        let mut cur = self.client.query(&q).fetch::<Row>()?;
        match cur.next().await? {
            Some(r) => Ok(r.active == 1),
            None    => Ok(false),
        }
    }

    /// Feature flags for a tenant — stored as JSON array in tenants.features column.
    pub async fn tenant_id_exists(&self, id: &str) -> bool {
        #[derive(Deserialize, clickhouse::Row)]
        struct Row { cnt: u64 }
        let q = format!("SELECT count() AS cnt FROM tenants FINAL WHERE id = '{}'", escape(id));
        self.client.query(&q).fetch_one::<Row>().await
            .map(|r| r.cnt > 0)
            .unwrap_or(false)
    }

    pub async fn get_tenant_features(&self, tenant_id: &str) -> Result<Vec<String>> {
        #[derive(Deserialize, clickhouse::Row)]
        struct Row { features: String }
        let q = format!(
            "SELECT coalesce(features, 'ndr') AS features
             FROM tenants FINAL WHERE id = '{}' LIMIT 1",
            escape(tenant_id)
        );
        let mut cur = self.client.query(&q).fetch::<Row>()?;
        if let Some(r) = cur.next().await? {
            // features stored as comma-separated (e.g. "ndr,ai,soar")
            let feats: Vec<String> = r.features
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
            return Ok(feats);
        }
        Ok(vec!["ndr".into()])
    }

    /// AI-analysis feature toggle for a tenant.
    pub async fn get_tenant_ai_enabled(&self, tenant_id: &str) -> bool {
        #[derive(Deserialize, clickhouse::Row)]
        struct Row { ai_enabled: u8 }
        let q = format!(
            "SELECT ai_enabled FROM tenants FINAL WHERE id = '{}' LIMIT 1",
            escape(tenant_id)
        );
        let Ok(mut cur) = self.client.query(&q).fetch::<Row>() else { return false };
        cur.next().await.ok().flatten().map(|r| r.ai_enabled == 1).unwrap_or(false)
    }

    /// Sensor IDs scoped to a user (empty = all sensors for the tenant).
    pub async fn get_sensor_ids(&self, user_id: &str) -> Result<Vec<String>> {
        #[derive(Deserialize, clickhouse::Row)]
        struct Row { sensor_id: String }
        let q = format!(
            "SELECT sensor_id FROM user_sensor_assignments WHERE user_id = '{}'",
            escape(user_id)
        );
        let mut cur = self.client.query(&q).fetch::<Row>()?;
        let mut ids = Vec::new();
        while let Some(r) = cur.next().await? { ids.push(r.sensor_id); }
        Ok(ids)
    }

    /// Tenant admin email for new-device notifications.
    pub async fn get_tenant_admin_email(&self, tenant_id: &str) -> Result<Option<String>> {
        #[derive(Deserialize, clickhouse::Row)]
        struct Row { gmail: String }
        let q = format!(
            "SELECT coalesce(gmail, '') AS gmail
             FROM users
             WHERE tenant_id = '{}' AND role IN ('tenant_admin','super_admin')
               AND gmail != ''
             LIMIT 1",
            escape(tenant_id)
        );
        let mut cur = self.client.query(&q).fetch::<Row>()?;
        Ok(cur.next().await?.map(|r| r.gmail).filter(|e| !e.is_empty()))
    }

    /// Update password hash (password reset).
    pub async fn set_password_hash(&self, user_id: &str, new_hash: &str) -> Result<()> {
        // mutations_sync=1: block until applied - a password reset must take
        // effect before this call returns, not asynchronously later.
        self.client
            .query(&format!(
                "ALTER TABLE users UPDATE password_hash = '{}' WHERE id = '{}' SETTINGS mutations_sync=1",
                escape(new_hash), escape(user_id)
            ))
            .execute()
            .await?;
        Ok(())
    }

    // ─────────────────────────────────────────────────────────────────────────
    // User management
    // ─────────────────────────────────────────────────────────────────────────

    pub async fn get_all_users(&self) -> Result<Vec<serde_json::Value>> {
        #[derive(Deserialize, clickhouse::Row)]
        struct Row {
            id: String, username: String, role: String,
            tenant_id: String, permissions: String, active: u8,
            gmail: String, created_at: String,
        }
        let q = "SELECT id, username, role, tenant_id, permissions, active, \
                        coalesce(gmail,'') AS gmail, toString(created_at) AS created_at \
                 FROM users ORDER BY created_at DESC";
        let mut cur = self.client.query(q).fetch::<Row>()?;
        let mut out = Vec::new();
        while let Some(r) = cur.next().await? {
            out.push(serde_json::json!({
                "id": r.id, "username": r.username, "role": r.role,
                "tenant_id": r.tenant_id, "permissions": r.permissions,
                "active": r.active, "gmail": r.gmail, "created_at": r.created_at,
            }));
        }
        Ok(out)
    }

    pub async fn get_users_by_tenant(&self, tenant_id: &str) -> Result<Vec<serde_json::Value>> {
        #[derive(Deserialize, clickhouse::Row)]
        struct Row {
            id: String, username: String, role: String,
            tenant_id: String, permissions: String, active: u8,
            gmail: String, created_at: String,
        }
        let q = format!(
            "SELECT id, username, role, tenant_id, permissions, active, \
                    coalesce(gmail,'') AS gmail, toString(created_at) AS created_at \
             FROM users WHERE tenant_id = '{}' AND role != 'super_admin' \
             ORDER BY created_at DESC",
            escape(tenant_id)
        );
        let mut cur = self.client.query(&q).fetch::<Row>()?;
        let mut out = Vec::new();
        while let Some(r) = cur.next().await? {
            out.push(serde_json::json!({
                "id": r.id, "username": r.username, "role": r.role,
                "tenant_id": r.tenant_id, "permissions": r.permissions,
                "active": r.active, "gmail": r.gmail, "created_at": r.created_at,
            }));
        }
        Ok(out)
    }

    pub async fn get_user_identity(&self, id: &str) -> Result<Option<(String, String, String)>> {
        #[derive(Deserialize, clickhouse::Row)]
        struct Row { username: String, role: String, tenant_id: String }
        let q = format!(
            "SELECT username, role, tenant_id FROM users WHERE id = '{}' LIMIT 1",
            escape(id)
        );
        let mut cur = self.client.query(&q).fetch::<Row>()?;
        Ok(cur.next().await?.map(|r| (r.username, r.role, r.tenant_id)))
    }

    pub async fn get_user_by_username_json(&self, username: &str) -> Result<Option<serde_json::Value>> {
        #[derive(Deserialize, clickhouse::Row)]
        struct Row {
            id: String, username: String, role: String, tenant_id: String,
            permissions: String, active: u8, gmail: String, secret_code: String,
        }
        let q = format!(
            "SELECT id, username, role, tenant_id, permissions, active, \
                    coalesce(gmail,'') AS gmail, coalesce(secret_code,'') AS secret_code \
             FROM users WHERE username = '{}' LIMIT 1",
            escape(username)
        );
        let mut cur = self.client.query(&q).fetch::<Row>()?;
        Ok(cur.next().await?.map(|r| serde_json::json!({
            "id": r.id, "username": r.username, "role": r.role,
            "tenant_id": r.tenant_id, "permissions": r.permissions,
            "active": r.active, "gmail": r.gmail, "secret_code": r.secret_code,
        })))
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn create_user(
        &self, username: &str, hash: &str, role: &str,
        tenant_id: &str, permissions: &str, gmail: &str, secret_code: &str,
    ) -> Result<()> {
        let q = format!(
            "INSERT INTO users (id, username, password_hash, role, tenant_id, permissions, \
                                active, created_at, last_login, gmail, secret_code) \
             VALUES (generateUUIDv4(), '{}', '{}', '{}', '{}', '{}', 1, now(), now(), '{}', '{}')",
            escape(username), escape(hash), escape(role), escape(tenant_id),
            escape(permissions), escape(gmail), escape(secret_code)
        );
        self.client.query(&q).execute().await?;
        Ok(())
    }

    pub async fn update_user_full(
        &self, id: &str, role: &str, tenant_id: &str,
        permissions: &str, active: bool, hash: Option<&str>,
    ) -> Result<()> {
        let active_u8 = active as u8;
        let hash_clause = match hash {
            Some(h) => format!(", password_hash = '{}'", escape(h)),
            None    => String::new(),
        };
        // mutations_sync=1: block until applied - a role/tenant/active change
        // (e.g. the privilege-escalation fix) must be immediately in effect.
        let q = format!(
            "ALTER TABLE users UPDATE role = '{}', tenant_id = '{}', \
                    permissions = '{}', active = {}{} WHERE id = '{}' SETTINGS mutations_sync=1",
            escape(role), escape(tenant_id), escape(permissions),
            active_u8, hash_clause, escape(id)
        );
        self.client.query(&q).execute().await?;
        Ok(())
    }

    pub async fn set_user_active(&self, id: &str, active: bool) -> Result<()> {
        // mutations_sync=1: block until applied (TC-062 found a ~0.6s window
        // where a just-deactivated user could still log in under the async
        // default).
        let q = format!(
            "ALTER TABLE users UPDATE active = {} WHERE id = '{}' SETTINGS mutations_sync=1",
            active as u8, escape(id)
        );
        self.client.query(&q).execute().await?;
        Ok(())
    }

    pub async fn update_user_permissions(&self, id: &str, permissions: &str) -> Result<()> {
        let q = format!(
            "ALTER TABLE users UPDATE permissions = '{}' WHERE id = '{}' SETTINGS mutations_sync=1",
            escape(permissions), escape(id)
        );
        self.client.query(&q).execute().await?;
        Ok(())
    }

    pub async fn update_user_password(&self, id: &str, hash: &str) -> Result<()> {
        // mutations_sync=1: same reasoning as set_password_hash - a password
        // reset must be immediately effective.
        let q = format!(
            "ALTER TABLE users UPDATE password_hash = '{}' WHERE id = '{}' SETTINGS mutations_sync=1",
            escape(hash), escape(id)
        );
        self.client.query(&q).execute().await?;
        Ok(())
    }

    pub async fn delete_user(&self, id: &str) -> Result<()> {
        // mutations_sync=1: block until applied - a deleted user shouldn't
        // still be listable/loggable-in immediately after this returns.
        let q = format!("ALTER TABLE users DELETE WHERE id = '{}' SETTINGS mutations_sync=1", escape(id));
        self.client.query(&q).execute().await?;
        Ok(())
    }

    pub async fn update_user_gmail(&self, id: &str, gmail: &str) -> Result<()> {
        let q = format!(
            "ALTER TABLE users UPDATE gmail = '{}' WHERE id = '{}' SETTINGS mutations_sync=1",
            escape(gmail), escape(id)
        );
        self.client.query(&q).execute().await?;
        Ok(())
    }

    pub async fn update_user_secret_code(&self, id: &str, code: &str) -> Result<()> {
        let q = format!(
            "ALTER TABLE users UPDATE secret_code = '{}' WHERE id = '{}' SETTINGS mutations_sync=1",
            escape(code), escape(id)
        );
        self.client.query(&q).execute().await?;
        Ok(())
    }

    pub async fn verify_tenant_admin_secret(
        &self, username: &str, secret_code: &str,
    ) -> Result<Option<String>> {
        #[derive(Deserialize, clickhouse::Row)]
        struct Row { gmail: String }
        let q = format!(
            "SELECT coalesce(gmail,'') AS gmail FROM users \
             WHERE username = '{}' AND secret_code = '{}' AND role = 'tenant_admin' LIMIT 1",
            escape(username), escape(secret_code)
        );
        let mut cur = self.client.query(&q).fetch::<Row>()?;
        Ok(cur.next().await?.map(|r| r.gmail))
    }

    pub async fn get_gmail_for_user(&self, username: &str) -> Result<Option<String>> {
        #[derive(Deserialize, clickhouse::Row)]
        struct Row { gmail: String }
        let q = format!(
            "SELECT coalesce(gmail,'') AS gmail FROM users WHERE username = '{}' LIMIT 1",
            escape(username)
        );
        let mut cur = self.client.query(&q).fetch::<Row>()?;
        Ok(cur.next().await?.map(|r| r.gmail))
    }

    pub async fn reset_password_by_username(&self, username: &str, hash: &str) -> Result<()> {
        let q = format!(
            "ALTER TABLE users UPDATE password_hash = '{}' WHERE username = '{}' SETTINGS mutations_sync=1",
            escape(hash), escape(username)
        );
        self.client.query(&q).execute().await?;
        Ok(())
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Tenant management
    // ─────────────────────────────────────────────────────────────────────────

    pub async fn get_all_tenants(&self) -> Result<Vec<serde_json::Value>> {
        #[derive(Deserialize, clickhouse::Row)]
        struct Row {
            id: String, name: String, active: u8, ai_enabled: u8,
            features: String, created_at: String,
        }
        let q = "SELECT id, name, active, ai_enabled, \
                        coalesce(features,'ndr') AS features, \
                        toString(created_at) AS created_at \
                 FROM tenants FINAL ORDER BY created_at DESC";
        let mut cur = self.client.query(q).fetch::<Row>()?;
        let mut out = Vec::new();
        while let Some(r) = cur.next().await? {
            out.push(serde_json::json!({
                "id": r.id, "name": r.name, "active": r.active,
                "ai_enabled": r.ai_enabled, "features": r.features,
                "created_at": r.created_at,
            }));
        }
        Ok(out)
    }

    /// Same shape as get_all_tenants but scoped to a single tenant — used so a
    /// tenant_admin can never enumerate other tenants' names/ids/features.
    pub async fn get_tenant_by_id(&self, tenant_id: &str) -> Result<Vec<serde_json::Value>> {
        #[derive(Deserialize, clickhouse::Row)]
        struct Row {
            id: String, name: String, active: u8, ai_enabled: u8,
            features: String, created_at: String,
        }
        let q = "SELECT id, name, active, ai_enabled, \
                        coalesce(features,'ndr') AS features, \
                        toString(created_at) AS created_at \
                 FROM tenants FINAL WHERE id = ? ORDER BY created_at DESC";
        let mut cur = self.client.query(q).bind(tenant_id).fetch::<Row>()?;
        let mut out = Vec::new();
        while let Some(r) = cur.next().await? {
            out.push(serde_json::json!({
                "id": r.id, "name": r.name, "active": r.active,
                "ai_enabled": r.ai_enabled, "features": r.features,
                "created_at": r.created_at,
            }));
        }
        Ok(out)
    }

    pub async fn create_tenant(&self, id: &str, name: &str) -> Result<()> {
        // 1) global registry row
        // features is stored comma-separated (e.g. "ndr,ai"), matching the
        // column's own schema default and every existing tenant row — NOT a
        // JSON array string, which get_tenant_features()'s comma-split
        // parser (and has_feature()) can't read back correctly.
        let q = format!(
            "INSERT INTO tenants (id, name, active, ai_enabled, updated_at, created_at, features) \
             VALUES ('{}', '{}', 1, 0, now(), now(), 'ndr')",
            escape(id), escape(name)
        );
        self.client.query(&q).execute().await?;

        // 2) dedicated tenant database + tenant-specific schema
        let db_name = format!("ndr_{}", id.replace('-', "_"));
        self.client
            .query(&format!(
                "CREATE DATABASE IF NOT EXISTS {} ON CLUSTER ndr_cluster",
                db_name
            ))
            .execute()
            .await?;

        let install_dir = std::env::var("INSTALL_DIR").unwrap_or_else(|_| ".".to_string());
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

                let mut tenant_stmt = stmt.replace("ndr.", &format!("{}.", db_name));
                tenant_stmt = tenant_stmt.replace(
                    "/clickhouse/tables/{shard}/ndr/",
                    &format!("/clickhouse/tables/{{shard}}/{}/", db_name),
                );
                tenant_stmt = tenant_stmt.replace("DEFAULT 'default'", &format!("DEFAULT '{}'", id));

                if let Err(e) = self.client.query(&tenant_stmt).execute().await {
                    tracing::warn!(
                        "Dynamic tenant schema warning for {}: {}. Error: {}",
                        db_name, tenant_stmt, e
                    );
                }
            }
            tracing::info!("✅ Tenant DB created and initialized: {}", db_name);
        } else {
            tracing::warn!("init.sql not found while provisioning tenant DB {}", db_name);
        }

        Ok(())
    }

    pub async fn update_tenant(&self, id: &str, name: &str, active: bool) -> Result<()> {
        // INSERT-SELECT pattern: ReplacingMergeTree keeps the row with the highest updated_at.
        // ALTER TABLE UPDATE on the version column (updated_at) is rejected by ClickHouse 24.x.
        let q = format!(
            "INSERT INTO tenants (id, name, active, ai_enabled, features, updated_at, created_at) \
             SELECT id, '{}', {}, ai_enabled, features, now(), created_at \
             FROM tenants FINAL WHERE id = '{}'",
            escape(name), active as u8, escape(id)
        );
        self.client.query(&q).execute().await?;
        Ok(())
    }

    pub async fn set_tenant_active(&self, id: &str, active: bool) -> Result<()> {
        let q = format!(
            "INSERT INTO tenants (id, name, active, ai_enabled, features, updated_at, created_at) \
             SELECT id, name, {}, ai_enabled, features, now(), created_at \
             FROM tenants FINAL WHERE id = '{}'",
            active as u8, escape(id)
        );
        self.client.query(&q).execute().await?;
        Ok(())
    }

    pub async fn set_tenant_ai_enabled(&self, id: &str, enabled: bool) -> Result<()> {
        let q = format!(
            "INSERT INTO tenants (id, name, active, ai_enabled, features, updated_at, created_at) \
             SELECT id, name, active, {}, features, now(), created_at \
             FROM tenants FINAL WHERE id = '{}'",
            enabled as u8, escape(id)
        );
        self.client.query(&q).execute().await?;
        Ok(())
    }

    pub async fn set_tenant_features(&self, id: &str, features: &[String]) -> Result<()> {
        let features_str = features.join(",");
        let q = format!(
            "INSERT INTO tenants (id, name, active, ai_enabled, features, updated_at, created_at) \
             SELECT id, name, active, ai_enabled, '{}', now(), created_at \
             FROM tenants FINAL WHERE id = '{}'",
            escape(&features_str), escape(id)
        );
        self.client.query(&q).execute().await?;
        Ok(())
    }

    // ─────────────────────────────────────────────────────────────────────────
    // SMTP settings
    // ─────────────────────────────────────────────────────────────────────────

    pub async fn get_smtp_settings(&self) -> Result<(String, String, String, String)> {
        #[derive(Deserialize, clickhouse::Row)]
        struct Row { key: String, value: String }
        let mut cur = self.client.query(
            "SELECT key, value FROM ndr.settings FINAL \
             WHERE key IN ('global_smtp_host','global_smtp_port','global_smtp_user','global_smtp_password')"
        ).fetch::<Row>()?;
        let mut host = "smtp.gmail.com".to_string();
        let mut port = "587".to_string();
        let mut user = String::new();
        let mut pass = String::new();
        while let Some(r) = cur.next().await? {
            match r.key.as_str() {
                "global_smtp_host"     => host = r.value,
                "global_smtp_port"     => port = r.value,
                "global_smtp_user"     => user = r.value,
                "global_smtp_password" => pass = r.value,
                _                      => {}
            }
        }
        Ok((host, port, user, pass))
    }

    // ── Announcements ────────────────────────────────────────────────────────

    pub async fn get_announcements(&self) -> Result<Vec<serde_json::Value>> {
        #[derive(Deserialize, clickhouse::Row)]
        struct Row {
            id: String, title: String, message: String,
            announcement_type: String, audience: String, status: String,
            target_roles: Vec<String>, target_tenants: Vec<String>,
            starts_at: String, ends_at: String,
            created_by: String, created_at: String, updated_at: String,
        }
        let q = "SELECT id, title, message, announcement_type, audience, status, \
                        target_roles, target_tenants, \
                        toString(start_at) AS starts_at, \
                        ifNull(toString(end_at), '') AS ends_at, \
                        created_by, toString(created_at) AS created_at, toString(updated_at) AS updated_at \
                 FROM ndr.announcements FINAL ORDER BY updated_at DESC";
        let mut cur = self.client.query(q).fetch::<Row>()?;
        let mut out = Vec::new();
        while let Some(r) = cur.next().await? {
            out.push(serde_json::json!({
                "id": r.id, "title": r.title, "message": r.message,
                "type": r.announcement_type, "announcement_type": r.announcement_type,
                "audience": r.audience, "status": r.status,
                "active": r.status == "active",
                "target_roles": r.target_roles, "target_tenants": r.target_tenants,
                "start_at": r.starts_at, "starts_at": r.starts_at,
                "end_at": r.ends_at, "ends_at": r.ends_at,
                "created_by": r.created_by,
                "created_at": r.created_at, "updated_at": r.updated_at
            }));
        }
        Ok(out)
    }

    pub async fn get_active_announcements(&self, role: &str, tenant_id: &str, username: &str) -> Result<Vec<serde_json::Value>> {
        #[derive(Deserialize, clickhouse::Row)]
        struct Row {
            id: String, title: String, message: String,
            announcement_type: String, audience: String, status: String,
            target_roles: Vec<String>, target_tenants: Vec<String>,
            starts_at: String, ends_at: String,
            created_by: String, created_at: String, updated_at: String,
        }
        let role_alias = if role == "tenant_admin" { "tenant_admins" } else { role };
        let q = format!(
            "SELECT id, title, message, announcement_type, audience, status, \
                    target_roles, target_tenants, \
                    toString(start_at) AS starts_at, \
                    ifNull(toString(end_at), '') AS ends_at, \
                    created_by, toString(created_at) AS created_at, toString(updated_at) AS updated_at \
             FROM ndr.announcements FINAL \
             WHERE status = 'active' \
               AND start_at <= now() \
               AND (isNull(end_at) OR end_at >= now()) \
               AND (length(target_roles) = 0 OR has(target_roles, 'all') OR has(target_roles, '{}') OR has(target_roles, '{}')) \
               AND (length(target_tenants) = 0 OR has(target_tenants, 'all') OR has(target_tenants, '{}')) \
             ORDER BY start_at DESC, updated_at DESC",
            escape(role), escape(role_alias), escape(tenant_id)
        );
        let mut cur = self.client.query(&q).fetch::<Row>()?;
        let read_ids: std::collections::HashSet<String> = {
            #[derive(Deserialize, clickhouse::Row)]
            struct ReadRow { announcement_id: String }
            let rq = format!("SELECT announcement_id FROM ndr.announcement_reads FINAL WHERE username = '{}'", escape(username));
            let mut rcur = self.client.query(&rq).fetch::<ReadRow>()?;
            let mut set = std::collections::HashSet::new();
            while let Some(r) = rcur.next().await? { set.insert(r.announcement_id); }
            set
        };
        let mut out = Vec::new();
        while let Some(r) = cur.next().await? {
            out.push(serde_json::json!({
                "id": r.id, "title": r.title, "message": r.message,
                "type": r.announcement_type, "announcement_type": r.announcement_type,
                "audience": r.audience, "status": r.status, "active": true,
                "read": read_ids.contains(&r.id),
                "target_roles": r.target_roles, "target_tenants": r.target_tenants,
                "start_at": r.starts_at, "starts_at": r.starts_at,
                "end_at": r.ends_at, "ends_at": r.ends_at,
                "created_by": r.created_by,
                "created_at": r.created_at, "updated_at": r.updated_at
            }));
        }
        Ok(out)
    }

    pub async fn create_announcement(
        &self, id: &str, title: &str, message: &str, atype: &str,
        audience: &str, status: &str, target_roles: &[String],
        target_tenants: &[String], start_at: Option<&str>, end_at: Option<&str>,
        created_by: &str,
    ) -> Result<()> {
        let start_expr = start_at.filter(|v| !v.trim().is_empty())
            .map(|v| format!("parseDateTimeBestEffort('{}')", escape(v)))
            .unwrap_or_else(|| "now()".to_string());
        let end_expr = end_at.filter(|v| !v.trim().is_empty())
            .map(|v| format!("parseDateTimeBestEffort('{}')", escape(v)))
            .unwrap_or_else(|| "CAST(NULL, 'Nullable(DateTime)')".to_string());
        let q = format!(
            "INSERT INTO ndr.announcements \
             (id, title, message, announcement_type, audience, status, \
              target_roles, target_tenants, start_at, end_at, created_by, updated_at) \
             VALUES ('{}','{}','{}','{}','{}','{}',{},{},{},{},'{}',now())",
            escape(id), escape(title), escape(message), escape(atype),
            escape(audience), escape(status),
            sql_array_literal(target_roles), sql_array_literal(target_tenants),
            start_expr, end_expr, escape(created_by)
        );
        self.client.query(&q).execute().await?;
        Ok(())
    }

    pub async fn update_announcement(
        &self, id: &str, title: &str, message: &str, atype: &str,
        audience: &str, status: &str, target_roles: &[String],
        target_tenants: &[String], start_at: Option<&str>, end_at: Option<&str>,
    ) -> Result<()> {
        let start_expr = start_at.filter(|v| !v.trim().is_empty())
            .map(|v| format!("parseDateTimeBestEffort('{}')", escape(v)))
            .unwrap_or_else(|| "now()".to_string());
        let end_expr = end_at.filter(|v| !v.trim().is_empty())
            .map(|v| format!("parseDateTimeBestEffort('{}')", escape(v)))
            .unwrap_or_else(|| "CAST(NULL, 'Nullable(DateTime)')".to_string());
        let q = format!(
            "INSERT INTO ndr.announcements \
             (id, title, message, announcement_type, audience, status, \
              target_roles, target_tenants, start_at, end_at, created_by, created_at, updated_at) \
             SELECT id, '{title}', '{message}', '{atype}', '{audience}', '{status}', \
                    {roles}, {tenants}, {start_expr}, {end_expr}, \
                    created_by, created_at, now() \
             FROM ndr.announcements FINAL WHERE id = '{id}'",
            title = escape(title), message = escape(message), atype = escape(atype),
            audience = escape(audience), status = escape(status),
            roles = sql_array_literal(target_roles), tenants = sql_array_literal(target_tenants),
            start_expr = start_expr, end_expr = end_expr, id = escape(id)
        );
        self.client.query(&q).execute().await?;
        Ok(())
    }

    pub async fn mark_announcement_read(&self, announcement_id: &str, username: &str) -> Result<()> {
        let q = format!(
            "INSERT INTO ndr.announcement_reads (announcement_id, username, read_at) VALUES ('{}','{}',now())",
            escape(announcement_id), escape(username)
        );
        self.client.query(&q).execute().await?;
        Ok(())
    }

    pub async fn delete_announcement(&self, id: &str) -> Result<()> {
        let q = format!(
            "ALTER TABLE ndr.announcements DELETE WHERE id = '{}' SETTINGS mutations_sync=1",
            escape(id)
        );
        self.client.query(&q).execute().await?;
        Ok(())
    }
}

/// Minimal SQL escape — single-quote sanitisation.
fn escape(s: &str) -> String {
    s.replace('\'', "\\'")
}

fn sql_array_literal(items: &[String]) -> String {
    let inner = items.iter().map(|s| format!("'{}'", escape(s))).collect::<Vec<_>>().join(",");
    format!("[{}]", inner)
}
