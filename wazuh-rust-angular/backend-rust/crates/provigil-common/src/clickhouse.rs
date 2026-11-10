use clickhouse::Client;

pub const ENV_CLICKHOUSE_URL:      &str = "CLICKHOUSE_URL";
pub const ENV_CLICKHOUSE_DB:       &str = "CLICKHOUSE_DB";
pub const ENV_CLICKHOUSE_USER:     &str = "CLICKHOUSE_USER";
pub const ENV_CLICKHOUSE_PASSWORD: &str = "CLICKHOUSE_PASSWORD";

pub const DEFAULT_CLICKHOUSE_URL:  &str = "http://localhost:8123";
pub const DEFAULT_CLICKHOUSE_DB:   &str = "ndr";
pub const DEFAULT_CLICKHOUSE_USER: &str = "ndr";

#[derive(Debug, Clone)]
pub struct ClickHouseConfig {
    pub url:      String,
    pub database: String,
    pub user:     String,
    pub password: String,
}

impl ClickHouseConfig {
    pub fn from_env() -> Self {
        let url      = std::env::var(ENV_CLICKHOUSE_URL)
            .unwrap_or_else(|_| DEFAULT_CLICKHOUSE_URL.to_string());
        let database = std::env::var(ENV_CLICKHOUSE_DB)
            .unwrap_or_else(|_| DEFAULT_CLICKHOUSE_DB.to_string());
        let user     = std::env::var(ENV_CLICKHOUSE_USER)
            .unwrap_or_else(|_| DEFAULT_CLICKHOUSE_USER.to_string());
        let password = std::env::var(ENV_CLICKHOUSE_PASSWORD).unwrap_or_else(|_| {
            tracing::error!("CLICKHOUSE_PASSWORD not set — connection will likely fail");
            String::new()
        });
        Self { url, database, user, password }
    }

    pub fn build_client(&self) -> Client {
        Client::default()
            .with_url(&self.url)
            .with_database(&self.database)
            .with_user(&self.user)
            .with_password(&self.password)
    }
}
