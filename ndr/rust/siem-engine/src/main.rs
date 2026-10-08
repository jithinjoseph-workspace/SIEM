use std::net::SocketAddr;
use std::sync::Arc;
use axum::{Router, Json, middleware, http::StatusCode};
use serde_json::{json, Value};
use tower_http::cors::{CorsLayer, Any};
use tracing::info;

mod api;
mod ingest;
mod db_init;
mod correlation;

use ingest::pipeline::Pipeline;

fn require_env(key: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| panic!("{} is required", key))
}

#[derive(Clone)]
pub struct AppState {
    pub jwt_secret:     String,
    pub valkey_url:     String,
    pub clickhouse_url: String,
    pub kafka_brokers:  String,
    pub pipeline:       Arc<Pipeline>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("siem_engine=info".parse().unwrap()),
        )
        .init();

    let jwt_secret     = require_env("JWT_SECRET");
    let valkey_url     = std::env::var("VALKEY_URL")
        .unwrap_or_else(|_| "redis://localhost:6379".to_string());
    let clickhouse_url = std::env::var("CLICKHOUSE_URL")
        .unwrap_or_else(|_| "http://localhost:8123".to_string());
    let kafka_brokers  = std::env::var("KAFKA_BROKERS")
        .unwrap_or_else(|_| "kafka1:9092,kafka2:9092,kafka3:9092".to_string());
    let hmac_key       = std::env::var("IP_TOKEN_KEY")
        .unwrap_or_else(|_| "change-me-in-production".to_string())
        .into_bytes();
    let listen_addr: SocketAddr = std::env::var("LISTEN_ADDR")
        .unwrap_or_else(|_| "0.0.0.0:3002".to_string())
        .parse()
        .expect("Invalid LISTEN_ADDR");

    // ── Common shared-table migrations (provigil-common) ─────────────────
    // Creates ndr.users, ndr.tenants, ndr.sigma_rules, ndr.siem_rules, etc.
    // Safe to run on every boot — all statements are IF NOT EXISTS.
    {
        let ch = provigil_common::clickhouse::ClickHouseConfig::from_env().build_client();
        provigil_common::migrations::run_common_migrations(&ch).await;
    }

    // ── SIEM schema init (per-tenant tables) ─────────────────────────────
    // Runs siem_init.sql for the default tenant DB on startup.
    // Per-tenant DBs are initialised by ndr-engine when a tenant is created.
    if let Err(e) = db_init::run(&clickhouse_url, "ndr").await {
        tracing::warn!("SIEM schema init warning: {e}");
    }

    // ── Pipeline ──────────────────────────────────────────────────────────
    let pipeline = Pipeline::new(
        hmac_key,
        clickhouse_url.clone(),
        valkey_url.clone(),
        &kafka_brokers,
    );

    let state = AppState {
        jwt_secret,
        valkey_url:     valkey_url.clone(),
        clickhouse_url: clickhouse_url.clone(),
        kafka_brokers:  kafka_brokers.clone(),
        pipeline:       Arc::clone(&pipeline),
    };

    // ── Syslog receivers ─────────────────────────────────────────────────
    let pl = Arc::clone(&pipeline);
    tokio::spawn(ingest::syslog::start_tcp("0.0.0.0:601",  Arc::clone(&pl)));
    tokio::spawn(ingest::syslog::start_tcp("0.0.0.0:6514", Arc::clone(&pl)));
    tokio::spawn(ingest::syslog::start_udp("0.0.0.0:514",  pl));
    info!("Syslog receivers spawned (TCP :601/:6514, UDP :514)");

    // ── ClickHouse consumer ───────────────────────────────────────────────
    let consumer = ingest::clickhouse_consumer::ClickHouseConsumer {
        clickhouse_url: clickhouse_url.clone(),
        valkey_url:     valkey_url.clone(),
        kafka_brokers:  kafka_brokers.clone(),
    };
    tokio::spawn(async move { consumer.run().await });
    info!("ClickHouse consumer spawned (group: siem-engine-consumers)");

    // ── Correlation engine ────────────────────────────────────────────────
    correlation::start(kafka_brokers.clone(), clickhouse_url.clone(), valkey_url.clone()).await?;

    // ── HTTP router ───────────────────────────────────────────────────────
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    // Decompress gzip request bodies (Winlogbeat compresses /_bulk by default)
    let decompress = tower_http::decompression::RequestDecompressionLayer::new();

    // Protected routes — require valid JWT with 'siem' feature (super_admin bypasses)
    let siem_routes = Router::new()
        .route("/api/siem/dashboard",  axum::routing::get(api::dashboard::handler))
        .route("/api/siem/logs",       axum::routing::get(api::logs::handler))
        .route("/api/siem/sources",    axum::routing::get(api::sources::list)
                                           .post(api::sources::create))
        .route("/api/siem/sources/:id", axum::routing::delete(api::sources::delete))
        .route("/api/xdr/alerts",      axum::routing::get(api::alerts::list))
        .route("/api/siem/rules",      axum::routing::get(api::rules::list_rules))
        .route("/api/siem/rules/:id",  axum::routing::put(api::rules::update_rule))
        .route_layer(middleware::from_fn_with_state(state.clone(), api::middleware::require_siem));

    let app = Router::new()
        .route("/api/health",      axum::routing::get(health))
        .route("/api/siem/ingest", axum::routing::post(ingest::rest::handle))
        .route("/api/siem/wec",    axum::routing::post(ingest::wec::handle_wec))
        // Elasticsearch-compatible endpoints for Winlogbeat / Filebeat
        .route("/",                axum::routing::get(ingest::beats::cluster_info))
        .route("/_bulk",           axum::routing::post(ingest::beats::bulk_ingest))
        .route("/_license",        axum::routing::get(ingest::beats::license))
        .route("/_xpack",          axum::routing::get(ingest::beats::xpack))
        .route("/_index_template/:name", axum::routing::put(ingest::beats::template_stub)
                                             .get(ingest::beats::template_stub))
        .route("/_ilm/policy/:name",         axum::routing::put(ingest::beats::ilm_stub)
                                                 .get(ingest::beats::ilm_stub))
        .route("/_component_template/:name", axum::routing::put(ingest::beats::template_stub)
                                                 .get(ingest::beats::template_stub))
        .route("/_data_stream/:name",        axum::routing::get(ingest::beats::template_stub)
                                                 .put(ingest::beats::template_stub))
        .route("/_ingest/pipeline/:name",    axum::routing::put(ingest::beats::template_stub)
                                                 .get(ingest::beats::template_stub)
                                                 .delete(ingest::beats::template_stub))
        .route("/:index",          axum::routing::head(ingest::beats::index_stub)
                                       .get(ingest::beats::index_stub))
        .merge(siem_routes)
        .layer(decompress)
        .layer(cors)
        .with_state(state);

    info!("siem-engine HTTP listening on {}", listen_addr);
    let listener = tokio::net::TcpListener::bind(listen_addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

async fn health() -> (StatusCode, Json<Value>) {
    (StatusCode::OK, Json(json!({
        "status":  "ok",
        "service": "siem-engine",
        "modules": [
            "correlation-engine",
            "kafka-consumer",
            "ueba-baseline",
            "sla-checker",
            "living-genome"
        ]
    })))
}



