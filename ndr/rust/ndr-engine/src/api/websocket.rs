use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::State;
use crate::api::AppState;
use futures_util::StreamExt;

/// Interval between periodic user/tenant active checks (Layer 2).
/// 60 seconds balances security (short window) against database load.
const REVALIDATION_INTERVAL_SECS: u64 = 60;

/// Redis channels used for instant session revocation (Layer 3).
const REVOKE_USER_CHANNEL: &str = "system:user_revoked";
const REVOKE_TENANT_CHANNEL: &str = "system:tenant_revoked";

/// Context extracted from the JWT during the WebSocket upgrade handshake.
/// Carried into `handle_ws` so every layer can reference identity without
/// re-parsing the token.
struct WsAuthContext {
    username: String,
    tenant_id: String,
    role: String,
    sensor_ids: Vec<String>,
}

pub async fn ws_handler(
    ws: WebSocketUpgrade,
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> axum::response::Response {
    // Try cookie auth on the HTTP upgrade request first (Step 3 cookie path).
    // Falls back to the app-level {"type":"auth","token":"..."} message so old
    // Bearer-header clients continue to work during the migration period.
    let pre_auth = crate::api::extract_claims(&headers);
    ws.on_upgrade(move |socket| authenticate_then_handle(socket, state, pre_auth))
}

async fn authenticate_then_handle(
    mut socket: WebSocket,
    state: AppState,
    pre_auth: Option<crate::api::AuthClaims>,
) {
    // If the HTTP upgrade already carried a valid cookie, skip the message wait.
    let claims = if let Some(c) = pre_auth {
        c
    } else {
        // Legacy path: wait up to 10 s for {"type":"auth","token":"..."}
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            async {
                while let Some(Ok(Message::Text(text))) = socket.next().await {
                    if let Ok(msg) = serde_json::from_str::<serde_json::Value>(&text) {
                        if msg["type"] == "auth" {
                            if let Some(token) = msg["token"].as_str() {
                                return crate::api::extract_claims_with_token(token);
                            }
                        }
                    }
                }
                None
            }
        ).await.unwrap_or(None);

        match result {
            Some(c) => c,
            None => {
                let _ = socket.send(Message::Text(
                    r#"{"type":"error","message":"Unauthorized"}"#.to_string()
                )).await;
                return;
            }
        }
    };

    // ── Layer 1: Gate check — reject blocked users at connection time ─────
    if claims.role != "super_admin" {
        match state.ch_storage.is_tenant_active(&claims.tenant_id).await {
            Ok(false) => {
                tracing::info!("🚫 WebSocket rejected: tenant '{}' is deactivated", claims.tenant_id);
                let _ = socket.send(Message::Text(
                    r#"{"type":"error","message":"Tenant has been deactivated"}"#.to_string()
                )).await;
                return;
            }
            Err(e) => {
                tracing::warn!("WebSocket tenant check failed for '{}': {}", claims.tenant_id, e);
                let _ = socket.send(Message::Text(
                    r#"{"type":"error","message":"Unable to verify tenant status"}"#.to_string()
                )).await;
                return;
            }
            Ok(true) => {}
        }

        let blockable_roles = ["analyst", "senior_analyst", "viewer", "default_user"];
        if blockable_roles.contains(&claims.role.as_str()) {
            match state.ch_storage.is_user_active(&claims.sub).await {
                Ok(false) => {
                    tracing::info!("🚫 WebSocket rejected: user '{}' is disabled", claims.sub);
                    let _ = socket.send(Message::Text(
                        r#"{"type":"error","message":"Your account has been disabled by your administrator.","code":"USER_DISABLED"}"#.to_string()
                    )).await;
                    return;
                }
                Err(e) => {
                    tracing::warn!("WebSocket user active check failed for '{}': {}", claims.sub, e);
                }
                Ok(true) => {}
            }
        }
    }

    let auth_ctx = WsAuthContext {
        username:   claims.sub,
        tenant_id:  claims.tenant_id,
        role:       claims.role,
        sensor_ids: claims.sensor_ids,
    };

    handle_ws(socket, state, auth_ctx).await;
}

async fn handle_ws(
    mut socket: WebSocket,
    state: AppState,
    auth: WsAuthContext,
) {
    let agent = std::env::var("NDR_AGENT_URL")
        .unwrap_or_else(|_| "http://host.docker.internal:3001".to_string());
    let client = state.http_client.clone();

    // Push interfaces only to default tenant
    if auth.tenant_id == "default" {
        if let Ok(resp) = client.get(
            format!("{}/agent/interfaces", agent)
        ).send().await {
            if let Ok(ifaces) = resp.json::<serde_json::Value>().await {
                let msg = serde_json::json!({
                    "type": "interfaces",
                    "interfaces": ifaces
                });
                let _ = socket.send(Message::Text(msg.to_string())).await;
            }
        }
    }

    // Push agent status only to default tenant (local sensor)
    if auth.tenant_id == "default" {
        if let Ok(resp) = client.get(
            format!("{}/agent/status", agent)
        ).send().await {
            if let Ok(data) = resp.json::<serde_json::Value>().await {
                let msg = serde_json::json!({
                    "type": "agent_status",
                    "agent-z": data.get("agent-z")
                        .and_then(|v| v.as_str())
                        .unwrap_or("stopped"),
                    "agent-s": data.get("agent-s")
                        .and_then(|v| v.as_str())
                        .unwrap_or("stopped"),
                    "interface": data.get("interface")
                        .and_then(|v| v.as_str())
                        .unwrap_or("eth0"),
                });
                let _ = socket.send(Message::Text(msg.to_string())).await;
            }
        }
    }

    // ── Try Redis-backed streaming (primary path) ─────────────────────────
    let tenant_channel = format!("tenant:{}", auth.tenant_id);
    if let Ok(conn) = state.redis.get_async_connection().await {
        let mut pubsub = conn.into_pubsub();

        let subscribed = pubsub.subscribe(&tenant_channel).await.is_ok()
            && pubsub.subscribe(REVOKE_USER_CHANNEL).await.is_ok()
            && pubsub.subscribe(REVOKE_TENANT_CHANNEL).await.is_ok();

        if subscribed {
            let mut stream = pubsub.on_message();
            let mut revalidation_interval = tokio::time::interval(
                tokio::time::Duration::from_secs(REVALIDATION_INTERVAL_SECS)
            );
            revalidation_interval.tick().await;
            let mut ping_interval = tokio::time::interval(
                tokio::time::Duration::from_secs(30)
            );
            ping_interval.tick().await; // skip immediate first tick

            loop {
                tokio::select! {
                    _ = ping_interval.tick() => {
                        // Push live stats + supporting data alongside the keepalive ping
                        let (stats, severity, top_src, top_dst, protocols) = tokio::join!(
                            state.ch_storage.get_stats_by_tenant(&auth.tenant_id, &auth.sensor_ids),
                            state.ch_storage.get_severity_by_tenant(&auth.tenant_id, &auth.sensor_ids, 0),
                            state.ch_storage.get_top_src_ips_by_tenant(10, &auth.tenant_id, &auth.sensor_ids),
                            state.ch_storage.get_top_dst_ips_by_tenant(10, &auth.tenant_id, &auth.sensor_ids),
                            state.ch_storage.get_top_protocols_by_tenant(10, &auth.tenant_id, &auth.sensor_ids),
                        );
                        if let Ok(stats) = stats {
                            let telemetry = serde_json::json!({
                                "type":             "telemetry",
                                "total_events":     stats.get("events_total").and_then(|v| v.as_u64()).unwrap_or(0),
                                "agent_z_events":   stats.get("agent_z_events").and_then(|v| v.as_u64()).unwrap_or(0),
                                "agent_s_events":   stats.get("agent_s_events").and_then(|v| v.as_u64()).unwrap_or(0),
                                "correlation_hits": stats.get("hits_total").and_then(|v| v.as_u64()).unwrap_or(0),
                                "events_1h":        stats.get("events_1h").and_then(|v| v.as_u64()).unwrap_or(0),
                                "severity":         severity.ok(),
                                "top_src_ips":      top_src.unwrap_or_default(),
                                "top_dst_ips":      top_dst.unwrap_or_default(),
                                "protocols":        protocols.unwrap_or_default(),
                            });
                            if socket.send(Message::Text(telemetry.to_string())).await.is_err() {
                                break;
                            }
                        }
                        if socket.send(Message::Ping(vec![])).await.is_err() {
                            break; // dead connection — clean up task
                        }
                    }
                    msg = stream.next() => {
                        match msg {
                            Some(m) => {
                                let channel: String = m.get_channel_name().to_string();

                                // ── Layer 3: Instant revocation via Redis ──
                                if channel == REVOKE_USER_CHANNEL {
                                    if let Ok(revoked_user) = m.get_payload::<String>() {
                                        if revoked_user == auth.username {
                                            tracing::info!(
                                                "⚡ Instant WebSocket revocation for user '{}'",
                                                auth.username
                                            );
                                            let _ = send_force_logout(
                                                &mut socket,
                                                "Your account has been disabled by your administrator."
                                            ).await;
                                            break;
                                        }
                                    }
                                    continue;
                                }
                                if channel == REVOKE_TENANT_CHANNEL {
                                    if let Ok(revoked_tenant) = m.get_payload::<String>() {
                                        if revoked_tenant == auth.tenant_id {
                                            tracing::info!(
                                                "⚡ Instant WebSocket revocation for tenant '{}'",
                                                auth.tenant_id
                                            );
                                            let _ = send_force_logout(
                                                &mut socket,
                                                "Your tenant has been deactivated."
                                            ).await;
                                            break;
                                        }
                                    }
                                    continue;
                                }

                                // ── Normal tenant alert message ───────────
                                if let Ok(payload) = m.get_payload::<String>() {
                                    // Apply sensor filter — skip events from sensors
                                    // the user is not assigned to.
                                    if !auth.sensor_ids.is_empty() {
                                        if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&payload) {
                                            let event_sensor = parsed.get("sensor_host")
                                                .or_else(|| parsed.get("sensor_id"))
                                                .and_then(|v| v.as_str())
                                                .unwrap_or("");
                                            if !auth.sensor_ids.iter().any(|s| s == event_sensor) {
                                                continue;
                                            }
                                        }
                                    }
                                    if socket.send(Message::Text(payload)).await.is_err() {
                                        break;
                                    }
                                }
                            }
                            None => break
                        }
                    }

                    // ── Layer 2: Periodic re-validation (every 60s) ───────
                    _ = revalidation_interval.tick() => {
                        if should_force_disconnect(&state, &auth).await {
                            tracing::info!(
                                "🔄 Periodic re-validation: disconnecting user='{}' tenant='{}'",
                                auth.username, auth.tenant_id
                            );
                            let _ = send_force_logout(
                                &mut socket,
                                "Your session has been terminated."
                            ).await;
                            break;
                        }
                    }
                }
            }
            return;
        }
    }

    // ── Fallback: local broadcast channel (no Redis) ──────────────────────
    let mut rx = state.tx.subscribe();
    let mut revalidation_interval = tokio::time::interval(
        tokio::time::Duration::from_secs(REVALIDATION_INTERVAL_SECS)
    );
    revalidation_interval.tick().await;
    let mut ping_interval_fb = tokio::time::interval(
        tokio::time::Duration::from_secs(30)
    );
    ping_interval_fb.tick().await;

    loop {
        tokio::select! {
            _ = ping_interval_fb.tick() => {
                let (stats, severity, top_src, top_dst, protocols) = tokio::join!(
                    state.ch_storage.get_stats_by_tenant(&auth.tenant_id, &auth.sensor_ids),
                    state.ch_storage.get_severity_by_tenant(&auth.tenant_id, &auth.sensor_ids, 0),
                    state.ch_storage.get_top_src_ips_by_tenant(10, &auth.tenant_id, &auth.sensor_ids),
                    state.ch_storage.get_top_dst_ips_by_tenant(10, &auth.tenant_id, &auth.sensor_ids),
                    state.ch_storage.get_top_protocols_by_tenant(10, &auth.tenant_id, &auth.sensor_ids),
                );
                if let Ok(stats) = stats {
                    let telemetry = serde_json::json!({
                        "type":             "telemetry",
                        "total_events":     stats.get("events_total").and_then(|v| v.as_u64()).unwrap_or(0),
                        "agent_z_events":   stats.get("agent_z_events").and_then(|v| v.as_u64()).unwrap_or(0),
                        "agent_s_events":   stats.get("agent_s_events").and_then(|v| v.as_u64()).unwrap_or(0),
                        "correlation_hits": stats.get("hits_total").and_then(|v| v.as_u64()).unwrap_or(0),
                        "events_1h":        stats.get("events_1h").and_then(|v| v.as_u64()).unwrap_or(0),
                        "severity":         severity.ok(),
                        "top_src_ips":      top_src.unwrap_or_default(),
                        "top_dst_ips":      top_dst.unwrap_or_default(),
                        "protocols":        protocols.unwrap_or_default(),
                    });
                    if socket.send(Message::Text(telemetry.to_string())).await.is_err() {
                        break;
                    }
                }
                if socket.send(Message::Ping(vec![])).await.is_err() {
                    break;
                }
            }
            result = rx.recv() => {
                match result {
                    Ok(msg) => {
                        let should_send = if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&msg) {
                            let tenant_ok = parsed.get("tenant_id")
                                .and_then(|t| t.as_str())
                                .map(|t| t == auth.tenant_id)
                                .unwrap_or(false);
                            let sensor_ok = if auth.sensor_ids.is_empty() {
                                true
                            } else {
                                let event_sensor = parsed.get("sensor_host")
                                    .or_else(|| parsed.get("sensor_id"))
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("");
                                auth.sensor_ids.iter().any(|s| s == event_sensor)
                            };
                            tenant_ok && sensor_ok
                        } else {
                            false
                        };

                        if should_send {
                            if socket.send(Message::Text(msg)).await.is_err() {
                                break;
                            }
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                        tracing::warn!(
                            "WebSocket client lagged, dropped {} messages", n
                        );
                    }
                    Err(_) => break,
                }
            }

            // ── Layer 2: Periodic re-validation (fallback path) ───────────
            _ = revalidation_interval.tick() => {
                if should_force_disconnect(&state, &auth).await {
                    tracing::info!(
                        "🔄 Periodic re-validation (fallback): disconnecting user='{}' tenant='{}'",
                        auth.username, auth.tenant_id
                    );
                    let _ = send_force_logout(
                        &mut socket,
                        "Your session has been terminated."
                    ).await;
                    break;
                }
            }
        }
    }
}

async fn should_force_disconnect(state: &AppState, auth: &WsAuthContext) -> bool {
    if auth.role == "super_admin" {
        return false;
    }

    let mut redis = state.redis_mux.clone();
    let cache_ttl = 60u64; // seconds — matches revalidation interval

    // ── Tenant active check — Redis cache first, ClickHouse on miss ──────
    let tenant_cache_key = format!("ndr:ws_tenant_active:{}", auth.tenant_id);
    let tenant_cached: Option<String> = redis::cmd("GET")
        .arg(&tenant_cache_key)
        .query_async(&mut redis).await.unwrap_or(None);

    let tenant_active = match tenant_cached.as_deref() {
        Some("1") => true,
        Some("0") => false,
        _ => {
            // Cache miss — query ClickHouse and cache result
            let active = state.ch_storage.is_tenant_active(&auth.tenant_id).await
                .unwrap_or(true); // default allow on error
            let val = if active { "1" } else { "0" };
            let _: () = redis::cmd("SETEX")
                .arg(&tenant_cache_key).arg(cache_ttl).arg(val)
                .query_async(&mut redis).await.unwrap_or(());
            active
        }
    };

    if !tenant_active {
        return true;
    }

    // ── User active check — Redis cache first, ClickHouse on miss ────────
    let blockable_roles = ["analyst", "senior_analyst", "viewer", "default_user"];
    if blockable_roles.contains(&auth.role.as_str()) {
        let user_cache_key = format!("ndr:ws_user_active:{}", auth.username);
        let user_cached: Option<String> = redis::cmd("GET")
            .arg(&user_cache_key)
            .query_async(&mut redis).await.unwrap_or(None);

        let user_active = match user_cached.as_deref() {
            Some("1") => true,
            Some("0") => false,
            _ => {
                let active = state.ch_storage.is_user_active(&auth.username).await
                    .unwrap_or(true);
                let val = if active { "1" } else { "0" };
                let _: () = redis::cmd("SETEX")
                    .arg(&user_cache_key).arg(cache_ttl).arg(val)
                    .query_async(&mut redis).await.unwrap_or(());
                active
            }
        };

        if !user_active {
            return true;
        }
    }

    false
}

async fn send_force_logout(
    socket: &mut WebSocket,
    reason: &str,
) -> Result<(), axum::Error> {
    let msg = serde_json::json!({
        "type": "force_logout",
        "reason": reason,
        "code": "SESSION_REVOKED"
    });
    socket.send(Message::Text(msg.to_string())).await?;
    socket.send(Message::Close(None)).await?;
    Ok(())
}
