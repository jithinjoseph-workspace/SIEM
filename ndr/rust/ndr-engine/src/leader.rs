//! Redis-based distributed leader election.
//!
//! Only ONE engine instance runs threat background tasks at any time.
//! If the leader dies, another engine automatically takes over within 30s.
//!
//! Algorithm:
//!   All engines race to SET a Redis key with NX (only if not exists) + TTL.
//!   Winner = leader. Losers = followers.
//!   Leader renews TTL every 10 seconds.
//!   If leader dies, TTL expires, new race begins automatically.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::time::Duration;

const LEADER_KEY:        &str = "ndr:threat_leader";
const LEADER_TTL_MS:     u64  = 30_000; // 30s — key expires if leader dies
const RENEW_INTERVAL_MS: u64  = 10_000; // 10s — leader renews before expiry
const RETRY_INTERVAL_MS: u64  =  5_000; //  5s — followers retry this often

pub struct LeaderElection {
    redis:       Arc<redis::Client>,
    instance_id: String,
    is_leader:   Arc<AtomicBool>,
}

impl LeaderElection {
    pub fn new(redis_url: &str) -> anyhow::Result<Self> {
        let client = redis::Client::open(redis_url)
            .map_err(|e| anyhow::anyhow!("Redis connect failed: {}", e))?;

        // ENGINE_NAME (e.g. ndr-engine-1) if configured, else hostname + PID + random suffix
        let instance_id = std::env::var("ENGINE_NAME")
            .unwrap_or_else(|_| {
                let hostname = hostname::get()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .to_string();
                let pid:         u32 = std::process::id();
                let rand_suffix: u32 = rand::random();
                format!("{}-{}-{}", hostname, pid, rand_suffix)
            });

        tracing::info!("Leader election instance_id: {}", instance_id);

        Ok(Self {
            redis: Arc::new(client),
            instance_id,
            is_leader: Arc::new(AtomicBool::new(false)),
        })
    }

    #[allow(dead_code)]
    pub fn is_leader(&self) -> bool {
        self.is_leader.load(Ordering::Relaxed)
    }

    /// A cheap, cloneable handle to the same flag `is_leader()` reads — pass this
    /// into background tasks so they can skip real work when not the leader,
    /// instead of only checking leadership once at spawn time (which previously
    /// let a task started as leader keep running forever after losing it).
    pub fn is_leader_flag(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.is_leader)
    }

    #[allow(dead_code)]
    pub fn instance_id(&self) -> &str {
        &self.instance_id
    }

    #[allow(dead_code)]
    pub fn redis_client(&self) -> Arc<redis::Client> {
        self.redis.clone()
    }

    /// Start event-driven leader election.
    /// Uses Redis keyspace notifications — followers react instantly when leader key expires.
    /// No polling loop. Failover latency ≈ milliseconds instead of 5 seconds.
    pub fn start(
        self: Arc<Self>,
        on_elected: impl Fn() + Send + Sync + 'static,
        on_lost:    impl Fn() + Send + Sync + 'static,
    ) {
        // Enable Redis keyspace notifications once at startup
        // KEA = Keyspace + Keyevent + All commands
        {
            let redis = self.redis.clone();
            tokio::spawn(async move {
                if let Ok(mut conn) = redis.get_multiplexed_async_connection().await {
                    let _: () = redis::cmd("CONFIG")
                        .arg("SET")
                        .arg("notify-keyspace-events")
                        .arg("gxE") // E=keyevent channel, g=generic cmds (DEL), x=expired
                        .query_async(&mut conn)
                        .await
                        .unwrap_or(());
                    tracing::info!("Redis keyspace notifications enabled (expired/deleted only)");
                }
            });
        }

        let on_elected = Arc::new(on_elected);
        let on_lost    = Arc::new(on_lost);
        let self_arc   = self.clone();

        tokio::spawn(async move {
            // Initial election attempt on startup
            let won = self_arc.try_acquire_or_renew().await;
            self_arc.is_leader.store(won, Ordering::Relaxed);

            if won {
                tracing::info!("LEADER ELECTED (initial): {}", self_arc.instance_id);
                on_elected();
            } else {
                tracing::info!("FOLLOWER (initial): {}", self_arc.instance_id);
            }

            // ── TASK A: Leader renewal loop (every 10s, no-op when follower) ──
            // Connection is established once and reused across renewals.
            // On Redis error the connection is refreshed rather than creating
            // a new TCP handshake every 10 seconds.
            {
                let redis         = self_arc.redis.clone();
                let is_leader     = self_arc.is_leader.clone();
                let instance_id   = self_arc.instance_id.clone();
                let on_lost_clone = on_lost.clone();

                tokio::spawn(async move {
                    // Establish once; refresh inside the loop only on error.
                    let mut conn = match redis.get_multiplexed_async_connection().await {
                        Ok(c)  => c,
                        Err(e) => {
                            tracing::error!("Leader renewal: Redis unavailable at start: {} — loop inactive", e);
                            return;
                        }
                    };

                    loop {
                        tokio::time::sleep(
                            Duration::from_millis(RENEW_INTERVAL_MS)
                        ).await;

                        if !is_leader.load(Ordering::Relaxed) {
                            continue; // follower — nothing to renew
                        }

                        let current: Option<String> = match redis::cmd("GET")
                            .arg(LEADER_KEY)
                            .query_async(&mut conn)
                            .await
                        {
                            Ok(v) => v,
                            Err(e) => {
                                tracing::warn!("Leader renewal: Redis error ({}), reconnecting", e);
                                if let Ok(new) = redis.get_multiplexed_async_connection().await {
                                    conn = new;
                                }
                                continue;
                            }
                        };

                        if current.as_deref() == Some(instance_id.as_str()) {
                            // Atomic: only extend TTL if we still own the key (Lua = single round-trip)
                            let renewed: i64 = redis::Script::new(
                                "if redis.call('GET', KEYS[1]) == ARGV[1] then \
                                    return redis.call('PEXPIRE', KEYS[1], ARGV[2]) \
                                 else return 0 end"
                            )
                            .key(LEADER_KEY)
                            .arg(&instance_id)
                            .arg(LEADER_TTL_MS)
                            .invoke_async(&mut conn)
                            .await
                            .unwrap_or(0);
                            if renewed == 1 {
                                tracing::debug!("Leadership renewed: {}", instance_id);
                            } else {
                                // Lost it between the GET above and the Lua call — treat as lost
                                is_leader.store(false, Ordering::Relaxed);
                                tracing::warn!("LEADERSHIP LOST (renewal race): {}", instance_id);
                                on_lost_clone();
                            }
                        } else {
                            // Key gone or taken — we lost it
                            is_leader.store(false, Ordering::Relaxed);
                            tracing::warn!("LEADERSHIP LOST unexpectedly: {}", instance_id);
                            on_lost_clone();
                        }
                    }
                });
            }

            // ── TASK B: Keyspace event listener (fires on key expiry/delete) ──
            {
                let redis         = self_arc.redis.clone();
                let is_leader     = self_arc.is_leader.clone();
                let self_for_ev   = self_arc.clone();
                let on_elected_ev = on_elected.clone();

                tokio::spawn(async move {
                    // Separate async connection required for pub/sub (blocking receive)
                    let conn = match redis.get_async_connection().await {
                        Ok(c)  => c,
                        Err(e) => {
                            tracing::warn!("PubSub unavailable: {} — falling back to polling", e);
                            // Polling fallback if pubsub setup fails
                            loop {
                                tokio::time::sleep(
                                    Duration::from_millis(RETRY_INTERVAL_MS)
                                ).await;
                                if is_leader.load(Ordering::Relaxed) { continue; }
                                let won = self_for_ev.try_acquire_or_renew().await;
                                if won {
                                    is_leader.store(true, Ordering::Relaxed);
                                    on_elected_ev();
                                }
                            }
                        }
                    };

                    let mut pubsub = conn.into_pubsub();

                    // Subscribe to expiry AND del events for any key (we filter by name)
                    let _ = pubsub.subscribe("__keyevent@0__:expired").await;
                    let _ = pubsub.subscribe("__keyevent@0__:del").await;

                    tracing::info!("Subscribed to Redis keyspace events for leader key");

                    use futures_util::StreamExt;
                    let mut stream = pubsub.on_message();

                    while let Some(msg) = stream.next().await {
                        let key: String = msg.get_payload().unwrap_or_default();

                        if key != LEADER_KEY {
                            continue; // not our key, ignore
                        }

                        tracing::info!("Leader key event — attempting election immediately");

                        // Fire immediately — no 5s wait
                        if !is_leader.load(Ordering::Relaxed) {
                            let won = self_for_ev.try_acquire_or_renew().await;
                            if won {
                                tracing::info!(
                                    "LEADER ELECTED (event-driven): {}",
                                    self_for_ev.instance_id
                                );
                                is_leader.store(true, Ordering::Relaxed);
                                on_elected_ev();
                            }
                        }
                    }

                    tracing::warn!("PubSub stream ended — falling back to polling");
                    // Stream died — fall back to polling
                    loop {
                        tokio::time::sleep(Duration::from_millis(RETRY_INTERVAL_MS)).await;
                        if is_leader.load(Ordering::Relaxed) { continue; }
                        let won = self_for_ev.try_acquire_or_renew().await;
                        if won {
                            is_leader.store(true, Ordering::Relaxed);
                            on_elected_ev();
                        }
                    }
                });
            }
        });
    }

    async fn try_acquire_or_renew(&self) -> bool {
        let Ok(mut conn) = self.redis.get_multiplexed_async_connection().await else {
            tracing::warn!("Redis unavailable — keeping current leader status");
            return self.is_leader.load(Ordering::Relaxed);
        };

        if self.is_leader.load(Ordering::Relaxed) {
            // Already leader — verify we still own the key then extend TTL
            let current: Option<String> = redis::cmd("GET")
                .arg(LEADER_KEY)
                .query_async(&mut conn)
                .await
                .unwrap_or(None);

            if current.as_deref() == Some(&self.instance_id) {
                let renewed: bool = redis::cmd("PEXPIRE")
                    .arg(LEADER_KEY)
                    .arg(LEADER_TTL_MS)
                    .query_async(&mut conn)
                    .await
                    .unwrap_or(false);
                return renewed;
            }
            tracing::warn!("Lost Redis key unexpectedly");
            return false;
        }

        // Not leader — race to win election with SET NX PX (atomic)
        let result: Option<String> = redis::cmd("SET")
            .arg(LEADER_KEY)
            .arg(&self.instance_id)
            .arg("NX")
            .arg("PX")
            .arg(LEADER_TTL_MS)
            .query_async(&mut conn)
            .await
            .unwrap_or(None);

        result.as_deref() == Some("OK")
    }

    /// Release leadership immediately on graceful shutdown.
    /// Another engine takes over in seconds instead of waiting 30s for TTL.
    pub async fn release(&self) {
        let Ok(mut conn) = self.redis.get_multiplexed_async_connection().await else {
            return;
        };

        // Atomic: only DEL if we still own the key — prevents deleting a new leader's key
        let deleted: i64 = redis::Script::new(
            "if redis.call('GET', KEYS[1]) == ARGV[1] then \
                return redis.call('DEL', KEYS[1]) \
             else return 0 end"
        )
        .key(LEADER_KEY)
        .arg(&self.instance_id)
        .invoke_async(&mut conn)
        .await
        .unwrap_or(0);

        if deleted == 1 {
            tracing::info!("Leadership released gracefully: {}", self.instance_id);
        }
    }
}
