//! Keeps the automatic evidence capture and AI analysis from repeating for the same thing.
//!
//! Every MEDIUM-or-higher alert used to start an evidence bundle and an AI call for its own
//! conversation, so one chatty host produced a dozen near-identical analyses in minutes. The
//! counters live in Redis, so all engines share them. If Redis is unreachable everything is
//! allowed (fail open): a repeat is better than a missed alert.

use redis::aio::MultiplexedConnection;

fn env_u64(name: &str, default: u64) -> u64 {
    std::env::var(name).ok().and_then(|v| v.trim().parse::<u64>().ok()).unwrap_or(default)
}

/// The same conversation (community id) is captured and analysed once per this many seconds.
pub fn capture_repeat_secs() -> u64 { env_u64("AUTOCAPTURE_REPEAT_SECS", 3600).max(10) }
/// The same source -> destination pair gets one AI analysis per this many seconds.
pub fn pair_repeat_secs() -> u64 { env_u64("AI_ANALYSIS_REPEAT_SECS", 6 * 3600).max(10) }
/// One source host gets at most this many AI analyses per hour (0 = no limit).
pub fn host_max_per_hour() -> u64 { env_u64("AI_ANALYSIS_MAX_PER_HOST_HOUR", 3) }

/// True the first time `key` is claimed within `ttl_secs` (SET NX EX); false while it is held.
pub async fn claim_once(redis: &mut MultiplexedConnection, key: &str, ttl_secs: u64) -> bool {
    let reply: Result<Option<String>, _> = redis::cmd("SET")
        .arg(key).arg("1").arg("NX").arg("EX").arg(ttl_secs).query_async(redis).await;
    match reply {
        Ok(Some(_)) => true,
        Ok(None)    => false,
        Err(_)      => true, // Redis down: allow
    }
}

/// Forget a claim (used when a later check refuses the work the claim was for).
pub async fn release(redis: &mut MultiplexedConnection, key: &str) {
    let _: Result<i64, _> = redis::cmd("DEL").arg(key).query_async(redis).await;
}

/// True while fewer than `max` uses of `key` were taken in the current hour window.
pub async fn take_hourly_slot(redis: &mut MultiplexedConnection, key: &str, max: u64) -> bool {
    if max == 0 { return true; }
    let n: Result<u64, _> = redis::cmd("INCR").arg(key).query_async(redis).await;
    match n {
        Ok(n) => {
            if n == 1 {
                let _: Result<i64, _> = redis::cmd("EXPIRE").arg(key).arg(3600u64).query_async(redis).await;
            }
            n <= max
        }
        Err(_) => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Needs a real Redis: TEST_REDIS_URL (default a throwaway DB 5 on localhost).
    //   cargo test -p ndr-engine throttle -- --ignored
    #[tokio::test]
    #[ignore]
    async fn repeats_are_blocked_and_slots_run_out_against_a_real_redis() {
        let url = std::env::var("TEST_REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379/5".into());
        let mut c = redis::Client::open(url).unwrap().get_multiplexed_async_connection().await.unwrap();
        let id = std::process::id();
        let (k1, k2) = (format!("thr-test:once:{id}"), format!("thr-test:slot:{id}"));
        let _: Result<i64, _> = redis::cmd("DEL").arg(&k1).arg(&k2).query_async(&mut c).await;

        assert!(claim_once(&mut c, &k1, 30).await, "first claim wins");
        assert!(!claim_once(&mut c, &k1, 30).await, "the same thing again is refused");
        release(&mut c, &k1).await;
        assert!(claim_once(&mut c, &k1, 30).await, "after release it can be claimed again");

        assert!(take_hourly_slot(&mut c, &k2, 2).await);
        assert!(take_hourly_slot(&mut c, &k2, 2).await);
        assert!(!take_hourly_slot(&mut c, &k2, 2).await, "third use in the hour is refused");
        assert!(take_hourly_slot(&mut c, "thr-test:zero", 0).await, "0 means no limit");
        let _: Result<i64, _> = redis::cmd("DEL").arg(&k1).arg(&k2).query_async(&mut c).await;
    }

    #[test]
    fn defaults_are_the_documented_ones() {
        assert_eq!(capture_repeat_secs(), 3600);
        assert_eq!(pair_repeat_secs(), 21600);
        assert_eq!(host_max_per_hour(), 3);
    }
}
