use axum::{extract::State, Json};
use serde_json::{json, Value};
use crate::api::AppState;

pub async fn kafka_status(_state: State<AppState>) -> Json<Value> {
    // Each of these shells out to a JVM-based Kafka CLI tool via `docker exec`
    // (real cold-start cost, often 1-3s+ per call) - run sequentially and
    // synchronously (std::process::Command, not tokio::process) this used to
    // take ~12s total and, because it blocked the async runtime instead of
    // yielding, could stall unrelated concurrent requests on the same
    // ndr-engine instance for that whole window. spawn_blocking moves each
    // call onto Tokio's dedicated blocking thread pool, and running all 5
    // concurrently cuts wall time to whichever single call is slowest
    // instead of their sum.
    let topics_task = tokio::task::spawn_blocking(|| {
        std::process::Command::new("docker")
            .args(["exec", "kafka1", "/opt/kafka/bin/kafka-topics.sh",
                   "--bootstrap-server", "localhost:9092",
                   "--describe", "--topic", "ndr-events"])
            .output()
    });

    let groups_task = tokio::task::spawn_blocking(|| {
        std::process::Command::new("docker")
            .args(["exec", "kafka1", "/opt/kafka/bin/kafka-consumer-groups.sh",
                   "--bootstrap-server", "localhost:9092",
                   "--describe", "--group", "ndr-engine-group"])
            .output()
    });

    let broker_list = [("kafka1", 1u32), ("kafka2", 2u32), ("kafka3", 3u32)];
    let mut broker_tasks = Vec::with_capacity(broker_list.len());
    for (host, id) in broker_list {
        broker_tasks.push(tokio::task::spawn_blocking(move || {
            let healthy = std::process::Command::new("docker")
                .args(["exec", host, "/opt/kafka/bin/kafka-broker-api-versions.sh",
                       "--bootstrap-server", "localhost:9092"])
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false);
            (host, id, healthy)
        }));
    }

    let (topics_result, groups_result) = tokio::join!(topics_task, groups_task);

    // ── Topic describe ────────────────────────────────────────────────
    let mut partitions: Vec<Value> = Vec::new();
    let mut replication_factor = 0u32;
    let mut partition_count    = 0u32;

    if let Ok(Ok(out)) = topics_result {
        let text = String::from_utf8_lossy(&out.stdout);
        for line in text.lines() {
            if line.contains("PartitionCount:") {
                for part in line.split('\t') {
                    if let Some(v) = part.strip_prefix("PartitionCount:") {
                        partition_count = v.trim().parse().unwrap_or(0);
                    }
                    if let Some(v) = part.strip_prefix("ReplicationFactor:") {
                        replication_factor = v.trim().parse().unwrap_or(0);
                    }
                }
            } else if line.trim_start().starts_with("Topic:") && line.contains("Partition:") {
                let mut id = 0i32;
                let mut leader = 0i32;
                let mut replicas = String::new();
                let mut isr = String::new();
                for part in line.split('\t') {
                    let part = part.trim();
                    if let Some(v) = part.strip_prefix("Partition:")  { id = v.trim().parse().unwrap_or(0); }
                    if let Some(v) = part.strip_prefix("Leader:")     { leader = v.trim().parse().unwrap_or(-1); }
                    if let Some(v) = part.strip_prefix("Replicas:")   { replicas = v.trim().to_string(); }
                    if let Some(v) = part.strip_prefix("Isr:")        { isr = v.trim().to_string(); }
                }
                let isr_count = isr.split(',').filter(|s| !s.trim().is_empty()).count();
                partitions.push(json!({
                    "partition":     id,
                    "leader_broker": leader,
                    "replicas":      replicas,
                    "isr":           isr,
                    "in_sync":       isr_count == replication_factor as usize,
                }));
            }
        }
    }

    // ── Consumer group lag ────────────────────────────────────────────
    let mut consumers: Vec<Value> = Vec::new();
    let mut total_lag: i64 = 0;

    if let Ok(Ok(out)) = groups_result {
        let text = String::from_utf8_lossy(&out.stdout);
        for line in text.lines() {
            // GROUP TOPIC PARTITION CURRENT-OFFSET LOG-END-OFFSET LAG CONSUMER-ID HOST CLIENT-ID
            let cols: Vec<&str> = line.split_whitespace().collect();
            if cols.len() >= 7 && cols[0] == "ndr-engine-group" {
                let partition: i32 = cols[2].parse().unwrap_or(-1);
                let lag: i64       = cols[5].parse().unwrap_or(0);
                let client_id = cols.get(8).unwrap_or(&"-").to_string();
                total_lag += lag;
                consumers.push(json!({
                    "partition":      partition,
                    "current_offset": cols[3],
                    "log_end_offset": cols[4],
                    "lag":            lag,
                    "engine":         client_id,
                }));
            }
        }
    }

    // ── Broker health ─────────────────────────────────────────────────
    let mut brokers: Vec<Value> = Vec::with_capacity(broker_tasks.len());
    for task in broker_tasks {
        if let Ok((host, id, healthy)) = task.await {
            brokers.push(json!({
                "id":     id,
                "host":   host,
                "status": if healthy { "healthy" } else { "unreachable" },
            }));
        }
    }

    Json(json!({
        "topic":              "ndr-events",
        "partition_count":    partition_count,
        "replication_factor": replication_factor,
        "brokers":            brokers,
        "partitions":         partitions,
        "consumers":          consumers,
        "total_lag":          total_lag,
    }))
}
