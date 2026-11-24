#!/bin/bash
# NDR Capacity Planner — Correct Architecture
# Separates: Capture → Transport → Processing → Query

INSTALL_DIR=$(cd "$(dirname "$0")/.." && pwd)
source $INSTALL_DIR/.env 2>/dev/null || true
if [ -z "$CLICKHOUSE_PASSWORD" ]; then
    echo "ERROR: CLICKHOUSE_PASSWORD not found in $INSTALL_DIR/.env — refusing to run with a default password." >&2
    exit 1
fi
IFACE_FILE="$INSTALL_DIR/.runtime/ndr_interface"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log()  { echo -e "${GREEN}[NDR]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
info() { echo -e "${BLUE}[INFO]${NC} $1"; }

# ── Capacity calculation ──────────────────────
calculate_capacity() {
    local computers=$1

    # Traffic estimation
    local conn_per_sec=$(( computers * 100 / 60 ))
    local events_per_sec=$(( conn_per_sec * 3 ))
    local peak_eps=$(( events_per_sec * 3 ))

    # CAPTURE LAYER (fixed at deploy — based on traffic)
    # Zeek: 50k conn/sec per instance with AF_PACKET fanout
    local zeek=$(( (peak_eps / 50000) + 1 ))
    # Suricata: 30k events/sec per instance
    local suri=$(( (peak_eps / 30000) + 1 ))
    # Vector: 100k events/sec per instance
    local vector=$(( (peak_eps / 100000) + 1 ))

    # TRANSPORT LAYER (fixed)
    # Kafka partitions: 1 per 5k events/sec minimum
    local kafka=$(( (peak_eps / 5000) + 2 ))

    # PROCESSING LAYER (workers — can auto-scale)
    # Each worker: 20k events/sec
    local workers=$(( (peak_eps / 20000) + 1 ))

    # QUERY LAYER (always 1)
    local api=1

    # Storage
    local ch_nodes=$(( (peak_eps / 500000) + 1 ))

    # Hardware
    local ram=$(( zeek*4 + suri*4 + vector*2 + workers*2 + 16 ))
    local cpu=$(( zeek*4 + suri*4 + vector*2 + workers*2 + 4 ))

    echo "$zeek $suri $vector $kafka $workers $api $ch_nodes $ram $cpu $peak_eps"
}

# ── Show plan ─────────────────────────────────
show_plan() {
    local computers=$1
    read zeek suri vector kafka workers api ch ram cpu eps \
        <<< $(calculate_capacity $computers)

    echo ""
    echo "╔═══════════════════════════════════════════════════════╗"
    echo "║           NDR CAPACITY PLAN (Correct Architecture)    ║"
    echo "╠═══════════════════════════════════════════════════════╣"
    printf "║  Computers to monitor:  %-30s║\n" "$computers"
    printf "║  Peak events/sec:       %-30s║\n" "$eps"
    echo "╠═══════════════════════════════════════════════════════╣"
    echo "║  CAPTURE LAYER  (fixed at deploy — never changes)     ║"
    printf "║  %-25s %-28s║\n" "Zeek IDS:"      "$zeek instances"
    printf "║  %-25s %-28s║\n" "Suricata EVE:"  "$suri instances"
    printf "║  %-25s %-28s║\n" "Vector:"        "$vector instances"
    echo "╠═══════════════════════════════════════════════════════╣"
    echo "║  TRANSPORT LAYER  (fixed at deploy)                   ║"
    printf "║  %-25s %-28s║\n" "Kafka partitions:" "$kafka"
    echo "╠═══════════════════════════════════════════════════════╣"
    echo "║  PROCESSING LAYER  (auto-scales based on Kafka lag)   ║"
    printf "║  %-25s %-28s║\n" "NDR Workers:"   "$workers instances (min)"
    echo "╠═══════════════════════════════════════════════════════╣"
    echo "║  QUERY LAYER  (always exactly 1 — never scales)       ║"
    printf "║  %-25s %-28s║\n" "NDR API:"       "1 instance (stable)"
    echo "╠═══════════════════════════════════════════════════════╣"
    echo "║  STORAGE LAYER                                        ║"
    printf "║  %-25s %-28s║\n" "ClickHouse:"    "$ch_nodes nodes"
    echo "╠═══════════════════════════════════════════════════════╣"
    echo "║  HARDWARE REQUIREMENTS                                ║"
    printf "║  %-25s %-28s║\n" "RAM:" "$ram GB minimum"
    printf "║  %-25s %-28s║\n" "CPU:" "$cpu cores minimum"
    echo "╚═══════════════════════════════════════════════════════╝"
    echo ""
    echo "  ℹ️  Capture layer is FIXED — decided at deployment"
    echo "  ℹ️  Workers AUTO-SCALE based on Kafka consumer lag"
    echo "  ℹ️  API is ALWAYS single instance — no inconsistency"
    echo ""
}

# ── Deploy capture layer ──────────────────────
deploy_capture_layer() {
    local computers=$1
    read zeek suri vector kafka workers api ch ram cpu eps \
        <<< $(calculate_capacity $computers)

    log "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    log "STEP 1: Deploying CAPTURE LAYER"
    log "  Zeek: $zeek | Suricata: $suri | Vector: $vector"
    log "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

    local iface=$(cat "$IFACE_FILE" 2>/dev/null || echo "enp0s3")

    # Stop existing
    sudo pkill -9 zeek 2>/dev/null || true
    sudo pkill -9 suricata 2>/dev/null || true
    sudo rm -f /tmp/zeek-*.pid /tmp/suricata-*.pid
    sleep 3

    # Start Zeek instances
    for i in $(seq 1 $zeek); do
        mkdir -p $HOME/logs/zeek-$i
        if [ $zeek -eq 1 ]; then
            nohup sudo /opt/zeek/bin/zeek \
                -i $iface local \
                "Log::default_logdir=$HOME/logs/zeek-$i" \
                "LogAscii::use_json=T" \
                > /tmp/zeek-$i.log 2>&1 &
        else
            nohup sudo /opt/zeek/bin/zeek \
                -i $iface local \
                "Log::default_logdir=$HOME/logs/zeek-$i" \
                "LogAscii::use_json=T" \
                "AF_Packet::fanout_id=$i" \
                "AF_Packet::fanout_mode=AF_Packet::FANOUT_HASH" \
                > /tmp/zeek-$i.log 2>&1 &
        fi
        echo $! > /tmp/zeek-$i.pid
        log "  ✅ Zeek-$i started (PID: $!)"
    done

    # Start Suricata instances
    for i in $(seq 1 $suri); do
        mkdir -p $HOME/logs/suricata-$i
        sudo rm -f /tmp/suricata-$i.pid
        nohup sudo suricata \
            -c /etc/suricata/suricata.yaml \
            -i $iface \
            -l $HOME/logs/suricata-$i \
            -D \
            --set "af-packet.0.cluster-id=$((i + 20))" \
            --pidfile /tmp/suricata-$i.pid \
            > /tmp/suricata-$i.log 2>&1
        log "  ✅ Suricata-$i started"
        sleep 3
    done

    # Generate Vector config for all sources
    cat > $HOME/.vector/vector.toml << VEOF
data_dir = "$HOME/.vector/data"
VEOF

    for i in $(seq 1 $zeek); do
        cat >> $HOME/.vector/vector.toml << VEOF

[sources.zeek_$i]
type = "file"
include = ["$HOME/logs/zeek-$i/conn.log"]
read_from = "end"

[transforms.zeek_json_$i]
type = "remap"
inputs = ["zeek_$i"]
source = '''
parsed, err = parse_json(.message)
if err == null { . = parsed; .source = "zeek" } else { abort }
'''
VEOF
    done

    for i in $(seq 1 $suri); do
        cat >> $HOME/.vector/vector.toml << VEOF

[sources.suricata_$i]
type = "file"
include = ["$HOME/logs/suricata-$i/eve.json"]
read_from = "end"

[transforms.suricata_json_$i]
type = "remap"
inputs = ["suricata_$i"]
source = '''
parsed, err = parse_json(.message)
if err == null { . = parsed; .source = "suricata" } else { abort }
'''
VEOF
    done

    # Build inputs list for Kafka sink
    local inputs=""
    for i in $(seq 1 $zeek); do inputs+="\"zeek_json_$i\","; done
    for i in $(seq 1 $suri); do inputs+="\"suricata_json_$i\","; done
    inputs="${inputs%,}"

    cat >> $HOME/.vector/vector.toml << VEOF

[sinks.kafka]
type = "kafka"
inputs = [$inputs]
bootstrap_servers = "localhost:9092"
topic = "ndr-events"
encoding.codec = "json"
VEOF

    sudo docker restart ndr-vector 2>/dev/null || true
    log "  ✅ Vector configured for $zeek Zeek + $suri Suricata"

    # Save capture config
    cat > $INSTALL_DIR/.capture-config << CEOF
ZEEK_INSTANCES=$zeek
SURI_INSTANCES=$suri
VECTOR_INSTANCES=$vector
IFACE=$iface
COMPUTERS=$computers
CEOF

    log "✅ Capture layer deployed — FIXED (restart required to change)"
}

# ── Deploy transport layer ────────────────────
deploy_transport_layer() {
    local computers=$1
    read zeek suri vector kafka workers api ch ram cpu eps \
        <<< $(calculate_capacity $computers)

    log "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    log "STEP 2: Deploying TRANSPORT LAYER"
    log "  Kafka partitions: $kafka"
    log "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

    sudo docker exec kafka \
        /opt/kafka/bin/kafka-topics.sh \
        --bootstrap-server localhost:9092 \
        --alter --topic ndr-events \
        --partitions $kafka 2>/dev/null || \
    sudo docker exec kafka \
        /opt/kafka/bin/kafka-topics.sh \
        --bootstrap-server localhost:9092 \
        --create --topic ndr-events \
        --partitions $kafka \
        --replication-factor 1 2>/dev/null

    log "  ✅ Kafka: $kafka partitions configured"

    cat > $INSTALL_DIR/.transport-config << TEOF
KAFKA_PARTITIONS=$kafka
TEOF
}

# ── Deploy processing layer ───────────────────
deploy_processing_layer() {
    local computers=$1
    read zeek suri vector kafka workers api ch ram cpu eps \
        <<< $(calculate_capacity $computers)

    log "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    log "STEP 3: Deploying PROCESSING LAYER"
    log "  Workers: $workers (auto-scales)"
    log "  API: 1 (fixed — never scales)"
    log "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

    # Stop existing
    sudo docker ps --filter "name=ndr-engine" \
        --format "{{.Names}}" | \
        xargs -r sudo docker stop 2>/dev/null
    sudo docker ps -a --filter "name=ndr-engine" \
        --format "{{.Names}}" | \
        xargs -r sudo docker rm 2>/dev/null
    sleep 2

    # Start API (single, stable, port 3000)
    sudo docker run -d \
        --name "ndr-engine" \
        --network sf_ndr-stack_default \
        -p "3000:3000" \
        -e KAFKA_BROKERS=kafka:9092 \
        -e NDR_AGENT_URL=http://${HOST_IP}:3001 \
        -e CLICKHOUSE_URL=http://${HOST_IP}:8123 \
        -e CLICKHOUSE_USER=ndr \
        -e CLICKHOUSE_PASSWORD=$CLICKHOUSE_PASSWORD \
        -e INSTANCE_ROLE=api_and_worker \
        -e INSTANCE_ID=1 \
        --privileged \
        sf_ndr-stack-ndr-engine-1 2>/dev/null

    log "  ✅ NDR Engine started (API + Worker combined)"
    log "  ℹ️  Future: split into separate api/worker images"

    cat > $INSTALL_DIR/.processing-config << PEOF
WORKER_INSTANCES=$workers
API_INSTANCES=1
MIN_WORKERS=1
MAX_WORKERS=$((workers * 3))
PEOF
}

# ── Install auto-scaler for workers only ──────
install_worker_autoscaler() {
    local computers=$1
    read zeek suri vector kafka workers api ch ram cpu eps \
        <<< $(calculate_capacity $computers)

    local max_workers=$((workers * 3))

    cat > $INSTALL_DIR/scripts/worker-autoscale.sh << WEOF
#!/bin/bash
# Worker-only auto-scaler
# ONLY scales processing workers — never touches capture or API

INSTALL_DIR="$INSTALL_DIR"
source "\$INSTALL_DIR/.env" 2>/dev/null || true
if [ -z "\$CLICKHOUSE_PASSWORD" ]; then
    echo "ERROR: CLICKHOUSE_PASSWORD not found in \$INSTALL_DIR/.env — refusing to run with a default password." >&2
    exit 1
fi
MIN_WORKERS=$workers
MAX_WORKERS=$max_workers
LOG_FILE="/tmp/ndr-worker-autoscale.log"

log() { echo "[\$(date '+%Y-%m-%d %H:%M:%S')] \$1" | tee -a \$LOG_FILE; }

get_kafka_lag() {
    sudo docker exec kafka \
        /opt/kafka/bin/kafka-consumer-groups.sh \
        --bootstrap-server localhost:9092 \
        --describe --all-groups 2>/dev/null | \
        awk 'NR>1 && \$5~/^[0-9]+$/ {sum+=\$5} END {print sum+0}'
}

get_worker_count() {
    sudo docker ps --filter "name=ndr-worker" \
        --format "{{.Names}}" 2>/dev/null | wc -l
}

scale_worker_up() {
    local current=\$(get_worker_count)
    if [ \$current -ge \$MAX_WORKERS ]; then
        log "⚠️ Max workers (\$MAX_WORKERS) reached"
        return
    fi
    local new=\$((current + 1))
    log "⬆️ Adding worker: \$current → \$new"

    sudo docker run -d \
        --name "ndr-worker-\$new" \
        --network sf_ndr-stack_default \
        -e KAFKA_BROKERS=kafka:9092 \
        -e NDR_AGENT_URL=http://${HOST_IP}:3001 \
        -e CLICKHOUSE_URL=http://${HOST_IP}:8123 \
        -e CLICKHOUSE_USER=ndr \
        -e CLICKHOUSE_PASSWORD=\$CLICKHOUSE_PASSWORD \
        -e INSTANCE_ROLE=worker_only \
        -e INSTANCE_ID=\$new \
        --privileged \
        sf_ndr-stack-ndr-engine-1 2>/dev/null

    log "✅ Worker-\$new started"
}

scale_worker_down() {
    local current=\$(get_worker_count)
    if [ \$current -le \$MIN_WORKERS ]; then
        log "⚠️ Min workers (\$MIN_WORKERS) reached"
        return
    fi
    log "⬇️ Removing worker: \$current → \$((current-1))"
    sudo docker stop "ndr-worker-\$current" 2>/dev/null
    sudo docker rm "ndr-worker-\$current" 2>/dev/null
    log "✅ Worker-\$current removed"
}

log "🚀 Worker auto-scaler started"
log "   Min: \$MIN_WORKERS | Max: \$MAX_WORKERS"

while true; do
    LAG=\$(get_kafka_lag)
    WORKERS=\$(get_worker_count)
    log "📊 Kafka lag: \$LAG | Workers: \$WORKERS"

    if [ "\$LAG" -gt 10000 ]; then
        log "🔴 HIGH LAG — adding worker"
        scale_worker_up
    elif [ "\$LAG" -lt 100 ] && [ "\$WORKERS" -gt \$MIN_WORKERS ]; then
        log "🟢 LOW LAG — removing worker"
        scale_worker_down
    fi

    sleep 30
done
WEOF
    chmod +x $INSTALL_DIR/scripts/worker-autoscale.sh

    # Install as service
    sudo tee /etc/systemd/system/ndr-worker-autoscaler.service > /dev/null << SEOF
[Unit]
Description=NDR Worker Auto-Scaler
After=docker.service

[Service]
Type=simple
User=root
ExecStart=/bin/bash $INSTALL_DIR/scripts/worker-autoscale.sh
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
SEOF

    sudo systemctl daemon-reload
    sudo systemctl enable ndr-worker-autoscaler
    sudo systemctl restart ndr-worker-autoscaler
    log "  ✅ Worker auto-scaler installed and running"
}

# ── Full deploy ───────────────────────────────
deploy_full() {
    local computers=$1
    read zeek suri vector kafka workers api ch ram cpu eps \
        <<< $(calculate_capacity $computers)

    show_plan $computers

    echo ""
    read -p "Proceed with deployment for $computers computers? (y/N): " confirm
    if [ "$confirm" != "y" ] && [ "$confirm" != "Y" ]; then
        echo "Deployment cancelled"
        exit 0
    fi

    log "🚀 Starting full deployment for $computers computers..."

    deploy_capture_layer $computers
    deploy_transport_layer $computers
    deploy_processing_layer $computers
    install_worker_autoscaler $computers

    # Save full deployment record
    cat > $INSTALL_DIR/.deployment << DEOF
COMPUTERS=$computers
PEAK_EPS=$eps
ZEEK_INSTANCES=$zeek
SURI_INSTANCES=$suri
VECTOR_INSTANCES=$vector
KAFKA_PARTITIONS=$kafka
WORKER_INSTANCES=$workers
API_INSTANCES=1
CH_NODES=$ch
DEPLOYED_AT=$(date)
DEOF

    echo ""
    echo "╔═══════════════════════════════════════════════════════╗"
    echo "║              ✅ DEPLOYMENT COMPLETE                    ║"
    echo "╠═══════════════════════════════════════════════════════╣"
    printf "║  Monitoring:    %-38s║\n" "$computers computers"
    printf "║  Peak capacity: %-38s║\n" "$eps events/sec"
    echo "╠═══════════════════════════════════════════════════════╣"
    echo "║  FIXED (never auto-scale):                            ║"
    printf "║  %-20s %-35s║\n" "Zeek:" "$zeek instances"
    printf "║  %-20s %-35s║\n" "Suricata:" "$suri instances"
    printf "║  %-20s %-35s║\n" "Vector:" "$vector instances"
    printf "║  %-20s %-35s║\n" "Kafka partitions:" "$kafka"
    printf "║  %-20s %-35s║\n" "NDR API:" "1 instance (always)"
    echo "╠═══════════════════════════════════════════════════════╣"
    echo "║  AUTO-SCALES (based on Kafka lag):                    ║"
    printf "║  %-20s %-35s║\n" "NDR Workers:" "$workers min → $((workers*3)) max"
    echo "╠═══════════════════════════════════════════════════════╣"
    printf "║  %-20s %-35s║\n" "UI:" "http://localhost:4200"
    printf "║  %-20s %-35s║\n" "API:" "http://localhost:3000"
    echo "╚═══════════════════════════════════════════════════════╝"
}

# ── Status ────────────────────────────────────
show_status() {
    if [ ! -f $INSTALL_DIR/.deployment ]; then
        warn "No deployment found"
        return
    fi
    source $INSTALL_DIR/.deployment

    local zeek_running=$(sudo pgrep -c zeek 2>/dev/null || echo 0)
    local suri_running=$(sudo pgrep -c suricata 2>/dev/null || echo 0)
    local workers_running=$(sudo docker ps \
        --filter "name=ndr-worker" \
        --format "{{.Names}}" | wc -l)
    local lag=$(sudo docker exec kafka \
        /opt/kafka/bin/kafka-consumer-groups.sh \
        --bootstrap-server localhost:9092 \
        --describe --all-groups 2>/dev/null | \
        awk 'NR>1 && $5~/^[0-9]+$/ {sum+=$5} END {print sum+0}' || echo "?")

    echo ""
    echo "╔═══════════════════════════════════════════════════════╗"
    echo "║              NDR DEPLOYMENT STATUS                    ║"
    echo "╠═══════════════════════════════════════════════════════╣"
    printf "║  %-20s %-35s║\n" "Computers:" "$COMPUTERS"
    printf "║  %-20s %-35s║\n" "Deployed:" "$DEPLOYED_AT"
    echo "╠═══════════════════════════════════════════════════════╣"
    echo "║  CAPTURE LAYER (fixed):                               ║"
    printf "║  %-20s %s/%s running\n" "Zeek:" "$zeek_running" "$ZEEK_INSTANCES"
    printf "║  %-20s %s/%s running\n" "Suricata:" "$suri_running" "$SURI_INSTANCES"
    echo "╠═══════════════════════════════════════════════════════╣"
    echo "║  PROCESSING LAYER (auto-scale):                       ║"
    printf "║  %-20s %s workers running\n" "Workers:" "$workers_running"
    printf "║  %-20s %s messages\n" "Kafka lag:" "$lag"
    echo "╠═══════════════════════════════════════════════════════╣"
    echo "║  QUERY LAYER (fixed):                                 ║"
    printf "║  %-20s 1 instance\n" "NDR API:"
    echo "╚═══════════════════════════════════════════════════════╝"
}

# ── Main ──────────────────────────────────────
case "$1" in
    plan)
        [ -z "$2" ] && echo "Usage: $0 plan <computers>" && exit 1
        show_plan $2
        ;;
    deploy)
        [ -z "$2" ] && echo "Usage: $0 deploy <computers>" && exit 1
        deploy_full $2
        ;;
    status)
        show_status
        ;;
    *)
        echo ""
        echo "NDR Capacity Planner"
        echo "===================="
        echo "Usage:"
        echo "  $0 plan   <N>  — Show plan for N computers"
        echo "  $0 deploy <N>  — Deploy for N computers"
        echo "  $0 status      — Show current status"
        echo ""
        echo "Examples:"
        echo "  $0 plan   1000"
        echo "  $0 plan   100000"
        echo "  $0 deploy 500"
        ;;
esac
