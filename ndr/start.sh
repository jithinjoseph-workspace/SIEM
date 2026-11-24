#!/bin/bash
INSTALL_DIR=$(cd "$(dirname "$0")" && pwd)
HOME_DIR=$HOME
RUNTIME_DIR="$INSTALL_DIR/.runtime"
IFACE_FILE="$RUNTIME_DIR/ndr_interface"

log()  { echo -e "\033[0;32m[NDR]\033[0m $1"; }
warn() { echo -e "\033[1;33m[WARN]\033[0m $1"; }

# ── Load .env (contains PRODUCT_MODE set during install) ─────────────
if [ -f "$INSTALL_DIR/.env" ]; then
    source "$INSTALL_DIR/.env"
fi
PRODUCT_MODE="${PRODUCT_MODE:-ndr}"

echo ""
echo "  Starting PromaSecure Stack — product: ${PRODUCT_MODE}"
echo ""

# ── Kernel modules ────────────────────────────
sudo modprobe overlay 2>/dev/null || true
sudo modprobe br_netfilter 2>/dev/null || true

# ── Network interface ─────────────────────────
IFACE=${IFACE:-$(ip -o -4 addr show 2>/dev/null | \
    grep -v "127.0.0.1\|docker\|br-\|veth" | \
    awk '{print $2}' | head -1)}
mkdir -p "$RUNTIME_DIR"
echo "$IFACE" > "$IFACE_FILE"
log "Interface: $IFACE"

# ── NDR-only steps ────────────────────────────
if [ "$PRODUCT_MODE" != "siem" ]; then
    log "Starting NDR Agent..."
    sudo systemctl start ndr-agent 2>/dev/null || \
        nohup python3 "$INSTALL_DIR/scripts/ndr-agent.py" > /tmp/ndr-agent.log 2>&1 &
    sleep 2

    log "Resetting Vector checkpoints..."
    sudo rm -rf "$HOME_DIR/.vector/data/suricata" \
                "$HOME_DIR/.vector/data/zeek" 2>/dev/null || true
    mkdir -p "$HOME_DIR/.vector/data/suricata" \
             "$HOME_DIR/.vector/data/zeek"
    log "Vector checkpoints cleared"
fi

# nginx: config/nginx/nginx.conf is the only nginx config and is used as-is.
# Nothing here copies another file over it (the old per-mode nginx-*.conf copies
# silently reverted fixes made to nginx.conf).

# ── Docker stack ──────────────────────────────
log "Starting Docker stack..."
cd "$INSTALL_DIR"
sudo docker rm -f vector 2>/dev/null || true

if [ "$PRODUCT_MODE" = "siem" ]; then
    sudo docker compose --profile siem up -d \
        clickhouse-keeper clickhouse1 clickhouse2 clickhouse-init \
        ndr-valkey \
        kafka1 kafka2 kafka3 kafka-init \
        provigil-auth siem-engine-1 ndr-ui nginx

elif [ "$PRODUCT_MODE" = "both" ]; then
    sudo docker compose --profile siem --profile onpremise up -d

else
    # NDR only
    sudo docker compose --profile onpremise up -d
fi

log "Docker stack started"

# ── Kafka topic check ─────────────────────────
log "Waiting for Kafka..."
for i in {1..30}; do
    if sudo docker exec kafka1 /opt/kafka/bin/kafka-broker-api-versions.sh \
        --bootstrap-server localhost:9092 > /dev/null 2>&1; then
        log "Kafka ready"
        break
    fi
    echo -n "."
    sleep 3
done
echo ""

if [ "$PRODUCT_MODE" != "siem" ]; then
    sudo docker exec kafka1 \
        /opt/kafka/bin/kafka-configs.sh \
        --bootstrap-server localhost:9092 \
        --alter --entity-type topics \
        --entity-name ndr-events \
        --add-config retention.ms=3600000 \
        2>/dev/null || true

    sudo docker exec kafka1 \
        /opt/kafka/bin/kafka-topics.sh \
        --bootstrap-server localhost:9092 \
        --create --if-not-exists \
        --topic ndr-events \
        --partitions 3 \
        --replication-factor 3 \
        2>/dev/null || true
    log "NDR Kafka topic ready"
fi

if [ "$PRODUCT_MODE" != "ndr" ]; then
    sudo docker exec kafka1 \
        /opt/kafka/bin/kafka-topics.sh \
        --bootstrap-server localhost:9092 \
        --create --if-not-exists \
        --topic siem-logs \
        --partitions 9 \
        --replication-factor 3 \
        2>/dev/null || true
    log "SIEM Kafka topic ready"
fi

# ── OpenSearch + Arkime (NDR only) ────────────
if [ "$PRODUCT_MODE" != "siem" ]; then
    log "Waiting for OpenSearch..."
    OS_READY=false
    for i in {1..40}; do
        if curl -sf http://localhost:9200/_cluster/health > /dev/null 2>&1; then
            OS_READY=true
            log "OpenSearch ready"
            break
        fi
        echo -n "."
        sleep 3
    done
    echo ""

    if [ "$OS_READY" = true ]; then
        log "Starting Arkime viewer..."
        sudo systemctl restart arkimeviewer 2>/dev/null || true
        sleep 2
        systemctl is-active --quiet arkimeviewer 2>/dev/null \
            && log "Arkime viewer running" \
            || warn "Arkime viewer failed — check: journalctl -u arkimeviewer -n 20"
    else
        warn "OpenSearch not ready — skipping Arkime viewer"
    fi
fi

# ── Wait for UI ───────────────────────────────
log "Waiting for ndr-ui container..."
for i in {1..30}; do
    if sudo docker exec ndr-ui curl -s http://localhost:80 > /dev/null 2>&1; then
        log "ndr-ui ready"
        break
    fi
    echo -n "."
    sleep 3
done
echo ""

# ── Status summary ────────────────────────────
echo ""
echo "  Status:"
echo "    ClickHouse : $(curl -s http://localhost:8123/ping 2>/dev/null || echo 'starting...')"
echo "    Docker     : $(sudo docker ps --format '{{.Names}}' | tr '\n' ' ')"
if [ "$PRODUCT_MODE" != "siem" ]; then
echo "    NDR Agent  : $(curl -s http://localhost:3001/agent/status 2>/dev/null || echo 'not running')"
echo "    Arkime     : $(systemctl is-active arkimeviewer 2>/dev/null || echo 'stopped')"
fi
if [ "$PRODUCT_MODE" != "ndr" ]; then
echo "    SIEM API   : $(curl -s http://localhost:3002/api/health 2>/dev/null || echo 'starting...')"
fi

echo ""
echo "  Access:"
echo "    Dashboard  : https://$(hostname -I | awk '{print $1}'):3000"
if [ "$PRODUCT_MODE" != "siem" ]; then
echo "    Packet Rec : http://localhost:8005"
fi
if [ "$PRODUCT_MODE" != "ndr" ]; then
echo "    SIEM API   : http://$(hostname -I | awk '{print $1}'):3002/api/health"
echo "    Syslog     : $(hostname -I | awk '{print $1}'):601 (TCP)"
fi
echo ""
echo "  Powered by PromaSecure"
echo ""
