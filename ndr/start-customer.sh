#!/bin/bash
set -euo pipefail

INSTALL_DIR=$(cd "$(dirname "$0")" && pwd)
RUNTIME_DIR="$INSTALL_DIR/.runtime"

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
log()  { echo -e "${GREEN}[NDR]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
err()  { echo -e "${RED}[ERR]${NC} $1"; }

echo "🚀 Starting NDR Customer Stack..."

# ── Load .env ────────────────────────────────────────────────────
if [ -f "$INSTALL_DIR/.env" ]; then
    source "$INSTALL_DIR/.env"
fi

# ── Detect host IP ───────────────────────────────────────────────
HOST_IP=${HOST_IP:-$(ip -o -4 addr show 2>/dev/null \
    | grep -v "127.0.0.1\|docker\|br-\|veth" \
    | awk '{print $4}' | cut -d/ -f1 | head -1)}

# ── Kernel modules ───────────────────────────────────────────────
sudo modprobe overlay      2>/dev/null || true
sudo modprobe br_netfilter 2>/dev/null || true

# ── Runtime dir ─────────────────────────────────────────────────
mkdir -p "$RUNTIME_DIR"
IFACE=${IFACE:-$(ip -o -4 addr show 2>/dev/null \
    | grep -v "127.0.0.1\|docker\|br-\|veth" \
    | awk '{print $2}' | head -1)}
echo "$IFACE" > "$RUNTIME_DIR/ndr_interface"
log "Interface: $IFACE ($HOST_IP)"

# ── NDR Agent ────────────────────────────────────────────────────
log "Starting NDR Agent..."
sudo systemctl start ndr-agent 2>/dev/null || \
    nohup python3 "$INSTALL_DIR/scripts/ndr-agent.py" > /tmp/ndr-agent.log 2>&1 &
sleep 2

# ── Docker stack ─────────────────────────────────────────────────
log "Starting Docker stack (with onpremise profile)..."
cd "$INSTALL_DIR"
sudo docker compose --profile onpremise up -d

# ── Wait for OpenSearch ──────────────────────────────────────────
log "Waiting for OpenSearch..."
OS_READY=false
for i in {1..40}; do
    if curl -sf http://localhost:9200/_cluster/health > /dev/null 2>&1; then
        OS_READY=true
        log "✅ OpenSearch ready"
        break
    fi
    echo -n "."
    sleep 3
done
echo ""

# ── Arkime viewer ────────────────────────────────────────────────
if $OS_READY; then
    log "Starting Arkime viewer..."
    sudo systemctl restart arkimeviewer 2>/dev/null || true
    sleep 2
    if systemctl is-active --quiet arkimeviewer 2>/dev/null; then
        log "✅ Arkime viewer running"
    else
        warn "Arkime viewer failed — check: journalctl -u arkimeviewer -n 20"
    fi
else
    warn "OpenSearch not ready — skipping Arkime viewer"
fi

# ── Wait for Kafka ───────────────────────────────────────────────
log "Waiting for Kafka..."
for i in {1..30}; do
    if sudo docker exec kafka1 /opt/kafka/bin/kafka-broker-api-versions.sh \
        --bootstrap-server localhost:9092 > /dev/null 2>&1; then
        log "✅ Kafka ready"
        break
    fi
    sleep 3
done

# ── Wait for ndr-ui ──────────────────────────────────────────────
log "Waiting for NDR UI container..."
for i in {1..30}; do
    if sudo docker exec ndr-ui curl -s http://localhost:80 > /dev/null 2>&1; then
        log "✅ NDR UI ready"
        break
    fi
    echo -n "."
    sleep 3
done
echo ""

# ── Summary ──────────────────────────────────────────────────────
echo ""
echo "📊 Status:"
echo "  ClickHouse:  $(curl -s http://localhost:8123/ping 2>/dev/null || echo 'starting...')"
echo "  OpenSearch:  $(curl -sf http://localhost:9200 2>/dev/null | python3 -c 'import sys,json; d=json.load(sys.stdin); print(d.get("tagline","ok"))' 2>/dev/null || echo 'starting...')"
echo "  Docker:      $(sudo docker ps --format '{{.Names}}' | tr '\n' ' ')"
echo "  Agent:       $(curl -s http://localhost:3001/agent/status 2>/dev/null || echo 'not running')"
echo "  Arkime:      $(systemctl is-active arkimeviewer 2>/dev/null || echo 'stopped')"

echo ""
echo -e "${GREEN}✅ NDR Customer Stack started${NC}"
echo "   Dashboard:  https://$HOST_IP:3000"
echo "   API:        https://$HOST_IP:3000/api"
echo "   Agent:      http://$HOST_IP:3001"
echo "   Arkime:     http://$HOST_IP:8005"
