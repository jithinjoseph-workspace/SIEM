#!/bin/bash
INSTALL_DIR=$(cd "$(dirname "$0")" && pwd)

if [ -f "$INSTALL_DIR/.env" ]; then
    source "$INSTALL_DIR/.env"
fi
PRODUCT_MODE="${PRODUCT_MODE:-ndr}"
HOST_IP=$(hostname -I | awk '{print $1}')

echo ""
echo "  PromaSecure Stack Status — product: ${PRODUCT_MODE}"
echo "  ──────────────────────────────────────────────────"
echo ""

# ── Docker containers ─────────────────────────
echo "  Docker containers:"
sudo docker ps --format "    {{.Names}}\t{{.Status}}" 2>/dev/null || echo "    Docker not running"
echo ""

# ── ClickHouse ────────────────────────────────
echo "  ClickHouse:"
CH_PING=$(curl -s --max-time 3 http://localhost:8123/ping 2>/dev/null || echo "not responding")
echo "    node1 : $CH_PING"
echo ""

# ── Kafka ─────────────────────────────────────
echo "  Kafka topics:"
sudo docker exec kafka1 /opt/kafka/bin/kafka-topics.sh \
    --bootstrap-server localhost:9092 --list 2>/dev/null \
    | sed 's/^/    /' || echo "    Kafka not ready"
echo ""

# ── Valkey/Redis ──────────────────────────────
echo "  Valkey:"
VALKEY_PING=$(sudo docker exec ndr-valkey valkey-cli ping 2>/dev/null || echo "not responding")
echo "    ping  : $VALKEY_PING"
echo ""

# ── Auth service ──────────────────────────────
echo "  Auth (provigil-auth):"
AUTH=$(curl -s --max-time 3 "http://localhost:3001/api/auth/check-username?username=ping" 2>/dev/null || echo "not responding")
echo "    health: $AUTH"
echo ""

# ── NDR-only checks ───────────────────────────
if [ "$PRODUCT_MODE" != "siem" ]; then
    echo "  NDR Engine:"
    NDR=$(curl -sk --max-time 3 "https://localhost:3000/api/health" 2>/dev/null || echo "not responding")
    echo "    health: $NDR"
    echo ""

    echo "  NDR Agent:"
    AGENT=$(curl -s --max-time 3 http://localhost:3001/agent/status 2>/dev/null || echo "not running")
    echo "    status: $AGENT"
    echo ""

    echo "  Arkime viewer  : $(systemctl is-active arkimeviewer 2>/dev/null || echo 'stopped')"
    echo "  Agent-Z (Zeek) : $(pgrep -x zeek > /dev/null 2>&1 && echo 'running' || echo 'stopped')"
    echo "  Agent-S (Suri) : $(pgrep -x suricata > /dev/null 2>&1 && echo 'running' || echo 'stopped')"
    echo ""
fi

# ── SIEM-only checks ──────────────────────────
if [ "$PRODUCT_MODE" != "ndr" ]; then
    echo "  SIEM Engine:"
    SIEM=$(curl -s --max-time 3 "http://localhost:3002/api/health" 2>/dev/null || echo "not responding")
    echo "    health: $SIEM"
    echo ""

    echo "  SIEM consumer group (siem-logs):"
    sudo docker exec kafka1 /opt/kafka/bin/kafka-consumer-groups.sh \
        --bootstrap-server localhost:9092 \
        --group siem-engine-consumers \
        --describe 2>/dev/null | sed 's/^/    /' || echo "    not available"
    echo ""
fi

# ── Access points ─────────────────────────────
echo "  Access:"
echo "    Dashboard  : https://${HOST_IP}:3000"
if [ "$PRODUCT_MODE" != "siem" ]; then
echo "    NDR API    : https://${HOST_IP}:3000/api/health"
echo "    Packet Rec : http://${HOST_IP}:8005"
fi
if [ "$PRODUCT_MODE" != "ndr" ]; then
echo "    SIEM API   : http://${HOST_IP}:3002/api/health"
echo "    Syslog TCP : ${HOST_IP}:601"
fi
echo ""
echo "  Powered by PromaSecure"
echo ""
