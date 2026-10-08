#!/bin/bash
INSTALL_DIR=$(cd "$(dirname "$0")" && pwd)

if [ -f "$INSTALL_DIR/.env" ]; then
    source "$INSTALL_DIR/.env"
fi
PRODUCT_MODE="${PRODUCT_MODE:-ndr}"

echo ""
echo "  Stopping PromaSecure Stack — product: ${PRODUCT_MODE}"
echo ""

# ── NDR-only: stop sensors + agent ───────────
if [ "$PRODUCT_MODE" != "siem" ]; then
    echo "  → Stopping Agent-Z and Agent-S..."
    curl -s -X POST http://localhost:3001/agent/stop > /dev/null 2>&1 || true
    sleep 2

    echo "  → Stopping NDR Agent..."
    sudo systemctl stop ndr-agent 2>/dev/null || true
    pkill -f ndr-agent.py 2>/dev/null || true
fi

# ── Stop dynamic engine containers ───────────
DYNAMIC_ENGINES=$(sudo docker ps -a \
    --filter "name=ndr-engine-" \
    --format "{{.Names}}" \
    | grep -v -E "ndr-engine-[123]$" || true)
if [ -n "$DYNAMIC_ENGINES" ]; then
    echo "  → Stopping dynamic engines: $DYNAMIC_ENGINES"
    echo "$DYNAMIC_ENGINES" | xargs sudo docker rm -f 2>/dev/null || true
fi

# ── Stop Docker stack ─────────────────────────
echo "  → Stopping Docker stack..."
cd "$INSTALL_DIR"

if [ "$PRODUCT_MODE" = "siem" ]; then
    sudo docker compose --profile siem down

elif [ "$PRODUCT_MODE" = "both" ]; then
    sudo docker compose --profile siem --profile onpremise down

else
    sudo docker compose --profile onpremise down
fi

# ── Kill any leftover sensor processes ────────
if [ "$PRODUCT_MODE" != "siem" ]; then
    sudo pkill -f suricata 2>/dev/null || true
    sudo pkill -f zeek     2>/dev/null || true
fi

# ── Verify ────────────────────────────────────
echo ""
echo "  Verification:"
echo "    Docker : $(sudo docker ps --format '{{.Names}}' | tr '\n' ' ' || echo 'none running')"
if [ "$PRODUCT_MODE" != "siem" ]; then
echo "    Sensors: $(ps aux | grep -E 'zeek|suricata' | grep -v grep | wc -l) processes"
fi
echo ""
echo "  Powered by PromaSecure — stack stopped"
echo ""
