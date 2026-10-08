#!/bin/bash
# NDR Host Agent — listens on port 3001 for commands from ndr-engine
# Runs on WSL host, controls Zeek and Suricata

AGENT_PORT=3001
LOGDIR=/home/jithin/logs
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
INSTALL_DIR=$(cd "$SCRIPT_DIR/.." && pwd)
RUNTIME_DIR="$INSTALL_DIR/.runtime"
IFACE_FILE="$RUNTIME_DIR/ndr_interface"

mkdir -p "$RUNTIME_DIR"

handle_request() {
    local request="$1"
    # Basic path extraction from HTTP request line
    local path=$(echo "$request" | grep -oP '(?<=GET |POST )[^ ]+')
    # Body usually follows a blank line. This is a very simple parser.
    local body=$(echo "$request" | tail -1)

    case "$path" in
        "/agent/start")
            IFACE=$(cat "$IFACE_FILE" 2>/dev/null || echo "eth0")
            pkill suricata 2>/dev/null; pkill zeek 2>/dev/null
            sleep 1
            nohup suricata -c /etc/suricata/suricata.yaml \
                -i $IFACE -l $LOGDIR/suricata > /tmp/suricata.log 2>&1 &
            nohup /opt/zeek/bin/zeek -i $IFACE local \
                Log::default_logdir=$LOGDIR/zeek > /tmp/zeek.log 2>&1 &
            echo -e "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"status\":\"started\",\"interface\":\"$IFACE\"}"
            ;;
        "/agent/stop")
            pkill suricata 2>/dev/null
            pkill zeek 2>/dev/null
            echo -e "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"status\":\"stopped\"}"
            ;;
        "/agent/status")
            ZEEK_PID=$(pgrep zeek || echo "")
            SURI_PID=$(pgrep suricata || echo "")
            IFACE=$(cat "$IFACE_FILE" 2>/dev/null || echo "eth0")
            echo -e "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"zeek\":\"${ZEEK_PID:-stopped}\",\"suricata\":\"${SURI_PID:-stopped}\",\"interface\":\"$IFACE\"}"
            ;;
        "/agent/interface")
            # Extract interface from JSON body like {"interface":"eth0"}
            IFACE=$(echo "$body" | grep -oP '(?<="interface":")[^"]+')
            echo "$IFACE" > "$IFACE_FILE"
            echo -e "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"status\":\"ok\",\"interface\":\"$IFACE\"}"
            ;;
        "/agent/interfaces")
            # Return real host interfaces
            IFACES=$(ip -o link | awk -F': ' '{print $2}' | grep -v lo | jq -R . | jq -s .)
            echo -e "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n$IFACES"
            ;;
        *)
            echo -e "HTTP/1.1 404 Not Found\r\n\r\n{\"error\":\"not found\"}"
            ;;
    esac
}

echo "🚀 NDR Host Agent listening on port $AGENT_PORT"
while true; do
    # Use netcat-traditional (-q 1 to quit after EOF)
    request=$(nc -l -p $AGENT_PORT -q 1)
    handle_request "$request"
done
