#!/bin/bash
INSTALL_DIR=$(cd "$(dirname "$0")/.." && pwd)
LOG_FILE="/tmp/ndr-autoscale.log"
MAX_ENGINES=5
MIN_ENGINES=1

if [ -f "$INSTALL_DIR/.env" ]; then
    CLICKHOUSE_PASSWORD=$(grep "^CLICKHOUSE_PASSWORD=" "$INSTALL_DIR/.env" | cut -d= -f2-)
fi
if [ -z "$CLICKHOUSE_PASSWORD" ]; then
    echo "ERROR: CLICKHOUSE_PASSWORD not found in $INSTALL_DIR/.env — refusing to run with a default password." >&2
    exit 1
fi

log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a $LOG_FILE; }

get_events_per_sec() {
    curl -s "http://localhost:3000/api/stats" 2>/dev/null | \
        python3 -c "
import sys, json
d = json.load(sys.stdin)
print(d.get('events_1h', 0) // 3600)
" 2>/dev/null || echo "0"
}

get_engine_count() {
    sudo docker ps --filter "name=ndr-engine" --format "{{.Names}}" | wc -l
}

update_nginx() {
    local count=$(get_engine_count)
    log "🔄 Updating Nginx config for $count engines..."

    # Build upstream block
    local upstream="upstream ndr_engines {\n    least_conn;\n"
    for i in $(seq 1 $count); do
        upstream+="    server ndr-engine-$i:3000;\n"
    done
    upstream+="}"

    # Write new nginx config
    cat > /tmp/nginx_new.conf << NGINXEOF
events { worker_connections 4096; }

http {
    $(echo -e "$upstream")

    server {
        listen 80;

        location /ws {
            proxy_pass         http://ndr_engines;
            proxy_http_version 1.1;
            proxy_set_header   Upgrade \$http_upgrade;
            proxy_set_header   Connection "upgrade";
            proxy_set_header   Host \$host;
            proxy_read_timeout 3600s;
        }

        location / {
            proxy_pass       http://ndr_engines;
            proxy_set_header Host \$host;
            proxy_set_header X-Real-IP \$remote_addr;
        }
    }
}
NGINXEOF

    sudo cp /tmp/nginx_new.conf $INSTALL_DIR/config/nginx/nginx.conf
    sudo docker exec ndr-nginx nginx -s reload 2>/dev/null
    log "✅ Nginx reloaded with $count engines"
}

scale_up() {
    local current=$(get_engine_count)
    if [ $current -ge $MAX_ENGINES ]; then
        log "⚠️ Already at max engines ($MAX_ENGINES)"
        return
    fi
    local new=$((current + 1))
    log "⬆️ Scaling UP: $current → $new engines"

    sudo docker run -d \
        --name "ndr-engine-$new" \
        --network sf_ndr-stack_default \
        -e KAFKA_BROKERS=kafka:9092 \
        -e NDR_AGENT_URL=http://${HOST_IP}:3001 \
        -e CLICKHOUSE_URL=http://${HOST_IP}:8123 \
        -e CLICKHOUSE_USER=ndr \
        -e CLICKHOUSE_PASSWORD=$CLICKHOUSE_PASSWORD \
        -e INSTANCE_ID=$new \
        --privileged \
        sf_ndr-stack-ndr-engine-1 2>/dev/null

    sleep 5
    update_nginx
    log "✅ Engine $new started"
}

scale_down() {
    local current=$(get_engine_count)
    if [ $current -le $MIN_ENGINES ]; then
        log "⚠️ Already at min engines ($MIN_ENGINES)"
        return
    fi
    log "⬇️ Scaling DOWN: $current → $((current-1)) engines"
    sudo docker stop "ndr-engine-$current" 2>/dev/null
    sudo docker rm "ndr-engine-$current" 2>/dev/null
    update_nginx
    log "✅ Engine $current removed"
}

log "🚀 NDR Auto-Scaler started"
log "   Min engines: $MIN_ENGINES | Max engines: $MAX_ENGINES"

while true; do
    EVENTS=$(get_events_per_sec)
    ENGINES=$(get_engine_count)
    CPU=$(top -bn1 | grep "Cpu(s)" | awk '{print $2}' | cut -d. -f1)

    log "📊 Events/sec: $EVENTS | Engines: $ENGINES | CPU: $CPU%"

    # Scale UP
    if [ "$EVENTS" -gt 5000 ] || [ "$CPU" -gt 80 ]; then
        log "⚠️ HIGH LOAD detected"
        scale_up
    fi

    # Scale DOWN
    if [ "$EVENTS" -lt 500 ] && [ "$CPU" -lt 20 ] && [ "$ENGINES" -gt 1 ]; then
        log "📉 LOW LOAD detected"
        scale_down
    fi

    sleep 30
done
