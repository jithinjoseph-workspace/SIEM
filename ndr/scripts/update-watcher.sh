#!/bin/bash
# Host-side watcher: picks up .update-requested flag written by the engine container
# and pulls new Docker images then restarts the engine containers.
FLAG="/home/user/Music/NDR/NDR-Demo/scripts/.update-requested"
INSTALL_DIR_="/home/user/Music/NDR/NDR-Demo"

logger -t ndr-updater "NDR update watcher started — watching $FLAG"

while true; do
    if [ -f "$FLAG" ]; then
        TARGET=$(cat "$FLAG" 2>/dev/null | tr -d '[:space:]')
        logger -t ndr-updater "Update flag detected — target: ${TARGET:-latest}"
        rm -f "$FLAG"
        cd "$INSTALL_DIR_"
        docker pull ghcr.io/jithinjoseph-workspace/ndr-engine:latest 2>&1 | logger -t ndr-updater || true
        docker pull ghcr.io/jithinjoseph-workspace/ndr-ui:latest     2>&1 | logger -t ndr-updater || true
        docker compose up -d --no-deps ndr-engine-1 ndr-engine-2 ndr-engine-3 ndr-ui 2>&1 | logger -t ndr-updater || true
        logger -t ndr-updater "Update complete"
    fi
    sleep 30
done
