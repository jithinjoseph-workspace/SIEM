#!/bin/bash
# NDR Sensor Uninstall / Cleanup Script
# Usage:
#   sudo bash uninstall-sensor.sh
#   sudo bash uninstall-sensor.sh --purge-packages   # also removes zeek/suricata/vector/arkime binaries

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

log()   { echo -e "${GREEN}[NDR-UNINSTALL]${NC} $1"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }
info()  { echo -e "${BLUE}[INFO]${NC} $1"; }
dry()   { echo -e "${CYAN}[DRY-RUN]${NC} Would: $1"; }

# ── Banner ────────────────────────────────────────────
echo ""
echo "╔══════════════════════════════════════════╗"
echo "║     NDR Sensor — Uninstall / Cleanup     ║"
echo "╚══════════════════════════════════════════╝"
echo ""

# ── Parse arguments ───────────────────────────────────
TENANT_ID=""
PURGE_PACKAGES=false
DRY_RUN=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --tenant-id)      TENANT_ID="$2"; shift 2 ;;
        --purge-packages) PURGE_PACKAGES=true; shift ;;
        --dry-run)        DRY_RUN=true; shift ;;
        *)                warn "Unknown option: $1"; shift ;;
    esac
done

# ── Root check ────────────────────────────────────────
if [ "$EUID" -ne 0 ]; then
    error "Please run as root: sudo $0"
fi

# Helper that either runs or dry-prints a command
run() {
    if $DRY_RUN; then
        dry "$*"
    else
        eval "$@" 2>/dev/null || true
    fi
}

# ── Resolve tenant list ───────────────────────────────
TENANTS=()
if [ -n "$TENANT_ID" ]; then
    TENANTS=("$TENANT_ID")
    info "Targeting single tenant: $TENANT_ID"
else
    # Discover all installed tenant IDs from /var/log/ndr-sensor/<tenant>
    if [ -d /var/log/ndr-sensor ]; then
        mapfile -t TENANTS < <(find /var/log/ndr-sensor -mindepth 1 -maxdepth 1 -type d -printf '%f\n' 2>/dev/null || true)
    fi
    # Also check /etc/ndr/sensor.conf for the currently configured tenant
    if [ -f /etc/ndr/sensor.conf ]; then
        CONF_TENANT=$(grep '^TENANT_ID=' /etc/ndr/sensor.conf | cut -d= -f2 | tr -d '[:space:]')
        if [ -n "$CONF_TENANT" ]; then
            # Add if not already in list
            if [[ ! " ${TENANTS[*]:-} " =~ " ${CONF_TENANT} " ]]; then
                TENANTS+=("$CONF_TENANT")
            fi
        fi
    fi
    if [ ${#TENANTS[@]} -eq 0 ]; then
        warn "No tenant data directories found in /var/log/ndr-sensor/ and no config at /etc/ndr/sensor.conf"
        TENANTS=()
    else
        info "Discovered tenants: ${TENANTS[*]}"
    fi
fi

echo ""

# ══════════════════════════════════════════════════════
# STEP 0 — Notify NDR cloud: sensor uninstalled
# ══════════════════════════════════════════════════════
log "Step 0: Reporting uninstall status to NDR cloud..."

NDR_CLOUD_URL=""
NDR_API_KEY=""
if [ -f /etc/ndr/sensor.conf ]; then
    NDR_CLOUD_URL=$(grep '^CLOUD_URL=' /etc/ndr/sensor.conf | cut -d= -f2 | tr -d '[:space:]')
    NDR_API_KEY=$(grep '^API_KEY=' /etc/ndr/sensor.conf | cut -d= -f2 | tr -d '[:space:]')
fi

if [ -n "$NDR_CLOUD_URL" ] && [ -n "$NDR_API_KEY" ]; then
    if ! $DRY_RUN; then
        curl -sf -X POST "${NDR_CLOUD_URL}/api/sensor/checkin" \
            -H "Content-Type: application/json" \
            -H "X-Sensor-Key: ${NDR_API_KEY}" \
            -d '{"zeek":"uninstalled","suricata":"uninstalled","vector":"uninstalled"}' \
            --max-time 5 \
            --retry 2 > /dev/null 2>&1 && \
            log "  ✅ Uninstall status reported to cloud" || \
            warn "  Could not reach NDR cloud — status will show offline after timeout"
    else
        dry "POST ${NDR_CLOUD_URL}/api/sensor/checkin {zeek:uninstalled,...}"
    fi
else
    warn "  No cloud config found — skipping status report"
fi

echo ""

# ══════════════════════════════════════════════════════
# STEP 1 — Stop & disable current services (ndr-sensor-*)
# ══════════════════════════════════════════════════════
log "Step 1: Stopping all NDR sensor services..."

# Stop and disable every service unconditionally, and do it BEFORE killing any
# process. The old version only stopped a service if `systemctl list-unit-files
# | grep -q` found it; when that check missed (it can, under `pipefail`), the
# later `pkill -9 agent.py` was followed by systemd restarting the agent
# (Restart=always), and the unit file was then deleted while it ran, leaving
# a running "not-found" service that nothing stopped.
for SVC in ndr-agent ndr-vector ndr-sensor-agent ndr-sensor-vector arkime-capture arkime-viewer; do
    WAS_ACTIVE=false
    systemctl is-active --quiet "$SVC" 2>/dev/null && WAS_ACTIVE=true
    run "systemctl stop $SVC"
    run "systemctl disable $SVC"
    run "systemctl reset-failed $SVC"
    if $WAS_ACTIVE; then
        log "  ✅ Stopped & disabled: $SVC"
    else
        info "  $SVC was not running"
    fi
done

log "  Killing remaining processes..."
run "pkill -9 -f agent.py"
run "pkill -9 -f suricata"
run "pkill -9 -f zeek"
run "pkill -9 -f pcap-uploader"
run "pkill -9 -f arkime-capture"
run "pkill -9 -f 'vector --config'"
run "pkill -9 -f '/usr/local/bin/vector'"
run "pkill -9 -f '/usr/bin/vector'"
run "killall -9 vector"
run "sleep 2"
if pgrep -f vector > /dev/null 2>&1; then
    warn "  Vector still alive — hard killing..."
    kill -9 $(pgrep -f vector 2>/dev/null) 2>/dev/null || true
fi
pgrep -f vector > /dev/null 2>&1 \
    && warn "  ⚠️  Vector could not be killed" \
    || log "  ✅ Vector dead"

log "  Removing OpenSearch container..."
run "docker stop opensearch-arkime"
run "docker rm   opensearch-arkime"

# ══════════════════════════════════════════════════════
# STEP 2 — Stop & disable LEGACY service (ndr-agent)
#          This is the old broken install that overwrote ndr-agent.service
# ══════════════════════════════════════════════════════
log "Step 2: Checking for legacy ndr-agent service..."

run "systemctl stop ndr-agent"
run "systemctl disable ndr-agent"
if [ -f /etc/systemd/system/ndr-agent.service ]; then
    warn "  Found ndr-agent.service unit file"
fi
run "rm -f /etc/systemd/system/ndr-agent.service"
log "  ✅ ndr-agent service stopped and its unit file removed"

# ══════════════════════════════════════════════════════
# STEP 3 — Kill Zeek and Suricata processes owned by sensor
#          Uses PID files — does NOT blindly pkill
# ══════════════════════════════════════════════════════
log "Step 3: Stopping Zeek and Suricata (sensor-owned only)..."

stop_pid_safe() {
    local PID_FILE="$1"
    local LABEL="$2"
    if [ -f "$PID_FILE" ]; then
        PID_VAL=$(cat "$PID_FILE" 2>/dev/null || echo "")
        if [ -n "$PID_VAL" ] && kill -0 "$PID_VAL" 2>/dev/null; then
            info "  Stopping $LABEL (PID $PID_VAL)..."
            run "kill $PID_VAL"
            sleep 2
            if kill -0 "$PID_VAL" 2>/dev/null; then
                run "kill -9 $PID_VAL"
            fi
            log "  ✅ $LABEL stopped"
        else
            info "  $LABEL PID $PID_VAL not running"
        fi
        run "rm -f $PID_FILE"
    else
        info "  No PID file for $LABEL at $PID_FILE"
    fi
}

stop_pid_safe "/run/ndr-sensor/zeek.pid"     "Zeek"
stop_pid_safe "/run/ndr-sensor/suricata.pid" "Suricata"

# Also check legacy PID paths used before the fix
stop_pid_safe "/tmp/suricata.pid"  "Suricata (legacy /tmp)"
stop_pid_safe "/var/run/suricata/suricata.pid" "Suricata (legacy /var/run)"

run "rm -rf /run/ndr-sensor"

# ══════════════════════════════════════════════════════
# STEP 4 — Remove systemd unit files
# ══════════════════════════════════════════════════════
log "Step 4: Removing systemd unit files..."

for UNIT_FILE in \
    /etc/systemd/system/ndr-agent.service \
    /etc/systemd/system/ndr-vector.service \
    /etc/systemd/system/ndr-sensor-agent.service \
    /etc/systemd/system/ndr-sensor-vector.service \
    /etc/systemd/system/arkime-capture.service \
    /etc/systemd/system/arkime-viewer.service; do
    if [ -f "$UNIT_FILE" ]; then
        run "rm -f $UNIT_FILE"
        log "  ✅ Removed: $UNIT_FILE"
    fi
done

# leftover enable-links for removed units (a dangling link keeps the name around)
for LINK in /etc/systemd/system/multi-user.target.wants/{ndr-agent,ndr-vector,ndr-sensor-agent,ndr-sensor-vector,arkime-capture,arkime-viewer}.service; do
    [ -L "$LINK" ] && run "rm -f $LINK"
done

run "systemctl daemon-reload"
run "systemctl reset-failed 2>/dev/null"

# ══════════════════════════════════════════════════════
# STEP 5 — Remove sensor agent files
# ══════════════════════════════════════════════════════
log "Step 5: Removing sensor agent files..."

run "rm -rf /opt/ndr-sensor"
log "  ✅ Removed /opt/ndr-sensor"

run "rm -rf /opt/arkime/raw"
run "rm -rf /opt/arkime/logs"
run "rm -f  /opt/arkime/etc/config.ini"
log "  ✅ Removed Arkime data"

run "rm -f /etc/ndr/vector.toml"
run "rm -f /etc/ndr/sensor.conf"
log "  ✅ Removed sensor config from /etc/ndr/"

# Remove /etc/ndr if empty
if $DRY_RUN; then
    dry "rmdir /etc/ndr (if empty)"
else
    rmdir /etc/ndr 2>/dev/null && log "  ✅ Removed empty /etc/ndr" || info "  /etc/ndr not empty — kept"
fi

# ══════════════════════════════════════════════════════
# STEP 6 — Remove per-tenant logs and vector state
# ══════════════════════════════════════════════════════
log "Step 6: Removing per-tenant log and data directories..."

if [ ${#TENANTS[@]} -gt 0 ]; then
    for TID in "${TENANTS[@]}"; do
        LOG_DIR="/var/log/ndr-sensor/${TID}"
        VEC_DIR="/etc/ndr-sensor/vector-data/${TID}"

        if [ -d "$LOG_DIR" ]; then
            run "rm -rf $LOG_DIR"
            log "  ✅ Removed logs: $LOG_DIR"
        fi
        if [ -d "$VEC_DIR" ]; then
            run "rm -rf $VEC_DIR"
            log "  ✅ Removed vector state: $VEC_DIR"
        fi
    done
else
    # No specific tenants — remove entire tree
    if [ -d /var/log/ndr-sensor ]; then
        run "rm -rf /var/log/ndr-sensor"
        log "  ✅ Removed /var/log/ndr-sensor"
    fi
fi

# Remove parent dirs if empty
if $DRY_RUN; then
    dry "rmdir /var/log/ndr-sensor /etc/ndr-sensor/vector-data /etc/ndr-sensor (if empty)"
else
    rmdir /var/log/ndr-sensor           2>/dev/null && log "  ✅ Removed empty /var/log/ndr-sensor"       || true
    rmdir /etc/ndr-sensor/vector-data   2>/dev/null && log "  ✅ Removed empty /etc/ndr-sensor/vector-data" || true
    rmdir /etc/ndr-sensor               2>/dev/null && log "  ✅ Removed empty /etc/ndr-sensor"           || true
fi

# Also remove legacy /var/log/ndr/ used before the fix
if [ -d /var/log/ndr ]; then
    warn "Found legacy /var/log/ndr/ directory (old install). Removing..."
    run "rm -rf /var/log/ndr"
fi

# ══════════════════════════════════════════════════════
# STEP 7 — Remove Suricata socket/run dir
# ══════════════════════════════════════════════════════
log "Step 7: Cleaning up Suricata runtime files..."
run "rm -rf /var/run/suricata"
run "rm -f /tmp/ndr-sensor-zeek.log /tmp/ndr-sensor-suricata.log /tmp/zeek.log /tmp/suricata.log"
log "  ✅ Suricata runtime files cleaned"

# ══════════════════════════════════════════════════════
# STEP 8 (optional) — Purge Zeek / Suricata / Vector packages
# ══════════════════════════════════════════════════════
if $PURGE_PACKAGES; then
    warn "Step 8: --purge-packages specified. Removing Zeek, Suricata, Vector binaries..."
    warn "  This affects ALL sensors on this machine, not just NDR sensor!"
    echo ""
    read -rp "Are you sure you want to remove Zeek, Suricata, and Vector? [y/N]: " CONFIRM
    if [[ "$CONFIRM" =~ ^[Yy]$ ]]; then
        run "apt-get remove -y --purge zeek zeek-lts suricata vector 2>/dev/null"
        run "apt-get autoremove -y 2>/dev/null"
        run "rm -rf /opt/zeek"
        run "rm -f /etc/apt/sources.list.d/security:zeek.list"
        run "rm -f /etc/apt/sources.list.d/vector.list"
        run "rm -f /etc/apt/trusted.gpg.d/security_zeek.gpg"
        run "rm -f /usr/share/keyrings/vector-keyring.gpg"
        run "apt-get update -qq 2>/dev/null"
        log "  ✅ Packages removed"
    else
        warn "  Package removal skipped."
    fi
else
    info "Step 8: Skipping package removal (use --purge-packages to remove zeek/suricata/vector)"
fi

# ══════════════════════════════════════════════════════
# STEP 9 — Verify nothing is left running
# ══════════════════════════════════════════════════════
log "Step 9: Verifying nothing is left running..."
if ! $DRY_RUN; then
    LEFT=""
    for PAT in 'agent\.py' 'pcap-uploader' 'zeek' 'suricata' 'arkime-capture' 'vector --config' '/usr/local/bin/vector'; do
        pgrep -f "$PAT" > /dev/null 2>&1 && LEFT="$LEFT $PAT"
    done
    if [ -n "$LEFT" ]; then
        warn "  Still running:$LEFT - killing again..."
        systemctl stop ndr-agent 2>/dev/null || true
        for PAT in 'agent\.py' 'pcap-uploader' 'zeek' 'suricata' 'arkime-capture' 'vector --config' '/usr/local/bin/vector'; do
            pkill -9 -f "$PAT" 2>/dev/null || true
        done
        sleep 2
        STILL=""
        for PAT in 'agent\.py' 'zeek' 'suricata' 'arkime-capture' 'vector --config'; do
            pgrep -f "$PAT" > /dev/null 2>&1 && STILL="$STILL $PAT"
        done
        if [ -n "$STILL" ]; then
            warn "  ⚠️  Could not stop:$STILL - check with: pgrep -af 'agent.py|zeek|suricata|vector'"
        else
            log "  ✅ Everything stopped"
        fi
    else
        log "  ✅ No sensor processes running"
    fi
    if systemctl is-active --quiet ndr-agent 2>/dev/null; then
        warn "  ⚠️  ndr-agent service is still active - run: sudo systemctl stop ndr-agent"
    fi
fi

# ══════════════════════════════════════════════════════
# Summary
# ══════════════════════════════════════════════════════
echo ""
echo "╔══════════════════════════════════════════╗"
if $DRY_RUN; then
echo "║  ℹ️  NDR Sensor Dry-Run Complete           ║"
else
echo "║  ✅ NDR Sensor Uninstall Complete!        ║"
fi
echo "╠══════════════════════════════════════════╣"
if [ ${#TENANTS[@]} -gt 0 ]; then
    for TID in "${TENANTS[@]}"; do
        printf "║  Tenant removed: %-23s ║\n" "$TID"
    done
else
    echo "║  All tenant data removed                 ║"
fi
echo "╠══════════════════════════════════════════╣"
echo "║  Services stopped & disabled             ║"
echo "║  Legacy ndr-agent cleaned if present     ║"
echo "║  Zeek/Suricata stopped (PID-safe)        ║"
if $PURGE_PACKAGES; then
echo "║  Packages purged                         ║"
else
echo "║  Packages kept (--purge-packages to rm)  ║"
fi
echo "╚══════════════════════════════════════════╝"
echo ""

if ! $DRY_RUN; then
    log "Uninstall complete. Re-run install-sensor.sh to reinstall clean."
fi
