#!/bin/bash

# ── Auto-fix Windows line endings ─────────────
SELF=$(readlink -f "$0")
if file "$SELF" | grep -q CRLF; then
    echo "Fixing line endings..."
    sed -i 's/\r//' "$SELF"
    find "$(dirname "$SELF")" \
        -name "*.sh" -o -name "*.py" | \
        xargs sed -i 's/\r//' 2>/dev/null || true
    exec bash "$SELF" "$@"
fi

set -e

# ── Bootstrap: download only the required config files (no source code) ──
if [ ! -f "$(dirname "$0")/docker-compose.yml" ]; then
    echo ""
    echo "  NDR installer — downloading required files..."
    echo ""
    read -rp "  GitHub token (provided by Proma Secure): " GH_TOKEN
    INSTALL_DIR="${1:-/opt/ndr}"
    echo "  Installing to: $INSTALL_DIR"
    sudo mkdir -p "$INSTALL_DIR"
    sudo chmod 755 "$INSTALL_DIR"

    echo "  Downloading config files via API..."
    GH_TOKEN="$GH_TOKEN" INSTALL_DIR="$INSTALL_DIR" python3 - << 'PYEOF'
import urllib.request, json, os, base64, sys

token    = os.environ["GH_TOKEN"]
dest     = os.environ["INSTALL_DIR"]
api_base = "https://api.github.com/repos/jithinjoseph-workspace/NDR-Demo"
headers  = {"Authorization": f"token {token}", "Accept": "application/vnd.github.v3+json"}

def gh_get(url):
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req) as r:
            return r.read()
    except Exception as e:
        print(f"  ERROR: API request failed: {e}")
        sys.exit(1)

def download_file(repo_path, local_path):
    meta = json.loads(gh_get(f"{api_base}/contents/{repo_path}?ref=arkime"))
    content = base64.b64decode(meta["content"].replace("\n", ""))
    os.makedirs(os.path.dirname(local_path), exist_ok=True)
    with open(local_path, "wb") as f:
        f.write(content)
    print(f"    {repo_path}")

def download_dir(repo_path, local_path):
    os.makedirs(local_path, exist_ok=True)
    items = json.loads(gh_get(f"{api_base}/contents/{repo_path}?ref=arkime"))
    for item in items:
        target = os.path.join(local_path, item["name"])
        if item["type"] == "file":
            meta = json.loads(gh_get(f"{api_base}/contents/{item['path']}?ref=arkime"))
            content = base64.b64decode(meta["content"].replace("\n", ""))
            with open(target, "wb") as f:
                f.write(content)
            print(f"    {item['path']}")
        elif item["type"] == "dir":
            download_dir(item["path"], target)

download_file("docker-compose.yml",   f"{dest}/docker-compose.yml")
download_file("install-customer.sh",  f"{dest}/install-customer.sh")
download_file("start.sh",             f"{dest}/start.sh")
download_file("stop.sh",              f"{dest}/stop.sh")
download_file("status.sh",            f"{dest}/status.sh")
download_dir("config",                f"{dest}/config")
download_dir("scripts",               f"{dest}/scripts")
download_dir("rust/ndr-engine/rules", f"{dest}/rust/ndr-engine/rules")
PYEOF
    chmod +x "$INSTALL_DIR/install-customer.sh"
    chmod +x "$INSTALL_DIR/start.sh"
    chmod +x "$INSTALL_DIR/stop.sh"
    chmod +x "$INSTALL_DIR/status.sh"

    echo ""
    exec bash "$INSTALL_DIR/install-customer.sh" "$INSTALL_DIR"
fi

# ── Fix DNS early — before any curl/apt/wget ──
if ! curl -s --max-time 3 https://archive.ubuntu.com > /dev/null 2>&1; then
    echo "[NDR] Fixing DNS (switching to 8.8.8.8)..."
    if systemctl is-active systemd-resolved > /dev/null 2>&1; then
        sudo mkdir -p /etc/systemd/resolved.conf.d/
        printf "[Resolve]\nDNS=8.8.8.8 8.8.4.4\nFallbackDNS=1.1.1.1\n" \
            | sudo tee /etc/systemd/resolved.conf.d/ndr-dns.conf > /dev/null
        sudo systemctl restart systemd-resolved 2>/dev/null || true
    else
        printf "nameserver 8.8.8.8\nnameserver 8.8.4.4\n" | sudo tee /etc/resolv.conf > /dev/null
    fi
fi

# ── Colors ────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

LOG_FILE="/var/log/ndr/install-customer-$(date +%Y%m%d-%H%M%S).log"
mkdir -p "$(dirname "$LOG_FILE")" 2>/dev/null && touch "$LOG_FILE" 2>/dev/null \
  || LOG_FILE="/tmp/ndr-install-customer-$(date +%Y%m%d-%H%M%S).log"
touch "$LOG_FILE" 2>/dev/null || true

# ── Log helpers ───────────────────────────────
log()  { echo -e "  ${GREEN}[+]${NC} $1"; }
warn() { echo -e "  ${YELLOW}[!]${NC} $1"; }
err()  { echo -e "  ${RED}[x]${NC} $1"; echo "[$(date '+%Y-%m-%d %H:%M:%S')] FATAL $1" >> "$LOG_FILE" 2>/dev/null; exit 1; }
info() { echo -e "  ${BLUE}[>]${NC} $1"; }

# record_error <component> <what went wrong> <how to fix it>
# Use instead of a bare warn() for anything that leaves a component
# non-functional but shouldn't abort the whole install — logs a structured,
# timestamped line to $LOG_FILE (survives a scrolled/closed terminal) in
# addition to the on-screen warning.
record_error() {
    local component="$1" detail="$2" hint="$3"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] ERROR component=\"$component\" detail=\"$detail\" fix=\"$hint\"" >> "$LOG_FILE" 2>/dev/null
    warn "$component: $detail"
    [ -n "$hint" ] && warn "  → Fix: $hint"
}

# This script runs as a normal user and prefixes individual privileged
# commands with sudo — validate sudo access up front instead of letting a
# no-sudo user hit a wall deep inside the script at whatever the first
# `sudo` command happens to be.
if [ "$(id -u)" -ne 0 ] && ! sudo -v 2>/dev/null; then
  err "This script needs sudo access to install Docker/system packages. Add this user to the sudoers group, or re-run as root."
fi
hdr()  {
    echo -e ""
    echo -e "  ${CYAN}${BOLD}┌─────────────────────────────────────────────┐${NC}"
    printf  "  ${CYAN}${BOLD}│${NC}  %-43s${CYAN}${BOLD}│${NC}\n" "$1"
    echo -e "  ${CYAN}${BOLD}└─────────────────────────────────────────────┘${NC}"
}

# ── Banner ────────────────────────────────────
clear 2>/dev/null || true  # fails under set -e without a TTY/TERM (e.g. non-interactive/CI runs)
printf "\n"
printf "  ${CYAN}╔══════════════════════════════════════════════╗${NC}\n"
printf "  ${CYAN}║${NC}                                              ${CYAN}║${NC}\n"
printf "  ${CYAN}║${NC}    ${BOLD}P R O M A   A L P H A   v 1 . 0${NC}          ${CYAN}║${NC}\n"
printf "  ${CYAN}║${NC}                                              ${CYAN}║${NC}\n"
printf "  ${CYAN}║${NC}    Network Detection & Response Platform      ${CYAN}║${NC}\n"
printf "  ${CYAN}║${NC}    Sensor  ·  Engine  ·  Analytics  ·  UI    ${CYAN}║${NC}\n"
printf "  ${CYAN}║${NC}                                              ${CYAN}║${NC}\n"
printf "  ${CYAN}║${NC}    ${DIM}◆  Powered by Proma Secure  ◆${NC}              ${CYAN}║${NC}\n"
printf "  ${CYAN}║${NC}                                              ${CYAN}║${NC}\n"
printf "  ${CYAN}╚══════════════════════════════════════════════╝${NC}\n"
printf "\n"

# ── Progress bar (inline, no cursor gymnastics) ─
TOTAL_STEPS=12
CURRENT_STEP=0

step() {
    CURRENT_STEP=$((CURRENT_STEP + 1))
    local label="$1" BAR_WIDTH=36
    local filled=$(( (CURRENT_STEP * BAR_WIDTH) / TOTAL_STEPS ))
    local pct=$(( (CURRENT_STEP * 100) / TOTAL_STEPS ))
    local bar="" i
    for ((i=0; i<filled; i++));          do bar+="▓"; done
    for ((i=filled; i<BAR_WIDTH; i++));  do bar+="░"; done
    printf "\n  ${CYAN}[%s]${NC}  ${BOLD}%3d%%${NC}  ${DIM}%d/%d${NC}\n" \
        "$bar" "$pct" "$CURRENT_STEP" "$TOTAL_STEPS"
    hdr "$label"
}

# ── Fix APT sources ───────────────────────────
UBUNTU_CODENAME=$(. /etc/os-release 2>/dev/null && echo "${VERSION_CODENAME:-$(lsb_release -cs 2>/dev/null)}")
UBUNTU_CODENAME=${UBUNTU_CODENAME:-noble}
UBUNTU_MAJOR_VER=$(. /etc/os-release 2>/dev/null && echo "${VERSION_ID}" | cut -d. -f1)
log "Ubuntu ${UBUNTU_CODENAME} (${UBUNTU_MAJOR_VER}.x) detected"

if [ -f /etc/apt/sources.list.d/ubuntu.sources ]; then
    log "ubuntu.sources found — clearing sources.list to avoid duplicates"
    sudo truncate -s 0 /etc/apt/sources.list
else
    log "Writing sources.list for Ubuntu ${UBUNTU_CODENAME}..."
    SECURITY_REPO_LINE=""
    if curl -fsSL --max-time 8 \
        "https://security.ubuntu.com/ubuntu/dists/${UBUNTU_CODENAME}-security/InRelease" \
        -o /dev/null 2>/dev/null; then
        SECURITY_REPO_LINE="deb https://security.ubuntu.com/ubuntu ${UBUNTU_CODENAME}-security main restricted universe multiverse"
    else
        warn "security.ubuntu.com/${UBUNTU_CODENAME}-security not yet available — skipping"
    fi
    sudo tee /etc/apt/sources.list > /dev/null << EOF
deb https://archive.ubuntu.com/ubuntu ${UBUNTU_CODENAME} main restricted universe multiverse
deb https://archive.ubuntu.com/ubuntu ${UBUNTU_CODENAME}-updates main restricted universe multiverse
deb https://archive.ubuntu.com/ubuntu ${UBUNTU_CODENAME}-backports main restricted universe multiverse
${SECURITY_REPO_LINE}
EOF
fi

sudo tee /etc/apt/apt.conf.d/99timeout > /dev/null << 'EOF'
Acquire::http::Timeout "15";
Acquire::https::Timeout "15";
Acquire::Retries "2";
EOF

sudo rm -rf /var/lib/apt/lists/* 2>/dev/null || true
log "APT cache cleared"
log "Updating package lists..."
sudo apt-get update 2>&1 | grep -E "^Get|^Hit|^Err" | head -15 || true
log "Network ready"

# ── Deployment Mode ───────────────────────────
# provigil-install.sh has already asked the role (all-in-one, or master with a separate data lake)
if [ -n "${PV_ROLE:-}" ]; then
    DEPLOY_MODE="local"
else
printf "\n"
printf "  ${CYAN}┌──────────────────────────────────────────────┐${NC}\n"
printf "  ${CYAN}│${NC}  ${BOLD}Select Deployment Mode${NC}                        ${CYAN}│${NC}\n"
printf "  ${CYAN}├──────────────────────────────────────────────┤${NC}\n"
printf "  ${CYAN}│${NC}  ${GREEN}[1]${NC} Local  — all services on this machine      ${CYAN}│${NC}\n"
printf "  ${CYAN}│${NC}       Recommended for single-site deployment  ${CYAN}│${NC}\n"
printf "  ${CYAN}│${NC}                                              ${CYAN}│${NC}\n"
printf "  ${CYAN}│${NC}  ${BLUE}[2]${NC} Hybrid — capture local, cloud processing   ${CYAN}│${NC}\n"
printf "  ${CYAN}│${NC}       For multi-office or cloud-connected use ${CYAN}│${NC}\n"
printf "  ${CYAN}└──────────────────────────────────────────────┘${NC}\n"
printf "\n"
read -p "  Enter choice (1/2) [default: 1]: " MODE_CHOICE

case "$MODE_CHOICE" in
    2)
        DEPLOY_MODE="hybrid"
        printf "\n"
        warn "Hybrid mode — Agent-Z/Agent-S local, Event Bus/DB in cloud"
        printf "\n"
        read -p "  Kafka broker URL  (e.g. broker.aws.com:9092):   " CLOUD_KAFKA
        read -p "  ClickHouse URL    (e.g. https://host:8123):     " CLOUD_CLICKHOUSE
        read -p "  ClickHouse user:                                 " CLOUD_CH_USER
        read -sp "  ClickHouse password:                            " CLOUD_CH_PASS
        echo ""
        printf "\n"
        log "Hybrid configuration saved"
        ;;
    *)
        DEPLOY_MODE="local"
        log "Local mode — all services on this machine"
        ;;
esac
fi

printf "\n"

# ── Image source: an offline kit's images, else the registry ───────────
# Only the licensed modules' images are pulled; the login happens once Docker is installed.
REGISTRY="${PROVIGIL_REGISTRY:-ghcr.io/jithinjoseph-workspace}"
if [ -n "${PV_OFFLINE_DIR:-}" ]; then
    log "Offline install: images from $PV_OFFLINE_DIR/images"
fi
# ProVigil's images are public (they run only with a valid licence): a token only for a private registry
printf "\n"

# ── Check OS ──────────────────────────────────
. /etc/os-release
log "Detected OS: $NAME $VERSION_ID"
[[ "$ID" != "ubuntu" ]] && warn "Only Ubuntu tested. Proceed with caution."

USERNAME=$(whoami)
HOME_DIR=$HOME
INSTALL_DIR=$(cd "$(dirname "$0")" && pwd)
RUNTIME_DIR="$INSTALL_DIR/.runtime"
IFACE_FILE="$RUNTIME_DIR/ndr_interface"
OS_VERSION=$(echo $VERSION_ID | cut -d'.' -f1,2)

log "Installing to:  $INSTALL_DIR"
log "Running as:     $USERNAME"
log "Deploy mode:    $DEPLOY_MODE"

# ── Licence: it decides the modules this install sets up ─────────
# provigil-install.sh passes a checked licence (PV_*); a reinstall keeps the one in .env unless
# a new one is given; run on its own, the token is asked for here.
env_get() { grep "^$1=" "$INSTALL_DIR/.env" 2>/dev/null | head -1 | cut -d= -f2-; }
LICENSE_PUBLIC_KEY=${PV_LICENSE_PUBLIC_KEY:-$(env_get LICENSE_PUBLIC_KEY)}
LICENSE_TOKEN=${PV_LICENSE_TOKEN:-$(env_get LICENSE_TOKEN)}
if [ -z "$LICENSE_TOKEN" ]; then
    read -p "  License token (from your ProVigil licence; Enter = every module): " -r LICENSE_TOKEN
fi
# the licence's modules, comma-separated ("" = every module: no licence, or one without a list)
licence_modules() {
    local p; p=$(printf '%s' "$1" | cut -d. -f2 | tr '_-' '/+')
    case $(( ${#p} % 4 )) in 2) p="${p}==" ;; 3) p="${p}=" ;; esac
    printf '%s' "$p" | base64 -d 2>/dev/null | python3 -c 'import json,sys; print(",".join(json.load(sys.stdin).get("features") or []))' 2>/dev/null
}
PV_MODULES=${PV_MODULES:-$(licence_modules "$LICENSE_TOKEN")}
has_module() { [ -z "$PV_MODULES" ] && return 0; case ",$PV_MODULES," in *",$1,"*) return 0 ;; *) return 1 ;; esac; }
HAS_NDR=0; HAS_SIEM=0
has_module ndr && HAS_NDR=1
has_module siem && HAS_SIEM=1
# a licence with only add-ons (soar, threat_intel, ai) still needs a base: the SIEM
[ "$HAS_NDR" = 0 ] && [ "$HAS_SIEM" = 0 ] && HAS_SIEM=1
if [ "$HAS_NDR" = 1 ] && [ "$HAS_SIEM" = 1 ]; then PRODUCT_MODE=both; elif [ "$HAS_NDR" = 1 ]; then PRODUCT_MODE=ndr; else PRODUCT_MODE=siem; fi
log "Licensed modules: ${PV_MODULES:-all}  (installs: $PRODUCT_MODE)"

# Write a minimal .env immediately so docker compose never sees blank variables.
# The network step overwrites this with full values once HOST_IP/JWT_SECRET are known.
IFACE_EARLY=$(ip route get 8.8.8.8 2>/dev/null | awk '{for(i=1;i<=NF;i++) if ($i=="dev") {print $(i+1); exit}}')
if [ -z "$IFACE_EARLY" ]; then
    IFACE_EARLY=$(ip -o -4 addr show 2>/dev/null | grep -v "127.0.0.1\|docker\|br-\|veth\| lo " | awk '{print $2}' | head -1)
fi
IFACE_EARLY=${IFACE_EARLY:-eth0}
HOST_IP_EARLY=$(ip -o -4 addr show "$IFACE_EARLY" 2>/dev/null | awk '{print $4}' | cut -d/ -f1)
HOST_IP_EARLY=${HOST_IP_EARLY:-$(hostname -I | awk '{print $1}')}
JWT_SECRET_EARLY=$(openssl rand -hex 32 2>/dev/null || echo "changeme-$(date +%s)")
NDR_AGENT_SECRET_EARLY=$(openssl rand -hex 32 2>/dev/null || echo "changeme-agent-$(date +%s)")

# siem-api encrypts stored credentials (integrations, AI keys) with AGENT_KEYS_SECRET: read it
# before .env is rewritten, so a reinstall keeps it (a new one would make them unreadable)
AGENT_KEYS_SECRET=$(grep "^AGENT_KEYS_SECRET=" "$INSTALL_DIR/.env" 2>/dev/null | cut -d= -f2-)
AGENT_KEYS_SECRET=${AGENT_KEYS_SECRET:-$(openssl rand -hex 32)}
# the agents' gateway passes enrollments to siem-api with this token (kept the same way)
GATEWAY_INTERNAL_TOKEN=$(grep "^GATEWAY_INTERNAL_TOKEN=" "$INSTALL_DIR/.env" 2>/dev/null | cut -d= -f2-)
GATEWAY_INTERNAL_TOKEN=${GATEWAY_INTERNAL_TOKEN:-$(openssl rand -hex 32)}

# Only on a fresh install: a reinstall keeps the existing .env, whose sign-in secret, licence
# keys and database password the later steps read back (new ones would sign everyone out,
# invalidate issued licences and lock the services out of the existing database).
if [ ! -s "$INSTALL_DIR/.env" ]; then
cat > "$INSTALL_DIR/.env" << _EARLY_ENV
HOST_IP=${HOST_IP_EARLY}
HOME_DIR=${HOME_DIR}
INSTALL_DIR=${INSTALL_DIR}
IFACE=${IFACE_EARLY}
DEPLOY_MODE=${DEPLOY_MODE}
LOCAL_SENSOR_ID=local-central
TENANT_ID=default
CLICKHOUSE_URL=http://ndr-nginx:8123
CLICKHOUSE_URL_SECONDARY=http://clickhouse2:8123
CLICKHOUSE_USER=ndr
CLICKHOUSE_PASSWORD=$(openssl rand -hex 16 2>/dev/null || echo "$(date +%s%N | sha256sum | head -c 32)")
KAFKA_BROKERS=kafka1:9092,kafka2:9092,kafka3:9092
JWT_SECRET=${JWT_SECRET_EARLY}
NDR_AGENT_SECRET=${NDR_AGENT_SECRET_EARLY}
CORS_ORIGIN=https://${HOST_IP_EARLY}:3000
ARKIME_URL=http://${HOST_IP_EARLY}:8005
ARKIME_PASS=$(openssl rand -hex 12 2>/dev/null || echo "$(date +%s%N | sha256sum | head -c 24)")
OPENSEARCH_URL=http://${HOST_IP_EARLY}:9200
OPENAI_API_KEY=
GROQ_API_KEY=
GROQ_MODEL=llama-3.3-70b-versatile
BEACON_WINDOW_HOURS=1
INGEST_RATE_LIMIT=0
SIEM_SYSLOG_HOST=
SIEM_SYSLOG_PORT=514
TRUSTED_SOURCE_CIDRS=
LICENSE_PUBLIC_KEY=${LICENSE_PUBLIC_KEY}
LICENSE_TOKEN=${LICENSE_TOKEN}
TENANT_ADMIN_USER=
TENANT_ADMIN_PASS=
AGENT_KEYS_SECRET=${AGENT_KEYS_SECRET}
GATEWAY_INTERNAL_TOKEN=${GATEWAY_INTERNAL_TOKEN}
_EARLY_ENV
log ".env written early (will be updated with final values in network step)"
else
    log "Reinstall: keeping the existing .env (secrets, licence keys and passwords are reused)"
fi

# ── Spinner ───────────────────────────────────
spinner() {
    local pid=$1 msg=$2
    local frames=('⠋' '⠙' '⠹' '⠸' '⠼' '⠴' '⠦' '⠧' '⠇' '⠏')
    local i=0
    while kill -0 $pid 2>/dev/null; do
        printf "\r  ${CYAN}${frames[$i]}${NC}  %s..." "$msg"
        i=$(( (i+1) % 10 ))
        sleep 0.1
    done
    printf "\r  ${GREEN}[+]${NC}  %s — done       \n" "$msg"
}

progress() {
    local msg=$1; shift
    "$@" &>/dev/null &
    spinner $! "$msg"
}

# ══════════════════════════════════════════════
step "System Dependencies"

log "Updating package lists..."
sudo apt-get update 2>&1 | grep -E "^Get|^Hit|^Err|^W:" || true

# auditd requires CAP_AUDIT_CONTROL which many hypervisors deny.
# Mask it so systemd refuses to start it during dpkg post-install,
# letting dpkg configure succeed without the daemon actually running.
sudo systemctl mask auditd 2>/dev/null || true
sudo dpkg --configure -a 2>/dev/null || true

log "Installing packages..."
sudo apt-get install -y \
    curl wget git jq python3 python3-pip \
    net-tools iproute2 \
    netcat-traditional \
    arp-scan iputils-arping snmp \
    libpcre3 2>/dev/null || true


if ! dpkg -l libpcre3 2>/dev/null | grep -q '^ii'; then
    for PCRE3_URL in \
        "http://archive.ubuntu.com/ubuntu/pool/main/p/pcre3/libpcre3_8.45-4_amd64.deb" \
        "http://archive.ubuntu.com/ubuntu/pool/main/p/pcre3/libpcre3_8.39-17build1_amd64.deb" \
        "http://security.ubuntu.com/ubuntu/pool/main/p/pcre3/libpcre3_8.39-13ubuntu0.22.04.1_amd64.deb"; do
        if wget -q --timeout=60 "$PCRE3_URL" -O /tmp/libpcre3.deb 2>/dev/null \
            && sudo dpkg -i /tmp/libpcre3.deb > /dev/null 2>&1; then
            rm -f /tmp/libpcre3.deb
            break
        fi
        rm -f /tmp/libpcre3.deb
    done
fi

if [ ! -e /usr/lib/x86_64-linux-gnu/libpcre.so.3 ]; then
    PCRE_SO=$(find /usr/lib/x86_64-linux-gnu /lib/x86_64-linux-gnu \
        -name "libpcre.so.3.*" 2>/dev/null | head -1)
    [ -n "$PCRE_SO" ] && sudo ln -sf "$PCRE_SO" /usr/lib/x86_64-linux-gnu/libpcre.so.3 \
        && sudo ldconfig
fi
log "System dependencies installed"

# ══════════════════════════════════════════════
step "Node.js 20"

log "Skipped — UI runs from Docker image, Node.js not required"

# ══════════════════════════════════════════════
step "Agent-S"

log "Skipped — Agent-S runs on dedicated remote sensor machines"

# ── Packet Recorder (Arkime): NDR only ────────
if [ "$HAS_NDR" = 1 ]; then
log "Installing Packet Recorder..."

ARKIME_VERSION="5.1.0"
UBUNTU_VER=$(lsb_release -rs 2>/dev/null || echo "22.04")
UBUNTU_MAJOR=$(echo $UBUNTU_VER | cut -d. -f1)

if ! command -v /opt/arkime/bin/capture &>/dev/null; then
    if [ "$UBUNTU_MAJOR" -le "21" ] 2>/dev/null; then
        ARKIME_DEB="arkime_${ARKIME_VERSION}-1.ubuntu2004_amd64.deb"
    elif [ "$UBUNTU_MAJOR" -le "23" ] 2>/dev/null; then
        ARKIME_DEB="arkime_${ARKIME_VERSION}-1.ubuntu2204_amd64.deb"
    elif [ "$UBUNTU_MAJOR" -ge "24" ] 2>/dev/null; then
        ARKIME_DEB="arkime_${ARKIME_VERSION}-1.ubuntu2404_amd64.deb"
    else
        warn "Unsupported OS for Packet Recorder: $UBUNTU_VER"
        ARKIME_DEB=""
    fi

    if [ -n "$ARKIME_DEB" ]; then
        log "Downloading Packet Recorder ${ARKIME_VERSION}..."
        if wget --timeout=120 --progress=dot:mega \
            "https://github.com/arkime/arkime/releases/download/v${ARKIME_VERSION}/${ARKIME_DEB}" \
            -O /tmp/arkime.deb 2>&1; then
            DEB_SIZE=$(du -sh /tmp/arkime.deb 2>/dev/null | cut -f1)
            log "Download complete (${DEB_SIZE})"
        else
            warn "Packet Recorder download failed — check internet and re-run"
            ARKIME_DEB=""
            rm -f /tmp/arkime.deb
        fi
    fi

    if [ -n "$ARKIME_DEB" ] && [ -f /tmp/arkime.deb ]; then
        log "Installing Packet Recorder dependencies..."
        sudo apt-get install -y -qq \
            libwww-perl libjson-perl \
            libyaml-dev libyara10 \
            librdkafka1 ethtool \
            libpcre3 libpcre3-dev \
            libmagic1 libmaxminddb0 \
            libpcre2-8-0 \
            libyaml-0-2 > /dev/null 2>&1 || true

        if ! dpkg -l libpcre3 2>/dev/null | grep -q '^ii'; then
            if sudo apt-get install -y -qq libpcre3 > /dev/null 2>&1; then
                log "libpcre3 installed from apt"
            else
                log "libpcre3 not in repos — downloading from Ubuntu archive..."
                PCRE3_INSTALLED=false
                for PCRE3_URL in \
                    "http://archive.ubuntu.com/ubuntu/pool/main/p/pcre3/libpcre3_8.45-4_amd64.deb" \
                    "http://archive.ubuntu.com/ubuntu/pool/main/p/pcre3/libpcre3_8.39-17build1_amd64.deb" \
                    "http://security.ubuntu.com/ubuntu/pool/main/p/pcre3/libpcre3_8.39-13ubuntu0.22.04.1_amd64.deb"; do
                    if wget -q --timeout=60 "$PCRE3_URL" -O /tmp/libpcre3.deb 2>/dev/null \
                        && sudo dpkg -i /tmp/libpcre3.deb > /dev/null 2>&1; then
                        rm -f /tmp/libpcre3.deb
                        log "libpcre3 installed"
                        PCRE3_INSTALLED=true
                        break
                    fi
                    rm -f /tmp/libpcre3.deb
                done
                $PCRE3_INSTALLED || warn "libpcre3 install failed — capture may crash"
            fi
        fi

        log "Installing Packet Recorder package..."
        if sudo dpkg -i /tmp/arkime.deb 2>&1; then
            log "dpkg install succeeded"
        else
            warn "dpkg reported errors — running apt-get install -f..."
            sudo apt-get install -f -y 2>&1 || true
        fi
        rm -f /tmp/arkime.deb

        if [ -f /opt/arkime/bin/capture ]; then
            ARKIME_VER=$(/opt/arkime/bin/capture --version 2>/dev/null | head -1 || echo "unknown")
            log "Packet Recorder installed: ${ARKIME_VER}"
        else
            warn "Arkime install failed — /opt/arkime/bin/capture not found"
        fi
    else
        warn "Packet Recorder skipped (no package available)"
    fi
else
    ARKIME_VER=$(/opt/arkime/bin/capture --version 2>/dev/null | head -1 || echo "unknown")
    log "Packet Recorder already installed: ${ARKIME_VER}"
fi
else
    log "Packet Recorder skipped — the licence has no NDR module"
fi

# ══════════════════════════════════════════════
step "Agent-Z"

log "Skipped — Agent-Z runs on dedicated remote sensor machines"

# ══════════════════════════════════════════════
step "Analytics Database  (ClickHouse)"

if [ -n "${PV_DATALAKE_URL:-}" ]; then
    # master role: the data lake PC holds every event (install-datalake.sh printed these)
    CLOUD_CLICKHOUSE="$PV_DATALAKE_URL"; CLOUD_CH_USER="${PV_DATALAKE_USER:-provigil}"; CLOUD_CH_PASS="$PV_DATALAKE_PASSWORD"
    CLOUD_KAFKA="kafka1:9092,kafka2:9092,kafka3:9092"
    CLICKHOUSE_URL="$PV_DATALAKE_URL"; CLICKHOUSE_URL_SECONDARY="$PV_DATALAKE_URL"
    log "Data lake: $PV_DATALAKE_URL (user $CLOUD_CH_USER); no local ClickHouse"
elif [ "$DEPLOY_MODE" = "local" ]; then
    log "ClickHouse — Docker container cluster (2 nodes, bridge network)"
    log "  Credentials:  user ndr, random password stored in $INSTALL_DIR/.env"
    log "  Endpoint:     http://localhost:8123  (node 1, localhost-only)"

    CH_NEEDS_IMPORT=false
    if systemctl is-active --quiet clickhouse-server 2>/dev/null; then
        warn "Existing ClickHouse installation detected on this host."
        printf "\n"
        printf "  ${CYAN}┌─────────────────────────────────────────┐${NC}\n"
        printf "  ${CYAN}│${NC}  ${BOLD}Migration Options${NC}                        ${CYAN}│${NC}\n"
        printf "  ${CYAN}├─────────────────────────────────────────┤${NC}\n"
        printf "  ${CYAN}│${NC}  [1] Migrate existing data into Docker   ${CYAN}│${NC}\n"
        printf "  ${CYAN}│${NC}  [2] Fresh start — wipe existing data    ${CYAN}│${NC}\n"
        printf "  ${CYAN}└─────────────────────────────────────────┘${NC}\n"
        printf "\n"
        read -p "  Enter choice [1/2]: " CH_MIGRATE_CHOICE
        printf "\n"

        if [ "$CH_MIGRATE_CHOICE" = "1" ]; then
            log "Exporting existing ClickHouse data..."
            bash "$INSTALL_DIR/scripts/ch-export.sh"
            CH_NEEDS_IMPORT=true
            log "Data exported to /home/user/ch-export/"
        else
            log "Fresh start — existing data will not be migrated"
        fi

        log "Stopping host ClickHouse (Docker takes over)..."
        sudo systemctl stop clickhouse-server
        sudo systemctl disable clickhouse-server
        log "Host ClickHouse stopped and disabled"

        printf "\n"
        read -p "  Uninstall ClickHouse packages from host? [y/N]: " CH_PURGE
        if [[ "$CH_PURGE" =~ ^[Yy]$ ]]; then
            log "Removing ClickHouse packages..."
            if command -v apt-get &>/dev/null; then
                sudo apt-get remove -y clickhouse-server clickhouse-client clickhouse-common-static 2>/dev/null || true
                sudo apt-get autoremove -y 2>/dev/null || true
            elif command -v yum &>/dev/null; then
                sudo yum remove -y clickhouse-server clickhouse-client 2>/dev/null || true
            fi
            log "ClickHouse packages removed — Docker container takes over"
        else
            log "Keeping packages (service remains disabled)"
        fi
    elif ss -tlnp 2>/dev/null | grep -qE ':8123|:9000'; then
        warn "Ports 8123/9000 in use — killing conflicting processes..."
        PIDS=$(ss -tlnp 2>/dev/null | grep -E ':8123|:9000' \
            | grep -oP 'pid=\K[0-9]+' | sort -u)
        if [ -n "$PIDS" ]; then
            for PID in $PIDS; do
                PNAME=$(ps -p "$PID" -o comm= 2>/dev/null || echo "unknown")
                log "  Killing PID $PID ($PNAME) holding ClickHouse ports..."
                sudo kill -9 "$PID" 2>/dev/null || true
            done
            sleep 2
            if ss -tlnp 2>/dev/null | grep -qE ':8123|:9000'; then
                warn "Some ports still in use — containers may conflict"
            else
                log "Ports 8123/9000 are now free"
            fi
        fi
    fi

    CLICKHOUSE_URL="http://localhost:8123"
    CLICKHOUSE_URL_SECONDARY="http://localhost:8123"
    CLOUD_CH_USER="ndr"
    # Use the random password already written to .env earlier in this run. It was
    # previously forced to a hardcoded "ndr123" here, giving every install the same
    # database credential. ClickHouse reads it from CLICKHOUSE_PASSWORD at start-up,
    # so a re-run simply rotates it consistently across the stack.
    CLOUD_CH_PASS=$(grep '^CLICKHOUSE_PASSWORD=' "$INSTALL_DIR/.env" 2>/dev/null | cut -d= -f2-)
    if [ -z "$CLOUD_CH_PASS" ]; then
        CLOUD_CH_PASS=$(openssl rand -hex 16 2>/dev/null || echo "$(date +%s%N | sha256sum | head -c 32)")
    fi
    CLOUD_KAFKA="kafka1:9092,kafka2:9092,kafka3:9092"
else
    log "Using cloud ClickHouse: $CLOUD_CLICKHOUSE"
    CLICKHOUSE_URL="$CLOUD_CLICKHOUSE"
    info "Skipping local ClickHouse setup"
fi
log "ClickHouse configured"

# ══════════════════════════════════════════════
step "Network & Sensor Configuration"

log "Detecting network interface..."
IFACE=$(ip route get 8.8.8.8 2>/dev/null | awk '{for(i=1;i<=NF;i++) if ($i=="dev") {print $(i+1); exit}}')
if [ -z "$IFACE" ]; then
    IFACE=$(ip -o -4 addr show 2>/dev/null | \
        grep -v "127.0.0.1\|docker\|br-\|veth\| lo " | \
        awk '{print $2}' | head -1)
fi
[ -z "$IFACE" ] && IFACE="eth0"
log "Management network card: $IFACE"

# NDR on this box: the card on the switch's mirror port or a TAP (listen only). Without one, NDR
# sees only this box's own traffic (specs/provigil-nodes.md: the single box).
CAPTURE_IFACE="${PV_CAPTURE_IFACE:-}"
if [ "$HAS_NDR" = 1 ] && [ -z "$CAPTURE_IFACE" ]; then
    CANDIDATES=$(ip -o link show 2>/dev/null | awk -F': ' '{print $2}' | cut -d@ -f1 \
        | grep -vE '^(lo|docker|br-|veth|virbr|tun|tap|wl)' | grep -vxF "$IFACE" || true)
    if [ -n "$CANDIDATES" ] && [ -t 0 ]; then
        echo ""
        echo "  Network cards (other than $IFACE, the management card):"
        for c in $CANDIDATES; do
            printf '    %-14s %s\n' "$c" "$(cat /sys/class/net/$c/operstate 2>/dev/null) $(ip -o -4 addr show dev "$c" 2>/dev/null | awk '{print $4}' | head -1)"
        done
        read -rp "  The card on the mirror port or TAP (Enter: none): " CAPTURE_IFACE
    elif [ -z "$CANDIDATES" ]; then
        warn "Only one network card: NDR sees only this box's traffic. Add a card on the switch mirror port or a TAP and run the installer again with --capture-iface <card>."
    fi
fi
if [ -n "$CAPTURE_IFACE" ]; then
    ip link show "$CAPTURE_IFACE" >/dev/null 2>&1 || err "No network card $CAPTURE_IFACE"
    [ "$CAPTURE_IFACE" = "$IFACE" ] && err "$CAPTURE_IFACE is the management card: the capture card must be another one"
    # listen only, at every start: no address, promiscuous, no offloads (they merge packets)
    sudo tee /etc/systemd/system/provigil-capture.service > /dev/null << CAPTURE_EOF
[Unit]
Description=ProVigil capture card $CAPTURE_IFACE (listen only)
After=network-pre.target
Before=network-online.target
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/sh -c 'ip addr flush dev $CAPTURE_IFACE; ip link set $CAPTURE_IFACE up promisc on; ethtool -K $CAPTURE_IFACE gro off lro off tso off gso off 2>/dev/null || true'
[Install]
WantedBy=multi-user.target
CAPTURE_EOF
    sudo systemctl daemon-reload
    sudo systemctl enable --now provigil-capture.service >/dev/null 2>&1 || warn "capture card $CAPTURE_IFACE not set listen-only (systemctl status provigil-capture)"
    log "Capture card: $CAPTURE_IFACE (listen only, promiscuous)"
    IFACE="$CAPTURE_IFACE"
fi
mkdir -p "$RUNTIME_DIR"
echo "$IFACE" > "$IFACE_FILE"

# ── Configure Arkime ──────────────────────────
if [ -f /opt/arkime/bin/capture ]; then
    log "Configuring Packet Recorder..."
    sudo mkdir -p /opt/arkime/raw /opt/arkime/logs /opt/arkime/etc
    sudo chmod 755 /opt/arkime/raw

    sudo tee /opt/arkime/etc/config.ini > /dev/null << ARKIME_EOF
[default]
elasticsearch=http://localhost:9200
passwordSecret=${API_KEY:-ndr-arkime-secret}
serverSecret=${API_KEY:-ndr-arkime-secret}
httpRealm=Arkime
interface=${IFACE:-eno1}
pcapDir=/opt/arkime/raw
maxFileSizeG=4
maxFileTimeM=60
viewPort=8005
viewHost=0.0.0.0
pcapWriteMethod=simple
pcapWriteSize=262143
authMode=basic
logLevel=warn
maxDays=7
freeSpaceG=5
tcpTimeout=600
udpTimeout=30
maxStreams=500000
maxPackets=10000
packetThreads=2
communityId=true
cronQueries=true
ARKIME_EOF

    sudo tee /etc/systemd/system/arkime-capture.service > /dev/null << EOF
[Unit]
Description=Arkime Packet Capture
After=network.target

[Service]
Type=simple
ExecStart=/opt/arkime/bin/capture \\
    -c /opt/arkime/etc/config.ini \\
    -o pcapDir=/opt/arkime/raw \\
    --insecure
Restart=always
RestartSec=10
LimitCORE=infinity
LimitMEMLOCK=infinity

[Install]
WantedBy=multi-user.target
EOF

    sudo tee /etc/systemd/system/arkime-viewer.service > /dev/null << EOF
[Unit]
Description=Arkime Packet Viewer
After=network.target

[Service]
Type=simple
WorkingDirectory=/opt/arkime/viewer
ExecStart=/opt/arkime/bin/node \\
    viewer.js \\
    -c /opt/arkime/etc/config.ini
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

    sudo systemctl daemon-reload
    sudo systemctl disable arkime-capture arkime-viewer 2>/dev/null || true
    log "Packet Recorder configured on interface: ${IFACE}"
fi

# ── Firewall ──────────────────────────────────
log "Configuring firewall rules for internal ports..."
INTERNAL_PORTS="8123 9000 2181 3001"
if command -v iptables &>/dev/null; then
    for PORT in $INTERNAL_PORTS; do
        while sudo iptables -D INPUT -p tcp --dport $PORT -i lo      -j ACCEPT 2>/dev/null; do :; done
        while sudo iptables -D INPUT -p tcp --dport $PORT -i docker+ -j ACCEPT 2>/dev/null; do :; done
        while sudo iptables -D INPUT -p tcp --dport $PORT -i br+     -j ACCEPT 2>/dev/null; do :; done
        while sudo iptables -D INPUT -p tcp --dport $PORT            -j DROP   2>/dev/null; do :; done
        sudo iptables -I INPUT -p tcp --dport $PORT -i lo      -j ACCEPT 2>/dev/null || true
        sudo iptables -I INPUT -p tcp --dport $PORT -i docker+ -j ACCEPT 2>/dev/null || true
        sudo iptables -I INPUT -p tcp --dport $PORT -i br+     -j ACCEPT 2>/dev/null || true
        sudo iptables -A INPUT -p tcp --dport $PORT            -j DROP   2>/dev/null || true
    done
    if command -v netfilter-persistent &>/dev/null; then
        sudo netfilter-persistent save 2>/dev/null || true
    elif command -v iptables-save &>/dev/null; then
        sudo mkdir -p /etc/iptables
        sudo iptables-save | sudo tee /etc/iptables/rules.v4 > /dev/null 2>&1 || true
    fi
    log "Firewall: ClickHouse/Keeper blocked externally, Docker+loopback allowed"
else
    warn "iptables not found — manually block ports $INTERNAL_PORTS from external access"
fi

# ── Directories ───────────────────────────────
log "Creating runtime directories..."
mkdir -p "$HOME_DIR/ndr-config"
sudo mkdir -p /opt/ndr/pcap /opt/ndr/evidence
sudo chmod -R 755 /opt/ndr
sudo chown -R "$USER:$USER" /opt/ndr

# The vector container bind-mounts ${HOME_DIR}/.vector/vector.toml as a
# read-only file — if that path doesn't exist yet, Docker auto-creates it
# as a directory instead, and the container then fails to start with a
# confusing "not a directory" mount error. A prior failed install run can
# leave exactly that bad directory behind, so a plain re-run needs to
# replace it, not just skip because "something" is already there.
mkdir -p "$HOME_DIR/.vector/data"
[ -d "$HOME_DIR/.vector/vector.toml" ] && rmdir "$HOME_DIR/.vector/vector.toml" 2>/dev/null
if [ ! -f "$HOME_DIR/.vector/vector.toml" ]; then
    cp "$INSTALL_DIR/config/vector.toml" "$HOME_DIR/.vector/vector.toml"
fi
log "Runtime directories created"

# ── Detect host IP ────────────────────────────
HOST_IP=$(ip -o -4 addr show "$IFACE" 2>/dev/null | awk '{print $4}' | cut -d/ -f1)
[ -z "$HOST_IP" ] && HOST_IP=$(hostname -I | awk '{print $1}')
log "Host IP: $HOST_IP"

# ── JWT & API keys ────────────────────────────
if [ -f "$INSTALL_DIR/.env" ] && grep -q "JWT_SECRET" "$INSTALL_DIR/.env"; then
    JWT_SECRET=$(grep "^JWT_SECRET=" "$INSTALL_DIR/.env" | cut -d= -f2-)
else
    JWT_SECRET=$(openssl rand -hex 32)
fi
if [ -f "$INSTALL_DIR/.env" ] && grep -q "NDR_AGENT_SECRET" "$INSTALL_DIR/.env"; then
    NDR_AGENT_SECRET=$(grep "^NDR_AGENT_SECRET=" "$INSTALL_DIR/.env" | cut -d= -f2-)
else
    NDR_AGENT_SECRET=$(openssl rand -hex 32)
fi

if [ -f "$INSTALL_DIR/.env" ] && grep -q "OPENAI_API_KEY" "$INSTALL_DIR/.env"; then
    OPENAI_API_KEY=$(grep "OPENAI_API_KEY" "$INSTALL_DIR/.env" | cut -d= -f2-)
fi
if [ -z "$OPENAI_API_KEY" ]; then
    printf "\n"
    read -p "  OpenAI API key for ARIA (press Enter to skip): " -r OPENAI_API_KEY
fi

# ── License public key + token (from PromaSecure super admin portal) ─────────
# (read with the token at the start; asked for here only when still missing)
if [ -z "$LICENSE_PUBLIC_KEY" ]; then
    printf "\n"
    printf "  License public key (paste base64 or PEM block, then press Enter twice):\n  "
    _RAW_KEY=""
    while IFS= read -r _line; do
        [ -z "$_line" ] && break
        _RAW_KEY="${_RAW_KEY}${_line}"$'\n'
    done
    # If pasted as PEM block, base64-encode it to a single line for .env storage
    if echo "$_RAW_KEY" | grep -q "BEGIN PUBLIC KEY"; then
        LICENSE_PUBLIC_KEY=$(printf '%s' "$_RAW_KEY" | base64 -w0)
    else
        LICENSE_PUBLIC_KEY=$(printf '%s' "$_RAW_KEY" | tr -d '\n\r ')
    fi
fi

if [ -z "$LICENSE_TOKEN" ]; then
    printf "\n"
    read -p "  License token (paste from your NDR admin portal, press Enter to skip): " -r LICENSE_TOKEN
fi

# ── Tenant admin credentials (provisioned on first engine boot) ──────────
TENANT_ADMIN_USER=${PV_ADMIN_USER:-}; TENANT_ADMIN_PASS=${PV_ADMIN_PASS:-}
if [ -z "$TENANT_ADMIN_USER" ] && [ -f "$INSTALL_DIR/.env" ] && grep -q "^TENANT_ADMIN_USER=." "$INSTALL_DIR/.env"; then
    TENANT_ADMIN_USER=$(grep "^TENANT_ADMIN_USER=" "$INSTALL_DIR/.env" | cut -d= -f2-)
fi
if [ -z "$TENANT_ADMIN_USER" ]; then
    printf "\n"
    read -p "  Tenant admin username (e.g. acme-admin): " -r TENANT_ADMIN_USER
fi

if [ -z "$TENANT_ADMIN_PASS" ] && [ -f "$INSTALL_DIR/.env" ] && grep -q "^TENANT_ADMIN_PASS=." "$INSTALL_DIR/.env"; then
    TENANT_ADMIN_PASS=$(grep "^TENANT_ADMIN_PASS=" "$INSTALL_DIR/.env" | cut -d= -f2-)
fi
if [ -z "$TENANT_ADMIN_PASS" ]; then
    printf "\n"
    read -sp "  Tenant admin password: " TENANT_ADMIN_PASS
    echo ""
    read -sp "  Confirm password    : " _PASS_CONFIRM
    echo ""
    [ "$TENANT_ADMIN_PASS" != "$_PASS_CONFIRM" ] && err "Passwords do not match — re-run the installer"
fi

# Auto-extract TENANT_ID from the license token so events are stored under
# the correct tenant, not hardcoded "default".
TENANT_ID="default"
if [ -n "$LICENSE_TOKEN" ]; then
    PAYLOAD=$(echo "$LICENSE_TOKEN" | cut -d. -f2)
    # JWT uses base64url (- and _ instead of + and /); add padding if needed
    PADDED=$(echo "$PAYLOAD" | tr '_-' '/+')
    case $(( ${#PAYLOAD} % 4 )) in
        2) PADDED="${PADDED}==" ;;
        3) PADDED="${PADDED}=" ;;
    esac
    EXTRACTED=$(echo "$PADDED" | base64 -d 2>/dev/null \
        | python3 -c "import json,sys; print(json.load(sys.stdin).get('tenant_id','default'))" 2>/dev/null \
        || echo "default")
    if [ -n "$EXTRACTED" ]; then
        TENANT_ID="$EXTRACTED"
        log "Tenant ID from license: $TENANT_ID"
    fi
fi

cat > "$INSTALL_DIR/.env" << ENVEOF
HOST_IP=$HOST_IP
HOME_DIR=$HOME_DIR
INSTALL_DIR=$INSTALL_DIR
IFACE=$IFACE
DEPLOY_MODE=$DEPLOY_MODE
LOCAL_SENSOR_ID=local-central
TENANT_ID=$TENANT_ID
CLICKHOUSE_URL=$CLICKHOUSE_URL
CLICKHOUSE_URL_SECONDARY=$CLICKHOUSE_URL_SECONDARY
CLICKHOUSE_USER=$CLOUD_CH_USER
CLICKHOUSE_PASSWORD=$CLOUD_CH_PASS
KAFKA_BROKERS=$CLOUD_KAFKA
DATALAKE_URL=${PV_DATALAKE_URL:-}
DATALAKE_USER=${PV_DATALAKE_URL:+$CLOUD_CH_USER}
PRODUCT_MODE=$PRODUCT_MODE
PV_ROLE=${PV_ROLE:-allinone}
PV_MODULES=$PV_MODULES
# SIEM: the agents' gateway (8089, 8443) and the rules engine run in siem-api
PROVIGIL_MANAGER=$HAS_SIEM
PROVIGIL_REGISTRY=$REGISTRY
JWT_SECRET=$JWT_SECRET
NDR_AGENT_SECRET=$NDR_AGENT_SECRET
CORS_ORIGIN=https://${HOST_IP}:3000
ARKIME_URL=http://${HOST_IP}:8005
ARKIME_PASS=$ARKIME_PASS
OPENSEARCH_URL=http://${HOST_IP}:9200
OPENAI_API_KEY=$OPENAI_API_KEY
GROQ_API_KEY=
GROQ_MODEL=llama-3.3-70b-versatile
BEACON_WINDOW_HOURS=1
INGEST_RATE_LIMIT=0
SIEM_SYSLOG_HOST=
SIEM_SYSLOG_PORT=514
LICENSE_PUBLIC_KEY=$LICENSE_PUBLIC_KEY
LICENSE_TOKEN=$LICENSE_TOKEN
TENANT_ADMIN_USER=$TENANT_ADMIN_USER
TENANT_ADMIN_PASS=$TENANT_ADMIN_PASS
AGENT_KEYS_SECRET=${AGENT_KEYS_SECRET}
GATEWAY_INTERNAL_TOKEN=${GATEWAY_INTERNAL_TOKEN}
ENVEOF
log ".env generated"

# ── Sudoers ───────────────────────────────────
log "Configuring sudo permissions..."
cat << SUDOERS | sudo tee /etc/sudoers.d/ndr-stack > /dev/null
# NDR platform — restricted sudo for platform services only
Cmnd_Alias NDR_SYSTEMCTL = /usr/bin/systemctl daemon-reload, /usr/bin/systemctl start ndr-autoscaler, /usr/bin/systemctl stop ndr-autoscaler, /usr/bin/systemctl restart ndr-autoscaler, /usr/bin/systemctl enable ndr-autoscaler, /usr/bin/systemctl disable ndr-autoscaler, /usr/bin/systemctl start ndr-worker-autoscaler, /usr/bin/systemctl stop ndr-worker-autoscaler, /usr/bin/systemctl restart ndr-worker-autoscaler, /usr/bin/systemctl enable ndr-worker-autoscaler, /usr/bin/systemctl disable ndr-worker-autoscaler, /usr/bin/systemctl start ndr-updater, /usr/bin/systemctl stop ndr-updater, /usr/bin/systemctl restart ndr-updater, /usr/bin/systemctl enable ndr-updater, /usr/bin/systemctl start arkime-capture, /usr/bin/systemctl stop arkime-capture, /usr/bin/systemctl restart arkime-capture, /usr/bin/systemctl start arkime-viewer, /usr/bin/systemctl stop arkime-viewer, /usr/bin/systemctl restart arkime-viewer
Cmnd_Alias NDR_TEE       = /usr/bin/tee /etc/systemd/system/ndr-autoscaler.service, /usr/bin/tee /etc/systemd/system/ndr-worker-autoscaler.service
Cmnd_Alias NDR_IPTABLES  = /usr/sbin/iptables
$USERNAME ALL=(ALL)  NOPASSWD: NDR_SYSTEMCTL, NDR_TEE
$USERNAME ALL=(root) NOPASSWD: NDR_IPTABLES
SUDOERS
sudo chmod 440 /etc/sudoers.d/ndr-stack
log "Sudo configured"

log "NDR Agent skipped — Agent-S/Agent-Z run on remote sensor machines"

# ══════════════════════════════════════════════
step "Dashboard UI  (Angular)"

log "UI image will be pulled after container runtime is ready"

# ══════════════════════════════════════════════
step "Container Runtime  (Docker)"

log "Installing Docker..."
sudo apt-get remove -y docker docker-engine docker.io containerd runc 2>/dev/null || true
sudo apt-get update -qq 2>/dev/null || true
sudo apt-get install -y ca-certificates curl gnupg lsb-release 2>/tmp/ndr_cust_err \
  || err "Could not install ca-certificates/curl/gnupg/lsb-release ($(cat /tmp/ndr_cust_err 2>/dev/null)) — check network connectivity and re-run."

sudo mkdir -p /etc/apt/keyrings
sudo rm -f /etc/apt/keyrings/docker.gpg
curl -fsSL https://download.docker.com/linux/ubuntu/gpg 2>/tmp/ndr_cust_err \
    | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg 2>>/tmp/ndr_cust_err \
    || err "Could not fetch/import the Docker repo signing key ($(cat /tmp/ndr_cust_err 2>/dev/null)) — check internet access to download.docker.com (443)."
rm -f /tmp/ndr_cust_err
sudo chmod a+r /etc/apt/keyrings/docker.gpg

DOCKER_CODENAME=$(lsb_release -cs 2>/dev/null || echo "noble")
case "$DOCKER_CODENAME" in
    jammy|noble|focal)
        # Well-established codenames Docker's repo definitely carries —
        # skip the network check entirely so a transient blip can't wrongly
        # trigger a fallback (see the * arm below for why that matters).
        ;;
    *)
        # Unknown/bleeding-edge codename (e.g. resolute, oracular) — verify
        # Docker's repo actually has it, with one retry so a single transient
        # network blip doesn't wrongly fall back to noble: noble's packages
        # need a newer glibc than older codenames ship, so a bad fallback
        # here silently breaks the whole Docker install with a confusing
        # "unmet dependencies" error much later instead of failing here.
        REACHABLE=0
        for _try in 1 2; do
            if curl -fsSL "https://download.docker.com/linux/ubuntu/dists/${DOCKER_CODENAME}/InRelease" \
                   --max-time 5 -o /dev/null 2>/dev/null; then
                REACHABLE=1
                break
            fi
            sleep 2
        done
        if [ "$REACHABLE" != "1" ]; then
            log "Docker repo not available for '${DOCKER_CODENAME}' — falling back to noble"
            DOCKER_CODENAME="noble"
        fi
        ;;
esac

echo \
    "deb [arch=$(dpkg --print-architecture) \
    signed-by=/etc/apt/keyrings/docker.gpg] \
    https://download.docker.com/linux/ubuntu \
    ${DOCKER_CODENAME} stable" \
    | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt-get update -qq 2>/dev/null || true
sudo apt-get install -y docker-ce docker-ce-cli \
    containerd.io docker-buildx-plugin docker-compose-plugin 2>/tmp/ndr_cust_err \
    || err "Docker package install failed ($(cat /tmp/ndr_cust_err 2>/dev/null)) — check network connectivity and re-run."
rm -f /tmp/ndr_cust_err
log "Docker installed"

sudo mkdir -p /etc/docker
sudo tee /etc/docker/daemon.json > /dev/null << 'DOCKEREOF'
{
  "dns": ["8.8.8.8", "8.8.4.4"]
}
DOCKEREOF

sudo modprobe overlay 2>/dev/null || true
sudo modprobe br_netfilter 2>/dev/null || true
echo -e "overlay\nbr_netfilter" | sudo tee /etc/modules-load.d/docker.conf > /dev/null

log "Starting Docker service..."
sudo systemctl enable docker 2>/tmp/ndr_cust_err \
  || record_error "Docker" "systemctl enable docker failed ($(cat /tmp/ndr_cust_err 2>/dev/null))" \
    "Is this host running under real systemd? Docker may still start manually: sudo dockerd &"
rm -f /tmp/ndr_cust_err
sudo systemctl start docker || true
sudo usermod -aG docker "$USERNAME"
# Socket stays at default 660 (root:docker) — engine containers run as root and have access

log "Waiting for Docker to initialize..."
for i in {1..20}; do
    if sudo docker info >/dev/null 2>&1; then
        log "Docker is running"
        break
    fi
    [ $i -eq 10 ] && sudo systemctl restart docker || true
    echo -n "."
    sleep 3
done
echo ""
sudo docker info >/dev/null 2>&1 || err "Docker failed to start"

# ══════════════════════════════════════════════
step "Detection Stack  (Building)"

log "Building Docker stack (this may take a few minutes)..."
cd "$INSTALL_DIR"

# ── TLS certificate for Nginx ─────────────────────────────────────────────────
# Generated once before Docker starts so Nginx can find it at /etc/nginx/ssl/.
# Skipped automatically if a cert already exists (e.g. CA-signed cert placed by admin).
SSL_DIR="$INSTALL_DIR/config/nginx/ssl"
if [ ! -f "$SSL_DIR/ndr.crt" ] || [ ! -f "$SSL_DIR/ndr.key" ]; then
    log "Generating self-signed TLS certificate for $HOST_IP..."
    mkdir -p "$SSL_DIR"
    openssl req -x509 -nodes -days 730 -newkey rsa:2048 \
        -keyout "$SSL_DIR/ndr.key" \
        -out    "$SSL_DIR/ndr.crt" \
        -subj   "/CN=$HOST_IP" \
        -addext "subjectAltName=IP:$HOST_IP,IP:127.0.0.1,DNS:localhost" \
        2>/dev/null
    chmod 600 "$SSL_DIR/ndr.key"
    log "✅ TLS certificate generated → $SSL_DIR"
else
    log "TLS certificate already exists — skipping generation"
fi
# ─────────────────────────────────────────────────────────────────────────────

# nginx: the config/nginx/nginx.conf downloaded above with the rest of config/ is used as-is.
# (An embedded older copy used to be written here, overwriting the repo's file.)
log "Using config/nginx/nginx.conf"

sudo docker compose --profile onpremise down 2>/dev/null || true
sudo docker rm -f vector 2>/dev/null || true

# ProVigil's images this licence needs (the rest come from Docker Hub, or the offline kit)
PV_IMAGES="provigil-auth siem-api ndr-ui"
[ "$HAS_NDR" = 1 ] && PV_IMAGES="$PV_IMAGES ndr-engine"
if [ -n "${PV_OFFLINE_DIR:-}" ]; then
    log "Loading images from the offline kit..."
    for f in "$PV_OFFLINE_DIR"/images/*.tar.gz; do
        [ -f "$f" ] || continue
        sudo docker load -i "$f" >/dev/null 2>/tmp/ndr_cust_err || err "Could not load $f ($(cat /tmp/ndr_cust_err 2>/dev/null))"
        log "  loaded $(basename "$f")"
    done
else
    if [ -n "${REGISTRY_TOKEN:-}" ]; then
        echo "$REGISTRY_TOKEN" | sudo docker login "${REGISTRY%%/*}" -u ndr-customer --password-stdin >/dev/null 2>&1 \
            || err "Registry login failed — check your token and try again"
    fi
    log "Pulling the licensed images: $PV_IMAGES"
    for IMG in $PV_IMAGES; do
      sudo docker pull "${REGISTRY}/${IMG}:latest" 2>/tmp/ndr_cust_err \
        || err "Could not pull ${REGISTRY}/${IMG}:latest ($(cat /tmp/ndr_cust_err 2>/dev/null)) — check the registry token and network access, then re-run."
    done
fi
rm -f /tmp/ndr_cust_err
sed -i '/^PV_IMAGES=/d; /^PV_SERVICES=/d' "$INSTALL_DIR/.env"
echo "PV_IMAGES=${PV_IMAGES// /,}" >> "$INSTALL_DIR/.env"

# The compose override: the pre-built images instead of build:, and for the master role (the data
# lake is another PC) no service waits for local ClickHouse containers. One entry per service.
datalake_deps() {
    [ -n "${PV_DATALAKE_URL:-}" ] || return 0
    case "$1" in
        provigil-auth) printf '    depends_on: !override\n      ndr-valkey:\n        condition: service_healthy\n' ;;
        siem-api)      printf '    depends_on: !override\n      ndr-valkey:\n        condition: service_started\n' ;;
        ndr-engine-*)  printf '    depends_on: !override\n      kafka-init:\n        condition: service_completed_successfully\n      ndr-valkey:\n        condition: service_healthy\n' ;;
    esac
}
{
    echo "services:"
    for S in ndr-engine-1 ndr-engine-2 ndr-engine-3 provigil-auth ndr-ui siem-api; do
        case "$S" in ndr-engine-*) IMG=ndr-engine ;; *) IMG=$S ;; esac
        printf '  %s:\n    image: %s/%s:latest\n' "$S" "$REGISTRY" "$IMG"
        case "$S" in ndr-engine-*) ;; *) printf '    build: !reset null\n' ;; esac
        datalake_deps "$S"
    done
} > "$INSTALL_DIR/docker-compose.customer.yml"

# the services of the licensed modules (one list, also used by start.sh and the updater)
PV_SERVICES="ndr-valkey provigil-auth siem-api ndr-ui nginx"
[ -z "${PV_DATALAKE_URL:-}" ] && PV_SERVICES="clickhouse-keeper clickhouse1 clickhouse2 clickhouse-init $PV_SERVICES"
[ "$HAS_NDR" = 1 ] && PV_SERVICES="$PV_SERVICES kafka1 kafka2 kafka3 kafka-init ndr-engine-1 ndr-engine-2 ndr-engine-3 qdrant opensearch vector"
[ "$DEPLOY_MODE" = "hybrid" ] && PV_SERVICES="vector ndr-engine-1 nginx ndr-ui"
echo "PV_SERVICES=${PV_SERVICES// /,}" >> "$INSTALL_DIR/.env"

if [ "$DEPLOY_MODE" = "hybrid" ]; then
    log "Hybrid mode — using cloud: $CLOUD_KAFKA"
    sudo docker compose -f docker-compose.yml -f docker-compose.customer.yml \
        --profile onpremise up -d --no-build $PV_SERVICES 2>/tmp/ndr_cust_err \
        || err "docker compose up failed ($(cat /tmp/ndr_cust_err 2>/dev/null)) — check: sudo docker compose logs"
else
    log "Starting: $PV_SERVICES"
    sudo docker compose -f docker-compose.yml -f docker-compose.customer.yml \
        --profile onpremise up -d --no-build $PV_SERVICES 2>/tmp/ndr_cust_err \
        || err "docker compose up failed ($(cat /tmp/ndr_cust_err 2>/dev/null)) — check: sudo docker compose logs"
fi
rm -f /tmp/ndr_cust_err
log "Docker stack started"

if [ "$DEPLOY_MODE" = "local" ] && [ -z "${PV_DATALAKE_URL:-}" ]; then
    log "Waiting for ClickHouse node 1..."
    for i in {1..40}; do
        if curl -s http://localhost:8123/ping > /dev/null 2>&1; then
            log "ClickHouse node 1 ready"
            break
        fi
        echo -n "."
        sleep 3
    done
    echo ""

    if [ "${CH_NEEDS_IMPORT:-false}" = "true" ] && [ -d "/home/user/ch-export" ]; then
        log "Importing exported ClickHouse data into Docker container..."
        if bash "$INSTALL_DIR/scripts/ch-import.sh"; then
            log "Data migration complete"
        else
            record_error "ClickHouse Import" "ch-import.sh exited with an error — pre-existing data may not be fully migrated" \
                "Re-run manually once the stack is confirmed healthy: bash $INSTALL_DIR/scripts/ch-import.sh"
        fi
    fi
fi

if [ "$HAS_NDR" = 1 ]; then
log "Configuring Kafka retention..."
sleep 15
if sudo docker exec kafka1 \
    /opt/kafka/bin/kafka-configs.sh \
    --bootstrap-server localhost:9092 \
    --alter --entity-type topics \
    --entity-name ndr-events \
    --add-config retention.ms=86400000 \
    2>/tmp/ndr_cust_err; then
  log "Kafka retention set to 24 hours"
else
  record_error "Kafka" "setting retention.ms failed ($(cat /tmp/ndr_cust_err 2>/dev/null))" \
    "Non-fatal — topic still works with the broker default retention."
fi

log "Creating Kafka topic with 3 partitions..."
if sudo docker exec kafka1 /opt/kafka/bin/kafka-topics.sh \
    --bootstrap-server localhost:9092 \
    --create --if-not-exists \
    --topic ndr-events \
    --partitions 3 \
    --replication-factor 3 \
    2>/tmp/ndr_cust_err; then
  log "Kafka topic ready"
else
  record_error "Kafka" "topic creation failed ($(cat /tmp/ndr_cust_err 2>/dev/null))" \
    "Run manually once Kafka is confirmed healthy: sudo docker exec kafka1 /opt/kafka/bin/kafka-topics.sh --bootstrap-server localhost:9092 --create --topic ndr-events --partitions 3 --replication-factor 3"
fi
rm -f /tmp/ndr_cust_err
fi

# ══════════════════════════════════════════════
step "Search Index  (OpenSearch)"

if [ "$HAS_NDR" = 1 ]; then
log "Waiting for OpenSearch..."
cd "$INSTALL_DIR"
for i in {1..30}; do
    if curl -s http://localhost:9200 > /dev/null 2>&1; then
        log "OpenSearch ready"
        break
    fi
    echo -n "."
    sleep 3
done
echo ""

if [ -f /opt/arkime/bin/capture ]; then
    log "Initializing Packet Recorder database..."
    echo "yes" | sudo timeout 60 /opt/arkime/db/db.pl http://localhost:9200 init --ifneeded 2>&1 || \
        echo "yes" | sudo timeout 60 /opt/arkime/db/db.pl http://localhost:9200 init 2>&1 || true
    log "Packet Recorder database initialized"
    log "Creating Packet Recorder admin user..."
    sudo /opt/arkime/bin/arkime_add_user.sh admin "Admin" admin --admin 2>/dev/null \
        && log "Packet Recorder admin ready (user: admin / pass: admin)" \
        || warn "Packet Recorder admin creation failed — run manually after install"
fi
else
    log "Skipped — NDR is not licensed"
fi

# ══════════════════════════════════════════════
step "Response Automation  (SOAR)"

log "Native SOAR is built into the NDR engine — no extra services needed"
info "Configure playbooks, cases and integrations from the UI → SOAR page"

log "Skipped — UI runs from ndr-ui Docker container (no Node.js/Angular build needed)"

log "Waiting for ndr-ui container to be ready..."
for i in {1..30}; do
    if sudo docker exec ndr-ui curl -s http://localhost:80 > /dev/null 2>&1; then
        log "ndr-ui container ready"
        break
    fi
    echo -n "."
    sleep 3
done
echo ""

if grep -qi microsoft /proc/version 2>/dev/null; then
    warn "WSL2 detected — run in Windows PowerShell as Admin:"
    printf "\n"
    echo "  netsh interface portproxy add v4tov4 listenport=3000 listenaddress=0.0.0.0 connectport=3000 connectaddress=$HOST_IP"
    echo "  netsh interface portproxy add v4tov4 listenport=9092 listenaddress=0.0.0.0 connectport=9092 connectaddress=$HOST_IP"
    printf "\n"
fi

# ── NDR Updater: host-side watcher that applies engine/UI updates ─────
log "Installing NDR update watcher..."

cat > "$INSTALL_DIR/scripts/update-watcher.sh" << 'WATCHEREOF'
#!/bin/bash
# Host-side update watcher. Runs as a systemd service.
# The ndr-engine container writes /scripts/.update-requested (same path as
# ${INSTALL_DIR}/scripts/.update-requested on the host) to trigger an update.
INSTALL_DIR="$(dirname "$(dirname "$(realpath "$0")")")"
envv() { grep "^$1=" "$INSTALL_DIR/.env" 2>/dev/null | head -1 | cut -d= -f2-; }
FLAG="$INSTALL_DIR/scripts/.update-requested"

while true; do
    if [ -f "$FLAG" ]; then
        TARGET_VERSION=$(cat "$FLAG" 2>/dev/null || echo "")
        rm -f "$FLAG"
        logger -t ndr-updater "Update triggered → pulling ${TARGET_VERSION:-latest}"
        cd "$INSTALL_DIR" || exit 1
        # the images and services this install's licence has (written by the installer)
        REGISTRY=$(envv PROVIGIL_REGISTRY); REGISTRY=${REGISTRY:-ghcr.io/jithinjoseph-workspace}
        IMAGES=$(envv PV_IMAGES); IMAGES=${IMAGES:-ndr-engine,provigil-auth,ndr-ui,siem-api}
        SERVICES=$(envv PV_SERVICES)
        for IMG in ${IMAGES//,/ }; do
            docker pull "${REGISTRY}/${IMG}:latest" 2>&1 | logger -t ndr-updater
        done
        docker compose -f docker-compose.yml -f docker-compose.customer.yml \
            --profile onpremise up -d --no-build ${SERVICES//,/ } 2>&1 | logger -t ndr-updater
        logger -t ndr-updater "Update complete"
    fi
    sleep 30
done
WATCHEREOF
chmod +x "$INSTALL_DIR/scripts/update-watcher.sh"

sudo tee /etc/systemd/system/ndr-updater.service > /dev/null << EOF
[Unit]
Description=NDR Update Watcher
After=docker.service
Requires=docker.service

[Service]
Type=simple
ExecStart=$INSTALL_DIR/scripts/update-watcher.sh
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

sudo tee /etc/systemd/system/ndr.service > /dev/null << EOF
[Unit]
Description=NDR Platform
After=docker.service network-online.target
Requires=docker.service
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=$INSTALL_DIR
ExecStart=/bin/bash $INSTALL_DIR/start.sh
ExecStop=/bin/bash $INSTALL_DIR/stop.sh
TimeoutStartSec=300

[Install]
WantedBy=multi-user.target
EOF

if sudo systemctl daemon-reload 2>/tmp/ndr_cust_err; then
  sudo systemctl enable ndr.service 2>/dev/null || true
  log "NDR auto-start on boot enabled"
else
  record_error "Service Setup" "systemctl daemon-reload failed ($(cat /tmp/ndr_cust_err 2>/dev/null))" \
    "Is this host running under real systemd? The Docker stack is already up regardless — this only affects auto-start-on-reboot."
fi
sudo systemctl enable --now ndr-updater.service 2>/tmp/ndr_cust_err \
  && log "NDR update watcher installed and running" \
  || record_error "Service Setup" "ndr-updater.service could not be started ($(cat /tmp/ndr_cust_err 2>/dev/null))" \
    "Non-fatal — the platform runs fine without it, just won't auto-update. Check: sudo systemctl status ndr-updater"
rm -f /tmp/ndr_cust_err

# ══════════════════════════════════════════════
step "Verification"

log "Verifying installation..."
info "Mode:       $DEPLOY_MODE  (role ${PV_ROLE:-allinone})"
info "Modules:    ${PV_MODULES:-all}"
info "Interface:  $IFACE  ($HOST_IP)"
if [ -n "${CAPTURE_IFACE:-}" ]; then
    info "Capture:    $CAPTURE_IFACE (listen only; the packet recorder uses it)"
    info "Analysers:  add Zeek and Suricata on this card: console Sensors, Add sensor (key), then"
    info "            sudo bash $INSTALL_DIR/scripts/install-sensor.sh --cloud-url https://127.0.0.1 --tenant-id $TENANT_ID --api-key <key> --interface $CAPTURE_IFACE --mode tap"
else
    info "Sensors:    remote (install.sh, role NDR sensor, on boxes at the mirror port or TAP)"
fi
info "Docker:     $(sudo docker --version)"
info "ndr-ui:     $(sudo docker inspect --format='{{.State.Status}}' ndr-ui 2>/dev/null || echo 'not started')"
if [ -n "${PV_DATALAKE_URL:-}" ]; then
    info "Data lake:  $PV_DATALAKE_URL"
elif [ "$DEPLOY_MODE" = "local" ]; then
    info "ClickHouse: $(curl -s http://localhost:8123/ping 2>/dev/null || echo 'starting...')"
else
    info "ClickHouse: $CLOUD_CLICKHOUSE  (cloud)"
    info "Kafka:      $CLOUD_KAFKA  (cloud)"
fi
info "NDR Agent:  $(curl -s http://localhost:3001/agent/status 2>/dev/null || echo 'starting...')"

# ── Completion banner ─────────────────────────
_pad() { printf '%-44s' "$1"; }

printf "\n\n"
printf "  ${CYAN}╔══════════════════════════════════════════════╗${NC}\n"
printf "  ${CYAN}║${NC}                                              ${CYAN}║${NC}\n"
printf "  ${CYAN}║${NC}  ${GREEN}${BOLD}      INSTALLATION COMPLETE               ${NC}  ${CYAN}║${NC}\n"
printf "  ${CYAN}║${NC}  ${DIM}         Proma Alpha v1.0  —  Proma Secure  ${NC}  ${CYAN}║${NC}\n"
printf "  ${CYAN}║${NC}                                              ${CYAN}║${NC}\n"
printf "  ${CYAN}╠══════════════════════════════════════════════╣${NC}\n"
printf "  ${CYAN}║${NC}  $(_pad "Mode:       ${DEPLOY_MODE}")${CYAN}║${NC}\n"
printf "  ${CYAN}║${NC}  $(_pad "Interface:  ${IFACE}  (${HOST_IP})")${CYAN}║${NC}\n"
printf "  ${CYAN}║${NC}  $(_pad "Modules:    ${PV_MODULES:-all}")${CYAN}║${NC}\n"
printf "  ${CYAN}╠══════════════════════════════════════════════╣${NC}\n"
printf "  ${CYAN}║${NC}  ${BOLD}$(_pad "Service         Access Point")${NC}  ${CYAN}║${NC}\n"
printf "  ${CYAN}║${NC}  ${DIM}$(_pad "─────────────── ────────────────────────")${NC}  ${CYAN}║${NC}\n"
printf "  ${CYAN}║${NC}  $(_pad "Dashboard       https://${HOST_IP}:3000")${CYAN}║${NC}\n"
printf "  ${CYAN}║${NC}  $(_pad "API Gateway     https://${HOST_IP}:3000")${CYAN}║${NC}\n"
printf "  ${CYAN}║${NC}  $(_pad "NDR Agent       http://localhost:3001")${CYAN}║${NC}\n"
[ "$HAS_NDR" = 1 ] && printf "  ${CYAN}║${NC}  $(_pad "Packet Recorder http://localhost:8005")${CYAN}║${NC}\n"
[ "$HAS_SIEM" = 1 ] && printf "  ${CYAN}║${NC}  $(_pad "SIEM agents     ${HOST_IP}:8089 / 8443")${CYAN}║${NC}\n"
printf "  ${CYAN}╠══════════════════════════════════════════════╣${NC}\n"
printf "  ${CYAN}║${NC}  $(_pad "start:    ./start.sh")${CYAN}║${NC}\n"
printf "  ${CYAN}║${NC}  $(_pad "stop:     ./stop.sh")${CYAN}║${NC}\n"
printf "  ${CYAN}║${NC}  $(_pad "status:   ./status.sh")${CYAN}║${NC}\n"
printf "  ${CYAN}╚══════════════════════════════════════════════╝${NC}\n"
printf "\n"
printf "  ${DIM}Proma Secure — Network Detection & Response Platform${NC}\n\n"
