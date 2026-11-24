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

# ── If running from a fresh machine (no repo yet), clone it first ──
# When a customer downloads just this script and runs it, it clones
# the full repo then re-executes itself from inside it.
if [ ! -f "$(dirname "$0")/docker-compose.yml" ]; then
    echo ""
    echo "  NDR repo not found locally — cloning from GitHub..."
    echo ""
    read -rp "  GitHub token (provided by your NDR vendor): " GH_TOKEN
    read -rp "  Install directory [default: /opt/ndr]: " CLONE_DIR
    CLONE_DIR="${CLONE_DIR:-/opt/ndr}"
    sudo git clone "https://${GH_TOKEN}@github.com/jithinjoseph-workspace/NDR-Demo.git" "$CLONE_DIR"
    sudo chown -R "$USER:$USER" "$CLONE_DIR"
    exec bash "$CLONE_DIR/install.sh" "$@"
fi

# ── Fix DNS early — before any curl/apt/wget ──
if ! curl -s --max-time 3 https://archive.ubuntu.com > /dev/null 2>&1; then
    echo "[NDR] Fixing DNS (switching to 8.8.8.8)..."
    if systemctl is-active systemd-resolved > /dev/null 2>&1; then
        # Configure resolved properly — stopping it breaks DNS on reboot
        sudo mkdir -p /etc/systemd/resolved.conf.d/
        printf "[Resolve]\nDNS=8.8.8.8 8.8.4.4\nFallbackDNS=1.1.1.1\n" \
            | sudo tee /etc/systemd/resolved.conf.d/ndr-dns.conf > /dev/null
        sudo systemctl restart systemd-resolved 2>/dev/null || true
    else
        printf "nameserver 8.8.8.8\nnameserver 8.8.4.4\n" | sudo tee /etc/resolv.conf > /dev/null
    fi
fi

# ── Force apt to use IPv4 — many hosts have no real IPv6 route, only
# link-local, which makes apt fail against dual-stack mirrors (e.g.
# archive.ubuntu.com) instead of falling back to IPv4 cleanly ──
echo 'Acquire::ForceIPv4 "true";' | sudo tee /etc/apt/apt.conf.d/99force-ipv4 > /dev/null

# ── Colors ────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

# ── Log helpers ───────────────────────────────
log()  { echo -e "  ${GREEN}[+]${NC} $1"; }
warn() { echo -e "  ${YELLOW}[!]${NC} $1"; }
err()  { echo -e "  ${RED}[x]${NC} $1"; exit 1; }
info() { echo -e "  ${BLUE}[>]${NC} $1"; }
hdr()  {
    echo -e ""
    echo -e "  ${CYAN}${BOLD}┌─────────────────────────────────────────────┐${NC}"
    printf  "  ${CYAN}${BOLD}│${NC}  %-43s${CYAN}${BOLD}│${NC}\n" "$1"
    echo -e "  ${CYAN}${BOLD}└─────────────────────────────────────────────┘${NC}"
}

# ── Banner ────────────────────────────────────
clear
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
validate_ubuntu_codename() {
    local candidate="${1:-}"
    [ -n "$candidate" ] || return 1
    curl -fsSL --max-time 8 "https://archive.ubuntu.com/ubuntu/dists/${candidate}/InRelease" > /dev/null 2>&1
}

resolve_ubuntu_codename() {
    local candidate="${1:-}"
    local fallback=""

    if [ -n "$candidate" ] && validate_ubuntu_codename "$candidate"; then
        echo "$candidate"
        return 0
    fi

    case "${UBUNTU_MAJOR_VER:-}" in
        24) fallback="noble" ;;
        23) fallback="lunar" ;;
        22) fallback="jammy" ;;
        21) fallback="impish" ;;
        20) fallback="focal" ;;
        19) fallback="disco" ;;
        18) fallback="bionic" ;;
        17) fallback="zesty" ;;
        16) fallback="xenial" ;;
        15) fallback="wily" ;;
        14) fallback="trusty" ;;
        *) fallback="" ;;
    esac

    if [ -n "$fallback" ] && validate_ubuntu_codename "$fallback"; then
        echo "$fallback"
        return 0
    fi

    return 1
}

UBUNTU_CODENAME=$(. /etc/os-release 2>/dev/null && echo "$VERSION_CODENAME")
UBUNTU_CODENAME=${UBUNTU_CODENAME:-$(lsb_release -cs 2>/dev/null)}
UBUNTU_CODENAME=${UBUNTU_CODENAME:-$(grep -oP "(?<=UBUNTU_CODENAME=).+" /etc/os-release 2>/dev/null)}
UBUNTU_MAJOR_VER=$(. /etc/os-release 2>/dev/null && echo "${VERSION_ID}" | cut -d. -f1)

if [ -n "$UBUNTU_CODENAME" ]; then
    UBUNTU_CODENAME=$(resolve_ubuntu_codename "$UBUNTU_CODENAME" 2>/dev/null || echo "$UBUNTU_CODENAME")
fi

if [ -z "$UBUNTU_CODENAME" ]; then
    UBUNTU_CODENAME="noble"
    warn "Detected Ubuntu codename is unsupported or unreachable; using fallback codename 'noble'"
fi

log "Ubuntu ${UBUNTU_CODENAME} (${UBUNTU_MAJOR_VER:-unknown}.x) detected"

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
        warn "security.ubuntu.com/${UBUNTU_CODENAME}-security not yet available — skipping (non-fatal)"
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

# Fresh Ubuntu installs run unattended-upgrades on first boot and hold the apt lock.
# Stop it and wait for any existing lock to clear before proceeding.
sudo systemctl stop unattended-upgrades 2>/dev/null || true
sudo systemctl stop apt-daily.service apt-daily-upgrade.service 2>/dev/null || true
log "Waiting for apt lock..."
for _apt_i in {1..24}; do
    if ! fuser /var/lib/dpkg/lock-frontend /var/lib/apt/lists/lock \
               /var/cache/apt/archives/lock >/dev/null 2>&1; then
        break
    fi
    echo -n "."
    sleep 5
done
echo ""

log "Updating package lists..."
_APT_LOG=$(mktemp /tmp/ndr-apt.XXXXXX)
sudo timeout 120 apt-get update 2>&1 \
    | tee "$_APT_LOG" \
    | grep --line-buffered -E "^Get|^Hit|^Err|^W:" || true
if grep -q "^Err" "$_APT_LOG" 2>/dev/null; then
    warn "apt-get update had errors — retrying once..."
    sudo timeout 120 apt-get update 2>&1 \
        | tee "$_APT_LOG" \
        | grep --line-buffered -E "^Get|^Hit|^Err|^W:" || true
fi
rm -f "$_APT_LOG"
log "Network ready"

# ── Product Selection ─────────────────────────
printf "\n"
printf "  ${CYAN}┌──────────────────────────────────────────────┐${NC}\n"
printf "  ${CYAN}│${NC}  ${BOLD}Select Product to Deploy${NC}                      ${CYAN}│${NC}\n"
printf "  ${CYAN}├──────────────────────────────────────────────┤${NC}\n"
printf "  ${CYAN}│${NC}  ${GREEN}[1]${NC} NDR only   — Network Detection & Response  ${CYAN}│${NC}\n"
printf "  ${CYAN}│${NC}       Agent-Z · Agent-S · Alerts · PCAP       ${CYAN}│${NC}\n"
printf "  ${CYAN}│${NC}                                              ${CYAN}│${NC}\n"
printf "  ${CYAN}│${NC}  ${BLUE}[2]${NC} SIEM only  — Log Ingest & Analytics        ${CYAN}│${NC}\n"
printf "  ${CYAN}│${NC}       Windows · Syslog · CEF · Dashboard      ${CYAN}│${NC}\n"
printf "  ${CYAN}│${NC}                                              ${CYAN}│${NC}\n"
printf "  ${CYAN}│${NC}  ${YELLOW}[3]${NC} NDR + SIEM — Full XDR Platform            ${CYAN}│${NC}\n"
printf "  ${CYAN}│${NC}       Complete detection + log analytics      ${CYAN}│${NC}\n"
printf "  ${CYAN}└──────────────────────────────────────────────┘${NC}\n"
printf "\n"
read -p "  Enter choice (1/2/3) [default: 1]: " PRODUCT_CHOICE

case "$PRODUCT_CHOICE" in
    2)
        PRODUCT_MODE="siem"
        log "Product: SIEM only"
        ;;
    3)
        PRODUCT_MODE="both"
        log "Product: NDR + SIEM (full XDR)"
        ;;
    *)
        PRODUCT_MODE="ndr"
        log "Product: NDR only"
        ;;
esac

printf "\n"

# ── Deployment Mode ───────────────────────────
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

# Write a minimal .env immediately so docker compose never sees blank variables.
# The network step overwrites this with full values once HOST_IP/JWT_SECRET are known.
IFACE_EARLY=$(ip -o -4 addr show 2>/dev/null | grep -v "127.0.0.1\|docker\|br-\|veth" | awk '{print $2}' | head -1)
IFACE_EARLY=${IFACE_EARLY:-eth0}
HOST_IP_EARLY=$(ip -o -4 addr show "$IFACE_EARLY" 2>/dev/null | awk '{print $4}' | cut -d/ -f1)
HOST_IP_EARLY=${HOST_IP_EARLY:-$(hostname -I | awk '{print $1}')}
JWT_SECRET_EARLY=$(openssl rand -hex 32 2>/dev/null || echo "changeme-$(date +%s)")
NDR_AGENT_SECRET_EARLY=$(openssl rand -hex 32 2>/dev/null || echo "changeme-agent-$(date +%s)")

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
LICENSE_PRIVATE_KEY=
LICENSE_PUBLIC_KEY=
LICENSE_TOKEN=
_EARLY_ENV
log ".env written early (will be updated with final values in network step)"

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

log "Installing packages..."
sudo apt-get install -y \
    curl wget git jq python3 python3-pip \
    net-tools iproute2 \
    netcat-traditional \
    arp-scan iputils-arping snmp \
    libpcre3 2>/dev/null || true

# scapy needed for ARP isolation in ndr-agent
pip3 install scapy --break-system-packages -q 2>/dev/null || pip3 install scapy -q 2>/dev/null || true

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

NODE_VER=$(node --version 2>/dev/null || echo "none")
NODE_MAJOR=$(echo $NODE_VER | cut -d. -f1 | tr -d 'v')

if [ "${NODE_MAJOR:-0}" -ge 18 ] 2>/dev/null; then
    log "Node.js already installed: $NODE_VER"
else
    if [ "${NODE_MAJOR:-0}" -lt 18 ] && [ "$NODE_VER" != "none" ]; then
        log "Removing old Node.js $NODE_VER..."
        sudo apt-get remove -y nodejs npm 2>/dev/null || true
        sudo apt-get autoremove -y 2>/dev/null || true
    fi
    curl -fsSL https://deb.nodesource.com/setup_20.x \
        | sudo -E bash - 2>/dev/null || true
    sudo apt-get install -y nodejs 2>/dev/null || true
fi

NODE_VER=$(node --version 2>/dev/null || echo "missing")
NPM_VER=$(npm --version 2>/dev/null || echo "missing")
log "Node.js: $NODE_VER  |  npm: $NPM_VER"

if ! command -v ng &>/dev/null; then
    log "Installing Angular CLI..."
    sudo npm install -g @angular/cli 2>/dev/null || \
        npm install -g @angular/cli 2>/dev/null || \
        warn "Angular CLI install failed"
    log "Angular CLI: $(ng version --skip-confirmation 2>/dev/null | grep 'Angular CLI' | head -1)"
else
    log "Angular CLI already installed: $(ng version --skip-confirmation 2>/dev/null | grep 'Angular CLI' | head -1)"
fi

# ══════════════════════════════════════════════
step "Agent-S"

if ! command -v suricata &>/dev/null; then
    log "Installing Agent-S..."
    sudo rm -rf /var/lib/apt/lists/* 2>/dev/null || true
    sudo apt-get update -qq 2>/dev/null || true
    if sudo apt-get install -y suricata 2>/dev/null; then
        log "Agent-S installed from repository"
    else
        warn "Agent-S install failed — skipping"
    fi
    sudo suricata-update 2>/dev/null || true
    sudo systemctl disable suricata 2>/dev/null || true
    sudo systemctl stop suricata 2>/dev/null || true
    log "Agent-S ready"
else
    log "Agent-S already installed"
    sudo systemctl disable suricata 2>/dev/null || true
    sudo systemctl stop suricata 2>/dev/null || true
fi

# ── Packet Recorder (Arkime) ──────────────────
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

# ══════════════════════════════════════════════
step "Agent-Z"

if ! command -v /opt/zeek/bin/zeek &>/dev/null; then
    log "Installing Agent-Z..."
    # Probe Zeek OBS repo dynamically — no hardcoded version fallbacks
    ZEEK_UBUNTU_VER="$OS_VERSION"
    ZEEK_VERSIONS=$(curl -fsSL --max-time 10 \
        "https://download.opensuse.org/repositories/security:zeek/" 2>/dev/null \
        | grep -oP 'xUbuntu_[\d.]+' | grep -oP '[\d.]+' | sort -rV)
    for TRY_VER in "$OS_VERSION" $ZEEK_VERSIONS; do
        ZEEK_KEY_URL="https://download.opensuse.org/repositories/security:zeek/xUbuntu_${TRY_VER}/Release.key"
        if curl -fsSL --max-time 10 "$ZEEK_KEY_URL" -o /dev/null 2>/dev/null; then
            ZEEK_UBUNTU_VER="$TRY_VER"
            break
        fi
    done
    log "Using Agent-Z repo for Ubuntu ${ZEEK_UBUNTU_VER}"
    echo "deb http://download.opensuse.org/repositories/security:/zeek/xUbuntu_${ZEEK_UBUNTU_VER}/ /" \
        | sudo tee /etc/apt/sources.list.d/security:zeek.list
    curl -fsSL "https://download.opensuse.org/repositories/security:zeek/xUbuntu_${ZEEK_UBUNTU_VER}/Release.key" \
        | gpg --dearmor \
        | sudo tee /etc/apt/trusted.gpg.d/security_zeek.gpg > /dev/null
    sudo apt-get update -qq 2>/dev/null || true
    if sudo apt-get install -y zeek 2>/dev/null; then
        log "Agent-Z installed"
    else
        warn "Agent-Z install failed — check repo availability for Ubuntu ${ZEEK_UBUNTU_VER}"
    fi
else
    log "Agent-Z already installed"
fi

# ══════════════════════════════════════════════
step "Analytics Database  (ClickHouse)"

if [ "$DEPLOY_MODE" = "local" ]; then
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
IFACE=$(ip -o -4 addr show 2>/dev/null | \
    grep -v "127.0.0.1\|docker\|br-\|veth" | \
    awk '{print $2}' | head -1)
[ -z "$IFACE" ] && IFACE="eth0"
log "Using interface: $IFACE"
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

# ── Configure Zeek ────────────────────────────
log "Configuring Agent-Z..."
# Write local.zeek — only load scripts that actually exist on this Zeek version
ZEEK_SITE=/opt/zeek/share/zeek/site
ZEEK_BASE=/opt/zeek/share/zeek

zeek_load() {
    local s="$1"
    for d in "$ZEEK_BASE" "$ZEEK_BASE/policy" "$ZEEK_BASE/base"; do
        [ -f "$d/$s.zeek" ] || [ -f "$d/$s" ] && { echo "@load $s"; return; }
    done
    if [[ "$s" == *"detect-sql-injection"* ]]; then
        local alt="${s/detect-sql-injection/detect-sqli}"
        for d in "$ZEEK_BASE" "$ZEEK_BASE/policy" "$ZEEK_BASE/base"; do
            [ -f "$d/$alt.zeek" ] || [ -f "$d/$alt" ] && { echo "@load $alt"; return; }
        done
    fi
    echo "  [zeek] skipping missing script: $s" >&2
}

sudo tee "$ZEEK_SITE/local.zeek" > /dev/null << ZEEKCONF
# NDR Stack — Zeek Configuration
@load policy/tuning/json-logs.zeek
@load policy/protocols/conn/community-id-logging
$(zeek_load protocols/ssh/detect-bruteforcing)
$(zeek_load protocols/ssl/validate-certs)
$(zeek_load protocols/http/detect-sql-injection)
$(zeek_load protocols/http/detect-webapps)
$(zeek_load misc/detect-traceroute)
$(zeek_load frameworks/files/hash-all-files)
$(zeek_load frameworks/files/detect-MHR)
$(zeek_load policy/frameworks/software/vulnerable)
$(zeek_load policy/frameworks/software/version-changes)
$(zeek_load policy/frameworks/software/windows-version-detection)
@load policy/protocols/conn/known-hosts
@load policy/protocols/conn/known-services
@load policy/tuning/track-all-assets.zeek
@load policy/protocols/http/software.zeek
@load policy/protocols/dhcp/software.zeek
@load policy/protocols/ssh/software.zeek
@load ndr-arp

redef tcp_inactivity_timeout  = 15 secs;
redef udp_inactivity_timeout  = 15 secs;
redef icmp_inactivity_timeout = 10 secs;
ZEEKCONF

sudo tee /opt/zeek/share/zeek/site/ndr-arp.zeek > /dev/null << 'ARPSCRIPT'
module ARP;

export {
    redef enum Log::ID += { LOG };

    type Info: record {
        ts:        time    &log;
        operation: string  &log;
        mac:       string  &log;
        dst_mac:   string  &log;
        ip:        addr    &log;
        dst_ip:    addr    &log;
    };
}

# NDR sensor self-exclusion — ndr-agent rewrites this file at every Start
# with the real sensor MAC and IP so ARP isolation doesn't self-alert.
# Empty sets here are safe: Zeek loads them only if agent hasn't started yet.
const NDR_SENSOR_MACS: set[string] = {};
const NDR_SENSOR_IPS:  set[addr]   = {};

event zeek_init() &priority=5
{
    Log::create_stream(ARP::LOG, [$columns=Info, $path="arp"]);
}

event arp_request(mac_src: string, mac_dst: string,
                  SPA: addr, SHA: string,
                  TPA: addr, THA: string)
{
    if (SHA in NDR_SENSOR_MACS) return;
    if (SPA in NDR_SENSOR_IPS)  return;
    Log::write(ARP::LOG, Info(
        $ts        = network_time(),
        $operation = "request",
        $mac       = SHA,
        $dst_mac   = mac_dst,
        $ip        = SPA,
        $dst_ip    = TPA
    ));
}

event arp_reply(mac_src: string, mac_dst: string,
                SPA: addr, SHA: string,
                TPA: addr, THA: string)
{
    if (SHA in NDR_SENSOR_MACS) return;
    if (SPA in NDR_SENSOR_IPS)  return;
    Log::write(ARP::LOG, Info(
        $ts        = network_time(),
        $operation = "reply",
        $mac       = SHA,
        $dst_mac   = THA,
        $ip        = SPA,
        $dst_ip    = TPA
    ));
}
ARPSCRIPT

/opt/zeek/bin/zkg install zeek/corelight/zeek-community-id \
    --force >/dev/null 2>&1 || true
log "Agent-Z configured"

sudo tee /etc/logrotate.d/zeek-ndr > /dev/null << 'EOF'
/home/user/logs/zeek/*.log {
    su root root
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    copytruncate
    dateext
    dateformat -%Y%m%d
}
EOF
log "Agent-Z log rotation configured"

# ── Configure Suricata ────────────────────────
log "Configuring Agent-S..."
sudo cp /etc/suricata/suricata.yaml \
    /etc/suricata/suricata.yaml.bak 2>/dev/null || true
sudo sed -i 's/community-id: false/community-id: true/g' \
    /etc/suricata/suricata.yaml 2>/dev/null || true
sudo sed -i "s|default-log-dir: /var/log/suricata|default-log-dir: $HOME_DIR/logs/suricata|g" \
    /etc/suricata/suricata.yaml 2>/dev/null || true
sudo sed -i "s|interface: eth0|interface: $IFACE|g" \
    /etc/suricata/suricata.yaml 2>/dev/null || true
log "Updating Agent-S rules..."
sudo suricata-update >/dev/null 2>&1 || true
log "Agent-S configured on interface: $IFACE"

log "Configuring Agent-S suppression..."
THRESHOLD_FILE="/etc/suricata/threshold.conf"
sudo touch "$THRESHOLD_FILE"
if sudo grep -q "threshold-file:" /etc/suricata/suricata.yaml 2>/dev/null; then
    sudo sed -i "s|threshold-file:.*|threshold-file: $THRESHOLD_FILE|g" /etc/suricata/suricata.yaml
else
    echo "threshold-file: $THRESHOLD_FILE" | sudo tee -a /etc/suricata/suricata.yaml > /dev/null
fi
log "Agent-S suppression ready"

log "Configuring Agent-Z suppression..."
sudo tee /opt/zeek/share/zeek/site/ndr-suppress.zeek > /dev/null << 'ZEEKSUPPRESS'
# NDR suppression filters — managed dynamically by NDR engine
# Hooks are appended here via suppress_sid commands; do not edit manually
ZEEKSUPPRESS
if ! sudo grep -q "ndr-suppress" /opt/zeek/share/zeek/site/local.zeek 2>/dev/null; then
    echo "@load ndr-suppress" | sudo tee -a /opt/zeek/share/zeek/site/local.zeek > /dev/null
fi
log "Agent-Z suppression ready"

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

sudo tee /etc/logrotate.d/suricata-ndr > /dev/null << 'EOF'
/home/user/logs/suricata/eve.json {
    su root root
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    copytruncate
    dateext
    dateformat -%Y%m%d
}
EOF
log "Agent-S log rotation configured"

# ── Directories ───────────────────────────────
log "Creating runtime directories..."
mkdir -p "$HOME_DIR/logs/suricata" "$HOME_DIR/logs/zeek"
mkdir -p "$HOME_DIR/.vector/data/suricata" "$HOME_DIR/.vector/data/zeek"
mkdir -p "$HOME_DIR/ndr-config"
sudo mkdir -p /opt/ndr/pcap /opt/ndr/evidence
sudo chmod -R 755 /opt/ndr
sudo chown -R "$USER:$USER" /opt/ndr
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

# ── Arkime password — generated once, preserved across reinstalls ──
if [ -f "$INSTALL_DIR/.env" ] && grep -q "^ARKIME_PASS=." "$INSTALL_DIR/.env"; then
    ARKIME_PASS=$(grep "^ARKIME_PASS=" "$INSTALL_DIR/.env" | cut -d= -f2-)
else
    ARKIME_PASS=$(openssl rand -hex 12 2>/dev/null || echo "$(date +%s%N | sha256sum | head -c 24)")
fi

# ── RSA license key pair (generated once; private key stays on this server) ──
if [ -f "$INSTALL_DIR/.env" ] && grep -q "LICENSE_PRIVATE_KEY" "$INSTALL_DIR/.env"; then
    LICENSE_PRIVATE_KEY=$(grep "^LICENSE_PRIVATE_KEY=" "$INSTALL_DIR/.env" | cut -d= -f2-)
    LICENSE_PUBLIC_KEY=$(grep "^LICENSE_PUBLIC_KEY=" "$INSTALL_DIR/.env" | cut -d= -f2-)
fi
if [ -z "$LICENSE_PRIVATE_KEY" ]; then
    printf "\n"
    log "Generating RSA-2048 key pair for license signing..."
    _TMP_KEY=$(mktemp)
    openssl genrsa -out "$_TMP_KEY" 2048 2>/dev/null
    LICENSE_PRIVATE_KEY=$(cat "$_TMP_KEY" | base64 -w0)
    LICENSE_PUBLIC_KEY=$(openssl rsa -in "$_TMP_KEY" -pubout 2>/dev/null | base64 -w0)
    rm -f "$_TMP_KEY"
    log "RSA key pair generated and stored in .env (base64-encoded)"
fi

if [ -f "$INSTALL_DIR/.env" ] && grep -q "LICENSE_TOKEN" "$INSTALL_DIR/.env"; then
    LICENSE_TOKEN=$(grep "^LICENSE_TOKEN=" "$INSTALL_DIR/.env" | cut -d= -f2-)
fi

# Auto-extract TENANT_ID from the license token so events are stored under
# the correct tenant, not hardcoded "default".
TENANT_ID="default"
if [ -n "$LICENSE_TOKEN" ]; then
    PAYLOAD=$(echo "$LICENSE_TOKEN" | cut -d. -f2)
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
TRUSTED_SOURCE_CIDRS=
PRODUCT_MODE=$PRODUCT_MODE
IP_TOKEN_KEY=$(openssl rand -hex 32 2>/dev/null || echo "change-me-in-production")
LICENSE_PRIVATE_KEY=$LICENSE_PRIVATE_KEY
LICENSE_PUBLIC_KEY=$LICENSE_PUBLIC_KEY
LICENSE_TOKEN=$LICENSE_TOKEN
ENVEOF
log ".env generated"

# ── Sudoers ───────────────────────────────────
log "Configuring sudo permissions..."
cat << SUDOERS | sudo tee /etc/sudoers.d/ndr-stack > /dev/null
# NDR stack — restricted sudo (each command locked to its specific purpose)
Cmnd_Alias NDR_SURICATA  = /usr/bin/suricata, /usr/bin/suricatasc
Cmnd_Alias NDR_ZEEK      = /opt/zeek/bin/zeek
Cmnd_Alias NDR_PKILL     = /usr/bin/pkill suricata, /usr/bin/pkill -9 suricata, /usr/bin/pkill zeek, /usr/bin/pkill -9 zeek, /usr/bin/pkill -f suricata, /usr/bin/pkill -f zeek
Cmnd_Alias NDR_PGREP     = /usr/bin/pgrep suricata, /usr/bin/pgrep zeek, /usr/bin/pgrep -f suricata, /usr/bin/pgrep -f zeek, /usr/bin/pgrep -x zeek
Cmnd_Alias NDR_SYSTEMCTL = /usr/bin/systemctl daemon-reload, /usr/bin/systemctl start ndr-agent, /usr/bin/systemctl stop ndr-agent, /usr/bin/systemctl restart ndr-agent, /usr/bin/systemctl enable ndr-agent, /usr/bin/systemctl disable ndr-agent, /usr/bin/systemctl status ndr-agent, /usr/bin/systemctl start ndr-autoscaler, /usr/bin/systemctl stop ndr-autoscaler, /usr/bin/systemctl restart ndr-autoscaler, /usr/bin/systemctl enable ndr-autoscaler, /usr/bin/systemctl disable ndr-autoscaler, /usr/bin/systemctl start ndr-worker-autoscaler, /usr/bin/systemctl stop ndr-worker-autoscaler, /usr/bin/systemctl restart ndr-worker-autoscaler, /usr/bin/systemctl enable ndr-worker-autoscaler, /usr/bin/systemctl disable ndr-worker-autoscaler, /usr/bin/systemctl start ndr-updater, /usr/bin/systemctl stop ndr-updater, /usr/bin/systemctl restart ndr-updater, /usr/bin/systemctl enable ndr-updater, /usr/bin/systemctl start ndr-vector, /usr/bin/systemctl stop ndr-vector, /usr/bin/systemctl restart ndr-vector, /usr/bin/systemctl enable ndr-vector, /usr/bin/systemctl start suricata, /usr/bin/systemctl stop suricata, /usr/bin/systemctl restart suricata, /usr/bin/systemctl start zeek, /usr/bin/systemctl stop zeek, /usr/bin/systemctl start arkime-capture, /usr/bin/systemctl stop arkime-capture, /usr/bin/systemctl restart arkime-capture, /usr/bin/systemctl start arkime-viewer, /usr/bin/systemctl stop arkime-viewer, /usr/bin/systemctl restart arkime-viewer
Cmnd_Alias NDR_TEE       = /usr/bin/tee /etc/suricata/threshold.conf, /usr/bin/tee -a /etc/suricata/threshold.conf, /usr/bin/tee /etc/suricata/ndr-sensor-suppress.conf, /usr/bin/tee -a /etc/suricata/ndr-sensor-suppress.conf, /usr/bin/tee /opt/zeek/share/zeek/site/ndr-arp.zeek, /usr/bin/tee -a /opt/zeek/share/zeek/site/local.zeek, /usr/bin/tee /etc/systemd/system/ndr-autoscaler.service, /usr/bin/tee /etc/systemd/system/ndr-worker-autoscaler.service
Cmnd_Alias NDR_CAT       = /usr/bin/cat /opt/zeek/share/zeek/site/local.zeek, /usr/bin/cat /etc/suricata/threshold.conf
Cmnd_Alias NDR_LOGROTATE = /usr/sbin/logrotate -f /etc/logrotate.d/suricata-ndr, /usr/sbin/logrotate -f /etc/logrotate.d/zeek-ndr
Cmnd_Alias NDR_RM        = /usr/bin/rm -f /var/run/suricata.pid, /usr/bin/rm -f /run/suricata.pid, /usr/bin/rm -f /var/run/suricata/suricata.pid
Cmnd_Alias NDR_IPTABLES  = /usr/sbin/iptables
$USERNAME ALL=(ALL)  NOPASSWD: NDR_SURICATA, NDR_ZEEK, NDR_PKILL, NDR_PGREP, NDR_SYSTEMCTL, NDR_TEE, NDR_CAT, NDR_LOGROTATE, NDR_RM
$USERNAME ALL=(root) NOPASSWD: NDR_IPTABLES
SUDOERS
sudo chmod 440 /etc/sudoers.d/ndr-stack
log "Sudo configured"

# ── ARP isolation capability ───────────────────
# Device isolation uses scapy to send raw ARP frames (CAP_NET_RAW required).
# setcap grants only that capability — no full root escalation.
log "Granting python3 raw socket capability for ARP device isolation..."
PYTHON3_BIN=$(readlink -f "$(which python3)")
sudo setcap cap_net_raw+ep "$PYTHON3_BIN"
log "ARP isolation ready (cap_net_raw set on $PYTHON3_BIN)"

# ── NDR Agent service ─────────────────────────
log "Setting up scripts..."
chmod +x "$INSTALL_DIR/scripts/"*.py \
         "$INSTALL_DIR/scripts/"*.sh 2>/dev/null || true

log "Installing NDR Agent as system service..."
sudo tee /etc/systemd/system/ndr-agent.service > /dev/null << SERVICE
[Unit]
Description=NDR Host Agent
After=network.target docker.service
Requires=docker.service

[Service]
Type=simple
User=$USERNAME
ExecStartPre=-/bin/rm -f /var/run/suricata.pid /run/suricata.pid /tmp/suricata.pid
ExecStart=/usr/bin/python3 $INSTALL_DIR/scripts/ndr-agent.py
Restart=always
RestartSec=3
Environment=HOME=$HOME_DIR
Environment=SENSOR_ID=local-central
Environment=TENANT_ID=default
Environment=NDR_AGENT_SECRET=$NDR_AGENT_SECRET

[Install]
WantedBy=multi-user.target
SERVICE
sudo systemctl daemon-reload
sudo systemctl enable ndr-agent
sudo systemctl restart ndr-agent
sleep 2
log "NDR Agent service started"

# ── Vector ────────────────────────────────────
log "Configuring Vector..."
cp "$INSTALL_DIR/config/vector.toml" "$HOME_DIR/.vector/vector.toml"
sed -i "s|/home/[^/]*/logs|$HOME_DIR/logs|g" "$HOME_DIR/.vector/vector.toml"
if [ "$DEPLOY_MODE" = "hybrid" ]; then
    sed -i "s|bootstrap_servers = \"kafka:9092\"|bootstrap_servers = \"$CLOUD_KAFKA\"|g" \
        "$HOME_DIR/.vector/vector.toml"
fi
log "Vector configured"

# ══════════════════════════════════════════════
step "Dashboard UI  (Angular)"

log "Installing Angular UI dependencies..."
cd "$INSTALL_DIR/ndr-ui"

if [ -d "node_modules/@angular/build" ]; then
    log "Angular dependencies already installed — skipping npm install"
else
    log "First-time install..."
    sudo chmod -R 777 "$INSTALL_DIR/ndr-ui" 2>/dev/null || true
    npm config set bin-links false
    log "Running npm install..."
    rm -rf node_modules 2>/dev/null || true
    npm install 2>&1
    npm config set bin-links true
    if [ -d "node_modules/@angular/build" ]; then
        log "Angular dependencies installed"
    else
        warn "npm install had issues — check output above"
    fi
fi

# Build now — BEFORE docker compose starts nginx.
# nginx bind-mounts dist/ndr-ui/browser from the host (docker-compose.yml line ~342).
# If dist doesn't exist when nginx starts, it serves an empty directory and the
# browser gets "site can't be reached". Building here ensures the files are ready
# before any container touches them.
log "Building Angular UI (production)..."
if npm run build -- --configuration production 2>&1 | tail -8; then
    log "Angular UI built → dist/ndr-ui/browser/"
else
    warn "Angular build had errors — UI may not load correctly after install"
fi

cd "$INSTALL_DIR"

# ══════════════════════════════════════════════
step "Container Runtime  (Docker)"

if command -v docker >/dev/null 2>&1; then
    log "Docker already installed: $(docker --version)"
else

log "Installing Docker..."
# Remove any old Docker packages and stale repo files from previous installs
sudo apt-get remove -y docker docker-engine docker.io containerd runc 2>/dev/null || true
sudo rm -f /etc/apt/sources.list.d/docker.list \
           /etc/apt/sources.list.d/docker.list.bak \
           /etc/apt/keyrings/docker.gpg \
           /etc/apt/trusted.gpg.d/docker.gpg 2>/dev/null || true
sudo timeout 60 apt-get update -qq 2>/dev/null || true
sudo apt-get install -y ca-certificates curl gnupg lsb-release

sudo mkdir -p /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
    | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
sudo chmod a+r /etc/apt/keyrings/docker.gpg

# Detect current Ubuntu codename — prefer /etc/os-release over lsb_release
# which can return stale/wrong values on new or upgraded systems.
DOCKER_CODENAME=$(. /etc/os-release 2>/dev/null && echo "${VERSION_CODENAME:-$UBUNTU_CODENAME}")
DOCKER_CODENAME=${DOCKER_CODENAME:-$(lsb_release -cs 2>/dev/null)}
log "Detected Ubuntu codename for Docker repo: ${DOCKER_CODENAME}"

# Verify Docker repo actually has packages for this codename (InRelease can exist
# with no packages for brand-new Ubuntu releases). Probe and fall back if needed.
_DOCKER_ARCH=$(dpkg --print-architecture)
_docker_has_packages() {
    local _cn="$1"
    local _count
    _count=$(curl -fsSL --max-time 15 \
        "https://download.docker.com/linux/ubuntu/dists/${_cn}/stable/binary-${_DOCKER_ARCH}/Packages.gz" \
        2>/dev/null | gzip -d 2>/dev/null | grep -c "^Package:" 2>/dev/null || echo 0)
    [ "${_count:-0}" -gt 0 ] 2>/dev/null
}

if ! _docker_has_packages "$DOCKER_CODENAME"; then
    warn "Docker packages not available for '${DOCKER_CODENAME}' — probing repo for a working codename..."
    _DOCKER_PROBE=$(curl -fsSL --max-time 10 \
        "https://download.docker.com/linux/ubuntu/dists/" 2>/dev/null \
        | grep -oP '(?<=href=")[a-z]{4,}(?=/)' | sort -r)
    for _dc in $_DOCKER_PROBE; do
        [ "$_dc" = "$DOCKER_CODENAME" ] && continue
        if _docker_has_packages "$_dc"; then
            log "Using Docker repo codename '${_dc}' instead of '${DOCKER_CODENAME}'"
            DOCKER_CODENAME="$_dc"
            break
        fi
    done
fi

echo "deb [arch=${_DOCKER_ARCH} signed-by=/etc/apt/keyrings/docker.gpg] \
https://download.docker.com/linux/ubuntu ${DOCKER_CODENAME} stable" \
    | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
log "Docker repo configured for codename: ${DOCKER_CODENAME}"
sudo timeout 60 apt-get update -qq 2>/dev/null || true
log "Downloading and installing Docker packages (this may take a few minutes)..."
sudo apt-get install -y docker-ce docker-ce-cli \
    containerd.io docker-buildx-plugin docker-compose-plugin

# InRelease may exist for a new Ubuntu release before the packages land.
# Detect that case and retry with a codename whose packages are confirmed present.
if ! command -v docker >/dev/null 2>&1; then
    warn "Docker packages not found for '${DOCKER_CODENAME}' — probing for a compatible repo codename..."
    _DOCKER_ARCH=$(dpkg --print-architecture)
    _DOCKER_FOUND=""
    _DOCKER_PROBE=$(curl -fsSL --max-time 10 \
        "https://download.docker.com/linux/ubuntu/dists/" 2>/dev/null \
        | grep -oP '(?<=href=")[a-z]{4,}(?=/)' | sort -r)
    for _dc in $_DOCKER_PROBE; do
        [ "$_dc" = "$DOCKER_CODENAME" ] && continue
        _PKG_COUNT=$(curl -fsSL --max-time 15 \
            "https://download.docker.com/linux/ubuntu/dists/${_dc}/stable/binary-${_DOCKER_ARCH}/Packages.gz" \
            2>/dev/null | gzip -d 2>/dev/null | grep -c "^Package:" 2>/dev/null || echo 0)
        if [ "${_PKG_COUNT:-0}" -gt 0 ] 2>/dev/null; then
            _DOCKER_FOUND="$_dc"
            break
        fi
    done
    if [ -n "$_DOCKER_FOUND" ]; then
        log "Retrying Docker install using repo codename '${_DOCKER_FOUND}'..."
        echo "deb [arch=${_DOCKER_ARCH} signed-by=/etc/apt/keyrings/docker.gpg] \
https://download.docker.com/linux/ubuntu ${_DOCKER_FOUND} stable" \
            | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
        sudo apt-get update -qq 2>/dev/null || true
        log "Downloading and installing Docker packages (fallback codename: ${_DOCKER_FOUND})..."
        sudo apt-get install -y docker-ce docker-ce-cli \
            containerd.io docker-buildx-plugin docker-compose-plugin
    fi
fi

# Last resort: snap (works on any Ubuntu release, packages ship ahead of apt)
if ! command -v docker >/dev/null 2>&1; then
    warn "Docker apt install unavailable — falling back to snap..."
    sudo snap install docker 2>/dev/null || true
fi

command -v docker >/dev/null 2>&1 || err "Docker could not be installed"
log "Docker installed"

fi

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
sudo systemctl enable docker
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

# ══════════════════════════════════════════════
step "Update Watcher  (Auto-Update Service)"

cat > "$INSTALL_DIR/scripts/update-watcher.sh" << WATCHER_EOF
#!/bin/bash
# Host-side watcher: picks up .update-requested flag written by the engine container
# and pulls new Docker images then restarts the engine containers.
FLAG="${INSTALL_DIR}/scripts/.update-requested"
INSTALL_DIR_="${INSTALL_DIR}"

logger -t ndr-updater "NDR update watcher started — watching \$FLAG"

while true; do
    if [ -f "\$FLAG" ]; then
        TARGET=\$(cat "\$FLAG" 2>/dev/null | tr -d '[:space:]')
        logger -t ndr-updater "Update flag detected — target: \${TARGET:-latest}"
        rm -f "\$FLAG"
        cd "\$INSTALL_DIR_"
        docker pull ghcr.io/jithinjoseph-workspace/ndr-engine:latest 2>&1 | logger -t ndr-updater || true
        docker pull ghcr.io/jithinjoseph-workspace/ndr-ui:latest     2>&1 | logger -t ndr-updater || true
        docker compose up -d --no-deps ndr-engine-1 ndr-engine-2 ndr-engine-3 ndr-ui 2>&1 | logger -t ndr-updater || true
        logger -t ndr-updater "Update complete"
    fi
    sleep 30
done
WATCHER_EOF
chmod +x "$INSTALL_DIR/scripts/update-watcher.sh"

sudo tee /etc/systemd/system/ndr-updater.service > /dev/null << EOF
[Unit]
Description=NDR Auto-Update Watcher
After=docker.service
Requires=docker.service

[Service]
Type=simple
ExecStart=/bin/bash ${INSTALL_DIR}/scripts/update-watcher.sh
Restart=always
RestartSec=15
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable ndr-updater 2>/dev/null || true
sudo systemctl restart ndr-updater 2>/dev/null || true
log "✅ Update watcher service installed and started"

sudo docker compose --profile onpremise --profile siem down 2>/dev/null || true
sudo docker rm -f vector 2>/dev/null || true

# nginx: config/nginx/nginx.conf is the only nginx config and is used as-is
# (the old per-mode nginx-*.conf copies were removed).

log "Starting Docker stack — product: ${PRODUCT_MODE}, mode: ${DEPLOY_MODE}"

if [ "$PRODUCT_MODE" = "siem" ]; then
    # SIEM only — no ndr-engine, no Agent-Z/S profile
    # clickhouse2 + clickhouse-init required: init.sql creates ndr DB + users/tenants tables for auth
    sudo docker compose --profile siem up -d --build \
        clickhouse-keeper clickhouse1 clickhouse2 clickhouse-init \
        ndr-valkey \
        kafka1 kafka2 kafka3 kafka-init \
        provigil-auth siem-engine-1 ndr-ui nginx
elif [ "$PRODUCT_MODE" = "both" ]; then
    # NDR + SIEM — full XDR stack
    if [ "$DEPLOY_MODE" = "hybrid" ]; then
        log "Hybrid + SIEM — cloud Kafka/CH, local sensors"
        sudo docker compose --profile siem --profile onpremise up -d --build \
            vector ndr-engine-1 siem-engine-1 ndr-ui nginx
    else
        sudo docker compose --profile siem --profile onpremise up -d --build
    fi
else
    # NDR only (default)
    if [ "$DEPLOY_MODE" = "hybrid" ]; then
        log "Hybrid NDR — using cloud: $CLOUD_KAFKA"
        sudo docker compose --profile onpremise up -d --build vector ndr-engine-1 nginx
    else
        sudo docker compose --profile onpremise up -d --build
    fi
fi
log "Docker stack started"

if [ "$DEPLOY_MODE" = "local" ]; then
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
        bash "$INSTALL_DIR/scripts/ch-import.sh"
        log "Data migration complete"
    fi
fi

log "Configuring Kafka retention..."
sleep 15
sudo docker exec kafka1 \
    /opt/kafka/bin/kafka-configs.sh \
    --bootstrap-server localhost:9092 \
    --alter --entity-type topics \
    --entity-name ndr-events \
    --add-config retention.ms=86400000 \
    2>/dev/null || true
log "Kafka retention set to 24 hours"

log "Creating Kafka topic with 3 partitions..."
sudo docker exec kafka1 /opt/kafka/bin/kafka-topics.sh \
    --bootstrap-server localhost:9092 \
    --create --if-not-exists \
    --topic ndr-events \
    --partitions 3 \
    --replication-factor 3 \
    2>/dev/null || true
log "Kafka topic ready"

# ══════════════════════════════════════════════
step "Search Index  (OpenSearch)"

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

# ══════════════════════════════════════════════
step "Response Automation  (SOAR)"

log "Native SOAR is built into the NDR engine — no extra services needed"
info "Configure playbooks, cases and integrations from the UI → SOAR page"

log "Angular UI — built inside the ndr-ui Docker container (no host build needed)"

# Kill any stale npm serve process left over from a previous install run
if [ -f /tmp/ndr-ui.pid ]; then
    OLD_UI_PID=$(cat /tmp/ndr-ui.pid 2>/dev/null || true)
    if [ -n "$OLD_UI_PID" ] && kill -0 "$OLD_UI_PID" 2>/dev/null; then
        kill "$OLD_UI_PID" 2>/dev/null || true
    fi
    rm -f /tmp/ndr-ui.pid
fi

# Wait for ndr-ui container and then nginx to confirm UI is live
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

log "Waiting for Angular UI (served by nginx)..."
for i in {1..20}; do
    if curl -sk https://localhost:3000/ > /dev/null 2>&1; then
        log "Angular UI ready at https://localhost:3000"
        break
    fi
    echo -n "."
    sleep 2
done
echo ""

if grep -qi microsoft /proc/version 2>/dev/null; then
    warn "WSL2 detected — run in Windows PowerShell as Admin:"
    printf "\n"
    echo "  netsh interface portproxy add v4tov4 listenport=3000 listenaddress=0.0.0.0 connectport=3000 connectaddress=$HOST_IP"
    echo "  netsh interface portproxy add v4tov4 listenport=3080 listenaddress=0.0.0.0 connectport=3080 connectaddress=$HOST_IP"
    echo "  netsh interface portproxy add v4tov4 listenport=9092 listenaddress=0.0.0.0 connectport=9092 connectaddress=$HOST_IP"
    printf "\n"
fi

# ══════════════════════════════════════════════
step "Verification"

log "Verifying installation..."
info "Mode:       $DEPLOY_MODE"
info "Interface:  $IFACE  ($HOST_IP)"
info "Agent-Z:    $(/opt/zeek/bin/zeek --version 2>&1 | head -1)"
info "Agent-S:    $(suricata --version 2>&1 | head -1)"
info "Docker:     $(sudo docker --version)"
info "ndr-ui:     $(sudo docker inspect --format='{{.State.Status}}' ndr-ui 2>/dev/null || echo 'not started')"
if [ "$DEPLOY_MODE" = "local" ]; then
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
printf "  ${CYAN}╠══════════════════════════════════════════════╣${NC}\n"
printf "  ${CYAN}║${NC}  ${BOLD}$(_pad "Service         Access Point")${NC}  ${CYAN}║${NC}\n"
printf "  ${CYAN}║${NC}  ${DIM}$(_pad "─────────────── ────────────────────────")${NC}  ${CYAN}║${NC}\n"
printf "  ${CYAN}║${NC}  $(_pad "Dashboard       https://${HOST_IP}:3000")${CYAN}║${NC}\n"
printf "  ${CYAN}║${NC}  $(_pad "Product:        ${PRODUCT_MODE}")${CYAN}║${NC}\n"
if [ "$PRODUCT_MODE" != "siem" ]; then
printf "  ${CYAN}║${NC}  $(_pad "NDR Agent       http://localhost:3001")${CYAN}║${NC}\n"
printf "  ${CYAN}║${NC}  $(_pad "Packet Recorder http://localhost:8005")${CYAN}║${NC}\n"
fi
if [ "$PRODUCT_MODE" != "ndr" ]; then
printf "  ${CYAN}║${NC}  $(_pad "SIEM API        http://${HOST_IP}:3002")${CYAN}║${NC}\n"
printf "  ${CYAN}║${NC}  $(_pad "Syslog (TCP)    ${HOST_IP}:601 / :6514")${CYAN}║${NC}\n"
fi
printf "  ${CYAN}╠══════════════════════════════════════════════╣${NC}\n"
printf "  ${CYAN}║${NC}  $(_pad "start:    ./start.sh")${CYAN}║${NC}\n"
printf "  ${CYAN}║${NC}  $(_pad "stop:     ./stop.sh")${CYAN}║${NC}\n"
printf "  ${CYAN}║${NC}  $(_pad "status:   ./status.sh")${CYAN}║${NC}\n"
printf "  ${CYAN}╚══════════════════════════════════════════════╝${NC}\n"
printf "\n"
printf "  ${DIM}Proma Secure — Network Detection & Response Platform${NC}\n\n"
