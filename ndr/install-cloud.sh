#!/bin/bash

# ── Auto-fix Windows line endings ─────────────
SELF=$(readlink -f "$0")
if file "$SELF" | grep -q CRLF; then
    echo "Fixing line endings..."
    sed -i 's/\r//' "$SELF"
    exec bash "$SELF" "$@"
fi

# ── Bootstrap: download required files if not already present ─────────────────
# Triggered when running via:  bash <(curl -fsSL .../install-cloud.sh)
# In that case $0 is /dev/stdin or /dev/fd/N — no docker-compose.yml next to it.
if [ ! -f "$(dirname "$0")/docker-compose.yml" ]; then
    echo ""
    echo "  NDR Cloud Installer — downloading required files..."
    echo ""
    read -rp "  GitHub token (optional, press Enter to skip): " GH_TOKEN
    INSTALL_DIR="${1:-/opt/ndr}"
    echo "  Installing to: $INSTALL_DIR"
    sudo mkdir -p "$INSTALL_DIR"
    sudo chown "$(id -u):$(id -g)" "$INSTALL_DIR"
    chmod 755 "$INSTALL_DIR"

    echo "  Downloading config files via GitHub API..."
    GH_TOKEN="$GH_TOKEN" INSTALL_DIR="$INSTALL_DIR" python3 - << 'PYEOF'
import urllib.request, json, os, base64, sys

token    = os.environ["GH_TOKEN"]
dest     = os.environ["INSTALL_DIR"]
api_base = "https://api.github.com/repos/jithinjoseph-workspace/NDR-SIEM"
headers  = {"Accept": "application/vnd.github.v3+json"}
if token:
    headers["Authorization"] = f"token {token}"

def gh_get(url):
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req) as r:
            return r.read()
    except Exception as e:
        print(f"  ERROR: {e}")
        sys.exit(1)

def download_file(repo_path, local_path):
    meta = json.loads(gh_get(f"{api_base}/contents/{repo_path}?ref=auth/service"))
    os.makedirs(os.path.dirname(local_path), exist_ok=True)
    # GitHub's Contents API only inlines base64 `content` for files under 1MB -
    # for anything larger it's present but empty, with a `download_url`
    # (raw.githubusercontent.com) instead. Silently writing an empty file here
    # was a real, undetected bug for any file over that size (e.g. the 65MB
    # GeoLite2-City.mmdb).
    if meta.get("content"):
        content = base64.b64decode(meta["content"].replace("\n", ""))
        with open(local_path, "wb") as f:
            f.write(content)
    elif meta.get("download_url"):
        req = urllib.request.Request(meta["download_url"], headers=headers)
        with urllib.request.urlopen(req) as r, open(local_path, "wb") as f:
            f.write(r.read())
    else:
        print(f"  ERROR: {repo_path} has neither inline content nor a download_url")
        sys.exit(1)
    on_disk = os.path.getsize(local_path)
    if on_disk != meta.get("size", on_disk):
        print(f"  ERROR: {repo_path} downloaded as {on_disk} bytes, expected {meta.get('size')}")
        sys.exit(1)
    print(f"    {repo_path}")

def download_dir(repo_path, local_path):
    os.makedirs(local_path, exist_ok=True)
    items = json.loads(gh_get(f"{api_base}/contents/{repo_path}?ref=auth/service"))
    for item in items:
        target = os.path.join(local_path, item["name"])
        if item["type"] == "file":
            meta = json.loads(gh_get(f"{api_base}/contents/{item['path']}?ref=auth/service"))
            content = base64.b64decode(meta["content"].replace("\n", ""))
            with open(target, "wb") as f:
                f.write(content)
            print(f"    {item['path']}")
        elif item["type"] == "dir":
            download_dir(item["path"], target)

download_file("docker-compose.yml",  f"{dest}/docker-compose.yml")
download_file("install-cloud.sh",    f"{dest}/install-cloud.sh")
# NOT start.sh/stop.sh/status.sh here - those are install.sh/install-customer.sh's
# on-prem scripts (PRODUCT_MODE, --profile onpremise, systemd Agent-Z/Agent-S,
# PRODUCT_MODE nginx variants). Cloud mode writes its own
# versions later, once docker-compose.cloud.yml actually exists to reference.

# Only the config files cloud mode's docker-compose.yml actually mounts -
# not the whole config/ tree (which also has ClickHouse
# files it does not use, a Dockerfile+xml unused by the pre-built clickhouse image, a
# Vector config cloud mode never runs, and a stale dev-machine ndr.crt/
# ndr.key that would block generating a real cert for this install).
for f in [
    "config/clickhouse/init.sql",
    "config/clickhouse/cluster/keeper-config.xml",
    "config/clickhouse/cluster/ch1-config.xml",
    "config/clickhouse/cluster/ch2-config.xml",
    "config/clickhouse/cluster/z-ndr-listen.xml",
    "config/clickhouse/cluster/users.xml",
    "config/nginx/nginx.conf",
]:
    download_file(f, f"{dest}/{f}")

download_dir("scripts",              f"{dest}/scripts")
download_dir("rust/ndr-engine/rules",f"{dest}/rust/ndr-engine/rules")

# Real, licensed MaxMind GeoLite2 databases - already committed to the repo
# and baked into the ndr-engine image at build time (rust/Dockerfile copies
# the whole ndr-engine/ tree in), but docker-compose.yml also bind-mounts
# $INSTALL_DIR/rust/ndr-engine/data over that same in-image path. Without
# downloading them here too, that mount source was an empty host directory
# that silently shadowed the image's real data with nothing - the actual
# cause of every geo-lookup returning empty, not a missing download step.
for f in [
    "rust/ndr-engine/data/GeoLite2-City.mmdb",
    "rust/ndr-engine/data/GeoLite2-ASN.mmdb",
]:
    download_file(f, f"{dest}/{f}")
PYEOF
    chmod +x "$INSTALL_DIR/install-cloud.sh"
    echo ""
    exec bash "$INSTALL_DIR/install-cloud.sh" "$INSTALL_DIR"
fi

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

LOG_FILE="/var/log/ndr/install-cloud-$(date +%Y%m%d-%H%M%S).log"
mkdir -p "$(dirname "$LOG_FILE")" 2>/dev/null && touch "$LOG_FILE" 2>/dev/null \
  || LOG_FILE="/tmp/ndr-install-cloud-$(date +%Y%m%d-%H%M%S).log"
touch "$LOG_FILE" 2>/dev/null || true

log()  { echo -e "${GREEN}[NDR]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
err()  { echo -e "${RED}[ERR]${NC} $1"; echo "[$(date '+%Y-%m-%d %H:%M:%S')] FATAL $1" >> "$LOG_FILE" 2>/dev/null; exit 1; }
info() { echo -e "${BLUE}[INFO]${NC} $1"; }

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
# commands with sudo (unlike install-sensor.sh, which expects to run as
# root outright) — so validate sudo access up front instead of requiring
# root, and instead of letting a no-sudo user hit a wall deep inside the
# script at whatever the first `sudo` command happens to be.
if [ "$(id -u)" -ne 0 ] && ! sudo -v 2>/dev/null; then
  err "This script needs sudo access to install Docker/system packages. Add this user to the sudoers group, or re-run as root."
fi

echo ""
echo "╔══════════════════════════════════════════╗"
echo "║     NDR Cloud Installer v1.0             ║"
echo "║  Kafka + ClickHouse + Redis + Engine     ║"
echo "╚══════════════════════════════════════════╝"
echo ""

TOTAL_STEPS=9
CURRENT_STEP=0

step() {
    CURRENT_STEP=$((CURRENT_STEP + 1))
    echo ""
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BLUE}  Step $CURRENT_STEP/$TOTAL_STEPS: $1${NC}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
}

# ── Detect public IP ──────────────────────────
log "Detecting public IP..."
PUBLIC_IP=$(curl -s --max-time 10 ifconfig.me 2>/dev/null || \
            curl -s --max-time 10 api.ipify.org 2>/dev/null || \
            hostname -I | awk '{print $1}')
log "✅ Public IP: $PUBLIC_IP"

# ── Public URL (optional) ─────────────────────
# The auto-detected IP is only correct when this machine is directly reachable
# on it. Behind a domain, reverse proxy or tunnel (ngrok, Cloudflare Tunnel...)
# customers use a different address, and the API must allow that origin (CORS).
# Set PUBLIC_URL in the environment, or enter it when asked. Leave it empty to
# keep the default (the detected IP).
PUBLIC_URL="${PUBLIC_URL:-}"
if [ -z "$PUBLIC_URL" ] && [ -t 0 ]; then
    read -rp "  Public URL sensors/users will use, e.g. https://ndr.example.com (Enter = use $PUBLIC_IP): " PUBLIC_URL
fi
PUBLIC_URL="${PUBLIC_URL%/}"
if [ -n "$PUBLIC_URL" ] && ! echo "$PUBLIC_URL" | grep -qE '^https?://[^/[:space:]]+$'; then
    case "$PUBLIC_URL" in
        http://*|https://*) err "PUBLIC_URL must be just scheme://host[:port] (no path): got '$PUBLIC_URL'" ;;
        *)                  PUBLIC_URL="https://$PUBLIC_URL" ;;
    esac
fi
if [ -n "$PUBLIC_URL" ]; then
    SENSOR_URL="$PUBLIC_URL"
    CORS_VALUE="$PUBLIC_URL,http://$PUBLIC_IP,https://$PUBLIC_IP"
    log "✅ Public URL: $PUBLIC_URL"
else
    SENSOR_URL="https://$PUBLIC_IP"
    CORS_VALUE="http://$PUBLIC_IP"
fi

USERNAME=$(whoami)
HOME_DIR=$HOME
INSTALL_DIR="${1:-$(cd "$(dirname "$0")" && pwd)}"

log "Installing to: $INSTALL_DIR"
log "Running as:    $USERNAME"
log "Mode:          cloud (no Agent-Z/Agent-S/Arkime/OpenSearch)"

# ── Check OS ──────────────────────────────────
. /etc/os-release
log "Detected OS: $NAME $VERSION_ID"
[[ "$ID" != "ubuntu" ]] && warn "Only Ubuntu tested. Proceed with caution."

# ── Fix APT sources ───────────────────────────
UBUNTU_CODENAME=$(. /etc/os-release 2>/dev/null && echo "${VERSION_CODENAME:-$(lsb_release -cs 2>/dev/null)}")
UBUNTU_CODENAME=${UBUNTU_CODENAME:-noble}
log "Ubuntu codename: ${UBUNTU_CODENAME}"

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
sudo apt-get update -qq 2>&1 | grep -E "^Get|^Hit|^Err" | head -10 || true

# ── Step 1: System dependencies ───────────────
step "Installing system dependencies"

log "Installing packages..."
if sudo apt-get install -y \
    curl wget git jq \
    python3 python3-pip python3-requests \
    net-tools iproute2 \
    ufw \
    apt-transport-https ca-certificates gnupg \
    lsb-release openssl 2>/tmp/ndr_cloud_err; then
  log "✅ System packages installed"
else
  record_error "System packages" "apt-get install failed ($(cat /tmp/ndr_cloud_err 2>/dev/null))" \
    "Check network connectivity and available disk space, then re-run this script."
fi
rm -f /tmp/ndr_cloud_err

# ── Docker ────────────────────────────────────
# `command -v docker` alone misses hosts with a bare `docker.io` install (the
# Ubuntu distro package, common when Docker was installed some other way) —
# it has the `docker` binary but not the Compose v2 plugin, since that only
# ships through Docker's own apt repo. Checking both here means a clear
# message now instead of a confusing raw CLI error at `docker compose up`,
# much later, after already spending time pulling large images.
DOCKER_OK=0
NEED_ENGINE=0
NEED_COMPOSE=0
if ! command -v docker &>/dev/null; then
    NEED_ENGINE=1
    NEED_COMPOSE=1
elif ! sudo docker compose version &>/dev/null; then
    NEED_COMPOSE=1
fi

if [ "$NEED_ENGINE" = "1" ] || [ "$NEED_COMPOSE" = "1" ]; then
    if [ "$NEED_ENGINE" = "1" ]; then
        log "Installing Docker..."
    else
        log "Docker is installed but the Compose plugin is missing — installing it..."
    fi
    if ! curl -fsSL https://download.docker.com/linux/ubuntu/gpg 2>/tmp/ndr_cloud_err \
        | sudo gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg 2>>/tmp/ndr_cloud_err; then
      record_error "Docker" "could not fetch/import the Docker repo signing key ($(cat /tmp/ndr_cloud_err 2>/dev/null))" \
        "Check internet access to download.docker.com (443) — no proxy/firewall blocking it."
    else
      DOCKER_CODENAME="${UBUNTU_CODENAME}"
      # Fall back to noble if Docker repo doesn't exist for this codename yet.
      # One retry so a single transient network blip can't wrongly trigger
      # this — noble's packages need a newer glibc than older codenames
      # ship, so a bad fallback here silently breaks the whole Docker
      # install with a confusing "unmet dependencies" error much later.
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
          log "Docker repo not yet available for '${DOCKER_CODENAME}' — falling back to noble"
          DOCKER_CODENAME="noble"
      fi
      PKGS="docker-compose-plugin"
      [ "$NEED_ENGINE" = "1" ] && PKGS="docker-ce docker-ce-cli containerd.io docker-compose-plugin"
      if ! { echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] \
          https://download.docker.com/linux/ubuntu ${DOCKER_CODENAME} stable" \
          | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null 2>/tmp/ndr_cloud_err \
          && sudo apt-get update -qq 2>>/tmp/ndr_cloud_err \
          && sudo DEBIAN_FRONTEND=noninteractive apt-get install -y $PKGS 2>>/tmp/ndr_cloud_err; }; then
        record_error "Docker" "install failed ($(cat /tmp/ndr_cloud_err 2>/dev/null))" \
          "Check network connectivity, or install Docker manually: https://docs.docker.com/engine/install/ubuntu/"
      elif [ "$NEED_ENGINE" != "1" ]; then
        DOCKER_OK=1
        log "✅ Docker Compose plugin installed"
      else
        sudo usermod -aG docker "$USERNAME" 2>/dev/null || true
        if sudo systemctl enable docker 2>/tmp/ndr_cloud_err && sudo systemctl start docker 2>>/tmp/ndr_cloud_err; then
          DOCKER_OK=1
          log "✅ Docker installed"
        else
          record_error "Docker" "installed but the service would not start ($(cat /tmp/ndr_cloud_err 2>/dev/null))" \
            "Check systemd is available on this host, then: sudo systemctl status docker"
        fi
      fi
    fi
    rm -f /tmp/ndr_cloud_err
else
    DOCKER_OK=1
    log "✅ Docker already installed"
fi
if [ "$DOCKER_OK" != "1" ]; then
  err "Docker is required for every step from here on — fix the issue above (see $LOG_FILE) and re-run this script."
fi

# ── Docker daemon config ──────────────────────────────────────────────────────
sudo tee /etc/docker/daemon.json > /dev/null << 'DOCKEREOF'
{
  "log-driver": "json-file",
  "log-opts": { "max-size": "10m", "max-file": "3" }
}
DOCKEREOF
if ! sudo systemctl restart docker 2>/tmp/ndr_cloud_err; then
  record_error "Docker" "could not restart the docker service after writing daemon.json ($(cat /tmp/ndr_cloud_err 2>/dev/null))" \
    "Check: sudo journalctl -u docker -n 50"
fi
rm -f /tmp/ndr_cloud_err
sleep 3

# ── Step 2: Create NDR directories ────────────
step "Creating NDR storage directories"

sudo mkdir -p /opt/ndr/pcap
sudo mkdir -p /opt/ndr/evidence
sudo chmod -R 755 /opt/ndr
sudo chown -R "$USERNAME:$USERNAME" /opt/ndr
log "✅ Created /opt/ndr/pcap and /opt/ndr/evidence"

# ── TLS certificate for Nginx ──────────────────
# nginx.conf (downloaded from the repo above) has SSL active by default and
# reads from config/nginx/ssl/, which docker-compose.yml mounts into the
# container at /etc/nginx/ssl/. Generate a self-signed cert there now so
# nginx has something valid to start with; skipped if a real CA-signed one
# has already been placed at the same path.
SSL_DIR="$INSTALL_DIR/config/nginx/ssl"
if [ ! -f "$SSL_DIR/ndr.crt" ] || [ ! -f "$SSL_DIR/ndr.key" ]; then
    log "Generating self-signed TLS certificate for $PUBLIC_IP..."
    mkdir -p "$SSL_DIR"
    openssl req -x509 -nodes -days 730 -newkey rsa:2048 \
        -keyout "$SSL_DIR/ndr.key" \
        -out    "$SSL_DIR/ndr.crt" \
        -subj   "/CN=$PUBLIC_IP" \
        -addext "subjectAltName=IP:$PUBLIC_IP,IP:127.0.0.1,DNS:localhost" \
        2>/dev/null
    chmod 600 "$SSL_DIR/ndr.key"
    log "✅ TLS certificate generated → $SSL_DIR"
else
    log "TLS certificate already exists — skipping generation"
fi
info "  For a real domain, use certbot then replace $SSL_DIR/ndr.crt + ndr.key,"
info "  then: docker restart ndr-nginx"

# ── Step 3: Configure ClickHouse ─────────────
step "Configuring ClickHouse"

# ClickHouse runs as a Docker container — started in Step 6 via docker compose up.
# The ndr user takes its password from CLICKHOUSE_PASSWORD (random per install, see .env).
# Schema (ndr database + all tables) is created by config/clickhouse/init.sql
# on the first container start via /docker-entrypoint-initdb.d/.
log "ClickHouse will start as a Docker container with the stack"
log "  User:   ndr  (random password stored in $INSTALL_DIR/.env)"
log "  Ports:  8123/8124 (HTTP), 9000/9001 (native) — 2-node cluster"
log "  Schema: auto-created on first start via init.sql"
log "✅ ClickHouse configured"

# ── Step 4: Generate .env ─────────────────────
step "Generating cloud .env"

if [ -f "$INSTALL_DIR/.env" ] && grep -q "JWT_SECRET" "$INSTALL_DIR/.env"; then
    JWT_SECRET=$(grep "JWT_SECRET" "$INSTALL_DIR/.env" | cut -d= -f2-)
else
    JWT_SECRET=$(openssl rand -hex 32)
fi

if [ -f "$INSTALL_DIR/.env" ] && grep -q "^NDR_AGENT_SECRET=." "$INSTALL_DIR/.env"; then
    NDR_AGENT_SECRET=$(grep "^NDR_AGENT_SECRET=" "$INSTALL_DIR/.env" | cut -d= -f2-)
else
    NDR_AGENT_SECRET=$(openssl rand -hex 32)
fi

if [ -f "$INSTALL_DIR/.env" ] && grep -q "^DEPLOY_WEBHOOK_SECRET=." "$INSTALL_DIR/.env"; then
    DEPLOY_WEBHOOK_SECRET=$(grep "^DEPLOY_WEBHOOK_SECRET=" "$INSTALL_DIR/.env" | cut -d= -f2-)
else
    DEPLOY_WEBHOOK_SECRET=$(openssl rand -hex 32)
fi

# Random per-install ClickHouse password — was previously hardcoded to
# "ndr123" for every cloud install, which meant every deployment shared
# the same database credential. Preserved across re-runs of this script
# so an existing install doesn't get locked out on upgrade.
if [ -f "$INSTALL_DIR/.env" ] && grep -q "^CLICKHOUSE_PASSWORD=." "$INSTALL_DIR/.env"; then
    CLICKHOUSE_PASSWORD=$(grep "^CLICKHOUSE_PASSWORD=" "$INSTALL_DIR/.env" | cut -d= -f2-)
else
    CLICKHOUSE_PASSWORD=$(openssl rand -hex 16 2>/dev/null || echo "$(date +%s%N | sha256sum | head -c 32)")
fi

# ── RSA license key pair (generated once; private key stays on this server) ──
if [ -f "$INSTALL_DIR/.env" ] && grep -q "^LICENSE_PRIVATE_KEY=." "$INSTALL_DIR/.env"; then
    LICENSE_PRIVATE_KEY=$(grep "^LICENSE_PRIVATE_KEY=" "$INSTALL_DIR/.env" | cut -d= -f2-)
    LICENSE_PUBLIC_KEY=$(grep "^LICENSE_PUBLIC_KEY=" "$INSTALL_DIR/.env" | cut -d= -f2-)
fi
if [ -z "$LICENSE_PRIVATE_KEY" ]; then
    log "Generating RSA-2048 key pair for license signing..."
    _TMP_KEY=$(mktemp)
    openssl genrsa -out "$_TMP_KEY" 2048 2>/dev/null
    LICENSE_PRIVATE_KEY=$(base64 -w0 < "$_TMP_KEY")
    LICENSE_PUBLIC_KEY=$(openssl rsa -in "$_TMP_KEY" -pubout 2>/dev/null | base64 -w0)
    rm -f "$_TMP_KEY"
    log "RSA key pair generated"
fi

# Prompt for Groq API key
GROQ_API_KEY=""
if [ -f "$INSTALL_DIR/.env" ]; then
    GROQ_API_KEY=$(grep "^GROQ_API_KEY=" "$INSTALL_DIR/.env" | cut -d= -f2- 2>/dev/null || echo "")
fi
if [ -z "$GROQ_API_KEY" ]; then
    echo ""
    info "  NDR uses Groq for AI threat analysis (free at console.groq.com)"
    read -rp "  Enter your Groq API key (or press Enter to skip): " GROQ_API_KEY
    GROQ_API_KEY="${GROQ_API_KEY:-}"
fi

cat > "$INSTALL_DIR/.env" << ENVEOF
HOST_IP=$PUBLIC_IP
HOME_DIR=$HOME_DIR
INSTALL_DIR=$INSTALL_DIR
CLOUD_MODE=true
DEPLOY_MODE=cloud
LOCAL_SENSOR_ID=local-central
TENANT_ID=default
CLICKHOUSE_URL=http://clickhouse1:8123
CLICKHOUSE_URL_SECONDARY=http://clickhouse2:8123
CLICKHOUSE_USER=ndr
CLICKHOUSE_PASSWORD=$CLICKHOUSE_PASSWORD
KAFKA_BROKERS=kafka1:9092,kafka2:9092,kafka3:9092
JWT_SECRET=$JWT_SECRET
NDR_AGENT_SECRET=$NDR_AGENT_SECRET
DEPLOY_WEBHOOK_SECRET=$DEPLOY_WEBHOOK_SECRET
CORS_ORIGIN=$CORS_VALUE
OPENSEARCH_URL=
ARKIME_URL=
ARKIME_PASS=
OPENAI_API_KEY=
GROQ_API_KEY=$GROQ_API_KEY
GROQ_MODEL=llama-3.3-70b-versatile
BEACON_WINDOW_HOURS=1
INGEST_RATE_LIMIT=0
# How many tenants ndr-engine's background analysis tasks (entity scoring,
# correlation, pattern matching, etc.) process at once, instead of one at a
# time. Higher = faster full-tenant-set cycles but more concurrent load on
# ClickHouse and any configured AI provider; size against your actual
# hardware and tenant count. Default (10) is reasonable for a modest
# tenant count - raise it for hundreds-to-thousands of tenants.
TENANT_SCAN_CONCURRENCY=10
# How many tenants' event batches the Kafka consumer's 100ms flush loop
# writes to ClickHouse concurrently, instead of one at a time. Different
# knob from TENANT_SCAN_CONCURRENCY above - this runs every 100ms in the
# live ingestion path, not every few minutes-to-hours in background
# analysis, so it needs its own value. Default (20) is reasonable for a
# modest number of simultaneously-active tenants - raise it if many
# tenants are pushing high event volume at the same time.
INGEST_FLUSH_CONCURRENCY=20
SIEM_SYSLOG_HOST=
SIEM_SYSLOG_PORT=514
TRUSTED_SOURCE_CIDRS=
LICENSE_PRIVATE_KEY=$LICENSE_PRIVATE_KEY
LICENSE_PUBLIC_KEY=$LICENSE_PUBLIC_KEY
LICENSE_TOKEN=
TENANT_ADMIN_USER=
TENANT_ADMIN_PASS=
ENVEOF
log "✅ Cloud .env generated"
info "  CLOUD_MODE=true — Agent-Z/Agent-S/Arkime/OpenSearch are disabled"
if [ -n "$GROQ_API_KEY" ]; then
    info "  AI: Groq llama-3.3-70b-versatile (fallback). Add providers in Settings for full control."
else
    warn "  AI: No Groq key set — add a provider in Settings > AI Providers after install."
fi

# ── Step 5: Nginx config ──────────────────────
# Already the correct file — downloaded from config/nginx/ (repo source of
# truth, has the real auth_service upstream + /api/auth/* routing) by the
# bootstrap step above. Nothing to write here; a separate embedded copy used
# to overwrite it with a stale version missing auth_service entirely, which
# silently broke login (and everything else under /api/auth/*) on every
# cloud install — removed rather than kept in sync by hand.
log "✅ Using downloaded nginx.conf (auth_service routing included)"

# GeoIP/ASN: the real MaxMind GeoLite2-City.mmdb + GeoLite2-ASN.mmdb are
# downloaded above in the bootstrap step, straight from the repo where
# they're already committed (rust/ndr-engine/data/) - same files baked into
# the ndr-engine image, now also populating the host side of
# docker-compose.yml's data/ bind mount so they're not shadowed by an empty
# directory. Nothing further to do here.

# ── Step 6: Start Docker stack ────────────────
step "Starting Docker stack (cloud profile)"

info "  ℹ️  Cloud mode starts: kafka (internal), redis, ndr-engine x3, nginx, ndr-ui"
info "  ℹ️  Skipped (onpremise profile only): opensearch, vector"
info "  ℹ️  Sensors send data via HTTP POST to $SENSOR_URL/api/ingest"
info "  ℹ️  Kafka runs internally only — not exposed to sensors"
info ""

# ── Registry login ────────────────────────────
REGISTRY="ghcr.io/jithinjoseph-workspace"
printf "\n"
read -rp "  Registry token (provided by Proma Secure): " REGISTRY_TOKEN
echo "$REGISTRY_TOKEN" | sudo docker login ghcr.io -u ndr-customer --password-stdin \
    || err "Registry login failed — check your token and try again"
log "Registry login successful"

# ── Pull pre-built images ─────────────────────
log "Pulling pre-built images..."
sudo docker pull "${REGISTRY}/ndr-engine:latest" 2>/tmp/ndr_cloud_err \
  || err "Could not pull ${REGISTRY}/ndr-engine:latest ($(cat /tmp/ndr_cloud_err 2>/dev/null)) — check the registry token and network access, then re-run."
sudo docker pull "${REGISTRY}/ndr-ui:latest" 2>/tmp/ndr_cloud_err \
  || err "Could not pull ${REGISTRY}/ndr-ui:latest ($(cat /tmp/ndr_cloud_err 2>/dev/null)) — check the registry token and network access, then re-run."
sudo docker pull "${REGISTRY}/provigil-auth:latest" 2>/tmp/ndr_cloud_err \
  || err "Could not pull ${REGISTRY}/provigil-auth:latest ($(cat /tmp/ndr_cloud_err 2>/dev/null)) — check the registry token and network access, then re-run."
rm -f /tmp/ndr_cloud_err

# ── Write compose override (pre-built images, no build:) ─────────────
cat > "$INSTALL_DIR/docker-compose.cloud.yml" << OVERRIDE
services:
  ndr-engine-1:
    image: ${REGISTRY}/ndr-engine:latest
  ndr-engine-2:
    image: ${REGISTRY}/ndr-engine:latest
  ndr-engine-3:
    image: ${REGISTRY}/ndr-engine:latest
  ndr-ui:
    image: ${REGISTRY}/ndr-ui:latest
    build: !reset null
  provigil-auth:
    image: ${REGISTRY}/provigil-auth:latest
    build: !reset null
OVERRIDE

# ── Write cloud-specific start/stop/status scripts ────────────────────
# Not install.sh/install-customer.sh's on-prem start.sh/stop.sh/status.sh -
# those assume PRODUCT_MODE, --profile onpremise, systemd Agent-Z/Agent-S,
# and used to copy per-mode nginx files over nginx.conf, none of
# which apply here and would silently break the auth_service nginx routing
# fixed above. These reference the actual cloud compose files instead.
cat > "$INSTALL_DIR/start.sh" << 'STARTEOF'
#!/bin/bash
INSTALL_DIR=$(cd "$(dirname "$0")" && pwd)
cd "$INSTALL_DIR"
echo ""
echo "  Starting NDR Cloud Stack..."
echo ""
sudo docker compose -f docker-compose.yml -f docker-compose.cloud.yml up -d
echo ""
echo "  Docker stack started:"
sudo docker ps --format "    {{.Names}}\t{{.Status}}"
echo ""
STARTEOF

cat > "$INSTALL_DIR/stop.sh" << 'STOPEOF'
#!/bin/bash
INSTALL_DIR=$(cd "$(dirname "$0")" && pwd)
cd "$INSTALL_DIR"
echo ""
echo "  Stopping NDR Cloud Stack..."
echo ""
sudo docker compose -f docker-compose.yml -f docker-compose.cloud.yml down
echo ""
echo "  Docker stack stopped"
echo ""
STOPEOF

cat > "$INSTALL_DIR/status.sh" << 'STATUSEOF'
#!/bin/bash
INSTALL_DIR=$(cd "$(dirname "$0")" && pwd)
if [ -f "$INSTALL_DIR/.env" ]; then
    source "$INSTALL_DIR/.env"
fi

echo ""
echo "  NDR Cloud Stack Status"
echo "  ──────────────────────────────────────────────────"
echo ""

echo "  Docker containers:"
sudo docker ps --format "    {{.Names}}\t{{.Status}}" 2>/dev/null || echo "    Docker not running"
echo ""

echo "  ClickHouse:"
echo "    node1 : $(curl -s --max-time 3 http://localhost:8123/ping 2>/dev/null || echo 'not responding')"
echo ""

echo "  Kafka topics:"
sudo docker exec kafka1 /opt/kafka/bin/kafka-topics.sh \
    --bootstrap-server localhost:9092 --list 2>/dev/null \
    | sed 's/^/    /' || echo "    not ready"
echo ""

echo "  Valkey:"
echo "    ping  : $(sudo docker exec ndr-valkey valkey-cli ping 2>/dev/null || echo 'not responding')"
echo ""

echo "  Auth (provigil-auth):"
echo "    health: $(curl -s --max-time 3 "http://localhost:3001/api/auth/check-username?username=ping" 2>/dev/null || echo 'not responding')"
echo ""

echo "  NDR Engine:"
echo "    health: $(curl -sk --max-time 3 "https://localhost/api/health" 2>/dev/null || echo 'not responding')"
echo ""

echo "  Access:"
echo "    API (HTTP)  : http://${HOST_IP:-localhost}"
echo "    API (HTTPS) : https://${HOST_IP:-localhost}"
echo ""
STATUSEOF

chmod +x "$INSTALL_DIR/start.sh" "$INSTALL_DIR/stop.sh" "$INSTALL_DIR/status.sh"
log "✅ Cloud start.sh/stop.sh/status.sh written"

cd "$INSTALL_DIR"
sudo docker compose down 2>/dev/null || true

sudo docker compose -f docker-compose.yml -f docker-compose.cloud.yml up -d 2>/tmp/ndr_cloud_err \
  || err "docker compose up failed ($(cat /tmp/ndr_cloud_err 2>/dev/null)) — check: sudo docker compose logs, and confirm no port conflicts (8123/9092/6379/etc)."
rm -f /tmp/ndr_cloud_err
log "✅ Docker stack started with pre-built images"
# docker compose up -d already waited for every depends_on:healthy condition
# before returning, so ch1 and ch2 are guaranteed healthy at this point.

# ── Step 7: Create Kafka topic ───────────────
# Partition count was a fixed 3 regardless of expected scale - Kafka's real
# parallelism ceiling IS its partition count (at most N things can consume
# in parallel, no matter how many ndr-engine replicas you run), so this
# needs to be sized to your actual tenant/sensor volume, not left at a
# fixed demo-scale default. Override with KAFKA_PARTITIONS=N before running
# this script if you know your expected scale; can only be *increased*
# later (kafka-topics.sh --alter --partitions N), never decreased, so it's
# safer to size a bit generously up front than to under-provision.
KAFKA_PARTITIONS="${KAFKA_PARTITIONS:-3}"
step "Creating Kafka topics (${KAFKA_PARTITIONS} partitions, replication-factor 3)"

log "Waiting for Kafka to be ready..."
sleep 20
for i in {1..30}; do
    if sudo docker exec kafka1 \
        /opt/kafka/bin/kafka-broker-api-versions.sh \
        --bootstrap-server localhost:9092 > /dev/null 2>&1; then
        log "✅ Kafka is ready"
        break
    fi
    echo -n "."
    sleep 3
done
echo ""

if sudo docker exec kafka1 \
    /opt/kafka/bin/kafka-topics.sh \
    --bootstrap-server localhost:9092 \
    --create --if-not-exists \
    --topic ndr-events \
    --partitions "$KAFKA_PARTITIONS" \
    --replication-factor 3 \
    2>/tmp/ndr_cloud_err; then
  log "✅ Kafka topic ndr-events created with ${KAFKA_PARTITIONS} partitions, replication-factor 3"
else
  record_error "Kafka" "topic creation failed ($(cat /tmp/ndr_cloud_err 2>/dev/null))" \
    "Run manually once Kafka is confirmed healthy: sudo docker exec kafka1 /opt/kafka/bin/kafka-topics.sh --bootstrap-server localhost:9092 --create --topic ndr-events --partitions $KAFKA_PARTITIONS --replication-factor 3"
fi

if sudo docker exec kafka1 \
    /opt/kafka/bin/kafka-configs.sh \
    --bootstrap-server localhost:9092 \
    --alter --entity-type topics \
    --entity-name ndr-events \
    --add-config retention.ms=86400000 \
    2>/tmp/ndr_cloud_err; then
  log "✅ Kafka retention set to 24 hours"
else
  record_error "Kafka" "setting retention.ms failed ($(cat /tmp/ndr_cloud_err 2>/dev/null))" \
    "Non-fatal — topic still works with the broker default retention; adjust later via kafka-configs.sh."
fi
rm -f /tmp/ndr_cloud_err

log "✅ Kafka topic and retention set"

# ── Step 8: UFW firewall rules ────────────────
step "Configuring UFW firewall"

if command -v ufw &>/dev/null; then
    log "Applying firewall rules..."
    sudo ufw --force reset > /dev/null 2>&1 || true
    sudo ufw default deny incoming > /dev/null
    sudo ufw default allow outgoing > /dev/null

    # Public-facing ports — sensors use HTTP, Kafka is internal only
    sudo ufw allow 22/tcp  comment "SSH"
    sudo ufw allow 80/tcp  comment "NDR API HTTP  (sensors + UI)"
    sudo ufw allow 443/tcp comment "NDR API HTTPS (sensors + UI)"
    sudo ufw allow 3000/tcp comment "NDR API legacy port"

    # Internal-only: Kafka, ClickHouse, Redis, Keeper all stay private
    sudo ufw deny 9092/tcp comment "Kafka (internal only — sensors use HTTP)"
    sudo ufw deny 8123/tcp comment "ClickHouse HTTP ch1 (internal only)"
    sudo ufw deny 8124/tcp comment "ClickHouse HTTP ch2 (internal only)"
    sudo ufw deny 9000/tcp comment "ClickHouse TCP ch1  (internal only)"
    sudo ufw deny 9001/tcp comment "ClickHouse TCP ch2  (internal only)"
    sudo ufw deny 9181/tcp comment "ClickHouse Keeper   (internal only)"
    sudo ufw deny 2181/tcp comment "ZooKeeper           (internal only)"
    sudo ufw deny 6379/tcp comment "Redis               (internal only)"

    sudo ufw --force enable > /dev/null
    log "✅ UFW rules applied:"
    log "   OPEN  : 22 (SSH), 80 (HTTP), 443 (HTTPS), 3000 (API)"
    log "   CLOSED: 9092 (Kafka), 8123/8124/9000/9001/9181 (ClickHouse/Keeper), 6379 (Redis)"
else
    warn "ufw not found — skipping firewall setup"
fi

# ── Step 8b: Auto-update watcher with health-check rollback ──────────
# Host-side loop (survives container restarts) watching for an update
# request, either from the in-app "Apply Update" button (writes this same
# flag file from inside ndr-engine, mounted through to this path) or
# triggered remotely - e.g. your CI running
# `ssh <user>@<this-host> "touch $INSTALL_DIR/scripts/.update-requested"`
# right after pushing new images. Before pulling, snapshots the current
# :latest as :latest-previous locally (no extra registry pull needed to
# roll back); after restarting on the new images, polls each service's
# Docker healthcheck. If they don't all report healthy within the
# timeout, retags :latest-previous back onto :latest and restarts again -
# verified live (tag-swap + restart correctly reverts a broken container
# to the last known-good image).
step "Installing auto-update watcher (with rollback on failed health check)"

cat > "$INSTALL_DIR/scripts/update-watcher.sh" << WATCHEREOF
#!/bin/bash
REGISTRY="${REGISTRY}"
INSTALL_DIR="$INSTALL_DIR"
FLAG="\$INSTALL_DIR/scripts/.update-requested"
IMAGES="ndr-engine ndr-ui provigil-auth"
SERVICES="ndr-engine-1 ndr-engine-2 ndr-engine-3 ndr-ui provigil-auth"
HEALTH_TIMEOUT=180

wait_healthy() {
    local deadline=\$(( \$(date +%s) + HEALTH_TIMEOUT ))
    while [ "\$(date +%s)" -lt "\$deadline" ]; do
        local all_healthy=true
        for svc in \$SERVICES; do
            status=\$(docker inspect --format='{{.State.Health.Status}}' "\$svc" 2>/dev/null || echo "missing")
            [ "\$status" = "healthy" ] || { all_healthy=false; break; }
        done
        [ "\$all_healthy" = true ] && return 0
        sleep 3
    done
    return 1
}

logger -t ndr-updater "NDR update watcher started — watching \$FLAG"
while true; do
    if [ -f "\$FLAG" ]; then
        rm -f "\$FLAG"
        logger -t ndr-updater "Update triggered"
        cd "\$INSTALL_DIR" || exit 1

        for img in \$IMAGES; do
            docker tag "\${REGISTRY}/\${img}:latest" "\${REGISTRY}/\${img}:latest-previous" 2>/dev/null || true
        done

        for img in \$IMAGES; do
            docker pull "\${REGISTRY}/\${img}:latest" 2>&1 | logger -t ndr-updater
        done
        docker compose -f docker-compose.yml -f docker-compose.cloud.yml up -d 2>&1 | logger -t ndr-updater

        logger -t ndr-updater "Waiting up to \${HEALTH_TIMEOUT}s for services to report healthy..."
        if wait_healthy; then
            logger -t ndr-updater "Update successful — all services healthy"
        else
            logger -t ndr-updater "Update FAILED health check — rolling back to previous images"
            for img in \$IMAGES; do
                docker tag "\${REGISTRY}/\${img}:latest-previous" "\${REGISTRY}/\${img}:latest" 2>/dev/null || true
            done
            docker compose -f docker-compose.yml -f docker-compose.cloud.yml up -d 2>&1 | logger -t ndr-updater
            if wait_healthy; then
                logger -t ndr-updater "Rollback successful — previous version restored"
            else
                logger -t ndr-updater "CRITICAL: rollback also failed health check — manual intervention required"
            fi
        fi
    fi
    sleep 30
done
WATCHEREOF
chmod +x "$INSTALL_DIR/scripts/update-watcher.sh"

sudo tee /etc/systemd/system/ndr-updater.service > /dev/null << EOF
[Unit]
Description=NDR Cloud Update Watcher
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

if sudo systemctl daemon-reload 2>/tmp/ndr_cloud_watcher_err && \
   sudo systemctl enable --now ndr-updater.service 2>>/tmp/ndr_cloud_watcher_err; then
    log "✅ Update watcher installed and running (ndr-updater.service)"
else
    warn "ndr-updater.service could not be started ($(cat /tmp/ndr_cloud_watcher_err 2>/dev/null)) — platform runs fine without it, just won't auto-update. Check: sudo systemctl status ndr-updater"
fi
rm -f /tmp/ndr_cloud_watcher_err

# ── Step 8c: Deploy webhook — lets CI trigger the watcher over HTTPS ──
# scripts/deploy-webhook.py (downloaded by the bootstrap step above, part of
# scripts/) checks X-Deploy-Secret and, if it matches, touches the same flag
# update-watcher.sh already polls. Runs on the host (needs no container
# access itself), reached through nginx's /deploy-webhook location - the
# secret is the only auth, so nginx rate-limits it hard (2r/m) and it's
# never exposed on its own port outside the Docker bridge.
step "Installing deploy webhook (CI trigger)"

sudo tee /etc/systemd/system/ndr-deploy-webhook.service > /dev/null << EOF
[Unit]
Description=NDR Deploy Webhook
After=network.target

[Service]
Type=simple
Environment=DEPLOY_WEBHOOK_SECRET=$DEPLOY_WEBHOOK_SECRET
Environment=UPDATE_FLAG_PATH=$INSTALL_DIR/scripts/.update-requested
Environment=DEPLOY_WEBHOOK_PORT=8099
ExecStart=/usr/bin/python3 $INSTALL_DIR/scripts/deploy-webhook.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

if sudo systemctl daemon-reload 2>/tmp/ndr_cloud_webhook_err && \
   sudo systemctl enable --now ndr-deploy-webhook.service 2>>/tmp/ndr_cloud_webhook_err; then
    log "✅ Deploy webhook installed and running (ndr-deploy-webhook.service)"
    info "  Trigger a deploy from CI right after release.sh pushes new images:"
    info "    curl -X POST https://$PUBLIC_IP/deploy-webhook -H \"X-Deploy-Secret: $DEPLOY_WEBHOOK_SECRET\""
    info "  (secret also saved in $INSTALL_DIR/.env as DEPLOY_WEBHOOK_SECRET)"
else
    warn "ndr-deploy-webhook.service could not be started ($(cat /tmp/ndr_cloud_webhook_err 2>/dev/null)) — you can still trigger updates via: touch $INSTALL_DIR/scripts/.update-requested"
fi
rm -f /tmp/ndr_cloud_webhook_err

# ── Step 9: Health checks ────────────────────
step "Running health checks"

echo ""
log "Checking services..."

# ClickHouse
if curl -s http://localhost:8123/ping > /dev/null 2>&1; then
    log "  ✅ ClickHouse ch1 — OK"
else
    warn "  ⚠️  ClickHouse ch1 — NOT READY"
fi
if sudo docker inspect --format='{{.State.Health.Status}}' clickhouse2 2>/dev/null | grep -q "^healthy$"; then
    log "  ✅ ClickHouse ch2 — OK"
else
    warn "  ⚠️  ClickHouse ch2 — NOT READY"
fi

# Kafka container
if sudo docker ps --format '{{.Names}}' | grep -q "^kafka1$"; then
    log "  ✅ Kafka         — running"
else
    warn "  ⚠️  Kafka         — NOT running"
fi

# Redis (Valkey) container — the actual container/service name is
# ndr-valkey, not ndr-redis; this check always warned regardless of real
# health because it was looking for a container that never exists.
if sudo docker ps --format '{{.Names}}' | grep -q "^ndr-valkey$"; then
    log "  ✅ Redis (Valkey) — running"
else
    warn "  ⚠️  Redis (Valkey) — NOT running"
fi

# Engine containers
for i in 1 2 3; do
    if sudo docker ps --format '{{.Names}}' | grep -q "^ndr-engine-$i$"; then
        log "  ✅ ndr-engine-$i  — running"
    else
        warn "  ⚠️  ndr-engine-$i  — NOT running"
    fi
done

# Nginx container
if sudo docker ps --format '{{.Names}}' | grep -q "^ndr-nginx$"; then
    log "  ✅ nginx         — running"
else
    warn "  ⚠️  nginx         — NOT running"
fi

# API health
sleep 5
if curl -s --max-time 5 http://localhost:80/api/health > /dev/null 2>&1; then
    log "  ✅ NDR API       — reachable at http://localhost"
else
    warn "  ⚠️  NDR API       — not responding yet (engines may still be starting)"
fi

# Skipped services confirmation
log "  ⏭️  OpenSearch    — skipped (cloud mode)"
log "  ⏭️  Vector        — skipped (cloud mode)"
log "  ⏭️  Agent-Z       — not installed (cloud mode)"
log "  ⏭️  Agent-S       — not installed (cloud mode)"
log "  ⏭️  Arkime        — not installed (cloud mode)"

# ── WSL2 auto port-forwarding ────────────────────────────────────────────────
# WSL2 runs in a VM — Windows doesn't auto-route external traffic into it.
# Call netsh.exe via WSL2 interop to set up the forwarding automatically.
if grep -qi microsoft /proc/version 2>/dev/null; then
    WSL_IP=$(ip addr show eth0 2>/dev/null | grep 'inet ' | awk '{print $2}' | cut -d/ -f1)
    if [ -n "$WSL_IP" ]; then
        log "WSL2 detected — configuring Windows port forwarding..."
        # Clear any stale rules first
        netsh.exe interface portproxy delete v4tov4 listenport=80  listenaddress=0.0.0.0 > /dev/null 2>&1 || true
        netsh.exe interface portproxy delete v4tov4 listenport=443 listenaddress=0.0.0.0 > /dev/null 2>&1 || true
        # Add forwarding rules: Windows 0.0.0.0:80/443 → WSL2 IP:80/443
        PORTPROXY_OK=true
        netsh.exe interface portproxy add v4tov4 \
            listenport=80 listenaddress=0.0.0.0 \
            connectport=80 connectaddress="$WSL_IP" > /dev/null 2>&1 || PORTPROXY_OK=false
        netsh.exe interface portproxy add v4tov4 \
            listenport=443 listenaddress=0.0.0.0 \
            connectport=443 connectaddress="$WSL_IP" > /dev/null 2>&1 || PORTPROXY_OK=false
        if $PORTPROXY_OK; then
            # Open Windows Firewall
            netsh.exe advfirewall firewall delete rule name="NDR HTTP"  > /dev/null 2>&1 || true
            netsh.exe advfirewall firewall delete rule name="NDR HTTPS" > /dev/null 2>&1 || true
            netsh.exe advfirewall firewall add rule name="NDR HTTP"  dir=in action=allow protocol=TCP localport=80  > /dev/null 2>&1 || true
            netsh.exe advfirewall firewall add rule name="NDR HTTPS" dir=in action=allow protocol=TCP localport=443 > /dev/null 2>&1 || true
            # Verify rules are actually in place
            PROXY_CHECK=$(netsh.exe interface portproxy show all 2>/dev/null | grep -c "$WSL_IP" || true)
            if [ "$PROXY_CHECK" -ge 2 ] 2>/dev/null; then
                log "✅ Windows port forwarding verified (WSL2 $WSL_IP → 0.0.0.0:80/443)"
                info "  Accessible at: http://$PUBLIC_IP  and  http://localhost"
                warn "  WSL2 IP changes on reboot — re-run install-cloud.sh to refresh forwarding"
            else
                warn "  portproxy rules may not have applied — verify with:"
                echo "    netsh.exe interface portproxy show all"
                info "  Expected: entries pointing to $WSL_IP on ports 80 and 443"
            fi
        else
            warn "  netsh failed (needs admin) — open PowerShell as Administrator and run:"
            echo "    netsh interface portproxy add v4tov4 listenport=80  listenaddress=0.0.0.0 connectport=80  connectaddress=$WSL_IP"
            echo "    netsh interface portproxy add v4tov4 listenport=443 listenaddress=0.0.0.0 connectport=443 connectaddress=$WSL_IP"
            echo "    netsh advfirewall firewall add rule name=\"NDR HTTP\"  dir=in action=allow protocol=TCP localport=80"
            echo "    netsh advfirewall firewall add rule name=\"NDR HTTPS\" dir=in action=allow protocol=TCP localport=443"
        fi
    fi
fi

# ── Final Summary ─────────────────────────────
echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║         NDR Cloud Deployment Complete!               ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${BLUE}  Public IP   :${NC} $PUBLIC_IP"
echo -e "${BLUE}  API (HTTP)  :${NC} http://$PUBLIC_IP (port 80)"
echo -e "${BLUE}  API (HTTPS) :${NC} https://$PUBLIC_IP (port 443, self-signed cert)"
[ -n "$PUBLIC_URL" ] && echo -e "${BLUE}  Public URL  :${NC} $PUBLIC_URL"
echo -e "${BLUE}  ClickHouse  :${NC} internal only (clickhouse1:8123, clickhouse2:8123)"
echo -e "${BLUE}  Kafka       :${NC} internal only (sensors use HTTP POST to /api/ingest)"
echo -e "${BLUE}  Redis       :${NC} internal only (ndr-redis:6379)"
echo -e "${BLUE}  SSL certs   :${NC} $INSTALL_DIR/config/nginx/ssl/ndr.crt + ndr.key (self-signed, already active)"
echo ""
echo -e "${YELLOW}  Next steps:${NC}"
echo "   1. (Optional, for a real domain instead of the self-signed cert)"
echo "      Point your domain DNS → $PUBLIC_IP"
echo "   2. sudo docker stop ndr-nginx"
echo "   3. certbot certonly --standalone -d your.domain.com"
echo "   4. Copy the resulting cert/key to $INSTALL_DIR/config/nginx/ssl/ndr.crt + ndr.key"
echo "   5. sudo docker start ndr-nginx"
echo "   6. On sensors: set CLOUD_URL=$SENSOR_URL in /opt/ndr-sensor/.env"
echo ""
echo -e "${GREEN}  Install log: $INSTALL_DIR/install-cloud.log${NC}"
echo ""
