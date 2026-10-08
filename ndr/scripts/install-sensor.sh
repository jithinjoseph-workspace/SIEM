#!/bin/bash
# NDR Sensor Installation Script
# Installs Agent-Z (Zeek), Agent-S (Suricata), Packet Recorder (Arkime),
# Vector telemetry pipeline, auditd endpoint visibility, and ndr-agent service.
set -e

# ── Colors ────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

# ── Persistent error log — survives a scrolled/closed terminal, unlike
# plain echo. Falls back to /tmp if /var/log isn't writable yet (e.g. this
# check runs before the root check below, in case someone sources this file).
LOG_FILE="/var/log/ndr/install-$(date +%Y%m%d-%H%M%S).log"
mkdir -p "$(dirname "$LOG_FILE")" 2>/dev/null && touch "$LOG_FILE" 2>/dev/null \
  || LOG_FILE="/tmp/ndr-install-$(date +%Y%m%d-%H%M%S).log"
touch "$LOG_FILE" 2>/dev/null || true

# ── Log helpers ───────────────────────────────────
log()  { echo -e "  ${GREEN}[+]${NC} $1"; }
warn() { echo -e "  ${YELLOW}[!]${NC} $1"; }
error(){ echo -e "  ${RED}[x]${NC} $1"; echo "[$(date '+%Y-%m-%d %H:%M:%S')] FATAL $1" >> "$LOG_FILE" 2>/dev/null; exit 1; }
info() { echo -e "  ${BLUE}[>]${NC} $1"; }

# record_error <component> <what went wrong> <how to fix it>
# Logs a structured, timestamped line to $LOG_FILE AND prints a warning —
# use this instead of a bare warn() for anything that leaves a component
# non-functional, so the reason + fix survive after the terminal is gone.
record_error() {
    local component="$1" detail="$2" hint="$3"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] ERROR component=\"$component\" detail=\"$detail\" fix=\"$hint\"" >> "$LOG_FILE" 2>/dev/null
    warn "$component: $detail"
    [ -n "$hint" ] && warn "  → Fix: $hint"
}

# ── Must run as root ──────────────────────────────
# Every failure mode we've seen in practice (can't write /etc/apt sources,
# can't install packages, can't manage systemd units) traces back to this.
# Check it up front with a clear message instead of dying 60 lines into the
# script on a cryptic "Permission denied".
if [ "$(id -u)" -ne 0 ]; then
  error "This script must be run as root. Try: sudo bash $0"
fi
hdr()  {
    echo -e ""
    echo -e "  ${CYAN}${BOLD}┌─────────────────────────────────────────────┐${NC}"
    printf  "  ${CYAN}${BOLD}│${NC}  %-43s${CYAN}${BOLD}│${NC}\n" "$1"
    echo -e "  ${CYAN}${BOLD}└─────────────────────────────────────────────┘${NC}"
}

# ── Progress bar ──────────────────────────────────
TOTAL_STEPS=15
CURRENT_STEP=0

step() {
    CURRENT_STEP=$((CURRENT_STEP + 1))
    local label="$1" BAR_WIDTH=36
    local filled=$(( (CURRENT_STEP * BAR_WIDTH) / TOTAL_STEPS ))
    local pct=$(( (CURRENT_STEP * 100) / TOTAL_STEPS ))
    local bar="" i
    for ((i=0; i<filled; i++));         do bar+="▓"; done
    for ((i=filled; i<BAR_WIDTH; i++)); do bar+="░"; done
    printf "\n  ${CYAN}[%s]${NC}  ${BOLD}%3d%%${NC}  ${DIM}%d/%d${NC}\n" \
        "$bar" "$pct" "$CURRENT_STEP" "$TOTAL_STEPS"
    hdr "$label"
}

# ── Spinner ───────────────────────────────────────
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

# ── Banner ────────────────────────────────────────
clear 2>/dev/null || true  # fails under set -e without a TTY/TERM (e.g. non-interactive/CI runs)
printf "\n"
printf "  ${CYAN}╔══════════════════════════════════════════════╗${NC}\n"
printf "  ${CYAN}║${NC}                                              ${CYAN}║${NC}\n"
printf "  ${CYAN}║${NC}    ${BOLD}ProVigilAI  —  Sensor Installer${NC}           ${CYAN}║${NC}\n"
printf "  ${CYAN}║${NC}                                              ${CYAN}║${NC}\n"
printf "  ${CYAN}║${NC}    Network Detection & Response Platform      ${CYAN}║${NC}\n"
printf "  ${CYAN}║${NC}    Agent-Z  ·  Agent-S  ·  Packet Recorder   ${CYAN}║${NC}\n"
printf "  ${CYAN}║${NC}                                              ${CYAN}║${NC}\n"
printf "  ${CYAN}║${NC}    ${DIM}◆  Powered by PromaSecure  ◆${NC}               ${CYAN}║${NC}\n"
printf "  ${CYAN}║${NC}                                              ${CYAN}║${NC}\n"
printf "  ${CYAN}╚══════════════════════════════════════════════╝${NC}\n"
printf "\n"

# ── Parse arguments ──────────────────────────────
CLOUD_URL=""
TENANT_ID=""
API_KEY=""
IFACE=""
KAFKA_BOOTSTRAP=""
SENSOR_MODE=""   # "tap" = passive probe/SPAN, "agent" = installed on monitored server
NDR_AGENT_SECRET=""

while [[ $# -gt 0 ]]; do
  case $1 in
    --cloud-url)      CLOUD_URL="$2";        shift 2 ;;
    --tenant-id)      TENANT_ID="$2";        shift 2 ;;
    --api-key)        API_KEY="$2";          shift 2 ;;
    --interface)      IFACE="$2";            shift 2 ;;
    --kafka)          KAFKA_BOOTSTRAP="$2";  shift 2 ;;
    --mode)           SENSOR_MODE="$2";      shift 2 ;;
    --agent-secret)   NDR_AGENT_SECRET="$2"; shift 2 ;;
    *) warn "Unknown option: $1"; shift ;;
  esac
done

# Generate agent secret if not provided
if [ -z "$NDR_AGENT_SECRET" ]; then
  NDR_AGENT_SECRET=$(openssl rand -hex 32 2>/dev/null || echo "ndr-sensor-$(date +%s)")
fi

# ── Validate ─────────────────────────────────────
if [ -z "$CLOUD_URL" ] || \
   [ -z "$TENANT_ID" ] || \
   [ -z "$API_KEY" ]; then
  echo "Usage: $0 \\"
  echo "  --cloud-url https://your-cloud.com \\"
  echo "  --tenant-id acme1 \\"
  echo "  --api-key YOUR_KEY \\"
  echo "  [--interface eth0] \\"
  echo "  [--kafka cloud-host:9092] \\"
  echo "  [--mode tap|agent]   # tap=passive probe, agent=on monitored server"
  exit 1
fi

# Derive Kafka bootstrap from cloud-url
# if not explicitly provided
if [ -z "$KAFKA_BOOTSTRAP" ]; then
  CLOUD_HOST=$(echo "$CLOUD_URL" | \
    sed -E 's|https?://([^:/]+).*|\1|')
  KAFKA_BOOTSTRAP="${CLOUD_HOST}:9092"
  log "Kafka bootstrap: $KAFKA_BOOTSTRAP"
fi

# ── Detect interface ──────────────────────────────
if [ -z "$IFACE" ]; then
  IFACES=$(ip -o -4 addr show 2>/dev/null | \
    grep -v "127\.0\.0\.1\|docker\|br-\|veth\| lo " | \
    awk '{print $2}') || true

  IFACE_COUNT=$(echo "$IFACES" | \
    grep -c . 2>/dev/null || echo 0)

  if [ "$IFACE_COUNT" -eq 0 ]; then
    read -rp "Enter interface (e.g. eth0, eno1): " \
      IFACE < /dev/tty
    IFACE=${IFACE:-eth0}
  elif [ "$IFACE_COUNT" -eq 1 ]; then
    IFACE=$(echo "$IFACES" | head -1)
    log "Auto-detected interface: $IFACE"
  else
    echo "Available interfaces:"
    echo "─────────────────────"
    i=1
    while IFS= read -r iface; do
      IP=$(ip -o -4 addr show "$iface" \
        2>/dev/null | awk '{print $4}' | \
        cut -d/ -f1)
      echo "  $i) $iface${IP:+ ($IP)}"
      i=$((i+1))
    done <<< "$IFACES"
    echo "─────────────────────"
    read -rp "Select interface [1]: " IFACE_NUM < /dev/tty
    IFACE_NUM=${IFACE_NUM:-1}
    IFACE=$(echo "$IFACES" | \
      sed -n "${IFACE_NUM}p")
    log "Selected: $IFACE"
  fi
fi

# ── Detect sensor's own IP on chosen interface ────
SENSOR_IP=$(ip -o -4 addr show "$IFACE" 2>/dev/null \
  | awk '{print $4}' | cut -d/ -f1 | head -1)
if [ -z "$SENSOR_IP" ]; then
  log "⚠️  Could not detect sensor IP on $IFACE — exclusion rules will be skipped"
fi
log "Sensor IP: ${SENSOR_IP:-unknown}"
mkdir -p "$(dirname "$0")/../.runtime"
echo "$SENSOR_IP" > "$(dirname "$0")/../.runtime/ndr_sensor_ip"

# ── Select deployment mode ────────────────────────
if [ -z "$SENSOR_MODE" ]; then
  printf "\n"
  printf "  ${CYAN}┌──────────────────────────────────────────────┐${NC}\n"
  printf "  ${CYAN}│${NC}  ${BOLD}Select Deployment Mode${NC}                        ${CYAN}│${NC}\n"
  printf "  ${CYAN}├──────────────────────────────────────────────┤${NC}\n"
  printf "  ${CYAN}│${NC}  ${GREEN}[1]${NC} TAP / SPAN  — passive network probe         ${CYAN}│${NC}\n"
  printf "  ${CYAN}│${NC}       Traffic mirrored to this VM             ${CYAN}│${NC}\n"
  printf "  ${CYAN}│${NC}       Sensor IP excluded from Agent-S alerts  ${CYAN}│${NC}\n"
  printf "  ${CYAN}│${NC}                                              ${CYAN}│${NC}\n"
  printf "  ${CYAN}│${NC}  ${BLUE}[2]${NC} Cloud Agent — installed ON monitored host   ${CYAN}│${NC}\n"
  printf "  ${CYAN}│${NC}       Server's own traffic is what we monitor ${CYAN}│${NC}\n"
  printf "  ${CYAN}└──────────────────────────────────────────────┘${NC}\n"
  printf "\n"
  read -rp "  Enter choice (1/2) [default: 1]: " MODE_NUM < /dev/tty
  case "${MODE_NUM:-1}" in
    1) SENSOR_MODE="tap"   ;;
    2) SENSOR_MODE="agent" ;;
    *) SENSOR_MODE="tap"   ;;
  esac
fi
log "Deployment mode: $SENSOR_MODE"
echo "$SENSOR_MODE" > "$(dirname "$0")/../.runtime/ndr_mode"

# ── Check OS and root ─────────────────────────────
[ -f /etc/os-release ] || error "Unsupported OS"
source /etc/os-release
log "OS: $PRETTY_NAME"
[ "$EUID" -eq 0 ] || error "Run as root: sudo $0"

# ── Stop existing services ────────────────────────
step "Preparing Environment"
log "Stopping any existing services..."
pkill -f agent.py       2>/dev/null || true
systemctl stop ndr-vector   2>/dev/null || true
systemctl stop ndr-agent    2>/dev/null || true
systemctl stop arkime-capture 2>/dev/null || true
pkill -9 -f suricata    2>/dev/null || true
pkill -9 -f "zeek"      2>/dev/null || true
pkill -9 -f vector      2>/dev/null || true
rm -f /tmp/suricata.pid \
      /var/run/suricata.pid \
      /run/suricata.pid
sleep 2

# ── Install dependencies ──────────────────────────
step "Installing Dependencies"
log "Updating package lists..."
# Foundational step — curl/wget/docker installed here are required by nearly
# everything downstream, so a hard stop is correct if this fails, but it
# needs a clear reason instead of a silent set -e death.
apt-get update -qq 2>/tmp/ndr_deps_err || error "apt-get update failed ($(cat /tmp/ndr_deps_err 2>/dev/null)) — check network/DNS connectivity before re-running."
rm -f /tmp/ndr_deps_err
# apt-get update can report success (exit 0) even when every index fetch failed
# (it just warns and falls back to whatever is cached) — so the real check for
# "are we actually offline" has to happen here, not above. curl/wget are load-
# bearing for the rest of this script, so verify they actually landed instead
# of trusting the install command's own exit code.
(apt-get install -y -qq \
  curl wget git python3 python3-pip python3-requests \
  apt-transport-https gnupg2 \
  software-properties-common \
  libpcre3 libpcre3-dev \
  ethtool docker.io \
  arp-scan iputils-arping snmp > /tmp/ndr_deps_install_err 2>&1) &
DEPS_PID=$!
spinner $DEPS_PID "Installing base packages"
DEPS_RC=0
wait $DEPS_PID || DEPS_RC=$?
if ! command -v curl >/dev/null 2>&1 || ! command -v wget >/dev/null 2>&1; then
    error "Base package install failed — curl/wget missing ($(tail -3 /tmp/ndr_deps_install_err 2>/dev/null | tr '\n' ' ')). Check network/DNS connectivity, then re-run: apt-get update && apt-get install -y curl wget git docker.io"
elif [ "$DEPS_RC" -ne 0 ]; then
    record_error "Base Packages" "some non-critical packages failed to install ($(tail -3 /tmp/ndr_deps_install_err 2>/dev/null | tr '\n' ' '))" "re-run manually once network is restored: apt-get install -y arp-scan iputils-arping snmp ethtool docker.io git python3 python3-pip"
fi
rm -f /tmp/ndr_deps_install_err

# scapy needed for ARP isolation on the sensor
pip3 install scapy --break-system-packages -q 2>/dev/null || pip3 install scapy -q 2>/dev/null || true
log "Dependencies installed"

# Allow sensor agent to run iptables without a password
mkdir -p /etc/sudoers.d
if echo "${SENSOR_USER:-root} ALL=(root) NOPASSWD: /usr/sbin/iptables" \
    | tee /etc/sudoers.d/ndr-iptables > /dev/null 2>/tmp/ndr_sudoers_err; then
  chmod 440 /etc/sudoers.d/ndr-iptables
else
  record_error "iptables sudoers" "could not write /etc/sudoers.d/ndr-iptables ($(cat /tmp/ndr_sudoers_err 2>/dev/null))" \
    "ARP isolation (device quarantine) will not work until this is fixed manually: mkdir -p /etc/sudoers.d && echo '${SENSOR_USER:-root} ALL=(root) NOPASSWD: /usr/sbin/iptables' > /etc/sudoers.d/ndr-iptables && chmod 440 /etc/sudoers.d/ndr-iptables"
fi
rm -f /tmp/ndr_sudoers_err

step "Capture Utilities"
log "Checking packet capture tools..."

DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
  software-properties-common zstd tcpdump > /dev/null 2>&1 || true

# Helper: returns tshark major.minor as integers
tshark_ver_ok() {
  local MAJOR MINOR
  MAJOR=$(tshark --version 2>/dev/null | grep -oP '(?<=TShark \(Wireshark\) )\d+' || echo 0)
  MINOR=$(tshark --version 2>/dev/null | grep -oP '(?<=TShark \(Wireshark\) \d\.)\d+' || echo 0)
  # returns 0 (true) if >= 3.4
  [ "${MAJOR:-0}" -gt 3 ] || \
    { [ "${MAJOR:-0}" -eq 3 ] && [ "${MINOR:-0}" -ge 4 ]; }
}

if tshark_ver_ok; then
  log "  ✅ tshark already >= 3.4: $(tshark --version 2>/dev/null | head -1) — skipping upgrade"
else
  log "  tshark too old ($(tshark --version 2>/dev/null | head -1 || echo 'not installed')) — upgrading..."

  # ── Option A: Wireshark PPA ─────────────────────────────────────────────
  log "  Trying Wireshark PPA (Option A)..."
  if add-apt-repository -y ppa:wireshark-dev/stable > /dev/null 2>&1; then
    apt-get update -qq > /dev/null 2>&1 || true
    DEBIAN_FRONTEND=noninteractive \
      apt-get install -y -qq tshark wireshark-common > /dev/null 2>&1 || true
  fi

  if tshark_ver_ok; then
    log "  ✅ tshark upgraded via PPA: $(tshark --version 2>/dev/null | head -1)"
  else
    # ── Option B: snap fallback ──────────────────────────────────────────
    log "  PPA insufficient — installing via snap (Option B)..."
    apt-get install -y -qq snapd > /dev/null 2>&1 || true
    snap install wireshark > /dev/null 2>&1 || true
    ln -sf /snap/bin/tshark /usr/local/bin/tshark 2>/dev/null || true
    if tshark_ver_ok; then
      log "  ✅ tshark upgraded via snap: $(tshark --version 2>/dev/null | head -1)"
    else
      warn "  tshark upgrade failed — communityid filter unavailable, will use raw copy"
    fi
  fi
fi

log "tshark: $(tshark --version 2>/dev/null | head -1 || echo 'not installed')"
log "zstd:   $(zstd --version 2>/dev/null | head -1 || echo 'not installed')"

pip3 install requests --quiet 2>/dev/null || true

# ── Install Agent-Z ───────────────────────────────
step "Agent-Z  (Network Analyzer)"
log "Installing Agent-Z..."
ZEEK_OK=0
if ! command -v /opt/zeek/bin/zeek &>/dev/null; then
  OS_VERSION=$(lsb_release -rs 2>/dev/null || echo "22.04")
  ZEEK_UBUNTU_VER="$OS_VERSION"
  for TRY_VER in "$OS_VERSION" "24.04" "22.04"; do
    ZEEK_KEY_URL="https://download.opensuse.org/repositories/security:zeek/xUbuntu_${TRY_VER}/Release.key"
    if curl -fsSL --max-time 10 "$ZEEK_KEY_URL" -o /dev/null 2>/dev/null; then
      ZEEK_UBUNTU_VER="$TRY_VER"
      break
    fi
  done
  log "Using Agent-Z repo for Ubuntu ${ZEEK_UBUNTU_VER}"

  # Every step below is an if/elif condition on purpose — under `set -e`, a
  # bare (unguarded) command that fails kills the ENTIRE script immediately
  # with no message. Wrapping each one in a condition is exempt from that,
  # so a failure here is recorded and reported instead of silently fatal.
  if ! echo "deb http://download.opensuse.org/repositories/security:/zeek/xUbuntu_${ZEEK_UBUNTU_VER}/ /" \
      | tee /etc/apt/sources.list.d/security:zeek.list > /dev/null 2>/tmp/ndr_zeek_err; then
    record_error "Agent-Z" "could not write apt source list ($(cat /tmp/ndr_zeek_err 2>/dev/null))" \
      "Run this script as root: sudo bash $0"
  elif ! curl -fsSL "https://download.opensuse.org/repositories/security:zeek/xUbuntu_${ZEEK_UBUNTU_VER}/Release.key" 2>/tmp/ndr_zeek_err \
      | gpg --dearmor > /etc/apt/trusted.gpg.d/security_zeek.gpg 2>>/tmp/ndr_zeek_err; then
    record_error "Agent-Z" "could not fetch/import the repo signing key ($(cat /tmp/ndr_zeek_err 2>/dev/null))" \
      "Check this host can reach download.opensuse.org (443) — no proxy/firewall blocking it."
  elif ! apt-get update -qq 2>/tmp/ndr_zeek_err; then
    record_error "Agent-Z" "apt-get update failed ($(cat /tmp/ndr_zeek_err 2>/dev/null))" \
      "Check general network/DNS connectivity and existing /etc/apt sources."
  elif apt-get install -y -qq zeek > /dev/null 2>/tmp/ndr_zeek_err; then
    log "Agent-Z installed"
    echo 'export PATH=$PATH:/opt/zeek/bin' >> /etc/profile
    export PATH=$PATH:/opt/zeek/bin
    ZEEK_OK=1
  else
    record_error "Agent-Z" "package install failed for Ubuntu ${ZEEK_UBUNTU_VER} ($(cat /tmp/ndr_zeek_err 2>/dev/null))" \
      "The security:zeek repo may not yet publish builds for this Ubuntu release — check https://download.opensuse.org/repositories/security:/zeek/ manually."
  fi
  rm -f /tmp/ndr_zeek_err
else
  log "Agent-Z already installed"
  ZEEK_OK=1
fi
if [ "$ZEEK_OK" = "1" ]; then
  log "✅ Agent-Z ready"
else
  warn "❌ Agent-Z NOT installed — network traffic analysis (DNS/HTTP/TLS/connection logs) will be unavailable on this sensor."
  warn "   Continuing with the rest of the install; see $LOG_FILE for details and re-run later once fixed."
fi

# ── Install Agent-S ───────────────────────────────
step "Agent-S  (Threat Detection)"
log "Installing Agent-S..."
SURICATA_OK=0
if ! command -v suricata &>/dev/null; then
  if ! apt-get update -qq 2>/tmp/ndr_suri_err; then
    record_error "Agent-S" "apt-get update failed ($(cat /tmp/ndr_suri_err 2>/dev/null))" \
      "Check general network/DNS connectivity."
  elif apt-get install -y suricata 2>/tmp/ndr_suri_err; then
    log "Agent-S installed from repository"
    SURICATA_OK=1
  else
    record_error "Agent-S" "package install failed ($(cat /tmp/ndr_suri_err 2>/dev/null))" \
      "Ensure the 'universe' repo is enabled: sudo add-apt-repository universe && sudo apt-get update"
  fi
  rm -f /tmp/ndr_suri_err
  systemctl disable suricata 2>/dev/null || true
  systemctl stop suricata 2>/dev/null || true
else
  log "Agent-S already installed"
  SURICATA_OK=1
  systemctl disable suricata 2>/dev/null || true
  systemctl stop suricata 2>/dev/null || true
fi
suricata-update > /dev/null 2>&1 || true
if [ "$SURICATA_OK" = "1" ]; then
  log "✅ Agent-S ready"
else
  warn "❌ Agent-S NOT installed — signature-based threat detection (ET rules) will be unavailable on this sensor."
  warn "   Continuing with the rest of the install; see $LOG_FILE for details and re-run later once fixed."
fi

# ── Packet Recorder ───────────────────────────────
step "Packet Recorder"
log "Installing Packet Recorder..."
ARKIME_VERSION="5.1.0"
UBUNTU_MAJOR=$(lsb_release -rs | cut -d. -f1)
ARKIME_OK=0

if ! command -v /opt/arkime/bin/capture &>/dev/null; then
  if   [ "$UBUNTU_MAJOR" -le "21" ]; then
    DEB="arkime_${ARKIME_VERSION}-1.ubuntu2004_amd64.deb"
  elif [ "$UBUNTU_MAJOR" -le "23" ]; then
    DEB="arkime_${ARKIME_VERSION}-1.ubuntu2204_amd64.deb"
  else
    DEB="arkime_${ARKIME_VERSION}-1.ubuntu2404_amd64.deb"
  fi

  log "Downloading Arkime ${ARKIME_VERSION}..."
  if ! wget --timeout=120 --progress=dot:mega \
      "https://github.com/arkime/arkime/releases/download/v${ARKIME_VERSION}/${DEB}" \
      -O /tmp/arkime.deb 2>/tmp/ndr_ark_err; then
    record_error "Packet Recorder" "download failed for ${DEB} ($(cat /tmp/ndr_ark_err 2>/dev/null))" \
      "Check internet access to github.com, or that Arkime ${ARKIME_VERSION} still publishes a build for Ubuntu ${UBUNTU_MAJOR}.x."
  else
    apt-get install -y -qq \
      libwww-perl libjson-perl \
      libyaml-dev librdkafka1 \
      libmagic1 libmaxminddb0 \
      libpcre2-8-0 > /dev/null 2>&1 || true

    if dpkg -i /tmp/arkime.deb > /dev/null 2>/tmp/ndr_ark_err || apt-get install -f -y > /dev/null 2>>/tmp/ndr_ark_err; then
      ARKIME_OK=1
    else
      record_error "Packet Recorder" "package install failed ($(cat /tmp/ndr_ark_err 2>/dev/null))" \
        "Try: sudo dpkg -i /tmp/arkime.deb && sudo apt-get install -f -y  (dependency resolution)."
    fi
  fi
  rm -f /tmp/arkime.deb /tmp/ndr_ark_err
else
  ARKIME_OK=1
fi
if command -v /opt/arkime/bin/capture &>/dev/null; then
  ARKIME_OK=1
  log "✅ Arkime: $(/opt/arkime/bin/capture --version 2>/dev/null | head -1)"
else
  warn "❌ Packet Recorder NOT installed — full-packet capture/PCAP evidence will be unavailable on this sensor."
  warn "   Continuing with the rest of the install; see $LOG_FILE for details and re-run later once fixed."
fi

# ── Log Collector ─────────────────────────────────
step "Log Collector"
log "Installing Log Collector..."
VECTOR_OK=0
if ! command -v vector &>/dev/null; then
  ARCH=$(dpkg --print-architecture)
  VECTOR_VER="0.32.1"

  if ! curl -fsSL https://repositories.vector.dev/gpg.key 2>/tmp/ndr_vec_err \
      | gpg --dearmor > /usr/share/keyrings/vector-keyring.gpg 2>>/tmp/ndr_vec_err; then
    record_error "Log Collector" "could not fetch/import the Vector repo signing key ($(cat /tmp/ndr_vec_err 2>/dev/null))" \
      "Check internet access to repositories.vector.dev — will fall back to a direct .deb download."
  elif ! { echo "deb [arch=$ARCH signed-by=/usr/share/keyrings/vector-keyring.gpg] https://repositories.vector.dev/ubuntu/ stable vector-0" \
        | tee /etc/apt/sources.list.d/vector.list > /dev/null 2>/tmp/ndr_vec_err \
      && apt-get update -qq 2>>/tmp/ndr_vec_err \
      && apt-get install -y -qq vector > /dev/null 2>>/tmp/ndr_vec_err; }; then
    record_error "Log Collector" "apt install failed ($(cat /tmp/ndr_vec_err 2>/dev/null)) — falling back to direct .deb download" ""
  else
    VECTOR_OK=1
  fi

  if [ "$VECTOR_OK" != "1" ]; then
    # -nv (not -q) — quiet mode suppresses wget's own error text too, which
    # would otherwise leave the captured error message blank below.
    if wget -nv --timeout=60 \
        "https://github.com/vectordotdev/vector/releases/download/v${VECTOR_VER}/vector_${VECTOR_VER}-1_${ARCH}.deb" \
        -O /tmp/vector.deb 2>/tmp/ndr_vec_err \
        && dpkg -i /tmp/vector.deb > /dev/null 2>>/tmp/ndr_vec_err; then
      VECTOR_OK=1
    else
      record_error "Log Collector" "direct .deb fallback also failed ($(cat /tmp/ndr_vec_err 2>/dev/null))" \
        "Check internet access to github.com, or install vector manually: https://vector.dev/docs/setup/installation/"
    fi
    rm -f /tmp/vector.deb
  fi
  rm -f /tmp/ndr_vec_err
else
  VECTOR_OK=1
fi
if command -v vector &>/dev/null; then
  log "✅ Log Collector: $(vector --version 2>/dev/null)"
else
  warn "❌ Log Collector NOT installed — logs will not be shipped to the cloud from this sensor."
  warn "   Continuing with the rest of the install; see $LOG_FILE for details and re-run later once fixed."
fi

# ── Endpoint Visibility ───────────────────────────
step "Endpoint Visibility"
log "Installing endpoint audit agent..."
if apt-get install -y -qq auditd audispd-plugins > /dev/null 2>/tmp/ndr_audit_err; then
  log "✅ Endpoint audit agent ready"
else
  record_error "Endpoint Visibility" "auditd install failed ($(cat /tmp/ndr_audit_err 2>/dev/null))" \
    "Ensure the 'universe' repo is enabled: sudo add-apt-repository universe && sudo apt-get update"
  warn "❌ Endpoint audit agent NOT installed — Linux endpoint visibility (auditd) will be unavailable on this sensor."
fi
rm -f /tmp/ndr_audit_err

# ── Create directories ────────────────────────────
step "Directories & Configuration"
log "Creating runtime directories..."
mkdir -p /opt/arkime/raw \
         /opt/arkime/logs \
         /opt/arkime/etc \
         /opt/ndr-sensor/pcap-tmp \
         /var/log/ndr/zeek \
         /var/log/ndr/suricata \
         /etc/ndr \
         /etc/vector/data \
         /var/run/suricata

chmod -R 777 /var/log/ndr/ \
             /etc/vector/data \
             /opt/ndr-sensor \
             /var/run/suricata
chmod 755 /opt/arkime/raw

# ── Zeek log rotation for all logs ───────────────
cat > /etc/logrotate.d/zeek-ndr << 'EOF'
/var/log/ndr/zeek/*.log {
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

# ── Save sensor config ────────────────────────────
log "Saving sensor config..."
cat > /etc/ndr/sensor.conf << EOF
CLOUD_URL=${CLOUD_URL}
TENANT_ID=${TENANT_ID}
API_KEY=${API_KEY}
IFACE=${IFACE}
KAFKA_BOOTSTRAP=${KAFKA_BOOTSTRAP}
NDR_AGENT_SECRET=${NDR_AGENT_SECRET}
INSTALL_DATE=$(date -u +%Y-%m-%dT%H:%M:%SZ)
# Optional: this sensor ignores its own traffic to the platform so it doesn't raise alerts about itself.
# EXCLUDE_CLOUD_TRAFFIC=0
# EXCLUDE_CLOUD_IPS=203.0.113.10,203.0.113.11
EOF

# ── Search Backend ────────────────────────────────
step "Search Backend"
# Start OpenSearch FIRST, wait fully,
# THEN configure and start Arkime
log "Starting local OpenSearch for Arkime..."

OS_PORT=9200

# Check if something is already on port 9200
if ss -tlnp 2>/dev/null | grep -q ":9200 " || \
   nc -z 127.0.0.1 9200 2>/dev/null; then
  echo ""
  echo "⚠️  Port 9200 is already in use."
  echo "   1) Kill whatever is on port 9200 and use it"
  echo "   2) Use a different port"
  read -rp "   Choice [1/2]: " _PORT_CHOICE < /dev/tty
  if [ "$_PORT_CHOICE" = "1" ]; then
    log "Killing process on port 9200..."
    fuser -k 9200/tcp 2>/dev/null || \
      lsof -ti:9200 2>/dev/null | xargs -r kill -9 || true
    sleep 2
    OS_PORT=9200
  else
    read -rp "   Enter port number [default 9201]: " _NEW_PORT < /dev/tty
    OS_PORT="${_NEW_PORT:-9201}"
    log "Using port $OS_PORT for OpenSearch"
  fi
fi

# Remove old container if exists
docker rm -f opensearch-arkime 2>/dev/null || true

# Fail fast with a clear reason if Docker itself isn't reachable, rather than
# burning through 5 port retries with a misleading "may be allocated" guess
# when the real problem is that the daemon never started.
if ! docker info >/dev/null 2>/tmp/ndr_os_err; then
  error "Docker is not reachable ($(cat /tmp/ndr_os_err 2>/dev/null)) — OpenSearch (required for Arkime) cannot start. Check: sudo systemctl status docker"
fi
rm -f /tmp/ndr_os_err

PORT_ATTEMPTS=0
MAX_PORT_RETRIES=5
while [ $PORT_ATTEMPTS -lt $MAX_PORT_RETRIES ]; do
  if docker run -d \
    --name opensearch-arkime \
    -e "discovery.type=single-node" \
    -e "DISABLE_SECURITY_PLUGIN=true" \
    -e "OPENSEARCH_JAVA_OPTS=-Xms256m -Xmx512m" \
    -p "${OS_PORT}:9200" \
    --restart unless-stopped \
    opensearchproject/opensearch:2.5.0 2>/tmp/ndr_os_err; then
    log "✅ OpenSearch container started on port ${OS_PORT}"
    break
  else
    warn "Failed to start on port ${OS_PORT} ($(tail -2 /tmp/ndr_os_err 2>/dev/null | tr '\n' ' '))."
    docker rm -f opensearch-arkime 2>/dev/null || true
    OS_PORT=$((OS_PORT+1))
    PORT_ATTEMPTS=$((PORT_ATTEMPTS+1))
    log "Trying next port: ${OS_PORT}..."
  fi
done
rm -f /tmp/ndr_os_err

if [ $PORT_ATTEMPTS -eq $MAX_PORT_RETRIES ]; then
  error "Could not find a free port for OpenSearch after several attempts."
fi

# Write the resolved OpenSearch port into sensor.conf so pcap-uploader reads it
echo "OPENSEARCH_URL=http://localhost:${OS_PORT}" >> /etc/ndr/sensor.conf

# Wait properly — up to 3 minutes
log "Waiting for OpenSearch on port ${OS_PORT} (up to 3 min)..."
TRIES=0
MAX_TRIES=60   # 60 × 3s = 180s = 3 min
while [ $TRIES -lt $MAX_TRIES ]; do
  if curl -s "http://localhost:${OS_PORT}" \
      > /dev/null 2>&1; then
    # Extra check: cluster health green or yellow
    STATUS=$(curl -s \
      "http://localhost:${OS_PORT}/_cluster/health" \
      2>/dev/null | \
      python3 -c "import sys,json; \
        d=json.load(sys.stdin); \
        print(d.get('status','red'))" \
      2>/dev/null || echo "red")
    if [ "$STATUS" != "red" ]; then
      log "✅ OpenSearch ready on port ${OS_PORT} (status: $STATUS)"
      break
    fi
  fi
  echo -n "."
  sleep 3
  TRIES=$((TRIES+1))
done
echo ""

if [ $TRIES -ge $MAX_TRIES ]; then
  warn "OpenSearch took too long to start"
  warn "Arkime may not work correctly"
fi

# ── Configure Packet Recorder ─────────────────────
step "Packet Recorder  · Configuration"
log "Configuring Packet Recorder..."
ARKIME_PASS=$(echo "$API_KEY" | \
  sha256sum | cut -c1-16)

cat > /opt/arkime/etc/config.ini << EOF
[default]
elasticsearch=http://localhost:${OS_PORT}
passwordSecret=${ARKIME_PASS}
serverSecret=${ARKIME_PASS}
httpRealm=Arkime
interface=${IFACE}
pcapDir=/opt/arkime/raw
maxFileSizeG=4
maxFileTimeM=60
pcapWriteMethod=simple
simpleCompression=none
pcapWriteSize=262143
logLevel=warn
maxDays=7
freeSpaceG=5
tcpTimeout=600
udpTimeout=30
maxStreams=500000
maxPackets=10000
packetThreads=2
communityId=true
cronQueries=false
viewPort=8005
EOF

# ── Initialize Arkime database ────────────────────
log "Initializing Arkime index in OpenSearch..."
echo "yes" | timeout 90 \
  /opt/arkime/db/db.pl \
  "http://localhost:${OS_PORT}" init \
  --ifneeded 2>&1 || \
echo "yes" | timeout 90 \
  /opt/arkime/db/db.pl \
  "http://localhost:${OS_PORT}" init \
  2>&1 || true

# ── Create Arkime admin user ──────────────────────
if [ "$ARKIME_OK" = "1" ]; then
  log "Creating Arkime admin user..."
  if /opt/arkime/bin/arkime_add_user.sh admin "NDR Admin" "$ARKIME_PASS" --admin 2>/tmp/ndr_ark_user_err; then
    log "✅ Arkime admin: user=admin pass=$ARKIME_PASS"
  else
    record_error "Packet Recorder" "could not create the Arkime admin user ($(cat /tmp/ndr_ark_user_err 2>/dev/null))" \
      "Run manually once Arkime is confirmed working: /opt/arkime/bin/arkime_add_user.sh admin \"NDR Admin\" '<password>' --admin"
  fi
  rm -f /tmp/ndr_ark_user_err
else
  warn "Skipping Arkime admin user creation — Packet Recorder was not installed."
fi

# ── FIX: Create Arkime CAPTURE service ───────────
cat > /etc/systemd/system/arkime-capture.service \
  << EOF
[Unit]
Description=Arkime Packet Capture
After=network.target opensearch-arkime.service
[Service]
Type=simple
ExecStartPre=/bin/sleep 5
ExecStart=/opt/arkime/bin/capture \
  -c /opt/arkime/etc/config.ini \
  --insecure
Restart=always
RestartSec=15
LimitCORE=infinity
LimitMEMLOCK=infinity
[Install]
WantedBy=multi-user.target
EOF

# ── Configure Agent-Z ─────────────────────────────
step "Agent-Z  · Configuration"
log "Configuring Agent-Z..."
export PATH=$PATH:/opt/zeek/bin

if [ -f /opt/zeek/etc/node.cfg ]; then
  cat > /opt/zeek/etc/node.cfg << EOF
[zeek]
type=standalone
host=localhost
interface=$IFACE
EOF

  cat > /opt/zeek/etc/zeekctl.cfg << EOF
LogRotationInterval = 3600
LogExpireInterval = 0
StatsLogEnable = 0
LogDir = /var/log/ndr/zeek
EOF

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
    # >&2 is required: zeek_load runs inside $(...) in the local.zeek heredoc
    # below, which captures stdout into the file. warn() prints ANSI-colored
    # text to stdout, so without this the escape codes (\x1b) land in
    # local.zeek in place of an @load line and Zeek fails to parse it,
    # crash-looping forever (seen live: "local.zeek, line 8: unrecognized
    # character: '\x1b'" when misc/detect-traceroute is missing on the
    # installed Zeek version). install.sh's copy already used plain stderr.
    warn "  Agent-Z: skipping missing script: $s" >&2
  }

  tee "$ZEEK_SITE/local.zeek" > /dev/null << ZEEKCONF
# NDR Agent-Z Configuration
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

  # TAP mode only: exclude sensor's own IP from Agent-Z conn.log
  if [ "$SENSOR_MODE" = "tap" ] && [ -n "$SENSOR_IP" ]; then
    echo "redef Site::local_nets += { ${SENSOR_IP}/32 };" \
      >> "$ZEEK_SITE/local.zeek"
    log "Agent-Z: sensor $SENSOR_IP added to local_nets (TAP mode)"
  fi

  tee "$ZEEK_SITE/ndr-arp.zeek" > /dev/null << 'ARPSCRIPT'
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

  tee "$ZEEK_SITE/ndr-suppress.zeek" > /dev/null << 'ZEEKSUPPRESS'
# NDR Agent-Z suppression filters — managed dynamically by NDR engine
# Hooks are appended here via suppress_sid commands; do not edit manually
ZEEKSUPPRESS
  if ! grep -q "ndr-suppress" "$ZEEK_SITE/local.zeek" 2>/dev/null; then
    echo "@load ndr-suppress" >> "$ZEEK_SITE/local.zeek"
  fi
  log "Agent-Z suppression filter ready"

  /opt/zeek/bin/zkg install zeek/corelight/zeek-community-id \
    --force > /dev/null 2>&1 || true

  log "✅ Agent-Z configured"
fi

# ── Configure Agent-S ─────────────────────────────
step "Agent-S  · Configuration"
log "Configuring Agent-S..."
if [ -f /etc/suricata/suricata.yaml ]; then
  cp /etc/suricata/suricata.yaml \
     /etc/suricata/suricata.yaml.bak \
     2>/dev/null || true

  sed -i 's/community-id: false/community-id: true/g' \
    /etc/suricata/suricata.yaml

  sed -i \
    "s|default-log-dir: /var/log/suricata|default-log-dir: /var/log/ndr/suricata|g" \
    /etc/suricata/suricata.yaml

  if grep -q "community-id: true" /etc/suricata/suricata.yaml; then
    log "Agent-S community-id: confirmed"
  else
    warn "community-id sed failed — patching manually"
    python3 << PYFIX
import re
with open('/etc/suricata/suricata.yaml','r') as f:
    content = f.read()
content = re.sub(r'community-id:\s*false', 'community-id: true', content)
with open('/etc/suricata/suricata.yaml','w') as f:
    f.write(content)
print("[NDR] Agent-S community-id patched")
PYFIX
  fi

  log "Agent-S updating threat rules..."
  suricata-update > /dev/null 2>&1 || true
  log "✅ Agent-S configured on $IFACE"

  # Tune AF-PACKET ring buffer for zero-drop capture
  python3 << 'AFPACKET_TUNE'
import re

with open('/etc/suricata/suricata.yaml', 'r') as f:
    content = f.read()

# Zero-copy ring buffer access
content = re.sub(r'(use-mmap:\s*)\w+',    r'\g<1>yes',   content)
# Pin ring buffer memory — prevent paging under load
content = re.sub(r'(mmap-locked:\s*)\w+', r'\g<1>yes',   content)
# Batched packet delivery (more efficient than tpacket-v2)
content = re.sub(r'(tpacket-v3:\s*)\w+',  r'\g<1>yes',   content)
# Larger ring buffer: 2048 packets (default is often 128/256)
content = re.sub(r'(ring-size:\s*)\d+',   r'\g<1>2048',  content)
# Block size for tpacket-v3
content = re.sub(r'(block-size:\s*)\d+',  r'\g<1>32768', content)
# Use all available CPU cores for capture threads
content = re.sub(r'(threads:\s*)\w+',     r'\g<1>auto',  content)

with open('/etc/suricata/suricata.yaml', 'w') as f:
    f.write(content)

print("[NDR] ✅ Agent-S AF-PACKET tuned: ring-size=2048, mmap=yes, tpacket-v3=yes, threads=auto")
AFPACKET_TUNE
fi

log "Writing Agent-S false-positive suppressions..."
THRESHOLD_FILE="/etc/suricata/threshold.conf"
touch "$THRESHOLD_FILE"

# Bootstrap-only SIDs — absolute known noise fired on every sensor at install time
# All other SIDs are added dynamically via suppress_sid commands from the engine
SUPPRESS_SIDS=(
  2066052   # ET INFO ngrok-free.dev in TLS SNI — sensor heartbeat to cloud
  2066057   # Related ngrok tunneling rule
)

for SID in "${SUPPRESS_SIDS[@]}"; do
  LINE="suppress gen_id 1, sig_id ${SID}"
  if ! grep -qF "$LINE" "$THRESHOLD_FILE" 2>/dev/null; then
    echo "$LINE" >> "$THRESHOLD_FILE"
    log "  ✅ Suppressed SID $SID"
  else
    log "  SID $SID already suppressed"
  fi
done

# TAP mode only: suppress all Suricata alerts from sensor's own IP
# Agent mode: server IS the monitored endpoint — never suppress its traffic by IP
if [ "$SENSOR_MODE" = "tap" ] && [ -n "$SENSOR_IP" ]; then
  SENSOR_LINE="suppress gen_id 1, sig_id 0, track by_src, ip ${SENSOR_IP}"
  if ! grep -qF "$SENSOR_LINE" "$THRESHOLD_FILE" 2>/dev/null; then
    echo "$SENSOR_LINE" >> "$THRESHOLD_FILE"
    log "  ✅ Suppressed all Agent-S alerts from sensor IP: $SENSOR_IP (TAP mode)"
  else
    log "  Sensor IP $SENSOR_IP already suppressed in Agent-S"
  fi
else
  log "  Agent mode: sensor IP NOT suppressed — server traffic is monitored"
fi

# Configure Suricata to load the threshold file
if [ "$SURICATA_OK" = "1" ]; then
  if grep -q "threshold-file:" /etc/suricata/suricata.yaml 2>/dev/null; then
    sed -i "s|threshold-file:.*|threshold-file: $THRESHOLD_FILE|g" \
      /etc/suricata/suricata.yaml
  else
    echo "threshold-file: $THRESHOLD_FILE" >> /etc/suricata/suricata.yaml
  fi
  log "✅ Suricata suppressions written to $THRESHOLD_FILE"
else
  warn "Skipping Suricata suppression config — Agent-S was not installed."
fi

# ── Configure auditd NDR rules ────────────────────
log "Writing NDR auditd rules..."
mkdir -p /etc/audit/rules.d
cat > /etc/audit/rules.d/ndr.rules << 'AUDITEOF'
# NDR Endpoint Telemetry Rules — process, privilege, network, persistence

# Process execution
-a always,exit -F arch=b64 -S execve -k process_execution
-a always,exit -F arch=b32 -S execve -k process_execution

# Privilege escalation calls
-a always,exit -F arch=b64 -S setuid,setgid,setreuid,setregid,setresuid,setresgid -k priv_escalation

# Outbound network connections (detects C2/reverse shells)
-a always,exit -F arch=b64 -S connect -k network_connect

# Sensitive credential files
-w /etc/passwd  -p wa -k credential_access
-w /etc/shadow  -p wa -k credential_access
-w /etc/sudoers -p wa -k priv_escalation
-w /etc/sudoers.d -p wa -k priv_escalation

# Persistence via cron and init
-w /etc/crontab         -p wa -k persistence
-w /var/spool/cron      -p wa -k persistence
-w /etc/cron.d          -p wa -k persistence
-w /etc/rc.local        -p wa -k persistence
-w /etc/systemd/system  -p wa -k persistence

# SSH key manipulation
-w /root/.ssh -p wa -k ssh_key_access
-w /home      -p wa -k ssh_key_access

# Execution from noisy/suspicious locations
-w /tmp     -p x -k tmp_exec
-w /dev/shm -p x -k shm_exec
-w /var/tmp -p x -k tmp_exec

# Kernel module loading (rootkit detection)
-a always,exit -F arch=b64 -S init_module,finit_module,delete_module -k kernel_module

# Log tampering
-a always,exit -F arch=b64 -S unlink,unlinkat,rename,renameat -F dir=/var/log -k log_tampering
AUDITEOF

# Apply rules immediately
augenrules --load > /dev/null 2>&1 || auditctl -R /etc/audit/rules.d/ndr.rules > /dev/null 2>&1 || true
systemctl enable auditd > /dev/null 2>&1 || true
systemctl restart auditd 2>/dev/null || service auditd restart 2>/dev/null || true
log "✅ Endpoint audit rules loaded"

# ── Configure Log Collector ────────────────────────
step "Log Collector  · Configuration"
log "Configuring Log Collector pipeline..."
HOSTNAME_VAL=$(hostname)

cat > /etc/ndr/vector.toml << EOF
data_dir = "/etc/vector/data"

# ── SOURCES: all Zeek log types ──────────────────
[sources.zeek_conn]
type = "file"
include = ["/var/log/ndr/zeek/conn.log"]
read_from = "beginning"
glob_minimum_cooldown_ms = 100

[sources.zeek_dns]
type = "file"
include = ["/var/log/ndr/zeek/dns.log"]
read_from = "beginning"
glob_minimum_cooldown_ms = 100

[sources.zeek_http]
type = "file"
include = ["/var/log/ndr/zeek/http.log"]
read_from = "beginning"
glob_minimum_cooldown_ms = 100

[sources.zeek_ssl]
type = "file"
include = ["/var/log/ndr/zeek/ssl.log"]
read_from = "beginning"
glob_minimum_cooldown_ms = 100

[sources.zeek_files]
type = "file"
include = ["/var/log/ndr/zeek/files.log"]
read_from = "beginning"
glob_minimum_cooldown_ms = 100

[sources.zeek_weird]
type = "file"
include = ["/var/log/ndr/zeek/weird.log"]
read_from = "beginning"
glob_minimum_cooldown_ms = 100

[sources.zeek_dhcp]
type = "file"
include = ["/var/log/ndr/zeek/dhcp.log"]
read_from = "beginning"
glob_minimum_cooldown_ms = 100

[sources.zeek_quic]
type = "file"
include = ["/var/log/ndr/zeek/quic.log"]
read_from = "beginning"
glob_minimum_cooldown_ms = 100

[sources.zeek_arp]
type = "file"
include = ["/var/log/ndr/zeek/arp.log"]
read_from = "beginning"
glob_minimum_cooldown_ms = 100

[sources.zeek_software]
type = "file"
include = ["/var/log/ndr/zeek/software.log"]
read_from = "beginning"
glob_minimum_cooldown_ms = 100

[sources.zeek_ipam]
type = "file"
include = ["/var/log/ndr/zeek/ipam.log"]
read_from = "beginning"
glob_minimum_cooldown_ms = 500

[sources.suricata]
type = "file"
include = ["/var/log/ndr/suricata/eve.json"]
read_from = "beginning"
glob_minimum_cooldown_ms = 100

[transforms.suricata_json]
type = "remap"
inputs = ["suricata"]
source = '''
parsed, err = parse_json(.message)
if err == null {
  . = parsed
  .source = "suricata"
  .tenant_id = "${TENANT_ID}"
  .sensor_host = "${HOSTNAME_VAL}"
} else { abort }
'''

[transforms.zeek_conn_json]
type = "remap"
inputs = ["zeek_conn"]
source = '''
parsed, err = parse_json(.message)
if err == null {
  . = parsed
  .source = "zeek"
  .tenant_id = "${TENANT_ID}"
  .sensor_host = "${HOSTNAME_VAL}"
} else { abort }
'''

[transforms.zeek_dns_json]
type = "remap"
inputs = ["zeek_dns"]
source = '''
parsed, err = parse_json(.message)
if err == null {
  . = parsed
  .source = "zeek"
  .log_type = "dns"
  .tenant_id = "${TENANT_ID}"
  .sensor_host = "${HOSTNAME_VAL}"
} else { abort }
'''

[transforms.zeek_http_json]
type = "remap"
inputs = ["zeek_http"]
source = '''
parsed, err = parse_json(.message)
if err == null {
  . = parsed
  .source = "zeek"
  .log_type = "http"
  .tenant_id = "${TENANT_ID}"
  .sensor_host = "${HOSTNAME_VAL}"
} else { abort }
'''

[transforms.zeek_ssl_json]
type = "remap"
inputs = ["zeek_ssl"]
source = '''
parsed, err = parse_json(.message)
if err == null {
  . = parsed
  .source = "zeek"
  .log_type = "ssl"
  .tenant_id = "${TENANT_ID}"
  .sensor_host = "${HOSTNAME_VAL}"
} else { abort }
'''

[transforms.zeek_files_json]
type = "remap"
inputs = ["zeek_files"]
source = '''
parsed, err = parse_json(.message)
if err == null {
  . = parsed
  .source = "zeek"
  .log_type = "files"
  .tenant_id = "${TENANT_ID}"
  .sensor_host = "${HOSTNAME_VAL}"
} else { abort }
'''

[transforms.zeek_weird_json]
type = "remap"
inputs = ["zeek_weird"]
source = '''
parsed, err = parse_json(.message)
if err == null {
  . = parsed
  .source = "zeek"
  .log_type = "weird"
  .tenant_id = "${TENANT_ID}"
  .sensor_host = "${HOSTNAME_VAL}"
} else { abort }
'''

[transforms.zeek_dhcp_json]
type = "remap"
inputs = ["zeek_dhcp"]
source = '''
parsed, err = parse_json(.message)
if err == null {
  . = parsed
  .source = "zeek"
  .log_type = "dhcp"
  .tenant_id = "${TENANT_ID}"
  .sensor_host = "${HOSTNAME_VAL}"
} else { abort }
'''

[transforms.zeek_quic_json]
type = "remap"
inputs = ["zeek_quic"]
source = '''
parsed, err = parse_json(.message)
if err == null {
  . = parsed
  .source = "zeek"
  .log_type = "quic"
  .tenant_id = "${TENANT_ID}"
  .sensor_host = "${HOSTNAME_VAL}"
} else { abort }
'''

[transforms.zeek_arp_json]
type = "remap"
inputs = ["zeek_arp"]
source = '''
parsed, err = parse_json(.message)
if err == null {
  . = parsed
  .source = "zeek"
  .log_type = "arp"
  .tenant_id = "${TENANT_ID}"
  .sensor_host = "${HOSTNAME_VAL}"
} else { abort }
'''

[transforms.zeek_software_json]
type = "remap"
inputs = ["zeek_software"]
source = '''
parsed, err = parse_json(.message)
if err == null {
  . = parsed
  .source = "zeek"
  .log_type = "software"
  .tenant_id = "${TENANT_ID}"
  .sensor_host = "${HOSTNAME_VAL}"
} else { abort }
'''

[transforms.zeek_ipam_json]
type = "remap"
inputs = ["zeek_ipam"]
source = '''
parsed, err = parse_json(.message)
if err == null {
  . = parsed
  .source = "zeek"
  .log_type = "ipam"
  .tenant_id = "${TENANT_ID}"
  .sensor_host = "${HOSTNAME_VAL}"
} else { abort }
'''

# ── SOURCE + TRANSFORM: Linux auditd endpoint logs ──
[sources.auditd]
type = "file"
include = ["/var/log/audit/audit.log"]
read_from = "beginning"
glob_minimum_cooldown_ms = 200

[transforms.auditd_json]
type = "remap"
inputs = ["auditd"]
source = '''
msg = string!(.message)

# Extract record type — skip noisy/irrelevant types early
type_m = parse_regex(msg, r'type=(?P<t>[A-Z_]+)') ?? {}
rec_type = string(type_m.t) ?? "UNKNOWN"
if !includes(["EXECVE","SYSCALL","PATH","PROCTITLE","SOCKADDR","USER_AUTH","USER_LOGIN","USER_CMD","CWD","BPRM_FCAPS"], rec_type) { abort }
.record_type = rec_type

# Extract audit timestamp and serial number
ts_m = parse_regex(msg, r'msg=audit\((?P<ts>[0-9.]+):(?P<serial>[0-9]+)\)') ?? {}
.audit_ts     = string(ts_m.ts)     ?? ""
.audit_serial = string(ts_m.serial) ?? ""

# Strip header, parse remaining key=value pairs
kv_str = replace(msg, r'^type=\S+ msg=audit\([^)]+\):\s*', "", count: 1)
kv, kv_err = parse_key_value(kv_str, field_delimiter: " ", key_value_delimiter: "=")
if kv_err == null {
  if exists(kv.exe)     { .exe     = string!(kv.exe) }
  if exists(kv.comm)    { .comm    = string!(kv.comm) }
  if exists(kv.pid)     { .pid     = string!(kv.pid) }
  if exists(kv.ppid)    { .ppid    = string!(kv.ppid) }
  if exists(kv.uid)     { .uid     = string!(kv.uid) }
  if exists(kv.auid)    { .auid    = string!(kv.auid) }
  if exists(kv.key)     { .key     = string!(kv.key) }
  if exists(kv.syscall) { .syscall = string!(kv.syscall) }
  if exists(kv.success) { .success = string!(kv.success) }
  if exists(kv.name)    { .TargetFilename = string!(kv.name) }

  # EXECVE: reconstruct CommandLine from a0 a1 a2 ... a7
  if rec_type == "EXECVE" {
    parts = []
    if exists(kv.a0) { parts = push(parts, string!(kv.a0)) }
    if exists(kv.a1) { parts = push(parts, string!(kv.a1)) }
    if exists(kv.a2) { parts = push(parts, string!(kv.a2)) }
    if exists(kv.a3) { parts = push(parts, string!(kv.a3)) }
    if exists(kv.a4) { parts = push(parts, string!(kv.a4)) }
    if exists(kv.a5) { parts = push(parts, string!(kv.a5)) }
    if exists(kv.a6) { parts = push(parts, string!(kv.a6)) }
    if exists(kv.a7) { parts = push(parts, string!(kv.a7)) }
    if length(parts) > 0 { .CommandLine = join!(parts, " ") }
  }
}

# Map to SIGMA-compatible field names (Linux SIGMA rules use these)
.Image = if exists(.exe) { string!(.exe) } else if exists(.comm) { string!(.comm) } else { "" }
if !exists(.CommandLine) { .CommandLine = if exists(.comm) { string!(.comm) } else { "" } }

.source      = "linux"
.log_type    = "auditd"
.tenant_id   = "${TENANT_ID}"
.sensor_host = "${HOSTNAME_VAL}"
'''

# ── SINK: HTTP POST to cloud /api/ingest ─────────
# Works through ngrok, reverse proxy, or direct IP.
# Sends NDJSON batches; ingest endpoint handles it.
[sinks.cloud_http]
type = "http"
inputs = [
  "suricata_json",
  "zeek_conn_json",
  "zeek_dns_json",
  "zeek_http_json",
  "zeek_ssl_json",
  "zeek_files_json",
  "zeek_weird_json",
  "zeek_dhcp_json",
  "zeek_quic_json",
  "zeek_arp_json",
  "zeek_software_json",
  "zeek_ipam_json",
  "auditd_json"
]
uri = "${CLOUD_URL}/api/ingest"
method = "post"
encoding.codec = "json"
framing.method = "newline_delimited"

# Fewer, larger requests: at thousands of sensors one request per second per
# sensor (100 events / 1 s) is thousands of requests and TLS records a second on
# the platform. 1000 events or 5 s (whichever first) is ~5x fewer requests, and
# gzip cuts the bytes sent (the platform decompresses request bodies).
compression = "gzip"

[sinks.cloud_http.batch]
max_events = 1000
max_bytes = 5000000
timeout_secs = 5

# Never give up on a batch because the platform is briefly down, restarting or answering
# 429/503: with 5 attempts / 30 s a deploy or a burst silently threw batches away.
# Backoff grows to at most 5 minutes so hundreds of sensors do not retry in lockstep.
# A revoked key (401) is still not retried. 30 s per request: a 1000-event gzip batch over a
# slow link can exceed 10 s, and a timeout only causes a retry (duplicate) of the same batch.
[sinks.cloud_http.request]
retry_attempts = 1000000
retry_initial_backoff_secs = 1
retry_max_duration_secs = 300
timeout_secs = 30
headers.X-Sensor-Key = "${API_KEY}"
headers.Content-Type = "application/x-ndjson"

# "block" instead of "drop_newest": when the buffer is full Vector stops reading the log
# files (their checkpoints keep the position) and resumes later, instead of dropping events.
[sinks.cloud_http.buffer]
type = "disk"
max_size = 1073741824
when_full = "block"
EOF

# ── Sensor Agent ──────────────────────────────────
step "Sensor Agent  · Service"
log "Creating sensor agent..."
cat > /opt/ndr-sensor/agent.py << 'AGENT'
#!/usr/bin/env python3
"""NDR Sensor Agent v2 — monitors and restarts all services"""
import os, time, subprocess, threading, requests, json, hashlib, re, socket, ipaddress
from datetime import datetime

config = {}
with open('/etc/ndr/sensor.conf') as f:
    for line in f:
        if '=' in line and not line.startswith('#'):
            k, v = line.strip().split('=', 1)
            config[k] = v

CLOUD_URL = config.get('CLOUD_URL', '').rstrip('/')
TENANT_ID = config.get('TENANT_ID', '')
API_KEY   = config.get('API_KEY', '')
IFACE     = config.get('IFACE', 'eth0')

# ── Don't alert on this sensor's own reporting traffic ───────────────────────
# The sensor ships its logs to the platform (CLOUD_URL) over the same interface
# Zeek and Suricata are watching, so that traffic is analysed and can raise
# alerts about the monitoring system itself (measured on one tenant: 115 of 129
# alerts). A narrow capture filter drops just that conversation: packets between
# THIS sensor's own addresses and the platform's addresses on the platform's
# port, in both directions (dropping only one direction would leave Zeek half a
# connection and it would alert on that instead). Everything else - other hosts,
# other ports, other destinations, other hosts talking to the platform - is
# still analysed. Arkime's packet capture and Vector's log shipping are not
# affected. Optional sensor.conf keys:
#   EXCLUDE_CLOUD_TRAFFIC=0         turn the filter off
#   EXCLUDE_CLOUD_IPS=1.2.3.4,...   extra platform addresses (CLOUD_URL behind a proxy, etc.)
EXCLUDE_ENABLED      = config.get('EXCLUDE_CLOUD_TRAFFIC', '1').strip() != '0'
EXCLUDE_EXTRA_IPS    = [x.strip() for x in config.get('EXCLUDE_CLOUD_IPS', '').split(',') if x.strip()]
EXCLUDE_BPF_FILE     = '/etc/ndr/exclude.bpf'
EXCLUDE_RECHECK_SECS = 300
CURRENT_EXCLUDE_BPF  = ''      # the filter Zeek/Suricata were last started with
_exclude_checked_at  = 0.0
_exclude_failed      = {'zeek': False, 'suricata': False}   # a tool that won't run with the filter
_down_with_filter    = {'zeek': 0, 'suricata': 0}

# Prevents check_and_restart from undoing an intentional stop command
MANUALLY_STOPPED = False

def derive_arkime_pass(key):
    return hashlib.sha256(key.encode())\
        .hexdigest()[:16]

ARKIME_PASS = derive_arkime_pass(API_KEY)

def is_running(pattern):
    return subprocess.run(
        ['pgrep', '-f', pattern],
        capture_output=True
    ).returncode == 0

def is_port_open(port):
    """Check if a local port is accepting connections"""
    import socket
    try:
        s = socket.socket()
        s.settimeout(2)
        s.connect(('127.0.0.1', port))
        s.close()
        return True
    except:
        return False

def is_capture_running():
    return is_running('arkime/bin/capture')

# ── Exclusion filter (see the comment block near the top) ────────────────────

def _valid_ip(s):
    try:
        return str(ipaddress.ip_address(str(s).strip().split('%')[0]))
    except ValueError:
        return None

def cloud_endpoint():
    """(host, port) of CLOUD_URL; port defaults from the scheme."""
    from urllib.parse import urlparse
    u = urlparse(CLOUD_URL)
    return u.hostname or '', (u.port or (443 if u.scheme == 'https' else 80))

def resolve_cloud_ips(host):
    """Every address the platform's hostname resolves to (A and AAAA). Empty on failure."""
    ip = _valid_ip(host)
    if ip:
        return {ip}
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except OSError:
        return set()
    return {a for a in (_valid_ip(i[4][0]) for i in infos) if a}

def own_ips(iface):
    """This machine's addresses on the capture interface."""
    try:
        out = subprocess.run(['ip', '-o', 'addr', 'show', 'dev', iface],
                             capture_output=True, text=True, timeout=5).stdout
    except (OSError, subprocess.SubprocessError):
        return set()
    ips = set()
    for line in out.splitlines():
        p = line.split()
        if len(p) >= 4 and p[2] in ('inet', 'inet6'):
            ip = _valid_ip(p[3].split('/')[0])
            if ip:
                ips.add(ip)
    return ips

def build_exclude_bpf(own, cloud, port, cap=16):
    """BPF that drops traffic between this sensor and the platform on `port`,
    both directions. '' when either side is unknown (then nothing is excluded)."""
    own   = sorted({a for a in (_valid_ip(x) for x in own) if a})[:cap]
    cloud = sorted({a for a in (_valid_ip(x) for x in cloud) if a})[:cap]
    if not own or not cloud or not isinstance(port, int) or not (0 < port < 65536):
        return ''
    o = ' or '.join('host ' + a for a in own)
    c = ' or '.join('host ' + a for a in cloud)
    return 'not ((%s) and (%s) and port %d)' % (o, c, port)

def bpf_ok(expr):
    """True if libpcap accepts the filter. Without tcpdump we can't ask; the expression is
    built only from validated addresses and an integer port, so it is well-formed anyway."""
    try:
        return subprocess.run(['tcpdump', '-d', expr], capture_output=True, timeout=10).returncode == 0
    except FileNotFoundError:
        return True
    except subprocess.SubprocessError:
        return False

def desired_exclude_bpf():
    """The filter the running tools should use, '' for none, or None to keep what is in
    place (name resolution failed - a DNS blip must not drop the exclusion and restart)."""
    if not EXCLUDE_ENABLED:
        return ''
    host, port = cloud_endpoint()
    cloud = resolve_cloud_ips(host) | {i for i in map(_valid_ip, EXCLUDE_EXTRA_IPS) if i}
    if not cloud:
        return None
    own = own_ips(IFACE)
    if own & cloud:
        return ''   # sensor runs on the platform's own machine: nothing to exclude
    bpf = build_exclude_bpf(own, cloud, port)
    if bpf and not bpf_ok(bpf):
        print("[NDR] Exclusion filter rejected by libpcap, not using it: " + bpf)
        return ''
    return bpf

def apply_exclusion(restart):
    """Recompute the filter. If it changed: remember it, write it for Suricata, and
    (when `restart`) restart Zeek and Suricata so it takes effect."""
    global CURRENT_EXCLUDE_BPF
    want = desired_exclude_bpf()
    if want is None or want == CURRENT_EXCLUDE_BPF:
        return
    try:
        with open(EXCLUDE_BPF_FILE, 'w') as f:
            f.write(want + '\n')
    except OSError as e:
        print("[NDR] Could not write %s: %s" % (EXCLUDE_BPF_FILE, e))
        return
    print("[NDR] Exclusion filter %s: %s" % ('set' if want else 'cleared', want or '(none)'))
    CURRENT_EXCLUDE_BPF = want
    _exclude_failed['zeek'] = _exclude_failed['suricata'] = False   # new filter, new chance
    if restart and not MANUALLY_STOPPED:
        start_zeek()
        start_suricata()

def refresh_exclusion():
    """Called every check-in; re-resolves the platform address every few minutes."""
    global _exclude_checked_at
    if time.time() - _exclude_checked_at < EXCLUDE_RECHECK_SECS:
        return
    _exclude_checked_at = time.time()
    apply_exclusion(restart=True)

def _note_down(name):
    """A tool that keeps dying while it runs with the filter: stop using the filter for it."""
    if CURRENT_EXCLUDE_BPF and not _exclude_failed[name]:
        _down_with_filter[name] += 1
        if _down_with_filter[name] >= 3:
            _exclude_failed[name] = True
            print("[NDR] %s keeps stopping with the exclusion filter - running it without the filter" % name)

def _launch_zeek(use_filter):
    cmd = ["/opt/zeek/bin/zeek", "-i", IFACE]
    if use_filter:
        cmd += ["-f", CURRENT_EXCLUDE_BPF]
    cmd += ["local", "Log::default_logdir=/var/log/ndr/zeek"]
    subprocess.Popen(cmd,
        stdout=open("/var/log/ndr/zeek/startup.log", "w"),
        stderr=subprocess.STDOUT
    )

def start_zeek():
    try:
        subprocess.run(['pkill', '-9', '-f', 'zeek'],
            capture_output=True)
        time.sleep(2)
        use_filter = bool(CURRENT_EXCLUDE_BPF) and not _exclude_failed['zeek']
        _launch_zeek(use_filter)
        if use_filter:
            # A bad option makes Zeek exit straight away; never leave the sensor without Zeek.
            time.sleep(4)
            if not is_running('zeek'):
                print("[NDR] Zeek did not start with the exclusion filter - starting it without")
                _exclude_failed['zeek'] = True
                _launch_zeek(False)
        print("[NDR] ✅ Zeek started")
        return True
    except Exception as e:
        print(f"[NDR] Zeek start failed: {e}")
        return False

def start_suricata():
    try:
        subprocess.run(['pkill', '-9', '-f', 'suricata'],
            capture_output=True)
        time.sleep(2)
        for pid in ['/tmp/suricata.pid',
                    '/var/run/suricata.pid',
                    '/run/suricata.pid',
                    '/var/run/suricata/suricata.pid']:
            try: os.remove(pid)
            except: pass

        subprocess.Popen(
            ["suricata",
             "-c", "/etc/suricata/suricata.yaml",
             "-i", IFACE,
             *(["-F", EXCLUDE_BPF_FILE] if CURRENT_EXCLUDE_BPF and not _exclude_failed['suricata'] else []),
             "-l", "/var/log/ndr/suricata",
             "-D",
             "--pidfile", "/tmp/suricata.pid",
             "--set", "detect.profile=medium",
             "--set", "max-pending-packets=4096"],
            stdout=open("/tmp/suricata.log", "w"),
            stderr=subprocess.STDOUT
        )
        print("[NDR] ✅ Suricata started")
        return True
    except Exception as e:
        print(f"[NDR] Suricata start failed: {e}")
        return False

def start_vector():
    try:
        subprocess.run(['systemctl', 'start',
            'ndr-vector'],
            capture_output=True, timeout=30)
        print("[NDR] ✅ Vector started")
        return True
    except Exception as e:
        print(f"[NDR] Vector start failed: {e}")
        return False

def start_capture():
    try:
        subprocess.run(['systemctl', 'start',
            'arkime-capture'],
            capture_output=True, timeout=30)
        print("[NDR] ✅ Arkime capture started")
        return True
    except Exception as e:
        print(f"[NDR] Arkime capture failed: {e}")
        return False

def discover_subnets():
    """Read network interface CIDRs and write to ipam.log so the engine
    can build per-tenant subnet maps and detect IP conflicts."""
    ipam_log = "/var/log/ndr/zeek/ipam.log"
    try:
        import ipaddress as _ipaddress
        out = subprocess.run(["ip", "addr", "show"], capture_output=True, text=True).stdout
        now = time.time()
        iface = None
        entries = []
        for line in out.splitlines():
            m = re.match(r'^\d+:\s+(\S+):', line)
            if m:
                iface = m.group(1).rstrip(':')
                continue
            m = re.match(r'\s+inet\s+(\d+\.\d+\.\d+\.\d+)/(\d+)', line)
            if m and iface:
                ip, prefix = m.group(1), int(m.group(2))
                if ip.startswith('127.') or ip.startswith('169.254.'):
                    continue
                network = _ipaddress.IPv4Network(f"{ip}/{prefix}", strict=False)
                cidr = str(network)
                gateway = str(network.network_address + 1)
                entries.append(json.dumps({
                    "ts": now, "log_type": "ipam",
                    "interface": iface, "cidr": cidr,
                    "local_ip": ip, "gateway": gateway
                }))
        if entries:
            os.makedirs(os.path.dirname(ipam_log), exist_ok=True)
            with open(ipam_log, 'a') as f:
                for e in entries:
                    f.write(e + '\n')
        print(f"[NDR] Subnet discovery: {len(entries)} subnets written")
    except Exception as e:
        print(f"[NDR] discover_subnets error: {e}")

def arp_scan(iface):
    """ARP scan the local subnet on startup.
    Only real devices reply to ARP — no ghost placeholders possible.
    Zeek captures the ARP replies via ndr-arp.zeek and enriches assets."""
    try:
        subprocess.run(
            ['sudo', 'arp-scan', f'--interface={iface}', '--localnet', '--quiet'],
            capture_output=True, timeout=60
        )
        print("[NDR] ✅ ARP scan complete")
    except Exception as e:
        print(f"[NDR] ARP scan error: {e}")

def arp_probe_unknown():
    """Background loop: every 5 min, ARP-probe internal IPs seen in traffic
    that have no ARP entry — so Zeek captures the reply and enriches the asset.
    Uses arping (Layer 2) instead of ping to avoid creating ghost placeholders."""
    import ipaddress
    conn_log = "/var/log/ndr/zeek/conn.log"
    while True:
        time.sleep(300)
        try:
            arp_out = subprocess.run(["ip", "neigh", "show"],
                                     capture_output=True, text=True).stdout
            known = {line.split()[0] for line in arp_out.splitlines() if line}

            seen = set()
            if os.path.exists(conn_log):
                with open(conn_log) as f:
                    for line in f.readlines()[-500:]:
                        try:
                            obj = json.loads(line)
                            for key in ("id.orig_h", "id.resp_h"):
                                ip = obj.get(key, "")
                                if ip:
                                    seen.add(ip)
                        except Exception:
                            pass

            for ip in seen - known:
                try:
                    if ipaddress.IPv4Address(ip).is_private:
                        subprocess.run(
                            ['sudo', 'arping', '-c', '1', '-w', '1', '-I', IFACE, ip],
                            capture_output=True, timeout=3
                        )
                except Exception:
                    pass
        except Exception:
            pass

def snmp_router_discovery():
    """Query the router's ARP table via SNMP to get all connected devices.
    Auto-detects gateway, tries common community strings."""
    import re as _re
    arp_log = "/var/log/ndr/zeek/arp.log"
    try:
        gw_out = subprocess.run(["ip", "route", "show", "default"],
                                capture_output=True, text=True).stdout
        m = _re.search(r'default via (\d+\.\d+\.\d+\.\d+)', gw_out)
        if not m:
            return
        gateway = m.group(1)
    except Exception:
        return

    entries = []
    for community in ["public", "private", "community", "admin"]:
        try:
            result = subprocess.run(
                ["snmpwalk", "-v2c", "-c", community, "-t", "3", "-r", "0",
                 gateway, "1.3.6.1.2.1.4.22.1.2"],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode != 0 or not result.stdout.strip():
                continue
            now = time.time()
            for line in result.stdout.splitlines():
                ip_m = _re.search(r'\.(\d+\.\d+\.\d+\.\d+)\s*=', line)
                mac_m = _re.search(r'(?:Hex-STRING:|STRING:)\s*([0-9A-Fa-f :]+)', line)
                if not ip_m or not mac_m:
                    continue
                ip = ip_m.group(1)
                mac_raw = mac_m.group(1).strip()
                mac = ":".join(mac_raw.split()).lower() if " " in mac_raw else mac_raw.lower()
                if len(mac) != 17:
                    continue
                entries.append(json.dumps({
                    "ts": now, "operation": "reply",
                    "mac": mac, "dst_mac": "", "ip": ip, "dst_ip": ""
                }))
            if entries:
                print(f"[NDR] SNMP: {len(entries)} devices from router {gateway} (community={community})")
                break
        except Exception:
            continue

    if entries:
        os.makedirs(os.path.dirname(arp_log), exist_ok=True)
        with open(arp_log, "a") as f:
            f.write("\n".join(entries) + "\n")

def bootstrap_from_arp_cache():
    """On startup, read the kernel ARP cache and write entries to arp.log
    so Vector ships them instantly — existing devices appear without any scanning."""
    arp_log = "/var/log/ndr/zeek/arp.log"
    try:
        out = subprocess.run(["ip", "neigh", "show"],
                             capture_output=True, text=True).stdout
        now = time.time()
        entries = []
        for line in out.splitlines():
            parts = line.split()
            if "lladdr" not in parts:
                continue
            idx = parts.index("lladdr")
            ip_str = parts[0]
            mac = parts[idx + 1] if idx + 1 < len(parts) else ""
            state = parts[-1]
            if state in ("FAILED", "INCOMPLETE") or not mac:
                continue
            try:
                import ipaddress as _ip
                addr = _ip.ip_address(ip_str)
                if not addr.is_private or addr.is_loopback:
                    continue
            except Exception:
                continue
            entries.append(json.dumps({
                "ts": now, "operation": "reply",
                "mac": mac, "dst_mac": "",
                "ip": ip_str, "dst_ip": ""
            }))
        if entries:
            os.makedirs(os.path.dirname(arp_log), exist_ok=True)
            with open(arp_log, "a") as f:
                f.write("\n".join(entries) + "\n")
            print(f"[NDR] Bootstrapped {len(entries)} known devices from ARP cache")
    except Exception as e:
        print(f"[NDR] ARP cache bootstrap error: {e}")

def check_and_restart():
    statuses = {}

    if MANUALLY_STOPPED:
        # Services were intentionally stopped — report stopped, do not restart
        statuses['agent-z']       = 'stopped'
        statuses['agent-s']       = 'stopped'
        statuses['vector']        = 'stopped'
        statuses['arkime_capture'] = 'stopped'
        return statuses

    if not is_running('zeek'):
        print("[NDR] Zeek down — restarting")
        _note_down('zeek')
        start_zeek()
        statuses['agent-z'] = 'restarting'
    else:
        _down_with_filter['zeek'] = 0
        statuses['agent-z'] = 'running'

    if not is_running('suricata'):
        print("[NDR] Suricata down — restarting")
        _note_down('suricata')
        start_suricata()
        statuses['agent-s'] = 'restarting'
    else:
        _down_with_filter['suricata'] = 0
        statuses['agent-s'] = 'running'

    if not is_running('vector'):
        print("[NDR] Vector down — restarting")
        start_vector()
        statuses['vector'] = 'restarting'
    else:
        statuses['vector'] = 'running'

    if not is_capture_running():
        print("[NDR] Arkime capture down — restarting")
        start_capture()
        statuses['arkime_capture'] = 'restarting'
    else:
        statuses['arkime_capture'] = 'running'

    return statuses

def report_status(statuses):
    import socket
    try:
        sensor_ip = socket.gethostbyname(
            socket.gethostname())
    except:
        sensor_ip = '127.0.0.1'

    payload = {
        'tenant_id':   TENANT_ID,
        'timestamp':   datetime.utcnow().isoformat(),
        'sensor_ip':   sensor_ip,
        **statuses
    }
    try:
        requests.post(
            f'{CLOUD_URL}/api/sensor/heartbeat',
            json=payload,
            headers={'X-Sensor-Key': API_KEY},
            timeout=5
        )
        print(f"[NDR] Heartbeat sent: "
              f"agent-z={statuses.get('agent-z')} "
              f"agent-s={statuses.get('agent-s')} "
              f"capture={statuses.get('arkime_capture')}")
    except Exception as e:
        print(f"[NDR] Heartbeat failed: {e}")

def get_pending_pcap():
    try:
        resp = requests.get(
            f'{CLOUD_URL}/api/pcap/pending',
            headers={'X-Sensor-Key': API_KEY},
            timeout=10
        )
        if resp.status_code == 200:
            data = resp.json()
            # Handle both formats:
            # old: ["cid1","cid2"]
            # new: {"pending":[{"community_id":"..."}]}
            if isinstance(data, list):
                return data
            items = data.get('pending', [])
            result = []
            for p in items:
                if isinstance(p, str):
                    result.append(p)
                elif isinstance(p, dict):
                    result.append(p.get('community_id', ''))
            return [x for x in result if x]
    except Exception as e:
        print(f"[NDR] pending poll error: {e}")
    return []

def process_pcap_uploads():
    pending = get_pending_pcap()
    if not pending:
        return

    print(f"[NDR] {len(pending)} PCAP uploads pending")
    for cid in pending[:5]:
        if not cid:
            continue
        try:
            result = subprocess.run(
                ['python3',
                 '/opt/ndr-sensor/pcap-uploader.py',
                 str(cid)],
                capture_output=True,
                text=True, timeout=120
            )
            if result.stdout.strip():
                print(result.stdout.strip())
            if result.returncode != 0:
                print(f"[NDR] Upload failed for "
                      f"{cid[:20]}: "
                      f"{result.stderr.strip()}")
        except subprocess.TimeoutExpired:
            print(f"[NDR] Upload timeout: {cid[:20]}")
        except Exception as e:
            print(f"[NDR] Upload error: {e}")

def execute_command(cmd):
    """Execute a received command string. Called by do_checkin() and
    the legacy check_and_execute_command() for backward compat."""
    global MANUALLY_STOPPED
    print(f"[NDR] *** COMMAND RECEIVED: {cmd} ***")
    if cmd == 'stop':
        MANUALLY_STOPPED = True
        subprocess.run(['pkill', '-9', '-f', 'zeek'], capture_output=True)
        subprocess.run(['pkill', '-9', '-f', 'suricata'], capture_output=True)
        subprocess.run(['systemctl', 'stop', 'ndr-vector'], capture_output=True)
        subprocess.run(['pkill', '-9', '-f', 'vector --config'], capture_output=True)
        subprocess.run(['pkill', '-9', '-f', '/usr/local/bin/vector'], capture_output=True)
        subprocess.run(['systemctl', 'stop', 'arkime-capture'], capture_output=True)
        subprocess.run(['pkill', '-9', '-f', 'arkime-capture'], capture_output=True)
        print("[NDR] All services stopped")
    elif cmd == 'start':
        MANUALLY_STOPPED = False
        discover_subnets()
        bootstrap_from_arp_cache()
        snmp_router_discovery()
        start_zeek()
        start_suricata()
        start_vector()
        start_capture()
        threading.Thread(target=arp_scan, args=(IFACE,), daemon=True).start()
        threading.Thread(target=arp_probe_unknown, daemon=True).start()
        print("[NDR] All services started")
    elif cmd == 'restart':
        MANUALLY_STOPPED = False
        subprocess.run(['systemctl', 'restart', 'zeek'], capture_output=True)
        subprocess.run(['systemctl', 'restart', 'suricata'], capture_output=True)
        subprocess.run(['pkill', '-f', 'vector'], capture_output=True)
        time.sleep(2)
        start_vector()
        subprocess.run(['pkill', '-f', 'arkime-capture'], capture_output=True)
        time.sleep(2)
        start_capture()
        print("[NDR] All services restarted")
    elif cmd.startswith('suppress_sid:'):
        # Formats:
        #   suppress_sid:2066052               → blanket SID suppress
        #   suppress_sid:2066052:by_dst:1.2.3.4 → suppress SID to specific dst IP
        #   suppress_sid:2066052:by_src:1.2.3.4 → suppress SID from specific src IP
        parts = cmd.split(':')
        sid = parts[1].strip()
        threshold_file = '/etc/suricata/threshold.conf'
        if len(parts) >= 4:
            track_type = parts[2].strip()
            track_ip   = parts[3].strip()
            track_kw   = 'by_dst' if track_type == 'by_dst' else 'by_src'
            suppress_line = (
                f'suppress gen_id 1, sig_id {sid}, '
                f'track {track_kw}, ip {track_ip}\n'
            )
        else:
            suppress_line = f'suppress gen_id 1, sig_id {sid}\n'
        try:
            with open(threshold_file, 'r') as f:
                existing = f.read()
        except FileNotFoundError:
            existing = ''
        if suppress_line.strip() not in existing:
            with open(threshold_file, 'a') as f:
                f.write(suppress_line)
            print(f"[NDR] Suppressed SID {sid} ({suppress_line.strip()})")
            reloaded = False
            try:
                pid_out = subprocess.run(['pidof', 'suricata'], capture_output=True, text=True)
                pid = pid_out.stdout.strip().split()[0]
                subprocess.run(['kill', '-USR2', pid], check=True)
                reloaded = True
            except Exception:
                pass
            if not reloaded:
                subprocess.run(['suricatasc', '-c', 'reload-rules'], capture_output=True)

            # ── Zeek collection-layer filter ──────────────────────────────
            # Map known SIDs to Zeek log_policy hooks so noise never reaches logs
            ZEEK_SID_FILTERS = {
                '2049049': ('dns',  '"ngrok" in rec$query'),
                '2066052': ('ssl',  '"ngrok" in rec$server_name'),
                '2066057': ('ssl',  '"ngrok" in rec$server_name'),
                '2022973': ('dhcp', 'rec?$host_name && "kali" in to_lower(rec$host_name)'),
            }
            zeek_filter_file = '/opt/zeek/share/zeek/site/ndr-suppress.zeek'
            if sid in ZEEK_SID_FILTERS:
                log_type, condition = ZEEK_SID_FILTERS[sid]
                hook_map = {
                    'dns':  ('DNS', 'DNS::Info', 'DNS::log_policy'),
                    'ssl':  ('SSL', 'SSL::Info', 'SSL::log_policy'),
                    'dhcp': ('DHCP', 'DHCP::Info', 'DHCP::log_policy'),
                }
                module, rec_type, hook_name = hook_map[log_type]
                hook_block = (
                    f'\nhook {hook_name}(rec: {rec_type}, '
                    f'id: Log::ID, filter: Log::Filter) {{\n'
                    f'    if ({condition}) break;\n}}\n'
                )
                try:
                    existing_zeek = open(zeek_filter_file).read() if os.path.exists(zeek_filter_file) else ''
                except Exception:
                    existing_zeek = ''
                if hook_block.strip() not in existing_zeek:
                    os.makedirs(os.path.dirname(zeek_filter_file), exist_ok=True)
                    with open(zeek_filter_file, 'a') as zf:
                        if not existing_zeek:
                            zf.write('# NDR auto-generated Zeek suppression filters\n')
                        zf.write(hook_block)
                    # Add @load to local.zeek if not already there
                    local_zeek = '/opt/zeek/share/zeek/site/local.zeek'
                    load_line = '@load ndr-suppress\n'
                    try:
                        lz = open(local_zeek).read()
                    except Exception:
                        lz = ''
                    if load_line.strip() not in lz:
                        with open(local_zeek, 'a') as lf:
                            lf.write(load_line)
                    # Restart Zeek to apply new filter
                    try:
                        subprocess.run(['pkill', '-f', 'zeek'], capture_output=True)
                        import time as _time; _time.sleep(1)
                        iface = open('/opt/ndr/.runtime/ndr_interface').read().strip()
                        subprocess.Popen(
                            ['/opt/zeek/bin/zeek', '-i', iface, 'local',
                             'Log::default_logdir=/var/log/ndr/zeek'],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
                        )
                        print(f"[NDR] Zeek filter added for SID {sid}, Zeek restarted")
                    except Exception as e:
                        print(f"[NDR] Zeek restart failed: {e}")
        else:
            print(f"[NDR] SID {sid} already suppressed")
    else:
        print(f"[NDR] Unknown command ignored: {cmd}")

def check_and_execute_command():
    """Legacy single-poll command handler — kept for backward compat.
    New sensors use do_checkin() which combines this with heartbeat
    and pcap pending into one request."""
    try:
        resp = requests.get(
            f'{CLOUD_URL}/api/sensor/command',
            headers={'X-Sensor-Key': API_KEY},
            timeout=5
        )
        if resp.status_code != 200:
            return
        cmd = resp.json().get('command', '').strip()
        if cmd:
            execute_command(cmd)
    except Exception as e:
        print(f"[NDR] Command poll error: {e}")

# ── Key revoked by an admin: stop shipping and remove this sensor ────────────
# The platform answers HTTP 401 {"status":"revoked"} to a key that was revoked
# (and only to someone holding that exact key). Two answers in a row are
# required so a single odd reply can never wipe a sensor. Optional sensor.conf
# key UNINSTALL_ON_REVOKE=0 keeps the software installed and only stops it.
UNINSTALL_ON_REVOKE  = config.get('UNINSTALL_ON_REVOKE', '1').strip() != '0'
REVOKED_CONFIRMS     = 2
_revoked_seen        = 0
_removal_started     = False
REMOVAL_SCRIPT       = '/tmp/ndr-remove-sensor.sh'

def _is_revoked_reply(resp):
    if resp.status_code != 401:
        return False
    try:
        return resp.json().get('status') == 'revoked'
    except Exception:
        return False

def handle_revoked():
    """Called after the platform confirmed twice that this sensor's key is revoked."""
    global MANUALLY_STOPPED, _removal_started
    MANUALLY_STOPPED = True
    print("[NDR] *** This sensor's key was REVOKED - stopping all services ***")
    execute_command('stop')          # log shipping stops right away
    if not UNINSTALL_ON_REVOKE:
        print("[NDR] UNINSTALL_ON_REVOKE=0 - services stopped, software left in place")
        return
    if _removal_started:
        return
    try:
        r = requests.get(f'{CLOUD_URL}/api/uninstall-sensor.sh', timeout=15)
        body = r.text
        # sanity: only run what really is the uninstall script
        if r.status_code != 200 or not body.startswith('#!') or 'NDR Sensor Uninstall' not in body:
            raise RuntimeError(f"unexpected uninstall script (HTTP {r.status_code})")
        with open(REMOVAL_SCRIPT, 'w') as f:
            f.write(body)
        os.chmod(REMOVAL_SCRIPT, 0o700)
    except Exception as e:
        # services are stopped; try again on the next check-in
        print(f"[NDR] Could not fetch the uninstall script ({e}) - will retry")
        return
    # The script stops ndr-agent (this process), so it must run OUTSIDE the
    # agent's systemd cgroup or it would be killed part-way. A transient unit does that.
    log_path = '/var/log/ndr-sensor-removal.log'
    try:
        if subprocess.run(['which', 'systemd-run'], capture_output=True).returncode == 0:
            cmd = ['systemd-run', '--unit=ndr-sensor-removal', '--collect',
                   f'--property=StandardOutput=file:{log_path}',
                   f'--property=StandardError=file:{log_path}',
                   'bash', REMOVAL_SCRIPT]
            subprocess.run(cmd, capture_output=True, timeout=20, check=True)
        else:
            subprocess.Popen(['bash', REMOVAL_SCRIPT], stdout=open(log_path, 'a'),
                             stderr=subprocess.STDOUT, start_new_session=True)
        _removal_started = True
        print(f"[NDR] Uninstall started (log: {log_path})")
    except Exception as e:
        print(f"[NDR] Could not start the uninstall ({e}) - services stay stopped, will retry")

def do_checkin():
    """Single combined check-in — replaces the old 3 separate polls
    (heartbeat, command, pcap pending) with one request.
    Returns the server-requested interval in seconds (default 30)."""
    import socket
    try:
        sensor_ip = socket.gethostbyname(socket.gethostname())
    except Exception:
        sensor_ip = '127.0.0.1'

    statuses = check_and_restart()

    payload = {
        'tenant_id':      TENANT_ID,
        'sensor_ip':      sensor_ip,
        'arkime_url':     f'http://{sensor_ip}:8005',
        'arkime_pass':    ARKIME_PASS,
        'agent-z':        statuses.get('agent-z', 'unknown'),
        'agent-s':        statuses.get('agent-s', 'unknown'),
        'vector':         statuses.get('vector', 'unknown'),
        'arkime_capture': statuses.get('arkime_capture', 'unknown'),
        'arkime_viewer':  statuses.get('arkime_viewer', 'unknown'),
    }

    try:
        resp = requests.post(
            f'{CLOUD_URL}/api/sensor/checkin',
            json=payload,
            headers={'X-Sensor-Key': API_KEY},
            timeout=10
        )
        global _revoked_seen
        if _is_revoked_reply(resp):
            _revoked_seen += 1
            print(f"[NDR] Platform says this sensor key is revoked ({_revoked_seen}/{REVOKED_CONFIRMS})")
            if _revoked_seen >= REVOKED_CONFIRMS:
                handle_revoked()
            return 10
        _revoked_seen = 0

        if resp.status_code != 200:
            print(f"[NDR] Checkin HTTP {resp.status_code}")
            return 30

        data = resp.json()
        print(f"[NDR] Checkin ok — "
              f"agent-z={payload['agent-z']} "
              f"agent-s={payload['agent-s']} "
              f"arkime={payload['arkime_capture']}")

        cmd = data.get('command', '').strip()
        if cmd:
            execute_command(cmd)

        pending = data.get('pcap_pending', [])
        if pending:
            print(f"[NDR] {len(pending)} PCAP uploads pending")
            for cid in pending[:5]:
                if not cid:
                    continue
                try:
                    result = subprocess.run(
                        ['python3',
                         '/opt/ndr-sensor/pcap-uploader.py',
                         str(cid)],
                        capture_output=True,
                        text=True, timeout=120
                    )
                    if result.stdout.strip():
                        print(result.stdout.strip())
                    if result.returncode != 0:
                        print(f"[NDR] Upload failed for "
                              f"{cid[:20]}: "
                              f"{result.stderr.strip()}")
                except subprocess.TimeoutExpired:
                    print(f"[NDR] Upload timeout: {cid[:20]}")
                except Exception as e:
                    print(f"[NDR] PCAP upload error: {e}")

        return int(data.get('checkin_interval_secs', 30))

    except Exception as e:
        print(f"[NDR] Checkin failed: {e}")
        return 30

# ── ARP isolation (same logic as ndr-agent.py local agent) ────────────────
import pathlib, socket as _socket

_isolated_devices = {}
_isolation_lock   = threading.Lock()
IFACE_FILE = pathlib.Path("/opt/ndr-sensor/iface")

def _arp_poison_loop(target_ip, gateway_ip, iface, stop_event):
    try:
        from scapy.all import ARP, Ether, sendp, get_if_hwaddr, getmacbyip, conf as scapy_conf
        scapy_conf.verb = 0
        our_mac     = get_if_hwaddr(iface)
        target_mac  = getmacbyip(target_ip)  or "ff:ff:ff:ff:ff:ff"
        gateway_mac = getmacbyip(gateway_ip) or "ff:ff:ff:ff:ff:ff"
        print(f"[NDR-ISOLATE] ARP loop: target_mac={target_mac} gateway_mac={gateway_mac}")
        while not stop_event.is_set():
            pkt1 = Ether(dst=target_mac) / ARP(
                op=2, pdst=target_ip, hwdst=target_mac,
                psrc=gateway_ip, hwsrc=our_mac)
            pkt2 = Ether(dst=gateway_mac) / ARP(
                op=2, pdst=gateway_ip, hwdst=gateway_mac,
                psrc=target_ip, hwsrc=our_mac)
            sendp([pkt1, pkt2], iface=iface, verbose=False)
            stop_event.wait(2)
    except ImportError:
        print("[NDR-ISOLATE] scapy not installed (pip install scapy)")
    except Exception as e:
        print(f"[NDR-ISOLATE] ARP loop error: {e}")

def isolate_device(target_ip, gateway_ip="192.168.1.1"):
    import datetime
    if not target_ip:
        return {"status": "error", "message": "target_ip required"}
    iface = IFACE_FILE.read_text().strip() if IFACE_FILE.exists() else IFACE
    with _isolation_lock:
        if target_ip in _isolated_devices:
            return {"status": "already_isolated", "ip": target_ip}
        stop_event = threading.Event()
        t = threading.Thread(
            target=_arp_poison_loop,
            args=(target_ip, gateway_ip, iface, stop_event),
            daemon=True)
        t.start()
        _isolated_devices[target_ip] = {
            "thread": t, "stop_event": stop_event,
            "gateway_ip": gateway_ip, "started_at": time.time()}
    subprocess.run(["sudo", "iptables", "-I", "FORWARD", "-s", target_ip, "-j", "DROP"], capture_output=True)
    subprocess.run(["sudo", "iptables", "-I", "FORWARD", "-d", target_ip, "-j", "DROP"], capture_output=True)
    print(f"[NDR-ISOLATE] Isolated {target_ip} via ARP on {iface}, gw {gateway_ip}")
    return {"status": "isolated", "ip": target_ip, "gateway_ip": gateway_ip,
            "interface": iface, "started_at": datetime.datetime.utcnow().isoformat() + "Z"}

def unisolate_device(target_ip):
    if not target_ip:
        return {"status": "error", "message": "target_ip required"}
    with _isolation_lock:
        entry = _isolated_devices.pop(target_ip, None)
    if not entry:
        return {"status": "not_found", "ip": target_ip}
    entry["stop_event"].set()
    subprocess.run(["sudo", "iptables", "-D", "FORWARD", "-s", target_ip, "-j", "DROP"], capture_output=True)
    subprocess.run(["sudo", "iptables", "-D", "FORWARD", "-d", target_ip, "-j", "DROP"], capture_output=True)
    try:
        from scapy.all import ARP, Ether, sendp, getmacbyip, conf as scapy_conf
        scapy_conf.verb = 0
        iface       = IFACE_FILE.read_text().strip() if IFACE_FILE.exists() else IFACE
        gateway_ip  = entry.get("gateway_ip", "192.168.1.1")
        target_mac  = getmacbyip(target_ip)
        gateway_mac = getmacbyip(gateway_ip)
        if target_mac and gateway_mac:
            pkt1 = Ether(dst=target_mac) / ARP(
                op=2, pdst=target_ip, hwdst=target_mac,
                psrc=gateway_ip, hwsrc=gateway_mac)
            pkt2 = Ether(dst=gateway_mac) / ARP(
                op=2, pdst=gateway_ip, hwdst=gateway_mac,
                psrc=target_ip, hwsrc=target_mac)
            sendp([pkt1, pkt2] * 5, iface=iface, verbose=False)
    except Exception as e:
        print(f"[NDR-ISOLATE] Restore ARP warning: {e}")
    print(f"[NDR-ISOLATE] Unisolated {target_ip}")
    return {"status": "unisolated", "ip": target_ip}

# ── HTTP agent server on :3001 for NDR engine to call ─────────────────────
import json as _json
from http.server import HTTPServer, BaseHTTPRequestHandler

NDR_AGENT_SECRET = config.get("NDR_AGENT_SECRET", "")

class SensorAgentHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args): pass  # suppress access logs

    def _auth(self):
        if not NDR_AGENT_SECRET:
            return True
        return self.headers.get("X-Agent-Secret", "") == NDR_AGENT_SECRET

    def _json(self, code, data):
        body = _json.dumps(data).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if not self._auth():
            self._json(401, {"error": "unauthorized"}); return
        if self.path == "/agent/status":
            statuses = check_and_restart()
            self._json(200, statuses)
        elif self.path == "/agent/isolations":
            with _isolation_lock:
                result = [{"ip": ip, "gateway_ip": v["gateway_ip"],
                           "started_at": v["started_at"]}
                          for ip, v in _isolated_devices.items()]
            self._json(200, result)
        else:
            self._json(404, {"error": "not found"})

    def do_POST(self):
        if not self._auth():
            self._json(401, {"error": "unauthorized"}); return
        length = int(self.headers.get("Content-Length", 0))
        body = _json.loads(self.rfile.read(length) or b"{}") if length else {}
        if self.path == "/agent/isolate":
            result = isolate_device(body.get("target_ip", ""), body.get("gateway_ip", "192.168.1.1"))
            code = 200 if result.get("status") in ("isolated", "already_isolated") else 400
            self._json(code, result)
        elif self.path == "/agent/unisolate":
            result = unisolate_device(body.get("target_ip", ""))
            code = 200 if result.get("status") == "unisolated" else 400
            self._json(code, result)
        else:
            self._json(404, {"error": "not found"})

def _start_agent_server():
    try:
        server = HTTPServer(("0.0.0.0", 3001), SensorAgentHandler)
        print("[NDR] Sensor agent HTTP server listening on :3001")
        server.serve_forever()
    except Exception as e:
        print(f"[NDR] Agent server error: {e}")

if __name__ == '__main__':
    print(f"[NDR] Agent starting — "
          f"tenant={TENANT_ID}")
    print(f"[NDR] Cloud={CLOUD_URL}")

    os.makedirs("/var/log/ndr/suricata",
        exist_ok=True)
    os.makedirs("/var/log/ndr/zeek",
        exist_ok=True)

    # Start all services
    print("[NDR] Starting all services...")
    discover_subnets()
    bootstrap_from_arp_cache()
    apply_exclusion(restart=False)   # before the first start so no restart is needed
    start_zeek()
    start_suricata()
    start_vector()
    start_capture()
    threading.Thread(target=arp_scan, args=(IFACE,), daemon=True).start()
    threading.Thread(target=arp_probe_unknown, daemon=True).start()
    threading.Thread(target=_start_agent_server, daemon=True).start()
    time.sleep(10)  # wait for capture to init

    checkin_interval = 30  # server will update this on first response
    while True:
        checkin_interval = do_checkin() or checkin_interval
        refresh_exclusion()
        time.sleep(checkin_interval)
AGENT
chmod +x /opt/ndr-sensor/agent.py

# ── pcap-uploader.py v3 — OpenSearch direct + tshark ─
cat > /opt/ndr-sensor/pcap-uploader.py \
  << 'UPLOADER'
#!/usr/bin/env python3
"""
NDR PCAP Uploader v3
- Queries OpenSearch directly (no viewer needed)
- Extracts from raw Arkime .pcap files using tshark
- Falls back to mergecap / raw copy
- Gzip compressed upload with 3 retries
"""
import os, sys, gzip, shutil, time, json
import requests, hashlib, subprocess
from datetime import datetime

def load_config():
    cfg = {}
    with open('/etc/ndr/sensor.conf') as f:
        for line in f:
            if '=' in line and \
               not line.startswith('#'):
                k,v = line.strip().split('=',1)
                cfg[k.strip()] = v.strip()
    return cfg

def sha16(key):
    return hashlib.sha256(
        key.encode()).hexdigest()[:16]

def get_opensearch_url():
    """Read OpenSearch URL from sensor.conf (written at install time)."""
    try:
        with open('/etc/ndr/sensor.conf') as f:
            for line in f:
                if line.startswith('OPENSEARCH_URL='):
                    return line.split('=', 1)[1].strip().rstrip('/')
    except Exception:
        pass
    return 'http://localhost:9200'

def find_in_raw_pcap_direct(cid):
    """Scan /opt/arkime/raw/ directly with tshark when OpenSearch is down.
    Returns (meta, pcap_files) or (None, [])."""
    raw_dir = '/opt/arkime/raw'
    if not os.path.isdir(raw_dir):
        print('[UPLOADER] No Arkime raw dir')
        return None, []
    # Collect pcap files modified in the last 24h, newest first
    cutoff = time.time() - 86400
    files = []
    for fn in os.listdir(raw_dir):
        if not (fn.endswith('.pcap') or fn.endswith('.pcap.zst')):
            continue
        fp = os.path.join(raw_dir, fn)
        try:
            mtime = os.path.getmtime(fp)
            if mtime >= cutoff:
                files.append((mtime, fp))
        except Exception:
            pass
    files.sort(reverse=True)
    pcap_files = [f for _, f in files]
    if not pcap_files:
        print('[UPLOADER] No recent Arkime raw files')
        return None, []
    print(f'[UPLOADER] OpenSearch down — scanning '
          f'{len(pcap_files)} raw file(s) directly')
    meta = {
        'src_ip': '', 'dst_ip': '',
        'src_port': '0', 'dst_port': '0',
        'proto': '', 'sensor_host': os.uname().nodename,
        'file_ids': [], 'root_id': ''
    }
    return meta, pcap_files

def find_session_in_opensearch(cid):
    os_base = get_opensearch_url()
    try:
        url = os_base + \
              "/arkime_sessions3-*/_search"
        query = {
            "query": {
                "term": {
                    "network.community_id": cid
                }
            },
            "_source": [
                "rootId","packetPos","packetLen",
                "fileId","source.ip",
                "destination.ip","source.port",
                "destination.port",
                "network.transport"
            ],
            "size": 10
        }
        r = requests.post(url,
            json=query, timeout=15)
        if r.status_code != 200:
            print(f"[UPLOADER] OpenSearch "
                  f"HTTP {r.status_code}")
            return None, None
        hits = r.json().get(
            'hits',{}).get('hits',[])
        if not hits:
            print(f"[UPLOADER] No session "
                  f"for {cid[:20]}")
            return None, None
        src = hits[0].get('_source', {})
        file_ids = src.get('fileId',
            src.get('fileIds', []))
        # OpenSearch returns ECS nested objects:
        # {"source":{"ip":"x"},"destination":{...}}
        # Use .get(key,{}).get(subkey) not dotted str
        meta = {
            "src_ip":    src.get('source',{}).get(
                             'ip',''),
            "dst_ip":    src.get('destination',{}).get(
                             'ip',''),
            "src_port":  str(src.get('source',{}).get(
                             'port', 0)),
            "dst_port":  str(src.get('destination',{}).get(
                             'port', 0)),
            "proto":     src.get('network',{}).get(
                             'transport',''),
            "sensor_host": os.uname().nodename,
            "file_ids":  file_ids,
            "root_id":   src.get('rootId',''),
        }
        print(f"[UPLOADER] Found session: "
              f"{meta['src_ip']}→"
              f"{meta['dst_ip']} "
              f"files={file_ids}")
        return meta, hits
    except Exception as e:
        print(f"[UPLOADER] OpenSearch error: {e}")
        return None, None

def get_arkime_files(file_ids):
    if not file_ids:
        return []
    try:
        url = get_opensearch_url() + \
              "/arkime_files/_search"
        query = {
            "query": {"terms": {"num": file_ids}},
            "_source": ["name","num"],
            "size": 20
        }
        r = requests.post(url,
            json=query, timeout=10)
        if r.status_code != 200:
            return []
        hits = r.json().get(
            'hits',{}).get('hits',[])
        files = []
        for h in hits:
            path = h.get('_source',{}).get(
                'name','')
            if path and os.path.exists(path):
                # Skip files Arkime is still writing
                age = time.time() - \
                    os.path.getmtime(path)
                if age < 60:
                    print(f"[UPLOADER] skipping "
                          f"active file "
                          f"({age:.0f}s old): "
                          f"{os.path.basename(path)}")
                    continue
                files.append(path)
                print(f"[UPLOADER] "
                      f"pcap file: {path}")
        return files
    except Exception as e:
        print(f"[UPLOADER] File lookup: {e}")
        return []

def decompress_if_needed(path, tmp_dir):
    """Decompress .pcap.zst to plain .pcap for tshark.
    Skips files modified in the last 30s (still being written by Arkime)."""
    if path.endswith('.pcap.zst') or path.endswith('.zst'):
        # Skip active files Arkime is still writing
        age = time.time() - os.path.getmtime(path)
        if age < 30:
            print(f"[UPLOADER] skipping active file "
                  f"(modified {age:.0f}s ago): "
                  f"{os.path.basename(path)}")
            return None
        out = os.path.join(tmp_dir,
            os.path.basename(path).replace('.zst',''))
        if not os.path.exists(out):
            result = subprocess.run(
                ['zstd', '-d', path, '-o', out, '-f'],
                capture_output=True, timeout=60)
            if result.returncode != 0:
                print(f"[UPLOADER] zstd failed: "
                      f"{result.stderr.decode()[:100]}")
                return None
        return out
    return path

def extract_with_tshark(pcap_files, cid, output):
    if not pcap_files:
        return False
    tmp_dir = os.path.dirname(output)
    decompressed = []
    for f in pcap_files:
        d = decompress_if_needed(f, tmp_dir)
        if d:
            decompressed.append(d)
    if not decompressed:
        return False
    input_args = []
    for f in decompressed:
        input_args += ['-r', f]
    # --enable-protocol communityid is required even on tshark >= 3.4
    # because the dissector ships disabled by default
    cmd = (['tshark',
            '--enable-protocol', 'communityid']
           + input_args +
           ['-Y',
            f'communityid.id == "{cid}"',
            '-w', output, '-F', 'pcap'])
    try:
        result = subprocess.run(cmd,
            capture_output=True, timeout=60)
        if (os.path.exists(output) and
                os.path.getsize(output) >= 24):
            out_size = os.path.getsize(output)
            # If tshark output is suspiciously close
            # to the source file size, the communityid
            # filter didn't work — treat as failure so
            # tcpdump fallback runs instead
            src_size = sum(
                os.path.getsize(f)
                for f in decompressed
                if os.path.exists(f))
            if src_size > 0 and out_size > src_size * 0.9:
                print(f"[UPLOADER] tshark filter "
                      f"ineffective "
                      f"({out_size}≈{src_size}B) "
                      f"— trying tcpdump")
                try: os.remove(output)
                except: pass
                return False
            print(f"[UPLOADER] tshark "
                  f"{out_size}B")
            return True
    except FileNotFoundError:
        pass
    except Exception as e:
        print(f"[UPLOADER] tshark: {e}")
    return False

def extract_with_tcpdump(pcap_files, meta, output):
    """Filter by src/dst IP + port using tcpdump BPF.
    Works on any Linux sensor without special tshark plugins."""
    if not pcap_files or not meta:
        return False
    src_ip   = meta.get('src_ip','')
    dst_ip   = meta.get('dst_ip','')
    src_port = meta.get('src_port','0')
    dst_port = meta.get('dst_port','0')
    if not src_ip or not dst_ip:
        return False
    tmp_dir = os.path.dirname(output)
    decompressed = []
    for f in pcap_files:
        d = decompress_if_needed(f, tmp_dir)
        if d:
            decompressed.append(d)
    if not decompressed:
        return False
    # BPF: match both directions of the flow. A port that is missing or 0 in the session
    # metadata must not be part of the filter ("port 0" matches nothing).
    clauses = [f"host {src_ip}", f"host {dst_ip}"]
    for port in (src_port, dst_port):
        if str(port).strip() not in ('', '0', 'None'):
            clauses.append(f"port {port}")
    bpf = "(" + " and ".join(clauses) + ")"
    try:
        cmd = ['tcpdump', '-r', decompressed[0],
               '-w', output, bpf]
        result = subprocess.run(
            cmd, capture_output=True, timeout=60)
        # A pcap with no packets is exactly 24 bytes (the file header). That used to count as
        # success, so nothing else was tried and an EMPTY capture was uploaded. A useful
        # capture holds at least one packet: 24-byte header + 16-byte record header + data.
        if (os.path.exists(output) and
                os.path.getsize(output) > 40):
            sz = os.path.getsize(output)
            src_sz = os.path.getsize(decompressed[0])
            # Same sanity check: if output ≈ full file,
            # filter didn't work
            if src_sz > 0 and sz > src_sz * 0.9:
                print(f"[UPLOADER] tcpdump filter "
                      f"ineffective — falling back")
                try: os.remove(output)
                except: pass
                return False
            print(f"[UPLOADER] tcpdump {sz}B")
            return True
    except FileNotFoundError:
        print("[UPLOADER] tcpdump not found")
    except Exception as e:
        print(f"[UPLOADER] tcpdump: {e}")
    return False

def extract_with_mergecap(pcap_files, output):
    if not pcap_files:
        return False
    tmp_dir = os.path.dirname(output)
    decompressed = []
    for f in pcap_files:
        d = decompress_if_needed(f, tmp_dir)
        if d:
            decompressed.append(d)
    if not decompressed:
        return False
    if len(decompressed) == 1:
        shutil.copy2(decompressed[0], output)
        return os.path.getsize(output) >= 24
    try:
        cmd = (['mergecap', '-w', output]
               + decompressed)
        subprocess.run(cmd,
            capture_output=True, timeout=60)
        if (os.path.exists(output) and
                os.path.getsize(output) >= 24):
            print(f"[UPLOADER] mergecap "
                  f"{os.path.getsize(output)}B")
            return True
    except FileNotFoundError:
        pass
    except Exception as e:
        print(f"[UPLOADER] mergecap: {e}")
    return False

def extract_raw_copy(pcap_files, output):
    if not pcap_files:
        return False
    shutil.copy2(pcap_files[0], output)
    size = os.path.getsize(output) \
        if os.path.exists(output) else 0
    if size >= 24:
        print(f"[UPLOADER] raw copy {size}B")
        return True
    return False

def compress_and_upload(
        cid, pcap, url, key, meta):
    gz = pcap + '.gz'
    try:
        with open(pcap,'rb') as fi, \
             gzip.open(gz,'wb',
                       compresslevel=6) as fo:
            shutil.copyfileobj(fi, fo)
        orig = os.path.getsize(pcap)
        comp = os.path.getsize(gz)
        pct = (1-comp/orig)*100 if orig else 0
        print(f"[UPLOADER] compressed "
              f"{orig}→{comp}B "
              f"({pct:.0f}% smaller)")
        for attempt in range(3):
            if attempt > 0:
                time.sleep(5 * attempt)
                print(f"[UPLOADER] retry "
                      f"{attempt}/2")
            try:
                with open(gz,'rb') as f:
                    r = requests.post(
                        f"{url}/api/pcap/upload",
                        headers={
                            "X-Sensor-Key": key,
                        },
                        files={"pcap":(
                            "session.pcap.gz",
                            f,
                            "application/gzip"
                        )},
                        data={
                            "community_id": cid,
                            "src_ip":   meta.get(
                                "src_ip",""),
                            "dst_ip":   meta.get(
                                "dst_ip",""),
                            "src_port": meta.get(
                                "src_port","0"),
                            "dst_port": meta.get(
                                "dst_port","0"),
                            "proto":    meta.get(
                                "proto",""),
                            "sensor_host": meta.get(
                                "sensor_host",""),
                        },
                        timeout=120
                    )
                if r.status_code == 409:
                    print("[UPLOADER] ✅ uploaded "
                          "(already exists)")
                    return True
                if r.status_code == 200:
                    try:
                        body = r.json()
                    except Exception:
                        body = {}
                    if body.get('status') \
                            == 'error':
                        print(f"[UPLOADER] "
                              f"server rejected:"
                              f" {body.get('message','?')}")
                        continue
                    sid = body.get(
                        'session_id','?')
                    print(f"[UPLOADER] "
                          f"✅ uploaded "
                          f"sid={sid[:8]}")
                    return True
                print(f"[UPLOADER] HTTP "
                      f"{r.status_code}: "
                      f"{r.text[:100]}")
            except Exception as e:
                print(f"[UPLOADER] upload: {e}")
        return False
    finally:
        try: os.remove(gz)
        except: pass

def report_failure(cid, url, key, err):
    try:
        requests.post(
            f"{url}/api/pcap/upload-failed",
            headers={"X-Sensor-Key": key},
            json={"community_id": cid,
                  "error": str(err)},
            timeout=10
        )
    except:
        pass

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: pcap-uploader.py <cid>")
        sys.exit(1)

    cid = sys.argv[1]
    cfg = load_config()
    url = cfg.get('CLOUD_URL','').rstrip('/')
    key = cfg.get('API_KEY','')
    pwd = sha16(key)

    safe = cid.replace(
        '/','_').replace(':','_')
    tmp  = "/opt/ndr-sensor/pcap-tmp"
    os.makedirs(tmp, exist_ok=True)
    raw_out    = f"{tmp}/raw_{safe}.pcap"
    retry_file = f"{tmp}/.retry_{safe}"

    try:
        print(f"[UPLOADER] Processing: "
              f"{cid[:30]}")

        meta, os_hits = \
            find_session_in_opensearch(cid)
        direct_pcap_files = []
        if not meta:
            # OpenSearch unreachable or session not indexed yet.
            # Try scanning Arkime raw files directly with tshark.
            meta, direct_pcap_files = \
                find_in_raw_pcap_direct(cid)

        if not meta:
            # Count local "not in Arkime" retries.
            # Normal: Arkime is still writing the file
            # — the pending queue retries every 30s.
            # After 5 misses (~2.5 min), the session
            # will never appear; report failure so the
            # server stops retrying (retry_count → 3).
            try:
                attempts = int(
                    open(retry_file).read().strip())
            except Exception:
                attempts = 0
            attempts += 1
            with open(retry_file, 'w') as f:
                f.write(str(attempts))

            if attempts >= 5:
                print(f"[UPLOADER] giving up after "
                      f"{attempts} misses: "
                      f"{cid[:20]}")
                try: os.remove(retry_file)
                except: pass
                report_failure(
                    cid, url, key,
                    f"not indexed by Arkime "
                    f"after {attempts} retries")
            else:
                print(f"[UPLOADER] not in Arkime "
                      f"yet (attempt {attempts}/5), "
                      f"will retry: {cid[:20]}")
            sys.exit(0)

        # Session found — clear retry counter
        try: os.remove(retry_file)
        except: pass

        extracted = False
        pcap_files = get_arkime_files(
            meta.get('file_ids', []))
        # If OpenSearch was down, use the directly scanned files
        if not pcap_files and direct_pcap_files:
            pcap_files = direct_pcap_files
        if pcap_files:
            # 1. tshark with communityid filter
            extracted = extract_with_tshark(
                pcap_files, cid, raw_out)
            # 2. tcpdump BPF filter (no plugin needed)
            if not extracted:
                extracted = extract_with_tcpdump(
                    pcap_files, meta, raw_out)
            # 3. mergecap (multi-file merge)
            if not extracted:
                extracted = extract_with_mergecap(
                    pcap_files, raw_out)
            # 4. raw copy — last resort, uploads full
            # Arkime PCAP rotation file. Acceptable for
            # rare cases; server stores it per-session.
            if not extracted:
                extracted = extract_raw_copy(
                    pcap_files, raw_out)

        if not extracted:
            print(f"[UPLOADER] ❌ all methods "
                  f"failed for {cid[:20]}")
            report_failure(cid, url, key,
                "all extraction methods failed")
            sys.exit(1)

        ok = compress_and_upload(
            cid, raw_out, url, key, meta or {})
        if not ok:
            report_failure(cid, url, key,
                "upload failed after 3 retries")
            sys.exit(1)

        print(f"[UPLOADER] ✅ Done: {cid[:20]}")

    finally:
        try: os.remove(raw_out)
        except: pass
UPLOADER
chmod +x /opt/ndr-sensor/pcap-uploader.py

# ── Systemd services ──────────────────────────────
log "Creating systemd services..."
VECTOR_BIN=$(which vector 2>/dev/null || \
  echo "/usr/bin/vector")

cat > /etc/systemd/system/ndr-vector.service \
  << EOF
[Unit]
Description=NDR Vector Log Forwarder
After=network.target
[Service]
ExecStart=$VECTOR_BIN --config /etc/ndr/vector.toml
Restart=always
RestartSec=5
[Install]
WantedBy=multi-user.target
EOF

cat > /etc/systemd/system/ndr-agent.service \
  << EOF
[Unit]
Description=NDR Sensor Agent
After=network.target
[Service]
ExecStart=/usr/bin/python3 -u \
  /opt/ndr-sensor/agent.py
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal
Environment=PYTHONUNBUFFERED=1
AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN
CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN
[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload 2>/tmp/ndr_svc_err || record_error "Service Setup" \
  "systemctl daemon-reload failed ($(cat /tmp/ndr_svc_err 2>/dev/null)) — is this host running under real systemd (not just a container without an init system)?" \
  "If this is a container, run the sensor on a real host/VM with systemd, or manage ndr-agent/vector/arkime-capture without systemd."
rm -f /tmp/ndr_svc_err
systemctl enable \
  ndr-vector \
  ndr-agent \
  arkime-capture \
  2>/dev/null || true

# ── Start all services ────────────────────────────
log "Starting Packet Recorder..."
systemctl start arkime-capture 2>/dev/null || true

log "Starting Log Collector..."
systemctl start ndr-vector 2>/dev/null || true

log "Starting Sensor Agent..."
systemctl start ndr-agent 2>/dev/null || true

# ── Register with cloud ───────────────────────────
log "Registering sensor with cloud..."
sleep 3
# By this point every engine (Zeek, Suricata, Arkime, Vector, auditd) is
# already installed and running — a network blip hitting this last curl call
# must not take down the whole install. REG=$(...) on its own is NOT exempt
# from `set -e` (only if/while/&&/|| guards are), so a bare assignment here
# would silently kill the script on a DNS/connectivity hiccup with no message
# at all, right after everything else already succeeded.
REG=$(curl -sS -X POST \
  "$CLOUD_URL/api/sensor/register" \
  -H "X-Sensor-Key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d "{
    \"tenant_id\": \"$TENANT_ID\",
    \"hostname\": \"$(hostname)\",
    \"interface\": \"$IFACE\",
    \"os\": \"$PRETTY_NAME\"
  }" 2>/tmp/ndr_reg_err) || true

if echo "$REG" | grep -q '"status":"ok"'; then
  log "✅ Registered with cloud"
else
  record_error "Cloud Registration" "could not register with $CLOUD_URL (${REG:-$(cat /tmp/ndr_reg_err 2>/dev/null)})" \
    "Sensor is fully installed and running locally — re-register manually once cloud connectivity is confirmed: curl -X POST $CLOUD_URL/api/sensor/register -H 'X-Sensor-Key: $API_KEY' -H 'Content-Type: application/json' -d '{\"tenant_id\":\"$TENANT_ID\",\"hostname\":\"'\"\$(hostname)\"'\",\"interface\":\"$IFACE\"}'"
fi
rm -f /tmp/ndr_reg_err

# ── Verify services ───────────────────────────────
log "Waiting for engines to initialize (up to 30s)..."
for i in {1..15}; do
  Z=$(pgrep -f "zeek"     > /dev/null 2>&1 && echo "✅ Running" || echo "❌ Stopped")
  S=$(pgrep -f "suricata" > /dev/null 2>&1 && echo "✅ Running" || echo "❌ Stopped")
  [[ "$Z" == "✅ Running" ]] && [[ "$S" == "✅ Running" ]] && break
  sleep 2
done
V=$(pgrep -f "vector"          > /dev/null 2>&1 && echo "✅ Running" || echo "❌ Stopped")
P=$(pgrep -f "arkime/bin/capture" > /dev/null 2>&1 && echo "✅ Running" || echo "❌ Stopped")

# ── Completion banner ─────────────────────────────
printf "\n"
printf "  ${CYAN}╔══════════════════════════════════════════════╗${NC}\n"
printf "  ${CYAN}║${NC}                                              ${CYAN}║${NC}\n"
printf "  ${CYAN}║${NC}    ${GREEN}${BOLD}✓  Sensor Installation Complete${NC}            ${CYAN}║${NC}\n"
printf "  ${CYAN}║${NC}                                              ${CYAN}║${NC}\n"
printf "  ${CYAN}╠══════════════════════════════════════════════╣${NC}\n"
printf "  ${CYAN}║${NC}  ${DIM}Tenant   :${NC}  %-32s${CYAN}║${NC}\n" "$TENANT_ID"
printf "  ${CYAN}║${NC}  ${DIM}Interface:${NC}  %-32s${CYAN}║${NC}\n" "$IFACE"
printf "  ${CYAN}║${NC}  ${DIM}Mode     :${NC}  %-32s${CYAN}║${NC}\n" "$SENSOR_MODE"
printf "  ${CYAN}║${NC}  ${DIM}Cloud    :${NC}  %-32s${CYAN}║${NC}\n" "${CLOUD_URL:0:30}"
printf "  ${CYAN}╠══════════════════════════════════════════════╣${NC}\n"
printf "  ${CYAN}║${NC}                                              ${CYAN}║${NC}\n"
printf "  ${CYAN}║${NC}  Agent-Z  (Network Analyzer) :  %-12s  ${CYAN}║${NC}\n" "$Z"
printf "  ${CYAN}║${NC}  Agent-S  (Threat Detection) :  %-12s  ${CYAN}║${NC}\n" "$S"
printf "  ${CYAN}║${NC}  Log Collector               :  %-12s  ${CYAN}║${NC}\n" "$V"
printf "  ${CYAN}║${NC}  Packet Recorder             :  %-12s  ${CYAN}║${NC}\n" "$P"
printf "  ${CYAN}║${NC}                                              ${CYAN}║${NC}\n"
printf "  ${CYAN}╠══════════════════════════════════════════════╣${NC}\n"
printf "  ${CYAN}║${NC}  ${DIM}Logs :${NC}  journalctl -u ndr-agent -f           ${CYAN}║${NC}\n"
printf "  ${CYAN}║${NC}  ${DIM}Conf :${NC}  /etc/ndr/sensor.conf                 ${CYAN}║${NC}\n"
printf "  ${CYAN}║${NC}                                              ${CYAN}║${NC}\n"
printf "  ${CYAN}║${NC}    ${DIM}◆  Powered by PromaSecure  ◆${NC}               ${CYAN}║${NC}\n"
printf "  ${CYAN}║${NC}                                              ${CYAN}║${NC}\n"
printf "  ${CYAN}╚══════════════════════════════════════════════╝${NC}\n"
printf "\n"

if [[ "$Z" != "✅ Running" ]] || [[ "$S" != "✅ Running" ]]; then
  warn "One or more engines did not start — check logs below:"
  echo ""
  journalctl -u ndr-agent -n 30 --no-pager 2>/dev/null || true
  cat /var/log/ndr/zeek/startup.log 2>/dev/null || true
fi