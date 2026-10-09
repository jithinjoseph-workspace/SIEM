#!/bin/bash
# ==============================================================================
# Wazuh Next-Gen Linux Agent Universal Installer (Rust)
# Full implementation mirroring official Wazuh installation & dist-detect.sh
# ==============================================================================
set -e

echo "==============================================================="
echo "   Wazuh Next-Gen Linux Endpoint Agent Universal Installer     "
echo "==============================================================="

# 1. Verify root privileges
if [ "$EUID" -ne 0 ]; then
    echo "[-] Error: This installation script must be executed as root (sudo)."
    exit 1
fi

# 2. Distribution & OS Version Detection (Mirroring Wazuh dist-detect.sh)
DIST_NAME="linux"
DIST_VER="unknown"
PKG_TYPE="tar"

if [ -r "/etc/os-release" ]; then
    . /etc/os-release
    DIST_NAME=${ID:-"linux"}
    DIST_VER=${VERSION_ID:-"unknown"}
elif [ -r "/etc/redhat-release" ]; then
    if grep -qi "centos" /etc/redhat-release; then
        DIST_NAME="centos"
    else
        DIST_NAME="rhel"
    fi
elif [ -r "/etc/debian_version" ]; then
    DIST_NAME="debian"
elif [ -r "/etc/arch-release" ]; then
    DIST_NAME="arch"
elif [ -r "/etc/alpine-release" ]; then
    DIST_NAME="alpine"
fi

case "${DIST_NAME}" in
    ubuntu|debian|kali|linuxmint|pop)
        PKG_TYPE="deb"
        ;;
    rhel|centos|rocky|almalinux|fedora|amzn|oracle)
        PKG_TYPE="rpm"
        ;;
    suse|opensuse*)
        PKG_TYPE="rpm-zypper"
        ;;
    alpine)
        PKG_TYPE="apk"
        ;;
    arch|manjaro)
        PKG_TYPE="pacman"
        ;;
    *)
        PKG_TYPE="generic"
        ;;
esac

echo "[+] Detected Linux Distribution: ${DIST_NAME} (Version: ${DIST_VER})"
echo "[+] Target Package Family:       ${PKG_TYPE}"

# Settings: SIEM_* names, or the official WAZUH_* deployment variables.
MANAGER_URL=${SIEM_MANAGER_URL:-${WAZUH_MANAGER:-"http://127.0.0.1:8088"}}
case "${MANAGER_URL}" in
    http://*|https://*) ;;
    *) MANAGER_URL="http://${MANAGER_URL}:${WAZUH_MANAGER_PORT:-8088}" ;;
esac
MANAGER_URL="${MANAGER_URL%/}"
AGENT_NAME=${SIEM_AGENT_NAME:-${WAZUH_AGENT_NAME:-$(hostname)}}
AGENT_GROUP=${SIEM_AGENT_GROUP:-${WAZUH_AGENT_GROUP:-"default"}}
TENANT_KEY=${SIEM_TENANT_KEY:-${WAZUH_TENANT_KEY:-""}}
INSTALL_DIR="/var/ossec"
USER="wazuh"
GROUP="wazuh"

echo "[+] SIEM Manager Endpoint:       ${MANAGER_URL}"
echo "[+] Agent Name:                  ${AGENT_NAME}"
echo "[+] Agent Group:                 ${AGENT_GROUP}"
if [ -n "${TENANT_KEY}" ]; then
    echo "[+] Tenant Agent Key:            provided"
else
    echo "[!] Tenant Agent Key:            none (the agent joins the default tenant)"
fi
echo "[+] Installation Prefix:         ${INSTALL_DIR}"

# HTTP helper: curl or wget
http_get() {
    if command -v curl > /dev/null 2>&1; then curl -fsSL "$1" -o "$2"; else wget -q "$1" -O "$2"; fi
}

# 3. Create dedicated system group and user
if ! getent group ${GROUP} > /dev/null 2>&1; then
    echo "[+] Creating system group '${GROUP}'..."
    if command -v groupadd > /dev/null 2>&1; then
        groupadd -r ${GROUP}
    elif command -v addgroup > /dev/null 2>&1; then
        addgroup --system ${GROUP}
    fi
fi

if ! getent passwd ${USER} > /dev/null 2>&1; then
    echo "[+] Creating system user '${USER}'..."
    SHELL="/sbin/nologin"
    if [ ! -f "${SHELL}" ] && [ -f "/bin/false" ]; then
        SHELL="/bin/false"
    fi
    if command -v useradd > /dev/null 2>&1; then
        useradd -r -g ${GROUP} -d ${INSTALL_DIR} -s ${SHELL} -c "Wazuh Security Agent" ${USER}
    elif command -v adduser > /dev/null 2>&1; then
        adduser --system --home ${INSTALL_DIR} --shell ${SHELL} --ingroup ${GROUP} ${USER}
    fi
fi

# 4. Create standard Wazuh directory tree
mkdir -p "${INSTALL_DIR}/bin"
mkdir -p "${INSTALL_DIR}/etc"
mkdir -p "${INSTALL_DIR}/logs"
mkdir -p "${INSTALL_DIR}/queue"
mkdir -p "${INSTALL_DIR}/quarantine"
mkdir -p "${INSTALL_DIR}/var/run"

# 5. Locate or compile the agent binary
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BINARY_CANDIDATES=(
    "${SCRIPT_DIR}/../../target/release/siem-agent-linux"
    "${SCRIPT_DIR}/../../target/debug/siem-agent-linux"
    "${SCRIPT_DIR}/siem-agent-linux"
    "./siem-agent-linux"
)

BINARY_FOUND=""
for cand in "${BINARY_CANDIDATES[@]}"; do
    if [ -f "${cand}" ]; then
        BINARY_FOUND="${cand}"
        break
    fi
done

if [ -n "${BINARY_FOUND}" ]; then
    echo "[+] Installing binary from '${BINARY_FOUND}'..."
    cp "${BINARY_FOUND}" "${INSTALL_DIR}/bin/siem-agent-linux"
elif http_get "${MANAGER_URL}/downloads/siem-agent-linux" "${INSTALL_DIR}/bin/siem-agent-linux.new" 2>/dev/null \
     && [ -s "${INSTALL_DIR}/bin/siem-agent-linux.new" ]; then
    echo "[+] Downloaded agent binary from ${MANAGER_URL}/downloads/siem-agent-linux"
    mv -f "${INSTALL_DIR}/bin/siem-agent-linux.new" "${INSTALL_DIR}/bin/siem-agent-linux"
elif command -v cargo > /dev/null 2>&1; then
    rm -f "${INSTALL_DIR}/bin/siem-agent-linux.new"
    echo "[+] Compiling siem-agent-linux in release mode via Cargo..."
    cargo build --release --package siem-agent-linux --manifest-path "${SCRIPT_DIR}/../../Cargo.toml"
    cp "${SCRIPT_DIR}/../../target/release/siem-agent-linux" "${INSTALL_DIR}/bin/siem-agent-linux"
else
    echo "[-] Error: siem-agent-linux binary not found and cargo compiler is not present."
    echo "    Please place the compiled 'siem-agent-linux' binary in this directory and re-run."
    exit 1
fi

chmod 750 "${INSTALL_DIR}/bin/siem-agent-linux"
ln -sf "${INSTALL_DIR}/bin/siem-agent-linux" /usr/local/bin/wazuh-agentd
ln -sf "${INSTALL_DIR}/bin/siem-agent-linux" /usr/local/bin/wazuh-control

# 6. Write official ossec.conf & client.keys
cat <<EOF > "${INSTALL_DIR}/etc/ossec.conf"
<ossec_config>
  <client>
    <server>
      <address>${MANAGER_URL}</address>
      <port>8088</port>
      <protocol>tcp</protocol>
    </server>
    <config-profile>${DIST_NAME}</config-profile>
    <crypto_method>aes</crypto_method>
  </client>

  <client_buffer>
    <disabled>no</disabled>
    <queue_size>5000</queue_size>
    <events_per_second>500</events_per_second>
  </client_buffer>

  <syscheck>
    <disabled>no</disabled>
    <frequency>43200</frequency>
    <scan_on_start>yes</scan_on_start>
    <directories>/etc,/usr/bin,/usr/sbin,/bin,/sbin</directories>
    <ignore>/etc/mtab</ignore>
    <ignore>/etc/hosts.deny</ignore>
  </syscheck>

  <wodle name="syscollector">
    <disabled>no</disabled>
    <interval>1h</interval>
    <scan_on_start>yes</scan_on_start>
    <hardware>yes</hardware>
    <os>yes</os>
    <network>yes</network>
    <packages>yes</packages>
    <ports>yes</ports>
    <processes>yes</processes>
  </wodle>

  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/auth.log</location>
  </localfile>

  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/syslog</location>
  </localfile>

  <active-response>
    <disabled>no</disabled>
    <command>firewall-drop</command>
    <location>local</location>
    <timeout>600</timeout>
  </active-response>
</ossec_config>
EOF

# Enrollment: the manager assigns an agent id that is unique across tenants.
# A re-install keeps an existing enrollment (client.keys from a previous run).
KEYS_FILE="${INSTALL_DIR}/etc/client.keys"
if [ -s "${KEYS_FILE}" ] && ! grep -q "a1b2c3d4e5f67890123456789abcdef0" "${KEYS_FILE}"; then
    echo "[+] Keeping existing enrollment: $(cut -d' ' -f1,2 "${KEYS_FILE}" | head -1)"
else
    rm -f "${KEYS_FILE}"
    BODY="{\"name\":\"${AGENT_NAME}\",\"groups\":\"${AGENT_GROUP}\",\"os_type\":\"linux\"}"
    RESP=""
    if command -v curl > /dev/null 2>&1; then
        RESP=$(curl -fsS -X POST "${MANAGER_URL}/api/v1/agents/enroll" \
            -H "Content-Type: application/json" ${TENANT_KEY:+-H "X-Tenant-Key: ${TENANT_KEY}"} \
            -d "${BODY}" 2>/dev/null || true)
    else
        RESP=$(wget -qO- --header="Content-Type: application/json" ${TENANT_KEY:+--header="X-Tenant-Key: ${TENANT_KEY}"} \
            --post-data="${BODY}" "${MANAGER_URL}/api/v1/agents/enroll" 2>/dev/null || true)
    fi
    NEW_ID=$(printf '%s' "${RESP}" | sed -n 's/.*"agent_id":"\([^"]*\)".*/\1/p')
    NEW_NAME=$(printf '%s' "${RESP}" | sed -n 's/.*"agent_name":"\([^"]*\)".*/\1/p')
    NEW_KEY=$(printf '%s' "${RESP}" | sed -n 's/.*"raw_key":"\([^"]*\)".*/\1/p')
    NEW_TENANT=$(printf '%s' "${RESP}" | sed -n 's/.*"tenant_id":"\([^"]*\)".*/\1/p')
    if [ -n "${NEW_ID}" ] && [ -n "${NEW_KEY}" ]; then
        echo "${NEW_ID} ${NEW_NAME:-${AGENT_NAME}} any ${NEW_KEY}" > "${KEYS_FILE}"
        echo "[✓] Enrolled as agent ${NEW_ID} (${NEW_NAME:-${AGENT_NAME}}) in tenant '${NEW_TENANT}'"
    else
        echo "[!] Enrollment with ${MANAGER_URL} failed; the agent will enroll itself when it starts."
    fi
fi

cat <<EOF > "${INSTALL_DIR}/etc/agent-config.json"
{
  "manager_url": "${MANAGER_URL}",
  "agent_name": "${AGENT_NAME}",
  "agent_group": "${AGENT_GROUP}",
  "tenant_key": "${TENANT_KEY}",
  "buffer_capacity": 5000,
  "events_per_second": 500
}
EOF

# 7. Apply hardened file permissions
chown root:${GROUP} "${INSTALL_DIR}"
chmod 750 "${INSTALL_DIR}"
chown -R root:${GROUP} "${INSTALL_DIR}/bin"
chmod 750 "${INSTALL_DIR}/bin"
chown root:${GROUP} "${INSTALL_DIR}/etc/ossec.conf"
chmod 640 "${INSTALL_DIR}/etc/ossec.conf"
if [ -f "${INSTALL_DIR}/etc/client.keys" ]; then
    chown root:${GROUP} "${INSTALL_DIR}/etc/client.keys"
    chmod 640 "${INSTALL_DIR}/etc/client.keys"
fi
chown root:${GROUP} "${INSTALL_DIR}/etc/agent-config.json"
chmod 640 "${INSTALL_DIR}/etc/agent-config.json"
chown -R ${USER}:${GROUP} "${INSTALL_DIR}/logs"
chmod 750 "${INSTALL_DIR}/logs"
chown -R ${USER}:${GROUP} "${INSTALL_DIR}/queue"
chmod 750 "${INSTALL_DIR}/queue"
chown -R root:${GROUP} "${INSTALL_DIR}/quarantine"
chmod 700 "${INSTALL_DIR}/quarantine"

# 8. Service Registration (Systemd / Init)
SERVICE_SOURCE="${SCRIPT_DIR}/init/wazuh-rust-agent.service"
# systemd only when it is actually running (containers / WSL often have the
# directories but no running systemd).
if [ -d /run/systemd/system ] && command -v systemctl > /dev/null 2>&1; then
    echo "[+] Provisioning systemd daemon (wazuh-rust-agent.service)..."
    if [ -f "${SERVICE_SOURCE}" ]; then
        cp "${SERVICE_SOURCE}" /etc/systemd/system/wazuh-rust-agent.service
    else
        cat <<EOF > /etc/systemd/system/wazuh-rust-agent.service
[Unit]
Description=Wazuh Next-Gen Endpoint Security Agent (Rust)
Documentation=https://wazuh.com
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=${INSTALL_DIR}
ExecStart=${INSTALL_DIR}/bin/siem-agent-linux --daemon
Restart=always
RestartSec=10
KillMode=process
StandardOutput=journal
StandardError=journal
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF
    fi
    systemctl daemon-reload
    systemctl enable wazuh-rust-agent.service
    systemctl restart wazuh-rust-agent.service
    echo "[✓] Service status: ACTIVE & ENABLED"
else
    echo "[i] systemd is not running: starting the agent in the background."
    pkill -f "${INSTALL_DIR}/bin/siem-agent-linux" 2>/dev/null || true
    ( cd "${INSTALL_DIR}" && nohup "${INSTALL_DIR}/bin/siem-agent-linux" --daemon < /dev/null >> "${INSTALL_DIR}/logs/agent.log" 2>&1 & )
    echo "[✓] Agent started (log: ${INSTALL_DIR}/logs/agent.log). Add it to your init system to start on boot."
fi

echo "==============================================================="
echo "   Wazuh Linux Agent Installed Successfully! [COMPLETE]        "
echo "   Control CLI:   wazuh-control status-service                 "
echo "   Binary Daemon: wazuh-agentd                                 "
echo "   Logs:          /var/ossec/logs/                             "
echo "==============================================================="
