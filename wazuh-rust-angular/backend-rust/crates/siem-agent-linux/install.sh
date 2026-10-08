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

MANAGER_URL=${SIEM_MANAGER_URL:-"http://127.0.0.1:8088"}
AGENT_ID=${SIEM_AGENT_ID:-"002"}
AGENT_NAME=${HOSTNAME:-$(hostname)}
INSTALL_DIR="/var/ossec"
USER="wazuh"
GROUP="wazuh"

echo "[+] SIEM Manager Endpoint:       ${MANAGER_URL}"
echo "[+] Assigned Agent ID:           ${AGENT_ID}"
echo "[+] Agent Hostname:              ${AGENT_NAME}"
echo "[+] Installation Prefix:         ${INSTALL_DIR}"

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
elif command -v cargo > /dev/null 2>&1; then
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

cat <<EOF > "${INSTALL_DIR}/etc/client.keys"
${AGENT_ID} ${AGENT_NAME} any a1b2c3d4e5f67890123456789abcdef0
EOF

cat <<EOF > "${INSTALL_DIR}/etc/agent-config.json"
{
  "manager_url": "${MANAGER_URL}",
  "agent_id": "${AGENT_ID}",
  "agent_name": "${AGENT_NAME}",
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
chown root:${GROUP} "${INSTALL_DIR}/etc/client.keys"
chmod 640 "${INSTALL_DIR}/etc/client.keys"
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
if [ -d /run/systemd/system ] || [ -d /etc/systemd/system ]; then
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
    echo "[i] Systemd not found. You can start the agent directly in the foreground or via init:"
    echo "    wazuh-control start"
fi

echo "==============================================================="
echo "   Wazuh Linux Agent Installed Successfully! [COMPLETE]        "
echo "   Control CLI:   wazuh-control status-service                 "
echo "   Binary Daemon: wazuh-agentd                                 "
echo "   Logs:          /var/ossec/logs/                             "
echo "==============================================================="
