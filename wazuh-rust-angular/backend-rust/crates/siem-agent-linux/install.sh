#!/bin/bash
# ProVigil Linux Endpoint Agent Universal Installer
set -e

echo "==============================================================="
echo "       ProVigil Linux Endpoint Agent Universal Installer       "
echo "==============================================================="

if [ "$EUID" -ne 0 ]; then
    echo "[-] Error: This installation script must be executed as root (sudo)."
    exit 1
fi

echo "[+] Stopping previous agent daemon..."
systemctl stop provigil-agent 2>/dev/null || true
if [ -x "/opt/provigil-agent/bin/provigil-control" ]; then
    /opt/provigil-agent/bin/provigil-control stop-service 2>/dev/null || true
fi
pkill -9 -f "provigil-agent-linux" 2>/dev/null || true
pkill -9 -f "provigil-agentd" 2>/dev/null || true
pkill -9 -f "siem-agent-linux" 2>/dev/null || true

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

MANAGER_URL=${SIEM_MANAGER_URL:-${PROVIGIL_MANAGER:-"https://127.0.0.1:8443"}}
case "${MANAGER_URL}" in
    http://*|https://*) ;;
    *)
        P="${SIEM_MANAGER_PORT:-${PROVIGIL_MANAGER_PORT:-8443}}"
        if [ "$P" = "8443" ] || [ "$P" = "443" ]; then
            MANAGER_URL="https://${MANAGER_URL}:${P}"
        else
            MANAGER_URL="http://${MANAGER_URL}:${P}"
        fi
        ;;
esac
MANAGER_URL="${MANAGER_URL%/}"
MANAGER_HOST=$(echo "${MANAGER_URL}" | sed -e 's|^[^/]*//||' -e 's|:.*||' -e 's|/.*||')
MANAGER_PORT=$(echo "${MANAGER_URL}" | sed -e 's|^.*:||' -e 's|/.*||')
if [ -z "${MANAGER_PORT}" ] || [ "${MANAGER_PORT}" = "${MANAGER_URL}" ] || [ "${MANAGER_PORT}" = "${MANAGER_HOST}" ]; then
    case "${MANAGER_URL}" in
        https://*) MANAGER_PORT="8443" ;;
        *) MANAGER_PORT="8088" ;;
    esac
fi
AGENT_NAME=${SIEM_AGENT_NAME:-${PROVIGIL_AGENT_NAME:-$(hostname)}}
AGENT_GROUP=${SIEM_AGENT_GROUP:-${PROVIGIL_AGENT_GROUP:-"default"}}
TENANT_KEY=${SIEM_TENANT_KEY:-${PROVIGIL_TENANT_KEY:-""}}
CA_SOURCE=${SIEM_CA_FILE:-""}
INSTALL_DIR="/opt/provigil-agent"
USER="provigil"
GROUP="provigil"

echo "[+] Manager Endpoint:            ${MANAGER_URL}"
echo "[+] Agent Name:                  ${AGENT_NAME}"
echo "[+] Agent Group:                 ${AGENT_GROUP}"
if [ -n "${TENANT_KEY}" ]; then
    echo "[+] Tenant Agent Key:            provided"
else
    echo "[!] Tenant Agent Key:            none (the agent joins the default tenant)"
fi
echo "[+] Installation Prefix:         ${INSTALL_DIR}"

CURL_CA=()
WGET_CA=()
http_get() {
    if command -v curl > /dev/null 2>&1; then curl -fsSL "${CURL_CA[@]}" "$1" -o "$2"; else wget -q "${WGET_CA[@]}" "$1" -O "$2"; fi
}

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
        useradd -r -g ${GROUP} -d ${INSTALL_DIR} -s ${SHELL} -c "ProVigil Endpoint Agent" ${USER}
    elif command -v adduser > /dev/null 2>&1; then
        adduser --system --home ${INSTALL_DIR} --shell ${SHELL} --ingroup ${GROUP} ${USER}
    fi
fi

mkdir -p "${INSTALL_DIR}/bin"
mkdir -p "${INSTALL_DIR}/etc"
mkdir -p "${INSTALL_DIR}/logs"
mkdir -p "${INSTALL_DIR}/queue"
mkdir -p "${INSTALL_DIR}/quarantine"
mkdir -p "${INSTALL_DIR}/ruleset/sca"
mkdir -p "${INSTALL_DIR}/var/run"

CA_FILE=""
if [ -n "${CA_SOURCE}" ]; then
    CA_FILE="${INSTALL_DIR}/etc/ca.pem"
    if [ "${CA_SOURCE}" != "${CA_FILE}" ]; then
        cp "${CA_SOURCE}" "${CA_FILE}"
    fi
    chmod 644 "${CA_FILE}"
    export SIEM_CA_FILE="${CA_FILE}"
    CURL_CA=(--cacert "${CA_FILE}")
    WGET_CA=(--ca-certificate="${CA_FILE}")
elif [ -s "${INSTALL_DIR}/etc/ca.pem" ]; then
    CA_FILE="${INSTALL_DIR}/etc/ca.pem"
    export SIEM_CA_FILE="${CA_FILE}"
    CURL_CA=(--cacert "${CA_FILE}")
    WGET_CA=(--ca-certificate="${CA_FILE}")
fi

case "${DIST_NAME}" in
    ubuntu)
        case "${DIST_VER}" in
            24.*) SCA_POLICY="cis_ubuntu24-04.yml" ;;
            20.*) SCA_POLICY="cis_ubuntu20-04.yml" ;;
            18.*) SCA_POLICY="cis_ubuntu18-04.yml" ;;
            *)    SCA_POLICY="cis_ubuntu22-04.yml" ;;
        esac
        ;;
    debian)
        case "${DIST_VER}" in
            11*) SCA_POLICY="cis_debian11.yml" ;;
            10*) SCA_POLICY="cis_debian10.yml" ;;
            *)   SCA_POLICY="cis_debian12.yml" ;;
        esac
        ;;
    rhel|centos|rocky|almalinux)
        case "${DIST_VER}" in
            9*) SCA_POLICY="cis_rhel9_linux.yml" ;;
            7*) SCA_POLICY="cis_rhel7_linux.yml" ;;
            *)  SCA_POLICY="cis_rhel8_linux.yml" ;;
        esac
        ;;
    *)
        SCA_POLICY="cis_ubuntu22-04.yml"
        ;;
esac

if http_get "${MANAGER_URL}/downloads/sca/${SCA_POLICY}" "${INSTALL_DIR}/ruleset/sca/${SCA_POLICY}" 2>/dev/null && [ -s "${INSTALL_DIR}/ruleset/sca/${SCA_POLICY}" ]; then
    echo "[+] Downloaded CIS Benchmark policy: ${SCA_POLICY}"
    mkdir -p "${INSTALL_DIR}/sca"
    cp -f "${INSTALL_DIR}/ruleset/sca/${SCA_POLICY}" "${INSTALL_DIR}/sca/$(basename "${SCA_POLICY}")" 2>/dev/null || true
fi

mkdir -p "${INSTALL_DIR}/active-response/bin" "${INSTALL_DIR}/bookmarks" "${INSTALL_DIR}/data" "${INSTALL_DIR}/upgrade" "${INSTALL_DIR}/sca"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BINARY_CANDIDATES=(
    "${SCRIPT_DIR}/../../target/release/provigil-agent"
    "${SCRIPT_DIR}/../../target/debug/provigil-agent"
    "${SCRIPT_DIR}/provigil-agent-linux"
    "./provigil-agent-linux"
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

TARGET_BIN="${INSTALL_DIR}/bin/provigil-agent-linux"
if [ -n "${BINARY_FOUND}" ]; then
    echo "[+] Installing binary from '${BINARY_FOUND}'..."
    cp "${BINARY_FOUND}" "${TARGET_BIN}"
elif http_get "${MANAGER_URL}/downloads/provigil-agent-linux" "${TARGET_BIN}.new" 2>/dev/null \
     && [ -s "${TARGET_BIN}.new" ]; then
    echo "[+] Downloaded unified agent binary from ${MANAGER_URL}/downloads/provigil-agent-linux"
    mv -f "${TARGET_BIN}.new" "${TARGET_BIN}"
elif http_get "${MANAGER_URL}/downloads/siem-agent-linux" "${TARGET_BIN}.new" 2>/dev/null \
     && [ -s "${TARGET_BIN}.new" ]; then
    echo "[+] Downloaded legacy agent binary from ${MANAGER_URL}/downloads/siem-agent-linux"
    mv -f "${TARGET_BIN}.new" "${TARGET_BIN}"
elif command -v cargo > /dev/null 2>&1; then
    rm -f "${TARGET_BIN}.new"
    echo "[+] Compiling unified provigil-agent in release mode..."
    cargo build --release --package provigil-agent --manifest-path "${SCRIPT_DIR}/../../Cargo.toml"
    cp "${SCRIPT_DIR}/../../target/release/provigil-agent" "${TARGET_BIN}"
else
    echo "[-] Error: agent binary not found and compiler is not present."
    exit 1
fi

chmod 750 "${TARGET_BIN}"
ln -sf "${TARGET_BIN}" "${INSTALL_DIR}/bin/siem-agent-linux"
ln -sf "${TARGET_BIN}" /usr/local/bin/provigil-agent
ln -sf "${TARGET_BIN}" /usr/local/bin/provigil-agentd
ln -sf "${TARGET_BIN}" /usr/local/bin/provigil-control

cat <<EOF > "${INSTALL_DIR}/etc/agent.conf"
<agent_config>
  <client>
    <server>
      <address>${MANAGER_HOST}</address>
      <port>${MANAGER_PORT}</port>
      <protocol>tcp</protocol>
    </server>
    <config-profile>${DIST_NAME}</config-profile>
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
</agent_config>
EOF

KEYS_FILE="${INSTALL_DIR}/etc/client.keys"
if [ -s "${KEYS_FILE}" ] && ! grep -q "a1b2c3d4e5f67890123456789abcdef0" "${KEYS_FILE}"; then
    OLD_NAME=$(head -1 "${KEYS_FILE}" | cut -d' ' -f2)
    AGENT_NAME=${OLD_NAME:-${AGENT_NAME}}
fi
# an enrolled agent's key and settings, put back when this enrollment is refused: a refused
# reinstall must not break an agent that works
KEPT=""
if [ -s "${KEYS_FILE}" ]; then
    KEPT="$(mktemp -d)"
    for f in "${KEYS_FILE}" "${INSTALL_DIR}/etc/agent-config.json" "${INSTALL_DIR}/etc/agent.env"; do [ -f "$f" ] && cp -p "$f" "${KEPT}/"; done
fi
rm -f "${KEYS_FILE}" "${INSTALL_DIR}/.decommissioned" "${INSTALL_DIR}/client.keys.deleted" "${INSTALL_DIR}/etc/.decommissioned" "${INSTALL_DIR}/etc/client.keys.deleted" /etc/provigil-agent/.decommissioned /etc/provigil-agent/client.keys.deleted
BODY="{\"name\":\"${AGENT_NAME}\",\"groups\":\"${AGENT_GROUP}\",\"os_type\":\"linux\",\"force\":true}"
RESP=""
if command -v curl > /dev/null 2>&1; then
    RESP=$(curl -sS "${CURL_CA[@]}" -X POST "${MANAGER_URL}/api/v1/agents/enroll" \
        -H "Content-Type: application/json" ${TENANT_KEY:+-H "X-Tenant-Key: ${TENANT_KEY}"} \
        -d "${BODY}" 2>/dev/null || true)
else
    RESP=$(wget -qO- --content-on-error "${WGET_CA[@]}" --header="Content-Type: application/json" ${TENANT_KEY:+--header="X-Tenant-Key: ${TENANT_KEY}"} \
        --post-data="${BODY}" "${MANAGER_URL}/api/v1/agents/enroll" 2>/dev/null || true)
fi
NEW_ID=$(printf '%s' "${RESP}" | sed -n 's/.*"agent_id"[ ]*:[ ]*"\([^"]*\)".*/\1/p')
NEW_NAME=$(printf '%s' "${RESP}" | sed -n 's/.*"agent_name"[ ]*:[ ]*"\([^"]*\)".*/\1/p')
NEW_KEY=$(printf '%s' "${RESP}" | sed -n 's/.*"raw_key"[ ]*:[ ]*"\([^"]*\)".*/\1/p')
NEW_TENANT=$(printf '%s' "${RESP}" | sed -n 's/.*"tenant_id"[ ]*:[ ]*"\([^"]*\)".*/\1/p')
if [ -n "${NEW_ID}" ] && [ -n "${NEW_KEY}" ]; then
    echo "${NEW_ID} ${NEW_NAME:-${AGENT_NAME}} any ${NEW_KEY}" > "${KEYS_FILE}"
    echo "[+] Enrolled as agent ${NEW_ID} (${NEW_NAME:-${AGENT_NAME}}) in tenant '${NEW_TENANT}'"
else
    echo "[-] Enrollment failed or did not return a valid key; the agent will enroll itself when it starts. Response: ${RESP}"
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
cp -f "${INSTALL_DIR}/etc/agent-config.json" "${INSTALL_DIR}/agent-config.json" 2>/dev/null || true
mkdir -p /etc/provigil-agent 2>/dev/null || true
cp -f "${INSTALL_DIR}/etc/agent-config.json" /etc/provigil-agent/agent-config.json 2>/dev/null || true

CA_JSON="null"
if [ -n "${CA_FILE:-}" ] && [ -s "${CA_FILE}" ]; then
    CA_JSON="\"${CA_FILE}\""
fi
cat <<EOF > "${INSTALL_DIR}/etc/provigil-agent.json"
{
  "manager_url": "${MANAGER_URL}",
  "manager_urls": [
    "${MANAGER_URL}",
    "https://192.168.56.1:8443",
    "https://10.0.2.2:8443"
  ],
  "tenant_key": "${TENANT_KEY}",
  "agent_name": "${AGENT_NAME}",
  "groups": "${AGENT_GROUP}",
  "ca_file": ${CA_JSON},
  "fresh_install": true,
  "fim_realtime": [
    "/etc",
    "/usr/local/bin",
    "/lib/systemd/system"
  ],
  "localfiles": [
    {"location": "/var/log/auth.log"},
    {"location": "/var/log/secure"},
    {"location": "/var/log/syslog"},
    {"location": "/var/log/messages"}
  ]
}
EOF
cp -f "${INSTALL_DIR}/etc/provigil-agent.json" "${INSTALL_DIR}/provigil-agent.json" 2>/dev/null || true
cp -f "${INSTALL_DIR}/etc/provigil-agent.json" /etc/provigil-agent/provigil-agent.json 2>/dev/null || true
chmod 600 "${INSTALL_DIR}/etc/provigil-agent.json" "${INSTALL_DIR}/provigil-agent.json" /etc/provigil-agent/provigil-agent.json 2>/dev/null || true

cat <<EOF > "${INSTALL_DIR}/etc/agent.env"
SIEM_MANAGER_URL="${MANAGER_URL}"
SIEM_AGENT_NAME="${AGENT_NAME}"
SIEM_AGENT_GROUP="${AGENT_GROUP}"
SIEM_TENANT_KEY="${TENANT_KEY}"
SIEM_CA_FILE="${CA_FILE}"
EOF

if [ -z "${NEW_ID}" ] && [ -n "${KEPT}" ]; then
    for f in "${KEPT}"/*; do
        case "$(basename "$f")" in client.keys) cp -p "$f" "${KEYS_FILE}" ;; *) cp -p "$f" "${INSTALL_DIR}/etc/" ;; esac
    done
    cp -f "${INSTALL_DIR}/etc/agent-config.json" "${INSTALL_DIR}/agent-config.json" 2>/dev/null || true
    cp -f "${INSTALL_DIR}/etc/agent-config.json" /etc/provigil-agent/agent-config.json 2>/dev/null || true
    echo "[!] Enrollment refused: the agent already installed here keeps its enrollment and settings."
fi
[ -n "${KEPT}" ] && rm -rf "${KEPT}"

chown root:${GROUP} "${INSTALL_DIR}"
chmod 750 "${INSTALL_DIR}"
chown -R root:${GROUP} "${INSTALL_DIR}/bin"
chmod 750 "${INSTALL_DIR}/bin"
chown root:${GROUP} "${INSTALL_DIR}/etc/agent.conf"
chmod 640 "${INSTALL_DIR}/etc/agent.conf"
if [ -f "${INSTALL_DIR}/etc/client.keys" ]; then
    chown root:${GROUP} "${INSTALL_DIR}/etc/client.keys"
    chmod 640 "${INSTALL_DIR}/etc/client.keys"
    cp -f "${INSTALL_DIR}/etc/client.keys" "${INSTALL_DIR}/client.keys" 2>/dev/null || true
    chown root:${GROUP} "${INSTALL_DIR}/client.keys" 2>/dev/null || true
    chmod 600 "${INSTALL_DIR}/client.keys" 2>/dev/null || true
fi
chown root:${GROUP} "${INSTALL_DIR}/etc/agent-config.json"
chmod 640 "${INSTALL_DIR}/etc/agent-config.json"
chown root:${GROUP} "${INSTALL_DIR}/etc/agent.env"
chmod 600 "${INSTALL_DIR}/etc/agent.env"
chown -R ${USER}:${GROUP} "${INSTALL_DIR}/logs"
chmod 750 "${INSTALL_DIR}/logs"
chown -R ${USER}:${GROUP} "${INSTALL_DIR}/queue"
chmod 750 "${INSTALL_DIR}/queue"
chown -R root:${GROUP} "${INSTALL_DIR}/quarantine"
chmod 700 "${INSTALL_DIR}/quarantine"
chown -R root:${GROUP} "${INSTALL_DIR}/ruleset"
chmod -R 750 "${INSTALL_DIR}/ruleset"

SERVICE_SOURCE="${SCRIPT_DIR}/init/provigil-agent.service"
if [ -d /run/systemd/system ] && command -v systemctl > /dev/null 2>&1; then
    echo "[+] Provisioning systemd daemon (provigil-agent.service)..."
    if [ -f "${SERVICE_SOURCE}" ]; then
        cp "${SERVICE_SOURCE}" /etc/systemd/system/provigil-agent.service
    else
        cat <<EOF > /etc/systemd/system/provigil-agent.service
[Unit]
Description=ProVigil Linux Endpoint Security Agent
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=${INSTALL_DIR}
EnvironmentFile=-${INSTALL_DIR}/etc/agent.env
ExecStart=${INSTALL_DIR}/bin/provigil-agent-linux --run
Restart=always
RestartSec=10
RestartPreventExitStatus=42
KillMode=process
StandardOutput=journal
StandardError=journal
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF
    fi
    systemctl daemon-reload
    systemctl enable provigil-agent.service
    systemctl restart provigil-agent.service
    echo "[+] Service status: ACTIVE & ENABLED"
else
    echo "[i] systemd is not running: starting the agent in the background."
    pkill -f "${INSTALL_DIR}/bin/provigil-agent-linux" 2>/dev/null || true
    pkill -f "${INSTALL_DIR}/bin/siem-agent-linux" 2>/dev/null || true
    ( cd "${INSTALL_DIR}" && nohup "${INSTALL_DIR}/bin/provigil-agent-linux" --run < /dev/null >> "${INSTALL_DIR}/logs/agent.log" 2>&1 & )
    echo "[+] Agent started (log: ${INSTALL_DIR}/logs/agent.log)."
fi

# One line for the mass deployment (provigil-deploy push-linux reads it)
json_s() { printf '%s' "$1" | tr -d '\000-\037"\\' | cut -c1-300; }
if [ -n "${NEW_ID}" ]; then RESULT_OUTCOME="installed"; RESULT_REASON=""; else RESULT_OUTCOME="failed"; RESULT_REASON="enrollment refused: $(json_s "${RESP:-no answer from ${MANAGER_URL}}")${KEPT:+; the agent already installed here was kept}"; fi
echo "PROVIGIL_RESULT {\"computer\":\"$(json_s "$(hostname -s 2>/dev/null || hostname)")\",\"os\":\"$(json_s "${PRETTY_NAME:-${DIST_NAME} ${DIST_VER}}")\",\"agent_name\":\"$(json_s "${NEW_NAME:-${AGENT_NAME}}")\",\"outcome\":\"${RESULT_OUTCOME}\",\"reason\":\"${RESULT_REASON}\",\"agent_id\":\"$(json_s "${NEW_ID}")\"}"

echo "==============================================================="
echo "   ProVigil Linux Agent Installed Successfully!                "
echo "   Control CLI:   provigil-control status-service              "
echo "   Binary Daemon: provigil-agentd                              "
echo "   Logs:          /opt/provigil-agent/logs/                    "
echo "==============================================================="
