#!/bin/sh
# ==============================================================================
# Wazuh Linux Agent - RPM post-install script
# ==============================================================================
DIR="/var/ossec"

mkdir -p "${DIR}/bin" "${DIR}/etc" "${DIR}/logs" "${DIR}/queue" "${DIR}/quarantine"

if [ ! -f "${DIR}/etc/agent-config.json" ]; then
    cat <<EOF > "${DIR}/etc/agent-config.json"
{
  "manager_url": "http://127.0.0.1:8088",
  "agent_id": "002",
  "agent_name": "wazuh-rhel-endpoint",
  "buffer_capacity": 5000,
  "events_per_second": 500
}
EOF
    chmod 640 "${DIR}/etc/agent-config.json"
    chown root:wazuh "${DIR}/etc/agent-config.json"
fi

chown root:wazuh "${DIR}"
chmod 750 "${DIR}"
chown -R root:wazuh "${DIR}/bin"
chmod 750 "${DIR}/bin"
chmod 750 "${DIR}/bin/siem-agent-linux"
chown -R wazuh:wazuh "${DIR}/logs" "${DIR}/queue"
chmod 750 "${DIR}/logs" "${DIR}/queue"
chown -R root:wazuh "${DIR}/quarantine"
chmod 700 "${DIR}/quarantine"

ln -sf "${DIR}/bin/siem-agent-linux" /usr/local/bin/wazuh-agentd
ln -sf "${DIR}/bin/siem-agent-linux" /usr/local/bin/wazuh-control

if [ -d /run/systemd/system ]; then
    systemctl daemon-reload > /dev/null 2>&1 || true
    systemctl enable wazuh-rust-agent.service > /dev/null 2>&1 || true
    systemctl restart wazuh-rust-agent.service > /dev/null 2>&1 || true
fi
exit 0
