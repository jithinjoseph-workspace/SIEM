#!/bin/sh
# ProVigil Linux Agent - RPM post-install script
DIR="/opt/provigil-agent"

mkdir -p "${DIR}/bin" "${DIR}/etc" "${DIR}/logs" "${DIR}/queue" "${DIR}/quarantine"

if [ ! -f "${DIR}/etc/agent-config.json" ]; then
    cat <<EOF > "${DIR}/etc/agent-config.json"
{
  "manager_url": "https://127.0.0.1:8443",
  "agent_name": "provigil-rhel-endpoint",
  "buffer_capacity": 5000,
  "events_per_second": 500
}
EOF
    chmod 640 "${DIR}/etc/agent-config.json"
    chown root:provigil "${DIR}/etc/agent-config.json"
fi

chown root:provigil "${DIR}"
chmod 750 "${DIR}"
chown -R root:provigil "${DIR}/bin"
chmod 750 "${DIR}/bin"
chmod 750 "${DIR}/bin/siem-agent-linux"
chown -R provigil:provigil "${DIR}/logs" "${DIR}/queue"
chmod 750 "${DIR}/logs" "${DIR}/queue"
chown -R root:provigil "${DIR}/quarantine"
chmod 700 "${DIR}/quarantine"

ln -sf "${DIR}/bin/siem-agent-linux" /usr/local/bin/provigil-agentd
ln -sf "${DIR}/bin/siem-agent-linux" /usr/local/bin/provigil-control

if [ -d /run/systemd/system ]; then
    systemctl daemon-reload > /dev/null 2>&1 || true
    systemctl enable provigil-agent.service > /dev/null 2>&1 || true
    systemctl restart provigil-agent.service > /dev/null 2>&1 || true
fi
exit 0
