#!/bin/sh
# ==============================================================================
# Wazuh Linux Agent - RPM pre-uninstall script
# ==============================================================================
if [ "$1" = "0" ]; then
    # Full package removal
    if [ -d /run/systemd/system ]; then
        systemctl stop wazuh-rust-agent.service > /dev/null 2>&1 || true
        systemctl disable wazuh-rust-agent.service > /dev/null 2>&1 || true
    fi
    rm -f /usr/local/bin/wazuh-agentd
    rm -f /usr/local/bin/wazuh-control
fi
exit 0
