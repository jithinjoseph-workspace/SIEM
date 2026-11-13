#!/bin/sh
# ProVigil Linux Agent - RPM pre-uninstall script
if [ "$1" = "0" ]; then
    if [ -d /run/systemd/system ]; then
        systemctl stop provigil-agent.service > /dev/null 2>&1 || true
        systemctl disable provigil-agent.service > /dev/null 2>&1 || true
    fi
    rm -f /usr/local/bin/provigil-agentd
    rm -f /usr/local/bin/provigil-control
fi
exit 0
