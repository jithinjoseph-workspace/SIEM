#!/bin/sh
# ==============================================================================
# Wazuh Linux Agent - RPM post-uninstall script
# ==============================================================================
if [ -d /run/systemd/system ]; then
    systemctl daemon-reload > /dev/null 2>&1 || true
fi
exit 0
