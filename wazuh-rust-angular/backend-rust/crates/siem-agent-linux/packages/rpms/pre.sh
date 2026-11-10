#!/bin/sh
# ==============================================================================
# Wazuh Linux Agent - RPM pre-install script
# ==============================================================================
if ! getent group wazuh >/dev/null 2>&1; then
    groupadd -r wazuh >/dev/null 2>&1 || true
fi
if ! getent passwd wazuh >/dev/null 2>&1; then
    useradd -r -g wazuh -d /var/ossec -s /sbin/nologin -c "Wazuh Agent" wazuh >/dev/null 2>&1 || true
fi
exit 0
