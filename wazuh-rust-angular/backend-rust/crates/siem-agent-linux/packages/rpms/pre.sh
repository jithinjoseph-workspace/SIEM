#!/bin/sh
# ProVigil Linux Agent - RPM pre-install script
if ! getent group provigil >/dev/null 2>&1; then
    groupadd -r provigil >/dev/null 2>&1 || true
fi
if ! getent passwd provigil >/dev/null 2>&1; then
    useradd -r -g provigil -d /opt/provigil-agent -s /sbin/nologin -c "ProVigil Agent" provigil >/dev/null 2>&1 || true
fi
exit 0
