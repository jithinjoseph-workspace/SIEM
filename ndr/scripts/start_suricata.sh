#!/bin/bash
# start_suricata.sh — Starts Suricata on the selected interface
# Reads selection from the installer runtime file

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
INSTALL_DIR=$(cd "$SCRIPT_DIR/.." && pwd)
IFACE_FILE="$INSTALL_DIR/.runtime/ndr_interface"
SENSOR_IP_FILE="$INSTALL_DIR/.runtime/ndr_sensor_ip"
IFACE=$(cat "$IFACE_FILE" 2>/dev/null || echo "eth0")
SENSOR_IP=$(cat "$SENSOR_IP_FILE" 2>/dev/null || "")

# Ensure sensor IP is suppressed in threshold.conf (idempotent)
THRESHOLD_FILE="/etc/suricata/threshold.conf"
if [ -n "$SENSOR_IP" ] && [ -f "$THRESHOLD_FILE" ]; then
  SENSOR_LINE="suppress gen_id 1, sig_id 0, track by_src, ip ${SENSOR_IP}"
  grep -qF "$SENSOR_LINE" "$THRESHOLD_FILE" 2>/dev/null || \
    echo "$SENSOR_LINE" >> "$THRESHOLD_FILE"
fi

echo "Starting Suricata on interface: $IFACE (sensor IP excluded: ${SENSOR_IP:-unknown})"
suricata -c /etc/suricata/suricata.yaml -i $IFACE -l /var/log/ndr/suricata
