#!/bin/bash
# start_zeek.sh — Starts Zeek on the selected interface
# Reads selection from the installer runtime file

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
INSTALL_DIR=$(cd "$SCRIPT_DIR/.." && pwd)
IFACE_FILE="$INSTALL_DIR/.runtime/ndr_interface"
IFACE=$(cat "$IFACE_FILE" 2>/dev/null || echo "eth0")

echo "Starting Zeek on interface: $IFACE"
# Note: Ensure /opt/zeek/bin/zeek exists or update the path
/opt/zeek/bin/zeek -i $IFACE local Log::default_logdir=/home/jithin/logs/zeek
