#!/bin/bash
INSTALL_DIR=$(cd "$(dirname "$0")/.." && pwd)
USERNAME=$(whoami)

sudo tee /etc/systemd/system/ndr-autoscaler.service > /dev/null << SERVICE
[Unit]
Description=NDR Auto-Scaler
After=docker.service ndr-agent.service

[Service]
Type=simple
User=$USERNAME
ExecStart=/bin/bash $INSTALL_DIR/scripts/autoscale.sh
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
SERVICE

sudo systemctl daemon-reload
sudo systemctl enable ndr-autoscaler
sudo systemctl start ndr-autoscaler
echo "✅ Auto-scaler installed and started"
echo "📊 View logs: tail -f /tmp/ndr-autoscale.log"
