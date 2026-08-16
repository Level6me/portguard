#!/bin/bash
set -e

echo "[+] 正在安装部署 Portsentry-UI 安全系统..."
mkdir -p /opt/portsentry-ui

# 创建 systemd 单元
cat << 'EOF' > /etc/systemd/system/portsentry-ui.service
[Unit]
Description=Portsentry Honeypot & WebUI Defense System
After=network.target network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/portsentry-ui
ExecStart=/usr/bin/python3 /opt/portsentry-ui/web_server.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable portsentry-ui.service
systemctl restart portsentry-ui.service

echo "[+] Portsentry-UI 服务已成功启动！"
systemctl status portsentry-ui.service --no-pager
