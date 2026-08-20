#!/bin/bash
set -e

echo "[+] 正在安装部署 PortGuard 安全系统..."
mkdir -p /opt/portguard

# 创建 systemd 单元
cat << 'EOF' > /etc/systemd/system/portguard.service
[Unit]
Description=PortGuard Honeypot & WebUI Defense System
After=network.target network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/portguard
ExecStart=/usr/bin/python3 /opt/portguard/web_server.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable portguard.service
systemctl restart portguard.service

echo "[+] PortGuard 服务已成功启动！"
systemctl status portguard.service --no-pager
