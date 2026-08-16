#!/usr/bin/env bash
# ==============================================================================
# Portsentry Defense & Apple-Style WebUI - 极速全自动生产部署脚本 (轻量可靠版)
# 适用系统: Ubuntu, Debian, CentOS, RHEL, Alibaba Cloud Linux, Rocky Linux, Alpine
# ==============================================================================

set -e

# 色彩定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${CYAN}================================================================${NC}"
echo -e "${GREEN}   🍯 Portsentry Apple-Style Honeypot & WebUI 一键极速部署    ${NC}"
echo -e "${CYAN}================================================================${NC}"

# 1. 检查 root 权限
if [ "$(id -u)" -ne 0 ]; then
   echo -e "${RED}[ERROR] 本脚本必须使用 root 权限执行！请使用 sudo bash install.sh${NC}" 
   exit 1
fi

INSTALL_DIR="/opt/portsentry-ui"
RAW_BASE_URL="https://raw.githubusercontent.com/Level6me/portsentry-ui/main"
MIRROR_BASE_URL="https://ghproxy.net/https://raw.githubusercontent.com/Level6me/portsentry-ui/main"

echo -e "\n${BLUE}[1/5] 正在检测并安装底层依赖环境 (Python3, iptables, curl, sqlite)...${NC}"
if command -v apt-get >/dev/null 2>&1; then
    apt-get update -y
    apt-get install -y python3 iptables iproute2 curl sqlite3
elif command -v yum >/dev/null 2>&1; then
    yum install -y python3 iptables iproute curl sqlite
elif command -v dnf >/dev/null 2>&1; then
    dnf install -y python3 iptables iproute curl sqlite
elif command -v apk >/dev/null 2>&1; then
    apk add python3 iptables iproute2 curl sqlite
fi

if ! command -v python3 >/dev/null 2>&1; then
    echo -e "${RED}[ERROR] Python3 安装失败，请手动安装 Python3 后重试！${NC}"
    exit 1
fi
echo -e "${GREEN}[✓] 系统依赖与 Python3 环境就绪 ($(python3 --version))${NC}"

echo -e "\n${BLUE}[2/5] 正在下载并安装核心防御引擎与 Apple WebUI ...${NC}"
mkdir -p "${INSTALL_DIR}"

# 下载函数 (双源重试)
download_file() {
    local filename="$1"
    local dest="${INSTALL_DIR}/${filename}"
    echo -e "  - 正在获取 ${filename} ..."
    if curl -fsSL --connect-timeout 8 "${RAW_BASE_URL}/${filename}" -o "${dest}"; then
        echo -e "    ${GREEN}[✓] 下载成功${NC}"
    elif curl -fsSL --connect-timeout 8 "${MIRROR_BASE_URL}/${filename}" -o "${dest}"; then
        echo -e "    ${GREEN}[✓] 通过镜像加速源下载成功${NC}"
    else
        echo -e "${RED}[ERROR] 下载 ${filename} 失败，请检查服务器公网连接！${NC}"
        exit 1
    fi
}

download_file "web_server.py"
download_file "sentry_daemon.py"
chmod 644 "${INSTALL_DIR}/web_server.py" "${INSTALL_DIR}/sentry_daemon.py"

echo -e "\n${BLUE}[3/5] 正在生成智能防误封白名单与诱饵策略...${NC}"
CURRENT_SSH_IP=$(echo "${SSH_CLIENT:-}" | awk '{print $1}')
if [ -z "${CURRENT_SSH_IP}" ]; then
    CURRENT_SSH_IP=$(echo "${SSH_CONNECTION:-}" | awk '{print $1}')
fi
LOCAL_IP=$(ip route get 1.1.1.1 2>/dev/null | awk '{print $7}' | head -n 1)

if [ ! -f "${INSTALL_DIR}/config.json" ]; then
    cat << EOF > "${INSTALL_DIR}/config.json"
{
  "web_bind": "0.0.0.0",
  "web_port": 9099,
  "whitelist": [
    {"ip": "127.0.0.1", "remark": "本地回环"},
    {"ip": "${CURRENT_SSH_IP:-127.0.0.1}", "remark": "当前部署管理端IP"},
    {"ip": "${LOCAL_IP:-127.0.0.1}", "remark": "本机内网IP"}
  ],
  "trap_ports": [
    {"port": 21, "name": "FTP 弱口令嗅探", "category": "ftp", "enabled": true, "level": "高危"},
    {"port": 135, "name": "RPC 远程端点映射", "category": "smb", "enabled": true, "level": "高危"},
    {"port": 139, "name": "NetBIOS 局域网嗅探", "category": "smb", "enabled": true, "level": "中危"},
    {"port": 445, "name": "SMB / 永恒之蓝高危探针", "category": "smb", "enabled": true, "level": "极高危"},
    {"port": 1433, "name": "MSSQL 数据库嗅探", "category": "db", "enabled": true, "level": "高危"},
    {"port": 3389, "name": "RDP 远程桌面爆破探测", "category": "rdp", "enabled": true, "level": "极高危"},
    {"port": 5900, "name": "VNC 屏幕控制探针", "category": "rdp", "enabled": true, "level": "高危"},
    {"port": 6379, "name": "Redis 未授权访问探针", "category": "db", "enabled": true, "level": "极高危"},
    {"port": 8888, "name": "宝塔/管理面板探测", "category": "web", "enabled": true, "level": "高危"},
    {"port": 9200, "name": "Elasticsearch RCE 探测", "category": "db", "enabled": true, "level": "高危"},
    {"port": 27017, "name": "MongoDB 未授权探针", "category": "db", "enabled": true, "level": "高危"}
  ],
  "ban_action_iptables": true,
  "ban_action_blackhole": true
}
EOF
    echo -e "${GREEN}[✓] 已自动将当前管理 IP (${CURRENT_SSH_IP}) 加入防误封白名单！${NC}"
else
    echo -e "${YELLOW}[!] 检测到已存在配置文件，保留现有配置与规则。${NC}"
fi

echo -e "\n${BLUE}[4/5] 正在注册并启动 Systemd 守护进程...${NC}"
PYTHON_BIN=$(command -v python3)
cat << EOF > /etc/systemd/system/portsentry-ui.service
[Unit]
Description=Portsentry Honeypot & Apple WebUI Defense System
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=${INSTALL_DIR}
ExecStart=${PYTHON_BIN} ${INSTALL_DIR}/web_server.py
Restart=always
RestartSec=3
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable portsentry-ui.service
systemctl restart portsentry-ui.service
sleep 2

echo -e "\n${BLUE}[5/5] 正在核验服务运行状态...${NC}"
if systemctl is-active --quiet portsentry-ui.service; then
    echo -e "${GREEN}[✓] Portsentry-UI 服务已成功启动且运行正常！${NC}"
else
    echo -e "${RED}[ERROR] 服务启动异常，请使用 journalctl -u portsentry-ui.service -n 20 查看错误日志。${NC}"
    exit 1
fi

PUBLIC_IP=$(curl -s --connect-timeout 3 ifconfig.me || curl -s --connect-timeout 3 icanhazip.com || echo "YOUR_SERVER_IP")

echo -e "\n${CYAN}================================================================${NC}"
echo -e "${GREEN}🎉 Portsentry 苹果原生风格安全控制台部署成功！${NC}"
echo -e "${CYAN}================================================================${NC}"
echo -e "🌐 Web 控制台访问入口: ${YELLOW}http://${PUBLIC_IP}:9099${NC}"
echo -e "📁 安装运行目录:       ${BLUE}${INSTALL_DIR}${NC}"
echo -e "⚙️ 配置文件路径:       ${BLUE}${INSTALL_DIR}/config.json${NC}"
echo -e "📊 数据库文件:         ${BLUE}${INSTALL_DIR}/data.db${NC}"
echo -e "----------------------------------------------------------------"
echo -e "💡 常用维护命令:"
echo -e "  查看服务状态: ${CYAN}systemctl status portsentry-ui.service${NC}"
echo -e "  重启防御服务: ${CYAN}systemctl restart portsentry-ui.service${NC}"
echo -e "  查看拦截日志: ${CYAN}journalctl -u portsentry-ui.service -f${NC}"
echo -e "${CYAN}================================================================${NC}\n"
