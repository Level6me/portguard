#!/usr/bin/env python3
import os
import base64
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

with open(os.path.join(BASE_DIR, 'web_server.py'), 'rb') as f:
    web_b64 = base64.b64encode(f.read()).decode('utf-8')

with open(os.path.join(BASE_DIR, 'sentry_daemon.py'), 'rb') as f:
    daemon_b64 = base64.b64encode(f.read()).decode('utf-8')

with open(os.path.join(BASE_DIR, 'uninstall.sh'), 'rb') as f:
    uninstall_b64 = base64.b64encode(f.read()).decode('utf-8')

with open(os.path.join(BASE_DIR, 'update.sh'), 'rb') as f:
    update_b64 = base64.b64encode(f.read()).decode('utf-8')

with open(os.path.join(BASE_DIR, 'chart.min.js'), 'rb') as f:
    chart_b64 = base64.b64encode(f.read()).decode('utf-8')

template = r'''#!/usr/bin/env bash
# ==============================================================================
# PortGuard Defense & WebUI - 独立自包含一行一键生产部署与更新脚本
# 适用系统: Ubuntu 18+, Debian 10+, CentOS 7/8/9, RHEL, Alibaba Cloud Linux, Rocky
# ==============================================================================

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

IS_UPDATE=false
for arg in "$@"; do
    if [[ "$arg" == "update" || "$arg" == "--update" || "$arg" == "-u" ]]; then
        IS_UPDATE=true
    fi
done

if [ "$IS_UPDATE" = true ]; then
    echo -e "${CYAN}================================================================${NC}"
    echo -e "${GREEN}      🔄 PortGuard 智能主动诱捕防御系统 一键平滑更新          ${NC}"
    echo -e "${CYAN}================================================================${NC}"
else
    echo -e "${CYAN}================================================================${NC}"
    echo -e "${GREEN}      🛡️ PortGuard 智能主动诱捕防御系统 一键极速部署          ${NC}"
    echo -e "${CYAN}================================================================${NC}"
fi

if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}[ERROR] 本脚本必须使用 root 权限执行！请使用 sudo bash install.sh${NC}" 
   exit 1
fi

INSTALL_DIR="/opt/portguard"
OLD_INSTALL_DIR="/opt/portsentry-ui"

echo -e "\n${BLUE}[1/5] 正在检测并安装底层依赖环境 (Python3, iptables, ipset, sqlite3)...${NC}"
if command -v apt-get >/dev/null 2>&1; then
    apt-get update -y
    apt-get install -y python3 iptables ipset iproute2 curl sqlite3
elif command -v yum >/dev/null 2>&1; then
    yum install -y python3 iptables ipset iproute curl sqlite
elif command -v dnf >/dev/null 2>&1; then
    dnf install -y python3 iptables ipset iproute curl sqlite
fi

if ! command -v python3 >/dev/null 2>&1; then
    echo -e "${RED}[ERROR] Python3 安装失败，请手动安装后重试！${NC}"
    exit 1
fi
echo -e "${GREEN}[✓] 系统依赖与 Python3 环境就绪 ($(python3 --version))${NC}"

# 如果存在旧版本，平滑迁移配置和数据库
if [ -d "${OLD_INSTALL_DIR}" ] && [ ! -d "${INSTALL_DIR}" ]; then
    echo -e "${YELLOW}[!] 检测到历史版本数据，正在平滑迁移至 ${INSTALL_DIR} ...${NC}"
    mkdir -p "${INSTALL_DIR}"
    if [ -f "${OLD_INSTALL_DIR}/config.json" ]; then
        cp -a "${OLD_INSTALL_DIR}/config.json" "${INSTALL_DIR}/config.json"
    fi
    if [ -f "${OLD_INSTALL_DIR}/data.db" ]; then
        cp -a "${OLD_INSTALL_DIR}/data.db" "${INSTALL_DIR}/data.db"
    fi
    systemctl stop portsentry-ui.service 2>/dev/null || true
    systemctl disable portsentry-ui.service 2>/dev/null || true
    rm -f /etc/systemd/system/portsentry-ui.service 2>/dev/null || true
    echo -e "${GREEN}[✓] 历史配置与审计数据库已无缝平滑迁移！${NC}"
fi

echo -e "\n${BLUE}[2/5] 正在释放核心防御模块至 ${INSTALL_DIR} ...${NC}"
mkdir -p "${INSTALL_DIR}"

# 释放 web_server.py
echo "__WEB_B64__" | base64 -d > "${INSTALL_DIR}/web_server.py"
chmod 644 "${INSTALL_DIR}/web_server.py"

# 释放 sentry_daemon.py
echo "__DAEMON_B64__" | base64 -d > "${INSTALL_DIR}/sentry_daemon.py"
chmod 644 "${INSTALL_DIR}/sentry_daemon.py"

# 释放 uninstall.sh
echo "__UNINSTALL_B64__" | base64 -d > "${INSTALL_DIR}/uninstall.sh"
chmod 755 "${INSTALL_DIR}/uninstall.sh"

# 释放 update.sh
echo "__UPDATE_B64__" | base64 -d > "${INSTALL_DIR}/update.sh"
chmod 755 "${INSTALL_DIR}/update.sh"

# 释放 chart.min.js（本地化 Chart.js，避免 CDN 依赖）
echo "__CHART_B64__" | base64 -d > "${INSTALL_DIR}/chart.min.js"
chmod 644 "${INSTALL_DIR}/chart.min.js"

echo -e "${GREEN}[✓] 核心代码、更新模块与卸载工具已成功解包并写入完毕！${NC}"

echo -e "\n${BLUE}[3/5] 正在生成智能防误封白名单与诱饵策略...${NC}"
# 多途径精准提取当前管理员公网 IP (兼容 sudo / su / 普通用户 / 各种云环境)
CURRENT_SSH_IP=""
if [[ -z "${CURRENT_SSH_IP}" ]]; then
    CURRENT_SSH_IP=$(who -m 2>/dev/null | awk '{print $NF}' | tr -d '()' | awk -F: '{print $1}')
fi
if [[ -z "${CURRENT_SSH_IP}" || "${CURRENT_SSH_IP}" == "localhost" ]]; then
    CURRENT_SSH_IP=$(who am i 2>/dev/null | awk '{print $NF}' | tr -d '()' | awk -F: '{print $1}')
fi
if [[ -z "${CURRENT_SSH_IP}" && -n "${SUDO_USER}" ]]; then
    CURRENT_SSH_IP=$(grep -z "SSH_CLIENT=" /proc/$PPID/environ 2>/dev/null | tr '\0' '\n' | grep "^SSH_CLIENT=" | cut -d= -f2 | awk '{print $1}')
fi
if [[ -z "${CURRENT_SSH_IP}" ]]; then
    CURRENT_SSH_IP=$(echo "${SSH_CLIENT:-${SSH_CONNECTION:-}}" | awk '{print $1}')
fi
if [[ -z "${CURRENT_SSH_IP}" ]] && command -v ss >/dev/null 2>&1; then
    CURRENT_SSH_IP=$(ss -tn state established '( sport = :22 or sport = :29675 )' 2>/dev/null | awk 'NR>1 {print $4}' | awk -F: '{print $(NF-1)}' | grep -v '^127\.' | head -n 1)
fi

LOCAL_IP=$(ip route get 1.1.1.1 2>/dev/null | awk '{print $7}' | head -n 1)
LOCAL_IP=${LOCAL_IP:-127.0.0.1}

if [[ ! -f "${INSTALL_DIR}/config.json" ]]; then
    cat << EOF > "${INSTALL_DIR}/config.json"
{
  "web_bind": "0.0.0.0",
  "web_port": 9099,
  "whitelist": [
    {"ip": "127.0.0.1", "remark": "本地回环"},
    {"ip": "::1", "remark": "IPv6 本地回环"},
    {"ip": "10.0.0.0/8", "remark": "私网 A 类地址"},
    {"ip": "172.16.0.0/12", "remark": "私网 B 类地址"},
    {"ip": "192.168.0.0/16", "remark": "私网 C 类地址"},
    {"ip": "100.64.0.0/10", "remark": "运营商 CGNAT / 云专网"},
    {"ip": "${CURRENT_SSH_IP:-127.0.0.1}", "remark": "当前部署管理端IP"}
  ],
  "trap_ports": [
    {"port": 21, "name": "FTP 弱口令嗅探", "category": "ftp", "enabled": true, "level": "高危"},
    {"port": 23, "name": "Telnet 弱口令嗅探", "category": "telnet", "enabled": true, "level": "高危"},
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
  "defense_mode": "standard",
  "enable_port_scan_defense": true,
  "port_scan_threshold": 3,
  "port_scan_window_seconds": 15,
  "ban_action_iptables": true,
  "ban_action_blackhole": true,
  "trap_threshold": 2,
  "trap_window_seconds": 30,
  "trap_all_ports": false,
  "trap_all_unopened_ports": false,
  "trap_business_ports": false,
  "defense_paused": false,
  "auto_clean_days": 30
}
EOF
    if [[ -n "${CURRENT_SSH_IP}" && "${CURRENT_SSH_IP}" != "127.0.0.1" ]]; then
        echo -e "${GREEN}[✓] 已成功探测并自动将当前运维 IP (${CURRENT_SSH_IP}) 加入安全白名单！${NC}"
    else
        echo -e "${GREEN}[✓] 智能防误封白名单已初始化（SSH 端口与 Web 管理端口已启用内核级硬编码保护）${NC}"
    fi
else
    echo -e "${YELLOW}[!] 检测到已存在配置文件，保留现有配置 (不覆盖用户策略)。${NC}"
fi

echo -e "\n${BLUE}[4/5] 正在注册并启动 Systemd 守护进程...${NC}"
PYTHON_BIN=$(command -v python3)
cat << EOF > /etc/systemd/system/portguard.service
[Unit]
Description=PortGuard Honeypot & WebUI Defense System
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
systemctl enable portguard.service

# 自动释放公网 DNS 与基础设施 IP (1.1.1.1, 8.8.8.8 等)，彻底恢复系统 DNS 与代理联通性
ip route del blackhole 1.1.1.1/32 2>/dev/null || true
ip route del blackhole 8.8.8.8/32 2>/dev/null || true
ip route del blackhole 223.5.5.5/32 2>/dev/null || true
ip route del blackhole 114.114.114.114/32 2>/dev/null || true
iptables -D INPUT -s 1.1.1.1 -j DROP 2>/dev/null || true
iptables -D INPUT -s 8.8.8.8 -j DROP 2>/dev/null || true
iptables -D INPUT -s 223.5.5.5 -j DROP 2>/dev/null || true
iptables -D INPUT -s 114.114.114.114 -j DROP 2>/dev/null || true
if command -v ipset >/dev/null 2>&1; then
    ipset del portguard_blacklist_v4 1.1.1.1 2>/dev/null || true
    ipset del portguard_blacklist_v4 8.8.8.8 2>/dev/null || true
    ipset del portguard_blacklist_v4 223.5.5.5 2>/dev/null || true
    ipset del portguard_blacklist_v4 114.114.114.114 2>/dev/null || true
fi
if [[ -f "${INSTALL_DIR}/data.db" ]] && command -v sqlite3 >/dev/null 2>&1; then
    sqlite3 "${INSTALL_DIR}/data.db" "DELETE FROM blacklist WHERE ip IN ('1.1.1.1','8.8.8.8','223.5.5.5','114.114.114.114','1.0.0.1','8.8.4.4','223.6.6.6','119.29.29.29');" 2>/dev/null || true
fi

systemctl restart portguard.service
sleep 2

echo -e "\n${BLUE}[5/5] 正在核验服务运行状态...${NC}"
if systemctl is-active --quiet portguard.service; then
    if [ "$IS_UPDATE" = true ]; then
        echo -e "${GREEN}[✓] PortGuard 服务已成功平滑更新且运行正常！${NC}"
    else
        echo -e "${GREEN}[✓] PortGuard 服务已成功启动且运行正常！${NC}"
    fi
else
    echo -e "${RED}[ERROR] 服务启动异常，请使用 journalctl -u portguard.service -n 20 查看错误日志。${NC}"
    exit 1
fi

PUBLIC_IP=$(curl -s --connect-timeout 3 ifconfig.me || curl -s --connect-timeout 3 icanhazip.com || echo "YOUR_SERVER_IP")

echo -e "\n${CYAN}================================================================${NC}"
if [ "$IS_UPDATE" = true ]; then
    echo -e "${GREEN}🎉 PortGuard 智能主动诱捕防御控制台更新完成！${NC}"
else
    echo -e "${GREEN}🎉 PortGuard 智能主动诱捕防御控制台部署成功！${NC}"
fi
echo -e "${CYAN}================================================================${NC}"
echo -e "🌐 Web 控制台访问入口: ${YELLOW}http://${PUBLIC_IP}:9099${NC}"
echo -e "📁 安装运行目录:       ${BLUE}${INSTALL_DIR}${NC}"
echo -e "⚙️ 配置文件路径:       ${BLUE}${INSTALL_DIR}/config.json${NC}"
echo -e "📊 数据库文件:         ${BLUE}${INSTALL_DIR}/data.db${NC}"
echo -e "----------------------------------------------------------------"
echo -e "💡 常用维护命令:"
echo -e "  查看服务状态: ${CYAN}systemctl status portguard.service${NC}"
echo -e "  重启防御服务: ${CYAN}systemctl restart portguard.service${NC}"
echo -e "  查看拦截日志: ${CYAN}journalctl -u portguard.service -f${NC}"
echo -e "  一键平滑更新: ${GREEN}curl -fsSL https://raw.githubusercontent.com/Level6me/portguard/main/update.sh | bash${NC}"
echo -e "  一键完全卸载: ${RED}curl -fsSL https://raw.githubusercontent.com/Level6me/portguard/main/uninstall.sh | bash${NC}"
echo -e "${CYAN}================================================================${NC}\n"
'''

final_content = (template.replace("__WEB_B64__", web_b64)
                 .replace("__DAEMON_B64__", daemon_b64)
                 .replace("__UNINSTALL_B64__", uninstall_b64)
                 .replace("__UPDATE_B64__", update_b64)
                 .replace("__CHART_B64__", chart_b64))

with open(os.path.join(BASE_DIR, 'install.sh'), 'w', encoding='utf-8') as f:
    f.write(final_content)

print('SUCCESS')
