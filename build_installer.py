#!/usr/bin/env python3
import os
import base64
import gzip

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

def get_gz_b64(filename):
    path = os.path.join(BASE_DIR, filename)
    with open(path, 'rb') as f:
        compressed = gzip.compress(f.read(), 9)
        return base64.b64encode(compressed).decode('utf-8')

web_b64 = get_gz_b64('web_server.py')
daemon_b64 = get_gz_b64('sentry_daemon.py')
uninstall_b64 = get_gz_b64('uninstall.sh')
update_b64 = get_gz_b64('update.sh')
chart_b64 = get_gz_b64('chart.min.js')

template = r'''#!/usr/bin/env bash
# ==============================================================================
# PortGuard Defense & WebUI - 独立自包含一行一键生产部署与更新脚本 (极致压缩安全强化版)
# 适用系统: Ubuntu 18+, Debian 10+, CentOS 7/8/9, RHEL, AlmaLinux, Rocky, Alpine
# ==============================================================================

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

IS_UPDATE=false
FORCE_YES=false
FORCE_CN=false
FORCE_GLOBAL=false
CUSTOM_BIND=""
CUSTOM_PORT=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        update|--update|-u)
            IS_UPDATE=true
            shift
            ;;
        -y|--yes|--silent|--force)
            FORCE_YES=true
            shift
            ;;
        -b|--bind)
            CUSTOM_BIND="$2"
            shift 2
            ;;
        -p|--port)
            CUSTOM_PORT="$2"
            shift 2
            ;;
        --cn)
            FORCE_CN=true
            shift
            ;;
        --global)
            FORCE_GLOBAL=true
            shift
            ;;
        *)
            shift
            ;;
    esac
done

if [ "$IS_UPDATE" = true ]; then
    echo -e "${CYAN}================================================================${NC}"
    echo -e "${GREEN}      🔄 PortGuard 智能主动诱捕防御系统 一键平滑热更新          ${NC}"
    echo -e "${CYAN}================================================================${NC}"
else
    echo -e "${CYAN}================================================================${NC}"
    echo -e "${GREEN}      🛡️ PortGuard 智能主动诱捕防御系统 一键生产极速部署        ${NC}"
    echo -e "${CYAN}================================================================${NC}"
fi

if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}[ERROR] 本脚本必须使用 root 权限执行！请使用 sudo bash install.sh${NC}" 
   exit 1
fi

INSTALL_DIR="/opt/portguard"
OLD_INSTALL_DIR="/opt/portsentry-ui"

# 智能网络通道测速与镜像选路
GH_PROXY=""
if [ "$FORCE_GLOBAL" = true ]; then
    GH_PROXY=""
    echo -e "${CYAN}[NET] 已指定海外直连通道 (GitHub Official)${NC}"
elif [ "$FORCE_CN" = true ]; then
    GH_PROXY="https://ghproxy.net/"
    echo -e "${CYAN}[NET] 已指定国内加速镜像通道 (ghproxy.net)${NC}"
else
    echo -n "正在测速选择最优更新下载节点... "
    if curl -sSL --connect-timeout 2 "https://raw.githubusercontent.com/Level6me/portguard/main/README.md" >/dev/null 2>&1; then
        GH_PROXY=""
        echo -e "${GREEN}直连官方源畅通${NC}"
    elif curl -sSL --connect-timeout 2 "https://ghproxy.net/https://raw.githubusercontent.com/Level6me/portguard/main/README.md" >/dev/null 2>&1; then
        GH_PROXY="https://ghproxy.net/"
        echo -e "${GREEN}自动优选镜像通道 (ghproxy.net)${NC}"
    elif curl -sSL --connect-timeout 2 "https://gh-proxy.com/https://raw.githubusercontent.com/Level6me/portguard/main/README.md" >/dev/null 2>&1; then
        GH_PROXY="https://gh-proxy.com/"
        echo -e "${GREEN}自动优选备用镜像通道 (gh-proxy.com)${NC}"
    else
        GH_PROXY=""
        echo -e "${YELLOW}直连模式 (带重试)${NC}"
    fi
fi

echo -e "\n${BLUE}[1/6] 正在执行系统环境与安全冲突体检...${NC}"

# 检测操作系统
OS_NAME="Linux"
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS_NAME="${PRETTY_NAME:-$NAME}"
fi

# 安装底层核心依赖
if command -v apt-get >/dev/null 2>&1; then
    apt-get update -y
    apt-get install -y python3 iptables ipset iproute2 curl gzip tar sqlite3
elif command -v yum >/dev/null 2>&1; then
    yum install -y python3 iptables ipset iproute curl gzip tar sqlite
elif command -v dnf >/dev/null 2>&1; then
    dnf install -y python3 iptables ipset iproute curl gzip tar sqlite
elif command -v apk >/dev/null 2>&1; then
    apk add --no-cache python3 iptables ipset iproute2 curl gzip tar sqlite
elif command -v zypper >/dev/null 2>&1; then
    zypper install -y python3 iptables ipset iproute2 curl gzip tar sqlite3
fi

if ! command -v python3 >/dev/null 2>&1; then
    echo -e "${RED}[ERROR] Python3 环境缺失或安装失败，请手动安装 Python 3.7+ 后重试！${NC}"
    exit 1
fi

PY_VER=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}')")

# 内核与特性检测 (ipset / iptables)
IPSET_SUPPORT=true
if ! (ipset create _pg_test hash:ip timeout 1 2>/dev/null && ipset destroy _pg_test 2>/dev/null); then
    IPSET_SUPPORT=false
fi

# 检测默认网关 (防自锁盾)
DEFAULT_GW=""
if [ -f /proc/net/route ]; then
    DEFAULT_GW=$(python3 -c '
import socket, struct
try:
    with open("/proc/net/route") as f:
        for l in f.readlines()[1:]:
            p = l.strip().split()
            if len(p) >= 3 and p[1] == "00000000" and p[2] != "00000000":
                print(socket.inet_ntoa(struct.pack("<L", int(p[2], 16))))
                break
except Exception:
    pass
' 2>/dev/null || true)
fi

# 管理员当前登录 IP 探测
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
    CURRENT_SSH_IP=$(ss -tn state established 2>/dev/null | awk 'NR>1 {print $4}' | awk -F: '{print $(NF-1)}' | grep -v '^127\.' | grep -v '^::' | head -n 1)
fi

# 探测宿主机当前正在活跃监听的业务端口 (LISTEN 状态)
ACTIVE_LISTEN_PORTS=$(python3 -c '
import os
ports = set()
for proc_file in ("/proc/net/tcp", "/proc/net/tcp6"):
    if os.path.exists(proc_file):
        try:
            with open(proc_file) as f:
                for l in f.readlines()[1:]:
                    parts = l.strip().split()
                    if len(parts) >= 4 and parts[3] == "0A":
                        ports.add(int(parts[1].split(":")[-1], 16))
        except Exception:
            pass
sorted_ports = sorted(list(ports))
print(", ".join(str(p) for p in sorted_ports[:12]))
' 2>/dev/null || echo "")

# 探测防火墙状态
FW_INFO="未运行外部防火墙"
if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -qw "active"; then
    FW_INFO="UFW 防火墙 (活跃，将自动联动放行)"
elif command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state 2>/dev/null | grep -qw "running"; then
    FW_INFO="Firewalld 防火墙 (活跃，将自动联动放行)"
fi

# 端口冲突初筛
DEFAULT_WEB_PORT=9099
TARGET_WEB_PORT="${CUSTOM_PORT:-$DEFAULT_WEB_PORT}"
PORT_OCCUPIED_INFO=""
if command -v ss >/dev/null 2>&1; then
    PORT_OCCUPIED_INFO=$(ss -tlnp 2>/dev/null | grep ":${TARGET_WEB_PORT} " || true)
fi

# 打印安全与体检报告面板
echo -e "\n${CYAN}================================================================${NC}"
echo -e "${GREEN}          🛡️ PortGuard 部署前系统环境与安全体检报告            ${NC}"
echo -e "${CYAN}================================================================${NC}"
echo -e " 🖥️  操作系统:       ${GREEN}${OS_NAME}${NC}"
echo -e " 🐍 Python环境:     ${GREEN}${PY_VER}${NC} (符合运行要求)"
if [ "$IPSET_SUPPORT" = true ]; then
    echo -e " ⚡ 防火墙内核特性: ${GREEN}ipset + iptables 高速匹配就绪${NC}"
else
    echo -e " ⚡ 防火墙内核特性: ${YELLOW}ipset受限，将启用内核路由黑洞降级防御${NC}"
fi
echo -e " 🌐 宿主机默认网关: ${GREEN}${DEFAULT_GW:-未知}${NC} (已自动锁定防自锁白名单)"
echo -e " 🛡️  运维管理端IP:   ${GREEN}${CURRENT_SSH_IP:-未识别}${NC} (已加入安全白名单)"
echo -e " 🔍 当前监听端口:   ${BLUE}${ACTIVE_LISTEN_PORTS:-无}${NC} (将自动识别豁免，绝不误封)"
echo -e " 🧱 系统防火墙联动: ${CYAN}${FW_INFO}${NC}"

if [ -n "$PORT_OCCUPIED_INFO" ] && ! echo "$PORT_OCCUPIED_INFO" | grep -q "portguard"; then
    echo -e " ⚠️  端口冲突警告:   ${RED}端口 ${TARGET_WEB_PORT} 已被外部程序占用！${NC}"
    echo -e "    占用详情: ${PORT_OCCUPIED_INFO}"
    if [ -t 0 ] && [ "$FORCE_YES" = false ]; then
        read -r -p "请输入新的 Web 控制台管理端口 (例如 9098，直接回车使用 9098): " USER_NEW_P
        TARGET_WEB_PORT="${USER_NEW_P:-9098}"
        echo -e " ${GREEN}[✓] 已调整管理端口为: ${TARGET_WEB_PORT}${NC}"
    else
        TARGET_WEB_PORT=9098
        echo -e " ${YELLOW}[!] 非交互模式，已自动为您避让切换至端口: 9098${NC}"
    fi
else
    echo -e " 🚪 Web管理端口:    ${GREEN}${TARGET_WEB_PORT} (空闲就绪)${NC}"
fi

echo -e "----------------------------------------------------------------"
echo -e " ⚠️  重要防自锁告知:"
echo -e "  1. 本机已监听的合法业务端口（SSH/Web/1Panel等）将 100% 自动豁免，绝不误封；"
echo -e "  2. 若您使用动态出口IP或代理，避免使用探测工具针对本机发起端口扫描。"
echo -e "${CYAN}================================================================${NC}"

if [ -t 0 ] && [ "$FORCE_YES" = false ] && [ "$IS_UPDATE" = false ]; then
    echo -e "\n系统自检完成，按回车键立即继续，或按 Ctrl+C 退出..."
    read -r -t 6 || true
fi

# 智能选择 Web 监听绑定地址与反代选项
WEB_BIND="0.0.0.0"
if [ -n "$CUSTOM_BIND" ]; then
    WEB_BIND="$CUSTOM_BIND"
    echo -e "\n${BLUE}[2/6] 使用命令行指定的 Web 监听地址: ${GREEN}${WEB_BIND}${NC}"
elif [ -t 0 ] && [ "$FORCE_YES" = false ] && [ "$IS_UPDATE" = false ] && [ ! -f "${INSTALL_DIR}/config.json" ]; then
    echo -e "\n${BLUE}[2/6] 请选择 Web 控制台网络监听与访问模式:${NC}"
    echo -e "  ${GREEN}[1] 0.0.0.0${NC}   - 允许公网直接访问 (适合独立部署、直接通过 http://公网IP:${TARGET_WEB_PORT} 访问)"
    echo -e "  ${GREEN}[2] 127.0.0.1${NC} - 仅监听本地环回 (【强烈推荐】专为 1Panel/Nginx 反代及密码鉴权设计，公网不可探)"
    read -r -p "请输入选项 [1/2] (默认 1): " BIND_CHOICE
    case "$BIND_CHOICE" in
        2|127*)
            WEB_BIND="127.0.0.1"
            echo -e "${GREEN}[✓] 已配置为: 127.0.0.1 (本地反代安全模式)${NC}"
            ;;
        *)
            WEB_BIND="0.0.0.0"
            echo -e "${GREEN}[✓] 已配置为: 0.0.0.0 (公网直连模式)${NC}"
            ;;
    esac
else
    WEB_BIND="${CUSTOM_BIND:-0.0.0.0}"
fi

# 兼容历史路径平滑迁移
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

echo -e "\n${BLUE}[3/6] 正在释放核心防御模块至 ${INSTALL_DIR} (Gzip高速解包)...${NC}"
mkdir -p "${INSTALL_DIR}"

# 释放 web_server.py
echo "__WEB_B64__" | base64 -d | gzip -d > "${INSTALL_DIR}/web_server.py"
chmod 644 "${INSTALL_DIR}/web_server.py"

# 释放 sentry_daemon.py
echo "__DAEMON_B64__" | base64 -d | gzip -d > "${INSTALL_DIR}/sentry_daemon.py"
chmod 644 "${INSTALL_DIR}/sentry_daemon.py"

# 释放 uninstall.sh
echo "__UNINSTALL_B64__" | base64 -d | gzip -d > "${INSTALL_DIR}/uninstall.sh"
chmod 755 "${INSTALL_DIR}/uninstall.sh"

# 释放 update.sh
echo "__UPDATE_B64__" | base64 -d | gzip -d > "${INSTALL_DIR}/update.sh"
chmod 755 "${INSTALL_DIR}/update.sh"

# 释放 chart.min.js
echo "__CHART_B64__" | base64 -d | gzip -d > "${INSTALL_DIR}/chart.min.js"
chmod 644 "${INSTALL_DIR}/chart.min.js"

# 验证核心程序文件解包完整性
if ! python3 -m py_compile "${INSTALL_DIR}/web_server.py" "${INSTALL_DIR}/sentry_daemon.py" >/dev/null 2>&1; then
    echo -e "${RED}[ERROR] 解包的核心 Python 代码校验失败，请检查系统 gzip/base64 支持！${NC}"
    exit 1
fi

echo -e "${GREEN}[✓] 核心代码、更新模块与卸载工具已校验并释放完毕！${NC}"

echo -e "\n${BLUE}[4/6] 正在探测并下载全球完整离线高精度定位数据库 (三库联动)...${NC}"

get_file_size() {
    stat -c%s "$1" 2>/dev/null || stat -f%z "$1" 2>/dev/null || wc -c < "$1" || echo "0"
}

download_db_safe() {
    local url="$1"
    local dest="$2"
    local min_sz="$3"
    local label="$4"
    
    if [ -f "$dest" ] && [ "$(get_file_size "$dest")" -ge "$min_sz" ]; then
        echo -e "${GREEN}[✓] ${label} 已存在且完整，跳过下载${NC}"
        return 0
    fi
    
    echo -e "正在下载 ${label} ..."
    if [ -n "$GH_PROXY" ]; then
        curl -fL --progress-bar --connect-timeout 8 --retry 2 "${GH_PROXY}${url}" -o "$dest" || \
        curl -fL --progress-bar --connect-timeout 8 --retry 2 "${url}" -o "$dest" || true
    else
        curl -fL --progress-bar --connect-timeout 8 --retry 2 "${url}" -o "$dest" || \
        curl -fL --progress-bar --connect-timeout 8 --retry 2 "https://ghproxy.net/${url}" -o "$dest" || true
    fi
    
    if [ -f "$dest" ] && [ "$(get_file_size "$dest")" -ge "$min_sz" ]; then
        chmod 644 "$dest" 2>/dev/null || true
        echo -e "${GREEN}[✓] ${label} 下载并校验成功！${NC}"
        return 0
    else
        echo -e "${YELLOW}[!] ${label} 下载未完成，系统将自动降级运行${NC}"
        return 1
    fi
}

# 1. IP2Region 本地纯内存离线库 (11MB)
download_db_safe "https://raw.githubusercontent.com/Level6me/portguard/main/ip2region.xdb" \
                 "${INSTALL_DIR}/ip2region.xdb" 5000000 "IP2Region 离线高精度数据库" || \
download_db_safe "https://raw.githubusercontent.com/lionsoul2014/ip2region/master/data/ip2region_v4.xdb" \
                 "${INSTALL_DIR}/ip2region.xdb" 5000000 "IP2Region 离线高精度数据库 (备用源)" || true

# 2. MaxMind GeoLite2-ASN 自治系统与运营商库 (12MB)
download_db_safe "https://raw.githubusercontent.com/P3TERX/GeoLite.mmdb/download/GeoLite2-ASN.mmdb" \
                 "${INSTALL_DIR}/GeoLite2-ASN.mmdb" 5000000 "MaxMind GeoLite2-ASN 运营商数据库" || true

# 3. MaxMind GeoLite2-City 全球城市离线高精度库 (65MB)
download_db_safe "https://raw.githubusercontent.com/P3TERX/GeoLite.mmdb/download/GeoLite2-City.mmdb" \
                 "${INSTALL_DIR}/GeoLite2-City.mmdb" 30000000 "MaxMind GeoLite2-City 全球城市定位库" || true

echo -e "\n${BLUE}[5/6] 正在初始化智能防误封白名单与诱捕策略...${NC}"
if [[ ! -f "${INSTALL_DIR}/config.json" ]]; then
    python3 -c "
import json, os

cfg = {
  'web_bind': '${WEB_BIND}',
  'web_port': int('${TARGET_WEB_PORT}'),
  'whitelist': [
    {'ip': '127.0.0.1', 'remark': '本地回环'},
    {'ip': '::1', 'remark': 'IPv6 本地回环'},
    {'ip': '10.0.0.0/8', 'remark': '私网 A 类地址'},
    {'ip': '172.16.0.0/12', 'remark': '私网 B 类地址'},
    {'ip': '192.168.0.0/16', 'remark': '私网 C 类地址'},
    {'ip': '100.64.0.0/10', 'remark': '运营商 CGNAT / 云专网'}
  ],
  'business_ports': [],
  'trap_ports': [
    {'port': 21, 'name': 'FTP 弱口令嗅探', 'category': 'ftp', 'enabled': True, 'level': '高危'},
    {'port': 23, 'name': 'Telnet 弱口令嗅探', 'category': 'telnet', 'enabled': True, 'level': '高危'},
    {'port': 135, 'name': 'RPC 远程端点映射', 'category': 'smb', 'enabled': True, 'level': '高危'},
    {'port': 139, 'name': 'NetBIOS 局域网嗅探', 'category': 'smb', 'enabled': True, 'level': '中危'},
    {'port': 445, 'name': 'SMB / 永恒之蓝高危探针', 'category': 'smb', 'enabled': True, 'level': '极高危'},
    {'port': 1433, 'name': 'MSSQL 数据库嗅探', 'category': 'db', 'enabled': True, 'level': '高危'},
    {'port': 3389, 'name': 'RDP 远程桌面爆破探测', 'category': 'rdp', 'enabled': True, 'level': '极高危'},
    {'port': 5900, 'name': 'VNC 屏幕控制探针', 'category': 'rdp', 'enabled': True, 'level': '高危'},
    {'port': 6379, 'name': 'Redis 未授权访问探针', 'category': 'db', 'enabled': True, 'level': '极高危'},
    {'port': 8888, 'name': '宝塔/管理面板探测', 'category': 'web', 'enabled': True, 'level': '高危'},
    {'port': 9200, 'name': 'Elasticsearch RCE 探测', 'category': 'db', 'enabled': True, 'level': '高危'},
    {'port': 27017, 'name': 'MongoDB 未授权探针', 'category': 'db', 'enabled': True, 'level': '高危'}
  ],
  'defense_mode': 'standard',
  'enable_port_scan_defense': True,
  'port_scan_threshold': 1,
  'port_scan_window_seconds': 15,
  'ban_action_iptables': True,
  'ban_action_blackhole': True,
  'trap_threshold': 2,
  'trap_window_seconds': 30,
  'trap_all_ports': False,
  'trap_all_unopened_ports': False,
  'trap_business_ports': False,
  'defense_paused': False,
  'auto_clean_days': 30
}

admin_ip = '${CURRENT_SSH_IP}'
if admin_ip and admin_ip != '127.0.0.1':
    cfg['whitelist'].append({'ip': admin_ip, 'remark': '当前运维登录端IP'})

gw = '${DEFAULT_GW}'
if gw and gw != '127.0.0.1':
    cfg['whitelist'].append({'ip': gw, 'remark': '宿主机默认路由网关(防自锁)'})

active_ports = set()
for proc_file in ('/proc/net/tcp', '/proc/net/tcp6'):
    if os.path.exists(proc_file):
        try:
            with open(proc_file) as f:
                for l in f.readlines()[1:]:
                    parts = l.strip().split()
                    if len(parts) >= 4 and parts[3] == '0A':
                        active_ports.add(int(parts[1].split(':')[-1], 16))
        except Exception:
            pass

known_names = {22: 'SSH 远程管理', 80: 'HTTP 网站服务', 443: 'HTTPS 网站服务', 10232: '1Panel 运维面板', 15633: '1Panel 运维面板'}
for p in sorted(list(active_ports)):
    if p != int('${TARGET_WEB_PORT}'):
        name = known_names.get(p, f'系统已监听服务 ({p})')
        cfg['business_ports'].append({'port': p, 'name': name, 'block_idc': False, 'block_scanner': True})

cfg['trap_ports'] = [t for t in cfg['trap_ports'] if int(t.get('port', 0)) not in active_ports]

with open('${INSTALL_DIR}/config.json', 'w', encoding='utf-8') as f:
    json.dump(cfg, f, indent=2, ensure_ascii=False)
"
    echo -e "${GREEN}[✓] 智能防误封白名单与业务端口已初始化完毕！${NC}"
else
    echo -e "${YELLOW}[!] 检测到已存在配置文件，保留现有配置并平滑增量合并新特性...${NC}"
    python3 -c "
import json, os, sys
cfg_p = '${INSTALL_DIR}/config.json'
try:
    with open(cfg_p, 'r', encoding='utf-8') as f:
        curr = json.load(f)
    sys.path.insert(0, '${INSTALL_DIR}')
    from sentry_daemon import DEFAULT_CONFIG
    mod = False
    for k, v in DEFAULT_CONFIG.items():
        if k not in curr:
            curr[k] = v
            mod = True
    if mod:
        with open(cfg_p, 'w', encoding='utf-8') as f:
            json.dump(curr, f, indent=2, ensure_ascii=False)
except Exception:
    pass
" 2>/dev/null || true
fi

# 防火墙自动放行联动 (仅在监听 0.0.0.0 公网模式下放行)
if [ "$WEB_BIND" == "0.0.0.0" ]; then
    if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -qw "active"; then
        ufw allow ${TARGET_WEB_PORT}/tcp comment 'PortGuard WebUI' 2>/dev/null || true
        echo -e "${GREEN}[✓] UFW 防火墙已自动放行端口 ${TARGET_WEB_PORT}/tcp${NC}"
    fi
    if command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state 2>/dev/null | grep -qw "running"; then
        firewall-cmd --add-port=${TARGET_WEB_PORT}/tcp --permanent 2>/dev/null || true
        firewall-cmd --reload 2>/dev/null || true
        echo -e "${GREEN}[✓] Firewalld 防火墙已自动放行端口 ${TARGET_WEB_PORT}/tcp${NC}"
    fi
fi

echo -e "\n${BLUE}[6/6] 正在注册并启动 Systemd 守护进程...${NC}"
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

# 自动释放公网 DNS 与核心基础设施 IP，彻底杜绝历史误封影响网络
for dns_ip in "1.1.1.1" "8.8.8.8" "223.5.5.5" "114.114.114.114" "1.0.0.1" "8.8.4.4"; do
    ip route del blackhole ${dns_ip}/32 2>/dev/null || true
    iptables -D INPUT -s ${dns_ip} -j DROP 2>/dev/null || true
    if command -v ipset >/dev/null 2>&1; then
        ipset del portguard_blacklist_v4 ${dns_ip} 2>/dev/null || true
    fi
done

systemctl restart portguard.service
sleep 2

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

echo -e "\n${CYAN}================================================================${NC}"
if [ "$IS_UPDATE" = true ]; then
    echo -e "${GREEN}🎉 PortGuard 智能主动诱捕防御控制台更新完成！${NC}"
else
    echo -e "${GREEN}🎉 PortGuard 智能主动诱捕防御控制台部署成功！${NC}"
fi
echo -e "${CYAN}================================================================${NC}"

if [ "$WEB_BIND" == "127.0.0.1" ]; then
    echo -e "🌐 Web 控制台访问入口: ${YELLOW}http://127.0.0.1:${TARGET_WEB_PORT}${NC}"
    echo -e "🔒 监听运行模式:       ${GREEN}本地反向代理安全模式 (公网不可探，最安全)${NC}"
    echo -e "💡 访问指引:           ${CYAN}请在 1Panel 或 Nginx 中添加反代站点，代理至: http://127.0.0.1:${TARGET_WEB_PORT}${NC}"
else
    PUBLIC_IP=$(curl -s --connect-timeout 2 ip.sb || curl -s --connect-timeout 2 cip.cc | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | head -n 1 || curl -s --connect-timeout 2 ifconfig.me || echo "YOUR_SERVER_IP")
    echo -e "🌐 Web 控制台访问入口: ${YELLOW}http://${PUBLIC_IP}:${TARGET_WEB_PORT}${NC}"
    echo -e "🔒 监听运行模式:       ${BLUE}公网直连访问模式${NC}"
fi

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

os.chmod(os.path.join(BASE_DIR, 'install.sh'), 0o755)
print('SUCCESS')

