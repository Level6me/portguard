#!/usr/bin/env bash
# ==============================================================================
# PortGuard Defense & WebUI - 一键完全卸载脚本
# ==============================================================================

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${CYAN}================================================================${NC}"
echo -e "${RED}      🗑️  PortGuard Defense & WebUI 一键完全卸载程序             ${NC}"
echo -e "${CYAN}================================================================${NC}"

if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}[ERROR] 本脚本必须使用 root 权限执行！请使用 sudo bash uninstall.sh${NC}" 
   exit 1
fi

INSTALL_DIR="/opt/portguard"
SERVICE_NAME="portguard.service"

# 检查是否存在参数 -y, --force, --keep-data
FORCE_YES=false
KEEP_DATA=false
for arg in "$@"; do
    if [[ "$arg" == "-y" || "$arg" == "--force" ]]; then
        FORCE_YES=true
    elif [[ "$arg" == "--keep-data" ]]; then
        KEEP_DATA=true
    fi
done

if [ "$FORCE_YES" = false ]; then
    # 仅在标准输入连接到交互式终端时进行提示，避免管道执行 (curl | bash) 时误判取消
    if [ -t 0 ]; then
        if [ "$KEEP_DATA" = true ]; then
            echo -e "${YELLOW}此操作将停止 PortGuard 守护进程并删除程序文件，但保留您的数据库与策略配置。${NC}"
        else
            echo -e "${YELLOW}此操作将停止 PortGuard 守护进程、注销 systemd 服务并彻底删除 ${INSTALL_DIR} 目录。${NC}"
        fi
        read -r -p "确认卸载 PortGuard 防御系统吗？(y/N): " confirm
        if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
            echo -e "${CYAN}[INFO] 卸载操作已取消。${NC}"
            exit 0
        fi
    fi
fi

echo -e "\n${BLUE}[1/4] 正在停止并注销系统守护服务...${NC}"
for s in "$SERVICE_NAME" "portsentry-ui.service"; do
    if systemctl is-active --quiet "$s" 2>/dev/null; then
        systemctl stop "$s" 2>/dev/null || true
    fi
    if systemctl is-enabled --quiet "$s" 2>/dev/null; then
        systemctl disable "$s" 2>/dev/null || true
    fi
    rm -f "/etc/systemd/system/$s" 2>/dev/null || true
done
systemctl daemon-reload 2>/dev/null || true
echo -e "${GREEN}[✓] 防御服务已停止并注销${NC}"

echo -e "\n${BLUE}[2/4] 正在清理后台残留进程、网络监听与防火墙规则...${NC}"
pkill -9 -f "/opt/portguard/web_server.py" 2>/dev/null || true
pkill -9 -f "/opt/portguard/sentry_daemon.py" 2>/dev/null || true
pkill -9 -f "/opt/portsentry-ui/web_server.py" 2>/dev/null || true
pkill -9 -f "/opt/portsentry-ui/sentry_daemon.py" 2>/dev/null || true
pkill -9 -f "portguard" 2>/dev/null || true
pkill -9 -f "portsentry-ui" 2>/dev/null || true

# 清理可能残留的 iptables 与 ipset 规则
if command -v iptables >/dev/null 2>&1; then
    iptables -D INPUT -m set --match-set portguard_blacklist_v4 src -j DROP 2>/dev/null || true
    iptables -D FORWARD -m set --match-set portguard_blacklist_v4 src -j DROP 2>/dev/null || true
fi
if command -v ipset >/dev/null 2>&1; then
    ipset destroy portguard_blacklist_v4 2>/dev/null || true
fi

# 清理 UFW / firewalld 开放端口规则
if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -qw "active"; then
    ufw delete allow 9099/tcp 2>/dev/null || true
fi
if command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state 2>/dev/null | grep -qw "running"; then
    firewall-cmd --remove-port=9099/tcp --permanent 2>/dev/null || true
    firewall-cmd --reload 2>/dev/null || true
fi
echo -e "${GREEN}[✓] 进程、网络规则与系统防火墙已全部释放清理${NC}"

echo -e "\n${BLUE}[3/4] 正在删除程序文件...${NC}"
if [ -d "$INSTALL_DIR" ]; then
    if [ "$KEEP_DATA" = true ]; then
        find "$INSTALL_DIR" -maxdepth 1 ! -name 'config.json' ! -name 'data.db' ! -name '.' -exec rm -rf {} + 2>/dev/null || true
        echo -e "${GREEN}[✓] 程序文件已删除，保留配置与数据库 (${INSTALL_DIR}/config.json, data.db)${NC}"
    else
        rm -rf "$INSTALL_DIR"
        echo -e "${GREEN}[✓] 安装目录 ${INSTALL_DIR} 已完全删除${NC}"
    fi
fi
if [ -d "/opt/portsentry-ui" ]; then
    rm -rf "/opt/portsentry-ui"
fi

# 清理临时日志与缓存
rm -f /tmp/portguard* /tmp/portsentry* 2>/dev/null || true

echo -e "\n${BLUE}[4/4] 验证卸载结果...${NC}"
if ! systemctl status "$SERVICE_NAME" >/dev/null 2>&1; then
    echo -e "${GREEN}[✓] 系统验证通过：无残留服务${NC}"
fi

echo -e "\n${CYAN}================================================================${NC}"
echo -e "${GREEN}   🎉 PortGuard Defense & WebUI 已从您的系统中彻底完全卸载！   ${NC}"
echo -e "${CYAN}================================================================${NC}\n"
