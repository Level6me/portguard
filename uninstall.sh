#!/usr/bin/env bash
# ==============================================================================
# Portsentry Defense & Apple-Style WebUI - 一键完全卸载脚本
# ==============================================================================

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${CYAN}================================================================${NC}"
echo -e "${RED}   🗑️  Portsentry Defense & WebUI 一键完全卸载程序             ${NC}"
echo -e "${CYAN}================================================================${NC}"

if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}[ERROR] 本脚本必须使用 root 权限执行！请使用 sudo bash uninstall.sh${NC}" 
   exit 1
fi

INSTALL_DIR="/opt/portsentry-ui"
SERVICE_NAME="portsentry-ui.service"

# 检查是否存在参数 -y 或 --force
FORCE_YES=false
for arg in "$@"; do
    if [[ "$arg" == "-y" || "$arg" == "--force" ]]; then
        FORCE_YES=true
    fi
done

if [ "$FORCE_YES" = false ]; then
    # 仅在标准输入连接到交互式终端时进行提示，避免管道执行 (curl | bash) 时误判取消
    if [ -t 0 ]; then
        echo -e "${YELLOW}此操作将停止 Portsentry 蜜罐防御守护进程、注销 systemd 服务并彻底删除 ${INSTALL_DIR} 目录。${NC}"
        read -r -p "确认完全卸载 Portsentry 防御系统吗？(y/N): " confirm
        if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
            echo -e "${CYAN}[INFO] 卸载操作已取消。${NC}"
            exit 0
        fi
    fi
fi

echo -e "\n${BLUE}[1/4] 正在停止并注销系统守护服务...${NC}"
if systemctl is-active --quiet "$SERVICE_NAME" 2>/dev/null; then
    systemctl stop "$SERVICE_NAME" 2>/dev/null || true
    echo -e "${GREEN}[✓] 防御服务已停止${NC}"
fi

if systemctl is-enabled --quiet "$SERVICE_NAME" 2>/dev/null; then
    systemctl disable "$SERVICE_NAME" 2>/dev/null || true
    echo -e "${GREEN}[✓] 开机自启服务已注销${NC}"
fi

# 删除服务文件
if [ -f "/etc/systemd/system/$SERVICE_NAME" ]; then
    rm -f "/etc/systemd/system/$SERVICE_NAME"
    systemctl daemon-reload 2>/dev/null || true
    echo -e "${GREEN}[✓] systemd 服务单元文件已清理${NC}"
fi

echo -e "\n${BLUE}[2/4] 正在清理后台残留进程与网络监听...${NC}"
pkill -9 -f "/opt/portsentry-ui/web_server.py" 2>/dev/null || true
pkill -9 -f "/opt/portsentry-ui/sentry_daemon.py" 2>/dev/null || true
pkill -9 -f "portsentry-ui" 2>/dev/null || true
echo -e "${GREEN}[✓] 进程已全部释放${NC}"

echo -e "\n${BLUE}[3/4] 正在删除程序文件与数据库...${NC}"
if [ -d "$INSTALL_DIR" ]; then
    rm -rf "$INSTALL_DIR"
    echo -e "${GREEN}[✓] 安装目录 ${INSTALL_DIR} 已完全删除${NC}"
fi

# 清理临时日志与缓存
rm -f /tmp/portsentry* 2>/dev/null || true

echo -e "\n${BLUE}[4/4] 验证卸载结果...${NC}"
if ! systemctl status "$SERVICE_NAME" >/dev/null 2>&1 && [ ! -d "$INSTALL_DIR" ]; then
    echo -e "${GREEN}[✓] 系统验证通过：无残留服务与文件${NC}"
fi

echo -e "\n${CYAN}================================================================${NC}"
echo -e "${GREEN}   🎉 Portsentry Defense & WebUI 已从您的系统中彻底完全卸载！   ${NC}"
echo -e "${CYAN}================================================================${NC}\n"
