#!/usr/bin/env bash
# ==============================================================================
# Portsentry Defense & Apple-Style WebUI - 一键极速平滑热更新脚本
# ==============================================================================

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${CYAN}================================================================${NC}"
echo -e "${GREEN}   🔄 Portsentry Defense & Apple-Style WebUI 一键平滑更新      ${NC}"
echo -e "${CYAN}================================================================${NC}"

if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}[ERROR] 本脚本必须使用 root 权限执行！请使用 sudo bash update.sh${NC}" 
   exit 1
fi

INSTALL_DIR="/opt/portsentry-ui"
SERVICE_NAME="portsentry-ui.service"

if [ ! -d "$INSTALL_DIR" ]; then
    echo -e "${YELLOW}[!] 检测到系统尚未安装 Portsentry-UI，正在自动执行全新安装...${NC}"
    curl -fsSL https://raw.githubusercontent.com/Level6me/portsentry-ui/main/install.sh | bash
    exit 0
fi

echo -e "\n${BLUE}[1/4] 正在获取最新代码版本与校验...${NC}"
TMP_UPDATE_DIR=$(mktemp -d /tmp/portsentry_update_XXXXXX)
cd "$TMP_UPDATE_DIR"

LATEST_SHA=$(curl -sSL -H "User-Agent: PortsentryUpdater" https://api.github.com/repos/Level6me/portsentry-ui/commits/main 2>/dev/null | grep '"sha"' | head -n 1 | cut -d '"' -f 4 || true)

if [ -n "$LATEST_SHA" ] && [ ${#LATEST_SHA} -ge 7 ]; then
    echo -e "最新版本提交哈希: ${CYAN}${LATEST_SHA:0:7}${NC}"
    REF_TARGET="$LATEST_SHA"
else
    REF_TARGET="main"
fi

curl -fsSL "https://raw.githubusercontent.com/Level6me/portsentry-ui/${REF_TARGET}/web_server.py" -o web_server.py
curl -fsSL "https://raw.githubusercontent.com/Level6me/portsentry-ui/${REF_TARGET}/sentry_daemon.py" -o sentry_daemon.py
curl -fsSL "https://raw.githubusercontent.com/Level6me/portsentry-ui/${REF_TARGET}/uninstall.sh" -o uninstall.sh

if [ ! -s web_server.py ] || [ ! -s sentry_daemon.py ]; then
    echo -e "${RED}[ERROR] 下载更新文件失败，请检查网络连接！${NC}"
    rm -rf "$TMP_UPDATE_DIR"
    exit 1
fi

echo -e "\n${BLUE}[2/4] 正在更新模块 (保留现有数据库与策略配置)...${NC}"
cp -f web_server.py "$INSTALL_DIR/web_server.py"
chmod 644 "$INSTALL_DIR/web_server.py"

cp -f sentry_daemon.py "$INSTALL_DIR/sentry_daemon.py"
chmod 644 "$INSTALL_DIR/sentry_daemon.py"

if [ -s uninstall.sh ]; then
    cp -f uninstall.sh "$INSTALL_DIR/uninstall.sh"
    chmod 755 "$INSTALL_DIR/uninstall.sh"
fi

rm -rf "$TMP_UPDATE_DIR"
echo -e "${GREEN}[✓] 核心程序已平滑覆盖更新 (原有 config.json 与 data.db 保持完好)${NC}"

echo -e "\n${BLUE}[3/4] 正在重启 Portsentry 防御服务...${NC}"
systemctl daemon-reload 2>/dev/null || true
systemctl restart "$SERVICE_NAME"
sleep 2

echo -e "\n${BLUE}[4/4] 正在验证服务运行状态...${NC}"
if systemctl is-active --quiet "$SERVICE_NAME"; then
    echo -e "${GREEN}[✓] Portsentry-UI 服务已成功重启且运行正常！${NC}"
else
    echo -e "${RED}[ERROR] 服务重启异常，请使用 journalctl -u portsentry-ui.service -n 20 查看错误日志。${NC}"
    exit 1
fi

PUBLIC_IP=$(curl -s --connect-timeout 3 ifconfig.me || curl -s --connect-timeout 3 icanhazip.com || echo "YOUR_SERVER_IP")

echo -e "\n${CYAN}================================================================${NC}"
echo -e "${GREEN}🎉 Portsentry 苹果原生风格安全控制台更新成功！${NC}"
echo -e "${CYAN}================================================================${NC}"
echo -e "🌐 Web 控制台访问入口: ${YELLOW}http://${PUBLIC_IP}:9099${NC}"
echo -e "📁 安装运行目录:       ${BLUE}${INSTALL_DIR}${NC}"
echo -e "💡 查看服务状态:       ${CYAN}systemctl status ${SERVICE_NAME}${NC}"
echo -e "💡 实时拦截日志:       ${CYAN}journalctl -u ${SERVICE_NAME} -f${NC}"
echo -e "${CYAN}================================================================${NC}\n"
