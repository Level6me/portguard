#!/usr/bin/env bash
# ==============================================================================
# PortGuard Defense & WebUI - 一键极速平滑热更新脚本 (含故障自愈与多通道加速)
# ==============================================================================

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${CYAN}================================================================${NC}"
echo -e "${GREEN}      🔄 PortGuard 智能主动诱捕防御系统 一键平滑热更新          ${NC}"
echo -e "${CYAN}================================================================${NC}"

if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}[ERROR] 本脚本必须使用 root 权限执行！请使用 sudo bash update.sh${NC}" 
   exit 1
fi

FORCE_CN=false
FORCE_GLOBAL=false
for arg in "$@"; do
    if [[ "$arg" == "--cn" ]]; then
        FORCE_CN=true
    elif [[ "$arg" == "--global" ]]; then
        FORCE_GLOBAL=true
    fi
done

INSTALL_DIR="/opt/portguard"
SERVICE_NAME="portguard.service"

# 兼容历史路径平滑迁移
if [ ! -d "$INSTALL_DIR" ] && [ -d "/opt/portsentry-ui" ]; then
    INSTALL_DIR="/opt/portsentry-ui"
    SERVICE_NAME="portsentry-ui.service"
fi

if [ ! -d "$INSTALL_DIR" ]; then
    echo -e "${YELLOW}[!] 检测到系统尚未安装 PortGuard，正在自动执行全新安装...${NC}"
    curl -fsSL https://raw.githubusercontent.com/Level6me/portguard/main/install.sh | bash
    exit 0
fi

# 智能网络通道测速与镜像选路
GH_PROXY=""
if [ "$FORCE_GLOBAL" = true ]; then
    GH_PROXY=""
    echo -e "${CYAN}[NET] 已指定海外直连通道 (GitHub Official)${NC}"
elif [ "$FORCE_CN" = true ]; then
    GH_PROXY="https://ghproxy.net/"
    echo -e "${CYAN}[NET] 已指定国内加速镜像通道${NC}"
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

# 1. 更新前创建快照备份 (故障自愈基石)
echo -e "\n${BLUE}[1/5] 正在创建当前运行版本快照备份...${NC}"
BACKUP_DIR="${INSTALL_DIR}/backup"
mkdir -p "$BACKUP_DIR"
BACKUP_FILE="${BACKUP_DIR}/portguard_backup_$(date +%Y%m%d_%H%M%S).tar.gz"
if [ -f "${INSTALL_DIR}/web_server.py" ]; then
    tar -czf "$BACKUP_FILE" -C "$INSTALL_DIR" web_server.py sentry_daemon.py config.json 2>/dev/null || true
    # 仅保留最近 3 份历史快照
    ls -t "${BACKUP_DIR}"/portguard_backup_*.tar.gz 2>/dev/null | tail -n +4 | xargs rm -f 2>/dev/null || true
    echo -e "${GREEN}[✓] 版本快照已存档至: ${BACKUP_FILE}${NC}"
fi

echo -e "\n${BLUE}[2/5] 正在获取最新代码版本与校验...${NC}"
TMP_UPDATE_DIR=$(mktemp -d /tmp/portguard_update_XXXXXX)
cd "$TMP_UPDATE_DIR"

LATEST_SHA=$(curl -sSL --connect-timeout 3 -H "User-Agent: PortGuardUpdater" "${GH_PROXY}https://api.github.com/repos/Level6me/portguard/commits/main" 2>/dev/null | grep '"sha"' | head -n 1 | cut -d '"' -f 4 || true)

if [ -n "$LATEST_SHA" ] && [ ${#LATEST_SHA} -ge 7 ]; then
    echo -e "最新版本提交哈希: ${CYAN}${LATEST_SHA:0:7}${NC}"
    REF_TARGET="$LATEST_SHA"
else
    REF_TARGET="main"
fi

get_file_size() {
    stat -c%s "$1" 2>/dev/null || stat -f%z "$1" 2>/dev/null || wc -c < "$1" || echo "0"
}

calc_sha256() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" 2>/dev/null | awk '{print $1}'
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$1" 2>/dev/null | awk '{print $1}'
    else
        echo ""
    fi
}

download_file_safe() {
    local url="$1"
    local dest="$2"
    local min_sz="${3:-100}"
    local expected_sha="$4"
    
    if [ -n "$GH_PROXY" ]; then
        curl -fsSL --connect-timeout 6 --retry 2 "${GH_PROXY}${url}" -o "$dest" 2>/dev/null || \
        curl -fsSL --connect-timeout 6 --retry 2 "${url}" -o "$dest" 2>/dev/null || true
    else
        curl -fsSL --connect-timeout 6 --retry 2 "${url}" -o "$dest" 2>/dev/null || \
        curl -fsSL --connect-timeout 6 --retry 2 "https://ghproxy.net/${url}" -o "$dest" 2>/dev/null || true
    fi
    
    if [ -f "$dest" ]; then
        local sz
        sz=$(get_file_size "$dest")
        if [ "$sz" -ge "$min_sz" ]; then
            if [ -n "$expected_sha" ]; then
                local got_sha
                got_sha=$(calc_sha256 "$dest")
                if [ -n "$got_sha" ] && [ "$got_sha" != "$expected_sha" ]; then
                    echo -e "${RED}[!] 文件 ${dest} 哈希不匹配 (可能被篡改或损坏)，已丢弃${NC}"
                    rm -f "$dest" 2>/dev/null || true
                    return 1
                fi
            fi
            return 0
        fi
    fi
    return 1
}

echo -e "正在获取最新代码架构与控制器组件..."
ARCHIVE_URL="${GH_PROXY}https://github.com/Level6me/portguard/archive/${REF_TARGET}.tar.gz"
if curl -fsSL --connect-timeout 8 "$ARCHIVE_URL" | tar -xzf - --strip-components=1 2>/dev/null; then
    echo -e "${GREEN}[✓] 完整架构组件包获取成功${NC}"
else
    download_file_safe "https://raw.githubusercontent.com/Level6me/portguard/${REF_TARGET}/web_server.py" "web_server.py" 20000 || true
    download_file_safe "https://raw.githubusercontent.com/Level6me/portguard/${REF_TARGET}/sentry_daemon.py" "sentry_daemon.py" 30000 || true
    download_file_safe "https://raw.githubusercontent.com/Level6me/portguard/${REF_TARGET}/uninstall.sh" "uninstall.sh" 1000 || true
    download_file_safe "https://raw.githubusercontent.com/Level6me/portguard/${REF_TARGET}/chart.min.js" "chart.min.js" 10000 || true
fi

if [ ! -s web_server.py ] || [ ! -s sentry_daemon.py ]; then
    echo -e "${RED}[ERROR] 下载更新文件失败，请检查网络连接！正在撤销本次更新。${NC}"
    rm -rf "$TMP_UPDATE_DIR"
    exit 1
fi

# 预编译语法完整性验证
if command -v python3 >/dev/null 2>&1; then
    if ! python3 -m py_compile web_server.py sentry_daemon.py 2>/dev/null; then
        echo -e "${RED}[ERROR] 下载的核心代码文件存在语法损坏，终止覆盖更新！${NC}"
        rm -rf "$TMP_UPDATE_DIR"
        exit 1
    fi
fi

echo -e "\n${BLUE}[3/5] 正在校验并补全 GeoIP 全球离线定位数据库...${NC}"
# 1. IP2Region (11MB，加入 SHA256 完整性校验)
IP2REGION_SHA="c6edaf379fe524d7283a9c11c7eac27d5641a0976baa48c22c319ccd59aa3f36"
if [ ! -f "$INSTALL_DIR/ip2region.xdb" ] || [ "$(get_file_size "$INSTALL_DIR/ip2region.xdb")" -lt 5000000 ]; then
    echo -e "正在获取 IP2Region 本地离线 IP 库 (约 11MB)..."
    download_file_safe "https://raw.githubusercontent.com/Level6me/portguard/${REF_TARGET}/ip2region.xdb" "ip2region.xdb" 5000000 "$IP2REGION_SHA" || \
    download_file_safe "https://raw.githubusercontent.com/lionsoul2014/ip2region/master/data/ip2region_v4.xdb" "ip2region.xdb" 5000000 "" || true
    if [ -f "ip2region.xdb" ] && [ "$(get_file_size "ip2region.xdb")" -ge 5000000 ]; then
        cp -f ip2region.xdb "$INSTALL_DIR/ip2region.xdb"
        chmod 644 "$INSTALL_DIR/ip2region.xdb"
    fi
fi

# 2. GeoLite2-ASN (12MB)
if [ ! -f "$INSTALL_DIR/GeoLite2-ASN.mmdb" ] || [ "$(get_file_size "$INSTALL_DIR/GeoLite2-ASN.mmdb")" -lt 5000000 ]; then
    echo -e "正在获取 MaxMind GeoLite2-ASN 全球自治系统与运营商数据库 (约 12MB)..."
    download_file_safe "https://raw.githubusercontent.com/P3TERX/GeoLite.mmdb/download/GeoLite2-ASN.mmdb" "GeoLite2-ASN.mmdb" 5000000 || true
    if [ -f "GeoLite2-ASN.mmdb" ] && [ "$(get_file_size "GeoLite2-ASN.mmdb")" -ge 5000000 ]; then
        cp -f GeoLite2-ASN.mmdb "$INSTALL_DIR/GeoLite2-ASN.mmdb"
        chmod 644 "$INSTALL_DIR/GeoLite2-ASN.mmdb"
    fi
fi

# 3. GeoLite2-City (65MB)
if [ ! -f "$INSTALL_DIR/GeoLite2-City.mmdb" ] || [ "$(get_file_size "$INSTALL_DIR/GeoLite2-City.mmdb")" -lt 30000000 ]; then
    echo -e "正在获取 MaxMind GeoLite2-City 全球高精度城市数据库 (约 65MB)..."
    download_file_safe "https://raw.githubusercontent.com/P3TERX/GeoLite.mmdb/download/GeoLite2-City.mmdb" "GeoLite2-City.mmdb" 30000000 || true
    if [ -f "GeoLite2-City.mmdb" ] && [ "$(get_file_size "GeoLite2-City.mmdb")" -ge 30000000 ]; then
        cp -f GeoLite2-City.mmdb "$INSTALL_DIR/GeoLite2-City.mmdb"
        chmod 644 "$INSTALL_DIR/GeoLite2-City.mmdb"
    fi
fi

echo -e "\n${BLUE}[4/5] 正在安全覆盖核心程序并平滑增量合并配置...${NC}"
cp -f web_server.py "$INSTALL_DIR/web_server.py"
chmod 644 "$INSTALL_DIR/web_server.py"

cp -f sentry_daemon.py "$INSTALL_DIR/sentry_daemon.py"
chmod 644 "$INSTALL_DIR/sentry_daemon.py"

cp -f chart.min.js "$INSTALL_DIR/chart.min.js"
chmod 644 "$INSTALL_DIR/chart.min.js"

for d in templates controllers geo collectors core cluster; do
    if [ -d "$d" ]; then
        mkdir -p "$INSTALL_DIR/$d"
        cp -rf "$d"/* "$INSTALL_DIR/$d/" 2>/dev/null || true
    fi
done

if [ -s uninstall.sh ]; then
    cp -f uninstall.sh "$INSTALL_DIR/uninstall.sh"
    chmod 755 "$INSTALL_DIR/uninstall.sh"
fi

# 核心配置平滑增量合并 (保留用户自定义规则的前提下注入新版默认特性字段)
python3 -c "
import json, os, sys
cfg_path = '${INSTALL_DIR}/config.json'
try:
    if os.path.exists(cfg_path):
        with open(cfg_path, 'r', encoding='utf-8') as f:
            curr = json.load(f)
        sys.path.insert(0, '${INSTALL_DIR}')
        from sentry_daemon import DEFAULT_CONFIG
        modified = False
        for k, v in DEFAULT_CONFIG.items():
            if k not in curr:
                curr[k] = v
                modified = True
        if modified:
            with open(cfg_path, 'w', encoding='utf-8') as f:
                json.dump(curr, f, indent=2, ensure_ascii=False)
except Exception:
    pass
" 2>/dev/null || true

rm -rf "$TMP_UPDATE_DIR"
echo -e "${GREEN}[✓] 核心程序更新与配置增量合并完毕 (原有黑名单/事件日志/自定义策略 100% 保持完好)${NC}"

echo -e "\n${BLUE}[5/5] 正在平滑重启服务并进行健康自愈校验...${NC}"
systemctl daemon-reload 2>/dev/null || true
systemctl restart "$SERVICE_NAME"
sleep 2

# 故障自愈验证逻辑
if systemctl is-active --quiet "$SERVICE_NAME"; then
    echo -e "${GREEN}[✓] PortGuard 服务已成功重启且运行正常！${NC}"
else
    echo -e "${RED}[ERROR] 服务重启异常！正在触发自动自愈机制，紧急回滚至历史版本...${NC}"
    if [ -f "$BACKUP_FILE" ]; then
        tar -xzf "$BACKUP_FILE" -C "$INSTALL_DIR"
        systemctl restart "$SERVICE_NAME" || true
        if systemctl is-active --quiet "$SERVICE_NAME"; then
            echo -e "${YELLOW}[!] 自动自愈成功：已回滚并恢复上一运行版本，防御服务未受影响。${NC}"
        else
            echo -e "${RED}[CRITICAL] 回滚后依然启动失败，请检查 journalctl -u ${SERVICE_NAME} -n 30 日志。${NC}"
        fi
    fi
    exit 1
fi

WEB_PORT=$(python3 -c "import json, os; print(json.load(open('${INSTALL_DIR}/config.json')).get('web_port', 9099))" 2>/dev/null || echo "9099")
WEB_BIND=$(python3 -c "import json, os; print(json.load(open('${INSTALL_DIR}/config.json')).get('web_bind', '0.0.0.0'))" 2>/dev/null || echo "0.0.0.0")

if [ "$WEB_BIND" == "127.0.0.1" ]; then
    ACCESS_URL="http://127.0.0.1:${WEB_PORT} (本地反代模式，请通过 1Panel / Nginx 站点访问)"
else
    PUBLIC_IP=$(curl -s --connect-timeout 2 ip.sb || curl -s --connect-timeout 2 cip.cc | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | head -n 1 || curl -s --connect-timeout 2 ifconfig.me || echo "YOUR_SERVER_IP")
    ACCESS_URL="http://${PUBLIC_IP}:${WEB_PORT}"
fi

echo -e "\n${CYAN}================================================================${NC}"
echo -e "${GREEN}🎉 PortGuard 智能主动诱捕防御控制台更新完成！${NC}"
echo -e "${CYAN}================================================================${NC}"
echo -e "🌐 控制台访问入口:     ${YELLOW}${ACCESS_URL}${NC}"
echo -e "📁 安装运行目录:       ${BLUE}${INSTALL_DIR}${NC}"
echo -e "💾 本次安全快照:       ${BLUE}${BACKUP_FILE}${NC}"
echo -e "💡 查看服务状态:       ${CYAN}systemctl status ${SERVICE_NAME}${NC}"
echo -e "💡 实时防御日志:       ${CYAN}journalctl -u ${SERVICE_NAME} -f${NC}"
echo -e "${CYAN}================================================================${NC}\n"
