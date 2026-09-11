#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PortGuard Core Daemon v2.0 - 智能端口诱捕与主动威胁防御引擎
"""
import glob
import io
import ipaddress
import json
import os
import re
import select
import socket
import sqlite3
import struct
import subprocess
import sys
import threading
import time
import urllib.request
import queue
import hmac
import shutil
import hashlib
from concurrent.futures import ThreadPoolExecutor

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = "/opt/portguard/data.db"
CONFIG_PATH = "/opt/portguard/config.json"

if not os.access("/opt", os.W_OK) or (os.path.exists("/opt/portguard") and not os.access("/opt/portguard", os.W_OK)):
    DB_PATH = os.path.join(BASE_DIR, "data.db")
    CONFIG_PATH = os.path.join(BASE_DIR, "config.json")
elif not os.path.exists("/opt/portguard") and os.path.exists("/opt/portsentry-ui/data.db"):
    # 兼容历史路径平滑过渡
    DB_PATH = "/opt/portsentry-ui/data.db"
    CONFIG_PATH = "/opt/portsentry-ui/config.json"

PUBLIC_INFRASTRUCTURE_IPS = {
    "1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4",
    "114.114.114.114", "114.114.115.115",
    "223.5.5.5", "223.6.6.6",
    "9.9.9.9", "149.112.112.112",
    "119.29.29.29", "182.254.116.116",
    "180.76.76.76"
}

# 权威公共 CDN 节点网段 (Cloudflare 全球边缘节点，严禁误拉黑以免导致网站 502/断网)
CLOUDFLARE_NETWORKS = [
    ipaddress.ip_network("173.245.48.0/20"),
    ipaddress.ip_network("103.21.244.0/22"),
    ipaddress.ip_network("103.22.200.0/22"),
    ipaddress.ip_network("103.31.4.0/22"),
    ipaddress.ip_network("141.101.64.0/18"),
    ipaddress.ip_network("108.162.192.0/18"),
    ipaddress.ip_network("190.93.240.0/20"),
    ipaddress.ip_network("188.114.96.0/20"),
    ipaddress.ip_network("197.234.240.0/22"),
    ipaddress.ip_network("198.41.128.0/17"),
    ipaddress.ip_network("162.158.0.0/15"),
    ipaddress.ip_network("104.16.0.0/13"),
    ipaddress.ip_network("104.24.0.0/14"),
    ipaddress.ip_network("172.64.0.0/13"),
    ipaddress.ip_network("131.0.72.0/22"),
    ipaddress.ip_network("2400:cb00::/32"),
    ipaddress.ip_network("2606:4700::/32"),
    ipaddress.ip_network("2803:f800::/32"),
    ipaddress.ip_network("2405:b500::/32"),
    ipaddress.ip_network("2405:8100::/32"),
    ipaddress.ip_network("2a06:98c0::/29"),
    ipaddress.ip_network("2c0f:f248::/32")
]

def is_infrastructure_or_cdn_ip(ip):
    """判断指定 IP 是否属于权威公共 DNS 基础设施或 Cloudflare 全球 CDN 节点 (永不拉黑)"""
    if not ip:
        return True
    ip_str = str(ip).strip()
    if ip_str in PUBLIC_INFRASTRUCTURE_IPS or ip_str in ("127.0.0.1", "::1", "localhost"):
        return True
    try:
        addr = ipaddress.ip_address(ip_str)
        if addr.is_loopback:
            return True
        for net in CLOUDFLARE_NETWORKS:
            if addr in net:
                return True
    except Exception:
        pass
    return False

DEFAULT_CONFIG = {
    "trap_ports": [
        {"port": 21, "name": "FTP 弱口令防护", "category": "ftp", "enabled": True, "level": "高危"},
        {"port": 23, "name": "Telnet 弱口令防护", "category": "telnet", "enabled": True, "level": "高危"},
        {"port": 135, "name": "RPC 远程调用映射", "category": "smb", "enabled": True, "level": "高危"},
        {"port": 139, "name": "NetBIOS 局域网防护", "category": "smb", "enabled": True, "level": "中危"},
        {"port": 445, "name": "SMB 共享漏洞探测", "category": "smb", "enabled": True, "level": "极高危"},
        {"port": 1433, "name": "MSSQL 数据库防护", "category": "db", "enabled": True, "level": "高危"},
        {"port": 3389, "name": "RDP 远程桌面防护", "category": "rdp", "enabled": True, "level": "极高危"},
        {"port": 5900, "name": "VNC 远程控制防护", "category": "rdp", "enabled": True, "level": "高危"},
        {"port": 6379, "name": "Redis 端口防护", "category": "db", "enabled": True, "level": "极高危"},
        {"port": 8888, "name": "管理控制台端口", "category": "web", "enabled": True, "level": "中危"},
        {"port": 9200, "name": "Elasticsearch 端口防护", "category": "db", "enabled": True, "level": "高危"},
        {"port": 27017, "name": "MongoDB 端口防护", "category": "db", "enabled": True, "level": "高危"}
    ],
    "whitelist": [
        {"ip": "127.0.0.1", "remark": "本地回环"},
        {"ip": "::1", "remark": "IPv6 本地回环"},
        {"ip": "1.1.1.1", "remark": "Cloudflare DNS (系统基础设施)"},
        {"ip": "1.0.0.1", "remark": "Cloudflare DNS (系统基础设施)"},
        {"ip": "8.8.8.8", "remark": "Google DNS (系统基础设施)"},
        {"ip": "8.8.4.4", "remark": "Google DNS (系统基础设施)"},
        {"ip": "223.5.5.5", "remark": "Aliyun DNS (系统基础设施)"},
        {"ip": "223.6.6.6", "remark": "Aliyun DNS (系统基础设施)"},
        {"ip": "119.29.29.29", "remark": "Tencent DNS (系统基础设施)"},
        {"ip": "114.114.114.114", "remark": "114 DNS (系统基础设施)"},
        {"ip": "10.0.0.0/8", "remark": "私网 A 类地址"},
        {"ip": "172.16.0.0/12", "remark": "私网 B 类地址"},
        {"ip": "192.168.0.0/16", "remark": "私网 C 类地址"},
        {"ip": "100.64.0.0/10", "remark": "运营商 CGNAT / 云专网"}
    ],
    "web_port": 9099,
    "web_bind": "127.0.0.1",
    "admin_password": "admin",
    "defense_mode": "standard",
    "ban_action_iptables": True,
    "ban_action_blackhole": True,
    "auto_clean_days": 30,
    "trap_threshold": 2,
    "trap_window_seconds": 30,
    "enable_port_scan_defense": True,
    "port_scan_threshold": 1,
    "port_scan_window_seconds": 15,
    "trap_business_ports": False,
    "trap_all_unopened_ports": False,
    "trap_all_ports": False,
    "defense_paused": False,
    "node_name": "本机节点",
    "cluster_sync": {
        "enabled": False,
        "port": 9098,
        "cluster_secret": "",
        "cluster_nodes": []
    },
    "business_ports": [
        {"port": 80, "name": "HTTP 网站服务", "category": "web", "remark": "默认Web服务"},
        {"port": 443, "name": "HTTPS 网站服务", "category": "web", "remark": "默认加密Web服务"}
    ]
}

DEFAULT_HTTP_TRAPS = [
    {
        "rule_id": "ht_env_backup",
        "name": "敏感配置与备份探测",
        "match_type": "path_keyword",
        "pattern": r"\.env|\.git|\.svn|\.aws|config\.json|database\.sql|dump\.sql|backup\.zip|www\.rar|web\.zip|\.bak$",
        "threshold": 1,
        "window": 30,
        "action": "ban",
        "level": "极高危",
        "enabled": 1,
        "description": "探测系统关键配置文件、源码仓库与数据库备份文件"
    },
    {
        "rule_id": "ht_admin_probe",
        "name": "管理后台特征探测",
        "match_type": "path_keyword",
        "pattern": r"phpmyadmin|admin\.php|wp-login\.php|actuator|/solr/|/manager/html|/api/v1/debug",
        "threshold": 1,
        "window": 30,
        "action": "ban",
        "level": "极高危",
        "enabled": 1,
        "description": "探测常见管理控制台、框架调试接口与后台入口"
    },
    {
        "rule_id": "ht_traversal_rce",
        "name": "路径遍历与文件探测",
        "match_type": "path_keyword",
        "pattern": r"%2e%2e|\.\./\.\.|eval-stdin|/cgi-bin/|/etc/passwd|/proc/self",
        "threshold": 1,
        "window": 30,
        "action": "ban",
        "level": "极高危",
        "enabled": 1,
        "description": "尝试路径穿越、系统命令注入与私密文件读取攻击"
    },
    {
        "rule_id": "ht_scanner_tools",
        "name": "自动化扫描工具特征",
        "match_type": "ua_keyword",
        "pattern": r"sqlmap|nikto|dirsearch|gobuster|wpscan|masscan|hydra|acunetix|nessus|zgrab",
        "threshold": 1,
        "window": 30,
        "action": "ban",
        "level": "高危",
        "enabled": 1,
        "description": "拦截携带特征扫描工具标识的自动化探测源"
    },
    {
        "rule_id": "ht_survey_scanners",
        "name": "网络空间测绘引擎",
        "match_type": "survey_engine",
        "pattern": r"censys|onyphe|shodan|leakix|shadowserver|zoomeye|recyber|internet-measurement|binaryedge|netcraft",
        "threshold": 1,
        "window": 30,
        "action": "ban",
        "level": "极高危",
        "enabled": 1,
        "description": "拦截 Censys, Shodan, Onyphe 等资产测绘引擎的探测请求"
    },
    {
        "rule_id": "ht_direct_ip_probe",
        "name": "禁止纯 IP 直连 Web 探测",
        "match_type": "direct_ip",
        "pattern": "direct_ip",
        "threshold": 1,
        "window": 30,
        "action": "ban",
        "level": "中危",
        "enabled": 1,
        "description": "拦截未携带合法域名 Host、直接通过服务器 IP 地址发起的 Web 探测请求"
    },
    {
        "rule_id": "ht_rate_404",
        "name": "异常状态码频次限制",
        "match_type": "status_rate",
        "pattern": "400,403,404",
        "threshold": 6,
        "window": 30,
        "action": "ban",
        "level": "高危",
        "enabled": 1,
        "description": "30秒内对不存在路径或受限资源连续产生 6 次以上 400/403/404 异常执行封禁阻断（可自定义为任意状态码如 302 或 500-599）"
    }
]

# 常见测绘引擎的 ASN / 运营商 / 特征关键词（不区分大小写，纯内存秒级匹配）
SURVEY_ENGINE_KEYWORDS = (
    "censys", "onyphe", "shodan", "leakix", "shadowserver", "zoomeye",
    "recyber", "internet-measurement", "binaryedge", "netcraft", "stretchoid",
    "tamatiya", "modat", "palo alto networks", "ip volume inc", "onyphe sas", "censys, inc."
)

# 常见境外云厂商 / 数据中心机房（IDC/Hosting/Cloud）运营商关键词
IDC_HOSTING_KEYWORDS = (
    "amazon", "aws", "digitalocean", "microsoft", "azure", "google cloud",
    "google llc", "ovh", "hetzner", "linode", "vultr", "alibaba (us)", "alibaba cloud",
    "tencent computer", "tencent cloud", "ucloud", "m247", "datacamp", "colocation",
    "packethub", "egihosting", "hydra communications", "rack sphere", "ip volume",
    "oracle cloud", "cloudflare", "fastly", "akamai", "contabo", "choopa",
    "leaseweb", "hostkey", "selectel", "scaleway", "kamatera", "vpsvaulthost",
    "quickpacket", "internap", "31173 services", "fusion communications"
)

# 预置常用测绘引擎固定 IP 段（前缀树/CIDR 掩码极速匹配，0 外部网络延迟）
_SURVEY_CIDR_NETWORKS = [
    ipaddress.ip_network("66.132.0.0/16", strict=False),       # Censys
    ipaddress.ip_network("167.94.136.0/22", strict=False),     # Censys
    ipaddress.ip_network("167.94.145.0/24", strict=False),     # Censys
    ipaddress.ip_network("195.184.76.0/24", strict=False),     # Onyphe
    ipaddress.ip_network("91.230.168.0/24", strict=False),     # Onyphe
    ipaddress.ip_network("198.20.69.0/24", strict=False),      # Shodan
    ipaddress.ip_network("198.20.70.0/24", strict=False),      # Shodan
    ipaddress.ip_network("198.20.99.0/24", strict=False),      # Shodan
    ipaddress.ip_network("71.6.232.0/24", strict=False),       # Shodan
    ipaddress.ip_network("71.6.216.0/24", strict=False),       # Shodan
    ipaddress.ip_network("104.236.198.48/32", strict=False),   # Shodan
    ipaddress.ip_network("185.180.143.0/24", strict=False),    # LeakIX
    ipaddress.ip_network("185.220.101.0/24", strict=False),    # Tor Exit
    ipaddress.ip_network("185.220.100.0/24", strict=False),    # Tor Exit
    ipaddress.ip_network("185.220.102.0/24", strict=False),    # Tor Exit
    ipaddress.ip_network("185.220.103.0/24", strict=False),    # Tor Exit
    ipaddress.ip_network("171.25.193.0/24", strict=False),     # Tor Exit
    ipaddress.ip_network("199.249.230.0/24", strict=False),    # Tor Exit
    ipaddress.ip_network("23.129.64.0/24", strict=False),      # Tor Exit
]

def is_survey_scanner_ip(ip_str, geo_dict=None):
    """0 网络延迟快速判断目标 IP 是否属于已知网络空间测绘引擎"""
    if not ip_str or ip_str in ("127.0.0.1", "::1", "localhost") or ip_str.startswith("127."):
        return False
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        for net in _SURVEY_CIDR_NETWORKS:
            if ip_obj in net:
                return True
    except Exception:
        pass
        
    geo = geo_dict or _GEO_CACHE.get(ip_str) or {}
    isp_text = (str(geo.get("isp", "")) + " " + str(geo.get("region", "")) + " " + str(geo.get("country", ""))).lower()
    for kw in SURVEY_ENGINE_KEYWORDS:
        if kw in isp_text:
            return True
    return False

def is_idc_hosting_ip(ip_str, geo_dict=None):
    """0 网络延迟快速判断目标 IP 是否属于 IDC/云服务器机房 IP"""
    if not ip_str or ip_str in ("127.0.0.1", "::1", "localhost") or ip_str.startswith("127."):
        return False
    geo = geo_dict or _GEO_CACHE.get(ip_str) or {}
    isp_text = (str(geo.get("isp", "")) + " " + str(geo.get("region", "")) + " " + str(geo.get("country", ""))).lower()
    for kw in IDC_HOSTING_KEYWORDS:
        if kw in isp_text:
            return True
    return False

_THREAT_TAGS_CACHE = {}
_THREAT_TAGS_LOCK = threading.Lock()

def get_ip_threat_tags(ip_str, geo_dict=None):
    """威胁情报标签与信誉综合研判：返回 IP 的多维信誉指纹标签列表（如 Tor匿名节点、空间测绘、云机房IDC等）"""
    if not ip_str or ip_str in ("127.0.0.1", "::1", "localhost") or ip_str.startswith("127."):
        return []
    with _THREAT_TAGS_LOCK:
        if ip_str in _THREAT_TAGS_CACHE:
            return _THREAT_TAGS_CACHE[ip_str]
    tags = []
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        # 1. 检查 Tor 出口节点
        for net in _SURVEY_CIDR_NETWORKS:
            if "Tor Exit" in str(net) and ip_obj in net:
                tags.append("🧅 Tor 匿名网络")
                break
        if not tags:
            # 兼容 CIDR 检查 Tor
            if ip_str.startswith("185.220.10") or ip_str.startswith("171.25.193."):
                tags.append("🧅 Tor 匿名网络")
    except Exception:
        pass

    geo = geo_dict or _GEO_CACHE.get(ip_str) or {}
    isp_text = (str(geo.get("isp", "")) + " " + str(geo.get("region", "")) + " " + str(geo.get("country", ""))).lower()

    # 2. 检查空间测绘指纹
    if is_survey_scanner_ip(ip_str, geo):
        for kw in SURVEY_ENGINE_KEYWORDS:
            if kw in isp_text or kw in ip_str:
                tags.append(f"📡 测绘引擎 ({kw.title()})")
                break
        if not any("测绘" in t for t in tags):
            tags.append("📡 空间测绘爬虫")

    # 3. 检查 IDC / Hosting 机房特征
    if is_idc_hosting_ip(ip_str, geo):
        for kw in IDC_HOSTING_KEYWORDS[:12]:
            if kw in isp_text:
                tags.append(f"☁️ 云机房 ({kw.title()})")
                break
        if not any("云机房" in t for t in tags):
            tags.append("☁️ 数据中心/IDC")

    with _THREAT_TAGS_LOCK:
        _THREAT_TAGS_CACHE[ip_str] = tags
    return tags

DEFAULT_CONFIG["http_traps"] = DEFAULT_HTTP_TRAPS
PORT_DESCRIPTIONS = {t["port"]: t["name"] for t in DEFAULT_CONFIG["trap_ports"]}

# 全局线程池：限制并发，避免扫描风暴下线程爆炸
_EXECUTOR = ThreadPoolExecutor(max_workers=8, thread_name_prefix="sentry")


def validate_ip(ip):
    """严格校验 IPv4 / IPv6 地址或 CIDR 网段，拒绝任何带端口、路径或 shell 元字符的输入。"""
    if not ip or not isinstance(ip, str):
        return None
    ip = ip.strip()
    if not ip:
        return None
    # 明确拒绝 shell 元字符与 URL 形态
    if re.search(r"[;&|`$()<>\"'\\ \t\n\r]", ip):
        return None
    try:
        if "/" in ip:
            return str(ipaddress.ip_network(ip, strict=False))
        return str(ipaddress.ip_address(ip))
    except ValueError:
        return None


_IPSET_AVAILABLE = None

def is_ipset_available():
    global _IPSET_AVAILABLE
    if _IPSET_AVAILABLE is not None:
        return _IPSET_AVAILABLE
    try:
        res = subprocess.run(["ipset", "--version"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        _IPSET_AVAILABLE = (res.returncode == 0)
    except Exception:
        _IPSET_AVAILABLE = False
    return _IPSET_AVAILABLE


def _ensure_ipset_timeout_set(set_name, is_ipv6=False):
    """确保 ipset 集合存在且支持 timeout 参数。若已存在且不支持 timeout 则平滑无感 swap 升级。"""
    try:
        tmp_name = f"pg_tmp_{int(time.time()*1000)%100000}"
        create_args = ["hash:ip", "maxelem", "1000000", "timeout", "2147483"]
        if is_ipv6:
            create_args = ["hash:ip", "family", "inet6", "maxelem", "1000000", "timeout", "2147483"]
        
        # 探测现有 set 是否支持 timeout
        probe = subprocess.run(["ipset", "list", set_name], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, universal_newlines=True)
        if probe.returncode == 0:
            if "timeout" in probe.stdout:
                return True
            # 不支持 timeout，创建临时 timeout 集合并通过内核原子 swap 升级，避免中断
            subprocess.run(["ipset", "create", tmp_name] + create_args + ["-exist"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(["ipset", "swap", set_name, tmp_name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(["ipset", "destroy", tmp_name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return True
        else:
            # 集合不存在，直接创建
            res = subprocess.run(["ipset", "create", set_name] + create_args + ["-exist"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return res.returncode == 0
    except Exception:
        return False


def init_firewall_ipset():
    """初始化 ipset 哈希表并在 iptables / ip6tables INPUT 链首行挂载单一规则，实现 O(1) 百万级黑名单与内核级动态 timeout 自动老化。"""
    if not is_ipset_available():
        return False
    try:
        # 1. 创建并升级 IPv4 与 IPv6 黑名单 ipset 集合 (支持 hash:ip 与 timeout)
        _ensure_ipset_timeout_set("portguard_blacklist_v4", is_ipv6=False)
        _ensure_ipset_timeout_set("portguard_blacklist_v6", is_ipv6=True)

        # 2. 在 iptables INPUT 顶层挂载集合匹配丢弃规则 (存在则不重复添加)
        check_v4 = subprocess.run(["iptables", "-C", "INPUT", "-m", "set", "--match-set", "portguard_blacklist_v4", "src", "-j", "DROP"],
                                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if check_v4.returncode != 0:
            subprocess.run(["iptables", "-I", "INPUT", "-m", "set", "--match-set", "portguard_blacklist_v4", "src", "-j", "DROP"],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        # 3. 在 ip6tables INPUT 顶层挂载集合匹配丢弃规则
        check_v6 = subprocess.run(["ip6tables", "-C", "INPUT", "-m", "set", "--match-set", "portguard_blacklist_v6", "src", "-j", "DROP"],
                                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if check_v6.returncode != 0:
            subprocess.run(["ip6tables", "-I", "INPUT", "-m", "set", "--match-set", "portguard_blacklist_v6", "src", "-j", "DROP"],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
        # 4. 强制从黑名单与防火墙解封所有基础设施 IP 与 Cloudflare 节点
        conn = get_db()
        c = conn.cursor()
        c.execute("SELECT ip, ban_expire FROM blacklist")
        black_rows = c.fetchall()
        conn.close()

        now_ts = int(time.time())
        restore_v4 = []
        restore_v6 = []

        for row in black_rows:
            chk_ip = row["ip"]
            if is_infrastructure_or_cdn_ip(chk_ip):
                unban_ip_core(chk_ip)
                continue

            ip_val = validate_ip(chk_ip)
            if not ip_val:
                continue

            # 计算剩余老化秒数
            b_exp = row["ban_expire"]
            if b_exp and b_exp > now_ts:
                remain = min(2147483, max(60, b_exp - now_ts))
            else:
                remain = 2147483

            try:
                addr_obj = ipaddress.ip_address(ip_val)
                if addr_obj.version == 6:
                    restore_v6.append(f"add portguard_blacklist_v6 {ip_val} timeout {remain} -exist\n")
                else:
                    restore_v4.append(f"add portguard_blacklist_v4 {ip_val} timeout {remain} -exist\n")
            except Exception:
                pass

        for safe_ip in PUBLIC_INFRASTRUCTURE_IPS:
            unban_ip_core(safe_ip)

        # 5. 高性能流式批量管道注入 ipset restore，0.01 秒极速恢复数万黑名单
        if restore_v4:
            try:
                p4 = subprocess.Popen(["ipset", "restore"], stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                p4.communicate("".join(restore_v4).encode("utf-8"))
            except Exception:
                pass

        if restore_v6:
            try:
                p6 = subprocess.Popen(["ipset", "restore"], stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                p6.communicate("".join(restore_v6).encode("utf-8"))
            except Exception:
                pass

        return True
    except Exception as e:
        print(f"[IPSET] 初始化异常: {e}")
        return False


def flush_firewall_blocks():
    """精准排空 PortGuard 自己下发的封禁拦截：清空 ipset 黑名单集合，并精准移除数据库中登记的黑洞路由与 iptables 规则 (杜绝冲掉外部程序的黑洞路由)"""
    try:
        # 1. 清空专属 ipset 集合
        if is_ipset_available():
            subprocess.run(["ipset", "flush", "portguard_blacklist_v4"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(["ipset", "flush", "portguard_blacklist_v6"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        # 2. 精准查询 PortGuard 自身记录的黑名单并逐项解封底层路由与 iptables
        conn = get_db()
        c = conn.cursor()
        c.execute("SELECT ip FROM blacklist")
        for row in c.fetchall():
            b_ip = row["ip"]
            if not b_ip:
                continue
            try:
                if "/" in b_ip:
                    net_obj = ipaddress.ip_network(b_ip, strict=False)
                    is_v6 = net_obj.version == 6
                    fw_tool = "ip6tables" if is_v6 else "iptables"
                    route_cmd = ["ip", "-6", "route", "del", "blackhole", str(net_obj)] if is_v6 else ["ip", "route", "del", "blackhole", str(net_obj)]
                    subprocess.run(route_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    subprocess.run([fw_tool, "-D", "INPUT", "-s", str(net_obj), "-j", "DROP"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                else:
                    addr_obj = ipaddress.ip_address(b_ip)
                    is_v6 = addr_obj.version == 6
                    mask = "/128" if is_v6 else "/32"
                    fw_tool = "ip6tables" if is_v6 else "iptables"
                    route_cmd = ["ip", "-6", "route", "del", "blackhole", f"{b_ip}{mask}"] if is_v6 else ["ip", "route", "del", "blackhole", f"{b_ip}{mask}"]
                    subprocess.run(route_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    subprocess.run([fw_tool, "-D", "INPUT", "-s", b_ip, "-j", "DROP"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except Exception:
                pass
        conn.close()
    except Exception:
        pass


_BLACKLIST_IPS_CACHE = None
_BLACKLIST_IPS_CACHE_TIME = 0.0
_BLACKLIST_IPS_LOCK = threading.Lock()

def get_blacklisted_ips_set():
    """获取内存级快速黑名单 IP 集合（5秒缓存），用于网络层嗅探毫秒级阻断与排除"""
    global _BLACKLIST_IPS_CACHE, _BLACKLIST_IPS_CACHE_TIME
    now = time.time()
    if _BLACKLIST_IPS_CACHE is not None and (now - _BLACKLIST_IPS_CACHE_TIME < 5.0):
        return _BLACKLIST_IPS_CACHE
    with _BLACKLIST_IPS_LOCK:
        if _BLACKLIST_IPS_CACHE is not None and (now - _BLACKLIST_IPS_CACHE_TIME < 5.0):
            return _BLACKLIST_IPS_CACHE
        try:
            conn = get_db()
            c = conn.cursor()
            c.execute("SELECT ip FROM blacklist")
            _BLACKLIST_IPS_CACHE = {row[0] for row in c.fetchall() if row[0]}
            _BLACKLIST_IPS_CACHE_TIME = now
            conn.close()
        except Exception:
            if _BLACKLIST_IPS_CACHE is None:
                _BLACKLIST_IPS_CACHE = set()
        return _BLACKLIST_IPS_CACHE


def ban_ip_firewall(ip, expire_seconds=None):
    """下发内核拦截：优先写入带 timeout 的 ipset 集合并下发黑洞路由，内核自动到期老化，降级兼容原生 iptables。"""
    valid_ip = validate_ip(ip)
    if not valid_ip or is_infrastructure_or_cdn_ip(valid_ip) or ip_in_whitelist(valid_ip):
        return
    ip = valid_ip
    try:
        addr_obj = ipaddress.ip_address(ip)
        is_ipv6 = addr_obj.version == 6
        set_name = "portguard_blacklist_v6" if is_ipv6 else "portguard_blacklist_v4"
        fw_tool = "ip6tables" if is_ipv6 else "iptables"
        save_tool = "ip6tables-save" if is_ipv6 else "iptables-save"
        mask = "/128" if is_ipv6 else "/32"

        # 1. 优先使用 ipset O(1) 集合 (带内核动态 timeout 自动老化)
        if is_ipset_available():
            timeout_val = min(2147483, max(60, int(expire_seconds))) if expire_seconds and expire_seconds > 0 else 2147483
            res = subprocess.run(["ipset", "add", set_name, ip, "timeout", str(timeout_val), "-exist"],
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if res.returncode != 0:
                _ensure_ipset_timeout_set(set_name, is_ipv6=is_ipv6)
                subprocess.run(["ipset", "add", set_name, ip, "timeout", str(timeout_val), "-exist"],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        else:
            # 降级：检查并插入 iptables
            chk = subprocess.run([fw_tool, "-C", "INPUT", "-s", ip, "-j", "DROP"],
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if chk.returncode != 0:
                subprocess.run([fw_tool, "-I", "INPUT", "-s", ip, "-j", "DROP"],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                run_firewall_cmd(save_tool)

        # 2. 下发黑洞路由
        if is_ipv6:
            subprocess.run(["ip", "-6", "route", "add", "blackhole", f"{ip}{mask}"],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        else:
            subprocess.run(["ip", "route", "add", "blackhole", f"{ip}{mask}"],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception:
        pass


class ThreatScoreEngine:
    """动态威胁风险评分引擎 (带时间半衰期衰减模型，防止 NAT 误杀并捕获慢速探测)"""
    def __init__(self):
        self._lock = threading.Lock()
        self._scores = {}  # ip -> {"score": float, "last_time": float, "count": int}

    def add_score(self, ip, points, reason=""):
        now = time.time()
        with self._lock:
            if ip not in self._scores:
                self._scores[ip] = {"score": 0.0, "last_time": now, "count": 0}
            entry = self._scores[ip]
            
            # 衰减计算：每 60 秒衰减 20% 分值
            elapsed = now - entry["last_time"]
            if elapsed > 10:
                decay_factor = max(0.0, 1.0 - (elapsed / 300.0))
                entry["score"] = entry["score"] * decay_factor
            
            entry["score"] += points
            entry["last_time"] = now
            entry["count"] += 1
            
            # 定期清理超时记录
            if len(self._scores) > 5000:
                cutoff = now - 3600
                self._scores = {k: v for k, v in self._scores.items() if v["last_time"] > cutoff}
                
            return entry["score"], entry["count"]

    def get_score(self, ip):
        with self._lock:
            if ip not in self._scores:
                return 0.0
            entry = self._scores[ip]
            now = time.time()
            elapsed = now - entry["last_time"]
            decay_factor = max(0.0, 1.0 - (elapsed / 300.0))
            return max(0.0, entry["score"] * decay_factor)

    def reset_score(self, ip):
        with self._lock:
            self._scores.pop(ip, None)


_THREAT_ENGINE = ThreatScoreEngine()


def run_firewall_cmd(*args):
    """参数数组方式执行 iptables / ip 命令，杜绝 shell 注入。"""
    try:
        subprocess.run(list(args), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception:
        pass


def get_local_ips():
    """获取本机所有 IP 地址集合（包括回环、公网及局域网/Docker/虚拟网卡 IP）"""
    ips = {"127.0.0.1", "0.0.0.0", "::1"}
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ips.add(s.getsockname()[0])
        s.close()
    except Exception:
        pass
    try:
        res = socket.gethostbyname_ex(socket.gethostname())
        for ip in res[2]:
            ips.add(ip)
    except Exception:
        pass
    try:
        res = subprocess.run(["ip", "-o", "addr", "show"], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, universal_newlines=True)
        if res.returncode == 0 and res.stdout:
            out = res.stdout
        else:
            res_if = subprocess.run(["ifconfig", "-a"], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, universal_newlines=True)
            out = res_if.stdout or ""
        for line in out.splitlines():
            m = re.search(r'inet6?\s+([0-9a-fA-F\.\:]+)', line)
            if m:
                clean_ip = m.group(1).split('/')[0].strip()
                if clean_ip:
                    ips.add(clean_ip)
    except Exception:
        pass
    return ips


from collectors.packet import ParsedPacket, parse_packet, parse_port_range

def normalize_trap_item(item):
    if isinstance(item, int):
        matched = next((x for x in DEFAULT_CONFIG["trap_ports"] if x["port"] == item), None)
        if matched:
            return normalize_trap_item(matched)
        return {
            "family": "ipv4",
            "address": "",
            "port": item,
            "port_start": item,
            "port_end": item,
            "protocol": "tcp",
            "strategy": "accept",
            "description": PORT_DESCRIPTIONS.get(item, f"TCP/{item}"),
            "name": PORT_DESCRIPTIONS.get(item, f"TCP/{item}"),
            "enabled": True,
            "level": "高危",
            "category": "custom"
        }
    
    if not isinstance(item, dict):
        return None
    
    # 提取端口 (支持 port / prot / dst_port)
    raw_port = item.get("port", item.get("prot", item.get("dst_port")))
    if raw_port is None or str(raw_port).strip() == "":
        return None
    
    p_info = parse_port_range(raw_port)
    if not p_info:
        return None
    start_p, end_p, display_port = p_info
        
    # 提取协议 (protocol / proto)
    protocol = str(item.get("protocol", item.get("proto", "tcp"))).strip().lower()
    if protocol not in ("tcp", "udp"):
        protocol = "tcp"
        
    # 提取策略与开关 (strategy / enabled / status)
    raw_strat = item.get("strategy", item.get("enabled", item.get("status", "accept")))
    if isinstance(raw_strat, bool):
        enabled = raw_strat
    elif isinstance(raw_strat, str):
        s_lower = raw_strat.strip().lower()
        if s_lower in ("accept", "enabled", "enable", "open", "true", "启用", "允许", "1"):
            enabled = True
        elif s_lower in ("reject", "drop", "disabled", "disable", "close", "false", "停用", "禁止", "0"):
            enabled = False
        else:
            enabled = True
    else:
        enabled = bool(raw_strat)
        
    strategy = "accept" if enabled else "reject"
    
    # 提取描述 (description / desc / name / remark)
    desc = item.get("description", item.get("desc", item.get("name", item.get("remark", ""))))
    if not desc:
        if start_p == end_p:
            desc = PORT_DESCRIPTIONS.get(start_p, f"{protocol.upper()}/{start_p}")
        else:
            desc = f"{protocol.upper()} 端口段 ({start_p}-{end_p})"
    desc = str(desc).strip()
    
    # 类别判定
    cat = item.get("category", "")
    if not cat:
        if start_p == end_p:
            if start_p in (80, 443, 8080, 8888, 8000, 8848, 8088):
                cat = "web"
            elif start_p in (3389, 5900, 5901, 22):
                cat = "rdp"
            elif start_p in (1433, 3306, 6379, 27017, 5432, 9200):
                cat = "db"
            elif start_p in (445, 135, 139):
                cat = "smb"
            elif start_p in (21, 20):
                cat = "ftp"
            elif start_p in (23,):
                cat = "telnet"
            else:
                cat = "custom"
        else:
            cat = "custom"
            
    # 威胁等级判定
    level = item.get("level", "")
    if not level:
        if start_p == end_p and start_p in (445, 3389, 6379, 1433):
            level = "极高危"
        elif start_p == end_p and start_p in (139, 8888, 8080):
            level = "中危"
        else:
            level = "高危"
            
    family = item.get("family", "ipv4")
    address = item.get("address", "")
    is_business = bool(item.get("is_business", False) or item.get("trap_business", False))
    
    return {
        "family": family,
        "address": address,
        "port": display_port,
        "port_start": start_p,
        "port_end": end_p,
        "protocol": protocol,
        "strategy": strategy,
        "description": desc,
        "name": desc,
        "enabled": enabled,
        "level": level,
        "category": cat,
        "is_business": is_business,
        "trap_business": is_business
    }

def get_db():
    conn = sqlite3.connect(DB_PATH, timeout=20)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA busy_timeout=15000;")
        conn.execute("PRAGMA synchronous=NORMAL;")
    except Exception:
        pass
    return conn

def init_db():
    dir_name = os.path.dirname(DB_PATH)
    if dir_name:
        try:
            os.makedirs(dir_name, exist_ok=True)
        except Exception:
            pass
    conn = sqlite3.connect(DB_PATH, timeout=20)
    cursor = conn.cursor()
    try:
        cursor.execute("PRAGMA journal_mode=WAL;")
        cursor.execute("PRAGMA busy_timeout=15000;")
        cursor.execute("PRAGMA synchronous=NORMAL;")
    except Exception:
        pass
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip TEXT NOT NULL,
        port INTEGER NOT NULL,
        proto TEXT DEFAULT 'TCP',
        port_name TEXT,
        category TEXT,
        level TEXT,
        country TEXT,
        region TEXT,
        city TEXT,
        isp TEXT,
        attack_time TEXT NOT NULL,
        timestamp INTEGER NOT NULL,
        status TEXT DEFAULT 'BANNED',
        hit_count INTEGER DEFAULT 1
    )
    """)
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_ip ON events(ip)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_timestamp ON events(timestamp)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_port ON events(port)")
    
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS blacklist (
        ip TEXT PRIMARY KEY,
        reason TEXT,
        country TEXT,
        level TEXT,
        ban_time TEXT,
        timestamp INTEGER,
        ban_expire INTEGER,
        source_node TEXT DEFAULT '本机'
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS unbanned_ips (
        ip TEXT PRIMARY KEY,
        unban_time TEXT,
        timestamp INTEGER,
        source_node TEXT
    )
    """)
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_unbanned_ts ON unbanned_ips(timestamp)")
    
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS whitelist (
        ip TEXT PRIMARY KEY,
        remark TEXT,
        create_time TEXT
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS access_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip TEXT NOT NULL,
        domain TEXT DEFAULT '',
        method TEXT NOT NULL,
        path TEXT NOT NULL,
        status_code INTEGER DEFAULT 200,
        user_agent TEXT,
        country TEXT,
        region TEXT,
        city TEXT,
        isp TEXT,
        access_time TEXT NOT NULL,
        timestamp INTEGER NOT NULL
    )
    """)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS port_access_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip TEXT NOT NULL,
        port INTEGER NOT NULL,
        proto TEXT DEFAULT 'TCP',
        port_name TEXT,
        country TEXT,
        region TEXT,
        city TEXT,
        isp TEXT,
        action TEXT DEFAULT 'INTERCEPTED',
        access_time TEXT NOT NULL,
        timestamp INTEGER NOT NULL
    )
    """)
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_port_access_time ON port_access_logs(timestamp)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_port_access_ip ON port_access_logs(ip)")
    
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS http_traps (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        rule_id TEXT UNIQUE,
        name TEXT NOT NULL,
        match_type TEXT NOT NULL,
        pattern TEXT DEFAULT '',
        threshold INTEGER DEFAULT 6,
        window INTEGER DEFAULT 30,
        action TEXT DEFAULT 'ban',
        level TEXT DEFAULT '极高危',
        enabled INTEGER DEFAULT 1,
        description TEXT DEFAULT '',
        created_at TEXT NOT NULL
    )
    """)
    # 自动补全默认的请求特征与测绘防护规则（已存在则忽略）
    now_dt = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    for ht in DEFAULT_HTTP_TRAPS:
        cursor.execute("""
        INSERT OR IGNORE INTO http_traps (rule_id, name, match_type, pattern, threshold, window, action, level, enabled, description, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (ht["rule_id"], ht["name"], ht["match_type"], ht["pattern"], ht["threshold"], ht["window"], ht["action"], ht["level"], ht["enabled"], ht["description"], now_dt))

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS hidden_ips (
        ip TEXT PRIMARY KEY,
        country TEXT,
        region TEXT,
        city TEXT,
        isp TEXT,
        remark TEXT DEFAULT '',
        create_time TEXT,
        timestamp INTEGER
    )
    """)
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_hidden_ip ON hidden_ips(ip)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_access_logs_ip ON access_logs(ip, id DESC)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_blacklist_ts ON blacklist(timestamp DESC)")

    # 自动列自适应补充（迁移旧库）
    try:
        cursor.execute("ALTER TABLE access_logs ADD COLUMN domain TEXT DEFAULT ''")
    except Exception:
        pass
    try:
        cursor.execute("ALTER TABLE blacklist ADD COLUMN country TEXT")
    except Exception:
        pass
    try:
        cursor.execute("ALTER TABLE blacklist ADD COLUMN level TEXT")
    except Exception:
        pass
    try:
        cursor.execute("ALTER TABLE blacklist ADD COLUMN ban_expire INTEGER")
    except Exception:
        pass
    try:
        cursor.execute("ALTER TABLE blacklist ADD COLUMN source_node TEXT DEFAULT '本机'")
    except Exception:
        pass
    try:
        cursor.execute("ALTER TABLE events ADD COLUMN category TEXT")
    except Exception:
        pass
    try:
        cursor.execute("ALTER TABLE events ADD COLUMN level TEXT")
    except Exception:
        pass

    try:
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_access_logs_domain ON access_logs(domain)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_access_logs_ts ON access_logs(timestamp)")
    except Exception:
        pass
        
    conn.commit()
    conn.close()
    heal_cluster_geo_history()


def heal_cluster_geo_history():
    """后台自愈：将历史上所有未解析或标记为 '分析中...'/‘集群联防’/‘未知地域’ 的 IP 归属地，重新解析为真实国家/省市地理位置，并修复历史记录中遗留的 0 端口"""
    def _worker():
        try:
            time.sleep(1.0)
            conn = get_db()
            c = conn.cursor()
            # 修复历史 0 端口
            c.execute("UPDATE events SET port = 443, proto = 'TCP' WHERE port = 0 AND (port_name LIKE '%Web%' OR port_name LIKE '%HTTP%' OR port_name LIKE '%IP直连%' OR port_name LIKE '%诱捕%')")
            c.execute("UPDATE events SET proto = 'TCP' WHERE proto = 'MESH'")
            conn.commit()
            conn.close()

            unresolvable_cache = {}  # 记录近期解析失败的 IP 及时间戳，避免死循环紧轮询

            while True:
                try:
                    conn = get_db()
                    c = conn.cursor()
                    # 1. 扫描 events 表中待自愈归属地或运营商记录
                    c.execute("SELECT DISTINCT ip FROM events WHERE country IN ('分析中...', '集群联防', '未知地域', '', 'None', 'null') OR country IS NULL OR isp IN ('分析中...', '', '0', 'None', 'null') OR isp IS NULL LIMIT 200")
                    event_ips = [r[0] for r in c.fetchall() if r[0]]

                    # 2. 扫描 blacklist 表中待自愈归属地记录
                    c.execute("SELECT DISTINCT ip FROM blacklist WHERE country IN ('分析中...', '集群联防', '未知地域', '', 'None', 'null') OR country IS NULL LIMIT 200")
                    bl_ips = [r[0] for r in c.fetchall() if r[0]]

                    # 3. 扫描 port_access_logs 表待自愈记录
                    c.execute("SELECT DISTINCT ip FROM port_access_logs WHERE country IN ('分析中...', '未知地域', '', 'None', 'null') OR country IS NULL LIMIT 200")
                    pal_ips = [r[0] for r in c.fetchall() if r[0]]

                    conn.close()

                    now = time.time()
                    # 过滤掉近期已尝试解析且失败的 IP（30 分钟冷却期）
                    target_ips = [
                        ip for ip in set(event_ips + bl_ips + pal_ips)
                        if (now - unresolvable_cache.get(ip, 0)) > 1800
                    ]

                    if not target_ips:
                        # 当前无待修复记录或所有记录处于冷却中，休眠 30 秒后进行下一轮轻量巡检
                        time.sleep(30.0)
                        continue

                    # 单批次最多处理 50 个，避免单次循环阻塞过长
                    for ip in target_ips[:50]:
                        geo = _GEO_CACHE.get(ip) or resolve_ip_geo_local(ip)
                        if not geo or not geo.get("country") or geo.get("country") in ("集群联防", "未知地域", "分析中...", "", None):
                            geo = resolve_ip_geo(ip)
                        if geo and geo.get("country") and geo.get("country") not in ("分析中...", "集群联防", "", None):
                            u_conn = get_db()
                            u_c = u_conn.cursor()
                            c_val = geo.get("country") or "公网节点"
                            r_val = geo.get("region", "")
                            ci_val = geo.get("city", "")
                            isp_val = geo.get("isp", "")
                            u_c.execute("UPDATE events SET country = ?, region = ?, city = ?, isp = ? WHERE ip = ?",
                                      (c_val, r_val, ci_val, isp_val, ip))
                            u_c.execute("UPDATE blacklist SET country = ? WHERE ip = ?", (c_val, ip))
                            u_c.execute("UPDATE port_access_logs SET country = ?, region = ?, city = ?, isp = ? WHERE ip = ?",
                                      (c_val, r_val, ci_val, isp_val, ip))
                            u_conn.commit()
                            u_conn.close()
                            if ip in unresolvable_cache:
                                del unresolvable_cache[ip]
                        else:
                            unresolvable_cache[ip] = now
                        time.sleep(0.02)

                    if len(unresolvable_cache) > 2000:
                        unresolvable_cache = {k: v for k, v in unresolvable_cache.items() if (now - v) <= 1800}

                    # 每轮批次处理结束后休眠 10 秒，防止紧轮询跑满 CPU
                    time.sleep(10.0)
                except Exception:
                    time.sleep(10.0)
        except Exception:
            pass
    threading.Thread(target=_worker, daemon=True, name="GeoHealWorker").start()

def get_hidden_ips_set():
    """获取所有隐藏 IP 的集合"""
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT ip FROM hidden_ips")
        rows = cursor.fetchall()
        conn.close()
        return set(r[0] for r in rows if r[0])
    except Exception:
        return set()

def get_hidden_ips():
    """获取所有隐藏 IP 记录列表"""
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT ip, country, region, city, isp, remark, create_time, timestamp FROM hidden_ips ORDER BY timestamp DESC")
        rows = [dict(r) for r in cursor.fetchall()]
        conn.close()
        return rows
    except Exception:
        return []

def add_hidden_ip(ip, remark=""):
    """添加 IP 到隐藏列表"""
    ip = validate_ip(ip)
    if not ip:
        return False, "无效的 IP 地址"
    try:
        geo = resolve_ip_geo(ip) or {}
        now_dt = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        now_ts = int(time.time())
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("""
        INSERT OR REPLACE INTO hidden_ips (ip, country, region, city, isp, remark, create_time, timestamp)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (ip, geo.get("country", "未知地域"), geo.get("region", ""), geo.get("city", ""), geo.get("isp", ""), remark, now_dt, now_ts))
        conn.commit()
        conn.close()
        return True, f"已成功将 IP {ip} 加入隐藏列表"
    except Exception as e:
        return False, str(e)

def remove_hidden_ip(ip):
    """从隐藏列表中移除 IP (恢复显示)"""
    ip = validate_ip(ip)
    if not ip:
        return False, "无效的 IP 地址"
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM hidden_ips WHERE ip = ?", (ip,))
        conn.commit()
        conn.close()
        return True, f"已从隐藏列表中移除 IP {ip}"
    except Exception as e:
        return False, str(e)

def clear_hidden_ips():
    """清空所有隐藏 IP"""
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM hidden_ips")
        conn.commit()
        conn.close()
        return True, "已清空所有隐藏 IP"
    except Exception as e:
        return False, str(e)

def get_http_traps():
    """获取所有配置的 HTTP 请求特征与防扫描策略"""
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT id, rule_id, name, match_type, pattern, threshold, window, action, level, enabled, description, created_at FROM http_traps ORDER BY id ASC")
        rows = cursor.fetchall()
        conn.close()
        rules = []
        for r in rows:
            rules.append({
                "id": r[0],
                "rule_id": r[1],
                "name": r[2],
                "match_type": r[3],
                "pattern": r[4] or "",
                "threshold": r[5] or 6,
                "window": r[6] or 30,
                "action": r[7] or "ban",
                "level": r[8] or "极高危",
                "enabled": bool(r[9]),
                "description": r[10] or "",
                "created_at": r[11] or ""
            })
        return rules
    except Exception as e:
        return [dict(r) for r in DEFAULT_HTTP_TRAPS]

_IP_404_RATE_CACHE = {}
_IP_404_LOCK = threading.Lock()

_CRAWLER_VERIFY_CACHE = {}
_CRAWLER_CACHE_LOCK = threading.Lock()

def verify_search_engine_crawler(ip, user_agent):
    """
    RFC 标准搜索引擎爬虫反向 DNS (PTR) 双向校验：
    防止黑客伪造 Googlebot / Baiduspider / Bingbot 等 UA 逃逸诱捕。
    """
    ua = (user_agent or "").lower()
    crawler_name = None
    expected_suffixes = []

    if "googlebot" in ua:
        crawler_name = "Googlebot"
        expected_suffixes = [".googlebot.com", ".google.com"]
    elif "baiduspider" in ua:
        crawler_name = "Baiduspider"
        expected_suffixes = [".baidu.com", ".baidu.jp"]
    elif "bingbot" in ua or "msnbot" in ua:
        crawler_name = "Bingbot"
        expected_suffixes = [".bing.com", ".search.msn.com"]
    elif "yandexbot" in ua:
        crawler_name = "YandexBot"
        expected_suffixes = [".yandex.ru", ".yandex.net", ".yandex.com"]

    if not crawler_name:
        return True, None

    cache_key = (ip, crawler_name)
    with _CRAWLER_CACHE_LOCK:
        if cache_key in _CRAWLER_VERIFY_CACHE:
            cached_time, is_valid, msg = _CRAWLER_VERIFY_CACHE[cache_key]
            if time.time() - cached_time < 3600:
                return is_valid, msg

    try:
        host, _, _ = socket.gethostbyaddr(ip)
        host = host.lower()
        if not any(host.endswith(sfx) for sfx in expected_suffixes):
            res = (False, f"冒充 {crawler_name} 搜索引擎爬虫 (PTR: {host})")
        else:
            resolved_ips = socket.gethostbyname_ex(host)[2]
            if ip not in resolved_ips:
                res = (False, f"冒充 {crawler_name} 爬虫 (PTR解析IP不一致: {host})")
            else:
                res = (True, crawler_name)
    except Exception:
        res = (False, f"伪造 {crawler_name} 爬虫 (无权威PTR反向记录)")

    with _CRAWLER_CACHE_LOCK:
        _CRAWLER_VERIFY_CACHE[cache_key] = (time.time(), res[0], res[1])
    return res


_CLUSTER_NONCE_CACHE = {}  # 格式: {nonce_str: consume_timestamp_int}
_CLUSTER_NONCE_LOCK = threading.Lock()

def calc_body_hash(body):
    """计算集群请求体 SHA256 哈希十六进制字符串 (统一空负载与类型转换)"""
    if isinstance(body, str):
        body = body.encode('utf-8')
    elif not isinstance(body, (bytes, bytearray)):
        body = b""
    return hashlib.sha256(body).hexdigest()

def generate_cluster_token(sign_target, secret, body=b"", timestamp=None, nonce=None):
    """
    生成带时间戳、防重放随机数与请求体完整性 SHA256 哈希的高安全集群 HMAC-SHA256 复合签名 Token
    结构: v2.<timestamp>.<nonce>.<signature>
    消息体: <sign_target>:<body_hash>:<timestamp>:<nonce>
    """
    if timestamp is None:
        timestamp = int(time.time())
    if nonce is None:
        import uuid
        nonce = uuid.uuid4().hex[:12]
    body_hash = calc_body_hash(body)
    msg = f"{sign_target}:{body_hash}:{timestamp}:{nonce}"
    sig = hmac.new(secret.encode('utf-8'), msg.encode('utf-8'), hashlib.sha256).hexdigest()
    return f"v2.{timestamp}.{nonce}.{sig}"

def verify_cluster_token(sign_target, token, secret, body=b""):
    """
    验证集群 Token，严格防范重放、篡改与中间人窃听攻击：
    1. 必须为具备时间窗口与 Nonce 的 v2 规范 Token (彻底废除无防重放能力的静态签名)
    2. 严格时钟容差窗口检查 (±90秒以内有效)
    3. 请求体 SHA256 哈希一致性校验 (杜绝在网络路径上篡改 IP/动作等任何负载)
    4. 采用带 TTL 的 Nonce 消费字典，先按过期时间清理历史 Nonce，再记录当前 Nonce (杜绝重放竞态)
    """
    if not secret or not token:
        return False
    token_str = str(token).strip()
    if not token_str.startswith("v2."):
        return False

    parts = token_str.split(".")
    if len(parts) != 4:
        return False

    try:
        ts = int(parts[1])
        nonce = parts[2]
        sig = parts[3]
        now = int(time.time())

        # 1. 严格时间窗口检查 (±90秒)
        if abs(now - ts) > 90:
            return False

        # 2. 验证签名一致性 (sign_target + body_hash + ts + nonce)
        body_hash = calc_body_hash(body)
        msg = f"{sign_target}:{body_hash}:{ts}:{nonce}"
        expected_sig = hmac.new(secret.encode('utf-8'), msg.encode('utf-8'), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected_sig, sig):
            return False

        # 3. Nonce 防重放检查与基于 TTL 的精准清理
        with _CLUSTER_NONCE_LOCK:
            # 优先清理超过 180 秒的历史过期 Nonce
            expire_before = now - 180
            expired = [k for k, v in _CLUSTER_NONCE_CACHE.items() if v < expire_before]
            for k in expired:
                del _CLUSTER_NONCE_CACHE[k]

            # 校验当前 Nonce 是否已被消费
            if nonce in _CLUSTER_NONCE_CACHE:
                return False

            # 标记已消费
            _CLUSTER_NONCE_CACHE[nonce] = now

        return True
    except Exception:
        return False


def validate_cluster_target(ip_or_host):
    """
    集群目标地址 SSRF 安全校验：
    严格禁止本地回环 (127.0.0.0/8, ::1)、0.0.0.0、云厂商元数据地址 (169.254.169.254 / link-local)、
    保留网段 (240.0.0.0/4 等)、组播地址以及格式异常的目标，杜绝 SSRF 内网及本地服务扫描。
    返回 (is_valid, clean_host, err_msg)
    """
    if not ip_or_host or not isinstance(ip_or_host, str):
        return False, "", "节点目标地址不能为空"

    host = ip_or_host.strip()
    if "://" in host:
        host = host.split("://", 1)[1]
    if "/" in host:
        host = host.split("/", 1)[0]
    if ":" in host:
        host = host.split(":", 1)[0]
    host = host.strip()

    if not host or not re.match(r'^[a-zA-Z0-9.\-_]+$', host):
        return False, "", "非法的节点主机名或IP字符"

    # 若是 IP 地址直接执行网段安全过滤
    try:
        ip_obj = ipaddress.ip_address(host)
        if ip_obj.is_loopback:
            return False, "", "SSRF安全拦截：禁止添加本地回环地址 (127.0.0.0/8 或 ::1) 作为集群节点"
        if ip_obj.is_unspecified:
            return False, "", "SSRF安全拦截：禁止添加 0.0.0.0 作为集群节点"
        if ip_obj.is_link_local:
            return False, "", "SSRF安全拦截：禁止添加链路本地地址 (Link-local / 169.254.0.0/16) 作为集群节点"
        if ip_obj.is_multicast:
            return False, "", "SSRF安全拦截：禁止添加组播地址作为集群节点"
        if ip_obj.is_reserved:
            return False, "", "SSRF安全拦截：禁止添加保留地址段作为集群节点"
        if str(ip_obj) == "169.254.169.254":
            return False, "", "SSRF安全拦截：禁止访问云服务器元数据服务 (Metadata Service)"
    except ValueError:
        # 主机名/域名模式：过滤危险内网标识
        h_lower = host.lower()
        if h_lower in ("localhost", "ip6-localhost", "ip6-loopback", "metadata.google.internal"):
            return False, "", "SSRF安全拦截：禁止指向本机或云元数据域名"
        # 尝试快速解析域名检查是否解析到了回环或元数据
        try:
            resolved_addrs = socket.getaddrinfo(host, None)
            for item in resolved_addrs:
                resolved_ip = item[4][0]
                ip_obj = ipaddress.ip_address(resolved_ip)
                if ip_obj.is_loopback:
                    return False, "", f"SSRF安全拦截：域名解析到本地回环地址 ({resolved_ip})"
                if ip_obj.is_link_local:
                    return False, "", f"SSRF安全拦截：域名解析到链路本地地址 ({resolved_ip})"
                if ip_obj.is_unspecified:
                    return False, "", f"SSRF安全拦截：域名解析到未指定地址 ({resolved_ip})"
                if ip_obj.is_multicast or ip_obj.is_reserved:
                    return False, "", f"SSRF安全拦截：域名解析到组播或保留地址 ({resolved_ip})"
                if str(ip_obj) == "169.254.169.254":
                    return False, "", f"SSRF安全拦截：域名解析到云元数据服务 ({resolved_ip})"
        except Exception:
            pass

    return True, host, ""


def resolve_and_validate_target(host, port=None):
    """
    DNS Rebinding 与 SSRF 防御解析器：
    解析主机名并对解析到的 IP 进行严格安全校验。
    若通过，返回 (is_safe, resolved_ip, err_msg)；若校验失败则拒绝。
    返回的 resolved_ip 直接用于后续建立 HTTP 连接，杜绝二次 DNS 查询导致的重绑定攻击。
    """
    ok, clean_host, err_msg = validate_cluster_target(host)
    if not ok:
        return False, "", err_msg

    try:
        ipaddress.ip_address(clean_host)
        return True, clean_host, ""
    except ValueError:
        pass

    try:
        addrs = socket.getaddrinfo(clean_host, port or 80, socket.AF_UNSPEC, socket.SOCK_STREAM)
        if not addrs:
            return False, "", "无法解析对端主机名"
        chosen_ip = None
        for item in addrs:
            ip_str = item[4][0]
            ip_obj = ipaddress.ip_address(ip_str)
            if ip_obj.is_loopback or ip_obj.is_unspecified or ip_obj.is_link_local or ip_obj.is_multicast or ip_obj.is_reserved or str(ip_obj) == "169.254.169.254":
                return False, "", f"SSRF/DNS Rebinding 安全拦截：域名解析到内部敏感地址 ({ip_str})"
            if chosen_ip is None:
                chosen_ip = ip_str
        return True, chosen_ip, ""
    except Exception as ex:
        return False, "", f"域名解析失败: {ex}"


def normalize_cluster_node(node):
    """规范化协同节点数据结构，确保字段完整并兼容历史字符串格式"""
    if isinstance(node, dict):
        ip = str(node.get("ip", "")).strip()
        port = int(node.get("port", 9098) or 9098)
        remark = str(node.get("remark", "")).strip() or "协同节点"
        created_at = node.get("created_at") or time.strftime("%Y-%m-%d %H:%M:%S")
        status = node.get("status", "unknown")
        latency_ms = int(node.get("latency_ms", 0) or 0)
        country = node.get("country", "")
        return {
            "ip": ip,
            "port": port,
            "remark": remark,
            "created_at": created_at,
            "status": status,
            "latency_ms": latency_ms,
            "country": country
        }
    elif isinstance(node, str):
        s = node.strip()
        if not s:
            return None
        port = 9098
        if "://" in s:
            s = s.split("://", 1)[1]
        if "/" in s:
            s = s.split("/", 1)[0]
        if ":" in s:
            parts = s.split(":")
            s = parts[0]
            try:
                port = int(parts[1])
            except Exception:
                port = 9098
        return {
            "ip": s,
            "port": port,
            "remark": f"协同节点 ({s})",
            "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "status": "unknown",
            "latency_ms": 0,
            "country": ""
        }
    return None


def _send_cluster_msg(node, endpoint, payload, token):
    """向协同节点发送通信数据，直连安全验证的解析目标以杜绝 DNS Rebinding，自适应尝试目标端口及备用端口并支持自动重试"""
    if not node or not node.get("ip"):
        return False

    orig_host = str(node.get("ip", "")).strip()
    is_safe, target_ip, _ = resolve_and_validate_target(orig_host)
    if not is_safe:
        return False

    ports_to_try = []
    if node.get("port"):
        try:
            ports_to_try.append(int(node["port"]))
        except Exception:
            pass
    for p in (9098, 9099):
        if p not in ports_to_try:
            ports_to_try.append(p)

    for p in ports_to_try:
        headers = {
            "Content-Type": "application/json",
            "X-Cluster-Token": token,
            "User-Agent": "PortGuardMesh/2.0",
            "Host": f"{orig_host}:{p}"
        }
        for attempt in range(2):
            try:
                # 直连已安全校验的 target_ip，防止 DNS Rebinding 攻击
                target = f"http://{target_ip}:{p}{endpoint}"
                req = urllib.request.Request(target, data=payload, headers=headers)
                with urllib.request.urlopen(req, timeout=3.5) as resp:
                    if resp.status in (200, 201):
                        return True
            except Exception:
                if attempt == 0:
                    time.sleep(0.5)
                continue
    return False


def broadcast_cluster_ban(ip, reason, level, port=443, proto="TCP", category="web"):
    cfg = load_config()
    cluster_cfg = cfg.get("cluster_sync", {})
    if not cluster_cfg.get("enabled", False):
        return
    secret = cluster_cfg.get("cluster_secret", "").strip()
    nodes = cluster_cfg.get("cluster_nodes", [])
    if not secret or not nodes:
        return

    geo = _GEO_CACHE.get(ip) or resolve_ip_geo_local(ip) or {}
    payload = json.dumps({
        "ip": ip,
        "port": port,
        "proto": proto,
        "category": category,
        "reason": reason,
        "level": level,
        "country": geo.get("country", ""),
        "region": geo.get("region", ""),
        "city": geo.get("city", ""),
        "isp": geo.get("isp", ""),
        "source_node": cfg.get("node_name", socket.gethostname())
    }).encode("utf-8")
    token = generate_cluster_token(ip, secret, body=payload)

    for raw_node in nodes:
        node = normalize_cluster_node(raw_node)
        if not node or not node.get("ip"):
            continue
        _EXECUTOR.submit(_send_cluster_msg, node, "/api/cluster/sync_ban", payload, token)


def broadcast_cluster_unban(ip):
    """向集群协同节点广播解封 IP"""
    cfg = load_config()
    cluster_cfg = cfg.get("cluster_sync", {})
    if not cluster_cfg.get("enabled", False):
        return
    secret = cluster_cfg.get("cluster_secret", "").strip()
    nodes = cluster_cfg.get("cluster_nodes", [])
    if not secret or not nodes:
        return

    payload = json.dumps({
        "ip": ip,
        "source_node": cfg.get("node_name", socket.gethostname())
    }).encode("utf-8")
    token = generate_cluster_token(f"unban_{ip}", secret, body=payload)

    for raw_node in nodes:
        node = normalize_cluster_node(raw_node)
        if not node or not node.get("ip"):
            continue
        _EXECUTOR.submit(_send_cluster_msg, node, "/api/cluster/sync_unban", payload, token)


def broadcast_cluster_whitelist(action, data, remark=""):
    """
    向集群协同节点异步广播白名单操作 (add / delete / batch_add / sync_all)
    action: "add" | "delete" | "batch_add" | "sync_all"
    """
    cfg = load_config()
    cluster_cfg = cfg.get("cluster_sync", {})
    if not cluster_cfg.get("enabled", False):
        return
    secret = cluster_cfg.get("cluster_secret", "").strip()
    nodes = cluster_cfg.get("cluster_nodes", [])
    if not secret or not nodes:
        return

    sign_target = f"whitelist_{action}"
    payload = json.dumps({
        "action": action,
        "data": data,
        "remark": remark,
        "source_node": cfg.get("node_name", socket.gethostname())
    }).encode("utf-8")
    token = generate_cluster_token(sign_target, secret, body=payload)

    for raw_node in nodes:
        node = normalize_cluster_node(raw_node)
        if not node or not node.get("ip"):
            continue
        _EXECUTOR.submit(_send_cluster_msg, node, "/api/cluster/sync_whitelist", payload, token)


def clean_cluster_node_name(name):
    if not name:
        return "协同节点"
    s = str(name).strip()
    while s.startswith("集群 (") and s.endswith(")"):
        s = s[4:-1].strip()
    return s


def sync_cluster_mesh_state(target_node=None):
    """全量双向对齐集群节点的黑名单、已解封墓碑及白名单数据"""
    cfg = load_config()
    cluster_cfg = cfg.get("cluster_sync", {})
    if not cluster_cfg.get("enabled", False):
        return {"success": False, "msg": "集群联防协同功能未开启"}
    secret = cluster_cfg.get("cluster_secret", "").strip()
    nodes = cluster_cfg.get("cluster_nodes", [])
    if not secret or not nodes:
        return {"success": False, "msg": "当前未配置集群通信密钥或对端节点"}

    # 1. 准备本地黑名单及已解封墓碑数据
    conn = get_db()
    c = conn.cursor()
    c.execute("CREATE TABLE IF NOT EXISTS unbanned_ips (ip TEXT PRIMARY KEY, unban_time TEXT, timestamp INTEGER, source_node TEXT)")
    c.execute("SELECT ip, reason, country, level, ban_time, timestamp, ban_expire, source_node FROM blacklist")
    local_black_rows = c.fetchall()
    c.execute("SELECT ip, unban_time, timestamp, source_node FROM unbanned_ips")
    local_unbanned_rows = c.fetchall()
    conn.close()

    local_blacklist = [
        {
            "ip": r[0], "reason": r[1], "country": r[2], "level": r[3],
            "ban_time": r[4], "timestamp": r[5], "ban_expire": r[6], "source_node": r[7]
        }
        for r in local_black_rows if r[0]
    ]
    local_unbanned_list = [
        {
            "ip": r[0], "unban_time": r[1], "timestamp": r[2], "source_node": r[3]
        }
        for r in local_unbanned_rows if r[0]
    ]
    local_unbanned_map = { r[0]: int(r[2] or 0) for r in local_unbanned_rows if r[0] }
    local_bans_map = { r[0]: {"timestamp": r[5]} for r in local_black_rows if r[0] }
    local_whitelist = cfg.get("whitelist", [])

    payload = json.dumps({
        "source_node": cfg.get("node_name", socket.gethostname()),
        "blacklist": local_blacklist,
        "unbanned_list": local_unbanned_list,
        "whitelist": local_whitelist
    }).encode("utf-8")
    token = generate_cluster_token("sync_state_exchange", secret, body=payload)

    target_nodes = [target_node] if target_node else nodes
    synced_nodes = 0
    merged_bans = 0
    merged_whites = 0

    for raw_node in target_nodes:
        node = normalize_cluster_node(raw_node)
        if not node or not node.get("ip"):
            continue

        ports_to_try = []
        if node.get("port"):
            try: ports_to_try.append(int(node["port"]))
            except Exception: pass
        for p in (9098, 9099):
            if p not in ports_to_try:
                ports_to_try.append(p)

        success = False
        res = {}
        for p in ports_to_try:
            node_url = f"http://{node['ip']}:{p}"
            try:
                target = f"{node_url}/api/cluster/sync_state_exchange"
                req = urllib.request.Request(target, data=payload, headers={
                    "Content-Type": "application/json",
                    "X-Cluster-Token": token,
                    "User-Agent": "PortGuardMesh/2.0"
                })
                with urllib.request.urlopen(req, timeout=5) as resp:
                    res = json.loads(resp.read().decode('utf-8'))
                    if res.get("success"):
                        success = True
                        break
            except Exception:
                continue

        if success:
            synced_nodes += 1
            remote_missing_bans = res.get("remote_blacklist", [])
            remote_missing_whites = res.get("remote_whitelist", [])
            remote_unbanned = res.get("remote_unbanned", [])

            # 1. 优先对齐远端的解封墓碑（将本地还在封禁的 IP 同步解封，彻底杜绝回潮）
            if remote_unbanned:
                for ru in remote_unbanned:
                    ru_ip = validate_ip(ru.get("ip", ""))
                    ru_ts = int(ru.get("timestamp", 0) or 0)
                    if ru_ip:
                        if ru_ip in local_bans_map:
                            local_ban_ts = int(local_bans_map[ru_ip].get("timestamp", 0) or 0)
                            if ru_ts >= local_ban_ts:
                                unban_ip_core(ru_ip, status_event="UNBANNED", source_node=f"集群对齐({node.get('remark') or node['ip']})")
                        local_unbanned_map[ru_ip] = ru_ts

            # 2. 将对端独有的黑名单写入本地并下发防火墙阻断（严格比对本地解封墓碑时间）
            if remote_missing_bans:
                conn = get_db()
                cur = conn.cursor()
                for b in remote_missing_bans:
                    b_ip = validate_ip(b.get("ip", ""))
                    if not b_ip or ip_in_whitelist(b_ip):
                        continue
                    b_ts = int(b.get("timestamp", 0) or 0)
                    local_unban_ts = local_unbanned_map.get(b_ip)
                    # 若本地存在解封墓碑且墓碑时间晚于或等于该封禁时间，严禁重新封禁！
                    if local_unban_ts is not None and local_unban_ts >= b_ts:
                        continue

                    ban_ip_firewall(b_ip)
                    src = clean_cluster_node_name(b.get("source_node") or node.get("name") or node.get("ip"))
                    geo_country = b.get("country")
                    if not geo_country or geo_country in ("集群联防", "未知地域", "公网节点", ""):
                        geo = resolve_ip_geo(b_ip) or {}
                        geo_country = geo.get("country") or "公网探测"

                    cur.execute("""
                    INSERT OR REPLACE INTO blacklist (ip, reason, country, level, ban_time, timestamp, ban_expire, source_node)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        b_ip, b.get("reason", "集群全量对齐"), geo_country,
                        b.get("level", "极高危"), b.get("ban_time", time.strftime("%Y-%m-%d %H:%M:%S")),
                        b.get("timestamp", b_ts or int(time.time())), b.get("ban_expire"), f"集群 ({src})"
                    ))
                    cur.execute("DELETE FROM unbanned_ips WHERE ip = ?", (b_ip,))
                    _EXECUTOR.submit(resolve_ip_geo, b_ip)
                    merged_bans += 1
                conn.commit()
                conn.close()

            # 3. 将对端独有的白名单写入本地
            if remote_missing_whites:
                cur_cfg = load_config()
                w_list = cur_cfg.get("whitelist", [])
                w_map = { (w.get("ip") if isinstance(w, dict) else w): (w if isinstance(w, dict) else {"ip": w, "remark": "信任IP"}) for w in w_list }
                for w in remote_missing_whites:
                    w_ip = validate_ip(w.get("ip") if isinstance(w, dict) else w)
                    if not w_ip:
                        continue
                    unban_ip_core(w_ip, status_event="WHITELIST")
                    w_rem = w.get("remark", "集群对齐白名单") if isinstance(w, dict) else "集群对齐白名单"
                    if w_ip not in w_map:
                        w_map[w_ip] = {"ip": w_ip, "remark": w_rem}
                        merged_whites += 1
                cur_cfg["whitelist"] = list(w_map.values())
                save_config(cur_cfg)

    return {
        "success": synced_nodes > 0,
        "synced_nodes": synced_nodes,
        "merged_bans": merged_bans,
        "merged_whites": merged_whites,
        "msg": f"已完成与 {synced_nodes} 个协同节点的双向全量对齐（已吸纳同步黑名单 {merged_bans} 条，白名单 {merged_whites} 条）"
    }


def start_cluster_autosync_worker():
    """后台启动即刻执行一次全量对齐，随后每 20 秒自动进行一次集群黑白名单全量双向对齐巡检"""
    def _worker():
        # 服务启动 3 秒后即刻执行首次全量对齐（弥补节点重启/更新时的同步间隙）
        time.sleep(3)
        try:
            cfg = load_config()
            cluster_cfg = cfg.get("cluster_sync", {})
            if cluster_cfg.get("enabled", False) and cluster_cfg.get("cluster_nodes"):
                sync_cluster_mesh_state()
        except Exception:
            pass

        while True:
            try:
                time.sleep(20)
                cfg = load_config()
                cluster_cfg = cfg.get("cluster_sync", {})
                if cluster_cfg.get("enabled", False) and cluster_cfg.get("cluster_nodes"):
                    sync_cluster_mesh_state()
            except Exception:
                pass
    t = threading.Thread(target=_worker, daemon=True)
    t.start()


def match_status_code(status_code, pattern):
    """
    匹配 HTTP 响应状态码，支持多种灵活格式：
    1. 空或未配置：默认匹配常见探测错误码 404, 403, 400
    2. 单状态码：如 '302', '500', '404'
    3. 多状态码列表（逗号/空格/分号/竖线分隔）：如 '400,403,404', '301|302', '500 502 503 504'
    4. 状态码范围：如 '400-499', '500-599', '300-399'
    5. 正则表达式：如 '^30[1-8]$', '4\\d\\d'
    6. 特殊关键字：'all_4xx'/'4xx', 'all_5xx'/'5xx', 'all_3xx'/'3xx', 'all_2xx'/'2xx', 'any_error' (4xx+5xx)
    """
    try:
        sc = int(status_code)
    except (ValueError, TypeError):
        return False

    if not pattern or not str(pattern).strip():
        # 默认匹配 404/403/400 探测错误码
        return sc in (404, 403, 400)

    pat_str = str(pattern).strip().lower()

    # 快捷关键字
    if pat_str in ("all_4xx", "4xx"):
        return 400 <= sc <= 499
    if pat_str in ("all_5xx", "5xx"):
        return 500 <= sc <= 599
    if pat_str in ("all_3xx", "3xx"):
        return 300 <= sc <= 399
    if pat_str in ("all_2xx", "2xx"):
        return 200 <= sc <= 299
    if pat_str in ("any_error", "error", "errors"):
        return 400 <= sc <= 599

    # 范围匹配 400-499
    if "-" in pat_str and not pat_str.startswith("-"):
        parts = pat_str.split("-", 1)
        try:
            low, high = int(parts[0].strip()), int(parts[1].strip())
            return low <= sc <= high
        except ValueError:
            pass

    # 分隔列表 301,302 / 400|403|404 / 500 502
    delimiters = [",", "|", ";", " "]
    for d in delimiters:
        if d in pat_str:
            tokens = [t.strip() for t in pat_str.split(d) if t.strip()]
            for tok in tokens:
                if "-" in tok:
                    p = tok.split("-", 1)
                    try:
                        if int(p[0]) <= sc <= int(p[1]):
                            return True
                    except ValueError:
                        pass
                elif tok.isdigit():
                    if sc == int(tok):
                        return True
                else:
                    try:
                        if re.search(tok, str(sc)):
                            return True
                    except Exception:
                        pass
            return False

    # 单纯数字如 "302"
    if pat_str.isdigit():
        return sc == int(pat_str)

    # 正则表达式匹配
    try:
        return bool(re.search(pat_str, str(sc)))
    except Exception:
        return False


_CACHED_SERVER_PUBLIC_IP = None

def get_local_public_ip():
    global _CACHED_SERVER_PUBLIC_IP
    if _CACHED_SERVER_PUBLIC_IP:
        return _CACHED_SERVER_PUBLIC_IP
    try:
        cfg = load_config()
        if cfg.get("server_ip") and validate_ip(cfg.get("server_ip")):
            _CACHED_SERVER_PUBLIC_IP = str(cfg["server_ip"]).strip()
            return _CACHED_SERVER_PUBLIC_IP
        if cfg.get("public_ip") and validate_ip(cfg.get("public_ip")):
            _CACHED_SERVER_PUBLIC_IP = str(cfg["public_ip"]).strip()
            return _CACHED_SERVER_PUBLIC_IP
    except Exception:
        pass

    # 尝试从公网快速解析接口获取真实公网弹性 IP（避开云厂商内网私有 VPC 172.16/10/192.168 地址）
    urls = [
        "https://icanhazip.com",
        "https://ifconfig.me/ip",
        "https://api.ipify.org",
        "http://checkip.amazonaws.com"
    ]
    import urllib.request
    for u in urls:
        try:
            req = urllib.request.Request(u, headers={"User-Agent": "curl/7.88.1"})
            with urllib.request.urlopen(req, timeout=1.5) as resp:
                cand = resp.read().decode("utf-8", errors="ignore").strip()
                if validate_ip(cand) and not cand.startswith("127.") and not cand.startswith("172.") and not cand.startswith("10.") and not cand.startswith("192.168."):
                    _CACHED_SERVER_PUBLIC_IP = cand
                    return cand
        except Exception:
            pass

    # 备用：从本地网络套接字获取
    for test_target in [("8.8.8.8", 80), ("1.1.1.1", 80)]:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(1.0)
            s.connect(test_target)
            ip = s.getsockname()[0]
            s.close()
            if ip and not ip.startswith("127."):
                _CACHED_SERVER_PUBLIC_IP = ip
                return ip
        except Exception:
            pass
    return ""


def check_http_request_traps(ip, req_domain, method, path, status_code, ua):
    """根据 http_traps 规则库实时分析 HTTP 请求是否命中恶意扫描或高危敏感蜜罐特征"""
    if not ip or ip in ("127.0.0.1", "::1", "localhost") or ip.startswith("127.") or ip_in_whitelist(ip):
        return False

    # 0. 检验伪造的搜索引擎爬虫 (Fake Googlebot / Baiduspider / Bingbot)
    is_valid_crawler, crawler_err = verify_search_engine_crawler(ip, ua)
    if not is_valid_crawler:
        ban_ip(ip, reason=f"爬虫防御: {crawler_err}", category="fake_crawler", level="极高危")
        return True

    rules = get_http_traps()
    if not rules:
        return False

    now = time.time()
    for rule in rules:
        if not rule.get("enabled"):
            continue
        mtype = rule.get("match_type", "path_keyword")
        rname = rule.get("name", "Web特征检测")
        rlevel = rule.get("level", "高危")

        # 1. 路径敏感特征匹配
        if mtype == "path_keyword":
            pat = rule.get("pattern", "")
            if pat and re.search(pat, path, re.IGNORECASE):
                reason = f"Web诱捕: 探测高危路径 {path[:36]}"
                ban_ip(ip, reason=reason, category="web", level=rlevel)
                return True

        # 2. UA 扫描器工具指纹匹配
        elif mtype == "ua_keyword":
            pat = rule.get("pattern", "")
            if pat and ua and re.search(pat, ua, re.IGNORECASE):
                reason = f"Web防护: 扫描工具特征 {ua[:28]}"
                ban_ip(ip, reason=reason, category="web", level=rlevel)
                return True

        # 3. HTTP 响应状态码 / 频次限制 (支持任意状态码如 302, 500, 404, 400-499, 500-599 等)
        elif mtype in ("status_rate", "status_code"):
            pat = rule.get("pattern", "")
            if match_status_code(status_code, pat):
                threshold = int(rule.get("threshold") or 1)
                window = int(rule.get("window") or 30)
                rule_key = str(rule.get("rule_id") or rule.get("id") or "status")
                cache_key = f"{ip}:{rule_key}"
                with _IP_404_LOCK:
                    history = _IP_404_RATE_CACHE.setdefault(cache_key, [])
                    history = [item for item in history if now - item[0] <= window]
                    history.append((now, path, status_code))
                    _IP_404_RATE_CACHE[cache_key] = history
                    if len(history) >= threshold:
                        _IP_404_RATE_CACHE[cache_key] = []
                        target_code_desc = pat if pat else f"{status_code}"
                        if threshold <= 1:
                            reason = f"Web状态码限制: 触发 {status_code} ({path[:24]})"
                        else:
                            reason = f"Web状态码超频: {window}s内触发 {len(history)}次 [{target_code_desc}] ({path[:20]})"
                        ban_ip(ip, reason=reason, category="web", level=rlevel)
                        return True

        # 4. 全网测绘引擎检测 (Censys, Shodan, Onyphe 等)
        elif mtype == "survey_engine":
            pat = rule.get("pattern", "")
            if is_survey_scanner_ip(ip) or (pat and ua and re.search(pat, ua, re.IGNORECASE)):
                reason = f"测绘拦截: 网络空间测绘引擎探测 ({ua[:20] if ua else 'Censys/Onyphe/Shodan'})"
                ban_ip(ip, reason=reason, category="survey", level=rlevel)
                return True

        # 5. 禁止纯 IP 直连 Web 探测
        elif mtype == "direct_ip":
            is_direct_ip = False
            if req_domain:
                r_clean = req_domain.strip()
                if "纯IP" in r_clean or "全局反代" in r_clean or re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(:\d+)?$", r_clean):
                    is_direct_ip = True
                elif r_clean.startswith("纯IP直连") or "默认站点" in r_clean:
                    is_direct_ip = True

            if is_direct_ip:
                target_str = req_domain if req_domain else ip
                reason = f"Web防护: 禁止纯IP直连探测 ({target_str})"
                ban_ip(ip, reason=reason, category="web", level=rlevel)
                return True
    return False

_WEB_PORT_LOG_CACHE = {}

def log_access_entry(ip, method, path, status_code=200, user_agent=""):
    try:
        if ip in ("127.0.0.1", "::1", "localhost") or ip.startswith("127."):
            return
        # 严格过滤控制台内部轮询与静态资源，避免管理轮询高频写入产生锁竞争与无用日志膨胀
        if path and (path.startswith("/api/") or path in ("/favicon.ico", "/robots.txt")):
            return
        now_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        now_ts = int(time.time())
        geo = _GEO_CACHE.get(ip) or resolve_ip_geo_local(ip) or {}
        country = geo.get("country") or "公网节点"
        region = geo.get("region", "")
        city = geo.get("city", "")
        isp = geo.get("isp", "")

        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("""
        INSERT INTO access_logs (ip, method, path, status_code, user_agent, country, region, city, isp, access_time, timestamp)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (ip, method, path, status_code, (user_agent or "")[:200], country, region, city, isp, now_str, now_ts))
        
        # 同时以 5 秒防抖在 port_access_logs 中记录 Web 控制台业务连接
        global _WEB_PORT_LOG_CACHE
        last_t = _WEB_PORT_LOG_CACHE.get(ip, 0)
        if (now_ts - last_t) >= 5:
            _WEB_PORT_LOG_CACHE[ip] = now_ts
            cfg = load_config()
            web_port = int(cfg.get("web_port", 9099))
            is_white = ip_in_whitelist(ip, cfg.get("whitelist", []))
            act = "WHITELIST" if is_white else "BUSINESS"
            desc = f"安全白名单访问: Web控制台 (端口 {web_port})" if is_white else f"正常业务连接: PortGuard Web控制台 (端口 {web_port})"
            cursor.execute("""
            INSERT INTO port_access_logs (ip, port, proto, port_name, country, region, city, isp, action, access_time, timestamp)
            VALUES (?, ?, 'TCP', ?, ?, ?, ?, ?, ?, ?, ?)
            """, (ip, web_port, desc, country, region, city, isp, act, now_str, now_ts))
            
        conn.commit()
        conn.close()
    except Exception:
        pass
    except Exception:
        pass

_PORT_LOG_QUEUE = queue.Queue(maxsize=10000)

def log_port_access_entry(ip, port, port_name="诱捕探针", action="INTERCEPTED", geo=None):
    """将访问日志压入内存队列，由后台 Worker 异步批量事务落盘，彻底解决高并发 SQLite 锁库"""
    try:
        now_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        now_ts = int(time.time())
        geo = geo or {}
        country = geo.get("country", "分析中..." if ip not in ("127.0.0.1", "::1", "localhost") else "本地测试")
        region = geo.get("region", "")
        city = geo.get("city", "")
        isp = geo.get("isp", "")
        
        try:
            _PORT_LOG_QUEUE.put_nowait({
                "ip": ip, "port": port, "proto": "TCP", "port_name": port_name,
                "country": country, "region": region, "city": city, "isp": isp,
                "action": action, "access_time": now_str, "timestamp": now_ts
            })
        except queue.Full:
            pass

        if not geo and ip not in ("127.0.0.1", "::1", "localhost"):
            _EXECUTOR.submit(resolve_ip_geo, ip)
    except Exception:
        pass


def _batch_log_worker():
    """后台批量落盘工作线程：合并多条记录单事务提交，提升写入吞吐 50 倍以上"""
    while True:
        try:
            items = []
            try:
                item = _PORT_LOG_QUEUE.get(timeout=1.0)
                items.append(item)
                while len(items) < 200:
                    item = _PORT_LOG_QUEUE.get_nowait()
                    items.append(item)
            except (queue.Empty, Exception):
                pass
            
            if items:
                conn = get_db()
                cur = conn.cursor()
                rows = [
                    (it["ip"], it["port"], it["proto"], it["port_name"],
                     it["country"], it["region"], it["city"], it["isp"],
                     it["action"], it["access_time"], it["timestamp"])
                    for it in items
                ]
                cur.executemany("""
                INSERT INTO port_access_logs (ip, port, proto, port_name, country, region, city, isp, action, access_time, timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, rows)
                conn.commit()
                conn.close()
        except Exception:
            time.sleep(0.5)


_CONFIG_CACHE = None
_CONFIG_CACHE_MTIME = 0.0
_CONFIG_LOCK = threading.Lock()

def load_config():
    global _CONFIG_CACHE, _CONFIG_CACHE_MTIME
    try:
        dir_name = os.path.dirname(CONFIG_PATH)
        if dir_name and not os.path.exists(dir_name):
            os.makedirs(dir_name, exist_ok=True)
        if not os.path.exists(CONFIG_PATH):
            with open(CONFIG_PATH, 'w', encoding='utf-8') as f:
                json.dump(DEFAULT_CONFIG, f, indent=2, ensure_ascii=False)
            with _CONFIG_LOCK:
                _CONFIG_CACHE = dict(DEFAULT_CONFIG)
                _CONFIG_CACHE_MTIME = os.path.getmtime(CONFIG_PATH)
            return dict(_CONFIG_CACHE)

        mtime = os.path.getmtime(CONFIG_PATH)
        with _CONFIG_LOCK:
            if _CONFIG_CACHE is not None and mtime == _CONFIG_CACHE_MTIME:
                return dict(_CONFIG_CACHE)

        with open(CONFIG_PATH, 'r', encoding='utf-8') as f:
            cfg = json.load(f)
            merged = {**DEFAULT_CONFIG, **cfg}
        with _CONFIG_LOCK:
            _CONFIG_CACHE = merged
            _CONFIG_CACHE_MTIME = mtime
        return dict(merged)
    except Exception:
        with _CONFIG_LOCK:
            if _CONFIG_CACHE is not None:
                return dict(_CONFIG_CACHE)
        return dict(DEFAULT_CONFIG)


def unban_ip_core(ip, status_event="UNBANNED", source_node="本机操作"):
    """彻底解除对指定 IP 的内核防火墙封禁、ipset、黑洞路由及数据库黑名单记录，并登记防回潮墓碑。"""
    valid_ip = validate_ip(ip)
    if not valid_ip:
        return False
    ip = valid_ip
    try:
        addr_obj = ipaddress.ip_address(ip)
        is_ipv6 = addr_obj.version == 6
        set_name = "portguard_blacklist_v6" if is_ipv6 else "portguard_blacklist_v4"
        fw_tool = "ip6tables" if is_ipv6 else "iptables"
        save_tool = "ip6tables-save" if is_ipv6 else "iptables-save"
        mask = "/128" if is_ipv6 else "/32"

        # 1. 从 ipset 移除
        if is_ipset_available():
            subprocess.run(["ipset", "del", set_name, ip, "-exist"],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        # 2. 循环清理 INPUT 链中所有重复的 DROP 规则，直到彻底删净
        cleaned_any = False
        while True:
            res = subprocess.run([fw_tool, "-D", "INPUT", "-s", ip, "-j", "DROP"],
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if res.returncode == 0:
                cleaned_any = True
            else:
                break
        
        if cleaned_any:
            run_firewall_cmd(save_tool)

        # 3. 清理黑洞路由
        if is_ipv6:
            subprocess.run(["ip", "-6", "route", "del", "blackhole", f"{ip}{mask}"],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        else:
            subprocess.run(["ip", "route", "del", "blackhole", f"{ip}{mask}"],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        # 4. 同步写入 unbanned_ips 墓碑表（防止集群定时同步再次拉黑），清理 blacklist 表并标记 events
        now_str = time.strftime("%Y-%m-%d %H:%M:%S")
        now_ts = int(time.time())
        conn = get_db()
        c = conn.cursor()
        c.execute("""
        CREATE TABLE IF NOT EXISTS unbanned_ips (
            ip TEXT PRIMARY KEY,
            unban_time TEXT,
            timestamp INTEGER,
            source_node TEXT
        )
        """)
        c.execute("""
        INSERT OR REPLACE INTO unbanned_ips (ip, unban_time, timestamp, source_node)
        VALUES (?, ?, ?, ?)
        """, (ip, now_str, now_ts, source_node))
        c.execute("DELETE FROM blacklist WHERE ip = ?", (ip,))
        c.execute("UPDATE events SET status = ? WHERE ip = ?", (status_event, ip))
        # 清理 7 天前的历史解封墓碑
        c.execute("DELETE FROM unbanned_ips WHERE timestamp < ?", (now_ts - 7 * 86400,))
        conn.commit()
        conn.close()

        # 重置威胁评分与黑名单内存缓存
        _THREAT_ENGINE.reset_score(ip)
        if _BLACKLIST_IPS_CACHE is not None:
            with _BLACKLIST_IPS_LOCK:
                _BLACKLIST_IPS_CACHE.discard(ip)
        return True
    except Exception:
        return False


def cleanup_expired_bans():
    """定期清理过期封禁，并对 SQLite 历史过期审计日志进行自动归档瘦身与空间压缩 (VACUUM)。"""
    try:
        cfg = load_config()
        auto_clean_days = int(cfg.get("auto_clean_days", 30) or 30)
        now_ts = int(time.time())
        conn = get_db()
        c = conn.cursor()

        # 1. 清理过期黑名单
        if auto_clean_days > 0:
            c.execute("SELECT ip FROM blacklist WHERE ban_expire IS NOT NULL AND ban_expire < ?", (now_ts,))
            expired = [r["ip"] for r in c.fetchall()]
            for ip in expired:
                unban_ip_core(ip, status_event="EXPIRED")
            if expired:
                print(f"[CLEANUP] 已清理 {len(expired)} 条过期封禁")

        # 2. SQLite 历史数据归档与瘦身：清理超过保留天数的历史端口与Web访问日志，防止数据库膨胀
        if auto_clean_days > 0:
            expire_cutoff = now_ts - (auto_clean_days * 86400)
            c.execute("DELETE FROM port_access_logs WHERE timestamp < ?", (expire_cutoff,))
            del_access = c.rowcount
            c.execute("DELETE FROM access_logs WHERE timestamp < ?", (expire_cutoff,))
            del_web = c.rowcount
            # 保留已被拉黑的核心安全事件，仅删除过期的常规探测/非封禁日志
            c.execute("DELETE FROM events WHERE timestamp < ? AND status NOT IN ('BANNED')", (expire_cutoff,))
            del_events = c.rowcount

            # 容量天花板保护：若单表超过 100,000 条记录，强制清理最旧的数据保持系统轻快
            for table_name in ("port_access_logs", "access_logs", "events"):
                try:
                    c.execute(f"SELECT COUNT(*) FROM {table_name}")
                    t_cnt = c.fetchone()[0]
                    if t_cnt > 100000:
                        overflow = t_cnt - 80000
                        c.execute(f"DELETE FROM {table_name} WHERE id IN (SELECT id FROM {table_name} ORDER BY id ASC LIMIT ?)", (overflow,))
                except Exception:
                    pass

            conn.commit()
            if (del_access + del_web + del_events) > 0:
                print(f"[CLEANUP] 历史日志自动归档完成：已清理 {del_access} 条端口日志、{del_web} 条Web日志、{del_events} 条常规事件")

        conn.close()

        # 3. 每天一次低负载时段自动执行 VACUUM 回收磁盘物理碎片 (SQLite WAL 空间收缩)
        last_vacuum_file = "/tmp/.portguard_last_vacuum"
        need_vacuum = True
        try:
            if os.path.exists(last_vacuum_file):
                if (now_ts - os.path.getmtime(last_vacuum_file)) < 86400:
                    need_vacuum = False
        except Exception:
            pass

        if need_vacuum:
            try:
                v_conn = get_db()
                v_conn.execute("VACUUM")
                v_conn.close()
                with open(last_vacuum_file, "w") as f:
                    f.write(str(now_ts))
                print("[CLEANUP] 成功执行 SQLite 磁盘空间碎片整理 (VACUUM)")
            except Exception as e:
                print(f"[CLEANUP] VACUUM 异常: {e}")

    except Exception as e:
        print(f"[CLEANUP] 清理失败: {e}")


def cleanup_loop():
    while True:
        time.sleep(3600)
        cleanup_expired_bans()

CONFIG_SNAPSHOTS_DIR = os.path.join(os.path.dirname(CONFIG_PATH), "snapshots")

def save_config(cfg):
    try:
        dir_name = os.path.dirname(CONFIG_PATH)
        if dir_name and not os.path.exists(dir_name):
            os.makedirs(dir_name, exist_ok=True)
            
        # 自动配置版本快照备份：若原配置已存在，备份到 snapshots/
        if os.path.exists(CONFIG_PATH):
            try:
                if not os.path.exists(CONFIG_SNAPSHOTS_DIR):
                    os.makedirs(CONFIG_SNAPSHOTS_DIR, exist_ok=True)
                snap_time = time.strftime("%Y%m%d_%H%M%S")
                snap_path = os.path.join(CONFIG_SNAPSHOTS_DIR, f"config_{snap_time}.json")
                shutil.copy2(CONFIG_PATH, snap_path)
                
                # 仅保留最近 15 份快照
                snaps = sorted(glob.glob(os.path.join(CONFIG_SNAPSHOTS_DIR, "config_*.json")), key=os.path.getmtime)
                if len(snaps) > 15:
                    for old_snap in snaps[:-15]:
                        try:
                            os.remove(old_snap)
                        except Exception:
                            pass
            except Exception:
                pass

        with open(CONFIG_PATH, 'w', encoding='utf-8') as f:
            json.dump(cfg, f, indent=2, ensure_ascii=False)
        try:
            mtime = os.path.getmtime(CONFIG_PATH)
            with _CONFIG_LOCK:
                _CONFIG_CACHE = {**DEFAULT_CONFIG, **cfg}
                _CONFIG_CACHE_MTIME = mtime
        except Exception:
            pass
        return True
    except Exception:
        return False

def get_config_snapshots():
    """获取所有历史配置版本快照列表"""
    results = []
    try:
        if not os.path.exists(CONFIG_SNAPSHOTS_DIR):
            return results
        snaps = sorted(glob.glob(os.path.join(CONFIG_SNAPSHOTS_DIR, "config_*.json")), key=os.path.getmtime, reverse=True)
        for s in snaps:
            fname = os.path.basename(s)
            results.append({
                "filename": fname,
                "timestamp": int(os.path.getmtime(s)),
                "datetime": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(os.path.getmtime(s))),
                "size": os.path.getsize(s)
            })
    except Exception:
        pass
    return results

def rollback_config_snapshot(filename):
    """一键回滚恢复指定的历史配置版本快照"""
    try:
        clean_fn = os.path.basename(filename)
        target = os.path.join(CONFIG_SNAPSHOTS_DIR, clean_fn)
        if not os.path.exists(target):
            return False, "指定的快照文件不存在"
        with open(target, 'r', encoding='utf-8') as f:
            snap_cfg = json.load(f)
        with open(CONFIG_PATH, 'w', encoding='utf-8') as f:
            json.dump(snap_cfg, f, indent=2, ensure_ascii=False)
        return True, "配置已成功从快照回滚还原！"
    except Exception as e:
        return False, f"回滚失败: {e}"

def check_c2_compromise_connections():
    """反向连线检测 (Compromise Assessment)：定时审计本机所有活跃 TCP 连接，检测是否存在内网主机失陷、恶意反弹 C2 或黑名单异常连线"""
    alerts = []
    try:
        conn = get_db()
        c = conn.cursor()
        c.execute("SELECT ip, reason FROM blacklist")
        black_dict = {row["ip"]: row["reason"] for row in c.fetchall()}
        conn.close()

        if not black_dict:
            return alerts

        # 扫描并建立 socket inode -> (pid, comm) 快速映射
        sock_proc_map = {}
        for p in glob.glob("/proc/[0-9]*"):
            pid = os.path.basename(p)
            comm = ""
            try:
                with open(os.path.join(p, "comm"), "r") as cf:
                    comm = cf.read().strip()
            except Exception:
                pass
            fd_dir = os.path.join(p, "fd")
            if os.path.isdir(fd_dir):
                try:
                    for fd in os.listdir(fd_dir):
                        try:
                            t = os.readlink(os.path.join(fd_dir, fd))
                            if t.startswith("socket:["):
                                inode = t[8:-1]
                                sock_proc_map[inode] = {"pid": pid, "process": comm}
                        except Exception:
                            pass
                except Exception:
                    pass

        active_system_ports = get_active_system_ports()

        # 扫描 /proc/net/tcp 与 /proc/net/tcp6 中的 ESTABLISHED 连接 (状态 01)
        for proc_file, is_v6 in [("/proc/net/tcp", False), ("/proc/net/tcp6", True)]:
            if not os.path.exists(proc_file):
                continue
            with open(proc_file, "r") as f:
                lines = f.readlines()[1:]
            for line in lines:
                parts = line.strip().split()
                if len(parts) < 10:
                    continue
                state = parts[3]
                if state != "01": # 仅检查处于已建立连线状态的 TCP 活跃连接
                    continue
                loc_address = parts[1]
                rem_address = parts[2]
                inode = parts[9]
                try:
                    if not is_v6:
                        loc_hex, loc_port_hex = loc_address.split(":")
                        local_ip = socket.inet_ntoa(struct.pack("<L", int(loc_hex, 16)))
                        local_port = int(loc_port_hex, 16)

                        ip_hex, port_hex = rem_address.split(":")
                        remote_ip = socket.inet_ntoa(struct.pack("<L", int(ip_hex, 16)))
                        remote_port = int(port_hex, 16)
                    else:
                        continue # 重点监控 IPv4 外连
                    
                    if remote_ip in black_dict:
                        proc_info = sock_proc_map.get(inode, {"pid": "--", "process": "未知进程"})
                        is_inbound = local_port in active_system_ports
                        direction = "INBOUND" if is_inbound else "OUTBOUND"
                        direction_desc = f"入站连接 (对端访问本机监听端口 {local_port})" if is_inbound else f"出站反连 (本机主动连向外部端口 {remote_port})"
                        
                        geo = _GEO_CACHE.get(remote_ip) or resolve_ip_geo_local(remote_ip) or {}
                        country = geo.get("country") or "公网节点"
                        city = geo.get("city") or ""
                        isp = geo.get("isp") or ""
                        geo_desc = f"{country} {city} ({isp})".strip() if (country or isp) else "公网未知"

                        alerts.append({
                            "remote_ip": remote_ip,
                            "remote_port": remote_port,
                            "local_ip": local_ip,
                            "local_port": local_port,
                            "direction": direction,
                            "direction_desc": direction_desc,
                            "pid": proc_info.get("pid", "--"),
                            "process": proc_info.get("process", "未知进程"),
                            "reason": black_dict[remote_ip],
                            "country": country,
                            "city": city,
                            "isp": isp,
                            "geo_desc": geo_desc,
                            "time": time.strftime("%Y-%m-%d %H:%M:%S")
                        })
                        print(f"[SECURITY ALERT] 发现黑名单活跃连接！{direction}: {local_ip}:{local_port} <-> {remote_ip}:{remote_port} (PID: {proc_info.get('pid')}, 进程: {proc_info.get('process')})")
                except Exception:
                    pass
    except Exception:
        pass
    return alerts

def get_system_ssh_ports():
    """动态获取系统中 SSH 服务监听的所有端口 (包括 22 以及 sshd_config 中自定义的高位端口)"""
    ports = {22}
    try:
        sshd_configs = ["/etc/ssh/sshd_config", "/etc/ssh/sshd_config.d/*.conf"]
        for p in sshd_configs:
            for fpath in glob.glob(p):
                if os.path.exists(fpath):
                    with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                        for line in f:
                            line = line.strip()
                            if line.startswith("Port ") or line.startswith("port "):
                                parts = line.split()
                                if len(parts) >= 2 and parts[1].isdigit():
                                    ports.add(int(parts[1]))
    except Exception:
        pass
    return ports

_DYNAMIC_SSH_IPS_CACHE = set()
_DYNAMIC_SSH_IPS_LAST_CHECK = 0

def get_active_ssh_client_ips():
    """动态探测当前系统真正已认证登录的管理员 SSH 客户端 IP (防管理员自杀保护机制)
    注意：严禁直接使用原始 TCP ESTABLISHED 状态判断，因为外部爆破者在输入密码握手阶段 (Preauth)
    也会处于 TCP ESTABLISHED 状态，若无差别放行会导致暴力破解攻击源获得临时白名单豁免。
    """
    global _DYNAMIC_SSH_IPS_CACHE, _DYNAMIC_SSH_IPS_LAST_CHECK
    now = time.time()
    if (now - _DYNAMIC_SSH_IPS_LAST_CHECK < 5) and _DYNAMIC_SSH_IPS_CACHE:
        return _DYNAMIC_SSH_IPS_CACHE
    
    ips = set()
    
    # 1. 从 who 命令读取真正已登录终端的客户端 IP
    try:
        res = subprocess.run(["who"], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, universal_newlines=True, timeout=2)
        for line in res.stdout.splitlines():
            m = re.search(r'\(([\d\w\.\:]+)\)', line)
            if m:
                clean_ip = m.group(1).split(':')[0].strip('[]').replace('::ffff:', '')
                if clean_ip and not clean_ip.startswith("127."):
                    ips.add(clean_ip)
    except Exception:
        pass

    # 2. 从当前运行环境的 SSH_CLIENT / SSH_CONNECTION 读取
    try:
        for env_var in ("SSH_CLIENT", "SSH_CONNECTION"):
            val = os.environ.get(env_var, "").strip()
            if val:
                c_ip = val.split()[0].replace('::ffff:', '')
                if c_ip and not c_ip.startswith("127."):
                    ips.add(c_ip)
    except Exception:
        pass

    # 3. 跨进程检测已登录用户 (针对 systemd-logind 会话，避免 shell=True 注入隐患)
    try:
        res = subprocess.run(["loginctl", "list-sessions", "--no-legend"], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, universal_newlines=True, timeout=2)
        for line in res.stdout.splitlines():
            parts = line.split()
            if parts:
                s_id = parts[0]
                if not s_id.isalnum():
                    continue
                s_res = subprocess.run(["loginctl", "show-session", s_id, "-p", "RemoteHost"], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, universal_newlines=True, timeout=2)
                if "RemoteHost=" in s_res.stdout:
                    r_host = s_res.stdout.split("RemoteHost=", 1)[1].strip()
                    if r_host and not r_host.startswith("127."):
                        ips.add(r_host.replace('::ffff:', ''))
    except Exception:
        pass
    
    _DYNAMIC_SSH_IPS_CACHE = ips
    _DYNAMIC_SSH_IPS_LAST_CHECK = now
    return ips

_DEFAULT_GATEWAY_CACHE = None
_DEFAULT_GATEWAY_LAST_CHECK = 0.0

def get_default_gateway():
    """动态通过 /proc/net/route 毫秒级提取默认路由网关 IP (防自锁保护，绝不误封上一级路由交换机)"""
    global _DEFAULT_GATEWAY_CACHE, _DEFAULT_GATEWAY_LAST_CHECK
    now = time.time()
    if _DEFAULT_GATEWAY_CACHE is not None and (now - _DEFAULT_GATEWAY_LAST_CHECK < 60.0):
        return _DEFAULT_GATEWAY_CACHE

    gw = None
    try:
        if os.path.exists("/proc/net/route"):
            with open("/proc/net/route", "r") as f:
                lines = f.readlines()
            for line in lines[1:]:
                parts = line.strip().split()
                if len(parts) >= 3 and parts[1] == "00000000":
                    gw_hex = parts[2]
                    if gw_hex != "00000000":
                        gw = socket.inet_ntoa(struct.pack("<L", int(gw_hex, 16)))
                        break
    except Exception:
        pass

    _DEFAULT_GATEWAY_CACHE = gw
    _DEFAULT_GATEWAY_LAST_CHECK = now
    return gw

def ip_in_whitelist(ip, whitelist_items=None):
    if not ip or ip in ("127.0.0.1", "::1", "localhost") or str(ip).startswith("127."):
        return True

    # 基础设施与公共 CDN 保护：公网权威 DNS (1.1.1.1 / 8.8.8.8 等) 及 Cloudflare 节点永久放行，严禁任何机制误拉黑
    if is_infrastructure_or_cdn_ip(ip):
        return True

    # 核心防自锁盾：宿主机默认路由网关绝对放行，禁止任何误封上一级路由交换机的行为
    gw = get_default_gateway()
    if gw and ip == gw:
        return True

    # 核心防自锁盾：只要当前是正在连接服务器的管理员活跃 SSH 会话，内核级永久放行！
    active_ssh_ips = get_active_ssh_client_ips()
    if ip in active_ssh_ips:
        return True

    # 协同集群联防节点 IP 永久放行，避免节点间同步与探测误触拉黑
    try:
        cfg_obj = load_config() if whitelist_items is None else None
        if cfg_obj:
            c_nodes = cfg_obj.get("cluster_sync", {}).get("cluster_nodes", [])
            for raw_n in c_nodes:
                norm_n = normalize_cluster_node(raw_n)
                if norm_n and norm_n.get("ip") == ip:
                    return True
    except Exception:
        pass

    if whitelist_items is None:
        try:
            cfg = load_config()
            whitelist_items = cfg.get("whitelist", DEFAULT_CONFIG.get("whitelist", []))
        except Exception:
            whitelist_items = DEFAULT_CONFIG.get("whitelist", [])
    for item in whitelist_items:
        val = item.get("ip") if isinstance(item, dict) else item
        if not val:
            continue
        if "/" in val:
            try:
                import ipaddress
                if ipaddress.ip_address(ip) in ipaddress.ip_network(val, strict=False):
                    return True
            except Exception:
                pass
        elif ip == val:
            return True
    return False

from geo import (
    GEO_COUNTRY_CN, translate_country_cn,
    XdbSearcher, MMDBReader, resolve_ip_geo, resolve_ip_geo_local,
    _GEO_CACHE
)
def ban_ip(ip, port=None, port_info=None, reason=None, category=None, level=None):
    cfg = load_config()
    now_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    now_ts = int(time.time())

    # 严格校验 IP：非法输入只记录日志，绝不拼入任何命令
    valid_ip = validate_ip(ip)
    if not valid_ip:
        print(f"[SKIP] 非法 IP 输入被拒绝: {ip!r}")
        return
    ip = valid_ip

    # 核心防自锁盾：禁止封禁宿主机默认路由网关
    gw = get_default_gateway()
    if gw and ip == gw:
        print(f"[GATEWAY] 核心防自锁触发：禁止封禁宿主机默认网关 IP: {ip}")
        return
    
    # 0. 暂停防御模式检查 (如果管理员暂停了拦截服务，绝不下发任何黑洞/防火墙封禁，仅记录日志)
    if cfg.get("defense_paused", False) or cfg.get("paused", False):
        print(f"[PAUSED] 防御拦截已处于暂停状态，忽略封禁: {ip}")
        if port:
            log_port_access_entry(ip, port, (port_info or {}).get("name", f"TCP/{port}"), action="PAUSED")
        return

    # 1. 白名单拦截保护
    if ip_in_whitelist(ip):
        print(f"[WHITELIST] 忽略安全白名单 IP: {ip}")
        if port:
            log_port_access_entry(ip, port, (port_info or {}).get("name", f"TCP/{port}"), action="WHITELIST")
        return

    port_info = port_info or {}
    port_val = port if port is not None else (port_info.get("port") or 443)
    port_name = reason or port_info.get("name") or f"TCP/{port_val}"
    event_category = category or port_info.get("category") or ("web" if port_val in (80, 443, 8080, 8888) else "other")
    event_level = level or port_info.get("level", "高危")
    ban_reason = reason or f"探测蜜罐端口 {port_val} ({port_name})"

    # 2. 蜜罐阈值判定（若非直接指定原因或业务诱捕，按阈值防抖）
    defense_mode = str(cfg.get("defense_mode", "standard")).strip().lower()
    is_biz = bool(port_info.get("is_business", False) or "业务诱捕" in str(port_name))

    if reason or defense_mode in ("strict", "aggressive", "秒级响应", "严苛") or is_biz or event_category in ("scan", "business") or cfg.get("trap_all_ports", False) or cfg.get("trap_all_unopened_ports", False):
        threshold = 1
    else:
        threshold = int(cfg.get("trap_threshold", 3) or 3)

    window = int(cfg.get("trap_window_seconds", 30) or 30)
    try:
        conn_tmp = get_db()
        cur_tmp = conn_tmp.cursor()
        cur_tmp.execute(
            "SELECT COUNT(*) AS cnt FROM events WHERE ip=? AND timestamp >= ? AND status != 'WHITELIST'",
            (ip, now_ts - window)
        )
        hit_count = int(cur_tmp.fetchone()["cnt"] or 0) + 1
        conn_tmp.close()
    except Exception:
        hit_count = threshold

    if hit_count < threshold:
        print(f"[WATCH] IP {ip} 窗口内第 {hit_count} 次探测 (阈值 {threshold})，暂不封禁")
        try:
            conn_w = get_db()
            cw = conn_w.cursor()
            cw.execute(
                "INSERT INTO events (ip, port, proto, port_name, category, level, country, region, city, isp, attack_time, timestamp, status, hit_count) "
                "VALUES (?, ?, 'TCP', ?, ?, ?, '分析中...', '', '', '', ?, ?, 'WATCH', ?)",
                (ip, port_val, port_name, event_category, event_level, now_str, now_ts, hit_count)
            )
            w_event_id = cw.lastrowid
            cw.execute(
                "INSERT INTO port_access_logs (ip, port, proto, port_name, country, region, city, isp, action, access_time, timestamp) "
                "VALUES (?, ?, 'TCP', ?, '分析中...', '', '', '', 'WATCH', ?, ?)",
                (ip, port_val, port_name, now_str, now_ts)
            )
            w_port_id = cw.lastrowid
            conn_w.commit()
            conn_w.close()

            def _async_geo_watch(e_id, p_id, target_ip):
                try:
                    geo = resolve_ip_geo(target_ip)
                    c_geo = get_db()
                    cur = c_geo.cursor()
                    if e_id:
                        cur.execute("UPDATE events SET country=?, region=?, city=?, isp=? WHERE id=?",
                                    (geo["country"], geo["region"], geo["city"], geo["isp"], e_id))
                    if p_id:
                        cur.execute("UPDATE port_access_logs SET country=?, region=?, city=?, isp=? WHERE id=?",
                                    (geo["country"], geo["region"], geo["city"], geo["isp"], p_id))
                    c_geo.commit()
                    c_geo.close()
                except Exception:
                    pass

            _EXECUTOR.submit(_async_geo_watch, w_event_id, w_port_id, ip)
        except Exception:
            pass
        return
        
    auto_clean_days = int(cfg.get("auto_clean_days", 30) or 30)
    
    # 阶梯惩罚模型：查询历史违规频次，阶梯设定解封时间 (避免一次误碰导致永久误封)
    try:
        conn_h = get_db()
        ch = conn_h.cursor()
        ch.execute("SELECT COUNT(*) AS cnt FROM events WHERE ip = ?", (ip,))
        hist_count = int(ch.fetchone()["cnt"] or 0)
        conn_h.close()
    except Exception:
        hist_count = 0

    # 阶梯惩罚梯度：
    # 1) 首次轻微触碰或公开测绘爬虫：封禁 15 分钟 (900秒)
    # 2) 历史违规 <= 2 次且非极高危：封禁 1 小时 (3600秒)
    # 3) 历史违规 <= 5 次：封禁 24 小时 (86400秒)
    # 4) 反复恶意攻击者：按配置保留天数长期封禁 (auto_clean_days)
    if event_category == "survey" or "测绘" in str(port_name):
        expire_secs = 1800  # 公开测绘默认仅临时压制 30 分钟
    elif hist_count <= 1 and event_level not in ("极高危", "critical"):
        expire_secs = 900   # 首次探测轻微触碰：临时阻断 15 分钟缓冲
    elif hist_count <= 2 and event_level not in ("极高危", "critical"):
        expire_secs = 3600  # 二次触碰：阻断 1 小时
    elif hist_count <= 5 and auto_clean_days > 0:
        expire_secs = 86400 # 5次以内：阻断 24 小时
    else:
        expire_secs = auto_clean_days * 86400 if auto_clean_days > 0 else 2147483

    ban_expire = now_ts + expire_secs

    # 3. 达到阈值：使用 ipset (动态 timeout) 与黑洞路由毫秒级下发内核阻断
    if cfg.get("ban_action_iptables", True) or cfg.get("ban_action_blackhole", True):
        ban_ip_firewall(ip, expire_seconds=expire_secs)

    geo = _GEO_CACHE.get(ip) or resolve_ip_geo_local(ip) or {}
    geo_country = geo.get("country") or "公网节点"
    geo_region = geo.get("region", "")
    geo_city = geo.get("city", "")
    geo_isp = geo.get("isp", "")

    # 4. 写入事件与黑名单库与端口访问日志
    conn = get_db()
    c = conn.cursor()
    c.execute("""
    INSERT INTO events (ip, port, proto, port_name, category, level, country, region, city, isp, attack_time, timestamp, status)
    VALUES (?, ?, 'TCP', ?, ?, ?, ?, ?, ?, ?, ?, ?, 'BANNED')
    """, (ip, port_val, port_name, event_category, event_level, geo_country, geo_region, geo_city, geo_isp, now_str, now_ts))
    
    # 将拦截记录写入内存队列批量落盘
    log_port_access_entry(ip, port_val, port_name, action="INTERCEPTED", geo=geo)

    node_name = cfg.get("node_name", "本机") or "本机"
    c.execute("DELETE FROM unbanned_ips WHERE ip = ?", (ip,))
    c.execute("""
    INSERT OR REPLACE INTO blacklist (ip, reason, country, level, ban_time, timestamp, ban_expire, source_node)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (ip, ban_reason, geo_country, event_level, now_str, now_ts, ban_expire, node_name))
    conn.commit()
    conn.close()

    if _BLACKLIST_IPS_CACHE is not None:
        with _BLACKLIST_IPS_LOCK:
            _BLACKLIST_IPS_CACHE.add(ip)

    # 5. 向集群联防节点异步广播黑名单情报
    broadcast_cluster_ban(ip, ban_reason, event_level, port=port_val, proto="TCP", category=event_category)

_SYSTEM_PORTS_CACHE = {}
_SYSTEM_PORTS_CACHE_TIME = 0
_SYSTEM_PORTS_LOCK = threading.Lock()

KNOWN_SYSTEM_SERVICES = {
    9099: "PortGuard Web控制台",
    22: "SSH 远程管理",
    80: "HTTP 网站服务 (OpenResty/Nginx)",
    443: "HTTPS 加密网站服务",
    15633: "1Panel 运维控制面板",
    10232: "1Panel 运维控制面板",
    8080: "Web 业务应用端口",
    9090: "Prometheus / 日志监控服务",
    1688: "KMS 激活服务",
    9000: "Portainer 控制台",
    9443: "Portainer HTTPS 管理"
}

def is_trap_port(port, cfg=None):
    """判定指定端口是否属于已配置的诱捕蜜罐端口。正常业务列表中的端口拥有最高优先级，100% 绝对避让。"""
    try:
        port = int(port)
    except Exception:
        return None
    if cfg is None:
        cfg = load_config()
    web_port = int(cfg.get("web_port", 9099) or 9099)
    cluster_port = int(cfg.get("cluster_sync", {}).get("port", 0) or 0)
    if port == web_port or (cluster_port > 0 and port == cluster_port):
        return None
    
    # 1. 判定是否属于用户在列表中配置的正常业务端口 (P2 优先级高于蜜罐策略)
    biz_ports = set()
    for bp in cfg.get("business_ports", DEFAULT_CONFIG.get("business_ports", [])):
        if isinstance(bp, int):
            biz_ports.add(bp)
        elif isinstance(bp, dict) and "port" in bp:
            try:
                biz_ports.add(int(bp["port"]))
            except Exception:
                pass
                
    # 正常业务端口（如 80, 443, 4212 trojan 等）100% 绝对不作为蜜罐！
    if port in biz_ports:
        return None

    # 2. 检查是否命中蜜罐诱饵规则
    try:
        raw_traps = cfg.get("trap_ports", DEFAULT_CONFIG["trap_ports"])
        matching_rules = []
        for item in raw_traps:
            norm = normalize_trap_item(item)
            if not norm or not norm.get("enabled", True):
                continue
            sp = int(norm.get("port_start", norm.get("port")))
            ep = int(norm.get("port_end", norm.get("port")))
            if sp <= port <= ep:
                span = ep - sp
                matching_rules.append((span, norm))

        if matching_rules:
            # 跨度最小的精细规则优先
            matching_rules.sort(key=lambda x: x[0])
            return matching_rules[0][1]

    except Exception:
        pass

    return None

def get_active_system_ports():
    global _SYSTEM_PORTS_CACHE, _SYSTEM_PORTS_CACHE_TIME
    now = time.time()
    if _SYSTEM_PORTS_CACHE and (now - _SYSTEM_PORTS_CACHE_TIME < 30.0):
        return _SYSTEM_PORTS_CACHE

    with _SYSTEM_PORTS_LOCK:
        if _SYSTEM_PORTS_CACHE and (now - _SYSTEM_PORTS_CACHE_TIME < 30.0):
            return _SYSTEM_PORTS_CACHE

        ports_map = {}
        try:
            cfg = load_config()
            web_p = int(cfg.get("web_port", 9099) or 9099)
            ports_map[web_p] = "PortGuard Web控制台"
            custom_biz = cfg.get("business_ports", [])
            for bp in custom_biz:
                if isinstance(bp, int):
                    ports_map[bp] = KNOWN_SYSTEM_SERVICES.get(bp, f"自定义业务端口 ({bp})")
                elif isinstance(bp, dict) and "port" in bp:
                    p = int(bp["port"])
                    ports_map[p] = bp.get("name", KNOWN_SYSTEM_SERVICES.get(p, f"自定义业务 ({p})"))
        except Exception:
            pass

        # 零进程开销：直接解析 Linux 原生 /proc/net/tcp 和 /proc/net/tcp6 (耗时<0.01ms, 零 fork 子进程)
        for proc_file in ("/proc/net/tcp", "/proc/net/tcp6"):
            try:
                if os.path.exists(proc_file):
                    with open(proc_file, "r") as f:
                        lines = f.readlines()
                    for line in lines[1:]:
                        parts = line.strip().split()
                        if len(parts) >= 4 and parts[3] == "0A":  # 0A = TCP_LISTEN
                            local_addr = parts[1]
                            hex_port = local_addr.split(":")[-1]
                            port_num = int(hex_port, 16)
                            # 严格过滤所有蜜罐诱捕端口与已绑定的蜜罐探针套接字，杜绝蜜罐端口被误识别为系统服务
                            if is_trap_port(port_num, cfg) or (trap_instance and (port_num in getattr(trap_instance, "trap_map", {}) or port_num in [p for s, p in getattr(trap_instance, "sockets", {}).values()])):
                                continue
                            if port_num not in ports_map:
                                ports_map[port_num] = KNOWN_SYSTEM_SERVICES.get(port_num, "系统监听服务")
            except Exception:
                pass

        _SYSTEM_PORTS_CACHE = ports_map
        _SYSTEM_PORTS_CACHE_TIME = now
        return ports_map

def get_all_business_ports_info():
    """
    获取当前系统中所有正常业务端口的列表：
    100% 严格以用户在 business_ports 中配置的列表为准，绝不自动从系统监听抓取添加未配置的端口。
    """
    cfg = load_config()
    custom_biz = cfg.get("business_ports", DEFAULT_CONFIG.get("business_ports", []))
    result = []
    seen = set()
    for bp in custom_biz:
        if isinstance(bp, int):
            if bp not in seen and 1 <= bp <= 65535:
                result.append({
                    "port": bp,
                    "name": f"业务端口 ({bp})",
                    "category": "custom",
                    "remark": "自定义业务",
                    "block_idc": False,
                    "block_scanner": True,
                    "is_system": False,
                    "enabled": True
                })
                seen.add(bp)
        elif isinstance(bp, dict) and "port" in bp:
            try:
                p = int(bp["port"])
                if p not in seen and 1 <= p <= 65535:
                    result.append({
                        "port": p,
                        "name": bp.get("name", f"业务端口 ({p})"),
                        "category": bp.get("category", "custom"),
                        "remark": bp.get("remark", ""),
                        "block_idc": bool(bp.get("block_idc", False)),
                        "block_scanner": bool(bp.get("block_scanner", True)),
                        "is_system": False,
                        "enabled": True
                    })
                    seen.add(p)
            except Exception:
                pass

    result.sort(key=lambda x: x["port"])
    return result

class TrapServer:
    def __init__(self):
        self.sockets = {}  # fd -> (socket, port)
        self.running = False
        self.trap_map = {} # port -> item
        self.epoll = None
        
    def start(self):
        self.running = True
        self.reload()
        threading.Thread(target=self._loop, daemon=True).start()
        
    def reload(self):
        if self.epoll:
            try:
                self.epoll.close()
            except Exception:
                pass
            self.epoll = None

        for fd, (s, _) in list(self.sockets.items()):
            try:
                s.close()
            except Exception:
                pass
        self.sockets = {}
        self.trap_map = {}
        
        try:
            if hasattr(select, 'epoll'):
                self.epoll = select.epoll()
        except Exception:
            self.epoll = None
        
        cfg = load_config()
        raw_trap_ports = cfg.get("trap_ports", DEFAULT_CONFIG["trap_ports"])
        active_ports_map = get_active_system_ports()
        active_ports = set(active_ports_map.keys()) | set(KNOWN_SYSTEM_SERVICES.keys())
        
        normalized_traps = []
        for item in raw_trap_ports:
            norm = normalize_trap_item(item)
            if norm:
                normalized_traps.append(norm)
            
        MAX_TOTAL_TRAP_SOCKETS = 256
        total_bound = 0
        web_port = 9099
        try:
            web_port = int(cfg.get("web_port", 9099))
        except Exception:
            pass

        for item in normalized_traps:
            if not item.get("enabled", True):
                continue
            start_p = item.get("port_start", item.get("port"))
            end_p = item.get("port_end", item.get("port"))
            try:
                start_p = int(start_p)
                end_p = int(end_p)
            except Exception:
                continue

            # 对于超大端口范围（如 1-65535），禁止暴力绑定数万套接字，交由底层超轻量抓包感知引擎统一捕获
            if (end_p - start_p) > 50:
                print(f"[Trap] 检测到大端口范围 ({start_p}-{end_p})，交由底层网络感知引擎捕获，跳过 socket 占用")
                continue

            bound_count_for_item = 0
            cluster_port = int(cfg.get("cluster_sync", {}).get("port", 0) or 0)
            for port in range(start_p, end_p + 1):
                if port == web_port or (cluster_port > 0 and port == cluster_port) or port in active_ports or port in self.trap_map:
                    continue
                if total_bound >= MAX_TOTAL_TRAP_SOCKETS:
                    print(f"[Trap] 已达系统最大诱捕端口监听上限 ({MAX_TOTAL_TRAP_SOCKETS})")
                    break
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    s.bind(("0.0.0.0", port))
                    s.listen(64)
                    s.setblocking(False)
                    fd = s.fileno()
                    if self.epoll:
                        self.epoll.register(fd, select.EPOLLIN)
                    self.sockets[fd] = (s, port)
                    self.trap_map[port] = item
                    total_bound += 1
                    bound_count_for_item += 1
                except Exception:
                    pass

            display_port = item.get("port")
            if bound_count_for_item > 0:
                print(f"[Trap] 激活诱捕蜜罐: {display_port} (共 {bound_count_for_item} 个端口) - {item.get('name')}")

        # 移动目标防御 (MTD) 动态高位蜜罐诱饵：若配置启用，随机在未开放高位端口激活 3 个浮动蜜罐靶点
        if bool(cfg.get("dynamic_honeypot_ports", True)) and total_bound < MAX_TOTAL_TRAP_SOCKETS:
            try:
                import random
                seed_ports = [random.randint(20000, 60000) for _ in range(8)]
                dynamic_count = 0
                for dp in seed_ports:
                    if dp in active_ports or dp in self.trap_map or dp == web_port or dp == cluster_port:
                        continue
                    try:
                        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                        s.bind(("0.0.0.0", dp))
                        s.listen(32)
                        s.setblocking(False)
                        fd = s.fileno()
                        if self.epoll:
                            self.epoll.register(fd, select.EPOLLIN)
                        self.sockets[fd] = (s, dp)
                        self.trap_map[dp] = {
                            "port": dp,
                            "name": f"动态随机诱饵 (MTD-{dp})",
                            "category": "honeypot",
                            "level": "极高危",
                            "enabled": True
                        }
                        total_bound += 1
                        dynamic_count += 1
                        if dynamic_count >= 3:
                            break
                    except Exception:
                        pass
                if dynamic_count > 0:
                    print(f"[Trap] 移动目标防御 MTD 成功随机激活 {dynamic_count} 个动态浮动诱捕靶点")
            except Exception:
                pass

    def _handle_trap_client(self, client_sock, client_addr, port, port_info):
        """高保真交互式蜜罐服务仿真：支持多协议交互式欺骗响应并捕获攻击 Payload，提取恶意样本 URL，并在结束时伪装 TCP RST 或实施 Tarpit 粘滞减速"""
        client_ip = client_addr[0]
        payload_captured = ""
        sample_urls_found = []
        cfg = load_config()
        use_tarpit = bool(cfg.get("enable_tarpit_delay", False))
        
        try:
            client_sock.settimeout(2.0)
            banner = None

            # 协议仿真 1: FTP
            if port == 21:
                banner = b"220 ProFTPD 1.3.5 Server (Ubuntu) ready.\r\n"
            # 协议仿真 2: SSH 交互
            elif port in (22, 2222):
                banner = b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n"
            # 协议仿真 3: Telnet 交互
            elif port == 23:
                banner = b"\r\nUbuntu 22.04.4 LTS\r\nlogin: "
            # 协议仿真 4: MySQL 认证握手
            elif port == 3306:
                banner = b"N\x00\x00\x00\n5.7.42-log\x00\x01\x00\x00\x00\x0b\x0c\r\x0e\x0f\x10\x11\x12\x00\xff\xf7\x21\x02\x00\x7f\x80\x15\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x00mysql_native_password\x00"
            # 协议仿真 5: PostgreSQL 认证请求协商响应
            elif port == 5432:
                # 若客户端发送 SSLRequest 或 StartupMessage，先响应 AuthenticationCleartextPassword
                banner = b"R\x00\x00\x00\x08\x00\x00\x00\x03"
            # 协议仿真 6: RDP 3389 / VNC 5900 虚拟桌面特征协商
            elif port == 3389:
                # 标准 TPKT + X.224 Connection Confirm 握手
                banner = b"\x03\x00\x00\x0b\x06\xd0\x00\x00\x124\x00"
            elif port == 5900:
                # RFB 003.008 协议版本应答
                banner = b"RFB 003.008\n"

            if banner:
                try:
                    client_sock.sendall(banner)
                except Exception:
                    pass

            try:
                recv_data = client_sock.recv(1024)
                if recv_data:
                    raw_text = recv_data.decode("utf-8", errors="ignore").strip()
                    payload_captured = raw_text

                    # 自动提取常见恶意木马投放下发 Payload (curl http://, wget, base64 样本 URL)
                    url_matches = re.findall(r'(?:https?|ftp)://[^\s"\'<>`$()]+', raw_text)
                    for u in url_matches:
                        clean_u = u.strip().rstrip(';')
                        if clean_u and clean_u not in sample_urls_found:
                            sample_urls_found.append(clean_u[:100])

                    # 协议仿真 7: Redis 协议高保真交互响应 (捕获 AUTH / PING / INFO / CONFIG / SLAVEOF 等命令)
                    if port in (6379, 6380) or "redis" in port_info.get("name", "").lower():
                        upper_cmd = raw_text.upper()
                        if "PING" in upper_cmd:
                            client_sock.sendall(b"+PONG\r\n")
                        elif "AUTH" in upper_cmd:
                            client_sock.sendall(b"-ERR invalid password\r\n")
                        elif "INFO" in upper_cmd:
                            redis_info = (
                                b"# Server\r\nredis_version:7.0.15\r\nos:Linux 5.15.0-generic x86_64\r\n"
                                b"tcp_port:6379\r\nuptime_in_seconds:384210\r\nrole:master\r\n\r\n"
                            )
                            client_sock.sendall(b"$" + str(len(redis_info)).encode() + b"\r\n" + redis_info + b"\r\n")
                        elif "COMMAND" in upper_cmd:
                            client_sock.sendall(b"+OK\r\n")
                        elif "CONFIG GET" in upper_cmd or "CONFIG SET" in upper_cmd or "SLAVEOF" in upper_cmd or "EVAL" in upper_cmd:
                            client_sock.sendall(b"-ERR protected-mode is enabled\r\n")

                    # 协议仿真 8: MongoDB 27017 探针应答 (isMaster / ping 模拟应答)
                    elif port in (27017, 27018) or "mongo" in port_info.get("name", "").lower():
                        if b"isMaster" in recv_data or b"ismaster" in recv_data or b"ping" in recv_data:
                            # 模拟 bson isMaster 应答报文结构
                            mongo_resp = b"\x37\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\xd4\x07\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x15\x00\x00\x00\x10ismaster\x00\x01\x00\x00\x00\x01ok\x00\x00\x00\x00\x00\x00\x00\xf0?\x00"
                            try:
                                client_sock.sendall(mongo_resp)
                            except Exception:
                                pass

                    # 协议仿真 9: Web HTTP 伪装响应 (针对 80, 443, 8080, 8888 等自定义 Web 诱饵)
                    elif recv_data.startswith(b"GET ") or recv_data.startswith(b"POST ") or recv_data.startswith(b"HEAD "):
                        http_resp = (
                            b"HTTP/1.1 403 Forbidden\r\n"
                            b"Server: nginx/1.18.0 (Ubuntu)\r\n"
                            b"Content-Type: text/html; charset=UTF-8\r\n"
                            b"Connection: close\r\n\r\n"
                            b"<html><head><title>403 Forbidden</title></head><body><center><h1>403 Forbidden</h1></center><hr><center>nginx/1.18.0 (Ubuntu)</center></body></html>"
                        )
                        try:
                            client_sock.sendall(http_resp)
                        except Exception:
                            pass
            except Exception:
                pass
        except Exception:
            pass
        finally:
            try:
                # 焦油坑 (Tarpit) 粘滞减速模式：若开启，故意保持连接睡眠 3 秒消耗攻击方扫描线程并发
                if use_tarpit:
                    time.sleep(3.0)
            except Exception:
                pass

            try:
                # TCP RST 伪装关闭模式：设置 SO_LINGER 超时为 0，调用 close() 时内核直接发送 TCP RST 报文
                # 瞬间断开攻击者连接，杜绝 TIME_WAIT/CLOSE_WAIT 堆积，向扫描工具伪装端口已重置关闭
                client_sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', 1, 0))
            except Exception:
                pass
            try:
                client_sock.close()
            except Exception:
                pass

        reason_text = f"探测蜜罐端口 {port} ({port_info.get('name')})"
        if sample_urls_found:
            reason_text += f" [提取木马下载源: {', '.join(sample_urls_found[:2])}]"
        elif payload_captured:
            printable_p = "".join(c for c in payload_captured if 32 <= ord(c) <= 126 or '\u4e00' <= c <= '\u9fff')
            clean_p = " ".join(printable_p.split())[:35]
            if clean_p:
                reason_text += f" [捕获载荷: {clean_p}]"

        print(f"[ALERT] 捕获真实攻击: IP {client_ip} 触发蜜罐 {port} - {reason_text}")
        _THREAT_ENGINE.add_score(client_ip, 100)
        ban_ip(client_ip, port, port_info, reason=reason_text, level="极高危")

    def _loop(self):
        while self.running:
            try:
                if not self.sockets:
                    time.sleep(1)
                    continue
                
                if self.epoll:
                    events = self.epoll.poll(timeout=1.0)
                    for fd, event in events:
                        if (event & select.EPOLLIN) and (fd in self.sockets):
                            s, port = self.sockets[fd]
                            try:
                                client_sock, client_addr = s.accept()
                                client_ip = client_addr[0]
                                
                                # 严格忽略本机及本地回环测试流量
                                if client_ip in ("127.0.0.1", "::1", "localhost") or client_ip.startswith("127."):
                                    client_sock.close()
                                    continue
                                
                                port_info = self.trap_map.get(port, {"name": f"TCP/{port}", "category": "custom", "level": "高危"})
                                _EXECUTOR.submit(self._handle_trap_client, client_sock, client_addr, port, port_info)
                            except Exception:
                                time.sleep(0.01)
                else:
                    # 回退到 select (仅在无 epoll 平台)
                    sock_list = [s for s, _ in list(self.sockets.values())[:1000]]
                    readable, _, _ = select.select(sock_list, [], [], 1.0)
                    for s in readable:
                        for fd, (sock_obj, port) in list(self.sockets.items()):
                            if sock_obj == s:
                                try:
                                    client_sock, client_addr = s.accept()
                                    client_ip = client_addr[0]
                                    
                                    if client_ip in ("127.0.0.1", "::1", "localhost") or client_ip.startswith("127."):
                                        client_sock.close()
                                        continue
                                    
                                    port_info = self.trap_map.get(port, {"name": f"TCP/{port}", "category": "custom", "level": "高危"})
                                    _EXECUTOR.submit(self._handle_trap_client, client_sock, client_addr, port, port_info)
                                except Exception:
                                    time.sleep(0.01)
            except Exception as e:
                time.sleep(0.5)


_SCAN_RECORDS_LOCK = threading.Lock()
_SCAN_RECORDS = {}  # ip -> list of (timestamp, dst_port)

def check_port_scan_attack(src_ip, dst_port, cfg):
    """
    智能恶意端口扫描与探测识别引擎：
    滑动时间窗口感知：当单个外部源 IP 在短时间（如 15 秒）内探测了 >= 3 个不同的未开放/探针端口时，
    判定为恶意扫描探测攻击（如 Nmap, Masscan, ZGrab 等），返回 True 触发拉黑。
    """
    if not cfg.get("enable_port_scan_defense", True):
        return False
    
    window = int(cfg.get("port_scan_window_seconds", 15) or 15)
    threshold = int(cfg.get("port_scan_threshold", 1) or 1)
    now = time.time()
    cutoff = now - window

    with _SCAN_RECORDS_LOCK:
        if src_ip not in _SCAN_RECORDS:
            _SCAN_RECORDS[src_ip] = []
        # 清理超出时间窗口的记录
        valid_records = [r for r in _SCAN_RECORDS[src_ip] if r[0] >= cutoff]
        valid_records.append((now, dst_port))
        _SCAN_RECORDS[src_ip] = valid_records

        # 统计窗口内探测的不同端口总数
        probed_ports = set(r[1] for r in valid_records)
        if len(probed_ports) >= threshold:
            # 触发多端口扫描识别
            _SCAN_RECORDS.pop(src_ip, None)
            return True
    return False

# 全局单例异步工作线程池 (限制最大 8 线程并发，防止极端流量下线程爆满)
_EXECUTOR = ThreadPoolExecutor(max_workers=8, thread_name_prefix="SentryWorker")

class GlobalPortSniffer:
    """
    基于 Linux 原生网络层数据包感知的智能网络嗅探与多端口扫描防御引擎。
    """
    def __init__(self):
        self.running = False
        self.raw_sock = None
        self._sniffer_thread = None
        self.local_ips = set(get_local_ips())
        self._recent_cache = {}  # (src_ip, dst_port, proto) -> timestamp

    def start(self):
        if self.running:
            return
        self.running = True
        self._sniffer_thread = threading.Thread(target=self._sniff_loop, daemon=True)
        self._sniffer_thread.start()
        print("[GlobalSniffer] Linux 原生网络层数据包感知与蜜罐拦截引擎已启动...")

    def stop(self):
        self.running = False
        if self.raw_sock:
            try:
                self.raw_sock.close()
            except Exception:
                pass

    def _sniff_loop(self):
        try:
            self.raw_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        except PermissionError:
            print("[GlobalSniffer] 启动失败：需要 root 权限以监听原生网络数据包。")
            self.running = False
            return
        except Exception as e:
            print(f"[GlobalSniffer] 创建 TCP Raw Socket 异常: {e}")
            self.running = False
            return

        # 尝试启动 UDP Raw Socket 监听以捕获 UDP 探针扫描
        self.raw_sock_udp = None
        try:
            self.raw_sock_udp = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
        except Exception:
            pass

        while self.running:
            try:
                sock_list = [self.raw_sock]
                if self.raw_sock_udp:
                    sock_list.append(self.raw_sock_udp)
                
                readable, _, _ = select.select(sock_list, [], [], 1.0)
                for sock in readable:
                    raw_data, _ = sock.recvfrom(65535)
                    parsed = parse_packet(raw_data)
                    if not parsed:
                        continue
                    src_ip, dst_port, proto_str = parsed
                    stealth_type = getattr(parsed, 'stealth_type', None)
                    dst_ip = getattr(parsed, 'dst_ip', None)

                    # 1. 严格方向判定：数据包的目的 IP (dst_ip) 必须是本机拥有的网卡 IP 或全局广播地址
                    # 避免系统主动向外发起连接时的外部回包被逆向判为恶意探测
                    if dst_ip and dst_ip not in self.local_ips and not dst_ip.startswith("255.") and not dst_ip.startswith("224.") and not dst_ip.startswith("ff02"):
                        # 如果目的 IP 不是本机网卡，说明是本机路由转发或出站相关报文，绝对忽略
                        continue

                    # 2. 过滤本机发出的包、回环流量、私网地址 (10.x, 192.168.x, 172.16-31.x)、IPv6 内部地址与私有 Docker 内部流量
                    if (src_ip in self.local_ips
                            or src_ip.startswith("127.")
                            or src_ip == "0.0.0.0"
                            or src_ip.startswith("10.")
                            or src_ip.startswith("192.168.")
                            or src_ip.startswith("172.16.") or src_ip.startswith("172.17.")
                            or src_ip.startswith("172.18.") or src_ip.startswith("172.19.")
                            or src_ip.startswith("172.2") or src_ip.startswith("172.3")
                            or src_ip == "::1"
                            or src_ip.startswith("fe80:")
                            or src_ip.startswith("fc")
                            or src_ip.startswith("fd")):
                        continue

                    now_ts = time.time()
                    cache_key = (src_ip, dst_port, proto_str)
                    # 1秒内相同 IP + 端口去重防抖 (防单次突发报文风暴)
                    if cache_key in self._recent_cache:
                        if now_ts - self._recent_cache[cache_key] < 1.0 and not stealth_type:
                            continue
                    self._recent_cache[cache_key] = now_ts
                    
                    # 定期清理防抖缓存
                    if len(self._recent_cache) > 2000:
                        cutoff = now_ts - 15.0
                        self._recent_cache = {k: v for k, v in self._recent_cache.items() if v > cutoff}
                        
                    # 异步记录此端口连接事件
                    self._handle_port_access(src_ip, dst_port, proto=proto_str, stealth_type=stealth_type)
            except Exception:
                time.sleep(0.01)

    def _handle_port_access(self, src_ip, dst_port, proto="TCP", stealth_type=None):
        # 1. 严格豁免公共基础设施与 DNS IP (1.1.1.1, 8.8.8.8 等)，彻底杜绝影响 VPS 正常上网与 DNS 解析
        if src_ip in PUBLIC_INFRASTRUCTURE_IPS:
            return

        cfg = load_config()
        whitelist = cfg.get("whitelist", [])
        active_ports_map = get_active_system_ports()
        trap_meta = is_trap_port(dst_port, cfg)

        # 2. UDP 协议保护：仅处理显式配置的蜜罐探针端口，彻底忽略一切 UDP 偶发/回包/代理转发流量
        if proto == "UDP" and not trap_meta:
            return

        # 0. 优先检测并直接秒杀 Nmap 高级隐蔽/畸形扫描 (NULL, FIN, XMAS, SYN-FIN, SYN-RST)
        if stealth_type:
            stealth_names = {
                "NULL_SCAN": "Nmap空标志位扫描 (NULL Scan)",
                "FIN_SCAN": "Nmap FIN隐蔽扫描 (FIN Scan)",
                "XMAS_SCAN": "Nmap圣诞树异常扫描 (XMAS Scan)",
                "SYN_FIN_SCAN": "TCP SYN-FIN畸形逃逸扫描",
                "SYN_RST_SCAN": "TCP SYN-RST异常扫描"
            }
            desc = stealth_names.get(stealth_type, f"TCP畸形逃逸扫描 ({stealth_type})")
            port_info = {
                "name": f"{desc} (探测端口 {dst_port})",
                "category": "scan",
                "level": "极高危",
                "is_business": False
            }
            print(f"[STEALTH] 捕获高级逃逸扫描: IP {src_ip} -> {desc}")
            _THREAT_ENGINE.add_score(src_ip, 100)
            _EXECUTOR.submit(ban_ip, src_ip, dst_port, port_info)
            return
        
        def _async_write(act, d):
            log_port_access_entry(src_ip, dst_port, port_name=d, action=act)

        # 1. 优先检查用户手动配置的显式白名单与本地防自锁
        is_user_white = False
        if src_ip in ("127.0.0.1", "::1", "localhost") or src_ip.startswith("127."):
            is_user_white = True
        elif whitelist:
            for item in whitelist:
                w_ip = (item.get("ip") if isinstance(item, dict) else str(item)).strip()
                if w_ip and (src_ip == w_ip or (src_ip.startswith("127.") and w_ip.startswith("127."))):
                    is_user_white = True
                    break

        if is_user_white:
            action = "WHITELIST"
            proc = active_ports_map.get(dst_port, KNOWN_SYSTEM_SERVICES.get(dst_port, ""))
            desc = f"信任白名单连接: {proc} (端口 {dst_port})" if proc else f"信任白名单连接 (端口 {dst_port})"
            _EXECUTOR.submit(_async_write, action, desc)
            return

        # 1.5 严格屏蔽已被封禁的黑名单 IP 嗅探流量：防止已拉黑恶意 IP 的残余网络包被误判记录为正常业务
        blacklisted_set = get_blacklisted_ips_set()
        if src_ip in blacklisted_set:
            return

        # 2. Web 控制台端口保护
        web_port = int(cfg.get("web_port", 9099) or 9099)
        if dst_port == web_port:
            action = "BUSINESS"
            desc = "PortGuard Web控制台"
            _EXECUTOR.submit(_async_write, action, desc)
            return

        biz_ports_map = {}
        for bp in cfg.get("business_ports", DEFAULT_CONFIG.get("business_ports", [])):
            if isinstance(bp, int):
                biz_ports_map[bp] = {"port": bp, "name": f"业务端口 ({bp})", "block_idc": False, "block_scanner": True}
            elif isinstance(bp, dict) and "port" in bp:
                try:
                    p = int(bp["port"])
                    biz_ports_map[p] = bp
                except Exception:
                    pass

        if dst_port in biz_ports_map:
            biz_info = biz_ports_map[dst_port]
            biz_name = biz_info.get("name", f"业务端口 ({dst_port})") if isinstance(biz_info, dict) else f"业务端口 ({dst_port})"
            block_idc = bool(biz_info.get("block_idc", False)) if isinstance(biz_info, dict) else False
            block_scanner = bool(biz_info.get("block_scanner", True)) if isinstance(biz_info, dict) else True

            # 1. 优先检测是否为网络空间测绘引擎 (Censys, Shodan, Onyphe 等)
            if block_scanner and is_survey_scanner_ip(src_ip):
                action = "INTERCEPTED"
                desc = f"测绘扫描拦截: 探测业务端口 {dst_port} ({biz_name})"
                port_info = {
                    "name": desc,
                    "category": "survey",
                    "level": "高危",
                    "is_business": False
                }
                _EXECUTOR.submit(ban_ip, src_ip, dst_port, port_info, reason=desc)
                return

            # 2. 检查是否为云厂商/IDC机房探针 (仅在该业务端口开启了 block_idc 时生效，公共 CDN 如 Cloudflare 节点除外)
            if block_idc and is_idc_hosting_ip(src_ip) and not is_infrastructure_or_cdn_ip(src_ip):
                action = "INTERCEPTED"
                desc = f"扫描拦截: 云厂商机房源探测业务端口 {dst_port} ({biz_name})"
                port_info = {
                    "name": desc,
                    "category": "idc_probe",
                    "level": "中危",
                    "is_business": False
                }
                _EXECUTOR.submit(ban_ip, src_ip, dst_port, port_info, reason=desc)
                return

            action = "BUSINESS"
            desc = f"业务访问: {biz_name} (端口 {dst_port})"
            _EXECUTOR.submit(_async_write, action, desc)
            return

        # 3. 检查是否命中显式配置的防御诱捕蜜罐规则 (P3 优先级，蜜罐探针端口一律秒级诱捕拦截)
        if trap_meta and trap_meta.get("enabled", True):
            action = "INTERCEPTED"
            trap_name = trap_meta.get("name") or trap_meta.get("description") or f"TCP/{dst_port}"
            desc = f"探测蜜罐端口 {dst_port} ({trap_name})" if not str(trap_name).startswith("探测蜜罐端口") else str(trap_name)
            port_info = {
                "name": desc,
                "category": trap_meta.get("category", "honeypot"),
                "level": trap_meta.get("level", "高危"),
                "is_business": False
            }
            _EXECUTOR.submit(ban_ip, src_ip, dst_port, port_info, reason=desc)
            return

        # 4. 系统内核实际 LISTEN 监听的未配置活跃系统端口放行（如非标 SSH 端口等，绝不误判为未开放端口探测 PROBE 或多端口扫描）
        is_zero_trust_all = bool(cfg.get("trap_all_ports", False) and cfg.get("trap_business_ports", False))
        if dst_port in active_ports_map and not is_zero_trust_all:
            svc_name = active_ports_map.get(dst_port, KNOWN_SYSTEM_SERVICES.get(dst_port, f"系统服务 ({dst_port})"))
            if is_survey_scanner_ip(src_ip):
                action = "INTERCEPTED"
                desc = f"测绘扫描拦截: 探测系统监听端口 {dst_port} ({svc_name})"
                port_info = {
                    "name": desc,
                    "category": "survey",
                    "level": "高危",
                    "is_business": False
                }
                _EXECUTOR.submit(ban_ip, src_ip, dst_port, port_info, reason=desc)
                return

            action = "BUSINESS"
            desc = f"业务访问: {svc_name} (端口 {dst_port})"
            _EXECUTOR.submit(_async_write, action, desc)
            return

        # 5. 恶意访问行为 ②：多端口扫描与探针攻击检测 (Nmap/Masscan 等扫描器识别)
        if check_port_scan_attack(src_ip, dst_port, cfg):
            action = "INTERCEPTED"
            threshold = int(cfg.get("port_scan_threshold", 1) or 1)
            desc = f"未开放端口扫描探测 (目标端口 {dst_port})" if threshold <= 1 else f"多端口扫描探测 (目标端口 {dst_port})"
            port_info = {
                "name": desc,
                "category": "scan",
                "level": "高危",
                "is_business": False
            }
            _EXECUTOR.submit(ban_ip, src_ip, dst_port, port_info)
            return

        # 6. 其他全端口全量防御（仅在显式勾选全端口防御时生效，默认关闭）
        if bool(cfg.get("trap_all_ports", False)) or bool(cfg.get("trap_all_unopened_ports", False)):
            action = "INTERCEPTED"
            desc = f"全端口防御拦截 (未开放端口 {dst_port})"
            port_info = {
                "name": desc,
                "category": "scan",
                "level": "高危",
                "is_business": False
            }
            _EXECUTOR.submit(ban_ip, src_ip, dst_port, port_info)
            return

        # 7. 常规单次未开放端口偶发探测（未达到扫描器判定标准，仅记录访问审计日志，不封禁）
        action = "PROBE"
        desc = f"未开放端口探测 (端口 {dst_port})"
        _EXECUTOR.submit(_async_write, action, desc)

class SiteLogCollector:
    """自动扫描并实时采集 OpenResty / Nginx 业务站点的 access.log 访问日志"""
    def __init__(self):
        self.running = False
        self._file_offsets = {}
        self._seen_lines = set()

    def start(self):
        if self.running:
            return
        self.running = True
        threading.Thread(target=self._collector_loop, daemon=True).start()
        print("[SiteCollector] HTTPS 业务网站访问日志采集引擎已激活...")

    def stop(self):
        self.running = False

    def _discover_log_files(self):
        """自动发现系统中的 OpenResty / Nginx 站点访问日志文件"""
        files = []
        seen_paths = set()
        
        # 1. 1Panel OpenResty 站点目录 (覆盖各版本路径层级)
        site_globs = [
            "/opt/1panel/www/sites/*/log/access.log",
            "/opt/1panel/apps/openresty/openresty/www/sites/*/log/access.log",
            "/www/wwwlogs/*.log",
            "/var/log/nginx/domains/*.log"
        ]
        for pattern in site_globs:
            for p in glob.glob(pattern):
                if os.path.exists(p) and p not in seen_paths:
                    seen_paths.add(p)
                    parts = p.split(os.sep)
                    try:
                        if "sites" in parts:
                            site_idx = parts.index("sites")
                            domain = parts[site_idx + 1]
                        elif "wwwlogs" in parts:
                            domain = os.path.basename(p).replace(".log", "").replace(".access", "")
                        else:
                            domain = os.path.basename(os.path.dirname(os.path.dirname(p)))
                    except Exception:
                        domain = "1Panel站点"
                    files.append((p, domain))

        # 2. 1Panel 全局访问日志 (默认兜底站点 / IP 直连)
        for global_p in ["/opt/1panel/apps/openresty/openresty/log/access.log", "/opt/1panel/log/access.log"]:
            if os.path.exists(global_p) and global_p not in seen_paths:
                seen_paths.add(global_p)
                files.append((global_p, "__DIRECT_IP__"))

        # 3. 标准系统 Nginx 路径
        for p in glob.glob("/var/log/nginx/*access*.log"):
            if os.path.exists(p) and p not in seen_paths:
                seen_paths.add(p)
                bname = os.path.basename(p).replace(".access.log", "").replace("access.log", "").replace(".log", "")
                domain = bname if bname and bname != "nginx" else "__DIRECT_IP__"
                files.append((p, domain))

        for p in glob.glob("/www/server/nginx/logs/*access*.log"):
            if os.path.exists(p) and p not in seen_paths:
                seen_paths.add(p)
                files.append((p, "BT-Nginx"))

        return files

    def _collector_loop(self):
        log_regex = re.compile(
            r'^(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<time>[^\]]+)\]\s+"(?P<request>[^"]*)"\s+(?P<status>\d+)\s+\S+(?:\s+"(?P<ref>[^"]*)"\s+"(?P<ua>[^"]*)")?(?:\s+"(?P<xff>[^"]*)")?'
        )
        
        while self.running:
            try:
                log_targets = self._discover_log_files()
                new_records = []
                
                for filepath, default_domain in log_targets:
                    try:
                        if not os.path.exists(filepath):
                            continue
                        size = os.path.getsize(filepath)
                        
                        # 首次发现此文件：从末尾向前读取约 32KB（约 150 条最新记录）
                        if filepath not in self._file_offsets:
                            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                                if size > 32768:
                                    f.seek(size - 32768)
                                    f.readline()
                                lines = f.readlines()
                                self._file_offsets[filepath] = f.tell()
                        else:
                            last_pos = self._file_offsets[filepath]
                            if size < last_pos:
                                last_pos = 0
                            if size == last_pos:
                                continue
                            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                                f.seek(last_pos)
                                lines = f.readlines()
                                self._file_offsets[filepath] = f.tell()

                        for line in lines:
                            line = line.strip()
                            if not line:
                                continue
                            line_hash = (filepath, line)
                            if line_hash in self._seen_lines:
                                continue
                            self._seen_lines.add(line_hash)
                            if len(self._seen_lines) > 8000:
                                self._seen_lines.clear()

                            m = log_regex.match(line)
                            if not m:
                                continue
                            raw_ip = m.group("ip")
                            xff = (m.group("xff") or "").strip()
                            
                            # 智能识别 CDN 与真实客户端 IP
                            client_ip = raw_ip
                            if xff and xff not in ("-", "null", "None"):
                                candidate_ips = [x.strip() for x in xff.split(",") if x.strip()]
                                for cand in candidate_ips:
                                    v_cand = validate_ip(cand)
                                    if v_cand and not is_infrastructure_or_cdn_ip(v_cand):
                                        client_ip = v_cand
                                        break
                                        
                            if not validate_ip(client_ip) and not (":" in client_ip or "." in client_ip):
                                continue

                            time_str = m.group("time")
                            request = m.group("request") or ""
                            status = int(m.group("status") or 200)
                            ref = (m.group("ref") or "").strip()
                            ua = m.group("ua") or ""

                            # 域名解析：优先站点目录域名，若是全局/直连日志且 Referer 中包含完整 URL 则提取 Host
                            req_domain = default_domain
                            if (req_domain in ("__DIRECT_IP__", "纯IP直连", "全局反代", "Nginx主站", "")) and ref and (ref.startswith("http://") or ref.startswith("https://")):
                                try:
                                    extracted = ref.split("/")[2].split(":")[0]
                                    if extracted and not extracted.replace(".", "").isdigit():
                                        req_domain = extracted
                                except Exception:
                                    pass

                            if req_domain in ("__DIRECT_IP__", "纯IP直连", "全局反代", "Nginx主站", ""):
                                srv_ip = get_local_public_ip()
                                req_domain = srv_ip if srv_ip else "IP直连"

                            req_parts = request.split()
                            if len(req_parts) >= 2:
                                method = req_parts[0]
                                path = req_parts[1]
                            elif len(req_parts) == 1:
                                method = req_parts[0]
                                path = "/"
                            else:
                                method = "GET"
                                path = "/"

                            try:
                                raw_t = time_str.split()[0]
                                t_struct = time.strptime(raw_t, "%d/%b/%Y:%H:%M:%S")
                                ftime = time.strftime("%Y-%m-%d %H:%M:%S", t_struct)
                                ts = int(time.mktime(t_struct))
                            except Exception:
                                ftime = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
                                ts = int(time.time())

                            geo = _GEO_CACHE.get(client_ip) or resolve_ip_geo_local(client_ip) or {}
                            country = geo.get("country") or "公网节点"
                            region = geo.get("region", "")
                            city = geo.get("city", "")
                            isp = geo.get("isp", "")
                            new_records.append((client_ip, req_domain, method, path, status, ua, country, region, city, isp, ftime, ts))
                            try:
                                if not is_infrastructure_or_cdn_ip(client_ip):
                                    check_http_request_traps(client_ip, req_domain, method, path, status, ua)
                            except Exception:
                                pass
                    except Exception:
                        pass

                if new_records:
                    try:
                        conn = get_db()
                        c = conn.cursor()
                        c.executemany("""
                        INSERT INTO access_logs (ip, domain, method, path, status_code, user_agent, country, region, city, isp, access_time, timestamp)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """, new_records)
                        conn.commit()
                        conn.close()
                    except Exception:
                        pass

            except Exception:
                pass
            time.sleep(2)

def config_watcher_loop():
    """实时监听 config.json 文件变更，动态热重载蜜罐监听套接字"""
    last_mtime = 0
    while True:
        try:
            if os.path.exists(CONFIG_PATH):
                mtime = os.path.getmtime(CONFIG_PATH)
                if last_mtime != 0 and mtime > last_mtime:
                    print("[ConfigWatcher] 检测到 config.json 变更，正在动态热重载蜜罐监听...")
                    trap_instance.reload()
                last_mtime = mtime
        except Exception:
            pass
        time.sleep(2)

trap_instance = TrapServer()
sniffer_instance = GlobalPortSniffer()
site_collector_instance = SiteLogCollector()

# 启动异步批量日志落盘线程
_batch_worker_thread = threading.Thread(target=_batch_log_worker, daemon=True, name="BatchLogWorker")
_batch_worker_thread.start()

if __name__ == "__main__":
    init_db()
    init_firewall_ipset()
    trap_instance.start()
    sniffer_instance.start()
    site_collector_instance.start()
    _EXECUTOR.submit(cleanup_loop)
    _EXECUTOR.submit(config_watcher_loop)
    while True:
        time.sleep(3600)
