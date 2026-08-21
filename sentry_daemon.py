#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PortGuard Core Daemon v2.0 - 智能端口诱捕与主动威胁防御引擎
"""
import glob
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

DEFAULT_CONFIG = {
    "trap_ports": [
        {"port": 21, "name": "FTP 暴力破解诱饵", "category": "ftp", "enabled": True, "level": "高危"},
        {"port": 23, "name": "Telnet 弱口令嗅探", "category": "telnet", "enabled": True, "level": "高危"},
        {"port": 135, "name": "RPC 远程调用映射", "category": "smb", "enabled": True, "level": "高危"},
        {"port": 139, "name": "NetBIOS 局域网嗅探", "category": "smb", "enabled": True, "level": "中危"},
        {"port": 445, "name": "SMB / 永恒之蓝漏洞探测", "category": "smb", "enabled": True, "level": "极高危"},
        {"port": 1433, "name": "MSSQL 数据库暴力嗅探", "category": "db", "enabled": True, "level": "高危"},
        {"port": 3389, "name": "RDP 远程桌面爆破探测", "category": "rdp", "enabled": True, "level": "极高危"},
        {"port": 5900, "name": "VNC 屏幕控制漏洞探测", "category": "rdp", "enabled": True, "level": "高危"},
        {"port": 6379, "name": "Redis 未授权提权探针", "category": "db", "enabled": True, "level": "极高危"},
        {"port": 8888, "name": "宝塔 / 管理控制台探针", "category": "web", "enabled": True, "level": "中危"},
        {"port": 9200, "name": "Elasticsearch RCE 探测", "category": "db", "enabled": True, "level": "高危"},
        {"port": 27017, "name": "MongoDB 默认数据库探针", "category": "db", "enabled": True, "level": "高危"}
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
    "web_bind": "0.0.0.0",
    "admin_password": "admin",
    "defense_mode": "standard",
    "ban_action_iptables": True,
    "ban_action_blackhole": True,
    "auto_clean_days": 30,
    "trap_threshold": 2,
    "trap_window_seconds": 30,
    "enable_port_scan_defense": True,
    "port_scan_threshold": 3,
    "port_scan_window_seconds": 15,
    "trap_business_ports": False,
    "trap_all_unopened_ports": False,
    "trap_all_ports": False,
    "defense_paused": False,
    "node_name": "本机节点",
    "cluster_sync": {
        "enabled": False,
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
        "name": "敏感配置与备份嗅探",
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
        "name": "高危管理后台探针",
        "match_type": "path_keyword",
        "pattern": r"phpmyadmin|admin\.php|wp-login\.php|actuator|/solr/|/manager/html|/api/v1/debug",
        "threshold": 1,
        "window": 30,
        "action": "ban",
        "level": "极高危",
        "enabled": 1,
        "description": "嗅探常见管理控制台、框架调试接口与后台入口"
    },
    {
        "rule_id": "ht_traversal_rce",
        "name": "路径遍历与系统文件嗅探",
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
        "name": "黑客扫描器工具指纹",
        "match_type": "ua_keyword",
        "pattern": r"sqlmap|nikto|dirsearch|gobuster|wpscan|masscan|hydra|acunetix|nessus|zgrab",
        "threshold": 1,
        "window": 30,
        "action": "ban",
        "level": "高危",
        "enabled": 1,
        "description": "拦截携带明确特征扫描工具指纹的自动化探测源"
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
        "description": "精准拦截 Censys, Shodan, Onyphe 等全球资产测绘引擎的漏洞与端口嗅探"
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
        "description": "拦截未携带合法域名 Host、直接通过服务器 IP 地址进行全网地毯式盲扫的 Web 探测"
    },
    {
        "rule_id": "ht_rate_404",
        "name": "高频 404/403 爆破熔断",
        "match_type": "status_rate",
        "pattern": "",
        "threshold": 6,
        "window": 30,
        "action": "ban",
        "level": "高危",
        "enabled": 1,
        "description": "30秒内对不存在路径连续产生 6 次以上 404/403 异常直接熔断拉黑"
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

DEFAULT_CONFIG["http_traps"] = DEFAULT_HTTP_TRAPS
PORT_DESCRIPTIONS = {t["port"]: t["name"] for t in DEFAULT_CONFIG["trap_ports"]}

# 全局线程池：限制并发，避免扫描风暴下线程爆炸
_EXECUTOR = ThreadPoolExecutor(max_workers=8, thread_name_prefix="sentry")


def validate_ip(ip):
    """严格校验 IPv4 / IPv6 地址，拒绝任何带端口、路径或 shell 元字符的输入。"""
    if not ip or not isinstance(ip, str):
        return None
    ip = ip.strip()
    if not ip:
        return None
    # 明确拒绝 shell 元字符与 URL 形态
    if re.search(r"[;&|`$()<>\"'\\ \t\n\r]", ip):
        return None
    try:
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


def init_firewall_ipset():
    """初始化 ipset 哈希表并在 iptables / ip6tables INPUT 链首行挂载单一规则，实现 O(1) 百万级黑名单拦截。"""
    if not is_ipset_available():
        return False
    try:
        # 1. 创建 IPv4 与 IPv6 黑名单 ipset 集合 (支持 hash:ip)
        subprocess.run(["ipset", "create", "portguard_blacklist_v4", "hash:ip", "hashsize", "4096", "maxelem", "1000000", "-exist"],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["ipset", "create", "portguard_blacklist_v6", "hash:ip", "family", "inet6", "hashsize", "4096", "maxelem", "1000000", "-exist"],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

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
        
        # 4. 强制从黑名单与防火墙解封所有基础设施 IP (1.1.1.1, 8.8.8.8 等公网权威 DNS)
        for safe_ip in PUBLIC_INFRASTRUCTURE_IPS:
            unban_ip_core(safe_ip)

        # 5. 同步数据库中已有黑名单至 ipset 集合 (服务启动恢复)
        conn = get_db()
        c = conn.cursor()
        c.execute("SELECT ip FROM blacklist")
        for row in c.fetchall():
            ip_val = validate_ip(row["ip"])
            if ip_val and ip_val not in PUBLIC_INFRASTRUCTURE_IPS:
                ban_ip_firewall(ip_val)
        conn.close()
        return True
    except Exception as e:
        print(f"[IPSET] 初始化异常: {e}")
        return False


def ban_ip_firewall(ip):
    """下发内核拦截：优先写入 ipset 集合并下发黑洞路由，降级兼容原生 iptables。"""
    valid_ip = validate_ip(ip)
    if not valid_ip or valid_ip in PUBLIC_INFRASTRUCTURE_IPS:
        return
    ip = valid_ip
    try:
        addr_obj = ipaddress.ip_address(ip)
        is_ipv6 = addr_obj.version == 6
        set_name = "portguard_blacklist_v6" if is_ipv6 else "portguard_blacklist_v4"
        fw_tool = "ip6tables" if is_ipv6 else "iptables"
        save_tool = "ip6tables-save" if is_ipv6 else "iptables-save"
        mask = "/128" if is_ipv6 else "/32"

        # 1. 优先使用 ipset O(1) 集合
        if is_ipset_available():
            subprocess.run(["ipset", "add", set_name, ip, "-exist"],
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
    """获取本机所有 IP 地址集合（包括回环、公网及局域网 IP）"""
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
    return ips


class ParsedPacket(tuple):
    """兼具 3 元组兼容性与隐蔽扫描属性扩展的数据包解析结果"""
    def __new__(cls, src_ip, dst_port, proto_str, stealth_type=None):
        return super(ParsedPacket, cls).__new__(cls, (src_ip, dst_port, proto_str))

    def __init__(self, src_ip, dst_port, proto_str, stealth_type=None):
        self.src_ip = src_ip
        self.dst_port = dst_port
        self.proto = proto_str
        self.stealth_type = stealth_type


def parse_packet(raw_data):
    """解析以太网帧 / SLL 帧 / 原始 IP 报文 (IPv4 / IPv6) 中的 TCP/UDP 报文与隐蔽畸形扫描标志位。

    返回 ParsedPacket(src_ip, dst_port, proto_str, stealth_type) 或 None。
    """
    try:
        if not raw_data or len(raw_data) < 20:
            return None

        offset = 0
        # 1. 优先判定 offset=0 (原始 IP 报文，Linux SOCK_RAW 绝大多数形态)
        if (raw_data[0] >> 4) in (4, 6):
            offset = 0
        elif len(raw_data) >= 34 and ((raw_data[14] >> 4) in (4, 6)):
            offset = 14
        elif len(raw_data) >= 36 and ((raw_data[16] >> 4) in (4, 6)):
            offset = 16
        else:
            return None

        version = raw_data[offset] >> 4
        if version == 4:
            if len(raw_data) < offset + 20:
                return None
            ip_hdr = raw_data[offset:offset + 20]
            proto_num = ip_hdr[9]
            ihl = (ip_hdr[0] & 0x0F) * 4
            if ihl < 20 or len(raw_data) < offset + ihl + 4:
                return None
            src_ip = socket.inet_ntoa(ip_hdr[12:16])
        elif version == 6:
            if len(raw_data) < offset + 40:
                return None
            ip_hdr = raw_data[offset:offset + 40]
            proto_num = ip_hdr[6]  # next header
            ihl = 40
            if len(raw_data) < offset + ihl + 4:
                return None
            src_ip = socket.inet_ntop(socket.AF_INET6, ip_hdr[8:24])
        else:
            return None

        if proto_num not in (6, 17):  # 仅 TCP / UDP
            return None
        proto_str = "TCP" if proto_num == 6 else "UDP"

        stealth_type = None
        if proto_num == 6 and len(raw_data) >= offset + ihl + 14:
            tcp_flags = raw_data[offset + ihl + 13]
            # 深度检测 Nmap 隐蔽逃逸扫描标志位 (NULL, FIN, XMAS, SYN-FIN, SYN-RST)
            if tcp_flags == 0:
                stealth_type = "NULL_SCAN"
            elif tcp_flags == 0x01:  # 仅 FIN
                stealth_type = "FIN_SCAN"
            elif (tcp_flags & 0x29) == 0x29:  # FIN(1) + PSH(8) + URG(32)
                stealth_type = "XMAS_SCAN"
            elif (tcp_flags & 0x03) == 0x03:  # SYN(2) + FIN(1)
                stealth_type = "SYN_FIN_SCAN"
            elif (tcp_flags & 0x06) == 0x06:  # SYN(2) + RST(4)
                stealth_type = "SYN_RST_SCAN"
            elif (tcp_flags & 0x02) and not (tcp_flags & 0x10):
                stealth_type = None  # 正常标准 TCP SYN 连接探测
            else:
                # 过滤已建立连接的数据流与纯 ACK
                return None

        l4_hdr = raw_data[offset + ihl:offset + ihl + 4]
        if len(l4_hdr) < 4:
            return None
        src_port, dst_port = struct.unpack("!HH", l4_hdr[:4])

        # 若为 UDP 协议：必须严格过滤所有出站回包与代理转发流量！
        if proto_num == 17:
            # 1. 常见公共服务源端口返回流量（DNS 53/853/5353, NTP 123, HTTPS/QUIC 443/80, OpenVPN 1194 等）直接丢弃
            if src_port in (53, 123, 853, 5353, 443, 80, 1194, 51820):
                return None
            # 2. 目标端口属于出站临时随机回包端口 (ephemeral ports >= 1024) 彻底忽略
            # (彻底避免 Trojan、代理转发、DNS、QUIC 正常出站回包被误判为入站端口扫描)
            if dst_port >= 1024:
                return None

        return ParsedPacket(src_ip, dst_port, proto_str, stealth_type=stealth_type)
    except Exception:
        return None

def parse_port_range(port_val):
    """解析单个端口或端口范围，返回 (start_port, end_port, display_str) 或 None"""
    if isinstance(port_val, int):
        if 1 <= port_val <= 65535:
            return (port_val, port_val, port_val)
        return None
    s = str(port_val).strip()
    if not s:
        return None
    if s.isdigit():
        p = int(s)
        if 1 <= p <= 65535:
            return (p, p, p)
        return None
    m = re.match(r'^(\d+)\s*[-:~]\s*(\d+)$', s)
    if m:
        p1 = int(m.group(1))
        p2 = int(m.group(2))
        start = min(p1, p2)
        end = max(p1, p2)
        if 1 <= start <= 65535 and 1 <= end <= 65535:
            if start == end:
                return (start, end, start)
            return (start, end, f"{start}-{end}")
    return None

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
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA busy_timeout=10000;")
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
    conn = get_db()
    cursor = conn.cursor()
    try:
        cursor.execute("PRAGMA journal_mode=WAL;")
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


def generate_cluster_token(ip, secret):
    return hmac.new(secret.encode('utf-8'), ip.encode('utf-8'), hashlib.sha256).hexdigest()

def verify_cluster_token(ip, token, secret):
    if not secret or not token:
        return False
    expected = generate_cluster_token(ip, secret)
    return hmac.compare_digest(expected, token)


def normalize_cluster_node(node):
    """规范化协同节点数据结构，确保字段完整并兼容历史字符串格式"""
    if isinstance(node, dict):
        ip = str(node.get("ip", "")).strip()
        port = int(node.get("port", 9099) or 9099)
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
        port = 9099
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
                port = 9099
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


def broadcast_cluster_ban(ip, reason, level):
    cfg = load_config()
    cluster_cfg = cfg.get("cluster_sync", {})
    if not cluster_cfg.get("enabled", False):
        return
    secret = cluster_cfg.get("cluster_secret", "").strip()
    nodes = cluster_cfg.get("cluster_nodes", [])
    if not secret or not nodes:
        return

    token = generate_cluster_token(ip, secret)
    payload = json.dumps({
        "ip": ip,
        "reason": reason,
        "level": level,
        "source_node": cfg.get("node_name", socket.gethostname())
    }).encode("utf-8")

    for raw_node in nodes:
        node = normalize_cluster_node(raw_node)
        if not node or not node.get("ip"):
            continue
        node_url = f"http://{node['ip']}:{node.get('port', 9099)}"
        def _send(url, pl, tk):
            try:
                target = f"{url}/api/cluster/sync_ban"
                req = urllib.request.Request(target, data=pl, headers={
                    "Content-Type": "application/json",
                    "X-Cluster-Token": tk,
                    "User-Agent": "PortGuardMesh/2.0"
                })
                urllib.request.urlopen(req, timeout=3)
            except Exception:
                pass
        _EXECUTOR.submit(_send, node_url, payload, token)


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
                reason = f"Web诱捕: 扫描工具指纹 {ua[:28]}"
                ban_ip(ip, reason=reason, category="web", level=rlevel)
                return True

        # 3. 404/403 频次熔断
        elif mtype == "status_rate":
            if status_code in (404, 403, 400):
                threshold = int(rule.get("threshold") or 6)
                window = int(rule.get("window") or 30)
                with _IP_404_LOCK:
                    history = _IP_404_RATE_CACHE.setdefault(ip, [])
                    history = [item for item in history if now - item[0] <= window]
                    history.append((now, path))
                    _IP_404_RATE_CACHE[ip] = history
                    if len(history) >= threshold:
                        _IP_404_RATE_CACHE[ip] = []
                        reason = f"Web防扫: {window}s内触发 {len(history)}次 404/403 ({path[:20]})"
                        ban_ip(ip, reason=reason, category="web", level=rlevel)
                        return True

        # 4. 全网测绘引擎检测 (Censys, Shodan, Onyphe 等)
        elif mtype == "survey_engine":
            pat = rule.get("pattern", "")
            if is_survey_scanner_ip(ip) or (pat and ua and re.search(pat, ua, re.IGNORECASE)):
                reason = f"测绘拦截: 网络空间测绘引擎嗅探 ({ua[:20] if ua else 'Censys/Onyphe/Shodan'})"
                ban_ip(ip, reason=reason, category="survey", level=rlevel)
                return True

        # 5. 禁止纯 IP 直连 Web 探测
        elif mtype == "direct_ip":
            if req_domain and re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(:\d+)?$", req_domain.strip()):
                reason = f"Web防护: 禁止纯IP直连探测 ({req_domain})"
                ban_ip(ip, reason=reason, category="web", level=rlevel)
                return True
    return False

_WEB_PORT_LOG_CACHE = {}

def log_access_entry(ip, method, path, status_code=200, user_agent=""):
    try:
        if ip in ("127.0.0.1", "::1", "localhost") or ip.startswith("127."):
            return
        now_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        now_ts = int(time.time())
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("""
        INSERT INTO access_logs (ip, method, path, status_code, user_agent, country, region, city, isp, access_time, timestamp)
        VALUES (?, ?, ?, ?, ?, '分析中...', '', '', '', ?, ?)
        """, (ip, method, path, status_code, (user_agent or "")[:200], now_str, now_ts))
        web_log_id = cursor.lastrowid
        
        # 同时以 5 秒防抖在 port_access_logs 中记录 Web 控制台业务连接
        global _WEB_PORT_LOG_CACHE
        last_t = _WEB_PORT_LOG_CACHE.get(ip, 0)
        port_log_id = None
        if (now_ts - last_t) >= 5:
            _WEB_PORT_LOG_CACHE[ip] = now_ts
            cfg = load_config()
            web_port = int(cfg.get("web_port", 9099))
            is_white = ip_in_whitelist(ip, cfg.get("whitelist", []))
            act = "WHITELIST" if is_white else "BUSINESS"
            desc = f"安全白名单访问: Web控制台 (端口 {web_port})" if is_white else f"正常业务连接: PortGuard Web控制台 (端口 {web_port})"
            cursor.execute("""
            INSERT INTO port_access_logs (ip, port, proto, port_name, country, region, city, isp, action, access_time, timestamp)
            VALUES (?, ?, 'TCP', ?, '分析中...', '', '', '', ?, ?, ?)
            """, (ip, web_port, desc, act, now_str, now_ts))
            port_log_id = cursor.lastrowid
            
        conn.commit()
        conn.close()
        
        # 异步解析地理位置
        if ip not in ("127.0.0.1", "::1", "localhost"):
            def _async_geo_web(w_id, p_id, client_ip):
                try:
                    g = resolve_ip_geo(client_ip)
                    c2 = get_db()
                    cur2 = c2.cursor()
                    cur2.execute("""
                    UPDATE access_logs SET country=?, region=?, city=?, isp=? WHERE id=?
                    """, (g.get("country", "公网节点"), g.get("region", ""), g.get("city", ""), g.get("isp", ""), w_id))
                    if p_id:
                        cur2.execute("""
                        UPDATE port_access_logs SET country=?, region=?, city=?, isp=? WHERE id=?
                        """, (g.get("country", "公网节点"), g.get("region", ""), g.get("city", ""), g.get("isp", ""), p_id))
                    c2.commit()
                    c2.close()
                except Exception:
                    pass
            _EXECUTOR.submit(_async_geo_web, web_log_id, port_log_id, ip)
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


def load_config():
    try:
        dir_name = os.path.dirname(CONFIG_PATH)
        if dir_name and not os.path.exists(dir_name):
            os.makedirs(dir_name, exist_ok=True)
        if not os.path.exists(CONFIG_PATH):
            with open(CONFIG_PATH, 'w', encoding='utf-8') as f:
                json.dump(DEFAULT_CONFIG, f, indent=2, ensure_ascii=False)
            return DEFAULT_CONFIG
        with open(CONFIG_PATH, 'r', encoding='utf-8') as f:
            cfg = json.load(f)
            return {**DEFAULT_CONFIG, **cfg}
    except Exception:
        return DEFAULT_CONFIG


def unban_ip_core(ip, status_event="UNBANNED"):
    """彻底解除对指定 IP 的内核防火墙封禁、ipset、黑洞路由及数据库黑名单记录。"""
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

        # 4. 同步清理数据库 blacklist 表并标记 events
        conn = get_db()
        c = conn.cursor()
        c.execute("DELETE FROM blacklist WHERE ip = ?", (ip,))
        c.execute("UPDATE events SET status = ? WHERE ip = ?", (status_event, ip))
        conn.commit()
        conn.close()

        # 重置威胁评分
        _THREAT_ENGINE.reset_score(ip)
        return True
    except Exception:
        return False


def cleanup_expired_bans():
    """定期清理过期封禁：解除 iptables / 黑洞路由并删除黑名单记录。"""
    try:
        cfg = load_config()
        auto_clean_days = int(cfg.get("auto_clean_days", 30) or 30)
        if auto_clean_days <= 0:
            return
        now_ts = int(time.time())
        conn = get_db()
        c = conn.cursor()
        c.execute("SELECT ip FROM blacklist WHERE ban_expire IS NOT NULL AND ban_expire < ?", (now_ts,))
        expired = [r["ip"] for r in c.fetchall()]
        conn.close()
        for ip in expired:
            unban_ip_core(ip, status_event="EXPIRED")
        if expired:
            print(f"[CLEANUP] 已清理 {len(expired)} 条过期封禁")
    except Exception as e:
        print(f"[CLEANUP] 清理失败: {e}")


def cleanup_loop():
    while True:
        time.sleep(3600)
        cleanup_expired_bans()

def save_config(cfg):
    try:
        with open(CONFIG_PATH, 'w', encoding='utf-8') as f:
            json.dump(cfg, f, indent=2, ensure_ascii=False)
        return True
    except Exception:
        return False

_DYNAMIC_SSH_IPS_CACHE = set()
_DYNAMIC_SSH_IPS_LAST_CHECK = 0

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

def get_active_ssh_client_ips():
    """动态探测当前系统所有活跃 SSH 会话的客户端 IP (防管理员自杀保护机制)"""
    global _DYNAMIC_SSH_IPS_CACHE, _DYNAMIC_SSH_IPS_LAST_CHECK
    now = time.time()
    if (now - _DYNAMIC_SSH_IPS_LAST_CHECK < 5) and _DYNAMIC_SSH_IPS_CACHE:
        return _DYNAMIC_SSH_IPS_CACHE
    
    ips = set()
    try:
        # 1. 从 who 命令读取登录客户端 IP
        out = subprocess.check_output("who 2>/dev/null || true", shell=True, text=True)
        for line in out.splitlines():
            m = re.search(r'\(([\d\w\.\:]+)\)', line)
            if m:
                clean_ip = m.group(1).split(':')[0].strip('[]')
                if clean_ip and not clean_ip.startswith("127."):
                    ips.add(clean_ip)
    except Exception:
        pass
    
    try:
        # 2. 从 ss 命令读取已建立的 SSH 连接来源
        ssh_ports = get_system_ssh_ports()
        port_filter = " or ".join([f"sport = :{p}" for p in ssh_ports])
        cmd = f"ss -tn state established '( {port_filter} )' 2>/dev/null || true"
        out = subprocess.check_output(cmd, shell=True, text=True)
        for line in out.splitlines()[1:]:
            parts = line.split()
            if len(parts) >= 4:
                peer = parts[3]
                peer_ip = peer.rsplit(':', 1)[0].strip('[]').replace('::ffff:', '')
                if peer_ip and not peer_ip.startswith("127."):
                    ips.add(peer_ip)
    except Exception:
        pass
    
    _DYNAMIC_SSH_IPS_CACHE = ips
    _DYNAMIC_SSH_IPS_LAST_CHECK = now
    return ips

def ip_in_whitelist(ip, whitelist_items=None):
    if not ip or ip in ("127.0.0.1", "::1", "localhost") or str(ip).startswith("127."):
        return True

    # 基础设施保护：公网权威 DNS (1.1.1.1 / 8.8.8.8 等) 永久放行，严禁任何机制误拉黑
    if str(ip).strip() in PUBLIC_INFRASTRUCTURE_IPS:
        return True

    # 核心防自锁盾：只要当前是正在连接服务器的管理员活跃 SSH 会话，内核级永久放行！
    active_ssh_ips = get_active_ssh_client_ips()
    if ip in active_ssh_ips:
        return True

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

GEO_COUNTRY_CN = {
    "United States": "美国", "United Kingdom": "英国", "Germany": "德国", "France": "法国",
    "Japan": "日本", "South Korea": "韩国", "China": "中国", "Russia": "俄罗斯",
    "Canada": "加拿大", "Australia": "澳大利亚", "Brazil": "巴西", "India": "印度",
    "Singapore": "新加坡", "Hong Kong": "中国香港", "Taiwan": "中国台湾", "Netherlands": "荷兰",
    "The Netherlands": "荷兰", "Italy": "意大利", "Spain": "西班牙", "Vietnam": "越南", "Thailand": "泰国",
    "Indonesia": "印度尼西亚", "Malaysia": "马来西亚", "Philippines": "菲律宾", "Turkey": "土耳其",
    "Ukraine": "乌克兰", "Poland": "波兰", "Sweden": "瑞典", "Switzerland": "瑞士",
    "South Africa": "南非", "Egypt": "埃及", "Mexico": "墨西哥", "Argentina": "阿根廷",
    "Chile": "智利", "Colombia": "哥伦比亚", "Iran": "伊朗", "Israel": "以色列",
    "Saudi Arabia": "沙特阿拉伯", "United Arab Emirates": "阿联酋", "Pakistan": "巴基斯坦",
    "Belgium": "比利时", "Finland": "芬兰", "Bulgaria": "保加利亚", "Romania": "罗马尼亚",
    "Seychelles": "塞舌尔", "Norway": "挪威", "Denmark": "丹麦", "Austria": "奥地利",
    "Czech Republic": "捷克", "Hungary": "匈牙利", "Greece": "希腊", "Portugal": "葡萄牙"
}

def translate_country_cn(name):
    if not name:
        return "未知地域"
    return GEO_COUNTRY_CN.get(name.strip(), name.strip())

_GEO_CACHE = {}
_GEO_CACHE_LOCK = threading.Lock()

def resolve_ip_geo(ip):
    # 结果缓存：同一 IP 且解析成功过只查一次，降低外部 API 压力
    with _GEO_CACHE_LOCK:
        if ip in _GEO_CACHE and _GEO_CACHE[ip].get("country") not in ("公网节点", "公网探测", "未知地域", "", None):
            return _GEO_CACHE[ip]
            
    # 过滤本地与私网 IP
    if not ip or ip in ("127.0.0.1", "::1", "localhost") or ip.startswith("127."):
        return {"country": "本地回环", "region": "", "city": "", "isp": "Localhost"}
    if ip.startswith("10.") or ip.startswith("192.168.") or (ip.startswith("172.") and len(ip.split(".")) > 1 and ip.split(".")[1].isdigit() and 16 <= int(ip.split(".")[1]) <= 31):
        return {"country": "局域私网", "region": "", "city": "", "isp": "Private LAN"}

    # 1. 首选高可用源：ipwho.is (原生支持简体中文返回，数据精准，无频控限制)
    try:
        url = f"http://ipwho.is/{ip}?lang=zh-CN"
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"})
        with urllib.request.urlopen(req, timeout=3) as resp:
            data = json.loads(resp.read().decode('utf-8'))
            if data.get("success"):
                country = data.get("country", "").strip()
                if country:
                    result = {
                        "country": translate_country_cn(country),
                        "region": data.get("region", "").strip(),
                        "city": data.get("city", "").strip(),
                        "isp": data.get("connection", {}).get("isp", "").strip()
                    }
                    with _GEO_CACHE_LOCK:
                        _GEO_CACHE[ip] = result
                    return result
    except Exception:
        pass

    # 2. 备选源：ip-api.com HTTP 接口
    try:
        url2 = f"http://ip-api.com/json/{ip}?lang=zh-CN&fields=status,country,regionName,city,isp"
        req2 = urllib.request.Request(url2, headers={"User-Agent": "PortGuardUI/2.0"})
        with urllib.request.urlopen(req2, timeout=3) as resp2:
            data2 = json.loads(resp2.read().decode('utf-8'))
            if data2.get("status") == "success":
                country = data2.get("country", "").strip()
                if country:
                    result = {
                        "country": translate_country_cn(country),
                        "region": data2.get("regionName", "").strip(),
                        "city": data2.get("city", "").strip(),
                        "isp": data2.get("isp", "").strip()
                    }
                    with _GEO_CACHE_LOCK:
                        _GEO_CACHE[ip] = result
                    return result
    except Exception:
        pass

    # 3. 备选源：api.ip.sb
    try:
        url3 = f"https://api.ip.sb/geoip/{ip}"
        req3 = urllib.request.Request(url3, headers={"User-Agent": "PortGuardUI/2.0"})
        with urllib.request.urlopen(req3, timeout=3) as resp3:
            data3 = json.loads(resp3.read().decode('utf-8'))
            country = data3.get("country", "").strip()
            if country:
                result = {
                    "country": translate_country_cn(country),
                    "region": data3.get("region", "").strip(),
                    "city": data3.get("city", "").strip(),
                    "isp": data3.get("isp", data3.get("organization", "")).strip()
                }
                with _GEO_CACHE_LOCK:
                    _GEO_CACHE[ip] = result
                return result
    except Exception:
        pass

    return {"country": "公网探测", "region": "", "city": "", "isp": ""}

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
        
    # 3. 达到阈值：使用 ipset 与黑洞路由毫秒级下发内核阻断
    if cfg.get("ban_action_iptables", True) or cfg.get("ban_action_blackhole", True):
        ban_ip_firewall(ip)
        
    auto_clean_days = int(cfg.get("auto_clean_days", 30) or 30)
    
    # 阶梯惩罚模型：查询历史违规频次，阶梯设定解封时间
    try:
        conn_h = get_db()
        ch = conn_h.cursor()
        ch.execute("SELECT COUNT(*) AS cnt FROM events WHERE ip = ?", (ip,))
        hist_count = int(ch.fetchone()["cnt"] or 0)
        conn_h.close()
    except Exception:
        hist_count = 0

    if hist_count <= 1 and auto_clean_days > 0 and event_level not in ("极高危", "critical"):
        ban_expire = now_ts + 3600  # 首次轻微触碰：阶梯轻度惩罚 1 小时
    else:
        ban_expire = now_ts + auto_clean_days * 86400 if auto_clean_days > 0 else None

    # 4. 写入事件与黑名单库与端口访问日志
    conn = get_db()
    c = conn.cursor()
    c.execute("""
    INSERT INTO events (ip, port, proto, port_name, category, level, country, region, city, isp, attack_time, timestamp, status)
    VALUES (?, ?, 'TCP', ?, ?, ?, '分析中...', '', '', '', ?, ?, 'BANNED')
    """, (ip, port_val, port_name, event_category, event_level, now_str, now_ts))
    event_id = c.lastrowid
    
    # 将拦截记录写入内存队列批量落盘
    log_port_access_entry(ip, port_val, port_name, action="INTERCEPTED")

    node_name = cfg.get("node_name", "本机") or "本机"
    c.execute("""
    INSERT OR REPLACE INTO blacklist (ip, reason, country, level, ban_time, timestamp, ban_expire, source_node)
    VALUES (?, ?, '分析中...', ?, ?, ?, ?, ?)
    """, (ip, ban_reason, event_level, now_str, now_ts, ban_expire, node_name))
    conn.commit()
    conn.close()
    
    # 5. 向集群联防节点异步广播黑名单情报
    broadcast_cluster_ban(ip, ban_reason, event_level)

    # 6. 后台异步解析地理位置并回填
    def _async_geo():
        geo = resolve_ip_geo(ip)
        try:
            c_geo = get_db()
            cur = c_geo.cursor()
            cur.execute("""
            UPDATE events SET country=?, region=?, city=?, isp=? WHERE id=?
            """, (geo["country"], geo["region"], geo["city"], geo["isp"], event_id))
            cur.execute("""
            UPDATE port_access_logs SET country=?, region=?, city=?, isp=? WHERE id=?
            """, (geo["country"], geo["region"], geo["city"], geo["isp"], port_log_id))
            cur.execute("""
            UPDATE blacklist SET country=? WHERE ip=?
            """, (geo["country"], ip))
            c_geo.commit()
            c_geo.close()
        except Exception:
            pass

    _EXECUTOR.submit(_async_geo)

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

def get_active_system_ports():
    global _SYSTEM_PORTS_CACHE, _SYSTEM_PORTS_CACHE_TIME
    now = time.time()
    if _SYSTEM_PORTS_CACHE and (now - _SYSTEM_PORTS_CACHE_TIME < 30.0):
        return _SYSTEM_PORTS_CACHE

    with _SYSTEM_PORTS_LOCK:
        if _SYSTEM_PORTS_CACHE and (now - _SYSTEM_PORTS_CACHE_TIME < 30.0):
            return _SYSTEM_PORTS_CACHE

        ports_map = dict(KNOWN_SYSTEM_SERVICES)
        try:
            cfg = load_config()
            web_p = int(cfg.get("web_port", 9099))
            ports_map[web_p] = "PortGuard Web控制台"
            custom_biz = cfg.get("business_ports", [])
            for bp in custom_biz:
                if isinstance(bp, int):
                    ports_map[bp] = f"自定义业务端口 ({bp})"
                elif isinstance(bp, dict) and "port" in bp:
                    ports_map[int(bp["port"])] = bp.get("name", f"自定义业务 ({bp['port']})")
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
            for port in range(start_p, end_p + 1):
                if port == web_port or port in active_ports or port in self.trap_map:
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

    def _handle_trap_client(self, client_sock, client_addr, port, port_info):
        """交互式蜜罐服务仿真：应答逼真 Banner 并嗅探首包攻击指令 Payload (100% 恶意行为确权)"""
        client_ip = client_addr[0]
        payload_captured = ""
        try:
            client_sock.settimeout(1.2)
            banner = None
            if port == 21:
                banner = b"220 ProFTPD 1.3.5 Server (Ubuntu) ready.\r\n"
            elif port in (22, 2222):
                banner = b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n"
            elif port == 23:
                banner = b"\r\nUbuntu 22.04.4 LTS\r\nlogin: "
            elif port == 3306:
                banner = b"N\x00\x00\x00\n5.7.42-log\x00\x01\x00\x00\x00\x0b\x0c\r\x0e\x0f\x10\x11\x12\x00\xff\xf7\x21\x02\x00\x7f\x80\x15\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x00mysql_native_password\x00"

            if banner:
                try:
                    client_sock.sendall(banner)
                except Exception:
                    pass

            try:
                recv_data = client_sock.recv(512)
                if recv_data:
                    payload_captured = recv_data.decode("utf-8", errors="ignore").strip()
            except Exception:
                pass
        except Exception:
            pass
        finally:
            try:
                client_sock.close()
            except Exception:
                pass

        reason_text = f"探测蜜罐端口 {port} ({port_info.get('name')})"
        if payload_captured:
            clean_p = " ".join(payload_captured.split())[:70]
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

def is_trap_port(port, cfg=None):
    """判定指定端口是否属于已配置的诱捕蜜罐端口。正常业务列表中的端口拥有最高优先级，100% 绝对避让。"""
    try:
        port = int(port)
    except Exception:
        return None
    if cfg is None:
        cfg = load_config()
    web_port = int(cfg.get("web_port", 9099) or 9099)
    if port == web_port:
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
    threshold = int(cfg.get("port_scan_threshold", 3) or 3)
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

                    # 过滤本机发出的包、回环流量、私网地址 (10.x, 192.168.x, 172.16-31.x)、IPv6 内部地址与私有 Docker 内部流量
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
            try:
                now_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
                now_ts = int(time.time())
                conn = get_db()
                c = conn.cursor()
                c.execute("""
                INSERT INTO port_access_logs (ip, port, proto, port_name, country, region, city, isp, action, access_time, timestamp)
                VALUES (?, ?, ?, ?, '分析中...', '', '', '', ?, ?, ?)
                """, (src_ip, dst_port, proto, d, act, now_str, now_ts))
                new_id = c.lastrowid
                conn.commit()
                conn.close()
                
                # 异步解析地理位置
                def _geo_backfill(record_id, ip_addr):
                    try:
                        g = resolve_ip_geo(ip_addr)
                        c2 = get_db()
                        cur = c2.cursor()
                        cur.execute("""
                        UPDATE port_access_logs SET country=?, region=?, city=?, isp=? WHERE id=?
                        """, (g.get("country", "公网节点"), g.get("region", ""), g.get("city", ""), g.get("isp", ""), record_id))
                        c2.commit()
                        c2.close()
                    except Exception:
                        pass
                _EXECUTOR.submit(_geo_backfill, new_id, src_ip)
            except Exception:
                pass

        # 1. 优先白名单放行
        if ip_in_whitelist(src_ip, whitelist):
            action = "WHITELIST"
            proc = active_ports_map.get(dst_port, KNOWN_SYSTEM_SERVICES.get(dst_port, ""))
            desc = f"信任白名单连接: {proc} (端口 {dst_port})" if proc else f"信任白名单连接 (端口 {dst_port})"
            _EXECUTOR.submit(_async_write, action, desc)
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
                desc = f"测绘扫描拦截: 嗅探业务端口 {dst_port} ({biz_name})"
                port_info = {
                    "name": desc,
                    "category": "survey",
                    "level": "高危",
                    "is_business": False
                }
                _EXECUTOR.submit(ban_ip, src_ip, dst_port, port_info)
                return

            # 2. 检查是否为云厂商/IDC机房探针 (仅在该业务端口开启了 block_idc 时生效)
            if block_idc and is_idc_hosting_ip(src_ip):
                action = "INTERCEPTED"
                desc = f"机房探针拦截: 云厂商IDC探测业务端口 {dst_port} ({biz_name})"
                port_info = {
                    "name": desc,
                    "category": "idc_probe",
                    "level": "中危",
                    "is_business": False
                }
                _EXECUTOR.submit(ban_ip, src_ip, dst_port, port_info)
                return

            action = "BUSINESS"
            desc = f"正常业务访问: {biz_name} (端口 {dst_port})"
            _EXECUTOR.submit(_async_write, action, desc)
            return

        # 4. 检查是否命中显式配置的蜜罐诱饵规则 (P3 优先级，仅针对非业务端口，如 1-60000 范围或单独未开放端口)
        if trap_meta and trap_meta.get("enabled", True):
            action = "INTERCEPTED"
            desc = trap_meta.get("name") or trap_meta.get("description") or f"蜜罐诱饵探针 (端口 {dst_port})"
            port_info = {
                "name": desc,
                "category": trap_meta.get("category", "honeypot"),
                "level": trap_meta.get("level", "高危"),
                "is_business": False
            }
            _EXECUTOR.submit(ban_ip, src_ip, dst_port, port_info)
            return

        # 5. 恶意访问行为 ②：恶意多端口扫描与探针攻击感知 (Nmap/Masscan 等扫描器识别)
        if check_port_scan_attack(src_ip, dst_port, cfg):
            action = "INTERCEPTED"
            desc = f"恶意多端口扫描探测 (触碰端口 {dst_port})"
            port_info = {
                "name": desc,
                "category": "scan",
                "level": "高危",
                "is_business": False
            }
            _EXECUTOR.submit(ban_ip, src_ip, dst_port, port_info)
            return

        # 6. 其他全端口全量诱捕（仅在显式勾选全端口诱捕时生效，默认关闭）
        if bool(cfg.get("trap_all_ports", False)) or bool(cfg.get("trap_all_unopened_ports", False)):
            action = "INTERCEPTED"
            desc = f"全端口嗅探诱捕 (未开放端口 {dst_port})"
            port_info = {
                "name": desc,
                "category": "scan",
                "level": "高危",
                "is_business": False
            }
            _EXECUTOR.submit(ban_ip, src_ip, dst_port, port_info)
            return

        # 7. 常规单次未开放端口偶发探测（未达到扫描器判定标准，仅记录访问审计日志，不拉黑）
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

        # 2. 1Panel 全局访问日志
        for global_p in ["/opt/1panel/apps/openresty/openresty/log/access.log", "/opt/1panel/log/access.log"]:
            if os.path.exists(global_p) and global_p not in seen_paths:
                seen_paths.add(global_p)
                files.append((global_p, "全局反代"))

        # 3. 标准系统 Nginx 路径
        for p in glob.glob("/var/log/nginx/*access*.log"):
            if os.path.exists(p) and p not in seen_paths:
                seen_paths.add(p)
                bname = os.path.basename(p).replace(".access.log", "").replace("access.log", "").replace(".log", "")
                domain = bname if bname and bname != "nginx" else "Nginx主站"
                files.append((p, domain))

        for p in glob.glob("/www/server/nginx/logs/*access*.log"):
            if os.path.exists(p) and p not in seen_paths:
                seen_paths.add(p)
                files.append((p, "BT-Nginx"))

        return files

    def _collector_loop(self):
        log_regex = re.compile(
            r'^(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<time>[^\]]+)\]\s+"(?P<request>[^"]*)"\s+(?P<status>\d+)\s+\S+(?:\s+"(?P<ref>[^"]*)"\s+"(?P<ua>[^"]*)")?'
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
                            ip = m.group("ip")
                            if not validate_ip(ip) and not (":" in ip or "." in ip):
                                continue
                            time_str = m.group("time")
                            request = m.group("request") or ""
                            status = int(m.group("status") or 200)
                            ref = (m.group("ref") or "").strip()
                            ua = m.group("ua") or ""

                            # 域名解析：优先站点目录域名，若是全局日志且 Referer 中包含完整 URL 则提取 Host
                            req_domain = default_domain
                            if (req_domain in ("全局反代", "Nginx主站", "")) and ref and (ref.startswith("http://") or ref.startswith("https://")):
                                try:
                                    extracted = ref.split("/")[2].split(":")[0]
                                    if extracted and not extracted.replace(".", "").isdigit():
                                        req_domain = extracted
                                except Exception:
                                    pass

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

                            new_records.append((ip, req_domain, method, path, status, ua, "分析中...", "", "", "", ftime, ts))
                            try:
                                check_http_request_traps(ip, req_domain, method, path, status, ua)
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

                        for item in new_records:
                            _EXECUTOR.submit(resolve_ip_geo, item[0])
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
