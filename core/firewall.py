#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PortGuard Core Firewall & Threat Interception Engine
内核防火墙规则下发、IPSet 动态集合加速、黑洞路由与智能解封
"""
import glob
import ipaddress
import os
import re
import socket
import struct
import subprocess
import threading
import time

from core.db import get_db, load_config, DEFAULT_CONFIG
from geo import _GEO_CACHE, resolve_ip_geo, resolve_ip_geo_local

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
    """威胁情报标签与信誉综合研判：返回 IP 的多维信誉指纹标签列表"""
    if not ip_str or ip_str in ("127.0.0.1", "::1", "localhost") or ip_str.startswith("127."):
        return []
    with _THREAT_TAGS_LOCK:
        if ip_str in _THREAT_TAGS_CACHE:
            return _THREAT_TAGS_CACHE[ip_str]
    tags = []
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        for net in _SURVEY_CIDR_NETWORKS:
            if "Tor Exit" in str(net) and ip_obj in net:
                tags.append("🧅 Tor 匿名网络")
                break
        if not tags:
            if ip_str.startswith("185.220.10") or ip_str.startswith("171.25.193."):
                tags.append("🧅 Tor 匿名网络")
    except Exception:
        pass

    geo = geo_dict or _GEO_CACHE.get(ip_str) or {}
    isp_text = (str(geo.get("isp", "")) + " " + str(geo.get("region", "")) + " " + str(geo.get("country", ""))).lower()

    if is_survey_scanner_ip(ip_str, geo):
        for kw in SURVEY_ENGINE_KEYWORDS:
            if kw in isp_text or kw in ip_str:
                tags.append(f"📡 测绘引擎 ({kw.title()})")
                break
        if not any("测绘" in t for t in tags):
            tags.append("📡 空间测绘爬虫")

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

def validate_ip(ip):
    """严格校验 IPv4 / IPv6 地址或 CIDR 网段，拒绝任何带端口、路径或 shell 元字符的输入。"""
    if not ip or not isinstance(ip, str):
        return None
    ip = ip.strip()
    if not ip:
        return None
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
        
        probe = subprocess.run(["ipset", "list", set_name], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, universal_newlines=True)
        if probe.returncode == 0:
            if "timeout" in probe.stdout:
                return True
            subprocess.run(["ipset", "create", tmp_name] + create_args + ["-exist"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(["ipset", "swap", set_name, tmp_name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(["ipset", "destroy", tmp_name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return True
        else:
            res = subprocess.run(["ipset", "create", set_name] + create_args + ["-exist"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return res.returncode == 0
    except Exception:
        return False

def init_firewall_ipset():
    """初始化 ipset 哈希表并在 iptables / ip6tables INPUT 链首行挂载单一规则，实现 O(1) 百万级黑名单与内核级动态 timeout 自动老化。"""
    if not is_ipset_available():
        return False
    try:
        _ensure_ipset_timeout_set("portguard_blacklist_v4", is_ipv6=False)
        _ensure_ipset_timeout_set("portguard_blacklist_v6", is_ipv6=True)

        check_v4 = subprocess.run(["iptables", "-C", "INPUT", "-m", "set", "--match-set", "portguard_blacklist_v4", "src", "-j", "DROP"],
                                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if check_v4.returncode != 0:
            subprocess.run(["iptables", "-I", "INPUT", "-m", "set", "--match-set", "portguard_blacklist_v4", "src", "-j", "DROP"],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        check_v6 = subprocess.run(["ip6tables", "-C", "INPUT", "-m", "set", "--match-set", "portguard_blacklist_v6", "src", "-j", "DROP"],
                                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if check_v6.returncode != 0:
            subprocess.run(["ip6tables", "-I", "INPUT", "-m", "set", "--match-set", "portguard_blacklist_v6", "src", "-j", "DROP"],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
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
    """精准排空 PortGuard 自己下发的封禁拦截：清空 ipset 黑名单集合，并精准移除数据库中登记的黑洞路由与 iptables 规则"""
    try:
        if is_ipset_available():
            subprocess.run(["ipset", "flush", "portguard_blacklist_v4"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(["ipset", "flush", "portguard_blacklist_v6"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

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

_BLACKLIST_IPS_CACHE = set()
_BLACKLIST_IPS_CACHE_TIME = 0.0
_BLACKLIST_IPS_LOCK = threading.Lock()

def get_blacklisted_ips_set():
    """获取内存级快速黑名单 IP 集合（5秒缓存），用于网络层嗅探毫秒级阻断与排除"""
    global _BLACKLIST_IPS_CACHE_TIME
    now = time.time()
    if _BLACKLIST_IPS_CACHE_TIME > 0 and (now - _BLACKLIST_IPS_CACHE_TIME < 5.0):
        return _BLACKLIST_IPS_CACHE
    with _BLACKLIST_IPS_LOCK:
        if _BLACKLIST_IPS_CACHE_TIME > 0 and (now - _BLACKLIST_IPS_CACHE_TIME < 5.0):
            return _BLACKLIST_IPS_CACHE
        try:
            conn = get_db()
            c = conn.cursor()
            c.execute("SELECT ip FROM blacklist")
            rows = {row[0] for row in c.fetchall() if row[0]}
            _BLACKLIST_IPS_CACHE.clear()
            _BLACKLIST_IPS_CACHE.update(rows)
            _BLACKLIST_IPS_CACHE_TIME = now
            conn.close()
        except Exception:
            pass
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

        if is_ipset_available():
            timeout_val = min(2147483, max(60, int(expire_seconds))) if expire_seconds and expire_seconds > 0 else 2147483
            res = subprocess.run(["ipset", "add", set_name, ip, "timeout", str(timeout_val), "-exist"],
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if res.returncode != 0:
                _ensure_ipset_timeout_set(set_name, is_ipv6=is_ipv6)
                subprocess.run(["ipset", "add", set_name, ip, "timeout", str(timeout_val), "-exist"],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        else:
            chk = subprocess.run([fw_tool, "-C", "INPUT", "-s", ip, "-j", "DROP"],
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if chk.returncode != 0:
                subprocess.run([fw_tool, "-I", "INPUT", "-s", ip, "-j", "DROP"],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                run_firewall_cmd(save_tool)

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
        self._scores = {}

    def add_score(self, ip, points, reason=""):
        now = time.time()
        with self._lock:
            if ip not in self._scores:
                self._scores[ip] = {"score": 0.0, "last_time": now, "count": 0}
            entry = self._scores[ip]
            
            elapsed = now - entry["last_time"]
            if elapsed > 10:
                decay_factor = max(0.0, 1.0 - (elapsed / 300.0))
                entry["score"] = entry["score"] * decay_factor
            
            entry["score"] += points
            entry["last_time"] = now
            entry["count"] += 1
            
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

def get_system_ssh_ports():
    """动态获取系统中 SSH 服务监听的所有端口"""
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
    """动态探测当前系统真正已认证登录的管理员 SSH 客户端 IP (防管理员自杀保护机制)"""
    global _DYNAMIC_SSH_IPS_CACHE, _DYNAMIC_SSH_IPS_LAST_CHECK
    now = time.time()
    if (now - _DYNAMIC_SSH_IPS_LAST_CHECK < 5) and _DYNAMIC_SSH_IPS_CACHE:
        return _DYNAMIC_SSH_IPS_CACHE
    
    ips = set()
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

    try:
        for env_var in ("SSH_CLIENT", "SSH_CONNECTION"):
            val = os.environ.get(env_var, "").strip()
            if val:
                c_ip = val.split()[0].replace('::ffff:', '')
                if c_ip and not c_ip.startswith("127."):
                    ips.add(c_ip)
    except Exception:
        pass

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

    if is_infrastructure_or_cdn_ip(ip):
        return True

    gw = get_default_gateway()
    if gw and ip == gw:
        return True

    active_ssh_ips = get_active_ssh_client_ips()
    if ip in active_ssh_ips:
        return True

    try:
        from core.mesh import normalize_cluster_node
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
                if ipaddress.ip_address(ip) in ipaddress.ip_network(val, strict=False):
                    return True
            except Exception:
                pass
        else:
            if val == ip:
                return True
    return False

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

        if is_ipset_available():
            subprocess.run(["ipset", "del", set_name, ip, "-exist"],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

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

        if is_ipv6:
            subprocess.run(["ip", "-6", "route", "del", "blackhole", f"{ip}{mask}"],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        else:
            subprocess.run(["ip", "route", "del", "blackhole", f"{ip}{mask}"],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

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
        c.execute("DELETE FROM unbanned_ips WHERE timestamp < ?", (now_ts - 7 * 86400,))
        conn.commit()
        conn.close()

        _THREAT_ENGINE.reset_score(ip)
        with _BLACKLIST_IPS_LOCK:
            _BLACKLIST_IPS_CACHE.discard(ip)
        return True
    except Exception:
        return False
