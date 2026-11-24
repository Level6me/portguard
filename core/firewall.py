#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PortGuard Core Firewall & Threat Interception Engine
内核防火墙规则下发、IPSet 动态集合加速、黑洞路由与智能解封
"""
from contextlib import closing
import glob
import ipaddress
import os
import re
import socket
import struct
import subprocess
import sys
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
_MAX_THREAT_TAGS_CACHE = 10000

def get_ip_threat_tags(ip_str, geo_dict=None):
    """威胁情报标签与信誉综合研判：返回 IP 的多维信誉指纹标签列表（带上限淘汰并防止未就绪空标签污染）"""
    if not ip_str or ip_str in ("127.0.0.1", "::1", "localhost") or ip_str.startswith("127."):
        return []
    with _THREAT_TAGS_LOCK:
        if ip_str in _THREAT_TAGS_CACHE:
            return list(_THREAT_TAGS_CACHE[ip_str])
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
    raw_country = str(geo.get("country", "") or "").strip()
    raw_isp = str(geo.get("isp", "") or "").strip()
    isp_text = (raw_isp + " " + str(geo.get("region", "")) + " " + raw_country).lower()

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

    geo_ready = bool(tags) or (raw_country and raw_country not in ("分析中...", "未知地域", "公网节点", "None", "null")) or bool(raw_isp)
    if geo_ready:
        with _THREAT_TAGS_LOCK:
            if len(_THREAT_TAGS_CACHE) >= _MAX_THREAT_TAGS_CACHE:
                for stale_k in list(_THREAT_TAGS_CACHE.keys())[:_MAX_THREAT_TAGS_CACHE // 5]:
                    _THREAT_TAGS_CACHE.pop(stale_k, None)
            _THREAT_TAGS_CACHE[ip_str] = list(tags)
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

def _run_ipset_restore(commands_list):
    """安全执行 ipset restore，带超时并在超时异常时彻底回收子进程防僵尸残留"""
    if not commands_list:
        return True
    p = None
    try:
        p = subprocess.Popen(["ipset", "restore"], stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        p.communicate("".join(commands_list).encode("utf-8"), timeout=5)
        return p.returncode == 0
    except subprocess.TimeoutExpired:
        if p is not None:
            try:
                p.kill()
                p.wait(timeout=1)
            except Exception:
                pass
        return False
    except Exception as e:
        if p is not None:
            try:
                p.kill()
                p.wait(timeout=1)
            except Exception:
                pass
        print(f"[Firewall] ipset restore 异常: {e}")
        return False

def _ensure_ipset_timeout_set(set_name, is_ipv6=False, set_type="hash:ip"):
    """确保 ipset 集合存在且支持 timeout 参数。若已存在且不支持 timeout 则平滑无感 swap 升级。"""
    try:
        tmp_name = f"pg_tmp_{int(time.time()*1000)%100000}"
        max_elem = "65536" if set_type == "hash:net" else "1000000"
        create_args = [set_type, "maxelem", max_elem, "timeout", "2147483"]
        if is_ipv6:
            create_args = [set_type, "family", "inet6", "maxelem", max_elem, "timeout", "2147483"]
        
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

def _ensure_ipset_net_set(set_name, is_ipv6=False):
    """确保 ipset 集合存在且为 hash:net 类型，完美支持单个 IP 及 CIDR 网段（如 111.181.0.0/16）。"""
    try:
        create_args = ["hash:net", "maxelem", "65536"]
        if is_ipv6:
            create_args = ["hash:net", "family", "inet6", "maxelem", "65536"]
        
        probe = subprocess.run(["ipset", "list", set_name], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, universal_newlines=True)
        if probe.returncode == 0:
            return True
        else:
            res = subprocess.run(["ipset", "create", set_name] + create_args + ["-exist"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return res.returncode == 0
    except Exception:
        return False

def init_firewall_ipset():
    """初始化 ipset 哈希表并在 iptables / ip6tables INPUT 链首行挂载规则。
    核心安全铁律：白名单集合挂载在第 1 行最高优先级绝对放行，黑名单单 IP 与 CIDR 网段集合挂载在其后！"""
    if not is_ipset_available():
        return False
    try:
        # 1. 确保黑名单单 IP 与 CIDR 网段集合存在 (带 timeout)
        _ensure_ipset_timeout_set("portguard_blacklist_v4", is_ipv6=False, set_type="hash:ip")
        _ensure_ipset_timeout_set("portguard_blacklist_v6", is_ipv6=True, set_type="hash:ip")
        _ensure_ipset_timeout_set("portguard_blacknet_v4", is_ipv6=False, set_type="hash:net")
        _ensure_ipset_timeout_set("portguard_blacknet_v6", is_ipv6=True, set_type="hash:net")

        # 2. 确保白名单集合存在 (hash:net 支持单IP与CIDR网段)
        _ensure_ipset_net_set("portguard_whitelist_v4", is_ipv6=False)
        _ensure_ipset_net_set("portguard_whitelist_v6", is_ipv6=True)

        # 3. iptables IPv4: 第 1 位白名单 ACCEPT，第 2 位黑名单 IP DROP，第 3 位黑名单网段 DROP
        for fw_bin, wl_set, bl_set, bn_set in (
            ("iptables", "portguard_whitelist_v4", "portguard_blacklist_v4", "portguard_blacknet_v4"),
            ("ip6tables", "portguard_whitelist_v6", "portguard_blacklist_v6", "portguard_blacknet_v6"),
        ):
            chk_w = subprocess.run([fw_bin, "-C", "INPUT", "-m", "set", "--match-set", wl_set, "src", "-j", "ACCEPT"],
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if chk_w.returncode != 0:
                subprocess.run([fw_bin, "-I", "INPUT", "1", "-m", "set", "--match-set", wl_set, "src", "-j", "ACCEPT"],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

            chk_b = subprocess.run([fw_bin, "-C", "INPUT", "-m", "set", "--match-set", bl_set, "src", "-j", "DROP"],
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if chk_b.returncode != 0:
                subprocess.run([fw_bin, "-I", "INPUT", "2", "-m", "set", "--match-set", bl_set, "src", "-j", "DROP"],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

            chk_n = subprocess.run([fw_bin, "-C", "INPUT", "-m", "set", "--match-set", bn_set, "src", "-j", "DROP"],
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if chk_n.returncode != 0:
                subprocess.run([fw_bin, "-I", "INPUT", "3", "-m", "set", "--match-set", bn_set, "src", "-j", "DROP"],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
        with closing(get_db()) as conn:
            c = conn.cursor()
            c.execute("SELECT ip, ban_expire FROM blacklist")
            black_rows = c.fetchall()

        now_ts = int(time.time())
        restore_cmds = []

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
                if "/" in ip_val:
                    net_obj = ipaddress.ip_network(ip_val, strict=False)
                    sname = "portguard_blacknet_v6" if net_obj.version == 6 else "portguard_blacknet_v4"
                    restore_cmds.append(f"add {sname} {net_obj} timeout {remain} -exist\n")
                else:
                    addr_obj = ipaddress.ip_address(ip_val)
                    sname = "portguard_blacklist_v6" if addr_obj.version == 6 else "portguard_blacklist_v4"
                    restore_cmds.append(f"add {sname} {ip_val} timeout {remain} -exist\n")
            except Exception:
                pass

        for safe_ip in PUBLIC_INFRASTRUCTURE_IPS:
            unban_ip_core(safe_ip)

        _run_ipset_restore(restore_cmds)
        return True
    except Exception as e:
        print(f"[IPSET] 初始化异常: {e}")
        return False

def flush_firewall_blocks():
    """精准排空 PortGuard 自己下发的封禁拦截：清空 ipset 黑名单集合，并仅移除 PortGuard 黑名单库记录的黑洞路由"""
    try:
        if is_ipset_available():
            for sname in ("portguard_blacklist_v4", "portguard_blacklist_v6", "portguard_blacknet_v4", "portguard_blacknet_v6"):
                subprocess.run(["ipset", "flush", sname], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        with closing(get_db()) as conn:
            rows = conn.execute("SELECT ip FROM blacklist").fetchall()

        for row in rows:
            valid_target = validate_ip(row["ip"])
            if not valid_target:
                continue
            del_cmd = ["ip", "-6", "route", "del", "blackhole", valid_target] if ":" in valid_target else ["ip", "route", "del", "blackhole", valid_target]
            subprocess.run(del_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return True
    except Exception as e:
        print(f"[Firewall] 清理阻断异常: {e}")
        return False

_BLACKLIST_IPS_CACHE = set()
_BLACKLIST_IPS_CACHE_TIME = 0.0
_BLACKLIST_IPS_LOCK = threading.Lock()

def get_blacklisted_ips_set():
    """获取内存级快速黑名单 IP 集合（5秒缓存，采用新集合引用原子替换避免并发遍历异常与清空瞬时漏判）"""
    global _BLACKLIST_IPS_CACHE, _BLACKLIST_IPS_CACHE_TIME
    now = time.time()
    cached_ref = _BLACKLIST_IPS_CACHE
    if _BLACKLIST_IPS_CACHE_TIME > 0 and (now - _BLACKLIST_IPS_CACHE_TIME < 5.0):
        return cached_ref
    with _BLACKLIST_IPS_LOCK:
        if _BLACKLIST_IPS_CACHE_TIME > 0 and (now - _BLACKLIST_IPS_CACHE_TIME < 5.0):
            return _BLACKLIST_IPS_CACHE
        try:
            with closing(get_db()) as conn:
                c = conn.cursor()
                c.execute("SELECT ip FROM blacklist")
                rows = {row[0] for row in c.fetchall() if row[0]}
            _BLACKLIST_IPS_CACHE = rows
            _BLACKLIST_IPS_CACHE_TIME = now
        except Exception:
            pass
        return _BLACKLIST_IPS_CACHE

def _parse_ip_or_cidr_target(ip_val):
    """统一解析单个 IP 或 CIDR 网段，返回 (is_cidr, is_ipv6, canonical_str, route_target)"""
    if "/" in ip_val:
        net_obj = ipaddress.ip_network(ip_val, strict=False)
        is_v6 = (net_obj.version == 6)
        # 若前缀等于单主机掩码 (/32 或 /128)，归一为单 IP 处理
        if (not is_v6 and net_obj.prefixlen == 32) or (is_v6 and net_obj.prefixlen == 128):
            host_str = str(net_obj.network_address)
            mask = "/128" if is_v6 else "/32"
            return False, is_v6, host_str, f"{host_str}{mask}"
        return True, is_v6, str(net_obj), str(net_obj)
    addr_obj = ipaddress.ip_address(ip_val)
    is_v6 = (addr_obj.version == 6)
    host_str = str(addr_obj)
    mask = "/128" if is_v6 else "/32"
    return False, is_v6, host_str, f"{host_str}{mask}"

def ban_ip_firewall(ip, expire_seconds=None, cfg=None):
    """下发内核拦截：同时兼容单个 IP 与 CIDR 网段，严格遵循 ban_action_iptables 与 ban_action_blackhole 独立开关，绝不压过白名单优先级。"""
    valid_ip = validate_ip(ip)
    if not valid_ip or is_infrastructure_or_cdn_ip(valid_ip) or ip_in_whitelist(valid_ip):
        return
    try:
        if cfg is None:
            cfg = load_config()
        use_iptables = bool(cfg.get("ban_action_iptables", True))
        use_blackhole = bool(cfg.get("ban_action_blackhole", True))
        if not use_iptables and not use_blackhole:
            return

        is_cidr, is_ipv6, target_str, route_target = _parse_ip_or_cidr_target(valid_ip)
        if is_cidr:
            set_name = "portguard_blacknet_v6" if is_ipv6 else "portguard_blacknet_v4"
            set_type = "hash:net"
        else:
            set_name = "portguard_blacklist_v6" if is_ipv6 else "portguard_blacklist_v4"
            set_type = "hash:ip"

        fw_tool = "ip6tables" if is_ipv6 else "iptables"
        wl_set = "portguard_whitelist_v6" if is_ipv6 else "portguard_whitelist_v4"
        save_tool = "ip6tables-save" if is_ipv6 else "iptables-save"

        if use_iptables:
            if is_ipset_available():
                timeout_val = min(2147483, max(60, int(expire_seconds))) if expire_seconds and expire_seconds > 0 else 2147483
                res = subprocess.run(["ipset", "add", set_name, target_str, "timeout", str(timeout_val), "-exist"],
                                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                if res.returncode != 0:
                    _ensure_ipset_timeout_set(set_name, is_ipv6=is_ipv6, set_type=set_type)
                    subprocess.run(["ipset", "add", set_name, target_str, "timeout", str(timeout_val), "-exist"],
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            else:
                chk = subprocess.run([fw_tool, "-C", "INPUT", "-s", target_str, "-j", "DROP"],
                                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                if chk.returncode != 0:
                    # 确保插入位置在白名单规则之后（若存在白名单集合规则则插在第 2 位）
                    chk_wl = subprocess.run([fw_tool, "-C", "INPUT", "-m", "set", "--match-set", wl_set, "src", "-j", "ACCEPT"],
                                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    insert_pos = ["2"] if chk_wl.returncode == 0 else []
                    subprocess.run([fw_tool, "-I", "INPUT"] + insert_pos + ["-s", target_str, "-j", "DROP"],
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    run_firewall_cmd(save_tool)

        if use_blackhole:
            if is_ipv6:
                subprocess.run(["ip", "-6", "route", "add", "blackhole", route_target],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            else:
                subprocess.run(["ip", "route", "add", "blackhole", route_target],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception as e:
        print(f"[Firewall] 下发封禁异常 ({valid_ip}): {e}")

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

_DYNAMIC_SSH_IPS_CACHE = None
_DYNAMIC_SSH_IPS_LAST_CHECK = 0.0
_DYNAMIC_SSH_IPS_LOCK = threading.Lock()

def get_active_ssh_client_ips():
    """动态探测当前系统真正已认证登录的管理员 SSH 客户端 IP (防管理员自杀保护机制，带10秒线程安全缓存)"""
    global _DYNAMIC_SSH_IPS_CACHE, _DYNAMIC_SSH_IPS_LAST_CHECK
    now = time.time()
    if (now - _DYNAMIC_SSH_IPS_LAST_CHECK < 10.0) and (_DYNAMIC_SSH_IPS_CACHE is not None):
        return _DYNAMIC_SSH_IPS_CACHE
    
    with _DYNAMIC_SSH_IPS_LOCK:
        if (now - _DYNAMIC_SSH_IPS_LAST_CHECK < 10.0) and (_DYNAMIC_SSH_IPS_CACHE is not None):
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
_DEFAULT_GATEWAY_LOCK = threading.Lock()

def get_default_gateway():
    """动态通过 /proc/net/route 毫秒级提取默认路由网关 IP (防自锁保护，绝不误封上一级路由交换机)"""
    global _DEFAULT_GATEWAY_CACHE, _DEFAULT_GATEWAY_LAST_CHECK
    now = time.time()
    if _DEFAULT_GATEWAY_CACHE is not None and (now - _DEFAULT_GATEWAY_LAST_CHECK < 60.0):
        return _DEFAULT_GATEWAY_CACHE

    with _DEFAULT_GATEWAY_LOCK:
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

_CLUSTER_NODES_IPS_CACHE = None
_CLUSTER_NODES_IPS_LAST_CHECK = 0.0
_CLUSTER_NODES_IPS_LOCK = threading.Lock()

def get_cluster_nodes_ips():
    """获取所有协同集群节点的 IP 集合（带10秒内存缓存，防止频繁读取配置造成锁竞争）"""
    global _CLUSTER_NODES_IPS_CACHE, _CLUSTER_NODES_IPS_LAST_CHECK
    now = time.time()
    if (now - _CLUSTER_NODES_IPS_LAST_CHECK < 10.0) and (_CLUSTER_NODES_IPS_CACHE is not None):
        return _CLUSTER_NODES_IPS_CACHE
    with _CLUSTER_NODES_IPS_LOCK:
        if (now - _CLUSTER_NODES_IPS_LAST_CHECK < 10.0) and (_CLUSTER_NODES_IPS_CACHE is not None):
            return _CLUSTER_NODES_IPS_CACHE
        node_ips = set()
        try:
            from core.mesh import normalize_cluster_node
            cfg = load_config()
            c_nodes = cfg.get("cluster_sync", {}).get("cluster_nodes", [])
            for raw_n in c_nodes:
                norm_n = normalize_cluster_node(raw_n)
                if norm_n and norm_n.get("ip"):
                    node_ips.add(norm_n.get("ip"))
        except Exception:
            pass
        _CLUSTER_NODES_IPS_CACHE = node_ips
        _CLUSTER_NODES_IPS_LAST_CHECK = now
        return node_ips

_WHITELIST_CACHE_TIME = 0.0
_WHITELIST_EXACT_IPS = set()
_WHITELIST_NETS = []
_WHITELIST_LOCK = threading.Lock()

def invalidate_whitelist_cache():
    global _WHITELIST_CACHE_TIME
    with _WHITELIST_LOCK:
        _WHITELIST_CACHE_TIME = 0.0

def compile_whitelist_rules(whitelist_items):
    """预编译白名单规则，提取精确 IP set 和网络段 list，支持 O(1) 检索"""
    exact = set()
    nets = []
    for item in whitelist_items or []:
        val = item.get("ip") if isinstance(item, dict) else item
        if not val:
            continue
        val_str = str(val).strip()
        if "/" in val_str:
            try:
                nets.append(ipaddress.ip_network(val_str, strict=False))
            except Exception:
                pass
        else:
            exact.add(val_str)
    return exact, nets

def get_compiled_whitelist():
    """获取已预编译的系统全局白名单（5秒内存缓存，极速匹配零磁盘与锁消耗）"""
    global _WHITELIST_CACHE_TIME, _WHITELIST_EXACT_IPS, _WHITELIST_NETS
    now = time.time()
    if _WHITELIST_CACHE_TIME > 0 and (now - _WHITELIST_CACHE_TIME < 5.0):
        return _WHITELIST_EXACT_IPS, _WHITELIST_NETS
    with _WHITELIST_LOCK:
        if _WHITELIST_CACHE_TIME > 0 and (now - _WHITELIST_CACHE_TIME < 5.0):
            return _WHITELIST_EXACT_IPS, _WHITELIST_NETS
        try:
            cfg = load_config()
            items = cfg.get("whitelist", DEFAULT_CONFIG.get("whitelist", []))
        except Exception:
            items = DEFAULT_CONFIG.get("whitelist", [])
        _WHITELIST_EXACT_IPS, _WHITELIST_NETS = compile_whitelist_rules(items)
        _WHITELIST_CACHE_TIME = now
        return _WHITELIST_EXACT_IPS, _WHITELIST_NETS

def ip_in_whitelist(ip, whitelist_items=None):
    if not ip or ip in ("127.0.0.1", "::1", "localhost") or str(ip).startswith("127."):
        return True

    if is_infrastructure_or_cdn_ip(ip):
        return True

    sd_mod = sys.modules.get("sentry_daemon")
    gw_fn = getattr(sd_mod, "get_default_gateway", get_default_gateway) if sd_mod else get_default_gateway
    gw = gw_fn()
    if gw and ip == gw:
        return True

    active_ssh_ips = get_active_ssh_client_ips()
    if ip in active_ssh_ips:
        return True

    cluster_ips = get_cluster_nodes_ips()
    if ip in cluster_ips:
        return True

    if whitelist_items is not None:
        exact, nets = compile_whitelist_rules(whitelist_items)
    else:
        exact, nets = get_compiled_whitelist()

    if ip in exact:
        return True

    if nets:
        try:
            if "/" in str(ip):
                target_net = ipaddress.ip_network(ip, strict=False)
                for net in nets:
                    if target_net.version == net.version and target_net.overlaps(net):
                        return True
            else:
                ip_obj = ipaddress.ip_address(ip)
                for net in nets:
                    if ip_obj in net:
                        return True
        except Exception:
            pass

    return False

def batch_ban_ip_firewall(ips, expire_seconds=None, cfg=None):
    """批量向内核 ipset 下发封禁规则，单次进程通信下发成百上千条，杜绝频繁 fork 造成的 CPU 脉冲"""
    if not ips:
        return
    if cfg is None:
        cfg = load_config()
    use_iptables = bool(cfg.get("ban_action_iptables", True))
    use_blackhole = bool(cfg.get("ban_action_blackhole", True))
    if not use_iptables and not use_blackhole:
        return
    if not is_ipset_available():
        for single_ip in ips:
            ban_ip_firewall(single_ip, expire_seconds=expire_seconds, cfg=cfg)
        return

    timeout_val = min(2147483, max(60, int(expire_seconds))) if expire_seconds and expire_seconds > 0 else 2147483
    restore_cmds = []
    
    exact_w, nets_w = get_compiled_whitelist()
    infra_set = PUBLIC_INFRASTRUCTURE_IPS
    gw = get_default_gateway()
    ssh_ips = get_active_ssh_client_ips()
    c_ips = get_cluster_nodes_ips()

    for raw_ip in ips:
        val_ip = validate_ip(raw_ip)
        if not val_ip or val_ip in infra_set or val_ip == gw or val_ip in ssh_ips or val_ip in c_ips or val_ip in exact_w or is_infrastructure_or_cdn_ip(val_ip) or ip_in_whitelist(val_ip):
            continue
        try:
            is_cidr, is_v6, target_str, route_target = _parse_ip_or_cidr_target(val_ip)
            if use_iptables:
                if is_cidr:
                    sname = "portguard_blacknet_v6" if is_v6 else "portguard_blacknet_v4"
                else:
                    sname = "portguard_blacklist_v6" if is_v6 else "portguard_blacklist_v4"
                restore_cmds.append(f"add {sname} {target_str} timeout {timeout_val} -exist\n")
            if use_blackhole:
                if is_v6:
                    subprocess.run(["ip", "-6", "route", "add", "blackhole", route_target], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                else:
                    subprocess.run(["ip", "route", "add", "blackhole", route_target], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception:
            continue

    _run_ipset_restore(restore_cmds)

def unban_ip_core(ip, status_event="UNBANNED", source_node="本机操作"):
    """彻底解除对指定单个 IP 或 CIDR 网段的内核防火墙封禁、ipset、黑洞路由及数据库黑名单记录，并登记防回潮墓碑。"""
    global _BLACKLIST_IPS_CACHE
    valid_ip = validate_ip(ip)
    if not valid_ip:
        return False
    try:
        is_cidr, is_ipv6, target_str, route_target = _parse_ip_or_cidr_target(valid_ip)
        fw_tool = "ip6tables" if is_ipv6 else "iptables"
        save_tool = "ip6tables-save" if is_ipv6 else "iptables-save"

        if is_ipset_available():
            if is_cidr:
                net_set = "portguard_blacknet_v6" if is_ipv6 else "portguard_blacknet_v4"
                subprocess.run(["ipset", "del", net_set, target_str, "-exist"],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            else:
                ip_set = "portguard_blacklist_v6" if is_ipv6 else "portguard_blacklist_v4"
                subprocess.run(["ipset", "del", ip_set, target_str, "-exist"],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        cleaned_any = False
        for candidate_src in ({target_str, valid_ip} if target_str != valid_ip else {target_str}):
            for _ in range(16):
                res = subprocess.run([fw_tool, "-D", "INPUT", "-s", candidate_src, "-j", "DROP"],
                                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                if res.returncode == 0:
                    cleaned_any = True
                else:
                    break
        
        if cleaned_any:
            run_firewall_cmd(save_tool)

        if is_ipv6:
            subprocess.run(["ip", "-6", "route", "del", "blackhole", route_target],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        else:
            subprocess.run(["ip", "route", "del", "blackhole", route_target],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        now_str = time.strftime("%Y-%m-%d %H:%M:%S")
        now_ts = int(time.time())
        with closing(get_db()) as conn:
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
            """, (valid_ip, now_str, now_ts, source_node))
            c.execute("DELETE FROM blacklist WHERE ip IN (?, ?)", (valid_ip, target_str))
            c.execute("UPDATE events SET status = ? WHERE ip IN (?, ?)", (status_event, valid_ip, target_str))
            c.execute("DELETE FROM unbanned_ips WHERE timestamp < ?", (now_ts - 7 * 86400,))
            conn.commit()

        _THREAT_ENGINE.reset_score(valid_ip)
        if target_str != valid_ip:
            _THREAT_ENGINE.reset_score(target_str)
        with _BLACKLIST_IPS_LOCK:
            if valid_ip in _BLACKLIST_IPS_CACHE or target_str in _BLACKLIST_IPS_CACHE:
                _BLACKLIST_IPS_CACHE = _BLACKLIST_IPS_CACHE - {valid_ip, target_str}
        return True
    except Exception as e:
        print(f"[Firewall] 解封目标异常 ({valid_ip}): {e}")
        return False


def auto_heal_whitelist_ips(whitelist_items=None):
    """
    白名单内核强联动与全自动双向同步自愈机制：
    1. 反向比对当前 Linux 内核黑洞路由、ipset 阻断集合与数据库黑名单，若命中白名单则立刻解封；
    2. 采用临时集合 + ipset swap 原子镜像同步 portguard_whitelist_v4/v6，新增立即放行、删除立即剔除，零幽灵残留！
    """
    try:
        invalidate_whitelist_cache()
        if whitelist_items is None:
            cfg = load_config()
            whitelist_items = cfg.get("whitelist", DEFAULT_CONFIG.get("whitelist", []))

        healed_count = 0
        # 1. 扫描当前 Linux 内核路由表中实际存在的 IPv4 / IPv6 黑洞
        active_blackholes = set()
        for cmd in (["ip", "route", "show"], ["ip", "-6", "route", "show"]):
            try:
                res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, universal_newlines=True, timeout=2)
                for line in (res.stdout or "").splitlines():
                    if "blackhole" in line:
                        parts = line.strip().split()
                        if len(parts) >= 2:
                            bh_target = validate_ip(parts[1])
                            if bh_target:
                                active_blackholes.add(bh_target)
            except Exception:
                pass

        # 2. 扫描数据库黑名单中的 IP / 网段
        try:
            with closing(get_db()) as conn:
                c = conn.cursor()
                c.execute("SELECT ip FROM blacklist")
                for r in c.fetchall():
                    if r[0]:
                        active_blackholes.add(r[0])
        except Exception:
            pass

        # 3. 对所有处于阻断态的目标进行白名单核验，若在白名单中则立刻执行内核级解封
        for test_ip in active_blackholes:
            if ip_in_whitelist(test_ip, whitelist_items=whitelist_items):
                unban_ip_core(test_ip, status_event="WHITELIST", source_node="白名单自愈")
                healed_count += 1

        # 4. 内核级白名单 IPSet 集合原子双向同步（swap 替换确保已删除的白名单项同步从内核移除）
        if is_ipset_available():
            _ensure_ipset_net_set("portguard_whitelist_v4", is_ipv6=False)
            _ensure_ipset_net_set("portguard_whitelist_v6", is_ipv6=True)
            tmp_v4 = f"pg_wl4_{int(time.time()*1000)%100000}"
            tmp_v6 = f"pg_wl6_{int(time.time()*1000)%100000}"
            restore_lines = [
                f"create {tmp_v4} hash:net maxelem 65536 -exist\n",
                f"flush {tmp_v4}\n",
                f"create {tmp_v6} hash:net family inet6 maxelem 65536 -exist\n",
                f"flush {tmp_v6}\n",
            ]

            for item in (whitelist_items or []):
                w_ip = (item.get("ip") if isinstance(item, dict) else item) or ""
                w_ip = str(w_ip).strip()
                if not w_ip:
                    continue
                valid_w = validate_ip(w_ip)
                if not valid_w:
                    continue
                try:
                    is_cidr, is_v6, target_str, _ = _parse_ip_or_cidr_target(valid_w)
                    if not is_cidr:
                        bl_set = "portguard_blacklist_v6" if is_v6 else "portguard_blacklist_v4"
                        restore_lines.append(f"del {bl_set} {target_str} -exist\n")
                    else:
                        bn_set = "portguard_blacknet_v6" if is_v6 else "portguard_blacknet_v4"
                        restore_lines.append(f"del {bn_set} {target_str} -exist\n")
                    wl_tmp = tmp_v6 if is_v6 else tmp_v4
                    restore_lines.append(f"add {wl_tmp} {target_str} -exist\n")
                except Exception:
                    pass

            restore_lines.extend([
                f"swap {tmp_v4} portguard_whitelist_v4\n",
                f"destroy {tmp_v4}\n",
                f"swap {tmp_v6} portguard_whitelist_v6\n",
                f"destroy {tmp_v6}\n",
            ])
            _run_ipset_restore(restore_lines)

        return healed_count
    except Exception as e:
        print(f"[AutoHeal] 白名单自愈异常: {e}")
        return 0

