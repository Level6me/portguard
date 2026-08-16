#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Portsentry Core Daemon v2.0 - 高级蜜罐诱捕与智能威胁防御引擎
"""
import os
import sys
import time
import socket
import select
import sqlite3
import threading
import subprocess
import json
import urllib.request
import re

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = "/opt/portsentry-ui/data.db"
CONFIG_PATH = "/opt/portsentry-ui/config.json"

if not os.path.exists("/opt/portsentry-ui") and not os.access("/opt", os.W_OK):
    DB_PATH = os.path.join(BASE_DIR, "data.db")
    CONFIG_PATH = os.path.join(BASE_DIR, "config.json")

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
        {"ip": "10.0.0.0/8", "remark": "私网 A 类地址"},
        {"ip": "172.16.0.0/12", "remark": "私网 B 类地址"},
        {"ip": "192.168.0.0/16", "remark": "私网 C 类地址"},
        {"ip": "43.155.173.146", "remark": "腾讯云节点"}
    ],
    "web_port": 9099,
    "web_bind": "0.0.0.0",
    "admin_password": "admin",
    "defense_mode": "strict",
    "ban_action_iptables": True,
    "ban_action_blackhole": True,
    "auto_clean_days": 30
}

PORT_DESCRIPTIONS = {t["port"]: t["name"] for t in DEFAULT_CONFIG["trap_ports"]}

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
        "category": cat
    }

def get_db():
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    dir_name = os.path.dirname(DB_PATH)
    if dir_name:
        os.makedirs(dir_name, exist_ok=True)
    conn = get_db()
    cursor = conn.cursor()
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
        timestamp INTEGER
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
    
    # 自动列自适应补充（迁移旧库）
    try:
        cursor.execute("ALTER TABLE blacklist ADD COLUMN country TEXT")
    except Exception:
        pass
    try:
        cursor.execute("ALTER TABLE blacklist ADD COLUMN level TEXT")
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
        
    conn.commit()
    conn.close()

_WEB_PORT_LOG_CACHE = {}

def log_access_entry(ip, method, path, status_code=200, user_agent=""):
    try:
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
            desc = f"安全白名单访问: Web控制台 (端口 {web_port})" if is_white else f"正常业务连接: Portsentry Web控制台 (端口 {web_port})"
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
            threading.Thread(target=_async_geo_web, args=(web_log_id, port_log_id, ip), daemon=True).start()
    except Exception:
        pass

def log_port_access_entry(ip, port, port_name="诱捕探针", action="INTERCEPTED", geo=None):
    try:
        now_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        now_ts = int(time.time())
        geo = geo or {}
        country = geo.get("country", "公网探测" if ip not in ("127.0.0.1", "::1", "localhost") else "本地测试")
        region = geo.get("region", "")
        city = geo.get("city", "")
        isp = geo.get("isp", "")
        
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("""
        INSERT INTO port_access_logs (ip, port, proto, port_name, country, region, city, isp, action, access_time, timestamp)
        VALUES (?, ?, 'TCP', ?, ?, ?, ?, ?, ?, ?, ?)
        """, (ip, port, port_name, country, region, city, isp, action, now_str, now_ts))
        conn.commit()
        conn.close()
    except Exception:
        pass

def load_config():
    dir_name = os.path.dirname(CONFIG_PATH)
    if dir_name and not os.path.exists(dir_name):
        os.makedirs(dir_name, exist_ok=True)
    if not os.path.exists(CONFIG_PATH):
        with open(CONFIG_PATH, 'w', encoding='utf-8') as f:
            json.dump(DEFAULT_CONFIG, f, indent=2, ensure_ascii=False)
        return DEFAULT_CONFIG
    try:
        with open(CONFIG_PATH, 'r', encoding='utf-8') as f:
            cfg = json.load(f)
            return {**DEFAULT_CONFIG, **cfg}
    except Exception:
        return DEFAULT_CONFIG

def save_config(cfg):
    try:
        with open(CONFIG_PATH, 'w', encoding='utf-8') as f:
            json.dump(cfg, f, indent=2, ensure_ascii=False)
        return True
    except Exception:
        return False

def ip_in_whitelist(ip, whitelist_items):
    if ip in ("127.0.0.1", "::1", "localhost"):
        return True
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
    "Italy": "意大利", "Spain": "西班牙", "Vietnam": "越南", "Thailand": "泰国",
    "Indonesia": "印度尼西亚", "Malaysia": "马来西亚", "Philippines": "菲律宾", "Turkey": "土耳其",
    "Ukraine": "乌克兰", "Poland": "波兰", "Sweden": "瑞典", "Switzerland": "瑞士",
    "South Africa": "南非", "Egypt": "埃及", "Mexico": "墨西哥", "Argentina": "阿根廷",
    "Chile": "智利", "Colombia": "哥伦比亚", "Iran": "伊朗", "Israel": "以色列",
    "Saudi Arabia": "沙特阿拉伯", "United Arab Emirates": "阿联酋", "Pakistan": "巴基斯坦"
}

def translate_country_cn(name):
    if not name:
        return "未知地域"
    return GEO_COUNTRY_CN.get(name.strip(), name.strip())

def resolve_ip_geo(ip):
    try:
        url = f"http://ip-api.com/json/{ip}?lang=zh-CN&fields=status,country,regionName,city,isp"
        req = urllib.request.Request(url, headers={"User-Agent": "PortsentryUI/2.0"})
        with urllib.request.urlopen(req, timeout=3) as resp:
            data = json.loads(resp.read().decode('utf-8'))
            if data.get("status") == "success":
                c = translate_country_cn(data.get("country", ""))
                return {
                    "country": c,
                    "region": data.get("regionName", ""),
                    "city": data.get("city", ""),
                    "isp": data.get("isp", "")
                }
    except Exception:
        pass
    return {"country": "公网节点", "region": "", "city": "", "isp": ""}

def ban_ip(ip, port, port_info):
    cfg = load_config()
    now_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    now_ts = int(time.time())
    
    # 1. 白名单拦截保护
    whitelist = cfg.get("whitelist", [])
    if ip_in_whitelist(ip, whitelist):
        print(f"[WHITELIST] 忽略安全白名单 IP: {ip} 探测端口 {port}")
        log_port_access_entry(ip, port, port_info.get("name", f"TCP/{port}"), action="WHITELIST")
        return
        
    # 2. 毫秒级优先执行内核防火墙阻断与黑洞路由
    if cfg.get("ban_action_iptables", True):
        subprocess.run(f"iptables -I INPUT -s {ip} -j DROP 2>/dev/null || true", shell=True)
        subprocess.run("iptables-save > /etc/sysconfig/iptables 2>/dev/null || true", shell=True)
        
    if cfg.get("ban_action_blackhole", True):
        subprocess.run(f"ip route add blackhole {ip}/32 2>/dev/null || true", shell=True)
        
    port_name = port_info.get("name", f"TCP/{port}")
    category = port_info.get("category", "other")
    level = port_info.get("level", "高危")

    # 3. 写入事件与黑名单库与端口访问日志
    conn = get_db()
    c = conn.cursor()
    c.execute("""
    INSERT INTO events (ip, port, proto, port_name, category, level, country, region, city, isp, attack_time, timestamp, status)
    VALUES (?, ?, 'TCP', ?, ?, ?, '分析中...', '', '', '', ?, ?, 'BANNED')
    """, (ip, port, port_name, category, level, now_str, now_ts))
    event_id = c.lastrowid
    
    c.execute("""
    INSERT INTO port_access_logs (ip, port, proto, port_name, country, region, city, isp, action, access_time, timestamp)
    VALUES (?, ?, 'TCP', ?, '分析中...', '', '', '', 'INTERCEPTED', ?, ?)
    """, (ip, port, port_name, now_str, now_ts))
    port_log_id = c.lastrowid

    c.execute("""
    INSERT OR REPLACE INTO blacklist (ip, reason, country, level, ban_time, timestamp)
    VALUES (?, ?, '分析中...', ?, ?, ?)
    """, (ip, f"探测蜜罐端口 {port} ({port_name})", level, now_str, now_ts))
    conn.commit()
    conn.close()
    
    # 4. 后台异步解析地理位置并回填
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

    threading.Thread(target=_async_geo, daemon=True).start()

_SYSTEM_PORTS_CACHE = {}
_SYSTEM_PORTS_CACHE_TIME = 0

def get_active_system_ports():
    global _SYSTEM_PORTS_CACHE, _SYSTEM_PORTS_CACHE_TIME
    now = time.time()
    if _SYSTEM_PORTS_CACHE and (now - _SYSTEM_PORTS_CACHE_TIME < 10.0):
        return _SYSTEM_PORTS_CACHE

    ports_map = {9099: "Portsentry Web控制台"}
    try:
        cfg = load_config()
        web_p = int(cfg.get("web_port", 9099))
        ports_map[web_p] = "Portsentry Web控制台"
    except Exception:
        pass
        
    try:
        # 兼容 Python 3.6+，排除自身 python3 进程，精准获取系统全部真实业务服务与进程名
        p = subprocess.Popen("ss -tulpn | grep -v python3", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
        stdout, _ = p.communicate(timeout=3)
        for line in stdout.splitlines():
            line = line.strip()
            if not ("LISTEN" in line or "UNCONN" in line):
                continue
            parts = line.split()
            if len(parts) >= 5:
                local_addr = parts[4]
                p_str = local_addr.split(":")[-1]
                if p_str.isdigit():
                    port = int(p_str)
                    proc_name = "系统服务"
                    if len(parts) >= 6 and 'users:(("' in line:
                        try:
                            proc_name = line.split('users:(("')[1].split('"')[0]
                        except Exception:
                            pass
                    ports_map[port] = proc_name
    except Exception:
        pass
    _SYSTEM_PORTS_CACHE = ports_map
    _SYSTEM_PORTS_CACHE_TIME = now
    return ports_map

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
        active_ports = set(active_ports_map.keys())
        
        normalized_traps = []
        for item in raw_trap_ports:
            norm = normalize_trap_item(item)
            if norm:
                normalized_traps.append(norm)
            
        MAX_TOTAL_TRAP_SOCKETS = 30000
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
                                client_sock.close()
                                
                                port_info = self.trap_map.get(port, {"name": f"TCP/{port}", "category": "custom", "level": "高危"})
                                print(f"[ALERT] 捕获扫描攻击: IP {client_ip} 正在探测蜜罐 {port} ({port_info.get('name')})")
                                threading.Thread(target=ban_ip, args=(client_ip, port, port_info), daemon=True).start()
                            except Exception:
                                pass
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
                                    client_sock.close()
                                    
                                    port_info = self.trap_map.get(port, {"name": f"TCP/{port}", "category": "custom", "level": "高危"})
                                    print(f"[ALERT] 捕获扫描攻击: IP {client_ip} 正在探测蜜罐 {port} ({port_info.get('name')})")
                                    threading.Thread(target=ban_ip, args=(client_ip, port, port_info), daemon=True).start()
                                except Exception:
                                    pass
            except Exception as e:
                time.sleep(0.5)

class GlobalPortSniffer:
    """全端口网络连接实时感知引擎 (基于 Linux 原生 Raw Socket 嗅探 TCP SYN 连接握手)"""
    def __init__(self):
        self.running = False
        self.raw_sock = None
        self._recent_cache = {} # (ip, port) -> timestamp (防抖降噪)
        self.local_ips = {"127.0.0.1", "0.0.0.0"}
        self._refresh_local_ips()
        
    def _refresh_local_ips(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            self.local_ips.add(s.getsockname()[0])
            s.close()
        except Exception:
            pass
        try:
            res = socket.gethostbyname_ex(socket.gethostname())
            for ip in res[2]:
                self.local_ips.add(ip)
        except Exception:
            pass
        
    def start(self):
        self.running = True
        self._refresh_local_ips()
        threading.Thread(target=self._sniffer_loop, daemon=True).start()
        
    def stop(self):
        self.running = False
        if self.raw_sock:
            try:
                self.raw_sock.close()
            except Exception:
                pass

    def _sniffer_loop(self):
        sock = None
        try:
            # 优先采用 Linux 链路层 AF_PACKET 套接字 (捕获全网卡、Docker 转发与全部 TCP 会话)
            ETH_P_IP = 0x0800
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_IP))
            print("[Sniffer] AF_PACKET 链路层全端口嗅探引擎已激活 (100% 捕获全网卡入站连接与服务通信)...")
        except Exception:
            try:
                # 降级方案: AF_INET RAW 套接字
                sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
                print("[Sniffer] IPPROTO_TCP 原始套接字嗅探引擎已激活...")
            except Exception as e:
                print(f"[Sniffer] 无法开启底层网络嗅探 (可能非 root 环境或无 RAW 权限): {e}")
                return
                
        self.raw_sock = sock
        while self.running:
            try:
                raw_data, _ = self.raw_sock.recvfrom(65535)
                # 自适应探测 IP 报文头起始偏移 (适配 14字节以太网帧、16字节SLL头或 0字节RAW)
                offset = 0
                if len(raw_data) >= 34 and ((raw_data[14] >> 4) == 4):
                    offset = 14
                elif len(raw_data) >= 36 and ((raw_data[16] >> 4) == 4):
                    offset = 16
                elif len(raw_data) >= 20 and ((raw_data[0] >> 4) == 4):
                    offset = 0
                else:
                    continue
                    
                ip_hdr = raw_data[offset:offset+20]
                proto = ip_hdr[9]
                if proto != 6: # 仅处理 TCP
                    continue
                    
                v_ihl = ip_hdr[0]
                ihl = (v_ihl & 0x0F) * 4
                if len(raw_data) < offset + ihl + 20:
                    continue
                    
                src_ip = socket.inet_ntoa(ip_hdr[12:16])
                dst_ip = socket.inet_ntoa(ip_hdr[16:20])
                
                # 过滤本机发出的包、环回流量以及私有 Docker 内部流量
                if src_ip in self.local_ips or src_ip.startswith("127.") or src_ip == "0.0.0.0" or src_ip.startswith("172.17.") or src_ip.startswith("172.18."):
                    continue
                    
                tcp_hdr = raw_data[offset+ihl:offset+ihl+20]
                src_port, dst_port = struct.unpack("!HH", tcp_hdr[:4])
                
                # 过滤外网公共响应包 (目的端口必须有效)
                if dst_port <= 0:
                    continue
                    
                now_ts = time.time()
                cache_key = (src_ip, dst_port)
                # 2秒内相同 IP + 端口去重防抖 (杜绝单次通信产生海量重复记录)
                if cache_key in self._recent_cache:
                    if now_ts - self._recent_cache[cache_key] < 2.0:
                        continue
                self._recent_cache[cache_key] = now_ts
                
                # 定期清理防抖缓存
                if len(self._recent_cache) > 5000:
                    cutoff = now_ts - 10.0
                    self._recent_cache = {k: v for k, v in self._recent_cache.items() if v > cutoff}
                    
                # 异步记录此端口连接事件
                self._handle_port_access(src_ip, dst_port)
            except Exception:
                pass

    def _handle_port_access(self, src_ip, dst_port):
        cfg = load_config()
        whitelist = cfg.get("whitelist", [])
        active_ports_map = get_active_system_ports()
        
        # 1. 优先白名单放行
        if ip_in_whitelist(src_ip, whitelist):
            action = "WHITELIST"
            proc = active_ports_map.get(dst_port, "")
            desc = f"白名单访问: {proc} (端口 {dst_port})" if proc else f"安全白名单访问 (端口 {dst_port})"
        # 2. 正常系统业务访问（如 SSH 29675、Web 9099、OpenResty 80/443、1Panel 等）
        elif dst_port in active_ports_map:
            action = "BUSINESS"
            proc = active_ports_map[dst_port]
            desc = f"正常业务连接: {proc} (端口 {dst_port})"
        # 3. 命中活跃诱饵蜜罐
        elif dst_port in trap_instance.trap_map:
            action = "INTERCEPTED"
            trap_meta = trap_instance.trap_map.get(dst_port, {})
            desc = trap_meta.get("name") or trap_meta.get("description") or f"蜜罐探针 (端口 {dst_port})"
        # 4. 其他未开放端口常规探测
        else:
            action = "PROBE"
            desc = f"常规端口探测 (端口 {dst_port})"
            
        def _async_write():
            try:
                now_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
                now_ts = int(time.time())
                conn = get_db()
                c = conn.cursor()
                c.execute("""
                INSERT INTO port_access_logs (ip, port, proto, port_name, country, region, city, isp, action, access_time, timestamp)
                VALUES (?, ?, 'TCP', ?, '分析中...', '', '', '', ?, ?, ?)
                """, (src_ip, dst_port, desc, action, now_str, now_ts))
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
                threading.Thread(target=_geo_backfill, args=(new_id, src_ip), daemon=True).start()
            except Exception:
                pass
                
        threading.Thread(target=_async_write, daemon=True).start()

trap_instance = TrapServer()
sniffer_instance = GlobalPortSniffer()

if __name__ == "__main__":
    init_db()
    trap_instance.start()
    sniffer_instance.start()
    while True:
        time.sleep(3600)
