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

DB_PATH = "/opt/portsentry-ui/data.db"
CONFIG_PATH = "/opt/portsentry-ui/config.json"

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

def get_db():
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
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

def load_config():
    if not os.path.exists(CONFIG_PATH):
        os.makedirs(os.path.dirname(CONFIG_PATH), exist_ok=True)
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

def resolve_ip_geo(ip):
    try:
        url = f"http://ip-api.com/json/{ip}?fields=status,country,regionName,city,isp"
        req = urllib.request.Request(url, headers={"User-Agent": "PortsentryUI/2.0"})
        with urllib.request.urlopen(req, timeout=3) as resp:
            data = json.loads(resp.read().decode('utf-8'))
            if data.get("status") == "success":
                return {
                    "country": data.get("country", "未知国家"),
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

    # 3. 写入事件与黑名单库
    conn = get_db()
    c = conn.cursor()
    c.execute("""
    INSERT INTO events (ip, port, proto, port_name, category, level, country, region, city, isp, attack_time, timestamp, status)
    VALUES (?, ?, 'TCP', ?, ?, ?, '分析中...', '', '', '', ?, ?, 'BANNED')
    """, (ip, port, port_name, category, level, now_str, now_ts))
    event_id = c.lastrowid
    
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
            UPDATE blacklist SET country=? WHERE ip=?
            """, (geo["country"], ip))
            c_geo.commit()
            c_geo.close()
        except Exception:
            pass

    threading.Thread(target=_async_geo, daemon=True).start()

def get_active_system_ports():
    ports = set()
    try:
        res = subprocess.run("ss -tulpn | awk '{print $5}'", shell=True, capture_output=True, text=True)
        for line in res.stdout.splitlines():
            line = line.strip()
            if ":" in line:
                p_str = line.split(":")[-1]
                if p_str.isdigit():
                    ports.add(int(p_str))
    except Exception:
        pass
    return ports

class TrapServer:
    def __init__(self):
        self.sockets = []
        self.running = False
        self.trap_map = {}
        
    def start(self):
        self.running = True
        self.reload()
        threading.Thread(target=self._loop, daemon=True).start()
        
    def reload(self):
        for s, _ in self.sockets:
            try:
                s.close()
            except Exception:
                pass
        self.sockets = []
        self.trap_map = {}
        
        cfg = load_config()
        raw_trap_ports = cfg.get("trap_ports", DEFAULT_CONFIG["trap_ports"])
        active_ports = get_active_system_ports()
        
        normalized_traps = []
        for item in raw_trap_ports:
            if isinstance(item, int):
                item = {"port": item, "name": PORT_DESCRIPTIONS.get(item, f"TCP/{item}"), "enabled": True, "level": "高危", "category": "custom"}
            normalized_traps.append(item)
            
        for item in normalized_traps:
            if not item.get("enabled", True):
                continue
            port = item["port"]
            if port in active_ports:
                print(f"[Trap] 避开已占用端口: {port}")
                continue
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.bind(("0.0.0.0", port))
                s.listen(128)
                s.setblocking(False)
                self.sockets.append((s, port))
                self.trap_map[port] = item
                print(f"[Trap] 激活诱捕蜜罐: {port} - {item.get('name')}")
            except Exception as e:
                print(f"[Trap] 监听端口 {port} 异常: {e}")

    def _loop(self):
        cfg = load_config()
        while self.running:
            try:
                if not self.sockets:
                    time.sleep(1)
                    continue
                rlist = [s for s, _ in self.sockets]
                readable, _, _ = select.select(rlist, [], [], 1.0)
                for s in readable:
                    port = next((p for sock, p in self.sockets if sock == s), 0)
                    try:
                        client_sock, client_addr = s.accept()
                        client_ip = client_addr[0]
                        client_sock.close()
                        
                        port_info = self.trap_map.get(port, {"name": f"TCP/{port}", "category": "other", "level": "高危"})
                        print(f"[ALERT] 捕获扫描攻击: IP {client_ip} 正在探测蜜罐 {port} ({port_info.get('name')})")
                        threading.Thread(target=ban_ip, args=(client_ip, port, port_info), daemon=True).start()
                    except Exception:
                        pass
            except Exception as e:
                time.sleep(1)

trap_instance = TrapServer()

if __name__ == "__main__":
    init_db()
    trap_instance.start()
    while True:
        time.sleep(3600)
