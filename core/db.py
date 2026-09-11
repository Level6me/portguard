#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PortGuard Core Database & Configuration Management Module
数据库管理、持久化存储与配置核心控制
"""
import glob
import json
import os
import shutil
import sqlite3
import threading
import time

# 路径自适应解析：根目录为 core/ 的上一级
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = "/opt/portguard/data.db"
CONFIG_PATH = "/opt/portguard/config.json"

if not os.access("/opt", os.W_OK) or (os.path.exists("/opt/portguard") and not os.access("/opt/portguard", os.W_OK)):
    DB_PATH = os.path.join(BASE_DIR, "data.db")
    CONFIG_PATH = os.path.join(BASE_DIR, "config.json")
elif not os.path.exists("/opt/portguard") and os.path.exists("/opt/portsentry-ui/data.db"):
    # 兼容历史路径平滑过渡
    DB_PATH = "/opt/portsentry-ui/data.db"
    CONFIG_PATH = "/opt/portsentry-ui/config.json"

CONFIG_SNAPSHOTS_DIR = os.path.join(os.path.dirname(CONFIG_PATH), "snapshots")

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
    "admin_password": "",
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

DEFAULT_CONFIG["http_traps"] = DEFAULT_HTTP_TRAPS
PORT_DESCRIPTIONS = {t["port"]: t["name"] for t in DEFAULT_CONFIG["trap_ports"]}

_CONFIG_CACHE = None
_CONFIG_CACHE_MTIME = 0.0
_CONFIG_LOCK = threading.Lock()

def get_db():
    """获取 SQLite 数据库连接并开启超时等待与 NORMAL 同步"""
    conn = sqlite3.connect(DB_PATH, timeout=20)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA busy_timeout=15000;")
        conn.execute("PRAGMA synchronous=NORMAL;")
    except Exception:
        pass
    return conn

def init_db(auto_heal=True):
    """初始化数据库表结构与索引，自动完成增量模式补全迁移"""
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

    for col_sql in (
        "ALTER TABLE access_logs ADD COLUMN domain TEXT DEFAULT ''",
        "ALTER TABLE blacklist ADD COLUMN country TEXT",
        "ALTER TABLE blacklist ADD COLUMN level TEXT",
        "ALTER TABLE blacklist ADD COLUMN ban_expire INTEGER",
        "ALTER TABLE blacklist ADD COLUMN source_node TEXT DEFAULT '本机'",
        "ALTER TABLE events ADD COLUMN category TEXT",
        "ALTER TABLE events ADD COLUMN level TEXT",
    ):
        try:
            cursor.execute(col_sql)
        except Exception:
            pass

    try:
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_access_logs_domain ON access_logs(domain)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_access_logs_ts ON access_logs(timestamp)")
    except Exception:
        pass
        
    conn.commit()
    conn.close()
    if auto_heal:
        heal_cluster_geo_history()

def heal_cluster_geo_history():
    """后台自愈：将历史上所有未解析或标记为 未知地域/分析中 的 IP 归属地，异步重新解析"""
    def _worker():
        try:
            time.sleep(1.0)
            conn = get_db()
            c = conn.cursor()
            c.execute("UPDATE events SET port = 443, proto = 'TCP' WHERE port = 0 AND (port_name LIKE '%Web%' OR port_name LIKE '%HTTP%' OR port_name LIKE '%IP直连%' OR port_name LIKE '%诱捕%')")
            c.execute("UPDATE events SET proto = 'TCP' WHERE proto = 'MESH'")
            conn.commit()
            conn.close()

            unresolvable_cache = {}

            while True:
                try:
                    conn = get_db()
                    c = conn.cursor()
                    c.execute("SELECT DISTINCT ip FROM events WHERE country IN ('分析中...', '集群联防', '未知地域', '', 'None', 'null') OR country IS NULL OR isp IN ('分析中...', '', '0', 'None', 'null') OR isp IS NULL LIMIT 200")
                    event_ips = [r[0] for r in c.fetchall() if r[0]]

                    c.execute("SELECT DISTINCT ip FROM blacklist WHERE country IN ('分析中...', '集群联防', '未知地域', '', 'None', 'null') OR country IS NULL LIMIT 200")
                    bl_ips = [r[0] for r in c.fetchall() if r[0]]

                    c.execute("SELECT DISTINCT ip FROM port_access_logs WHERE country IN ('分析中...', '未知地域', '', 'None', 'null') OR country IS NULL LIMIT 200")
                    pal_ips = [r[0] for r in c.fetchall() if r[0]]

                    conn.close()

                    now = time.time()
                    target_ips = [
                        ip for ip in set(event_ips + bl_ips + pal_ips)
                        if (now - unresolvable_cache.get(ip, 0)) > 1800
                    ]

                    if not target_ips:
                        time.sleep(30.0)
                        continue

                    try:
                        from geo import _GEO_CACHE, resolve_ip_geo, resolve_ip_geo_local
                    except ImportError:
                        time.sleep(30.0)
                        continue

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

                    time.sleep(10.0)
                except Exception:
                    time.sleep(10.0)
        except Exception:
            pass
    threading.Thread(target=_worker, daemon=True, name="GeoHealWorker").start()

def load_config():
    global _CONFIG_CACHE, _CONFIG_CACHE_MTIME
    try:
        dir_name = os.path.dirname(CONFIG_PATH)
        if dir_name and not os.path.exists(dir_name):
            os.makedirs(dir_name, exist_ok=True)
        if not os.path.exists(CONFIG_PATH):
            initial_cfg = dict(DEFAULT_CONFIG)
            try:
                import secrets
                initial_cfg["admin_password"] = secrets.token_urlsafe(12)
            except Exception:
                import uuid
                initial_cfg["admin_password"] = uuid.uuid4().hex[:12]
            with open(CONFIG_PATH, "w", encoding="utf-8") as f:
                json.dump(initial_cfg, f, indent=2, ensure_ascii=False)
            with _CONFIG_LOCK:
                _CONFIG_CACHE = dict(initial_cfg)
                _CONFIG_CACHE_MTIME = os.path.getmtime(CONFIG_PATH)
            return dict(_CONFIG_CACHE)

        mtime = os.path.getmtime(CONFIG_PATH)
        with _CONFIG_LOCK:
            if _CONFIG_CACHE is not None and mtime == _CONFIG_CACHE_MTIME:
                return dict(_CONFIG_CACHE)

        with open(CONFIG_PATH, "r", encoding="utf-8") as f:
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

def save_config(cfg):
    global _CONFIG_CACHE, _CONFIG_CACHE_MTIME
    try:
        dir_name = os.path.dirname(CONFIG_PATH)
        if dir_name and not os.path.exists(dir_name):
            os.makedirs(dir_name, exist_ok=True)
            
        if os.path.exists(CONFIG_PATH):
            try:
                if not os.path.exists(CONFIG_SNAPSHOTS_DIR):
                    os.makedirs(CONFIG_SNAPSHOTS_DIR, exist_ok=True)
                snap_time = time.strftime("%Y%m%d_%H%M%S")
                snap_path = os.path.join(CONFIG_SNAPSHOTS_DIR, f"config_{snap_time}.json")
                shutil.copy2(CONFIG_PATH, snap_path)
                
                snaps = sorted(glob.glob(os.path.join(CONFIG_SNAPSHOTS_DIR, "config_*.json")), key=os.path.getmtime)
                if len(snaps) > 15:
                    for old_snap in snaps[:-15]:
                        try:
                            os.remove(old_snap)
                        except Exception:
                            pass
            except Exception:
                pass

        with open(CONFIG_PATH, "w", encoding="utf-8") as f:
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
    try:
        clean_fn = os.path.basename(filename)
        target = os.path.join(CONFIG_SNAPSHOTS_DIR, clean_fn)
        if not os.path.exists(target):
            return False, "指定的快照文件不存在"
        with open(target, "r", encoding="utf-8") as f:
            snap_cfg = json.load(f)
        with open(CONFIG_PATH, "w", encoding="utf-8") as f:
            json.dump(snap_cfg, f, indent=2, ensure_ascii=False)
        return True, "配置已成功从快照回滚还原！"
    except Exception as e:
        return False, f"回滚失败: {e}"

def get_hidden_ips_set():
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
    from core.firewall import validate_ip
    from geo import resolve_ip_geo
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
    from core.firewall import validate_ip
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
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT id, rule_id, name, match_type, pattern, threshold, window, action, level, enabled, description, created_at FROM http_traps ORDER BY id ASC")
        rows = cursor.fetchall()
        conn.close()
        if rows:
            return [dict(r) for r in rows]
        return [dict(r) for r in DEFAULT_HTTP_TRAPS]
    except Exception:
        return [dict(r) for r in DEFAULT_HTTP_TRAPS]
