import gzip
import os
import sys
import json
import time
import sqlite3
import subprocess
import re
import threading
import socket
import ipaddress
try:
    from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
except ImportError:
    from http.server import HTTPServer, BaseHTTPRequestHandler
    from socketserver import ThreadingMixIn
    class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
        daemon_threads = True
        allow_reuse_address = True
import urllib.request
import urllib.error
import urllib.parse
from urllib.parse import urlparse, parse_qs

_RAW_HTML_CACHE = None
_GZIP_HTML_CACHE = None
from sentry_daemon import (
    DB_PATH, CONFIG_PATH, load_config, save_config, get_db, init_db,
    trap_instance, sniffer_instance, site_collector_instance, DEFAULT_CONFIG, PORT_DESCRIPTIONS,
    DEFAULT_HTTP_TRAPS, get_http_traps, check_http_request_traps,
    normalize_trap_item, log_access_entry, validate_ip, run_firewall_cmd,
    cleanup_expired_bans, ip_in_whitelist, resolve_ip_geo, resolve_ip_geo_local, _GEO_CACHE, _EXECUTOR,
    get_hidden_ips, get_hidden_ips_set, add_hidden_ip, remove_hidden_ip, clear_hidden_ips,
    get_all_business_ports_info, get_active_system_ports, unban_ip_core,
    ban_ip_firewall, init_firewall_ipset, flush_firewall_blocks, verify_cluster_token, generate_cluster_token, ban_ip,
    normalize_cluster_node, broadcast_cluster_whitelist, broadcast_cluster_ban,
    broadcast_cluster_unban, sync_cluster_mesh_state, start_cluster_autosync_worker,
    get_ip_threat_tags, get_config_snapshots, rollback_config_snapshot, check_c2_compromise_connections
)

def parse_loose_json_or_lines(text):
    text = (text or "").strip()
    if not text:
        return []
    # 1. 尝试直接标准 JSON 解析
    try:
        data = json.loads(text)
        if isinstance(data, list):
            return data
        if isinstance(data, dict):
            for k in ("data", "items", "traps", "blacklist", "whitelist", "rules", "list"):
                if k in data and isinstance(data[k], list):
                    return data[k]
            return [data]
    except Exception:
        pass
    
    # 2. 修复常见手输 JSON 瑕疵 (如末尾多余逗号 ,] 或 ,} 以及注释)
    cleaned = text
    cleaned = re.sub(r'//.*', '', cleaned)
    cleaned = re.sub(r'/\*[\s\S]*?\*/', '', cleaned)
    cleaned = re.sub(r',\s*([\]\}])', r'\1', cleaned)
    try:
        data = json.loads(cleaned)
        if isinstance(data, list):
            return data
        if isinstance(data, dict):
            for k in ("data", "items", "traps", "blacklist", "whitelist", "rules", "list"):
                if k in data and isinstance(data[k], list):
                    return data[k]
            return [data]
    except Exception:
        pass

    # 3. 逐行提取（针对纯文本 IP / 规则行模式）
    results = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith('#') or line.startswith('//'):
            continue
        try:
            line_obj = json.loads(re.sub(r',\s*$', '', line))
            results.append(line_obj)
        except Exception:
            results.append(line)
    return results

TEMPLATES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "templates")
_HTML_TEMPLATE_CACHE = None
_HTML_TEMPLATE_MTIME = 0.0

def load_html_template():
    global _HTML_TEMPLATE_CACHE, _HTML_TEMPLATE_MTIME, _RAW_HTML_CACHE, _GZIP_HTML_CACHE
    template_path = os.path.join(TEMPLATES_DIR, "index.html")
    if not os.path.exists(template_path):
        alt_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "index.html")
        if os.path.exists(alt_path):
            template_path = alt_path

    if os.path.exists(template_path):
        try:
            mtime = os.path.getmtime(template_path)
            if _HTML_TEMPLATE_CACHE is not None and mtime == _HTML_TEMPLATE_MTIME:
                return _HTML_TEMPLATE_CACHE
            with open(template_path, "r", encoding="utf-8") as f:
                html = f.read()
            chart_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "chart.min.js")
            if os.path.exists(chart_path):
                try:
                    with open(chart_path, "r", encoding="utf-8") as cf:
                        chart_src = cf.read()
                    html = html.replace(
                        '<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>',
                        "<script>" + chart_src + "</script>"
                    )
                except Exception:
                    pass
            _HTML_TEMPLATE_CACHE = html
            _HTML_TEMPLATE_MTIME = mtime
            _RAW_HTML_CACHE = html.encode("utf-8")
            _GZIP_HTML_CACHE = gzip.compress(_RAW_HTML_CACHE, compresslevel=6)
            return html
        except Exception:
            pass
    return _HTML_TEMPLATE_CACHE or "<h1>PortGuard 模板文件缺失，请检查 templates/index.html</h1>"

HTML_TEMPLATE = load_html_template()

def load_report_template():
    report_path = os.path.join(TEMPLATES_DIR, "report.html")
    if not os.path.exists(report_path):
        alt_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "report.html")
        if os.path.exists(alt_path):
            report_path = alt_path
    if os.path.exists(report_path):
        try:
            with open(report_path, "r", encoding="utf-8") as f:
                return f.read()
        except Exception:
            pass
    return ""

# 黑名单全局极速内存缓存（毫秒级响应，防全量离线库二次计算卡顿）
_BLACKLIST_CACHE = None
_BLACKLIST_CACHE_TIME = 0.0
_BLACKLIST_CACHE_LOCK = threading.Lock()

def invalidate_blacklist_cache():
    global _BLACKLIST_CACHE, _BLACKLIST_CACHE_TIME
    with _BLACKLIST_CACHE_LOCK:
        _BLACKLIST_CACHE = None
        _BLACKLIST_CACHE_TIME = 0.0

class RequestHandler(BaseHTTPRequestHandler):
    def send_response(self, code, message=None):
        # 在响应层统一记录访问日志：真实状态码、覆盖 GET/POST/HEAD/OPTIONS/404/400 等全部请求
        super().send_response(code, message)
        try:
            client_ip = self.client_address[0]  # 直连来源 IP，不信任可伪造的 X-Forwarded-For
            user_agent = self.headers.get('User-Agent', '')
            parsed = urlparse(self.path)
            log_access_entry(client_ip, self.command, parsed.path, code, user_agent)
        except Exception:
            pass

    def _send_response_data(self, data_bytes, content_type="application/json; charset=utf-8", status=200):
        try:
            self.send_response(status)
            self.send_header('Content-Type', content_type)
            origin = self.headers.get('Origin', '')
            host = self.headers.get('Host', '')
            if origin:
                parsed_origin = urlparse(origin)
                origin_host = parsed_origin.netloc.split(':')[0]
                req_host = host.split(':')[0] if host else ''
                if origin_host in (req_host, 'localhost', '127.0.0.1', '::1') or not req_host:
                    self.send_header('Access-Control-Allow-Origin', origin)
                    self.send_header('Access-Control-Allow-Credentials', 'true')
                    self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
                    self.send_header('Access-Control-Allow-Headers', 'Content-Type, X-Requested-With, X-Cluster-Token')
            self.send_header('X-Content-Type-Options', 'nosniff')
            self.send_header('X-Frame-Options', 'SAMEORIGIN')
            self.send_header('Referrer-Policy', 'strict-origin-when-cross-origin')
            self.send_header('Cache-Control', 'no-cache, no-store, must-revalidate, max-age=0')
            self.send_header('Pragma', 'no-cache')
            self.send_header('Expires', '0')
            
            accept_encoding = self.headers.get('Accept-Encoding', '')
            if 'gzip' in accept_encoding and len(data_bytes) > 256:
                compressed = gzip.compress(data_bytes, compresslevel=5)
                self.send_header('Content-Encoding', 'gzip')
                self.send_header('Content-Length', str(len(compressed)))
                self.end_headers()
                self.wfile.write(compressed)
            else:
                self.send_header('Content-Length', str(len(data_bytes)))
                self.end_headers()
                self.wfile.write(data_bytes)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _send_json(self, data, status=200):
        payload = json.dumps(data, ensure_ascii=False).encode('utf-8')
        self._send_response_data(payload, content_type="application/json; charset=utf-8", status=status)

    def _send_html(self, html, status=200):
        global _GZIP_HTML_CACHE, _RAW_HTML_CACHE
        if _RAW_HTML_CACHE is None:
            _RAW_HTML_CACHE = html.encode('utf-8')
            _GZIP_HTML_CACHE = gzip.compress(_RAW_HTML_CACHE, compresslevel=6)
        
        try:
            accept_encoding = self.headers.get('Accept-Encoding', '')
            self.send_response(status)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.send_header('X-Content-Type-Options', 'nosniff')
            self.send_header('X-Frame-Options', 'SAMEORIGIN')
            self.send_header('Referrer-Policy', 'strict-origin-when-cross-origin')
            self.send_header('Cache-Control', 'no-cache, no-store, must-revalidate, max-age=0')
            self.send_header('Pragma', 'no-cache')
            self.send_header('Expires', '0')
            
            if 'gzip' in accept_encoding:
                self.send_header('Content-Encoding', 'gzip')
                self.send_header('Content-Length', str(len(_GZIP_HTML_CACHE)))
                self.end_headers()
                self.wfile.write(_GZIP_HTML_CACHE)
            else:
                self.send_header('Content-Length', str(len(_RAW_HTML_CACHE)))
                self.end_headers()
                self.wfile.write(_RAW_HTML_CACHE)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def do_OPTIONS(self):
        self._send_response_data(b"", status=204)

    def do_HEAD(self):
        self.send_response(200)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.end_headers()

    def do_GET(self):
        try:
            parsed = urlparse(self.path)
            path = parsed.path

            # 0. Web 隐形金丝雀蜜标与爬虫诱捕 (Canary Honey Tokens)
            CANARY_PATHS = {
                "/admin_internal_backup/": "高危管理备份目录",
                "/system-debug-console/": "系统调试控制台入口",
                "/.env_backup": "环境配置文件备份",
                "/api/v1/internal_debug_auth": "内部调试授权接口",
                "/backup_internal_2026.tar.gz": "全站源码与数据库备份包"
            }
            if path == "/robots.txt":
                robots_content = (
                    "User-agent: *\n"
                    "Disallow: /admin_internal_backup/\n"
                    "Disallow: /system-debug-console/\n"
                    "Disallow: /.env_backup\n"
                    "Disallow: /api/v1/internal_debug_auth\n"
                    "Disallow: /backup_internal_2026.tar.gz\n"
                ).encode("utf-8")
                self.send_response(200)
                self.send_header('Content-Type', 'text/plain; charset=utf-8')
                self.send_header('Content-Length', str(len(robots_content)))
                self.end_headers()
                self.wfile.write(robots_content)
                return

            if path in CANARY_PATHS:
                client_ip = self.client_address[0]
                canary_desc = CANARY_PATHS[path]
                ban_ip(client_ip, reason=f"Web蜜标触发: 访问隐藏诱饵路径 ({canary_desc})", category="canary", level="极高危")
                self.send_response(404)
                self.send_header('Content-Type', 'text/html; charset=utf-8')
                self.end_headers()
                self.wfile.write(b"<h1>404 Not Found</h1>")
                return

            if path in ("/", "/index.html"):
                self._send_html(HTML_TEMPLATE)
                return

            if path == "/api/stats":
                conn = get_db()
                c = conn.cursor()
                
                c.execute("SELECT COUNT(DISTINCT ip) FROM blacklist WHERE ip NOT IN (SELECT ip FROM hidden_ips)")
                total_banned = c.fetchone()[0]
                
                today_prefix = time.strftime("%Y-%m-%d", time.localtime())
                c.execute("SELECT COUNT(*) FROM events WHERE attack_time LIKE ? AND ip NOT IN (SELECT ip FROM hidden_ips)", (f"{today_prefix}%",))
                today_events = c.fetchone()[0]
                
                c.execute("""
                SELECT port, port_name, COUNT(*) as cnt 
                FROM events 
                WHERE ip NOT IN (SELECT ip FROM hidden_ips)
                GROUP BY port 
                ORDER BY cnt DESC 
                LIMIT 5
                """)
                port_dist = [{"port": row["port"], "name": row["port_name"], "count": row["cnt"]} for row in c.fetchall()]
                
                # 国家排行 Top 10
                c.execute("""
                SELECT country, COUNT(*) as cnt 
                FROM events 
                WHERE country IS NOT NULL AND country != '' 
                  AND country NOT IN ('分析中...', '未知地域', 'Localhost', '本地回环')
                  AND ip NOT IN (SELECT ip FROM hidden_ips)
                GROUP BY country 
                ORDER BY cnt DESC 
                LIMIT 10
                """)
                geo_rank = [{"country": row["country"], "count": row["cnt"]} for row in c.fetchall()]
                
                # 24小时趋势
                labels = []
                full_labels = []
                data_points = []
                now_ts = int(time.time())
                for i in range(23, -1, -1):
                    hour_start = now_ts - (i * 3600)
                    hour_end = hour_start + 3600
                    hour_label = time.strftime("%H:00", time.localtime(hour_start))
                    full_label = time.strftime("%Y-%m-%d %H:00", time.localtime(hour_start))
                    c.execute("SELECT COUNT(*) FROM events WHERE timestamp >= ? AND timestamp < ? AND ip NOT IN (SELECT ip FROM hidden_ips)", (hour_start, hour_end))
                    labels.append(hour_label)
                    full_labels.append(full_label)
                    data_points.append(c.fetchone()[0])
                    
                c.execute("SELECT COUNT(DISTINCT ip) FROM events WHERE ip NOT IN (SELECT ip FROM hidden_ips)")
                unique_attackers = c.fetchone()[0]

                cfg = load_config()
                conn.close()
                
                raw_traps = cfg.get("trap_ports", DEFAULT_CONFIG["trap_ports"])
                active_traps = sum(1 for t in raw_traps if (t.get("enabled", True) if isinstance(t, dict) else True))
                whitelist_count = len(cfg.get("whitelist", []))
                hidden_ips_cnt = len(get_hidden_ips_set())
                cluster_nodes_count = max(1, len(cfg.get("cluster_sync", {}).get("cluster_nodes", [])) + 1)
                
                self._send_json({
                    "total_banned": total_banned,
                    "today_events": today_events,
                    "unique_attackers": unique_attackers,
                    "active_traps": active_traps,
                    "whitelist_count": whitelist_count,
                    "cluster_nodes_count": cluster_nodes_count,
                    "hidden_count": hidden_ips_cnt,
                    "defense_paused": bool(cfg.get("defense_paused", False)),
                    "port_distribution": port_dist,
                    "geo_rank": geo_rank,
                    "hourly_trend": {
                        "labels": labels,
                        "full_labels": full_labels,
                        "data": data_points
                    }
                })
                return

            if path == "/api/report/export":
                # 一键生成专业安全合规审计报告 (自包含响应式 HTML，支持直接浏览器打印转为 PDF)
                conn = get_db()
                c = conn.cursor()
                now_ts = int(time.time())
                now_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(now_ts))
                cfg = load_config()

                c.execute("SELECT COUNT(DISTINCT ip) FROM blacklist")
                total_banned = c.fetchone()[0] or 0

                c.execute("SELECT COUNT(*) FROM events")
                total_events = c.fetchone()[0] or 0

                c.execute("SELECT COUNT(*) FROM port_access_logs")
                total_access = c.fetchone()[0] or 0

                # 严重级别分布
                c.execute("SELECT level, COUNT(*) as cnt FROM events GROUP BY level ORDER BY cnt DESC")
                level_rows = c.fetchall()
                level_summary = "".join([f"<li><strong>{r['level'] or '未知'}:</strong> {r['cnt']} 次</li>" for r in level_rows]) or "<li>暂无事件</li>"

                # Top 10 攻击源国家/地区
                c.execute("SELECT country, COUNT(*) as cnt FROM events WHERE country != '' GROUP BY country ORDER BY cnt DESC LIMIT 10")
                country_rows = c.fetchall()
                country_table = "".join([f"<tr><td>{idx+1}</td><td>{r['country']}</td><td>{r['cnt']}</td></tr>" for idx, r in enumerate(country_rows)]) or "<tr><td colspan='3'>暂无数据</td></tr>"

                # Top 10 被攻击端口
                c.execute("SELECT port, port_name, COUNT(*) as cnt FROM events GROUP BY port ORDER BY cnt DESC LIMIT 10")
                port_rows = c.fetchall()
                port_table = "".join([f"<tr><td>{r['port']}</td><td>{r['port_name']}</td><td>{r['cnt']}</td></tr>" for r in port_rows]) or "<tr><td colspan='3'>暂无数据</td></tr>"

                # 最近 20 条阻断记录
                c.execute("SELECT ip, reason, country, level, ban_time FROM blacklist ORDER BY timestamp DESC LIMIT 20")
                ban_rows = c.fetchall()
                ban_table = "".join([f"<tr><td><code>{r['ip']}</code></td><td>{r['level']}</td><td>{r['country']}</td><td>{r['reason']}</td><td>{r['ban_time']}</td></tr>" for r in ban_rows]) or "<tr><td colspan='5'>暂无封禁</td></tr>"

                conn.close()

                tpl = load_report_template()
                if tpl:
                    report_html = tpl.format(
                        report_date=now_str[:10],
                        node_name=cfg.get('node_name', '本机节点'),
                        now_str=now_str,
                        total_banned=total_banned,
                        total_events=total_events,
                        total_access=total_access,
                        trap_rules_count=len(cfg.get('trap_ports', [])),
                        level_summary=level_summary,
                        country_table=country_table,
                        port_table=port_table,
                        ban_table=ban_table
                    )
                else:
                    report_html = "<h1>PortGuard 审计报告模板缺失，请检查 templates/report.html</h1>"

                report_bytes = report_html.encode("utf-8")
                self.send_response(200)
                self.send_header('Content-Type', 'text/html; charset=utf-8')
                self.send_header('Content-Length', str(len(report_bytes)))
                self.send_header('Content-Disposition', f'attachment; filename="portguard_audit_report_{now_str[:10]}.html"')
                self.end_headers()
                self.wfile.write(report_bytes)
                return

            if path == "/api/analytics":
                query_params = parse_qs(parsed.query)
                range_param = query_params.get("range", ["7d"])[0]
                hourly_mode = query_params.get("hourly_mode", [""])[0]
                now_ts = int(time.time())
                now_dt = time.localtime(now_ts)
                today_str = time.strftime("%Y-%m-%d", now_dt)
                today_midnight = int(time.mktime(time.strptime(f"{today_str} 00:00:00", "%Y-%m-%d %H:%M:%S")))
                yesterday_dt = time.localtime(today_midnight - 3600)
                yesterday_str = time.strftime("%Y-%m-%d", yesterday_dt)
                yesterday_midnight = today_midnight - 86400
                current_hour = now_dt.tm_hour

                end_ts = now_ts

                if range_param == "today":
                    cutoff_ts = today_midnight
                    step_seconds = 3600
                    num_steps = 24
                    date_format = "%H:00"
                    date_badge = f"📅 {today_str} (今日)"
                    date_sub = f"统计范围：{today_str} 00:00 ~ {time.strftime('%H:%M', now_dt)} · 今日各时段安全态势"
                    date_display = today_str
                elif range_param == "yesterday":
                    cutoff_ts = yesterday_midnight
                    end_ts = today_midnight
                    step_seconds = 3600
                    num_steps = 24
                    date_format = "%H:00"
                    date_badge = f"📅 {yesterday_str} (昨日)"
                    date_sub = f"统计范围：{yesterday_str} 00:00 ~ 23:59 · 昨日全天安全态势"
                    date_display = yesterday_str
                elif range_param == "24h":
                    cutoff_ts = now_ts - 86400
                    step_seconds = 3600
                    num_steps = 24
                    date_format = "%H:00"
                    start_time_str = time.strftime("%Y-%m-%d %H:%M", time.localtime(cutoff_ts))
                    end_time_str = time.strftime("%Y-%m-%d %H:%M", now_dt)
                    date_badge = f"📅 {yesterday_str[5:]} ~ {today_str[5:]} (近24H)"
                    date_sub = f"统计范围：{start_time_str} ~ {end_time_str} (近 24 小时)"
                    date_display = f"{start_time_str[:10]} ~ {end_time_str[:10]}"
                elif range_param == "30d":
                    cutoff_ts = now_ts - 30 * 86400
                    step_seconds = 86400
                    num_steps = 30
                    date_format = "%m/%d"
                    start_time_str = time.strftime("%Y-%m-%d", time.localtime(cutoff_ts))
                    date_badge = f"📅 {start_time_str} ~ {today_str} (近30天)"
                    date_sub = f"统计范围：{start_time_str} ~ {today_str} · 近 30 天安全态势"
                    date_display = f"{start_time_str} ~ {today_str}"
                elif range_param == "all":
                    cutoff_ts = 0
                    step_seconds = 86400
                    num_steps = 30
                    date_format = "%m/%d"
                    date_badge = f"📅 历史全量数据 (截至 {today_str})"
                    date_sub = f"统计范围：历史全量记录累计 (截至 {today_str})"
                    date_display = f"历史全量 ~ {today_str}"
                else: # 7d
                    cutoff_ts = now_ts - 7 * 86400
                    step_seconds = 86400
                    num_steps = 7
                    date_format = "%m/%d"
                    start_time_str = time.strftime("%Y-%m-%d", time.localtime(cutoff_ts))
                    date_badge = f"📅 {start_time_str} ~ {today_str} (近7天)"
                    date_sub = f"统计范围：{start_time_str} ~ {today_str} · 近 7 天安全态势"
                    date_display = f"{start_time_str} ~ {today_str}"

                conn = get_db()
                c = conn.cursor()

                c.execute("SELECT COUNT(*) FROM port_access_logs WHERE timestamp >= ? AND timestamp < ? AND ip NOT IN (SELECT ip FROM hidden_ips)", (cutoff_ts, end_ts))
                total_probes = c.fetchone()[0]

                c.execute("SELECT COUNT(*) FROM events WHERE timestamp >= ? AND timestamp < ? AND ip NOT IN (SELECT ip FROM hidden_ips)", (cutoff_ts, end_ts))
                total_intercepted = c.fetchone()[0]

                c.execute("SELECT COUNT(DISTINCT ip) FROM events WHERE timestamp >= ? AND timestamp < ? AND ip NOT IN (SELECT ip FROM hidden_ips)", (cutoff_ts, end_ts))
                unique_attackers = c.fetchone()[0]

                c.execute("SELECT COUNT(DISTINCT country) FROM events WHERE timestamp >= ? AND timestamp < ? AND country NOT IN ('分析中...', '', '未知地域', 'Localhost', '本地回环') AND ip NOT IN (SELECT ip FROM hidden_ips)", (cutoff_ts, end_ts))
                unique_countries = c.fetchone()[0]

                c.execute("SELECT COUNT(*) FROM access_logs WHERE timestamp >= ? AND timestamp < ? AND ip NOT IN (SELECT ip FROM hidden_ips)", (cutoff_ts, end_ts))
                total_web_requests = c.fetchone()[0]

                c.execute("SELECT COUNT(*) FROM access_logs WHERE timestamp >= ? AND timestamp < ? AND (status_code >= 400 OR path LIKE '%.env%' OR path LIKE '%.git%' OR path LIKE '%php%' OR path LIKE '%admin%' OR path LIKE '%actuator%') AND ip NOT IN (SELECT ip FROM hidden_ips)", (cutoff_ts, end_ts))
                abnormal_web_requests = c.fetchone()[0]

                ban_rate = round((total_intercepted / total_probes * 100), 1) if total_probes > 0 else (100.0 if total_intercepted > 0 else 0.0)

                labels = []
                full_labels = []
                events_trend = []
                probes_trend = []
                web_trend = []
                for i in range(num_steps - 1, -1, -1):
                    s_ts = end_ts - ((i + 1) * step_seconds)
                    e_ts = end_ts - (i * step_seconds)
                    label = time.strftime(date_format, time.localtime(e_ts))
                    labels.append(label)
                    full_labels.append(time.strftime("%Y-%m-%d %H:%M" if step_seconds < 86400 else "%Y-%m-%d", time.localtime(e_ts)))

                    c.execute("SELECT COUNT(*) FROM events WHERE timestamp >= ? AND timestamp < ? AND ip NOT IN (SELECT ip FROM hidden_ips)", (s_ts, e_ts))
                    events_trend.append(c.fetchone()[0])

                    c.execute("SELECT COUNT(*) FROM port_access_logs WHERE timestamp >= ? AND timestamp < ? AND ip NOT IN (SELECT ip FROM hidden_ips)", (s_ts, e_ts))
                    probes_trend.append(c.fetchone()[0])

                    c.execute("SELECT COUNT(*) FROM access_logs WHERE timestamp >= ? AND timestamp < ? AND ip NOT IN (SELECT ip FROM hidden_ips)", (s_ts, e_ts))
                    web_trend.append(c.fetchone()[0])

                if hourly_mode == "today":
                    h_cutoff = today_midnight
                    h_end = now_ts
                    h_badge = f"📅 {today_str} (今日)"
                    h_sub = f"统计时段：{today_str} 00:00 ~ {time.strftime('%H:%M', now_dt)} · 今日各时段分布"
                elif hourly_mode == "yesterday":
                    h_cutoff = yesterday_midnight
                    h_end = today_midnight
                    h_badge = f"📅 {yesterday_str} (昨日)"
                    h_sub = f"统计时段：{yesterday_str} 00:00 ~ 23:59 · 昨日全天各时段分布"
                elif hourly_mode == "24h" or (not hourly_mode and range_param == "24h"):
                    h_cutoff = now_ts - 86400
                    h_end = now_ts
                    h_badge = f"📅 {yesterday_str[5:]} ~ {today_str[5:]} (近24H)"
                    start_hm_str = time.strftime("%Y-%m-%d %H:%M", time.localtime(h_cutoff))
                    end_hm_str = time.strftime("%Y-%m-%d %H:%M", now_dt)
                    h_sub = f"统计范围：{start_hm_str} ~ {end_hm_str} (深红: 今日 / 橙色: 昨日)"
                else:
                    h_cutoff = cutoff_ts
                    h_end = end_ts
                    h_badge = date_badge
                    h_sub = f"按每日 00:00~23:00 统计各时段累计分布 ({date_display})"

                c.execute("SELECT strftime('%H', datetime(timestamp, 'unixepoch', 'localtime')) AS hr, COUNT(*) as cnt FROM events WHERE timestamp >= ? AND timestamp < ? AND ip NOT IN (SELECT ip FROM hidden_ips) GROUP BY hr ORDER BY hr ASC", (h_cutoff, h_end))
                hourly_map = {row[0]: row[1] for row in c.fetchall() if row[0] is not None}

                effective_hourly_mode = hourly_mode or ("24h" if range_param == "24h" else range_param)
                hourly_dist = []
                for h in range(24):
                    cnt = hourly_map.get(f"{h:02d}", 0)
                    is_yesterday = False
                    if effective_hourly_mode == "24h":
                        is_yesterday = (h > current_hour)
                        item_date = yesterday_str if is_yesterday else today_str
                        day_tag = "昨日" if is_yesterday else "今日"
                    elif effective_hourly_mode == "yesterday":
                        item_date = yesterday_str
                        day_tag = "昨日"
                    elif effective_hourly_mode == "today":
                        item_date = today_str
                        day_tag = "今日"
                    else:
                        item_date = date_display
                        day_tag = "全周期"

                    hourly_dist.append({
                        "hour": f"{h:02d}:00",
                        "count": cnt,
                        "date": item_date,
                        "day_tag": day_tag,
                        "is_yesterday": is_yesterday,
                        "full_label": f"{item_date} {h:02d}:00 ({day_tag})" if day_tag in ("今日", "昨日") else f"{h:02d}:00 ({day_tag}累计)"
                    })

                c.execute("SELECT country, COUNT(*) as cnt FROM events WHERE timestamp >= ? AND timestamp < ? AND country NOT IN ('分析中...', '', '未知地域', 'Localhost', '本地回环') AND ip NOT IN (SELECT ip FROM hidden_ips) GROUP BY country ORDER BY cnt DESC LIMIT 8", (cutoff_ts, end_ts))
                geo_countries = [{"country": row[0], "count": row[1]} for row in c.fetchall()]

                c.execute("SELECT isp, COUNT(*) as cnt FROM events WHERE timestamp >= ? AND timestamp < ? AND isp NOT IN ('分析中...', '', 'Private LAN', 'Localhost', '未知') AND ip NOT IN (SELECT ip FROM hidden_ips) GROUP BY isp ORDER BY cnt DESC LIMIT 8", (cutoff_ts, end_ts))
                geo_isps = [{"isp": row[0], "count": row[1]} for row in c.fetchall()]

                c.execute("SELECT category, COUNT(*) as cnt FROM events WHERE timestamp >= ? AND timestamp < ? AND ip NOT IN (SELECT ip FROM hidden_ips) GROUP BY category ORDER BY cnt DESC", (cutoff_ts, end_ts))
                category_dist = [{"category": row[0], "count": row[1]} for row in c.fetchall()]

                c.execute("SELECT port, port_name, COUNT(*) as cnt FROM events WHERE timestamp >= ? AND timestamp < ? AND ip NOT IN (SELECT ip FROM hidden_ips) GROUP BY port ORDER BY cnt DESC LIMIT 8", (cutoff_ts, end_ts))
                port_dist = [{"port": row[0], "name": row[1] or f"端口 {row[0]}", "count": row[2]} for row in c.fetchall()]

                c.execute("SELECT action, COUNT(*) as cnt FROM port_access_logs WHERE timestamp >= ? AND timestamp < ? AND ip NOT IN (SELECT ip FROM hidden_ips) GROUP BY action ORDER BY cnt DESC", (cutoff_ts, end_ts))
                action_dist = [{"action": row[0], "count": row[1]} for row in c.fetchall()]

                c.execute("SELECT level, COUNT(*) as cnt FROM events WHERE timestamp >= ? AND timestamp < ? AND ip NOT IN (SELECT ip FROM hidden_ips) GROUP BY level ORDER BY cnt DESC", (cutoff_ts, end_ts))
                level_dist = [{"level": row[0], "count": row[1]} for row in c.fetchall()]

                c.execute("SELECT status_code, COUNT(*) as cnt FROM access_logs WHERE timestamp >= ? AND timestamp < ? AND ip NOT IN (SELECT ip FROM hidden_ips) GROUP BY status_code ORDER BY cnt DESC", (cutoff_ts, end_ts))
                http_status_dist = [{"code": str(row[0]), "count": row[1]} for row in c.fetchall()]

                c.execute("""
                    SELECT path, method, COUNT(*) as cnt 
                    FROM access_logs 
                    WHERE timestamp >= ? AND timestamp < ? AND ip NOT IN (SELECT ip FROM hidden_ips)
                    GROUP BY path 
                    ORDER BY 
                        (CASE WHEN status_code >= 400 OR path LIKE '%.env%' OR path LIKE '%.git%' OR path LIKE '%php%' OR path LIKE '%admin%' OR path LIKE '%actuator%' OR path LIKE '%api%' OR path LIKE '%.sql%' OR path LIKE '%swagger%' OR path LIKE '%shell%' THEN 1 ELSE 0 END) DESC,
                        cnt DESC 
                    LIMIT 10
                """, (cutoff_ts, end_ts))
                top_paths = [{"path": str(row[0] or "/"), "method": str(row[1] or "GET"), "count": int(row[2] or 0)} for row in c.fetchall()]

                # 扫描器与自动化工具指纹定义表：(关键词, 标签, 是否恶意扫描器, 显示名称)
                SCANNER_PATTERNS = [
                    ("sqlmap", "🔥 漏洞扫描器", True, "SQLMap 注入利用工具"),
                    ("nmap", "🔥 漏洞扫描器", True, "Nmap 网络映射扫描器"),
                    ("nikto", "🔥 漏洞扫描器", True, "Nikto Web漏洞扫描器"),
                    ("nuclei", "🔥 漏洞扫描器", True, "Nuclei 快速漏洞扫描器"),
                    ("fscan", "🔥 漏洞扫描器", True, "Fscan 内网综合扫描器"),
                    ("acunetix", "🔥 漏洞扫描器", True, "AWVS 漏洞扫描器"),
                    ("awvs", "🔥 漏洞扫描器", True, "AWVS 漏洞扫描器"),
                    ("nessus", "🔥 漏洞扫描器", True, "Nessus 脆弱性评估器"),
                    ("dirsearch", "🔥 路径爆破", True, "Dirsearch 敏感路径扫描"),
                    ("gobuster", "🔥 路径爆破", True, "Gobuster 目录枚举工具"),
                    ("ffuf", "🔥 路径爆破", True, "FFUF 快速模糊测试器"),
                    ("hydra", "🔥 弱口令爆破", True, "Hydra 自动化爆破工具"),
                    ("wpscan", "🔥 探针扫描", True, "WPScan WordPress扫描器"),
                    ("masscan", "📡 高速扫描", True, "Masscan 端口扫描器"),
                    ("zgrab", "📡 资产测绘", True, "ZGrab 测绘握手工具"),
                    ("censys", "📡 资产测绘", True, "Censys 测绘探测器"),
                    ("shodan", "📡 资产测绘", True, "Shodan 空间测绘爬虫"),
                    ("zoomeye", "📡 资产测绘", True, "ZoomEye 空间指纹探测"),
                    ("netcraft", "📡 资产测绘", True, "Netcraft 探测探针"),
                    ("infrawatch", "📡 资产测绘", True, "Infrawatch 基础探针"),
                    ("httpx", "⚡ 探测脚本", True, "HTTPX 快速探测工具"),
                    ("whatweb", "⚡ 指纹识别", True, "WhatWeb 技术栈识别器"),
                    ("libredtail", "⚡ 恶意脚本", True, "Redtail 恶意攻击脚本"),
                    ("python", "⚡ 脚本工具", False, "Python 自动化脚本"),
                    ("requests", "⚡ 脚本工具", False, "Python Requests 探测库"),
                    ("urllib", "⚡ 脚本工具", False, "Python Urllib 探测库"),
                    ("aiohttp", "⚡ 脚本工具", False, "Python Aiohttp 异步请求"),
                    ("go-http", "⚡ 脚本工具", False, "Go HTTP 自动化客户端"),
                    ("curl", "⚡ 命令行工具", False, "cURL 命令行请求"),
                    ("wget", "⚡ 命令行工具", False, "Wget 命令行下载器"),
                    ("java", "⚡ 脚本工具", False, "Java 自动化探测客户端"),
                    ("oai-searchbot", "🕷️ 搜索引擎爬虫", False, "OpenAI SearchBot 搜索引擎"),
                    ("gptbot", "🕷️ AI 训练爬虫", False, "OpenAI GPTBot 语料抓取"),
                    ("bytespider", "🕷️ 商业爬虫", False, "ByteSpider 字节跳动爬虫"),
                    ("googlebot", "🕷️ 商业爬虫", False, "Googlebot 谷歌索引爬虫"),
                    ("bingbot", "🕷️ 商业爬虫", False, "Bingbot 必应搜索爬虫"),
                    ("baiduspider", "🕷️ 商业爬虫", False, "BaiduSpider 百度索引爬虫"),
                    ("yandex", "🕷️ 商业爬虫", False, "Yandex 搜索引擎爬虫"),
                    ("bot", "🕷️ 爬虫/索引器", False, "网络自动化 Bot"),
                    ("crawler", "🕷️ 爬虫/索引器", False, "网络爬虫程序"),
                    ("spider", "🕷️ 爬虫/索引器", False, "网络蜘蛛爬虫"),
                    ("probe", "📡 测绘与探测", False, "网络探针程序"),
                    ("scan", "📡 测绘与探测", False, "自动化扫描程序"),
                ]

                COMMON_BROWSER_TOKENS = ["mozilla/5.0", "applewebkit", "safari", "chrome", "edge", "firefox"]

                c.execute("""
                    SELECT user_agent, COUNT(*) as cnt 
                    FROM access_logs 
                    WHERE timestamp >= ? AND timestamp < ?
                      AND user_agent IS NOT NULL 
                      AND TRIM(user_agent) NOT IN ('', '-', 'null', 'None', 'undefined')
                    GROUP BY user_agent 
                    ORDER BY cnt DESC 
                    LIMIT 300
                """, (cutoff_ts, end_ts))
                raw_ua_rows = c.fetchall()

                top_uas = []
                for r in raw_ua_rows:
                    ua_str = str(r[0] or "").strip()
                    cnt = int(r[1] or 0)
                    ua_lower = ua_str.lower()

                    matched = None
                    for key, tag, is_scanner, name in SCANNER_PATTERNS:
                        if key in ua_lower:
                            matched = (tag, is_scanner, name)
                            break

                    if matched:
                        tag, is_scanner, name = matched
                        top_uas.append({
                            "ua": ua_str,
                            "display_name": name,
                            "count": cnt,
                            "tag": tag,
                            "is_scanner": is_scanner
                        })
                    else:
                        is_normal_browser = any(b in ua_lower for b in COMMON_BROWSER_TOKENS)
                        if not is_normal_browser and len(ua_str) < 80:
                            top_uas.append({
                                "ua": ua_str,
                                "display_name": ua_str,
                                "count": cnt,
                                "tag": "🤖 自定义探针",
                                "is_scanner": False
                            })

                    if len(top_uas) >= 10:
                        break

                c.execute("""
                    SELECT ip, country, isp, level, COUNT(*) as hits, MAX(attack_time) as last_seen, GROUP_CONCAT(DISTINCT port) as ports 
                    FROM events 
                    WHERE timestamp >= ? AND timestamp < ? AND ip NOT IN (SELECT ip FROM hidden_ips)
                    GROUP BY ip 
                    ORDER BY hits DESC 
                    LIMIT 10
                """, (cutoff_ts, end_ts))
                attacker_rows = c.fetchall()

                c.execute("SELECT DISTINCT ip FROM blacklist WHERE ip NOT IN (SELECT ip FROM hidden_ips)")
                banned_ips_set = set(r[0] for r in c.fetchall())

                top_attackers = []
                for row in attacker_rows:
                    att_ip = row[0]
                    geo = _GEO_CACHE.get(att_ip) or resolve_ip_geo_local(att_ip) or {}
                    raw_country = (row[1] or "").strip()
                    raw_isp = (row[2] or "").strip()

                    final_country = (geo.get("country") if geo and geo.get("country") not in ("分析中...", "未知地域", "公网节点", "", "None", None) else None) or (raw_country if raw_country not in ("分析中...", "未知地域", "公网节点", "", "None", None) else None) or (geo.get("country") if geo else None) or "公网节点"
                    final_isp = (geo.get("isp") if geo and geo.get("isp") not in ("分析中...", "", "0", "None", "未知", None) else None) or (raw_isp if raw_isp not in ("分析中...", "", "0", "None", "未知", None) else None) or ""

                    top_attackers.append({
                        "ip": att_ip,
                        "country": final_country,
                        "isp": final_isp,
                        "level": row[3] or "极高危",
                        "hit_count": row[4],
                        "last_seen": row[5] or "--",
                        "ports": row[6] or "--",
                        "is_banned": att_ip in banned_ips_set
                    })

                conn.close()

                self._send_json({
                    "range": range_param,
                    "date_info": {
                        "start_time": time.strftime("%Y-%m-%d %H:%M", time.localtime(cutoff_ts)),
                        "end_time": time.strftime("%Y-%m-%d %H:%M", time.localtime(end_ts)),
                        "date_badge": date_badge,
                        "date_sub": date_sub,
                        "date_display": date_display,
                        "today": today_str,
                        "yesterday": yesterday_str,
                        "current_hour": current_hour,
                        "hourly_badge": h_badge,
                        "hourly_sub": h_sub,
                        "hourly_mode": effective_hourly_mode
                    },
                    "kpis": {
                        "total_probes": total_probes,
                        "total_intercepted": total_intercepted,
                        "unique_attackers": unique_attackers,
                        "unique_countries": unique_countries,
                        "total_web_requests": total_web_requests,
                        "abnormal_web_requests": abnormal_web_requests,
                        "ban_rate": ban_rate
                    },
                    "trend": {
                        "labels": labels,
                        "full_labels": full_labels,
                        "events": events_trend,
                        "probes": probes_trend,
                        "web": web_trend
                    },
                    "hourly_distribution": hourly_dist,
                    "geo_countries": geo_countries,
                    "geo_isps": geo_isps,
                    "category_distribution": category_dist,
                    "port_distribution": port_dist,
                    "action_distribution": action_dist,
                    "threat_level_distribution": level_dist,
                    "http_status_distribution": http_status_dist,
                    "top_sensitive_paths": top_paths,
                    "top_user_agents": top_uas,
                    "top_attackers": top_attackers
                })
                return
            if path == "/api/settings":
                cfg = load_config()
                self._send_json({
                    "trap_threshold": int(cfg.get("trap_threshold", 2) or 2),
                    "trap_window_seconds": int(cfg.get("trap_window_seconds", 30) or 30),
                    "auto_clean_days": int(cfg.get("auto_clean_days", 30) if cfg.get("auto_clean_days") is not None else 30),
                    "defense_mode": cfg.get("defense_mode", "standard"),
                    "enable_port_scan_defense": bool(cfg.get("enable_port_scan_defense", True)),
                    "port_scan_threshold": int(cfg.get("port_scan_threshold", 1) or 1),
                    "port_scan_window_seconds": int(cfg.get("port_scan_window_seconds", 15) or 15),
                    "trap_all_ports": bool(cfg.get("trap_all_ports", False)),
                    "trap_all_unopened_ports": bool(cfg.get("trap_all_unopened_ports", False)),
                    "trap_business_ports": bool(cfg.get("trap_business_ports", False)),
                    "ban_action_iptables": bool(cfg.get("ban_action_iptables", True)),
                    "ban_action_blackhole": bool(cfg.get("ban_action_blackhole", True)),
                    "enable_tarpit_delay": bool(cfg.get("enable_tarpit_delay", False)),
                    "dynamic_honeypot_ports": bool(cfg.get("dynamic_honeypot_ports", True)),
                    "defense_paused": bool(cfg.get("defense_paused", False)),
                    "node_name": str(cfg.get("node_name", "本机节点") or "本机节点"),
                    "cluster_sync": cfg.get("cluster_sync", {
                        "enabled": False,
                        "cluster_secret": "",
                        "cluster_nodes": []
                    }),
                    "web_port": int(cfg.get("web_port", 9099) or 9099)
                })
                return

            if path == "/api/config/snapshots":
                snaps = get_config_snapshots()
                self._send_json(snaps)
                return

            if path == "/api/config/backup":
                # 导出完整配置文件备份
                cfg_str = json.dumps(load_config(), indent=2, ensure_ascii=False).encode('utf-8')
                self.send_response(200)
                self.send_header('Content-Type', 'application/json; charset=utf-8')
                self.send_header('Content-Length', str(len(cfg_str)))
                self.send_header('Content-Disposition', f'attachment; filename="portguard_config_backup_{int(time.time())}.json"')
                self.end_headers()
                self.wfile.write(cfg_str)
                return

            if path == "/api/compromise/check":
                # C2 反向连线失陷检测
                alerts = check_c2_compromise_connections()
                self._send_json({
                    "status": "safe" if not alerts else "warning",
                    "compromised_alerts": alerts,
                    "check_time": time.strftime("%Y-%m-%d %H:%M:%S")
                })
                return

            if path == "/api/cluster/nodes":
                cfg = load_config()
                cluster_cfg = cfg.get("cluster_sync", {})
                nodes = cluster_cfg.get("cluster_nodes", [])
                norm_nodes = []
                for raw in nodes:
                    n = normalize_cluster_node(raw)
                    if n and n.get("ip"):
                        if not n.get("country") or n.get("country") in ("分析中...", ""):
                            geo = resolve_ip_geo(n["ip"])
                            n["country"] = f"{geo.get('country', '')} {geo.get('city', '')}".strip() or "公网节点"
                        norm_nodes.append(n)
                self._send_json({
                    "enabled": bool(cluster_cfg.get("enabled", False)),
                    "port": int(cluster_cfg.get("port", 9098) or 9098),
                    "cluster_secret": cluster_cfg.get("cluster_secret", ""),
                    "nodes": norm_nodes
                })
                return

            if path in ("/api/hidden-ips", "/api/hidden_ips", "/api/hidden-ips/export", "/api/hidden_ips/export"):
                hidden_list = get_hidden_ips()
                self._send_json(hidden_list)
                return

            if path == "/api/events":
                conn = get_db()
                c = conn.cursor()
                c.execute("""
                    SELECT e.id, e.ip, e.port, e.proto, e.port_name, e.category, e.level, e.country, e.region, e.city, e.isp, e.attack_time, e.status,
                           (SELECT a.user_agent FROM access_logs a WHERE a.ip = e.ip AND a.user_agent IS NOT NULL AND TRIM(a.user_agent) NOT IN ('', '-', 'null', 'None') ORDER BY a.id DESC LIMIT 1) as user_agent
                    FROM events e 
                    WHERE e.ip NOT IN (SELECT ip FROM hidden_ips)
                    ORDER BY e.id DESC 
                    LIMIT 200
                """)
                rows = [dict(r) for r in c.fetchall()]
                conn.close()
                for r in rows:
                    raw_c = (r.get("country") or "").strip()
                    if not raw_c or raw_c in ("分析中...", "未知地域", "None", "null"):
                        geo = _GEO_CACHE.get(r["ip"]) or resolve_ip_geo_local(r["ip"])
                        if geo and geo.get("country") and geo.get("country") not in ("分析中...", "未知地域", "", None):
                            r["country"] = geo.get("country")
                            r["region"] = geo.get("region", "")
                            r["city"] = geo.get("city", "")
                            r["isp"] = geo.get("isp", "")
                        else:
                            r["country"] = "公网节点"
                            _EXECUTOR.submit(resolve_ip_geo, r["ip"])
                    # 动态植入威胁信誉指纹标签
                    r["threat_tags"] = get_ip_threat_tags(r["ip"], r)
                self._send_json(rows)
                return

            if path == "/api/attacker/timeline":
                # 攻击者全景画像与足迹时间线档案 API
                query = parse_qs(parsed.query)
                att_ip = query.get("ip", [""])[0].strip()
                if not att_ip:
                    self._send_json({"error": "缺少 IP 参数"}, status=400)
                    return
                conn = get_db()
                c = conn.cursor()
                # 1. 查找历史拦截事件时间线
                c.execute("""
                    SELECT id, port, proto, port_name, category, level, attack_time, timestamp, status
                    FROM events WHERE ip = ? ORDER BY timestamp DESC LIMIT 100
                """, (att_ip,))
                events_list = [dict(r) for r in c.fetchall()]

                # 2. 查找黑名单阻断记录
                c.execute("SELECT ip, reason, country, level, ban_time, timestamp, ban_expire, source_node FROM blacklist WHERE ip = ?", (att_ip,))
                ban_record = c.fetchone()
                ban_dict = dict(ban_record) if ban_record else None

                # 3. 统计总探测次数及首见/末见时间
                c.execute("SELECT COUNT(*), MIN(timestamp), MAX(timestamp) FROM events WHERE ip = ?", (att_ip,))
                ev_stats = c.fetchone()
                total_events = ev_stats[0] if ev_stats and ev_stats[0] else 0

                c.execute("SELECT COUNT(*), MIN(timestamp), MAX(timestamp) FROM port_access_logs WHERE ip = ?", (att_ip,))
                pal_stats = c.fetchone()
                total_pal = pal_stats[0] if pal_stats and pal_stats[0] else 0

                total_probes = max(total_events, total_pal, len(events_list))

                min_ts = None
                max_ts = None
                if ev_stats and ev_stats[1]:
                    min_ts = ev_stats[1]
                if pal_stats and pal_stats[1]:
                    min_ts = min(min_ts, pal_stats[1]) if min_ts else pal_stats[1]

                if ev_stats and ev_stats[2]:
                    max_ts = ev_stats[2]
                if pal_stats and pal_stats[2]:
                    max_ts = max(max_ts, pal_stats[2]) if max_ts else pal_stats[2]

                first_seen = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(min_ts)) if min_ts else "--"
                last_seen = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(max_ts)) if max_ts else "--"

                # 4. 查找所有端口访问探测足迹 (distinct ports)
                c.execute("SELECT DISTINCT port, port_name, action FROM port_access_logs WHERE ip = ? ORDER BY id DESC", (att_ip,))
                footprints = [dict(r) for r in c.fetchall()]

                c.execute("SELECT DISTINCT port FROM events WHERE ip = ? AND port IS NOT NULL", (att_ip,))
                ports_ev = [r[0] for r in c.fetchall() if r[0]]
                ports_pal = [f["port"] for f in footprints if f.get("port")]
                ports_hit = sorted(list(set(ports_ev + ports_pal)))

                # 5. 提取捕获的恶意载荷与木马 URL
                extracted_payloads = []
                for ev in events_list:
                    pname = ev.get("port_name") or ""
                    if "[提取木马下载源:" in pname:
                        try:
                            m = re.search(r"\[提取木马下载源:\s*([^\]]+)\]", pname)
                            if m:
                                for u in m.group(1).split(","):
                                    u_c = u.strip()
                                    if u_c and u_c not in extracted_payloads:
                                        extracted_payloads.append(u_c)
                        except Exception:
                            pass
                    elif "[捕获载荷:" in pname:
                        try:
                            m = re.search(r"\[捕获载荷:\s*([^\]]+)\]", pname)
                            if m:
                                p_c = m.group(1).strip()
                                if p_c and p_c not in extracted_payloads:
                                    extracted_payloads.append(p_c)
                        except Exception:
                            pass

                # 6. 统计同 C 段 (/24) 活跃攻击威胁源
                c_subnet_ips = []
                try:
                    if "." in att_ip:
                        c_prefix = ".".join(att_ip.split(".")[:3]) + ".%"
                        c.execute("SELECT DISTINCT ip FROM events WHERE ip LIKE ? AND ip != ? LIMIT 10", (c_prefix, att_ip))
                        c_subnet_ips = [r[0] for r in c.fetchall()]
                except Exception:
                    pass

                conn.close()

                geo = _GEO_CACHE.get(att_ip) or resolve_ip_geo_local(att_ip) or {}
                threat_tags = get_ip_threat_tags(att_ip, geo)

                self._send_json({
                    "ip": att_ip,
                    "geo": geo,
                    "country": geo.get("country") or "公网节点",
                    "region": geo.get("region") or "",
                    "city": geo.get("city") or "",
                    "isp": geo.get("isp") or "",
                    "threat_tags": threat_tags,
                    "ban_record": ban_dict,
                    "is_banned": bool(ban_dict),
                    "total_probes": total_probes,
                    "ports_hit": ports_hit,
                    "first_seen": first_seen,
                    "last_seen": last_seen,
                    "extracted_payloads": extracted_payloads,
                    "event_count": total_probes,
                    "events": events_list,
                    "port_footprints": footprints,
                    "subnet_c_peers": c_subnet_ips,
                    "subnet_cidr": ".".join(att_ip.split(".")[:3]) + ".0/24" if "." in att_ip else att_ip
                })
                return

            if path == "/api/ip_info":
                query = parse_qs(parsed.query)
                ip = query.get("ip", [""])[0].strip()
                if not ip:
                    self._send_json({"country": "未知地域", "region": "", "city": "", "isp": "", "threat_tags": []})
                    return
                geo = resolve_ip_geo(ip)
                geo["threat_tags"] = get_ip_threat_tags(ip, geo)
                try:
                    conn = get_db()
                    c = conn.cursor()
                    c.execute("SELECT reason, ban_time FROM blacklist WHERE ip = ? LIMIT 1", (ip,))
                    b_row = c.fetchone()
                    conn.close()
                    if b_row:
                        geo["is_banned"] = True
                        geo["ban_reason"] = b_row["reason"] or ""
                    else:
                        geo["is_banned"] = False
                        geo["ban_reason"] = ""
                except Exception:
                    pass
                self._send_json(geo)
                return

            if path == "/api/blacklist":
                global _BLACKLIST_CACHE, _BLACKLIST_CACHE_TIME
                now_mono = time.monotonic()
                with _BLACKLIST_CACHE_LOCK:
                    if _BLACKLIST_CACHE is not None and (now_mono - _BLACKLIST_CACHE_TIME) < 5.0:
                        cached_data = _BLACKLIST_CACHE
                    else:
                        cached_data = None
                if cached_data is not None:
                    self._send_json(cached_data)
                    return

                conn = get_db()
                c = conn.cursor()
                c.execute("SELECT ip, reason, country, level, ban_time, timestamp, source_node FROM blacklist WHERE ip NOT IN (SELECT ip FROM hidden_ips) ORDER BY timestamp DESC")
                rows = [dict(r) for r in c.fetchall()]
                conn.close()
                for r in rows:
                    ip_k = r["ip"]
                    geo = _GEO_CACHE.get(ip_k) or resolve_ip_geo_local(ip_k) or {}
                    raw_country = (r.get("country") or "").strip()
                    if geo.get("country") and geo["country"] not in ("未知地域", "公网节点", "分析中...", "", "None", None):
                        r["country"] = geo["country"]
                        r["region"] = geo.get("region", "")
                        r["city"] = geo.get("city", "")
                        r["isp"] = geo.get("isp", "")
                    else:
                        if not raw_country or raw_country in ("分析中...", "未知地域", "公网节点", "", "None"):
                            r["country"] = geo.get("country") or "公网节点"
                            _EXECUTOR.submit(resolve_ip_geo, ip_k)
                        else:
                            r["country"] = raw_country
                        r["region"] = geo.get("region") or r.get("region", "")
                        r["city"] = geo.get("city") or r.get("city", "")
                        r["isp"] = geo.get("isp") or r.get("isp", "")
                    r["threat_tags"] = get_ip_threat_tags(ip_k, geo)
                with _BLACKLIST_CACHE_LOCK:
                    _BLACKLIST_CACHE = rows
                    _BLACKLIST_CACHE_TIME = now_mono
                self._send_json(rows)
                return

            if path == "/api/traps":
                cfg = load_config()
                raw_traps = cfg.get("trap_ports", DEFAULT_CONFIG["trap_ports"])
                normalized = []
                for item in raw_traps:
                    norm = normalize_trap_item(item)
                    if norm:
                        normalized.append(norm)
                self._send_json(normalized)
                return

            if path in ("/api/business_ports", "/api/business_ports/export"):
                biz_list = get_all_business_ports_info()
                self._send_json(biz_list)
                return

            if path in ("/api/http_traps", "/api/http_traps/export"):
                rules = get_http_traps()
                self._send_json(rules)
                return

            if path == "/api/traps/export":
                cfg = load_config()
                raw_traps = cfg.get("trap_ports", DEFAULT_CONFIG["trap_ports"])
                export_list = []
                for item in raw_traps:
                    norm = normalize_trap_item(item)
                    if norm:
                        export_list.append({
                            "family": norm.get("family", "ipv4"),
                            "address": norm.get("address", ""),
                            "port": str(norm.get("port")),
                            "protocol": norm.get("protocol", "tcp"),
                            "strategy": norm.get("strategy", "accept"),
                            "description": norm.get("description", norm.get("name", ""))
                        })
                self._send_json(export_list)
                return

            if path in ("/api/whitelist", "/api/whitelist/export"):
                cfg = load_config()
                raw_white = cfg.get("whitelist", DEFAULT_CONFIG["whitelist"])
                normalized = []
                for item in raw_white:
                    if isinstance(item, str):
                        item = {"ip": item, "remark": "信任IP"}
                    normalized.append(item)
                self._send_json(normalized)
                return

            if path in ("/api/blacklist/export",):
                conn = get_db()
                c = conn.cursor()
                c.execute("SELECT ip, reason, country, level, ban_time, timestamp FROM blacklist WHERE ip NOT IN (SELECT ip FROM hidden_ips) ORDER BY timestamp DESC")
                rows = [dict(r) for r in c.fetchall()]
                conn.close()
                self._send_json(rows)
                return

            if path == "/api/access_logs":
                query = parse_qs(parsed.query)
                log_type = query.get("type", ["port"])[0]
                try:
                    limit_cnt = min(int(query.get("limit", [500])[0]), 2000)
                except Exception:
                    limit_cnt = 500
                conn = get_db()
                c = conn.cursor()
                if log_type in ("web", "site"):
                    domain_filter = query.get("domain", [None])[0]
                    if domain_filter:
                        c.execute("SELECT id, ip, domain, method, path, status_code, user_agent, country, region, city, isp, access_time, timestamp FROM access_logs WHERE domain = ? AND ip NOT IN (SELECT ip FROM hidden_ips) ORDER BY id DESC LIMIT ?", (domain_filter, limit_cnt))
                    else:
                        c.execute("SELECT id, ip, domain, method, path, status_code, user_agent, country, region, city, isp, access_time, timestamp FROM access_logs WHERE ip NOT IN (SELECT ip FROM hidden_ips) ORDER BY id DESC LIMIT ?", (limit_cnt,))
                    rows = [dict(r) for r in c.fetchall()]
                    for r in rows:
                        if (not r.get("country") or r.get("country") == "分析中...") and r.get("ip") in _GEO_CACHE:
                            g = _GEO_CACHE[r["ip"]]
                            r["country"] = g.get("country", "")
                            r["region"] = g.get("region", "")
                            r["city"] = g.get("city", "")
                            r["isp"] = g.get("isp", "")
                else:
                    c.execute("SELECT id, ip, port, proto, port_name, country, region, city, isp, action, access_time, timestamp FROM port_access_logs WHERE ip NOT IN (SELECT ip FROM hidden_ips) ORDER BY id DESC LIMIT ?", (limit_cnt,))
                    rows = [dict(r) for r in c.fetchall()]
                    if not rows:
                        c.execute("SELECT id, ip, port, proto, port_name, country, region, city, isp, status as action, attack_time as access_time, timestamp FROM events WHERE ip NOT IN (SELECT ip FROM hidden_ips) ORDER BY id DESC LIMIT ?", (limit_cnt,))
                        rows = [dict(r) for r in c.fetchall()]
                    for r in rows:
                        if (not r.get("country") or r.get("country") == "分析中...") and r.get("ip") in _GEO_CACHE:
                            g = _GEO_CACHE[r["ip"]]
                            r["country"] = g.get("country", "")
                            r["region"] = g.get("region", "")
                            r["city"] = g.get("city", "")
                            r["isp"] = g.get("isp", "")
                conn.close()
                self._send_json(rows)
                return

            self._send_json({"error": "Not Found"}, status=404)
        except Exception as e:
            import traceback
            traceback.print_exc()
            try:
                self._send_json({"error": str(e)}, status=500)
            except Exception:
                pass

    def do_POST(self):
        try:
            parsed = urlparse(self.path)
            path = parsed.path

            length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(length).decode('utf-8') if length > 0 else "{}"
            try:
                req_data = json.loads(body)
            except Exception:
                req_data = {}

            if path == "/api/access_logs/clear":
                log_type = req_data.get("type", "port")
                conn = get_db()
                c = conn.cursor()
                if log_type == "web":
                    c.execute("DELETE FROM access_logs")
                else:
                    c.execute("DELETE FROM port_access_logs")
                conn.commit()
                conn.close()
                self._send_json({"success": True, "msg": f"{'Web控制台' if log_type == 'web' else '端口网络'}访问日志已全部清空"})
                return

            if path == "/api/unban":
                ip = req_data.get("ip", "").strip()
                if not ip:
                    self._send_json({"success": False, "msg": "IP 不能为空"}, status=400)
                    return
                valid_ip = validate_ip(ip)
                if not valid_ip:
                    self._send_json({"success": False, "msg": "IP 格式不合法"}, status=400)
                    return
                ip = valid_ip

                cfg = load_config()
                node_name = cfg.get("node_name", "本机") or "本机"
                unban_ip_core(ip, status_event="UNBANNED", source_node=f"手动解封({node_name})")
                # 广播解封至全网集群协同节点
                broadcast_cluster_unban(ip)
                invalidate_blacklist_cache()
                self._send_json({"success": True, "msg": f"已成功从内核黑名单与防火墙中解封 IP: {ip}（已同步全网集群协同解封）"})
                return

            if path == "/api/cluster/sync_unban":
                token = self.headers.get("X-Cluster-Token", "").strip()
                cfg = load_config()
                cluster_cfg = cfg.get("cluster_sync", {})
                secret = cluster_cfg.get("cluster_secret", "").strip()

                ip = req_data.get("ip", "").strip()
                if not verify_cluster_token(f"unban_{ip}", token, secret):
                    self._send_json({"success": False, "msg": "集群鉴权签名无效"}, status=403)
                    return

                valid_ip = validate_ip(ip)
                if not valid_ip:
                    self._send_json({"success": False, "msg": "IP格式不合法"}, status=400)
                    return
                source_node = req_data.get("source_node", "协同节点").strip()
                unban_ip_core(valid_ip, status_event="UNBANNED", source_node=f"集群解封({source_node})")
                self._send_json({"success": True, "msg": f"已协同解封: {valid_ip}"})
                return

            if path == "/api/cluster/sync_state_exchange":
                token = self.headers.get("X-Cluster-Token", "").strip()
                cfg = load_config()
                cluster_cfg = cfg.get("cluster_sync", {})
                secret = cluster_cfg.get("cluster_secret", "").strip()
                if not verify_cluster_token("sync_state_exchange", token, secret):
                    self._send_json({"success": False, "msg": "集群鉴权签名无效"}, status=403)
                    return

                source_node = req_data.get("source_node", "远程节点").strip()
                remote_bans = req_data.get("blacklist", [])
                remote_unbanned = req_data.get("unbanned_list", [])
                remote_whites = req_data.get("whitelist", [])

                conn = get_db()
                c = conn.cursor()
                c.execute("CREATE TABLE IF NOT EXISTS unbanned_ips (ip TEXT PRIMARY KEY, unban_time TEXT, timestamp INTEGER, source_node TEXT)")
                c.execute("SELECT ip, reason, country, level, ban_time, timestamp, ban_expire, source_node FROM blacklist")
                local_rows = c.fetchall()
                local_bans_map = { r[0]: { "ip": r[0], "reason": r[1], "country": r[2], "level": r[3], "ban_time": r[4], "timestamp": r[5], "ban_expire": r[6], "source_node": r[7] } for r in local_rows }
                c.execute("SELECT ip, unban_time, timestamp, source_node FROM unbanned_ips")
                local_unbanned_rows = c.fetchall()
                local_unbanned_map = { r[0]: int(r[2] or 0) for r in local_unbanned_rows if r[0] }

                # 1. 优先对齐远端发来的解封墓碑
                for ru in remote_unbanned:
                    ru_ip = validate_ip(ru.get("ip", ""))
                    ru_ts = int(ru.get("timestamp", 0) or 0)
                    if ru_ip:
                        if ru_ip in local_bans_map:
                            local_ban_ts = int(local_bans_map[ru_ip].get("timestamp", 0) or 0)
                            if ru_ts >= local_ban_ts:
                                unban_ip_core(ru_ip, status_event="UNBANNED", source_node=f"集群同步({source_node})")
                        local_unbanned_map[ru_ip] = ru_ts
                        c.execute("""
                        INSERT OR REPLACE INTO unbanned_ips (ip, unban_time, timestamp, source_node)
                        VALUES (?, ?, ?, ?)
                        """, (ru_ip, ru.get("unban_time", time.strftime("%Y-%m-%d %H:%M:%S")), ru_ts, f"集群同步({source_node})"))

                # 2. 吸纳对方有而本地没有的黑名单 (比对解封墓碑)
                added_bans = 0
                now_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
                now_ts = int(time.time())
                for rb in remote_bans:
                    rb_ip = validate_ip(rb.get("ip", ""))
                    if not rb_ip or ip_in_whitelist(rb_ip):
                        continue
                    rb_ts = int(rb.get("timestamp", 0) or 0)
                    local_unban_ts = local_unbanned_map.get(rb_ip)
                    if local_unban_ts is not None and local_unban_ts >= rb_ts:
                        continue

                    if rb_ip not in local_bans_map:
                        ban_ip_firewall(rb_ip)
                        src = rb.get("source_node", source_node)
                        geo_country = rb.get("country")
                        if not geo_country or geo_country in ("集群联防", "未知地域", "公网节点", ""):
                            geo = resolve_ip_geo(rb_ip) or {}
                            geo_country = geo.get("country") or "公网探测"

                        c.execute("""
                        INSERT OR REPLACE INTO blacklist (ip, reason, country, level, ban_time, timestamp, ban_expire, source_node)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                        """, (
                            rb_ip, rb.get("reason", f"[{source_node}对齐] 威胁同步"), geo_country,
                            rb.get("level", "极高危"), rb.get("ban_time", now_str),
                            rb.get("timestamp", rb_ts or now_ts), rb.get("ban_expire"), f"集群 ({src})"
                        ))
                        c.execute("DELETE FROM unbanned_ips WHERE ip = ?", (rb_ip,))
                        _EXECUTOR.submit(resolve_ip_geo, rb_ip)
                        added_bans += 1
                conn.commit()
                conn.close()

                # 3. 合并白名单
                whitelist = cfg.get("whitelist", [])
                w_map = { (w.get("ip") if isinstance(w, dict) else w): (w if isinstance(w, dict) else {"ip": w, "remark": "信任IP"}) for w in whitelist }
                added_whites = 0
                for rw in remote_whites:
                    rw_ip = validate_ip(rw.get("ip") if isinstance(rw, dict) else rw)
                    if not rw_ip:
                        continue
                    unban_ip_core(rw_ip, status_event="WHITELIST")
                    rw_rem = rw.get("remark", "集群对齐白名单") if isinstance(rw, dict) else "集群对齐白名单"
                    if rw_ip not in w_map:
                        w_map[rw_ip] = {"ip": rw_ip, "remark": rw_rem}
                        added_whites += 1
                cfg["whitelist"] = list(w_map.values())
                save_config(cfg)

                # 返回本地独有的黑名单、解封墓碑与白名单给发起端
                remote_ban_ips = { rb.get("ip") for rb in remote_bans if rb.get("ip") }
                missing_for_remote_bans = [ b for ip_k, b in local_bans_map.items() if ip_k not in remote_ban_ips and ip_k not in local_unbanned_map ]

                remote_white_ips = { (w.get("ip") if isinstance(w, dict) else w) for w in remote_whites if (w.get("ip") if isinstance(w, dict) else w) }
                missing_for_remote_whites = [ w for ip_k, w in w_map.items() if ip_k not in remote_white_ips ]

                # 本地解封墓碑数据
                local_unbanned_resp = [
                    { "ip": r[0], "unban_time": r[1], "timestamp": r[2], "source_node": r[3] }
                    for r in local_unbanned_rows if r[0]
                ]

                self._send_json({
                    "success": True,
                    "added_bans": added_bans,
                    "added_whites": added_whites,
                    "remote_blacklist": missing_for_remote_bans,
                    "remote_unbanned": local_unbanned_resp,
                    "remote_whitelist": missing_for_remote_whites
                })
                return

            if path in ("/api/cluster/sync_all_mesh", "/api/cluster/sync_all_blacklist"):
                res = sync_cluster_mesh_state()
                self._send_json(res)
                return

            if path == "/api/cluster/sync_ban":
                token = self.headers.get("X-Cluster-Token", "").strip()
                cfg = load_config()
                cluster_cfg = cfg.get("cluster_sync", {})
                secret = cluster_cfg.get("cluster_secret", "").strip()

                ip = req_data.get("ip", "").strip()
                reason = req_data.get("reason", "集群威胁同步").strip()
                level = req_data.get("level", "极高危").strip()
                source_node = req_data.get("source_node", "远程探针").strip()

                if not verify_cluster_token(ip, token, secret):
                    self._send_json({"success": False, "msg": "集群鉴权签名无效"}, status=403)
                    return

                valid_ip = validate_ip(ip)
                if not valid_ip:
                    self._send_json({"success": False, "msg": "IP格式不合法"}, status=400)
                    return
                ip = valid_ip

                if ip_in_whitelist(ip):
                    self._send_json({"success": True, "msg": "本地白名单已忽略"})
                    return

                ban_ip_firewall(ip)
                now_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
                now_ts = int(time.time())
                auto_clean_days = int(cfg.get("auto_clean_days", 30) or 30)
                ban_expire = now_ts + auto_clean_days * 86400 if auto_clean_days > 0 else None

                geo_country = req_data.get("country") or ""
                geo_region = req_data.get("region") or ""
                geo_city = req_data.get("city") or ""
                geo_isp = req_data.get("isp") or ""

                if not geo_country or geo_country in ("集群联防", "公网节点", "未知地域", ""):
                    geo = resolve_ip_geo(ip) or {}
                    geo_country = geo.get("country") or "公网探测"
                    geo_region = geo.get("region") or ""
                    geo_city = geo.get("city") or ""
                    geo_isp = geo.get("isp") or ""

                synced_port = int(req_data.get("port") or 443)
                synced_proto = str(req_data.get("proto") or "TCP").upper()
                synced_category = req_data.get("category") or "mesh"

                conn = get_db()
                c = conn.cursor()
                c.execute("""
                INSERT OR REPLACE INTO blacklist (ip, reason, country, level, ban_time, timestamp, ban_expire, source_node)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (ip, f"[{source_node}联防] {reason}", geo_country, level, now_str, now_ts, ban_expire, f"集群 ({source_node})"))
                c.execute("""
                INSERT INTO events (ip, port, proto, port_name, category, level, country, region, city, isp, attack_time, timestamp, status)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'BANNED')
                """, (ip, synced_port, synced_proto, f"[{source_node}联防] {reason}", synced_category, level, geo_country, geo_region, geo_city, geo_isp, now_str, now_ts))
                conn.commit()
                conn.close()

                _EXECUTOR.submit(resolve_ip_geo, ip)
                self._send_json({"success": True, "msg": f"已完成集群同步封禁: {ip}"})
                return

            if path == "/api/cluster/sync_whitelist":
                token = self.headers.get("X-Cluster-Token", "").strip()
                cfg = load_config()
                cluster_cfg = cfg.get("cluster_sync", {})
                secret = cluster_cfg.get("cluster_secret", "").strip()

                action = req_data.get("action", "add").strip()
                data = req_data.get("data")
                remark = req_data.get("remark", "集群协同白名单").strip()
                source_node = req_data.get("source_node", "远程节点").strip()

                sign_target = f"whitelist_{action}"
                if not verify_cluster_token(sign_target, token, secret):
                    self._send_json({"success": False, "msg": "集群鉴权签名无效"}, status=403)
                    return

                whitelist = cfg.get("whitelist", [])

                if action == "add":
                    ip = str(data or "").strip()
                    valid_ip = validate_ip(ip)
                    if not valid_ip:
                        self._send_json({"success": False, "msg": "IP 格式不合法"}, status=400)
                        return
                    ip = valid_ip
                    unban_ip_core(ip, status_event="WHITELIST")
                    if not any(w.get("ip") == ip if isinstance(w, dict) else w == ip for w in whitelist):
                        node_remark = f"[{source_node}联防] {remark}" if not str(remark).startswith(f"[{source_node}") else remark
                        whitelist.append({"ip": ip, "remark": node_remark})
                        cfg["whitelist"] = whitelist
                        save_config(cfg)
                    self._send_json({"success": True, "msg": f"已成功同步添加白名单: {ip}"})
                    return

                elif action == "delete":
                    ip = str(data or "").strip()
                    whitelist = [w for w in whitelist if (w.get("ip") if isinstance(w, dict) else w) != ip]
                    cfg["whitelist"] = whitelist
                    save_config(cfg)
                    self._send_json({"success": True, "msg": f"已成功同步移除白名单: {ip}"})
                    return

                elif action in ("batch_add", "sync_all"):
                    items = data if isinstance(data, list) else []
                    updated_cnt = 0
                    current_map = {}
                    for w in whitelist:
                        w_ip = w.get("ip") if isinstance(w, dict) else w
                        if w_ip:
                            current_map[w_ip] = w if isinstance(w, dict) else {"ip": w_ip, "remark": "信任IP"}

                    for it in items:
                        if isinstance(it, dict):
                            it_ip = str(it.get("ip", "")).strip()
                            it_rem = str(it.get("remark", remark)).strip()
                        else:
                            it_ip = str(it).strip()
                            it_rem = remark
                        v_ip = validate_ip(it_ip)
                        if not v_ip:
                            continue
                        unban_ip_core(v_ip, status_event="WHITELIST")
                        node_rem = f"[{source_node}联防] {it_rem}" if not it_rem.startswith(f"[{source_node}") else it_rem
                        if v_ip not in current_map:
                            current_map[v_ip] = {"ip": v_ip, "remark": node_rem}
                            updated_cnt += 1

                    cfg["whitelist"] = list(current_map.values())
                    save_config(cfg)
                    self._send_json({"success": True, "msg": f"已批量同步 {updated_cnt} 条协同白名单", "count": updated_cnt})
                    return

                self._send_json({"success": False, "msg": "未知的白名单同步操作"}, status=400)
                return

            if path == "/api/cluster/sync_all_whitelist":
                cfg = load_config()
                cluster_cfg = cfg.get("cluster_sync", {})
                if not cluster_cfg.get("enabled", False):
                    self._send_json({"success": False, "msg": "集群联防协同功能未开启"}, status=400)
                    return
                nodes = cluster_cfg.get("cluster_nodes", [])
                if not nodes:
                    self._send_json({"success": False, "msg": "当前未配置任何集群协同节点"}, status=400)
                    return
                whitelist = cfg.get("whitelist", [])
                broadcast_cluster_whitelist("sync_all", whitelist, "全网协同全量同步")
                self._send_json({"success": True, "msg": f"已向 {len(nodes)} 个集群节点广播全量白名单 (共 {len(whitelist)} 条规则)"})
                return

            if path == "/api/cluster/ping":
                token = self.headers.get("X-Cluster-Token", "").strip()
                cfg = load_config()
                cluster_cfg = cfg.get("cluster_sync", {})
                secret = cluster_cfg.get("cluster_secret", "").strip()
                if not secret or not verify_cluster_token("ping", token, secret):
                    self._send_json({"success": False, "msg": "集群鉴权密钥无效或未配置"}, status=403)
                    return
                self._send_json({
                    "success": True,
                    "node_name": cfg.get("node_name", "远程节点"),
                    "version": "2.0.0"
                })
                return

            if path == "/api/cluster/test_node":
                node_url = req_data.get("node_url", "").strip().rstrip("/")
                secret = req_data.get("secret", "").strip()
                if not node_url:
                    self._send_json({"success": False, "msg": "节点地址不能为空"}, status=400)
                    return
                if not secret:
                    self._send_json({"success": False, "msg": "通信密钥不能为空"}, status=400)
                    return

                # SSRF 安全防御校验：阻断云厂商元数据及敏感内网地址探测
                try:
                    parsed_node = urlparse(node_url)
                    if parsed_node.scheme not in ('http', 'https'):
                        self._send_json({"success": False, "msg": "协议不合法，仅支持 http:// 或 https:// 协议"}, status=400)
                        return
                    host_part = parsed_node.hostname
                    if not host_part:
                        self._send_json({"success": False, "msg": "节点地址格式错误"}, status=400)
                        return

                    resolved_addrs = socket.getaddrinfo(host_part, None)
                    for item in resolved_addrs:
                        ip_str = item[4][0]
                        ip_obj = ipaddress.ip_address(ip_str)
                        if ip_obj.is_link_local:
                            self._send_json({"success": False, "msg": f"安全拦截：禁止探测云元数据/链路本地地址 ({ip_str})"}, status=403)
                            return
                        if ip_obj.is_loopback:
                            self._send_json({"success": False, "msg": f"安全拦截：禁止访问本地回环地址 ({ip_str})"}, status=403)
                            return
                        if ip_obj.is_unspecified:
                            self._send_json({"success": False, "msg": f"安全拦截：禁止访问未指定地址 ({ip_str})"}, status=403)
                            return
                except Exception as ex:
                    self._send_json({"success": False, "msg": f"节点主机名解析异常: {ex}"}, status=400)
                    return

                token = generate_cluster_token("ping", secret)
                t0 = time.time()
                try:
                    target = f"{node_url}/api/cluster/ping"
                    req = urllib.request.Request(target, data=b"{}", headers={
                        "Content-Type": "application/json",
                        "X-Cluster-Token": token,
                        "User-Agent": "PortGuardMesh/2.0"
                    })
                    with urllib.request.urlopen(req, timeout=3.0) as resp:
                        res_data = json.loads(resp.read().decode('utf-8'))
                        latency = int((time.time() - t0) * 1000)
                        if res_data.get("success"):
                            self._send_json({
                                "success": True,
                                "node_name": res_data.get("node_name", "远程节点"),
                                "latency_ms": latency,
                                "msg": f"连接成功！节点响应正常 (延迟 {latency}ms)"
                            })
                        else:
                            self._send_json({
                                "success": False,
                                "msg": res_data.get("msg", "鉴权失败")
                            })
                except urllib.error.HTTPError as e:
                    self._send_json({"success": False, "msg": f"HTTP {e.code}: 鉴权失败或密钥不一致"})
                except Exception as e:
                    self._send_json({"success": False, "msg": f"连接超时或无法访问 ({e})"})
                return

            if path == "/api/cluster/nodes/add":
                ip_raw = str(req_data.get("ip", "")).strip()
                port = int(req_data.get("port", 9099) or 9099)
                remark = str(req_data.get("remark", "")).strip()
                
                # 兼容清洗输入的 URL 或端口前缀
                if "://" in ip_raw:
                    ip_raw = ip_raw.split("://", 1)[1]
                if "/" in ip_raw:
                    ip_raw = ip_raw.split("/", 1)[0]
                if ":" in ip_raw:
                    p_parts = ip_raw.split(":")
                    ip_raw = p_parts[0]
                    try:
                        port = int(p_parts[1])
                    except Exception:
                        pass
                
                if not ip_raw:
                    self._send_json({"success": False, "msg": "节点 IP 或域名不能为空"}, status=400)
                    return
                    
                cfg = load_config()
                cluster_cfg = cfg.get("cluster_sync", {})
                if "cluster_nodes" not in cluster_cfg or not isinstance(cluster_cfg["cluster_nodes"], list):
                    cluster_cfg["cluster_nodes"] = []
                    
                geo = resolve_ip_geo(ip_raw)
                country_str = f"{geo.get('country', '')} {geo.get('city', '')}".strip() or "公网节点"
                
                # 初始连通性快速探测
                secret = cluster_cfg.get("cluster_secret", "").strip()
                status = "unknown"
                latency_ms = 0
                if secret:
                    token = generate_cluster_token("ping", secret)
                    try:
                        target = f"http://{ip_raw}:{port}/api/cluster/ping"
                        req = urllib.request.Request(target, data=b"{}", headers={
                            "Content-Type": "application/json",
                            "X-Cluster-Token": token,
                            "User-Agent": "PortGuardMesh/2.0"
                        })
                        t0 = time.time()
                        with urllib.request.urlopen(req, timeout=2.5) as resp:
                            res_data = json.loads(resp.read().decode('utf-8'))
                            if res_data.get("success"):
                                status = "online"
                                latency_ms = int((time.time() - t0) * 1000)
                                if not remark and res_data.get("node_name"):
                                    remark = res_data.get("node_name")
                            else:
                                status = "offline"
                    except Exception:
                        status = "offline"
                        
                node_obj = {
                    "ip": ip_raw,
                    "port": port,
                    "remark": remark or f"协同节点 ({ip_raw})",
                    "country": country_str,
                    "status": status,
                    "latency_ms": latency_ms,
                    "created_at": time.strftime("%Y-%m-%d %H:%M:%S")
                }
                
                # 查重更新或追加
                updated = False
                new_list = []
                for ex in cluster_cfg["cluster_nodes"]:
                    norm_ex = normalize_cluster_node(ex)
                    if norm_ex and norm_ex["ip"] == ip_raw and norm_ex["port"] == port:
                        new_list.append(node_obj)
                        updated = True
                    elif norm_ex:
                        new_list.append(norm_ex)
                if not updated:
                    new_list.append(node_obj)
                    
                cluster_cfg["cluster_nodes"] = new_list
                cfg["cluster_sync"] = cluster_cfg
                save_config(cfg)
                self._send_json({
                    "success": True, 
                    "msg": f"协同节点 {ip_raw}:{port} 已成功添加！" if not updated else f"协同节点 {ip_raw}:{port} 配置已更新！",
                    "node": node_obj,
                    "nodes": new_list
                })
                return

            if path == "/api/cluster/nodes/delete":
                ip_raw = str(req_data.get("ip", "")).strip()
                port = int(req_data.get("port", 9099) or 9099)
                cfg = load_config()
                cluster_cfg = cfg.get("cluster_sync", {})
                existing = cluster_cfg.get("cluster_nodes", [])
                new_list = []
                for ex in existing:
                    norm_ex = normalize_cluster_node(ex)
                    if norm_ex and norm_ex["ip"] == ip_raw and (port == 0 or norm_ex["port"] == port):
                        continue
                    elif norm_ex:
                        new_list.append(norm_ex)
                cluster_cfg["cluster_nodes"] = new_list
                cfg["cluster_sync"] = cluster_cfg
                save_config(cfg)
                self._send_json({"success": True, "msg": f"协同节点 {ip_raw} 已成功移除", "nodes": new_list})
                return

            if path == "/api/cluster/nodes/update_remark":
                ip_raw = str(req_data.get("ip", "")).strip()
                port = int(req_data.get("port", 9098) or 9098)
                new_remark = str(req_data.get("remark", "")).strip()
                if not new_remark:
                    self._send_json({"success": False, "msg": "节点备注名称不能为空"}, 400)
                    return
                
                cfg = load_config()
                cluster_cfg = cfg.get("cluster_sync", {})
                existing = cluster_cfg.get("cluster_nodes", [])
                updated = False
                for ex in existing:
                    if isinstance(ex, dict) and ex.get("ip") == ip_raw and int(ex.get("port", 9098)) == port:
                        ex["remark"] = new_remark
                        updated = True
                if updated:
                    cluster_cfg["cluster_nodes"] = existing
                    cfg["cluster_sync"] = cluster_cfg
                    save_config(cfg)
                    self._send_json({"success": True, "msg": f"节点 {ip_raw}:{port} 备注已更新为: {new_remark}", "nodes": existing})
                else:
                    self._send_json({"success": False, "msg": "未找到匹配的协同节点"}, 404)
                return

            if path == "/api/cluster/nodes/test_all":
                cfg = load_config()
                cluster_cfg = cfg.get("cluster_sync", {})
                secret = cluster_cfg.get("cluster_secret", "").strip()
                existing = cluster_cfg.get("cluster_nodes", [])
                
                updated_nodes = []
                for ex in existing:
                    node = normalize_cluster_node(ex)
                    if not node or not node.get("ip"):
                        continue
                    ip_addr = node["ip"]
                    port_num = node.get("port", 9099)
                    
                    if not secret:
                        node["status"] = "offline"
                        node["latency_ms"] = 0
                        updated_nodes.append(node)
                        continue
                        
                    token = generate_cluster_token("ping", secret)
                    try:
                        target = f"http://{ip_addr}:{port_num}/api/cluster/ping"
                        req = urllib.request.Request(target, data=b"{}", headers={
                            "Content-Type": "application/json",
                            "X-Cluster-Token": token,
                            "User-Agent": "PortGuardMesh/2.0"
                        })
                        t0 = time.time()
                        with urllib.request.urlopen(req, timeout=2.5) as resp:
                            res_data = json.loads(resp.read().decode('utf-8'))
                            if res_data.get("success"):
                                node["status"] = "online"
                                node["latency_ms"] = int((time.time() - t0) * 1000)
                            else:
                                node["status"] = "offline"
                    except Exception:
                        node["status"] = "offline"
                        
                    if not node.get("country") or node.get("country") in ("分析中...", ""):
                        geo = resolve_ip_geo(ip_addr)
                        node["country"] = f"{geo.get('country', '')} {geo.get('city', '')}".strip() or "公网节点"
                        
                    updated_nodes.append(node)
                    
                cluster_cfg["cluster_nodes"] = updated_nodes
                cfg["cluster_sync"] = cluster_cfg
                save_config(cfg)
                self._send_json({"success": True, "nodes": updated_nodes})
                return

            if path == "/api/cluster/nodes/test_single":
                ip_raw = str(req_data.get("ip", "")).strip()
                port = int(req_data.get("port", 9099) or 9099)
                cfg = load_config()
                cluster_cfg = cfg.get("cluster_sync", {})
                secret = cluster_cfg.get("cluster_secret", "").strip()
                token = generate_cluster_token("ping", secret)
                
                status = "offline"
                latency_ms = 0
                node_name = "远程节点"
                try:
                    target = f"http://{ip_raw}:{port}/api/cluster/ping"
                    req = urllib.request.Request(target, data=b"{}", headers={
                        "Content-Type": "application/json",
                        "X-Cluster-Token": token,
                        "User-Agent": "PortGuardMesh/2.0"
                    })
                    t0 = time.time()
                    with urllib.request.urlopen(req, timeout=3.0) as resp:
                        res_data = json.loads(resp.read().decode('utf-8'))
                        if res_data.get("success"):
                            status = "online"
                            latency_ms = int((time.time() - t0) * 1000)
                            node_name = res_data.get("node_name", "远程节点")
                except Exception:
                    pass
                    
                # 更新到配置
                for ex in cluster_cfg.get("cluster_nodes", []):
                    if isinstance(ex, dict) and ex.get("ip") == ip_raw and int(ex.get("port", 9099)) == port:
                        ex["status"] = status
                        ex["latency_ms"] = latency_ms
                cfg["cluster_sync"] = cluster_cfg
                save_config(cfg)
                
                self._send_json({
                    "success": (status == "online"),
                    "status": status,
                    "latency_ms": latency_ms,
                    "node_name": node_name
                })
                return

            if path == "/api/ban":
                ip = req_data.get("ip", "").strip()
                reason = req_data.get("reason", "管理员手动封禁").strip()
                if not ip:
                    self._send_json({"success": False, "msg": "IP 不能为空"}, status=400)
                    return
                valid_ip = validate_ip(ip)
                if not valid_ip:
                    self._send_json({"success": False, "msg": "IP 格式不合法"}, status=400)
                    return
                ip = valid_ip

                # 防自锁与白名单保护：当前控制台客户端、活跃SSH管理会话及安全白名单严禁封禁
                client_ip = getattr(self, "client_address", ("", 0))[0]
                if ip == client_ip:
                    self._send_json({"success": False, "msg": f"操作已阻断：目标 IP [{ip}] 为当前登录控制台的客户端地址，触发管理员防自锁保护！"}, status=400)
                    return
                if ip_in_whitelist(ip):
                    self._send_json({"success": False, "msg": f"操作已阻断：目标 IP [{ip}] 属于系统安全白名单或活跃管理会话，严禁封禁！"}, status=400)
                    return

                ban_ip(ip, reason=reason, category="manual", level="极高危")
                invalidate_blacklist_cache()
                self._send_json({"success": True, "msg": f"已成功永久封禁 IP: {ip}（已下发内核防火墙并同步集群协同阻断）"})
                return

            if path == "/api/defense/toggle_pause":
                cfg = load_config()
                action = req_data.get("action", "")
                if action == "pause":
                    cfg["defense_paused"] = True
                elif action == "resume":
                    cfg["defense_paused"] = False
                else:
                    cfg["defense_paused"] = not bool(cfg.get("defense_paused", False))
                
                is_paused = cfg["defense_paused"]
                save_config(cfg)

                if is_paused:
                    flush_firewall_blocks()
                    msg = "PortGuard 防御拦截已暂停（系统进入观察模式，已排空防火墙与黑洞路由，Web控制台正常运行）。"
                else:
                    init_firewall_ipset()
                    msg = "PortGuard 防御拦截已恢复（安全防护与实时阻断已重新生效）。"

                self._send_json({"success": True, "paused": is_paused, "msg": msg})
                return

            if path == "/api/settings":
                cfg = load_config()
                if "node_name" in req_data:
                    cfg["node_name"] = str(req_data["node_name"]).strip() or "本机节点"
                if "trap_threshold" in req_data:
                    cfg["trap_threshold"] = int(req_data["trap_threshold"])
                if "trap_window_seconds" in req_data:
                    cfg["trap_window_seconds"] = int(req_data["trap_window_seconds"])
                if "auto_clean_days" in req_data:
                    cfg["auto_clean_days"] = int(req_data["auto_clean_days"])
                if "enable_port_scan_defense" in req_data:
                    cfg["enable_port_scan_defense"] = bool(req_data["enable_port_scan_defense"])
                if "port_scan_threshold" in req_data:
                    cfg["port_scan_threshold"] = int(req_data["port_scan_threshold"])
                if "port_scan_window_seconds" in req_data:
                    cfg["port_scan_window_seconds"] = int(req_data["port_scan_window_seconds"])
                if "ban_action_iptables" in req_data:
                    cfg["ban_action_iptables"] = bool(req_data["ban_action_iptables"])
                if "ban_action_blackhole" in req_data:
                    cfg["ban_action_blackhole"] = bool(req_data["ban_action_blackhole"])
                if "enable_tarpit_delay" in req_data:
                    cfg["enable_tarpit_delay"] = bool(req_data["enable_tarpit_delay"])
                if "dynamic_honeypot_ports" in req_data:
                    cfg["dynamic_honeypot_ports"] = bool(req_data["dynamic_honeypot_ports"])
                if "trap_business_ports" in req_data:
                    cfg["trap_business_ports"] = bool(req_data["trap_business_ports"])
                if "trap_all_unopened_ports" in req_data:
                    cfg["trap_all_unopened_ports"] = bool(req_data["trap_all_unopened_ports"])
                if "trap_all_ports" in req_data:
                    cfg["trap_all_ports"] = bool(req_data["trap_all_ports"])
                if "defense_paused" in req_data:
                    cfg["defense_paused"] = bool(req_data["defense_paused"])
                if "cluster_sync" in req_data and isinstance(req_data["cluster_sync"], dict):
                    cfg["cluster_sync"] = req_data["cluster_sync"]
                save_config(cfg)
                self._send_json({"success": True, "msg": "系统防御设置已成功保存并立即生效！"})
                return

            if path == "/api/config/rollback":
                # 快照一键回滚接口
                snap_filename = req_data.get("filename", "").strip()
                if not snap_filename:
                    self._send_json({"success": False, "msg": "缺少快照文件名"}, status=400)
                    return
                ok, msg = rollback_config_snapshot(snap_filename)
                self._send_json({"success": ok, "msg": msg})
                return

            if path == "/api/blacklist/ban_subnet":
                # 一键封禁整个 /24 C段网段
                subnet = req_data.get("subnet", "").strip()
                reason = req_data.get("reason", "管理员手动封禁攻击源 /24 C段").strip()
                if not subnet or "/" not in subnet:
                    self._send_json({"success": False, "msg": "非法的 CIDR 网段格式 (如 1.2.3.0/24)"}, status=400)
                    return
                try:
                    net_obj = ipaddress.ip_network(subnet, strict=False)
                    # 下发网段级黑洞路由与防火墙拦截
                    subprocess.run(["ip", "route", "add", "blackhole", str(net_obj)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    subprocess.run(["iptables", "-I", "INPUT", "-s", str(net_obj), "-j", "DROP"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    ban_ip(str(net_obj), reason=reason, category="subnet_ban", level="极高危")
                    self._send_json({"success": True, "msg": f"已成功对 {net_obj} 整个网段实施内核黑洞阻断与拦截！"})
                except Exception as e:
                    self._send_json({"success": False, "msg": f"网段阻断失败: {e}"}, status=400)
                return

            if path == "/api/blacklist/batch_ban_all":
                cfg = load_config()
                whitelist = cfg.get("whitelist", [])
                conn = get_db()
                c = conn.cursor()
                c.execute("SELECT DISTINCT ip, port FROM port_access_logs WHERE (action = 'PROBE' OR action = 'WATCH' OR action = 'INTERCEPTED') AND ip NOT IN ('127.0.0.1', '::1', '0.0.0.0')")
                rows = c.fetchall()
                
                now_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
                now_ts = int(time.time())
                auto_clean_days = int(cfg.get("auto_clean_days", 30) if cfg.get("auto_clean_days") is not None else 30)
                ban_expire = now_ts + auto_clean_days * 86400 if auto_clean_days > 0 else None
                
                count = 0
                for ip, port in rows:
                    v = validate_ip(ip)
                    if not v or ip_in_whitelist(v, whitelist):
                        continue
                    c.execute("SELECT ip FROM blacklist WHERE ip = ?", (v,))
                    if c.fetchone():
                        continue
                    cached_geo = _GEO_CACHE.get(v, {})
                    country = cached_geo.get("country", "公网探测")
                    
                    if cfg.get("ban_action_iptables", True):
                        run_firewall_cmd("iptables", "-C", "INPUT", "-s", v, "-j", "DROP")
                        run_firewall_cmd("iptables", "-I", "INPUT", "-s", v, "-j", "DROP")
                    if cfg.get("ban_action_blackhole", True):
                        run_firewall_cmd("ip", "route", "add", "blackhole", f"{v}/32")
                        
                    c.execute("""
                    INSERT OR REPLACE INTO blacklist (ip, reason, country, level, ban_time, timestamp, ban_expire)
                    VALUES (?, ?, ?, '高危', ?, ?, ?)
                    """, (v, f"未开放端口扫描探测 (端口 {port})", country, now_str, now_ts, ban_expire))
                    
                    c.execute("""
                    INSERT INTO events (ip, port, proto, port_name, category, level, country, region, city, isp, attack_time, timestamp, status)
                    VALUES (?, ?, 'TCP', '多端口扫描探测', 'scan', '高危', ?, '', '', '', ?, ?, 'BANNED')
                    """, (v, port, country, now_str, now_ts))
                    
                    if not cached_geo:
                        _EXECUTOR.submit(resolve_ip_geo, v)
                    count += 1
                    
                conn.commit()
                conn.close()
                if cfg.get("ban_action_iptables", True):
                    run_firewall_cmd("iptables-save")
                self._send_json({"success": True, "count": count, "msg": f"已成功将 {count} 个恶意探测 IP 批量加入黑名单并下发防火墙阻断。"})
                return

            if path == "/api/blacklist/import":
                raw_input = req_data.get("data")
                mode = req_data.get("mode", "append")
                if isinstance(raw_input, str):
                    parsed_items = parse_loose_json_or_lines(raw_input)
                elif isinstance(raw_input, list):
                    parsed_items = raw_input
                elif isinstance(raw_input, dict):
                    parsed_items = [raw_input]
                else:
                    parsed_items = []
                    
                if not parsed_items:
                    self._send_json({"success": False, "msg": "未解析到有效的 IP 数据"}, status=400)
                    return
                    
                conn = get_db()
                c = conn.cursor()
                
                if mode == "replace":
                    c.execute("SELECT ip FROM blacklist")
                    for (old_ip,) in c.fetchall():
                        v_old = validate_ip(old_ip)
                        if v_old:
                            run_firewall_cmd("iptables", "-D", "INPUT", "-s", v_old, "-j", "DROP")
                            run_firewall_cmd("ip", "route", "del", "blackhole", f"{v_old}/32")
                    c.execute("DELETE FROM blacklist")
                    conn.commit()
                    
                now_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
                now_ts = int(time.time())
                
                success_count = 0
                for item in parsed_items:
                    if isinstance(item, dict):
                        ip = str(item.get("ip", "")).strip()
                        reason = str(item.get("reason", "批量导入封禁")).strip()
                        country = str(item.get("country", "手动导入")).strip()
                        level = str(item.get("level", "极高危")).strip()
                        ban_time = str(item.get("ban_time", now_str)).strip()
                    elif isinstance(item, str):
                        parts = item.strip().split(maxsplit=1)
                        ip = parts[0].strip() if parts else ""
                        reason = parts[1].strip() if len(parts) > 1 else "批量导入封禁"
                        country = "手动导入"
                        level = "极高危"
                        ban_time = now_str
                    else:
                        continue
                        
                    if not ip or len(ip) < 7:
                        continue
                    valid_ip = validate_ip(ip)
                    if not valid_ip:
                        continue
                    ip = valid_ip

                    run_firewall_cmd("iptables", "-C", "INPUT", "-s", ip, "-j", "DROP")
                    run_firewall_cmd("iptables", "-I", "INPUT", "-s", ip, "-j", "DROP")
                    run_firewall_cmd("ip", "route", "add", "blackhole", f"{ip}/32")

                    cfg_import = load_config()
                    node_name = cfg_import.get("node_name", "本机") or "本机"
                    c.execute("""
                    INSERT OR REPLACE INTO blacklist (ip, reason, country, level, ban_time, timestamp, ban_expire, source_node)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """, (ip, reason, country, level, ban_time, now_ts, None, f"批量导入 ({node_name})"))
                    success_count += 1
                    
                run_firewall_cmd("iptables-save")
                conn.commit()
                conn.close()
                
                self._send_json({"success": True, "msg": f"黑名单导入成功！共写入 {success_count} 个拦截目标", "count": success_count})
                return

            if path == "/api/whitelist/add":
                ip = req_data.get("ip", "").strip()
                remark = req_data.get("remark", "信任IP").strip()
                if not ip:
                    self._send_json({"success": False, "msg": "IP 不能为空"}, status=400)
                    return
                
                valid_ip = validate_ip(ip)
                if not valid_ip:
                    self._send_json({"success": False, "msg": "IP 格式不合法"}, status=400)
                    return
                ip = valid_ip

                # 检查该 IP 是否存在于黑名单库中
                was_banned = False
                conn = get_db()
                c = conn.cursor()
                c.execute("SELECT ip FROM blacklist WHERE ip = ?", (ip,))
                if c.fetchone():
                    was_banned = True
                conn.close()

                # 自动联动从内核防火墙、黑洞路由与黑名单库中解封
                unban_ip_core(ip, status_event="WHITELIST")

                cfg = load_config()
                whitelist = cfg.get("whitelist", [])
                if not any(w.get("ip") == ip if isinstance(w, dict) else w == ip for w in whitelist):
                    whitelist.append({"ip": ip, "remark": remark})
                    cfg["whitelist"] = whitelist
                    save_config(cfg)
                    # 广播至集群协同节点
                    broadcast_cluster_whitelist("add", ip, remark)
                
                extra_tip = "（已自动解除原黑名单封禁并撤销防火墙阻断）" if was_banned else ""
                self._send_json({"success": True, "msg": f"已成功将 {ip} 加入信任白名单{extra_tip}！"})
                return

            if path == "/api/whitelist/delete":
                ip = req_data.get("ip", "").strip()
                cfg = load_config()
                cfg["whitelist"] = [w for w in cfg.get("whitelist", []) if (w.get("ip") if isinstance(w, dict) else w) != ip]
                save_config(cfg)
                # 广播至集群协同节点
                broadcast_cluster_whitelist("delete", ip)
                self._send_json({"success": True, "msg": f"已移除白名单: {ip}"})
                return

            if path == "/api/whitelist/import":
                raw_input = req_data.get("data")
                mode = req_data.get("mode", "append")
                if isinstance(raw_input, str):
                    parsed_items = parse_loose_json_or_lines(raw_input)
                elif isinstance(raw_input, list):
                    parsed_items = raw_input
                elif isinstance(raw_input, dict):
                    parsed_items = [raw_input]
                else:
                    parsed_items = []
                    
                if not parsed_items:
                    self._send_json({"success": False, "msg": "未解析到有效的白名单数据"}, status=400)
                    return
                    
                cfg = load_config()
                existing_list = cfg.get("whitelist", DEFAULT_CONFIG["whitelist"])
                current_map = {}
                if mode == "append":
                    for item in existing_list:
                        if isinstance(item, str):
                            current_map[item] = {"ip": item, "remark": "信任IP"}
                        elif isinstance(item, dict) and item.get("ip"):
                            current_map[item["ip"]] = item
                            
                success_count = 0
                unbanned_count = 0
                for item in parsed_items:
                    if isinstance(item, dict):
                        ip = str(item.get("ip", "")).strip()
                        remark = str(item.get("remark", "导入信任IP")).strip()
                    elif isinstance(item, str):
                        parts = item.strip().split(maxsplit=1)
                        ip = parts[0].strip() if parts else ""
                        remark = parts[1].strip() if len(parts) > 1 else "导入信任IP"
                    else:
                        continue
                        
                    if not ip:
                        continue
                    
                    v_ip = validate_ip(ip)
                    if not v_ip:
                        continue
                    ip = v_ip
                        
                    current_map[ip] = {"ip": ip, "remark": remark}
                    success_count += 1
                    
                    # 批量自动联动解封已有黑名单
                    if unban_ip_core(ip, status_event="WHITELIST"):
                        unbanned_count += 1
                    
                if success_count == 0:
                    self._send_json({"success": False, "msg": "未能提取到有效的 IP 白名单项"}, status=400)
                    return
                    
                new_whitelist = list(current_map.values())
                cfg["whitelist"] = new_whitelist
                save_config(cfg)
                # 广播批量导入至集群协同节点
                broadcast_cluster_whitelist("batch_add", new_whitelist, "批量导入同步")
                unban_tip = f"，并同步解除 {unbanned_count} 个原黑名单目标" if unbanned_count > 0 else ""
                self._send_json({
                    "success": True,
                    "msg": f"信任白名单导入成功！共载入 {success_count} 条规则{unban_tip} (当前总计 {len(current_map)} 条)",
                    "count": success_count,
                    "unbanned_count": unbanned_count,
                    "total": len(current_map)
                })
                return

            if path == "/api/traps/add":
                raw_port = req_data.get("port")
                name = req_data.get("name", "").strip()
                level = req_data.get("level", "高危")
                category = req_data.get("category", "custom")
                is_business = bool(req_data.get("is_business", False))
                if not raw_port:
                    self._send_json({"success": False, "msg": "端口不能为空"}, status=400)
                    return
                    
                temp_item = {
                    "port": raw_port,
                    "name": name,
                    "description": name,
                    "category": category,
                    "level": level,
                    "enabled": True,
                    "strategy": "accept",
                    "is_business": is_business,
                    "trap_business": is_business
                }
                norm_new = normalize_trap_item(temp_item)
                if not norm_new:
                    self._send_json({"success": False, "msg": "端口格式不合法，请输入单个端口 (1-65535) 或端口范围 (例如 1000-3000)"}, status=400)
                    return
                    
                cfg = load_config()
                traps = cfg.get("trap_ports", [])
                normalized = []
                for item in traps:
                    norm = normalize_trap_item(item)
                    if norm:
                        normalized.append(norm)
                        
                port_key = str(norm_new["port"])
                if not any(str(t.get("port")) == port_key for t in normalized):
                    normalized.append(norm_new)
                    cfg["trap_ports"] = normalized
                    save_config(cfg)
                    trap_instance.reload()
                self._send_json({"success": True, "msg": f"已激活诱捕端口/策略: {port_key}"})
                return

            if path == "/api/traps/edit":
                orig_port = str(req_data.get("orig_port", "")).strip()
                new_port = str(req_data.get("port", "")).strip()
                name = str(req_data.get("name", "")).strip()
                level = req_data.get("level", "高危")
                category = req_data.get("category", "custom")
                enabled = bool(req_data.get("enabled", True))
                is_business = bool(req_data.get("is_business", False))
                
                temp_item = {
                    "port": new_port,
                    "name": name,
                    "description": name,
                    "category": category,
                    "level": level,
                    "enabled": enabled,
                    "strategy": "accept" if enabled else "reject",
                    "is_business": is_business,
                    "trap_business": is_business
                }
                norm_new = normalize_trap_item(temp_item)
                if not norm_new:
                    self._send_json({"success": False, "msg": "端口格式不合法，请输入单个端口 (1-65535) 或端口范围 (例如 1000-3000)"}, status=400)
                    return
                    
                cfg = load_config()
                traps = cfg.get("trap_ports", [])
                normalized = []
                found = False
                for item in traps:
                    norm = normalize_trap_item(item)
                    if norm:
                        if str(norm.get("port")) == orig_port:
                            normalized.append(norm_new)
                            found = True
                        else:
                            normalized.append(norm)
                if not found:
                    normalized.append(norm_new)
                    
                cfg["trap_ports"] = normalized
                save_config(cfg)
                trap_instance.reload()
                self._send_json({"success": True, "msg": f"蜜罐策略已更新: {norm_new['port']}"})
                return

            if path == "/api/traps/delete":
                port_key = str(req_data.get("port", "")).strip()
                cfg = load_config()
                traps = cfg.get("trap_ports", [])
                normalized = []
                for item in traps:
                    norm = normalize_trap_item(item)
                    if norm and str(norm.get("port")) != port_key:
                        normalized.append(norm)
                cfg["trap_ports"] = normalized
                save_config(cfg)
                trap_instance.reload()
                self._send_json({"success": True, "msg": f"已彻底删除蜜罐策略: {port_key}"})
                return

            if path == "/api/traps/toggle":
                port_key = str(req_data.get("port", "")).strip()
                enabled = req_data.get("enabled", True)
                cfg = load_config()
                traps = cfg.get("trap_ports", [])
                normalized = []
                for item in traps:
                    norm = normalize_trap_item(item)
                    if norm:
                        normalized.append(norm)
                for t in normalized:
                    if str(t.get("port")) == port_key:
                        t["enabled"] = enabled
                        t["strategy"] = "accept" if enabled else "reject"
                cfg["trap_ports"] = normalized
                save_config(cfg)
                trap_instance.reload()
                self._send_json({"success": True, "msg": f"已更新端口策略 {port_key} 状态"})
                return

            if path == "/api/http_traps/toggle":
                rule_id = req_data.get("id")
                enabled = 1 if req_data.get("enabled") else 0
                conn = get_db()
                c = conn.cursor()
                c.execute("UPDATE http_traps SET enabled = ? WHERE id = ? OR rule_id = ?", (enabled, rule_id, str(rule_id)))
                conn.commit()
                conn.close()
                self._send_json({"success": True, "msg": f"请求特征策略已{'启用' if enabled else '停用'}"})
                return

            if path == "/api/http_traps/add":
                name = str(req_data.get("name", "")).strip()
                mtype = str(req_data.get("match_type", "path_keyword")).strip()
                pattern = str(req_data.get("pattern", "")).strip()
                threshold = int(req_data.get("threshold") or 6)
                window = int(req_data.get("window") or 30)
                level = str(req_data.get("level", "高危")).strip()
                desc = str(req_data.get("description", "")).strip()
                rule_id = "ht_" + str(int(time.time()))
                now_dt = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
                if not name:
                    self._send_json({"success": False, "msg": "策略名称不能为空"}, status=400)
                    return
                conn = get_db()
                c = conn.cursor()
                c.execute("""
                INSERT INTO http_traps (rule_id, name, match_type, pattern, threshold, window, action, level, enabled, description, created_at)
                VALUES (?, ?, ?, ?, ?, ?, 'ban', ?, 1, ?, ?)
                """, (rule_id, name, mtype, pattern, threshold, window, level, desc, now_dt))
                conn.commit()
                conn.close()
                self._send_json({"success": True, "msg": f"已添加请求特征策略: {name}"})
                return

            if path == "/api/http_traps/edit":
                rule_db_id = req_data.get("id")
                name = str(req_data.get("name", "")).strip()
                mtype = str(req_data.get("match_type", "path_keyword")).strip()
                pattern = str(req_data.get("pattern", "")).strip()
                threshold = int(req_data.get("threshold") or 6)
                window = int(req_data.get("window") or 30)
                level = str(req_data.get("level", "高危")).strip()
                desc = str(req_data.get("description", "")).strip()
                if not name:
                    self._send_json({"success": False, "msg": "策略名称不能为空"}, status=400)
                    return
                conn = get_db()
                c = conn.cursor()
                c.execute("""
                UPDATE http_traps SET name = ?, match_type = ?, pattern = ?, threshold = ?, window = ?, level = ?, description = ?
                WHERE id = ? OR rule_id = ?
                """, (name, mtype, pattern, threshold, window, level, desc, rule_db_id, str(rule_db_id)))
                conn.commit()
                conn.close()
                self._send_json({"success": True, "msg": f"已更新请求特征策略: {name}"})
                return

            if path == "/api/http_traps/delete":
                rule_db_id = req_data.get("id")
                conn = get_db()
                c = conn.cursor()
                c.execute("DELETE FROM http_traps WHERE id = ? OR rule_id = ?", (rule_db_id, str(rule_db_id)))
                conn.commit()
                conn.close()
                self._send_json({"success": True, "msg": "已删除请求特征策略"})
                return

            if path == "/api/http_traps/import":
                raw_input = req_data.get("data")
                mode = req_data.get("mode", "append")
                if isinstance(raw_input, str):
                    parsed_items = parse_loose_json_or_lines(raw_input)
                elif isinstance(raw_input, list):
                    parsed_items = raw_input
                elif isinstance(raw_input, dict):
                    parsed_items = [raw_input]
                else:
                    parsed_items = []

                if not parsed_items:
                    self._send_json({"success": False, "msg": "未解析到有效的请求特征策略数据，请检查格式"}, status=400)
                    return

                conn = get_db()
                c = conn.cursor()
                if mode == "replace":
                    c.execute("DELETE FROM http_traps")

                count = 0
                now_dt = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
                for idx, item in enumerate(parsed_items):
                    if not isinstance(item, dict):
                        continue
                    name = str(item.get("name", f"导入策略-{idx+1}")).strip()
                    mtype = str(item.get("match_type", "path_keyword")).strip()
                    pattern = str(item.get("pattern", "")).strip()
                    threshold = int(item.get("threshold") or 6)
                    window = int(item.get("window") or 30)
                    level = str(item.get("level", "极高危")).strip()
                    desc = str(item.get("description", "")).strip()
                    enabled = 1 if item.get("enabled") is not False else 0
                    rule_id = str(item.get("rule_id") or f"ht_{int(time.time())}_{idx}")

                    c.execute("""
                    INSERT OR REPLACE INTO http_traps (rule_id, name, match_type, pattern, threshold, window, action, level, enabled, description, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, 'ban', ?, ?, ?, ?)
                    """, (rule_id, name, mtype, pattern, threshold, window, level, enabled, desc, now_dt))
                    count += 1

                conn.commit()
                conn.close()
                self._send_json({"success": True, "msg": f"成功{'全量覆盖' if mode=='replace' else '增量导入'} {count} 条请求特征策略"})
                return

            if path == "/api/traps/import":
                raw_input = req_data.get("data")
                mode = req_data.get("mode", "append")
                if isinstance(raw_input, str):
                    parsed_items = parse_loose_json_or_lines(raw_input)
                elif isinstance(raw_input, list):
                    parsed_items = raw_input
                elif isinstance(raw_input, dict):
                    parsed_items = [raw_input]
                else:
                    parsed_items = []
                    
                if not parsed_items:
                    self._send_json({"success": False, "msg": "未解析到有效的蜜罐策略数据，请检查格式"}, status=400)
                    return
                    
                cfg = load_config()
                existing_traps = cfg.get("trap_ports", DEFAULT_CONFIG["trap_ports"])
                current_map = {}
                if mode == "append":
                    for item in existing_traps:
                        norm = normalize_trap_item(item)
                        if norm:
                            current_map[norm["port"]] = norm
                            
                success_count = 0
                for item in parsed_items:
                    norm = normalize_trap_item(item)
                    if norm:
                        current_map[norm["port"]] = norm
                        success_count += 1
                        
                if success_count == 0:
                    self._send_json({"success": False, "msg": "未能提取到任何合法端口策略（端口号必须为 1-65535）"}, status=400)
                    return
                    
                cfg["trap_ports"] = list(current_map.values())
                save_config(cfg)
                trap_instance.reload()
                self._send_json({
                    "success": True,
                    "msg": f"蜜罐策略导入成功！共载入 {success_count} 条策略 (当前总计 {len(current_map)} 条)",
                    "count": success_count,
                    "total": len(current_map)
                })
                return

            if path == "/api/business_ports/add":
                port_raw = req_data.get("port")
                if not port_raw:
                    self._send_json({"success": False, "msg": "端口号不能为空"}, status=400)
                    return
                try:
                    port = int(port_raw)
                    if port < 1 or port > 65535:
                        raise ValueError()
                except Exception:
                    self._send_json({"success": False, "msg": "端口号必须为 1-65535 的整数"}, status=400)
                    return
                name = str(req_data.get("name", f"业务端口 ({port})")).strip()
                category = str(req_data.get("category", "custom")).strip()
                remark = str(req_data.get("remark", "自定义业务")).strip()
                block_scanner = bool(req_data.get("block_scanner", True))
                block_idc = bool(req_data.get("block_idc", False))
                
                cfg = load_config()
                biz_list = cfg.get("business_ports", [])
                
                for bp in biz_list:
                    p = bp if isinstance(bp, int) else int(bp.get("port", 0))
                    if p == port:
                        self._send_json({"success": False, "msg": f"业务端口 {port} 已存在，无需重复添加"}, status=400)
                        return
                        
                biz_list.append({
                    "port": port,
                    "name": name,
                    "category": category,
                    "remark": remark,
                    "block_scanner": block_scanner,
                    "block_idc": block_idc
                })
                cfg["business_ports"] = biz_list
                # 恢复该端口（解除排除）
                excluded = set(int(p) for p in cfg.get("excluded_business_ports", []) if str(p).isdigit())
                if port in excluded:
                    excluded.remove(port)
                    cfg["excluded_business_ports"] = sorted(list(excluded))
                save_config(cfg)
                self._send_json({"success": True, "msg": f"已成功添加正常业务端口: {port} ({name})"})
                return

            if path == "/api/business_ports/edit":
                port_raw = req_data.get("port")
                if not port_raw:
                    self._send_json({"success": False, "msg": "端口号不能为空"}, status=400)
                    return
                try:
                    port = int(port_raw)
                except Exception:
                    self._send_json({"success": False, "msg": "无效端口号"}, status=400)
                    return
                name = str(req_data.get("name", "")).strip()
                category = str(req_data.get("category", "custom")).strip()
                remark = str(req_data.get("remark", "")).strip()
                block_scanner = bool(req_data.get("block_scanner", True))
                block_idc = bool(req_data.get("block_idc", False))
                
                cfg = load_config()
                biz_list = cfg.get("business_ports", [])
                updated = False
                new_list = []
                for bp in biz_list:
                    p = bp if isinstance(bp, int) else int(bp.get("port", 0))
                    if p == port:
                        new_list.append({
                            "port": port,
                            "name": name or (bp.get("name") if isinstance(bp, dict) else f"业务端口 ({port})"),
                            "category": category or (bp.get("category") if isinstance(bp, dict) else "custom"),
                            "remark": remark or (bp.get("remark") if isinstance(bp, dict) else ""),
                            "block_scanner": block_scanner,
                            "block_idc": block_idc
                        })
                        updated = True
                    else:
                        new_list.append(bp)
                if not updated:
                    new_list.append({"port": port, "name": name or f"业务端口 ({port})", "category": category, "remark": remark, "block_scanner": block_scanner, "block_idc": block_idc})
                cfg["business_ports"] = new_list
                # 恢复该端口（解除排除）
                excluded = set(int(p) for p in cfg.get("excluded_business_ports", []) if str(p).isdigit())
                if port in excluded:
                    excluded.remove(port)
                    cfg["excluded_business_ports"] = sorted(list(excluded))
                save_config(cfg)
                self._send_json({"success": True, "msg": f"已成功更新业务端口: {port}"})
                return

            if path == "/api/business_ports/delete":
                port_raw = req_data.get("port")
                if not port_raw:
                    self._send_json({"success": False, "msg": "端口号不能为空"}, status=400)
                    return
                try:
                    port = int(port_raw)
                except Exception:
                    self._send_json({"success": False, "msg": "无效端口号"}, status=400)
                    return
                cfg = load_config()
                # 1. 从自定义业务列表中移除
                biz_list = cfg.get("business_ports", [])
                new_list = [bp for bp in biz_list if (bp != port if isinstance(bp, int) else int(bp.get("port", 0)) != port)]
                cfg["business_ports"] = new_list
                # 2. 将端口记入已排除业务端口集合 (确保系统监听端口也不会再回显)
                excluded = set(int(p) for p in cfg.get("excluded_business_ports", []) if str(p).isdigit())
                excluded.add(port)
                cfg["excluded_business_ports"] = sorted(list(excluded))
                save_config(cfg)
                self._send_json({"success": True, "msg": f"已成功删除业务端口: {port}"})
                return

            if path == "/api/business_ports/import":
                raw_input = req_data.get("data")
                mode = req_data.get("mode", "append")
                if isinstance(raw_input, str):
                    parsed_items = parse_loose_json_or_lines(raw_input)
                elif isinstance(raw_input, list):
                    parsed_items = raw_input
                elif isinstance(raw_input, dict):
                    parsed_items = [raw_input]
                else:
                    parsed_items = []
                    
                if not parsed_items:
                    self._send_json({"success": False, "msg": "未解析到有效的业务端口数据，请检查格式"}, status=400)
                    return
                    
                cfg = load_config()
                current_map = {}
                if mode == "append":
                    for bp in cfg.get("business_ports", []):
                        if isinstance(bp, int):
                            current_map[bp] = {"port": bp, "name": f"业务端口 ({bp})", "category": "custom", "remark": "自定义业务"}
                        elif isinstance(bp, dict) and "port" in bp:
                            current_map[int(bp["port"])] = bp
                            
                count = 0
                for item in parsed_items:
                    p = None
                    name = ""
                    remark = ""
                    cat = "custom"
                    if isinstance(item, int):
                        p = item
                    elif isinstance(item, str):
                        item_s = item.strip()
                        if item_s.isdigit():
                            p = int(item_s)
                        else:
                            parts = item_s.split()
                            if parts and parts[0].isdigit():
                                p = int(parts[0])
                                name = parts[1] if len(parts) > 1 else ""
                                remark = parts[2] if len(parts) > 2 else ""
                    elif isinstance(item, dict):
                        p_raw = item.get("port", item.get("prot", item.get("dst_port")))
                        if p_raw is not None and str(p_raw).isdigit():
                            p = int(p_raw)
                            name = str(item.get("name", item.get("description", ""))).strip()
                            remark = str(item.get("remark", "")).strip()
                            cat = str(item.get("category", "custom")).strip()
                            block_scanner = bool(item.get("block_scanner", True))
                            block_idc = bool(item.get("block_idc", False))
                    if p and 1 <= p <= 65535:
                        current_map[p] = {
                            "port": p,
                            "name": name or f"业务端口 ({p})",
                            "category": cat,
                            "remark": remark or "导入业务",
                            "block_scanner": block_scanner,
                            "block_idc": block_idc
                        }
                        count += 1
                if count == 0:
                    self._send_json({"success": False, "msg": "未能提取到任何合法业务端口（端口必须为 1-65535）"}, status=400)
                    return
                cfg["business_ports"] = list(current_map.values())
                # 导入的端口全部从 excluded_business_ports 解除排除
                excluded = set(int(p) for p in cfg.get("excluded_business_ports", []) if str(p).isdigit())
                for p in current_map.keys():
                    if p in excluded:
                        excluded.remove(p)
                cfg["excluded_business_ports"] = sorted(list(excluded))
                save_config(cfg)
                self._send_json({
                    "success": True,
                    "msg": f"业务端口列表导入成功！共载入 {count} 条 (当前自定义总计 {len(current_map)} 条)",
                    "count": count,
                    "total": len(current_map)
                })
                return

            if path in ("/api/hidden-ips", "/api/hidden_ips"):
                action = req_data.get("action", "add")
                ip = req_data.get("ip", "").strip()
                if not ip:
                    self._send_json({"success": False, "msg": "IP 不能为空"}, status=400)
                    return
                if action == "remove":
                    ok, msg = remove_hidden_ip(ip)
                else:
                    remark = req_data.get("remark", "").strip()
                    ok, msg = add_hidden_ip(ip, remark)
                self._send_json({"success": ok, "msg": msg})
                return

            if path in ("/api/hidden-ips/remove", "/api/hidden_ips/remove", "/api/hidden-ips/delete", "/api/hidden_ips/delete"):
                ip = req_data.get("ip", "").strip()
                if not ip:
                    self._send_json({"success": False, "msg": "IP 不能为空"}, status=400)
                    return
                ok, msg = remove_hidden_ip(ip)
                self._send_json({"success": ok, "msg": msg})
                return

            if path in ("/api/hidden-ips/clear", "/api/hidden_ips/clear"):
                ok, msg = clear_hidden_ips()
                self._send_json({"success": ok, "msg": msg})
                return

            if path in ("/api/hidden-ips/import", "/api/hidden_ips/import"):
                raw_input = req_data.get("data")
                mode = req_data.get("mode", "append")
                if isinstance(raw_input, str):
                    parsed_items = parse_loose_json_or_lines(raw_input)
                elif isinstance(raw_input, list):
                    parsed_items = raw_input
                elif isinstance(raw_input, dict):
                    parsed_items = [raw_input]
                else:
                    parsed_items = []
                    
                if not parsed_items:
                    self._send_json({"success": False, "msg": "未解析到有效的 IP 数据，请检查格式"}, status=400)
                    return
                    
                if mode == "replace":
                    clear_hidden_ips()
                    
                count = 0
                for item in parsed_items:
                    ip = ""
                    remark = ""
                    if isinstance(item, str):
                        item_s = item.strip()
                        parts = item_s.split()
                        if parts:
                            ip = parts[0]
                            remark = parts[1] if len(parts) > 1 else "批量导入隐藏"
                    elif isinstance(item, dict):
                        ip = str(item.get("ip", "")).strip()
                        remark = str(item.get("remark", "批量导入隐藏")).strip()
                    if ip:
                        valid_ip = validate_ip(ip)
                        if valid_ip:
                            ok, _ = add_hidden_ip(valid_ip, remark)
                            if ok:
                                count += 1
                self._send_json({"success": True, "msg": f"成功{'全量覆盖' if mode=='replace' else '增量导入'} {count} 条隐藏 IP 规则"})
                return

            self._send_json({"error": "Not Found"}, status=404)
        except Exception as e:
            import traceback
            traceback.print_exc()
            try:
                self._send_json({"error": str(e)}, status=500)
            except Exception:
                pass

    def do_DELETE(self):
        try:
            parsed = urlparse(self.path)
            path = parsed.path
            length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(length).decode('utf-8') if length > 0 else "{}"
            try:
                req_data = json.loads(body)
            except Exception:
                req_data = {}

            if path in ("/api/hidden-ips", "/api/hidden_ips"):
                ip = req_data.get("ip", "").strip()
                if not ip:
                    query = parse_qs(parsed.query)
                    ip = query.get("ip", [""])[0].strip()
                if not ip:
                    self._send_json({"success": False, "msg": "IP 不能为空"}, status=400)
                    return
                ok, msg = remove_hidden_ip(ip)
                self._send_json({"success": ok, "msg": msg})
                return

            self._send_json({"error": "Not Found"}, status=404)
        except Exception as e:
            self._send_json({"error": str(e)}, status=500)

class ClusterRequestHandler(BaseHTTPRequestHandler):
    """
    专门处理多机网格情报联防的独立安全通信通道 (与 Web UI 完全隔离)
    只接收与处理带有效 HMAC-SHA256 签名的集群指令 (ping, sync_ban, sync_whitelist)
    对任何未授权或非集群请求直接返回 403 Forbidden，不暴露 Web 控制台与登录界面。
    """
    def log_message(self, format, *args):
        pass

    def _send_json(self, data, status=200):
        try:
            body = json.dumps(data, ensure_ascii=False).encode('utf-8')
            self.send_response(status)
            self.send_header('Content-Type', 'application/json; charset=utf-8')
            self.send_header('Content-Length', str(len(body)))
            self.send_header('Server', 'PortGuardMesh/2.0')
            self.end_headers()
            self.wfile.write(body)
        except Exception:
            pass

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        if path == "/api/cluster/ping":
            token = self.headers.get("X-Cluster-Token", "").strip()
            cfg = load_config()
            cluster_cfg = cfg.get("cluster_sync", {})
            secret = cluster_cfg.get("cluster_secret", "").strip()
            if not secret or not verify_cluster_token("ping", token, secret):
                self._send_json({"success": False, "msg": "集群鉴权密钥无效或未配置"}, status=403)
                return
            self._send_json({
                "success": True,
                "node_name": cfg.get("node_name", "远程节点"),
                "version": "2.0.0"
            })
            return
        self._send_json({"error": "Forbidden: Dedicated PortGuard Cluster Channel"}, status=403)

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path
        try:
            length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(length).decode('utf-8') if length > 0 else "{}"
            try:
                req_data = json.loads(body)
            except Exception:
                req_data = {}

            if path == "/api/cluster/ping":
                token = self.headers.get("X-Cluster-Token", "").strip()
                cfg = load_config()
                cluster_cfg = cfg.get("cluster_sync", {})
                secret = cluster_cfg.get("cluster_secret", "").strip()
                if not secret or not verify_cluster_token("ping", token, secret):
                    self._send_json({"success": False, "msg": "集群鉴权密钥无效或未配置"}, status=403)
                    return
                self._send_json({
                    "success": True,
                    "node_name": cfg.get("node_name", "远程节点"),
                    "version": "2.0.0"
                })
                return

            if path == "/api/cluster/sync_ban":
                token = self.headers.get("X-Cluster-Token", "").strip()
                cfg = load_config()
                cluster_cfg = cfg.get("cluster_sync", {})
                secret = cluster_cfg.get("cluster_secret", "").strip()

                ip = req_data.get("ip", "").strip()
                reason = req_data.get("reason", "集群威胁同步").strip()
                level = req_data.get("level", "极高危").strip()
                source_node = req_data.get("source_node", "远程探针").strip()

                if not verify_cluster_token(ip, token, secret):
                    self._send_json({"success": False, "msg": "集群鉴权签名无效"}, status=403)
                    return

                valid_ip = validate_ip(ip)
                if not valid_ip:
                    self._send_json({"success": False, "msg": "IP格式不合法"}, status=400)
                    return
                ip = valid_ip

                if ip_in_whitelist(ip):
                    self._send_json({"success": True, "msg": "本地白名单已忽略"})
                    return

                ban_ip_firewall(ip)
                now_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
                now_ts = int(time.time())
                auto_clean_days = int(cfg.get("auto_clean_days", 30) or 30)
                ban_expire = now_ts + auto_clean_days * 86400 if auto_clean_days > 0 else None

                geo_country = req_data.get("country") or ""
                geo_region = req_data.get("region") or ""
                geo_city = req_data.get("city") or ""
                geo_isp = req_data.get("isp") or ""

                if not geo_country or geo_country in ("集群联防", "公网节点", "未知地域", ""):
                    geo = resolve_ip_geo(ip) or {}
                    geo_country = geo.get("country") or "公网探测"
                    geo_region = geo.get("region") or ""
                    geo_city = geo.get("city") or ""
                    geo_isp = geo.get("isp") or ""

                synced_port = int(req_data.get("port") or 443)
                synced_proto = str(req_data.get("proto") or "TCP").upper()
                synced_category = req_data.get("category") or "mesh"

                conn = get_db()
                c = conn.cursor()
                c.execute("""
                INSERT OR REPLACE INTO blacklist (ip, reason, country, level, ban_time, timestamp, ban_expire, source_node)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (ip, f"[{source_node}联防] {reason}", geo_country, level, now_str, now_ts, ban_expire, f"集群 ({source_node})"))
                c.execute("""
                INSERT INTO events (ip, port, proto, port_name, category, level, country, region, city, isp, attack_time, timestamp, status)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'BANNED')
                """, (ip, synced_port, synced_proto, f"[{source_node}联防] {reason}", synced_category, level, geo_country, geo_region, geo_city, geo_isp, now_str, now_ts))
                conn.commit()
                conn.close()

                _EXECUTOR.submit(resolve_ip_geo, ip)
                self._send_json({"success": True, "msg": f"已完成集群同步封禁: {ip}"})
                return

            if path == "/api/cluster/sync_unban":
                token = self.headers.get("X-Cluster-Token", "").strip()
                cfg = load_config()
                cluster_cfg = cfg.get("cluster_sync", {})
                secret = cluster_cfg.get("cluster_secret", "").strip()

                ip = req_data.get("ip", "").strip()
                if not verify_cluster_token(f"unban_{ip}", token, secret):
                    self._send_json({"success": False, "msg": "集群鉴权签名无效"}, status=403)
                    return

                valid_ip = validate_ip(ip)
                if not valid_ip:
                    self._send_json({"success": False, "msg": "IP格式不合法"}, status=400)
                    return
                source_node = req_data.get("source_node", "协同节点").strip()
                unban_ip_core(valid_ip, status_event="UNBANNED", source_node=f"集群解封({source_node})")
                self._send_json({"success": True, "msg": f"已协同解封: {valid_ip}"})
                return

            if path == "/api/cluster/sync_state_exchange":
                token = self.headers.get("X-Cluster-Token", "").strip()
                cfg = load_config()
                cluster_cfg = cfg.get("cluster_sync", {})
                secret = cluster_cfg.get("cluster_secret", "").strip()
                if not verify_cluster_token("sync_state_exchange", token, secret):
                    self._send_json({"success": False, "msg": "集群鉴权签名无效"}, status=403)
                    return

                source_node = req_data.get("source_node", "远程节点").strip()
                remote_bans = req_data.get("blacklist", [])
                remote_unbanned = req_data.get("unbanned_list", [])
                remote_whites = req_data.get("whitelist", [])

                conn = get_db()
                c = conn.cursor()
                c.execute("CREATE TABLE IF NOT EXISTS unbanned_ips (ip TEXT PRIMARY KEY, unban_time TEXT, timestamp INTEGER, source_node TEXT)")
                c.execute("SELECT ip, reason, country, level, ban_time, timestamp, ban_expire, source_node FROM blacklist")
                local_rows = c.fetchall()
                local_bans_map = { r[0]: { "ip": r[0], "reason": r[1], "country": r[2], "level": r[3], "ban_time": r[4], "timestamp": r[5], "ban_expire": r[6], "source_node": r[7] } for r in local_rows }
                c.execute("SELECT ip, unban_time, timestamp, source_node FROM unbanned_ips")
                local_unbanned_rows = c.fetchall()
                local_unbanned_map = { r[0]: int(r[2] or 0) for r in local_unbanned_rows if r[0] }

                # 1. 优先对齐远端发来的解封墓碑
                for ru in remote_unbanned:
                    ru_ip = validate_ip(ru.get("ip", ""))
                    ru_ts = int(ru.get("timestamp", 0) or 0)
                    if ru_ip:
                        if ru_ip in local_bans_map:
                            local_ban_ts = int(local_bans_map[ru_ip].get("timestamp", 0) or 0)
                            if ru_ts >= local_ban_ts:
                                unban_ip_core(ru_ip, status_event="UNBANNED", source_node=f"集群同步({source_node})")
                        local_unbanned_map[ru_ip] = ru_ts
                        c.execute("""
                        INSERT OR REPLACE INTO unbanned_ips (ip, unban_time, timestamp, source_node)
                        VALUES (?, ?, ?, ?)
                        """, (ru_ip, ru.get("unban_time", time.strftime("%Y-%m-%d %H:%M:%S")), ru_ts, f"集群同步({source_node})"))

                # 2. 吸纳对方有而本地没有的黑名单 (比对解封墓碑)
                added_bans = 0
                now_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
                now_ts = int(time.time())
                for rb in remote_bans:
                    rb_ip = validate_ip(rb.get("ip", ""))
                    if not rb_ip or ip_in_whitelist(rb_ip):
                        continue
                    rb_ts = int(rb.get("timestamp", 0) or 0)
                    local_unban_ts = local_unbanned_map.get(rb_ip)
                    if local_unban_ts is not None and local_unban_ts >= rb_ts:
                        continue

                    if rb_ip not in local_bans_map:
                        ban_ip_firewall(rb_ip)
                        src = rb.get("source_node", source_node)
                        geo_country = rb.get("country")
                        if not geo_country or geo_country in ("集群联防", "未知地域", "公网节点", ""):
                            geo = resolve_ip_geo(rb_ip) or {}
                            geo_country = geo.get("country") or "公网探测"

                        c.execute("""
                        INSERT OR REPLACE INTO blacklist (ip, reason, country, level, ban_time, timestamp, ban_expire, source_node)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                        """, (
                            rb_ip, rb.get("reason", f"[{source_node}对齐] 威胁同步"), geo_country,
                            rb.get("level", "极高危"), rb.get("ban_time", now_str),
                            rb.get("timestamp", rb_ts or now_ts), rb.get("ban_expire"), f"集群 ({src})"
                        ))
                        c.execute("DELETE FROM unbanned_ips WHERE ip = ?", (rb_ip,))
                        _EXECUTOR.submit(resolve_ip_geo, rb_ip)
                        added_bans += 1
                conn.commit()
                conn.close()

                # 3. 合并白名单
                whitelist = cfg.get("whitelist", [])
                w_map = { (w.get("ip") if isinstance(w, dict) else w): (w if isinstance(w, dict) else {"ip": w, "remark": "信任IP"}) for w in whitelist }
                added_whites = 0
                for rw in remote_whites:
                    rw_ip = validate_ip(rw.get("ip") if isinstance(rw, dict) else rw)
                    if not rw_ip:
                        continue
                    unban_ip_core(rw_ip, status_event="WHITELIST")
                    rw_rem = rw.get("remark", "集群对齐白名单") if isinstance(rw, dict) else "集群对齐白名单"
                    if rw_ip not in w_map:
                        w_map[rw_ip] = {"ip": rw_ip, "remark": rw_rem}
                        added_whites += 1
                cfg["whitelist"] = list(w_map.values())
                save_config(cfg)

                # 返回本地独有的黑名单、解封墓碑与白名单给发起端
                remote_ban_ips = { rb.get("ip") for rb in remote_bans if rb.get("ip") }
                missing_for_remote_bans = [ b for ip_k, b in local_bans_map.items() if ip_k not in remote_ban_ips and ip_k not in local_unbanned_map ]

                remote_white_ips = { (w.get("ip") if isinstance(w, dict) else w) for w in remote_whites if (w.get("ip") if isinstance(w, dict) else w) }
                missing_for_remote_whites = [ w for ip_k, w in w_map.items() if ip_k not in remote_white_ips ]

                # 本地解封墓碑数据
                local_unbanned_resp = [
                    { "ip": r[0], "unban_time": r[1], "timestamp": r[2], "source_node": r[3] }
                    for r in local_unbanned_rows if r[0]
                ]

                self._send_json({
                    "success": True,
                    "added_bans": added_bans,
                    "added_whites": added_whites,
                    "remote_blacklist": missing_for_remote_bans,
                    "remote_unbanned": local_unbanned_resp,
                    "remote_whitelist": missing_for_remote_whites
                })
                return

            if path == "/api/cluster/sync_whitelist":
                token = self.headers.get("X-Cluster-Token", "").strip()
                cfg = load_config()
                cluster_cfg = cfg.get("cluster_sync", {})
                secret = cluster_cfg.get("cluster_secret", "").strip()

                action = req_data.get("action", "add").strip()
                data = req_data.get("data")
                remark = req_data.get("remark", "集群协同白名单").strip()
                source_node = req_data.get("source_node", "远程节点").strip()

                sign_target = f"whitelist_{action}"
                if not verify_cluster_token(sign_target, token, secret):
                    self._send_json({"success": False, "msg": "集群鉴权签名无效"}, status=403)
                    return

                whitelist = cfg.get("whitelist", [])

                if action == "add":
                    ip = str(data or "").strip()
                    valid_ip = validate_ip(ip)
                    if not valid_ip:
                        self._send_json({"success": False, "msg": "IP 格式不合法"}, status=400)
                        return
                    ip = valid_ip
                    unban_ip_core(ip, status_event="WHITELIST")
                    if not any(w.get("ip") == ip if isinstance(w, dict) else w == ip for w in whitelist):
                        node_remark = f"[{source_node}联防] {remark}" if not str(remark).startswith(f"[{source_node}") else remark
                        whitelist.append({"ip": ip, "remark": node_remark})
                        cfg["whitelist"] = whitelist
                        save_config(cfg)
                    self._send_json({"success": True, "msg": f"已成功同步添加白名单: {ip}"})
                    return

                elif action == "delete":
                    ip = str(data or "").strip()
                    whitelist = [w for w in whitelist if (w.get("ip") if isinstance(w, dict) else w) != ip]
                    cfg["whitelist"] = whitelist
                    save_config(cfg)
                    self._send_json({"success": True, "msg": f"已成功同步移除白名单: {ip}"})
                    return

                elif action in ("batch_add", "sync_all"):
                    items = data if isinstance(data, list) else []
                    updated_cnt = 0
                    current_map = {}
                    for w in whitelist:
                        w_ip = w.get("ip") if isinstance(w, dict) else w
                        if w_ip:
                            current_map[w_ip] = w if isinstance(w, dict) else {"ip": w_ip, "remark": "信任IP"}

                    for it in items:
                        if isinstance(it, dict):
                            it_ip = str(it.get("ip", "")).strip()
                            it_rem = str(it.get("remark", remark)).strip()
                        else:
                            it_ip = str(it).strip()
                            it_rem = remark
                        v_ip = validate_ip(it_ip)
                        if not v_ip:
                            continue
                        unban_ip_core(v_ip, status_event="WHITELIST")
                        node_rem = f"[{source_node}联防] {it_rem}" if not it_rem.startswith(f"[{source_node}") else it_rem
                        if v_ip not in current_map:
                            current_map[v_ip] = {"ip": v_ip, "remark": node_rem}
                            updated_cnt += 1

                    cfg["whitelist"] = list(current_map.values())
                    save_config(cfg)
                    self._send_json({"success": True, "msg": f"已批量同步 {updated_cnt} 条协同白名单", "count": updated_cnt})
                    return

                self._send_json({"success": False, "msg": "未知的白名单同步操作"}, status=400)
                return

            self._send_json({"error": "Forbidden: Dedicated PortGuard Cluster Channel"}, status=403)
        except Exception as e:
            self._send_json({"error": str(e)}, status=500)

def run_server():
    init_db()
    cfg = load_config()
    bind_ip = cfg.get("web_bind", "0.0.0.0")
    bind_port = int(cfg.get("web_port", 9099))
    cluster_port = int(cfg.get("cluster_sync", {}).get("port", 9098) or 9098)

    ThreadingHTTPServer.allow_reuse_address = True
    httpd = ThreadingHTTPServer((bind_ip, bind_port), RequestHandler)
    print(f"[PortGuard Full-Responsive] 控制台已就绪: http://{bind_ip}:{bind_port}")

    # 若配置了独立于 WebUI 的集群通信端口，启动轻量级独立集群通信服务
    if cluster_port > 0 and cluster_port != bind_port:
        try:
            cluster_httpd = ThreadingHTTPServer((bind_ip, cluster_port), ClusterRequestHandler)
            print(f"[PortGuard Mesh] 独立集群联防通信服务已就绪: http://{bind_ip}:{cluster_port}")
            threading.Thread(target=cluster_httpd.serve_forever, daemon=True).start()
        except Exception as e:
            print(f"[PortGuard Mesh] 独立集群通信服务端口 ({cluster_port}) 启动异常: {e}")
    
    trap_instance.start()
    sniffer_instance.start()
    site_collector_instance.start()
    cleanup_expired_bans()
    # 启动多机集群黑白名单全量双向定时自动对齐巡检
    start_cluster_autosync_worker()

    # 后台平滑增量重放黑名单到 iptables / 黑洞路由（彻底杜绝进程风暴与 CPU 脉冲）
    def _async_replay_blacklist():
        try:
            init_firewall_ipset()
            print("[PortGuard] 异步完成内核 ipset 黑名单规则初始化与加载")
        except Exception as e:
            print(f"[PortGuard] 黑名单初始化失败: {e}")
    threading.Thread(target=_async_replay_blacklist, daemon=True).start()
    
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    sniffer_instance.stop()
    httpd.server_close()

if __name__ == "__main__":
    run_server()
