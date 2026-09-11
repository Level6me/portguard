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
from controllers import dispatch_get, dispatch_post, dispatch_delete
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

MAX_BODY_SIZE = 10 * 1024 * 1024  # 10MB 请求体上限，防大包内存 DoS 攻击

class RequestHandler(BaseHTTPRequestHandler):
    def _get_real_client_ip(self):
        """安全提取客户端真实 IP：若是本地反向代理发起的请求，优先提取受信任的反代头 (CF-Connecting-IP / X-Real-IP / X-Forwarded-For)"""
        direct_ip = self.client_address[0].replace("::ffff:", "")
        # 仅当直连来源是本机回环/私网（如 1Panel/Nginx 反代服务器）时才信任反代头
        if direct_ip in ("127.0.0.1", "::1", "localhost") or direct_ip.startswith("127.") or direct_ip.startswith("10.") or direct_ip.startswith("192.168.") or direct_ip.startswith("172."):
            cf_ip = self.headers.get("CF-Connecting-IP", "").strip()
            if cf_ip and validate_ip(cf_ip):
                return cf_ip
            x_real = self.headers.get("X-Real-IP", "").strip()
            if x_real and validate_ip(x_real):
                return x_real
            xff = self.headers.get("X-Forwarded-For", "").strip()
            if xff:
                first_ip = xff.split(",")[0].strip()
                if validate_ip(first_ip):
                    return first_ip
        return direct_ip

    def send_response(self, code, message=None):
        # 在响应层统一记录访问日志：真实状态码、覆盖 GET/POST/HEAD/OPTIONS/404/400 等全部请求
        super().send_response(code, message)
        try:
            client_ip = self._get_real_client_ip()
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
                    "Disallow: /.env_backup/\n"
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

            if dispatch_get(self, parsed):
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
            length = int(self.headers.get('Content-Length', 0))
            if length > MAX_BODY_SIZE:
                self._send_json({"error": "Payload Too Large: 请求体大小超出限制 (最大 10MB)"}, status=413)
                return
            body = self.rfile.read(length).decode('utf-8') if length > 0 else "{}"
            try:
                req_data = json.loads(body)
            except Exception:
                req_data = {}

            if dispatch_post(self, parsed, req_data):
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
            length = int(self.headers.get('Content-Length', 0))
            if length > MAX_BODY_SIZE:
                self._send_json({"error": "Payload Too Large: 请求体大小超出限制 (最大 10MB)"}, status=413)
                return
            body = self.rfile.read(length).decode('utf-8') if length > 0 else "{}"
            try:
                req_data = json.loads(body)
            except Exception:
                req_data = {}

            if dispatch_delete(self, parsed, req_data):
                return

            self._send_json({"error": "Not Found"}, status=404)
        except Exception as e:
            import traceback
            traceback.print_exc()
            try:
                self._send_json({"error": str(e)}, status=500)
            except Exception:
                pass


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
                conn.close()

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

                # 2. 吸纳对方有而本地没有的黑名单 (比对解封墓碑)
                added_bans = 0
                now_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
                now_ts = int(time.time())
                
                conn = get_db()
                c = conn.cursor()
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
