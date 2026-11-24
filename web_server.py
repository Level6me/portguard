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
_AUTH_SESSIONS = {}  # token -> expire_ts
_AUTH_LOCK = threading.Lock()
MAX_AUTH_SESSIONS = 1024

_CLUSTER_PEER_GET_ENDPOINTS = {"/api/cluster/ping"}
_CLUSTER_PEER_POST_ENDPOINTS = {
    "/api/cluster/ping",
    "/api/cluster/sync_ban",
    "/api/cluster/sync_unban",
    "/api/cluster/sync_whitelist",
    "/api/cluster/sync_state_exchange",
}

from controllers import dispatch_get, dispatch_post, dispatch_delete
from sentry_daemon import (
    DB_PATH, CONFIG_PATH, load_config, save_config, get_db, init_db,
    trap_instance, sniffer_instance, site_collector_instance, DEFAULT_CONFIG, PORT_DESCRIPTIONS,
    DEFAULT_HTTP_TRAPS, get_http_traps, check_http_request_traps,
    normalize_trap_item, log_access_entry, validate_ip, run_firewall_cmd,
    cleanup_expired_bans, cleanup_loop, config_watcher_loop, ip_in_whitelist, resolve_ip_geo, resolve_ip_geo_local, _GEO_CACHE, _EXECUTOR,
    get_hidden_ips, get_hidden_ips_set, add_hidden_ip, remove_hidden_ip, clear_hidden_ips,
    get_all_business_ports_info, get_active_system_ports, unban_ip_core,
    ban_ip_firewall, batch_ban_ip_firewall, get_compiled_whitelist, init_firewall_ipset, flush_firewall_blocks, verify_cluster_token, generate_cluster_token, ban_ip,
    normalize_cluster_node, broadcast_cluster_whitelist, broadcast_cluster_ban,
    broadcast_cluster_unban, sync_cluster_mesh_state, start_cluster_autosync_worker,
    get_ip_threat_tags, get_config_snapshots, rollback_config_snapshot, check_c2_compromise_connections,
    generate_cluster_response_token, verify_cluster_response_token, safe_cluster_urlopen,
    auto_heal_whitelist_ips, start_listen_port_watcher, start_feishu_ws
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
                html = html.replace(
                    '<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>',
                    '<script src="/chart.min.js"></script>'
                )
            _HTML_TEMPLATE_CACHE = html
            _HTML_TEMPLATE_MTIME = mtime
            _RAW_HTML_CACHE = html.encode("utf-8")
            _GZIP_HTML_CACHE = gzip.compress(_RAW_HTML_CACHE, compresslevel=6)
            return html
        except Exception:
            pass
    return _HTML_TEMPLATE_CACHE or "<h1>PortGuard 模板文件缺失，请检查 templates/index.html</h1>"

HTML_TEMPLATE = load_html_template()

_RAW_CHART_CACHE = None
_GZIP_CHART_CACHE = None
chart_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "chart.min.js")
if os.path.exists(chart_file):
    try:
        with open(chart_file, "rb") as f:
            _RAW_CHART_CACHE = f.read()
        _GZIP_CHART_CACHE = gzip.compress(_RAW_CHART_CACHE, compresslevel=6)
    except Exception:
        pass

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

def _extract_host_only(host_hdr):
    """从 Host 请求头安全提取纯主机名（兼容 IPv4、域名与带括号 [IPv6]:port）"""
    h = (host_hdr or "").strip()
    if not h:
        return ""
    if h.startswith("["):
        if "]:" in h:
            return h[1:].split("]:", 1)[0].lower()
        return h.strip("[]").lower()
    if h.count(":") == 1:
        return h.split(":", 1)[0].lower()
    return h.lower()

class RequestHandler(BaseHTTPRequestHandler):
    def _get_real_client_ip(self):
        """安全提取客户端真实 IP：仅当直连来源是本机回环或 config.json 中显式配置的 trusted_proxies 时，才解析反代头，杜绝局域网/容器内任意节点伪造反代头触发反射误封"""
        direct_ip = self.client_address[0].replace("::ffff:", "")
        is_trusted_proxy = False
        if direct_ip in ("127.0.0.1", "::1", "localhost") or direct_ip.startswith("127."):
            is_trusted_proxy = True
        else:
            try:
                trusted_list = load_config().get("trusted_proxies", []) or []
                if trusted_list:
                    d_addr = ipaddress.ip_address(direct_ip)
                    for tp in trusted_list:
                        tp_str = str(tp or "").strip()
                        if not tp_str:
                            continue
                        if "/" in tp_str:
                            tp_net = ipaddress.ip_network(tp_str, strict=False)
                            if d_addr.version == tp_net.version and d_addr in tp_net:
                                is_trusted_proxy = True
                                break
                        elif direct_ip == tp_str:
                            is_trusted_proxy = True
                            break
            except Exception:
                pass

        if is_trusted_proxy:
            cf_ip = self.headers.get("CF-Connecting-IP", "").strip()
            v_cf = validate_ip(cf_ip)
            if v_cf and "/" not in v_cf:
                return v_cf
            x_real = self.headers.get("X-Real-IP", "").strip()
            v_real = validate_ip(x_real)
            if v_real and "/" not in v_real:
                return v_real
            xff = self.headers.get("X-Forwarded-For", "").strip()
            if xff:
                for cand in reversed([x.strip() for x in xff.split(",")]):
                    v_cand = validate_ip(cand)
                    if v_cand and "/" not in v_cand:
                        return v_cand
        return direct_ip

    def send_response(self, code, message=None):
        self._resp_started = True
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
                origin_host = (parsed_origin.hostname or '').strip('[]').lower()
                req_host = _extract_host_only(host)
                if req_host and origin_host and origin_host == req_host:
                    self.send_header('Access-Control-Allow-Origin', origin)
                    self.send_header('Access-Control-Allow-Credentials', 'true')
                    self.send_header('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS')
                    self.send_header('Access-Control-Allow-Headers', 'Content-Type, X-Requested-With, X-Cluster-Token')
                    self.send_header('Access-Control-Expose-Headers', 'X-Cluster-Response-Token')
            self.send_header('X-Content-Type-Options', 'nosniff')
            self.send_header('X-Frame-Options', 'SAMEORIGIN')
            self.send_header('Referrer-Policy', 'strict-origin-when-cross-origin')
            self.send_header('Cache-Control', 'no-cache, no-store, must-revalidate, max-age=0')
            self.send_header('Pragma', 'no-cache')
            self.send_header('Expires', '0')
            if hasattr(self, 'path') and self.path and self.path.startswith("/api/cluster/"):
                cfg = load_config()
                secret = cfg.get("cluster_sync", {}).get("cluster_secret", "").strip()
                if secret:
                    req_token = self.headers.get("X-Cluster-Token", "").strip()
                    resp_token = generate_cluster_response_token(secret, body=data_bytes, req_token=req_token)
                    self.send_header('X-Cluster-Response-Token', resp_token)
            
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

    def _create_auth_session(self):
        token = os.urandom(24).hex()
        with _AUTH_LOCK:
            now = time.time()
            expired = [t for t, exp in _AUTH_SESSIONS.items() if exp < now]
            for t in expired:
                _AUTH_SESSIONS.pop(t, None)
            if len(_AUTH_SESSIONS) >= MAX_AUTH_SESSIONS:
                oldest = sorted(_AUTH_SESSIONS.items(), key=lambda x: x[1])[:len(_AUTH_SESSIONS) - MAX_AUTH_SESSIONS + 1]
                for t, _ in oldest:
                    _AUTH_SESSIONS.pop(t, None)
            _AUTH_SESSIONS[token] = now + 7 * 86400
        return token

    def _verify_same_origin(self):
        """CSRF 防护：校验浏览器携带的 Origin / Referer 是否与当前 Host 同源"""
        origin = (self.headers.get("Origin") or "").strip()
        host = (self.headers.get("Host") or "").strip()
        if not host:
            return True
        req_host = _extract_host_only(host)
        if origin:
            if origin.lower() == "null":
                return False
            origin_host = (urlparse(origin).hostname or "").strip("[]").lower()
            return bool(origin_host and origin_host == req_host)
        referer = (self.headers.get("Referer") or "").strip()
        if referer:
            ref_host = (urlparse(referer).hostname or "").strip("[]").lower()
            return bool(ref_host and ref_host == req_host)
        return True

    def _destroy_auth_session(self):
        token = self._get_session_token()
        if token:
            with _AUTH_LOCK:
                _AUTH_SESSIONS.pop(token, None)

    def _get_session_token(self):
        cookie = self.headers.get("Cookie", "")
        if cookie:
            for part in cookie.split(";"):
                if "=" in part:
                    k, v = part.strip().split("=", 1)
                    if k.strip() == "portguard_session":
                        return v.strip()
        auth_header = self.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            return auth_header[7:].strip()
        token_hdr = self.headers.get("X-Auth-Token", "").strip()
        if token_hdr:
            return token_hdr
        return ""

    def _is_request_authenticated(self):
        cfg = load_config()
        if not bool(cfg.get("auth_enabled", False)):
            return True
        admin_pwd = str(cfg.get("admin_password", "")).strip()
        if not admin_pwd:
            return True
        token = self._get_session_token()
        if not token:
            return False
        with _AUTH_LOCK:
            exp = _AUTH_SESSIONS.get(token)
            if exp and exp > time.time():
                return True
            if exp:
                _AUTH_SESSIONS.pop(token, None)
        return False

    def do_OPTIONS(self):
        self._send_response_data(b"", status=204)

    def do_HEAD(self):
        parsed = urlparse(self.path)
        path = parsed.path
        if path == "/chart.min.js":
            if _RAW_CHART_CACHE:
                accept_encoding = self.headers.get('Accept-Encoding', '')
                self.send_response(200)
                self.send_header('Content-Type', 'application/javascript; charset=utf-8')
                self.send_header('Cache-Control', 'public, max-age=31536000, immutable')
                if 'gzip' in accept_encoding and _GZIP_CHART_CACHE:
                    self.send_header('Content-Encoding', 'gzip')
                    self.send_header('Content-Length', str(len(_GZIP_CHART_CACHE)))
                else:
                    self.send_header('Content-Length', str(len(_RAW_CHART_CACHE)))
                self.end_headers()
                return
            self.send_response(404)
            self.end_headers()
            return
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
            if path == "/chart.min.js":
                if _RAW_CHART_CACHE:
                    accept_encoding = self.headers.get('Accept-Encoding', '')
                    self.send_response(200)
                    self.send_header('Content-Type', 'application/javascript; charset=utf-8')
                    self.send_header('Cache-Control', 'public, max-age=31536000, immutable')
                    if 'gzip' in accept_encoding and _GZIP_CHART_CACHE:
                        self.send_header('Content-Encoding', 'gzip')
                        self.send_header('Content-Length', str(len(_GZIP_CHART_CACHE)))
                        self.end_headers()
                        self.wfile.write(_GZIP_CHART_CACHE)
                    else:
                        self.send_header('Content-Length', str(len(_RAW_CHART_CACHE)))
                        self.end_headers()
                        self.wfile.write(_RAW_CHART_CACHE)
                    return
                self.send_response(404)
                self.end_headers()
                return

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
                client_ip = self._get_real_client_ip()
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

            if path == "/api/auth/status" or path in _CLUSTER_PEER_GET_ENDPOINTS:
                pass
            elif path.startswith("/api/"):
                if not self._is_request_authenticated():
                    self._send_json({"error": "Unauthorized", "auth_required": True, "msg": "控制台安全登录已启用，请先登录"}, status=401)
                    return

            if dispatch_get(self, parsed):
                return

            self._send_json({"error": "Not Found"}, status=404)
        except Exception:
            import traceback
            traceback.print_exc()
            if not getattr(self, "_resp_started", False):
                try:
                    self._send_json({"error": "Internal Server Error", "msg": "服务器内部处理异常"}, status=500)
                except Exception:
                    pass

    def do_POST(self):
        try:
            parsed = urlparse(self.path)
            path = parsed.path
            try:
                length = int(self.headers.get('Content-Length', 0))
            except Exception:
                length = 0
            if length < 0:
                self._send_json({"error": "Bad Request: 非法的 Content-Length"}, status=400)
                return
            if length > MAX_BODY_SIZE:
                self._send_json({"error": "Payload Too Large: 请求体大小超出限制 (最大 10MB)"}, status=413)
                return
            raw_body_bytes = self.rfile.read(length) if length > 0 else b""
            self.raw_body = raw_body_bytes
            body = raw_body_bytes.decode('utf-8', errors='ignore') if raw_body_bytes else "{}"
            try:
                req_data = json.loads(body)
            except Exception:
                req_data = {}

            if path in ("/api/auth/login", "/api/auth/logout") or path in _CLUSTER_PEER_POST_ENDPOINTS:
                pass
            elif path.startswith("/api/"):
                if not self._is_request_authenticated():
                    self._send_json({"error": "Unauthorized", "auth_required": True, "msg": "控制台安全登录已启用，请先登录"}, status=401)
                    return
                if not self._verify_same_origin():
                    self._send_json({"error": "Forbidden", "msg": "CSRF 安全拦截：跨站请求来源不一致"}, status=403)
                    return

            if dispatch_post(self, parsed, req_data):
                return

            self._send_json({"error": "Not Found"}, status=404)
        except Exception:
            import traceback
            traceback.print_exc()
            if not getattr(self, "_resp_started", False):
                try:
                    self._send_json({"error": "Internal Server Error", "msg": "服务器内部处理异常"}, status=500)
                except Exception:
                    pass

    def do_DELETE(self):
        try:
            parsed = urlparse(self.path)
            try:
                length = int(self.headers.get('Content-Length', 0))
            except Exception:
                length = 0
            if length < 0:
                self._send_json({"error": "Bad Request: 非法的 Content-Length"}, status=400)
                return
            if length > MAX_BODY_SIZE:
                self._send_json({"error": "Payload Too Large: 请求体大小超出限制 (最大 10MB)"}, status=413)
                return
            raw_body_bytes = self.rfile.read(length) if length > 0 else b""
            self.raw_body = raw_body_bytes
            body = raw_body_bytes.decode('utf-8', errors='ignore') if raw_body_bytes else "{}"
            try:
                req_data = json.loads(body)
            except Exception:
                req_data = {}

            path = parsed.path
            if path.startswith("/api/"):
                if not self._is_request_authenticated():
                    self._send_json({"error": "Unauthorized", "auth_required": True, "msg": "控制台安全登录已启用，请先登录"}, status=401)
                    return
                if not self._verify_same_origin():
                    self._send_json({"error": "Forbidden", "msg": "CSRF 安全拦截：跨站请求来源不一致"}, status=403)
                    return

            if dispatch_delete(self, parsed, req_data):
                return

            self._send_json({"error": "Not Found"}, status=404)
        except Exception:
            import traceback
            traceback.print_exc()
            if not getattr(self, "_resp_started", False):
                try:
                    self._send_json({"error": "Internal Server Error", "msg": "服务器内部处理异常"}, status=500)
                except Exception:
                    pass


_CLUSTER_SERVER_SYNC_LOCK = threading.Lock()

class ClusterRequestHandler(BaseHTTPRequestHandler):
    """
    专门处理多机网格情报联防的独立安全通信通道 (与 Web UI 完全隔离)：
    统一复用 controllers.cluster_controller 中的单一权威集群逻辑，彻底消除 9098/9099 双轨分叉。
    """
    def log_message(self, format, *args):
        pass

    def send_response(self, code, message=None):
        self._resp_started = True
        super().send_response(code, message)

    def _send_json(self, data, status=200):
        try:
            body = json.dumps(data, ensure_ascii=False).encode('utf-8')
            self.send_response(status)
            self.send_header('Content-Type', 'application/json; charset=utf-8')
            self.send_header('Content-Length', str(len(body)))
            self.send_header('Server', 'PortGuardMesh/2.0')
            cfg = load_config()
            secret = cfg.get("cluster_sync", {}).get("cluster_secret", "").strip()
            if secret:
                req_token = self.headers.get("X-Cluster-Token", "").strip()
                resp_token = generate_cluster_response_token(secret, body=body, req_token=req_token)
                self.send_header('X-Cluster-Response-Token', resp_token)
            self.end_headers()
            self.wfile.write(body)
        except Exception:
            pass

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path in _CLUSTER_PEER_GET_ENDPOINTS:
            from controllers.cluster_controller import handle_cluster_ping
            handle_cluster_ping(self, parsed, None)
            return
        self._send_json({"error": "Forbidden: Dedicated PortGuard Cluster Channel"}, status=403)

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path
        try:
            try:
                length = int(self.headers.get('Content-Length', 0))
            except Exception:
                length = 0
            if length < 0:
                self._send_json({"error": "Bad Request: 非法的 Content-Length"}, status=400)
                return
            if length > MAX_BODY_SIZE:
                self._send_json({"error": "Payload Too Large: 集群请求体大小超出限制 (最大 10MB)"}, status=413)
                return
            raw_body_bytes = self.rfile.read(length) if length > 0 else b""
            self.raw_body = raw_body_bytes
            body = raw_body_bytes.decode('utf-8', errors='ignore') if raw_body_bytes else "{}"
            try:
                req_data = json.loads(body)
            except Exception:
                req_data = {}

            if path in _CLUSTER_PEER_POST_ENDPOINTS and dispatch_post(self, parsed, req_data):
                return

            self._send_json({"error": "Forbidden: Dedicated PortGuard Cluster Channel"}, status=403)
        except Exception:
            import traceback
            traceback.print_exc()
            if not getattr(self, "_resp_started", False):
                self._send_json({"error": "Internal Server Error"}, status=500)

def run_server():
    from sentry_daemon import _ensure_batch_log_worker
    init_db()
    _ensure_batch_log_worker()
    cfg = load_config()
    try:
        healed = auto_heal_whitelist_ips()
        if healed > 0:
            print(f"[PortGuard] 启动自愈：已成功将 {healed} 个误阻断白名单目标从内核与防火墙解封")
    except Exception as e:
        print(f"[PortGuard] 启动自愈异常: {e}")
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
    # 后台异步执行过期清理与日志归档瘦身，避免阻塞 Web 服务端口响应
    threading.Thread(target=cleanup_expired_bans, daemon=True, name="StartupCleanup").start()
    # 启动后台自动清理守护线程 (定期清理过期黑名单/过期日志/VACUUM) 与配置变动热加载线程
    threading.Thread(target=cleanup_loop, daemon=True, name="CleanupLoop").start()
    threading.Thread(target=config_watcher_loop, daemon=True, name="ConfigWatcherLoop").start()
    # 启动多机集群黑白名单全量双向定时自动对齐巡检
    start_cluster_autosync_worker()
    # 启动内核新增监听端口自动感知与告警守护线程
    start_listen_port_watcher()
    # 启动飞书应用机器人长连接守护 (WebSocket)
    try:
        start_feishu_ws(cfg)
    except Exception as e:
        print(f"[PortGuard] 启动飞书长连接异常: {e}")

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
