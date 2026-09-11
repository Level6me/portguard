#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PortGuard Core Mesh & Distributed Cluster Synergy Module
集群节点发现、HMAC 双向鉴权与重放防御、全量双向对齐与分布式联防
"""
from concurrent.futures import ThreadPoolExecutor
import hashlib
import hmac
import ipaddress
import json
import os
import re
import socket
import threading
import time
import urllib.request
import uuid

from core.db import get_db, load_config, save_config
from core.firewall import validate_ip, ban_ip_firewall, unban_ip_core, ip_in_whitelist
from geo import _GEO_CACHE, resolve_ip_geo, resolve_ip_geo_local

class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """
    集群安全出站请求重定向阻断器：
    彻底禁止跟随任何 HTTP 3xx 重定向，防止 Location 跳转绕过 SSRF 防护。
    """
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None

_SAFE_CLUSTER_OPENER = urllib.request.build_opener(NoRedirectHandler())

def safe_cluster_urlopen(req, timeout=3.0):
    """集群出站安全专属 HTTP 请求方法，强制禁用 3xx 自动跳转"""
    return _SAFE_CLUSTER_OPENER.open(req, timeout=timeout)

_CLUSTER_NONCE_CACHE = {}
_CLUSTER_NONCE_LOCK = threading.Lock()
MAX_CLUSTER_NONCES = 100000

def calc_body_hash(body):
    """计算集群请求体 SHA256 哈希十六进制字符串"""
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
        nonce = uuid.uuid4().hex
    body_hash = calc_body_hash(body)
    msg = f"{sign_target}:{body_hash}:{timestamp}:{nonce}"
    sig = hmac.new(secret.encode('utf-8'), msg.encode('utf-8'), hashlib.sha256).hexdigest()
    return f"v2.{timestamp}.{nonce}.{sig}"

def generate_cluster_response_token(secret, body=b"", req_token=None, timestamp=None):
    """
    生成集群响应端 HMAC-SHA256 签名：
    结构: v2.resp.<timestamp>.<signature>
    消息体: resp:<body_hash>:<timestamp>:<req_nonce_or_empty>
    """
    if timestamp is None:
        timestamp = int(time.time())
    req_nonce = ""
    if req_token and isinstance(req_token, str) and req_token.startswith("v2."):
        parts = req_token.strip().split(".")
        if len(parts) == 4:
            req_nonce = parts[2]
    body_hash = calc_body_hash(body)
    msg = f"resp:{body_hash}:{timestamp}:{req_nonce}"
    sig = hmac.new(secret.encode('utf-8'), msg.encode('utf-8'), hashlib.sha256).hexdigest()
    return f"v2.resp.{timestamp}.{sig}"

def verify_cluster_response_token(resp_token, secret, body=b"", req_token=None):
    """验证集群节点返回的响应签名"""
    if not secret or not resp_token:
        return False
    token_str = str(resp_token).strip()
    if not token_str.startswith("v2.resp."):
        return False
    parts = token_str.split(".")
    if len(parts) != 4:
        return False
    try:
        ts = int(parts[2])
        sig = parts[3]
        now = int(time.time())
        if abs(now - ts) > 90:
            return False
        req_nonce = ""
        if req_token and isinstance(req_token, str) and req_token.startswith("v2."):
            req_parts = req_token.strip().split(".")
            if len(req_parts) == 4:
                req_nonce = req_parts[2]
        body_hash = calc_body_hash(body)
        msg = f"resp:{body_hash}:{ts}:{req_nonce}"
        expected_sig = hmac.new(secret.encode('utf-8'), msg.encode('utf-8'), hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected_sig, sig)
    except Exception:
        return False

def verify_cluster_token(sign_target, token, secret, body=b""):
    """验证集群 Token，严格防范重放、篡改与中间人窃听攻击"""
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

        # 2. 验证签名一致性
        body_hash = calc_body_hash(body)
        msg = f"{sign_target}:{body_hash}:{ts}:{nonce}"
        expected_sig = hmac.new(secret.encode('utf-8'), msg.encode('utf-8'), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected_sig, sig):
            return False

        # 3. Nonce 防重放检查与基于 TTL 的清理
        with _CLUSTER_NONCE_LOCK:
            expire_before = now - 180
            expired = [k for k, v in _CLUSTER_NONCE_CACHE.items() if v < expire_before]
            for k in expired:
                del _CLUSTER_NONCE_CACHE[k]

            if len(_CLUSTER_NONCE_CACHE) >= MAX_CLUSTER_NONCES:
                sorted_items = sorted(_CLUSTER_NONCE_CACHE.items(), key=lambda x: x[1])
                to_remove = len(_CLUSTER_NONCE_CACHE) - int(MAX_CLUSTER_NONCES * 0.8)
                for k, _ in sorted_items[:to_remove]:
                    _CLUSTER_NONCE_CACHE.pop(k, None)

            if nonce in _CLUSTER_NONCE_CACHE:
                return False

            _CLUSTER_NONCE_CACHE[nonce] = now

        return True
    except Exception:
        return False

def parse_cluster_host_port(target_str, default_port=9098):
    """稳健解析集群节点的主机名/IP与端口，全面兼容 IPv4、域名以及 RFC 3986 带括号 [IPv6]:port 与纯 IPv6 地址"""
    if not target_str:
        return "", default_port
    s = str(target_str).strip()
    if "://" in s:
        s = s.split("://", 1)[1]
    if "/" in s:
        s = s.split("/", 1)[0]
    s = s.strip()
    if not s:
        return "", default_port

    if s.startswith("["):
        if "]:" in s:
            host_part, port_part = s[1:].split("]:", 1)
            try:
                port = int(port_part)
            except (ValueError, TypeError):
                port = default_port
            return host_part.strip(), port
        elif s.endswith("]"):
            return s[1:-1].strip(), default_port

    if s.count(":") > 1:
        try:
            ipaddress.IPv6Address(s)
            return s, default_port
        except ValueError:
            pass

    if ":" in s:
        parts = s.split(":", 1)
        host_part = parts[0].strip()
        try:
            port = int(parts[1])
        except (ValueError, TypeError):
            port = default_port
        return host_part, port

    return s, default_port

def format_http_target_url(target_ip, port, endpoint=""):
    """格式化集群 HTTP 请求目标 URL，严格遵循 RFC 2732 / 3986 标准"""
    clean_ip = str(target_ip).strip()
    if clean_ip.startswith("[") and clean_ip.endswith("]"):
        clean_ip = clean_ip[1:-1].strip()
    if ":" in clean_ip:
        host_repr = f"[{clean_ip}]"
    else:
        host_repr = clean_ip
    return f"http://{host_repr}:{port}{endpoint}"

def format_host_header(host, port):
    """格式化 HTTP Host 请求头，针对 IPv6 地址自动规范化为 [IPv6]:port"""
    h = str(host).strip()
    if h.startswith("[") and h.endswith("]"):
        h = h[1:-1].strip()
    if ":" in h:
        return f"[{h}]:{port}"
    return f"{h}:{port}"

def verify_cluster_response_strictly(resp, secret, req_token):
    """严格校验集群响应端 HMAC 签名"""
    resp_bytes = resp.read()
    if not secret:
        return True, resp_bytes, ""
    resp_token = resp.headers.get("X-Cluster-Response-Token", "").strip()
    if not resp_token:
        return False, resp_bytes, "安全拦截：对端响应缺少 X-Cluster-Response-Token 签名头 (可能遭受中间人降级或剥离攻击)"
    if not verify_cluster_response_token(resp_token, secret, body=resp_bytes, req_token=req_token):
        return False, resp_bytes, "安全拦截：对端响应 X-Cluster-Response-Token 签名校验失败或内容遭篡改"
    return True, resp_bytes, ""

def validate_cluster_target(ip_or_host):
    """集群目标地址 SSRF 安全校验，禁止回环、元数据、保留网段"""
    if not ip_or_host or not isinstance(ip_or_host, str):
        return False, "", "节点目标地址不能为空"

    host, _ = parse_cluster_host_port(ip_or_host)
    if not host:
        return False, "", "节点目标地址格式无效"

    try:
        ip_obj = ipaddress.ip_address(host)
        if ip_obj.is_loopback:
            return False, "", f"SSRF安全拦截：禁止添加本地回环地址 ({host}) 作为集群节点"
        if ip_obj.is_unspecified:
            return False, "", f"SSRF安全拦截：禁止添加未指定地址 ({host}) 作为集群节点"
        if ip_obj.is_link_local:
            return False, "", f"SSRF安全拦截：禁止添加链路本地地址 ({host}) 作为集群节点"
        if ip_obj.is_multicast:
            return False, "", "SSRF安全拦截：禁止添加组播地址作为集群节点"
        if ip_obj.is_reserved:
            return False, "", "SSRF安全拦截：禁止添加保留地址段作为集群节点"
        if str(ip_obj) == "169.254.169.254":
            return False, "", "SSRF安全拦截：禁止访问云服务器元数据服务 (Metadata Service)"
        return True, str(ip_obj), ""
    except ValueError:
        pass

    if not re.match(r'^[a-zA-Z0-9.\-_]+$', host):
        return False, "", "非法的节点主机名或IP字符"

    h_lower = host.lower()
    if h_lower in ("localhost", "ip6-localhost", "ip6-loopback", "metadata.google.internal"):
        return False, "", "SSRF安全拦截：禁止指向本机或云元数据域名"

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
    """DNS Rebinding 与 SSRF 防御解析器"""
    clean_h, _ = parse_cluster_host_port(host, port or 80)
    ok, clean_host, err_msg = validate_cluster_target(clean_h)
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
    """规范化协同节点数据结构，确保字段完整并兼容 IPv4、IPv6 与域名格式"""
    if isinstance(node, dict):
        raw_ip = str(node.get("ip", "")).strip()
        host, default_port = parse_cluster_host_port(raw_ip, default_port=int(node.get("port", 9098) or 9098))
        port = int(node.get("port", default_port) or default_port)
        remark = str(node.get("remark", "")).strip() or f"协同节点 ({host})"
        created_at = node.get("created_at") or time.strftime("%Y-%m-%d %H:%M:%S")
        status = node.get("status", "unknown")
        latency_ms = int(node.get("latency_ms", 0) or 0)
        country = node.get("country", "")
        return {
            "ip": host,
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
        host, port = parse_cluster_host_port(s, default_port=9098)
        if not host:
            return None
        return {
            "ip": host,
            "port": port,
            "remark": f"协同节点 ({host})",
            "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "status": "unknown",
            "latency_ms": 0,
            "country": ""
        }
    return None

_MESH_EXECUTOR = ThreadPoolExecutor(max_workers=8, thread_name_prefix="cluster-mesh")

def _send_cluster_msg(node, endpoint, payload, token, secret=""):
    """向协同节点发送通信数据，直连安全验证的解析目标以杜绝 DNS Rebinding，严格禁止 HTTP 重定向并双向强制校验响应签名"""
    if not node or not node.get("ip"):
        return False

    orig_host = str(node.get("ip", "")).strip()
    is_safe, target_ip, _ = resolve_and_validate_target(orig_host)
    if not is_safe:
        return False

    if not secret:
        cfg = load_config()
        secret = cfg.get("cluster_sync", {}).get("cluster_secret", "").strip()

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
            "Host": format_host_header(orig_host, p)
        }
        for attempt in range(2):
            try:
                target = format_http_target_url(target_ip, p, endpoint)
                req = urllib.request.Request(target, data=payload, headers=headers)
                with safe_cluster_urlopen(req, timeout=3.5) as resp:
                    if resp.status in (200, 201):
                        is_valid, _, _ = verify_cluster_response_strictly(resp, secret, token)
                        if not is_valid:
                            continue
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
        _MESH_EXECUTOR.submit(_send_cluster_msg, node, "/api/cluster/sync_ban", payload, token, secret)

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
        _MESH_EXECUTOR.submit(_send_cluster_msg, node, "/api/cluster/sync_unban", payload, token, secret)

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
        _MESH_EXECUTOR.submit(_send_cluster_msg, node, "/api/cluster/sync_whitelist", payload, token, secret)

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

        orig_host = str(node.get("ip", "")).strip()
        is_safe, target_ip, _ = resolve_and_validate_target(orig_host)
        if not is_safe:
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
            target = format_http_target_url(target_ip, p, "/api/cluster/sync_state_exchange")
            try:
                req = urllib.request.Request(target, data=payload, headers={
                    "Content-Type": "application/json",
                    "X-Cluster-Token": token,
                    "User-Agent": "PortGuardMesh/2.0",
                    "Host": format_host_header(orig_host, p)
                })
                with safe_cluster_urlopen(req, timeout=5) as resp:
                    is_valid, resp_bytes, err_msg = verify_cluster_response_strictly(resp, secret, token)
                    if not is_valid:
                        continue
                    res = json.loads(resp_bytes.decode('utf-8'))
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

            if remote_missing_bans:
                conn = get_db()
                cur = conn.cursor()
                for b in remote_missing_bans:
                    b_ip = validate_ip(b.get("ip", ""))
                    if not b_ip or ip_in_whitelist(b_ip):
                        continue
                    b_ts = int(b.get("timestamp", 0) or 0)
                    local_unban_ts = local_unbanned_map.get(b_ip)
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
                    _MESH_EXECUTOR.submit(resolve_ip_geo, b_ip)
                    merged_bans += 1
                conn.commit()
                conn.close()

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
