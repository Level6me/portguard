# -*- coding: utf-8 -*-
import json
import time
import socket
import ipaddress
import urllib.request
import urllib.error
from urllib.parse import parse_qs, urlparse
from sentry_daemon import (
    get_db, load_config, save_config, normalize_cluster_node,
    verify_cluster_token, generate_cluster_token, resolve_ip_geo,
    resolve_ip_geo_local, ban_ip_firewall, unban_ip_core,
    broadcast_cluster_ban, broadcast_cluster_unban, broadcast_cluster_whitelist,
    sync_cluster_mesh_state, get_hidden_ips_set, validate_ip, ip_in_whitelist,
    _EXECUTOR
)
from controllers.base import invalidate_blacklist_cache

def handle_cluster_nodes(req, parsed):
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
    req._send_json({
        "enabled": bool(cluster_cfg.get("enabled", False)),
        "port": int(cluster_cfg.get("port", 9098) or 9098),
        "cluster_secret": cluster_cfg.get("cluster_secret", ""),
        "nodes": norm_nodes
    })
    return


def handle_cluster_sync_unban(req, parsed, req_data):
    token = req.headers.get("X-Cluster-Token", "").strip()
    cfg = load_config()
    cluster_cfg = cfg.get("cluster_sync", {})
    secret = cluster_cfg.get("cluster_secret", "").strip()

    ip = req_data.get("ip", "").strip()
    if not verify_cluster_token(f"unban_{ip}", token, secret):
        req._send_json({"success": False, "msg": "集群鉴权签名无效"}, status=403)
        return

    valid_ip = validate_ip(ip)
    if not valid_ip:
        req._send_json({"success": False, "msg": "IP格式不合法"}, status=400)
        return
    source_node = req_data.get("source_node", "协同节点").strip()
    unban_ip_core(valid_ip, status_event="UNBANNED", source_node=f"集群解封({source_node})")
    req._send_json({"success": True, "msg": f"已协同解封: {valid_ip}"})
    return



def handle_cluster_sync_state_exchange(req, parsed, req_data):
    token = req.headers.get("X-Cluster-Token", "").strip()
    cfg = load_config()
    cluster_cfg = cfg.get("cluster_sync", {})
    secret = cluster_cfg.get("cluster_secret", "").strip()
    if not verify_cluster_token("sync_state_exchange", token, secret):
        req._send_json({"success": False, "msg": "集群鉴权签名无效"}, status=403)
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

    req._send_json({
        "success": True,
        "added_bans": added_bans,
        "added_whites": added_whites,
        "remote_blacklist": missing_for_remote_bans,
        "remote_unbanned": local_unbanned_resp,
        "remote_whitelist": missing_for_remote_whites
    })
    return


def handle_cluster_sync_all_mesh(req, parsed, req_data=None):
    res = sync_cluster_mesh_state()
    req._send_json(res)
    return

def handle_cluster_sync_ban(req, parsed, req_data):
    token = req.headers.get("X-Cluster-Token", "").strip()
    cfg = load_config()
    cluster_cfg = cfg.get("cluster_sync", {})
    secret = cluster_cfg.get("cluster_secret", "").strip()

    ip = req_data.get("ip", "").strip()
    reason = req_data.get("reason", "集群威胁同步").strip()
    level = req_data.get("level", "极高危").strip()
    source_node = req_data.get("source_node", "远程探针").strip()

    if not verify_cluster_token(ip, token, secret):
        req._send_json({"success": False, "msg": "集群鉴权签名无效"}, status=403)
        return

    valid_ip = validate_ip(ip)
    if not valid_ip:
        req._send_json({"success": False, "msg": "IP格式不合法"}, status=400)
        return
    ip = valid_ip

    if ip_in_whitelist(ip):
        req._send_json({"success": True, "msg": "本地白名单已忽略"})
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
    req._send_json({"success": True, "msg": f"已完成集群同步封禁: {ip}"})
    return



def handle_cluster_sync_whitelist(req, parsed, req_data):
    token = req.headers.get("X-Cluster-Token", "").strip()
    cfg = load_config()
    cluster_cfg = cfg.get("cluster_sync", {})
    secret = cluster_cfg.get("cluster_secret", "").strip()

    action = req_data.get("action", "add").strip()
    data = req_data.get("data")
    remark = req_data.get("remark", "集群协同白名单").strip()
    source_node = req_data.get("source_node", "远程节点").strip()

    sign_target = f"whitelist_{action}"
    if not verify_cluster_token(sign_target, token, secret):
        req._send_json({"success": False, "msg": "集群鉴权签名无效"}, status=403)
        return

    whitelist = cfg.get("whitelist", [])

    if action == "add":
        ip = str(data or "").strip()
        valid_ip = validate_ip(ip)
        if not valid_ip:
            req._send_json({"success": False, "msg": "IP 格式不合法"}, status=400)
            return
        ip = valid_ip
        unban_ip_core(ip, status_event="WHITELIST")
        if not any(w.get("ip") == ip if isinstance(w, dict) else w == ip for w in whitelist):
            node_remark = f"[{source_node}联防] {remark}" if not str(remark).startswith(f"[{source_node}") else remark
            whitelist.append({"ip": ip, "remark": node_remark})
            cfg["whitelist"] = whitelist
            save_config(cfg)
        req._send_json({"success": True, "msg": f"已成功同步添加白名单: {ip}"})
        return

    elif action == "delete":
        ip = str(data or "").strip()
        whitelist = [w for w in whitelist if (w.get("ip") if isinstance(w, dict) else w) != ip]
        cfg["whitelist"] = whitelist
        save_config(cfg)
        req._send_json({"success": True, "msg": f"已成功同步移除白名单: {ip}"})
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
        req._send_json({"success": True, "msg": f"已批量同步 {updated_cnt} 条协同白名单", "count": updated_cnt})
        return

    req._send_json({"success": False, "msg": "未知的白名单同步操作"}, status=400)
    return



def handle_cluster_sync_all_whitelist(req, parsed, req_data):
    cfg = load_config()
    cluster_cfg = cfg.get("cluster_sync", {})
    if not cluster_cfg.get("enabled", False):
        req._send_json({"success": False, "msg": "集群联防协同功能未开启"}, status=400)
        return
    nodes = cluster_cfg.get("cluster_nodes", [])
    if not nodes:
        req._send_json({"success": False, "msg": "当前未配置任何集群协同节点"}, status=400)
        return
    whitelist = cfg.get("whitelist", [])
    broadcast_cluster_whitelist("sync_all", whitelist, "全网协同全量同步")
    req._send_json({"success": True, "msg": f"已向 {len(nodes)} 个集群节点广播全量白名单 (共 {len(whitelist)} 条规则)"})
    return



def handle_cluster_ping(req, parsed, req_data=None):
    token = req.headers.get("X-Cluster-Token", "").strip()
    cfg = load_config()
    cluster_cfg = cfg.get("cluster_sync", {})
    secret = cluster_cfg.get("cluster_secret", "").strip()
    if not secret or not verify_cluster_token("ping", token, secret):
        req._send_json({"success": False, "msg": "集群鉴权密钥无效或未配置"}, status=403)
        return
    req._send_json({
        "success": True,
        "node_name": cfg.get("node_name", "远程节点"),
        "version": "2.0.0"
    })
    return



def handle_cluster_test_node(req, parsed, req_data):
    node_url = req_data.get("node_url", "").strip().rstrip("/")
    secret = req_data.get("secret", "").strip()
    if not node_url:
        req._send_json({"success": False, "msg": "节点地址不能为空"}, status=400)
        return
    if not secret:
        req._send_json({"success": False, "msg": "通信密钥不能为空"}, status=400)
        return

    # SSRF 安全防御校验：阻断云厂商元数据及敏感内网地址探测
    try:
        parsed_node = urlparse(node_url)
        if parsed_node.scheme not in ('http', 'https'):
            req._send_json({"success": False, "msg": "协议不合法，仅支持 http:// 或 https:// 协议"}, status=400)
            return
        host_part = parsed_node.hostname
        if not host_part:
            req._send_json({"success": False, "msg": "节点地址格式错误"}, status=400)
            return

        resolved_addrs = socket.getaddrinfo(host_part, None)
        for item in resolved_addrs:
            ip_str = item[4][0]
            ip_obj = ipaddress.ip_address(ip_str)
            if ip_obj.is_link_local:
                req._send_json({"success": False, "msg": f"安全拦截：禁止探测云元数据/链路本地地址 ({ip_str})"}, status=403)
                return
            if ip_obj.is_loopback:
                req._send_json({"success": False, "msg": f"安全拦截：禁止访问本地回环地址 ({ip_str})"}, status=403)
                return
            if ip_obj.is_unspecified:
                req._send_json({"success": False, "msg": f"安全拦截：禁止访问未指定地址 ({ip_str})"}, status=403)
                return
    except Exception as ex:
        req._send_json({"success": False, "msg": f"节点主机名解析异常: {ex}"}, status=400)
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
                req._send_json({
                    "success": True,
                    "node_name": res_data.get("node_name", "远程节点"),
                    "latency_ms": latency,
                    "msg": f"连接成功！节点响应正常 (延迟 {latency}ms)"
                })
            else:
                req._send_json({
                    "success": False,
                    "msg": res_data.get("msg", "鉴权失败")
                })
    except urllib.error.HTTPError as e:
        req._send_json({"success": False, "msg": f"HTTP {e.code}: 鉴权失败或密钥不一致"})
    except Exception as e:
        req._send_json({"success": False, "msg": f"连接超时或无法访问 ({e})"})
    return



def handle_cluster_nodes_add(req, parsed, req_data):
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
        req._send_json({"success": False, "msg": "节点 IP 或域名不能为空"}, status=400)
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
    req._send_json({
        "success": True, 
        "msg": f"协同节点 {ip_raw}:{port} 已成功添加！" if not updated else f"协同节点 {ip_raw}:{port} 配置已更新！",
        "node": node_obj,
        "nodes": new_list
    })
    return



def handle_cluster_nodes_delete(req, parsed, req_data):
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
    req._send_json({"success": True, "msg": f"协同节点 {ip_raw} 已成功移除", "nodes": new_list})
    return



def handle_cluster_nodes_update_remark(req, parsed, req_data):
    ip_raw = str(req_data.get("ip", "")).strip()
    port = int(req_data.get("port", 9098) or 9098)
    new_remark = str(req_data.get("remark", "")).strip()
    if not new_remark:
        req._send_json({"success": False, "msg": "节点备注名称不能为空"}, 400)
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
        req._send_json({"success": True, "msg": f"节点 {ip_raw}:{port} 备注已更新为: {new_remark}", "nodes": existing})
    else:
        req._send_json({"success": False, "msg": "未找到匹配的协同节点"}, 404)
    return



def handle_cluster_nodes_test_all(req, parsed, req_data):
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
    req._send_json({"success": True, "nodes": updated_nodes})
    return



def handle_cluster_nodes_test_single(req, parsed, req_data):
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
        http_req = urllib.request.Request(target, data=b"{}", headers={
            "Content-Type": "application/json",
            "X-Cluster-Token": token,
            "User-Agent": "PortGuardMesh/2.0"
        })
        t0 = time.time()
        with urllib.request.urlopen(http_req, timeout=3.0) as resp:
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

    req._send_json({
        "success": (status == "online"),
        "status": status,
        "latency_ms": latency_ms,
        "node_name": node_name
    })
    return


