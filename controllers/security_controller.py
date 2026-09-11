# -*- coding: utf-8 -*-
import json
import time
import re
import sqlite3
import ipaddress
import subprocess
import threading
from urllib.parse import parse_qs
from sentry_daemon import (
    get_db, load_config, save_config, validate_ip, unban_ip_core, ban_ip,
    ban_ip_firewall, broadcast_cluster_ban, broadcast_cluster_unban,
    broadcast_cluster_whitelist, resolve_ip_geo, resolve_ip_geo_local,
    get_ip_threat_tags, get_hidden_ips, get_hidden_ips_set,
    add_hidden_ip, remove_hidden_ip, clear_hidden_ips, _GEO_CACHE,
    DEFAULT_CONFIG, run_firewall_cmd, ip_in_whitelist, _EXECUTOR
)
from controllers.base import (
    invalidate_blacklist_cache, get_blacklist_cache, set_blacklist_cache,
    parse_loose_json_or_lines, _BLACKLIST_CACHE_LOCK, _BLACKLIST_CACHE,
    _BLACKLIST_CACHE_TIME
)

def handle_hidden_ips(req, parsed):
    hidden_list = get_hidden_ips()
    req._send_json(hidden_list)
    return


def handle_attacker_timeline(req, parsed):
    # 攻击者全景画像与足迹时间线档案 API
    query = parse_qs(parsed.query)
    att_ip = query.get("ip", [""])[0].strip()
    if not att_ip:
        req._send_json({"error": "缺少 IP 参数"}, status=400)
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

    req._send_json({
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



def handle_ip_info(req, parsed):
    query = parse_qs(parsed.query)
    ip = query.get("ip", [""])[0].strip()
    if not ip:
        req._send_json({"country": "未知地域", "region": "", "city": "", "isp": "", "threat_tags": []})
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
    req._send_json(geo)
    return



def handle_blacklist(req, parsed):
    global _BLACKLIST_CACHE, _BLACKLIST_CACHE_TIME
    now_mono = time.monotonic()
    with _BLACKLIST_CACHE_LOCK:
        if _BLACKLIST_CACHE is not None and (now_mono - _BLACKLIST_CACHE_TIME) < 5.0:
            cached_data = _BLACKLIST_CACHE
        else:
            cached_data = None
    if cached_data is not None:
        req._send_json(cached_data)
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
    req._send_json(rows)
    return



def handle_whitelist(req, parsed):
    cfg = load_config()
    raw_white = cfg.get("whitelist", DEFAULT_CONFIG["whitelist"])
    normalized = []
    for item in raw_white:
        if isinstance(item, str):
            item = {"ip": item, "remark": "信任IP"}
        normalized.append(item)
    req._send_json(normalized)
    return



def handle_blacklist_export(req, parsed):
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT ip, reason, country, level, ban_time, timestamp FROM blacklist WHERE ip NOT IN (SELECT ip FROM hidden_ips) ORDER BY timestamp DESC")
    rows = [dict(r) for r in c.fetchall()]
    conn.close()
    req._send_json(rows)
    return



def handle_unban(req, parsed, req_data):
    ip = req_data.get("ip", "").strip()
    if not ip:
        req._send_json({"success": False, "msg": "IP 不能为空"}, status=400)
        return
    valid_ip = validate_ip(ip)
    if not valid_ip:
        req._send_json({"success": False, "msg": "IP 格式不合法"}, status=400)
        return
    ip = valid_ip

    cfg = load_config()
    node_name = cfg.get("node_name", "本机") or "本机"
    unban_ip_core(ip, status_event="UNBANNED", source_node=f"手动解封({node_name})")
    # 广播解封至全网集群协同节点
    broadcast_cluster_unban(ip)
    invalidate_blacklist_cache()
    req._send_json({"success": True, "msg": f"已成功从内核黑名单与防火墙中解封 IP: {ip}（已同步全网集群协同解封）"})
    return


def handle_ban(req, parsed, req_data):
    ip = req_data.get("ip", "").strip()
    reason = req_data.get("reason", "管理员手动封禁").strip()
    if not ip:
        req._send_json({"success": False, "msg": "IP 不能为空"}, status=400)
        return
    valid_ip = validate_ip(ip)
    if not valid_ip:
        req._send_json({"success": False, "msg": "IP 格式不合法"}, status=400)
        return
    ip = valid_ip

    # 防自锁与白名单保护：当前控制台客户端、活跃SSH管理会话及安全白名单严禁封禁
    client_ip = getattr(req, "client_address", ("", 0))[0]
    if ip == client_ip:
        req._send_json({"success": False, "msg": f"操作已阻断：目标 IP [{ip}] 为当前登录控制台的客户端地址，触发管理员防自锁保护！"}, status=400)
        return
    if ip_in_whitelist(ip):
        req._send_json({"success": False, "msg": f"操作已阻断：目标 IP [{ip}] 属于系统安全白名单或活跃管理会话，严禁封禁！"}, status=400)
        return

    ban_ip(ip, reason=reason, category="manual", level="极高危")
    invalidate_blacklist_cache()
    req._send_json({"success": True, "msg": f"已成功永久封禁 IP: {ip}（已下发内核防火墙并同步集群协同阻断）"})
    return



def handle_ban_subnet(req, parsed, req_data):
    # 一键封禁整个 /24 C段网段
    subnet = req_data.get("subnet", "").strip()
    ip = req_data.get("ip", "").strip()
    reason = req_data.get("reason", "管理员手动封禁攻击源 /24 C段").strip()
    
    if not subnet and ip:
        parts = ip.split('.')
        if len(parts) == 4:
            subnet = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"

    if not subnet or "/" not in subnet:
        req._send_json({"success": False, "msg": "非法的 CIDR 网段格式 (如 1.2.3.0/24)"}, status=400)
        return
    try:
        net_obj = ipaddress.ip_network(subnet, strict=False)

        # 防自锁与白名单保护：检查当前控制台客户端、活跃白名单是否落在目标网段内
        client_ip = getattr(req, "client_address", ("", 0))[0]
        if client_ip:
            try:
                c_addr = ipaddress.ip_address(client_ip)
                if c_addr in net_obj:
                    req._send_json({"success": False, "msg": f"操作已阻断：目标网段 [{net_obj}] 包含了当前登录控制台的客户端 IP [{client_ip}]，触发管理员防自锁保护！"}, status=400)
                    return
            except Exception:
                pass

        cfg = load_config()
        whitelist = cfg.get("whitelist", DEFAULT_CONFIG.get("whitelist", []))
        for w_item in whitelist:
            w_ip_str = w_item.get("ip") if isinstance(w_item, dict) else str(w_item)
            w_ip_str = (w_ip_str or "").strip()
            if not w_ip_str:
                continue
            try:
                if "/" in w_ip_str:
                    w_net = ipaddress.ip_network(w_ip_str, strict=False)
                    if net_obj.overlaps(w_net):
                        req._send_json({"success": False, "msg": f"操作已阻断：目标网段 [{net_obj}] 与系统安全白名单网段 [{w_ip_str}] 存在重叠冲突，严禁封禁！"}, status=400)
                        return
                else:
                    w_addr = ipaddress.ip_address(w_ip_str)
                    if w_addr in net_obj:
                        req._send_json({"success": False, "msg": f"操作已阻断：目标网段 [{net_obj}] 包含了系统安全白名单 IP [{w_ip_str}]，严禁封禁！"}, status=400)
                        return
            except Exception:
                pass

        # 下发网段级黑洞路由与防火墙拦截 (兼容 IPv4 与 IPv6 网段)
        is_v6 = net_obj.version == 6
        fw_tool = "ip6tables" if is_v6 else "iptables"
        route_cmd = ["ip", "-6", "route", "add", "blackhole", str(net_obj)] if is_v6 else ["ip", "route", "add", "blackhole", str(net_obj)]
        subprocess.run(route_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run([fw_tool, "-I", "INPUT", "-s", str(net_obj), "-j", "DROP"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        ban_ip(str(net_obj), reason=reason, category="subnet_ban", level="极高危")
        invalidate_blacklist_cache()
        req._send_json({"success": True, "msg": f"已成功对 {net_obj} 整个网段实施内核黑洞阻断与拦截！"})
    except Exception as e:
        req._send_json({"success": False, "msg": f"网段阻断失败: {e}"}, status=400)
    return



def handle_batch_ban_all(req, parsed, req_data):
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

        # 统一通过底层高性能 ipset + 黑洞路由下发阻断，杜绝逐条iptables规则线性膨胀
        if cfg.get("ban_action_iptables", True) or cfg.get("ban_action_blackhole", True):
            ban_ip_firewall(v, expire_seconds=(auto_clean_days * 86400 if auto_clean_days > 0 else None))

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
    req._send_json({"success": True, "count": count, "msg": f"已成功将 {count} 个恶意探测 IP 批量加入黑名单并下发内核阻断。"})
    return



def handle_blacklist_import(req, parsed, req_data):
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
        req._send_json({"success": False, "msg": "未解析到有效的 IP 数据"}, status=400)
        return

    conn = get_db()
    c = conn.cursor()

    if mode == "replace":
        c.execute("SELECT ip FROM blacklist")
        for (old_ip,) in c.fetchall():
            v_old = validate_ip(old_ip)
            if v_old:
                unban_ip_core(v_old, status_event="REPLACED")
        c.execute("DELETE FROM blacklist")
        conn.commit()

    now_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    now_ts = int(time.time())

    cfg_import = load_config()
    auto_clean_days = int(cfg_import.get("auto_clean_days", 30) or 30)
    ban_expire = now_ts + (auto_clean_days * 86400) if auto_clean_days > 0 else None
    node_name = cfg_import.get("node_name", "本机") or "本机"

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
        if not valid_ip or ip_in_whitelist(valid_ip):
            continue
        ip = valid_ip

        # 统一使用 ipset + 黑洞路由高速阻断
        if cfg_import.get("ban_action_iptables", True) or cfg_import.get("ban_action_blackhole", True):
            ban_ip_firewall(ip, expire_seconds=(auto_clean_days * 86400 if auto_clean_days > 0 else None))

        c.execute("""
        INSERT OR REPLACE INTO blacklist (ip, reason, country, level, ban_time, timestamp, ban_expire, source_node)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (ip, reason, country, level, ban_time, now_ts, ban_expire, f"批量导入 ({node_name})"))
        success_count += 1

    conn.commit()
    conn.close()

    req._send_json({"success": True, "msg": f"黑名单导入成功！共写入 {success_count} 个拦截目标", "count": success_count})
    return



def handle_whitelist_add(req, parsed, req_data):
    ip = req_data.get("ip", "").strip()
    remark = req_data.get("remark", "信任IP").strip()
    if not ip:
        req._send_json({"success": False, "msg": "IP 不能为空"}, status=400)
        return

    valid_ip = validate_ip(ip)
    if not valid_ip:
        req._send_json({"success": False, "msg": "IP 格式不合法"}, status=400)
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
    req._send_json({"success": True, "msg": f"已成功将 {ip} 加入信任白名单{extra_tip}！"})
    return



def handle_whitelist_delete(req, parsed, req_data):
    ip = req_data.get("ip", "").strip()
    cfg = load_config()
    cfg["whitelist"] = [w for w in cfg.get("whitelist", []) if (w.get("ip") if isinstance(w, dict) else w) != ip]
    save_config(cfg)
    # 广播至集群协同节点
    broadcast_cluster_whitelist("delete", ip)
    req._send_json({"success": True, "msg": f"已移除白名单: {ip}"})
    return



def handle_whitelist_import(req, parsed, req_data):
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
        req._send_json({"success": False, "msg": "未解析到有效的白名单数据"}, status=400)
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
        req._send_json({"success": False, "msg": "未能提取到有效的 IP 白名单项"}, status=400)
        return

    new_whitelist = list(current_map.values())
    cfg["whitelist"] = new_whitelist
    save_config(cfg)
    # 广播批量导入至集群协同节点
    broadcast_cluster_whitelist("batch_add", new_whitelist, "批量导入同步")
    unban_tip = f"，并同步解除 {unbanned_count} 个原黑名单目标" if unbanned_count > 0 else ""
    req._send_json({
        "success": True,
        "msg": f"信任白名单导入成功！共载入 {success_count} 条规则{unban_tip} (当前总计 {len(current_map)} 条)",
        "count": success_count,
        "unbanned_count": unbanned_count,
        "total": len(current_map)
    })
    return



def handle_hidden_ips_add(req, parsed, req_data):
    action = req_data.get("action", "add")
    ip = req_data.get("ip", "").strip()
    if not ip:
        req._send_json({"success": False, "msg": "IP 不能为空"}, status=400)
        return
    if action == "remove":
        ok, msg = remove_hidden_ip(ip)
    else:
        remark = req_data.get("remark", "").strip()
        ok, msg = add_hidden_ip(ip, remark)
    req._send_json({"success": ok, "msg": msg})
    return



def handle_hidden_ips_remove(req, parsed, req_data):
    ip = req_data.get("ip", "").strip()
    if not ip:
        req._send_json({"success": False, "msg": "IP 不能为空"}, status=400)
        return
    ok, msg = remove_hidden_ip(ip)
    req._send_json({"success": ok, "msg": msg})
    return



def handle_hidden_ips_clear(req, parsed, req_data):
    ok, msg = clear_hidden_ips()
    req._send_json({"success": ok, "msg": msg})
    return



def handle_hidden_ips_import(req, parsed, req_data):
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
        req._send_json({"success": False, "msg": "未解析到有效的 IP 数据，请检查格式"}, status=400)
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
    req._send_json({"success": True, "msg": f"成功{'全量覆盖' if mode=='replace' else '增量导入'} {count} 条隐藏 IP 规则"})
    return


def handle_hidden_ips_post_delete(req, parsed, req_data):
    ip = req_data.get("ip", "").strip()
    if not ip:
        query = parse_qs(parsed.query)
        ip = query.get("ip", [""])[0].strip()
    if not ip:
        req._send_json({"success": False, "msg": "IP 不能为空"}, status=400)
        return
    ok, msg = remove_hidden_ip(ip)
    req._send_json({"success": ok, "msg": msg})
    return

