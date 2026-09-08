# -*- coding: utf-8 -*-
import json
import time
import re
from urllib.parse import parse_qs
from sentry_daemon import (
    get_db, load_config, save_config, DEFAULT_CONFIG, PORT_DESCRIPTIONS,
    DEFAULT_HTTP_TRAPS, get_http_traps, normalize_trap_item, trap_instance,
    get_all_business_ports_info
)
from controllers.base import parse_loose_json_or_lines

def handle_traps(req, parsed):
    cfg = load_config()
    raw_traps = cfg.get("trap_ports", DEFAULT_CONFIG["trap_ports"])
    normalized = []
    for item in raw_traps:
        norm = normalize_trap_item(item)
        if norm:
            normalized.append(norm)
    req._send_json(normalized)
    return



def handle_business_ports(req, parsed):
    biz_list = get_all_business_ports_info()
    req._send_json(biz_list)
    return



def handle_http_traps(req, parsed):
    rules = get_http_traps()
    req._send_json(rules)
    return



def handle_traps_export(req, parsed):
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
    req._send_json(export_list)
    return



def handle_traps_add(req, parsed, req_data):
    raw_port = req_data.get("port")
    name = req_data.get("name", "").strip()
    level = req_data.get("level", "高危")
    category = req_data.get("category", "custom")
    is_business = bool(req_data.get("is_business", False))
    if not raw_port:
        req._send_json({"success": False, "msg": "端口不能为空"}, status=400)
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
        req._send_json({"success": False, "msg": "端口格式不合法，请输入单个端口 (1-65535) 或端口范围 (例如 1000-3000)"}, status=400)
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
    req._send_json({"success": True, "msg": f"已激活诱捕端口/策略: {port_key}"})
    return



def handle_traps_edit(req, parsed, req_data):
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
        req._send_json({"success": False, "msg": "端口格式不合法，请输入单个端口 (1-65535) 或端口范围 (例如 1000-3000)"}, status=400)
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
    req._send_json({"success": True, "msg": f"蜜罐策略已更新: {norm_new['port']}"})
    return



def handle_traps_delete(req, parsed, req_data):
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
    req._send_json({"success": True, "msg": f"已彻底删除蜜罐策略: {port_key}"})
    return



def handle_traps_toggle(req, parsed, req_data):
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
    req._send_json({"success": True, "msg": f"已更新端口策略 {port_key} 状态"})
    return



def handle_http_traps_toggle(req, parsed, req_data):
    rule_id = req_data.get("id")
    enabled = 1 if req_data.get("enabled") else 0
    conn = get_db()
    c = conn.cursor()
    c.execute("UPDATE http_traps SET enabled = ? WHERE id = ? OR rule_id = ?", (enabled, rule_id, str(rule_id)))
    conn.commit()
    conn.close()
    req._send_json({"success": True, "msg": f"请求特征策略已{'启用' if enabled else '停用'}"})
    return



def handle_http_traps_add(req, parsed, req_data):
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
        req._send_json({"success": False, "msg": "策略名称不能为空"}, status=400)
        return
    conn = get_db()
    c = conn.cursor()
    c.execute("""
    INSERT INTO http_traps (rule_id, name, match_type, pattern, threshold, window, action, level, enabled, description, created_at)
    VALUES (?, ?, ?, ?, ?, ?, 'ban', ?, 1, ?, ?)
    """, (rule_id, name, mtype, pattern, threshold, window, level, desc, now_dt))
    conn.commit()
    conn.close()
    req._send_json({"success": True, "msg": f"已添加请求特征策略: {name}"})
    return



def handle_http_traps_edit(req, parsed, req_data):
    rule_db_id = req_data.get("id")
    name = str(req_data.get("name", "")).strip()
    mtype = str(req_data.get("match_type", "path_keyword")).strip()
    pattern = str(req_data.get("pattern", "")).strip()
    threshold = int(req_data.get("threshold") or 6)
    window = int(req_data.get("window") or 30)
    level = str(req_data.get("level", "高危")).strip()
    desc = str(req_data.get("description", "")).strip()
    if not name:
        req._send_json({"success": False, "msg": "策略名称不能为空"}, status=400)
        return
    conn = get_db()
    c = conn.cursor()
    c.execute("""
    UPDATE http_traps SET name = ?, match_type = ?, pattern = ?, threshold = ?, window = ?, level = ?, description = ?
    WHERE id = ? OR rule_id = ?
    """, (name, mtype, pattern, threshold, window, level, desc, rule_db_id, str(rule_db_id)))
    conn.commit()
    conn.close()
    req._send_json({"success": True, "msg": f"已更新请求特征策略: {name}"})
    return



def handle_http_traps_delete(req, parsed, req_data):
    rule_db_id = req_data.get("id")
    conn = get_db()
    c = conn.cursor()
    c.execute("DELETE FROM http_traps WHERE id = ? OR rule_id = ?", (rule_db_id, str(rule_db_id)))
    conn.commit()
    conn.close()
    req._send_json({"success": True, "msg": "已删除请求特征策略"})
    return



def handle_http_traps_import(req, parsed, req_data):
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
        req._send_json({"success": False, "msg": "未解析到有效的请求特征策略数据，请检查格式"}, status=400)
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
    req._send_json({"success": True, "msg": f"成功{'全量覆盖' if mode=='replace' else '增量导入'} {count} 条请求特征策略"})
    return



def handle_traps_import(req, parsed, req_data):
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
        req._send_json({"success": False, "msg": "未解析到有效的蜜罐策略数据，请检查格式"}, status=400)
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
        req._send_json({"success": False, "msg": "未能提取到任何合法端口策略（端口号必须为 1-65535）"}, status=400)
        return

    cfg["trap_ports"] = list(current_map.values())
    save_config(cfg)
    trap_instance.reload()
    req._send_json({
        "success": True,
        "msg": f"蜜罐策略导入成功！共载入 {success_count} 条策略 (当前总计 {len(current_map)} 条)",
        "count": success_count,
        "total": len(current_map)
    })
    return



def handle_business_ports_add(req, parsed, req_data):
    port_raw = req_data.get("port")
    if not port_raw:
        req._send_json({"success": False, "msg": "端口号不能为空"}, status=400)
        return
    try:
        port = int(port_raw)
        if port < 1 or port > 65535:
            raise ValueError()
    except Exception:
        req._send_json({"success": False, "msg": "端口号必须为 1-65535 的整数"}, status=400)
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
            req._send_json({"success": False, "msg": f"业务端口 {port} 已存在，无需重复添加"}, status=400)
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
    req._send_json({"success": True, "msg": f"已成功添加正常业务端口: {port} ({name})"})
    return



def handle_business_ports_edit(req, parsed, req_data):
    port_raw = req_data.get("port")
    if not port_raw:
        req._send_json({"success": False, "msg": "端口号不能为空"}, status=400)
        return
    try:
        port = int(port_raw)
    except Exception:
        req._send_json({"success": False, "msg": "无效端口号"}, status=400)
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
    req._send_json({"success": True, "msg": f"已成功更新业务端口: {port}"})
    return



def handle_business_ports_delete(req, parsed, req_data):
    port_raw = req_data.get("port")
    if not port_raw:
        req._send_json({"success": False, "msg": "端口号不能为空"}, status=400)
        return
    try:
        port = int(port_raw)
    except Exception:
        req._send_json({"success": False, "msg": "无效端口号"}, status=400)
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
    req._send_json({"success": True, "msg": f"已成功删除业务端口: {port}"})
    return



def handle_business_ports_import(req, parsed, req_data):
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
        req._send_json({"success": False, "msg": "未解析到有效的业务端口数据，请检查格式"}, status=400)
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
        req._send_json({"success": False, "msg": "未能提取到任何合法业务端口（端口必须为 1-65535）"}, status=400)
        return
    cfg["business_ports"] = list(current_map.values())
    # 导入的端口全部从 excluded_business_ports 解除排除
    excluded = set(int(p) for p in cfg.get("excluded_business_ports", []) if str(p).isdigit())
    for p in current_map.keys():
        if p in excluded:
            excluded.remove(p)
    cfg["excluded_business_ports"] = sorted(list(excluded))
    save_config(cfg)
    req._send_json({
        "success": True,
        "msg": f"业务端口列表导入成功！共载入 {count} 条 (当前自定义总计 {len(current_map)} 条)",
        "count": count,
        "total": len(current_map)
    })
    return

