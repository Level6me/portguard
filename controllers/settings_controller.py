# -*- coding: utf-8 -*-
import json
import time
from sentry_daemon import (
    load_config, save_config, get_config_snapshots, rollback_config_snapshot,
    check_c2_compromise_connections, trap_instance, sniffer_instance,
    site_collector_instance, init_firewall_ipset, flush_firewall_blocks,
    validate_cluster_target, normalize_cluster_node
)

def handle_settings_get(req, parsed):
    cfg = load_config()
    req._send_json({
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


def handle_config_snapshots(req, parsed):
    snaps = get_config_snapshots()
    req._send_json(snaps)
    return


def handle_config_backup(req, parsed):
    # 导出完整配置文件备份
    cfg_str = json.dumps(load_config(), indent=2, ensure_ascii=False).encode('utf-8')
    req.send_response(200)
    req.send_header('Content-Type', 'application/json; charset=utf-8')
    req.send_header('Content-Length', str(len(cfg_str)))
    req.send_header('Content-Disposition', f'attachment; filename="portguard_config_backup_{int(time.time())}.json"')
    req.end_headers()
    req.wfile.write(cfg_str)
    return


def handle_compromise_check(req, parsed):
    # C2 反向连线失陷检测
    alerts = check_c2_compromise_connections()
    req._send_json({
        "status": "safe" if not alerts else "warning",
        "compromised_alerts": alerts,
        "check_time": time.strftime("%Y-%m-%d %H:%M:%S")
    })
    return


def handle_defense_toggle(req, parsed, req_data):
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

    req._send_json({"success": True, "paused": is_paused, "msg": msg})
    return



def handle_settings_post(req, parsed, req_data):
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
        cs = req_data["cluster_sync"]
        if "cluster_nodes" in cs and isinstance(cs["cluster_nodes"], list):
            safe_nodes = []
            for n_raw in cs["cluster_nodes"]:
                norm = normalize_cluster_node(n_raw)
                if norm and norm.get("ip"):
                    ok, _, _ = validate_cluster_target(norm["ip"])
                    if ok:
                        safe_nodes.append(norm)
            cs["cluster_nodes"] = safe_nodes
        cfg["cluster_sync"] = cs
    save_config(cfg)
    req._send_json({"success": True, "msg": "系统防御设置已成功保存并立即生效！"})
    return



def handle_config_rollback(req, parsed, req_data):
    # 快照一键回滚接口
    snap_filename = req_data.get("filename", "").strip()
    if not snap_filename:
        req._send_json({"success": False, "msg": "缺少快照文件名"}, status=400)
        return
    ok, msg = rollback_config_snapshot(snap_filename)
    req._send_json({"success": ok, "msg": msg})
    return


