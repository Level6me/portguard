# -*- coding: utf-8 -*-
from urllib.parse import parse_qs
from sentry_daemon import get_db, _GEO_CACHE

def handle_events(req, parsed):
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
    req._send_json(rows)
    return



def handle_access_logs(req, parsed):
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
    req._send_json(rows)
    return


def handle_access_logs_clear(req, parsed, req_data):
    log_type = req_data.get("type", "port")
    conn = get_db()
    c = conn.cursor()
    if log_type == "web":
        c.execute("DELETE FROM access_logs")
    else:
        c.execute("DELETE FROM port_access_logs")
    conn.commit()
    conn.close()
    req._send_json({"success": True, "msg": f"{'Web控制台' if log_type == 'web' else '端口网络'}访问日志已全部清空"})
    return

