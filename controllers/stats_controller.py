# -*- coding: utf-8 -*-
import time
import json
from urllib.parse import parse_qs
from sentry_daemon import (
    get_db, load_config, DEFAULT_CONFIG, get_hidden_ips_set,
    resolve_ip_geo_local, _GEO_CACHE
)
from controllers.base import load_report_template

def handle_stats(req, parsed):
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

    req._send_json({
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


def handle_report_export(req, parsed):
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
    req.send_response(200)
    req.send_header('Content-Type', 'text/html; charset=utf-8')
    req.send_header('Content-Length', str(len(report_bytes)))
    req.send_header('Content-Disposition', f'attachment; filename="portguard_audit_report_{now_str[:10]}.html"')
    req.end_headers()
    req.wfile.write(report_bytes)
    return


def handle_analytics(req, parsed):
    query_params = parse_qs(parsed.query)
    range_param = query_params.get("range", ["7d"])[0]
    now_ts = int(time.time())
    now_dt = time.localtime(now_ts)
    today_str = time.strftime("%Y-%m-%d", now_dt)
    today_midnight = int(time.mktime(time.strptime(f"{today_str} 00:00:00", "%Y-%m-%d %H:%M:%S")))
    yesterday_dt = time.localtime(today_midnight - 3600)
    yesterday_str = time.strftime("%Y-%m-%d", yesterday_dt)
    yesterday_midnight = today_midnight - 86400

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

    c.execute("SELECT strftime('%H', datetime(timestamp, 'unixepoch', 'localtime')) AS hr, COUNT(*) as cnt FROM events WHERE timestamp >= ? AND timestamp < ? AND ip NOT IN (SELECT ip FROM hidden_ips) GROUP BY hr ORDER BY hr ASC", (cutoff_ts, end_ts))
    hourly_map = {row[0]: row[1] for row in c.fetchall() if row[0] is not None}
    hourly_dist = [{"hour": f"{h:02d}:00", "count": hourly_map.get(f"{h:02d}", 0)} for h in range(24)]

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

    req._send_json({
        "range": range_param,
        "date_info": {
            "start_time": time.strftime("%Y-%m-%d %H:%M", time.localtime(cutoff_ts)),
            "end_time": time.strftime("%Y-%m-%d %H:%M", time.localtime(end_ts)),
            "date_badge": date_badge,
            "date_sub": date_sub,
            "date_display": date_display
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

