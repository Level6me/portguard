import gzip
import os
import sys
import json
import time
import sqlite3
import subprocess
import re
import threading
try:
    from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
except ImportError:
    from http.server import HTTPServer, BaseHTTPRequestHandler
    from socketserver import ThreadingMixIn
    class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
        daemon_threads = True
        allow_reuse_address = True
from urllib.parse import urlparse, parse_qs

_RAW_HTML_CACHE = None
_GZIP_HTML_CACHE = None
from sentry_daemon import (
    DB_PATH, CONFIG_PATH, load_config, save_config, get_db, init_db,
    trap_instance, sniffer_instance, site_collector_instance, DEFAULT_CONFIG, PORT_DESCRIPTIONS,
    DEFAULT_HTTP_TRAPS, get_http_traps, check_http_request_traps,
    normalize_trap_item, log_access_entry, validate_ip, run_firewall_cmd,
    cleanup_expired_bans, ip_in_whitelist, resolve_ip_geo, _GEO_CACHE, _EXECUTOR
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

HTML_TEMPLATE = r"""<!DOCTYPE html>
<html lang="zh-CN" data-theme="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, minimum-scale=1.0, user-scalable=no, shrink-to-fit=no, viewport-fit=cover">
    <title>Portsentry · Apple Defense Dashboard</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        :root {
            --bg: #000000;
            --card: #1c1c1e;
            --card-sec: #2c2c2e;
            --card-hover: #262629;
            --text: #ffffff;
            --text-sec: #98989d;
            --text-ter: #636366;
            --accent: #007aff;
            --accent-hover: #0062cc;
            --accent-bg: rgba(0, 122, 255, 0.18);
            --danger: #ff3b30;
            --danger-bg: rgba(255, 59, 48, 0.16);
            --success: #34c759;
            --success-bg: rgba(52, 199, 89, 0.16);
            --warning: #ff9500;
            --warning-bg: rgba(255, 149, 0, 0.16);
            --purple: #af52de;
            --purple-bg: rgba(175, 82, 222, 0.16);
            --dock: rgba(28, 28, 30, 0.88);
            --border: rgba(255, 255, 255, 0.12);
            --border-subtle: rgba(255, 255, 255, 0.06);
            --modal-bg: rgba(28, 28, 30, 0.96);
            --table-stripe: rgba(255, 255, 255, 0.02);
            --shadow-sm: 0 2px 8px rgba(0, 0, 0, 0.3);
            --shadow-md: 0 6px 20px rgba(0, 0, 0, 0.45);
            --shadow-lg: 0 20px 50px rgba(0, 0, 0, 0.6);
        }

        :root[data-theme="light"] {
            --bg: #f2f2f7;
            --card: #ffffff;
            --card-sec: #f8f8fa;
            --card-hover: #f5f5f7;
            --text: #1c1c1e;
            --text-sec: #8e8e93;
            --text-ter: #aeaeb2;
            --accent-bg: rgba(0, 122, 255, 0.1);
            --dock: rgba(255, 255, 255, 0.85);
            --border: rgba(120, 120, 128, 0.15);
            --border-subtle: rgba(120, 120, 128, 0.08);
            --modal-bg: rgba(255, 255, 255, 0.95);
            --table-stripe: rgba(120, 120, 128, 0.03);
            --shadow-sm: 0 2px 8px rgba(0, 0, 0, 0.04);
            --shadow-md: 0 6px 20px rgba(0, 0, 0, 0.06);
            --shadow-lg: 0 20px 50px rgba(0, 0, 0, 0.18);
        }

        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, "SF Pro Text", "SF Pro Display", "PingFang SC", "Hiragino Sans GB", "Microsoft YaHei", sans-serif;
            background-color: var(--bg);
            color: var(--text);
            min-height: 100vh;
            padding: 12px 16px calc(100px + env(safe-area-inset-bottom)) 16px;
            -webkit-font-smoothing: antialiased;
            transition: background-color 0.3s ease, color 0.3s ease;
        }
        .container { max-width: 1100px; margin: 0 auto; }

        /* Toast Notifications */
        .toast-container {
            position: fixed;
            top: 20px;
            left: 50%;
            transform: translateX(-50%);
            z-index: 9999;
            display: flex;
            flex-direction: column;
            gap: 8px;
            pointer-events: none;
            width: max-content;
            max-width: 90vw;
        }
        .toast {
            background: var(--card);
            backdrop-filter: blur(24px);
            -webkit-backdrop-filter: blur(24px);
            border: 1px solid var(--border);
            color: var(--text);
            padding: 9px 16px;
            border-radius: 24px;
            font-size: 13px;
            font-weight: 600;
            box-shadow: var(--shadow-lg);
            display: flex;
            align-items: center;
            gap: 8px;
            animation: toastIn 0.25s cubic-bezier(0.1, 0.9, 0.2, 1);
            pointer-events: auto;
        }
        @keyframes toastIn {
            from { opacity: 0; transform: translateY(-12px) scale(0.95); }
            to { opacity: 1; transform: translateY(0) scale(1); }
        }

        /* Header (Abit 移动端与桌面自适应) */
        .header {
            margin: 4px 0 16px 0;
            display: flex;
            justify-content: space-between;
            align-items: center;
            gap: 8px;
            min-height: 48px;
            width: 100%;
        }
        .header-left {
            display: flex;
            flex-direction: column;
            justify-content: center;
            min-width: 0;
            flex-shrink: 1;
        }
        .date-badge {
            font-size: 11px;
            color: var(--text-sec);
            font-weight: 700;
            letter-spacing: 0.04em;
            text-transform: uppercase;
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
            display: flex;
            align-items: center;
            gap: 5px;
        }
        .status-dot {
            display: inline-block;
            width: 7px;
            height: 7px;
            border-radius: 50%;
            background: var(--success);
            box-shadow: 0 0 8px rgba(52, 199, 89, 0.5);
            animation: pulse 2s infinite;
            flex-shrink: 0;
        }
        @keyframes pulse { 0% { opacity: 0.4; } 50% { opacity: 1; } 100% { opacity: 0.4; } }
        .title {
            font-size: 28px;
            font-weight: 800;
            letter-spacing: -0.03em;
            line-height: 1.15;
            margin-top: 2px;
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
        }
        .header-actions {
            display: flex;
            align-items: center;
            gap: 6px;
            margin-left: auto;
            flex-shrink: 0;
        }

        @media (max-width: 600px) {
            .header { margin: 2px 0 12px 0; min-height: 42px; }
            .title { font-size: 22px; }
            .date-badge { font-size: 10px; }
            .pill-btn { padding: 5px 8px; font-size: 11px; gap: 4px; }
            .pill-btn .btn-text-full { display: none; }
        }

        /* Pill Buttons */
        .pill-btn {
            display: inline-flex;
            align-items: center;
            gap: 6px;
            padding: 6px 12px;
            border-radius: 20px;
            background: var(--card);
            border: 1px solid var(--border);
            font-size: 12px;
            font-weight: 600;
            color: var(--text);
            cursor: pointer;
            box-shadow: var(--shadow-sm);
            transition: all 0.2s cubic-bezier(0.1, 0.8, 0.25, 1);
            white-space: nowrap;
        }
        .pill-btn:hover { background: var(--card-hover); border-color: rgba(255,255,255,0.22); }
        .pill-btn:active { transform: scale(0.95); }
        .pill-btn.accent { background: var(--accent); color: #fff; border-color: var(--accent); }
        .pill-btn.danger { background: var(--danger-bg); color: var(--danger); border-color: rgba(255, 59, 48, 0.3); }
        .pill-btn.danger:hover { background: var(--danger); color: #fff; }

        /* Grid Layouts */
        .grid-4 {
            display: grid;
            grid-template-columns: repeat(4, minmax(0, 1fr));
            gap: 12px;
            margin-bottom: 16px;
        }
        @media (max-width: 860px) { .grid-4 { grid-template-columns: repeat(2, minmax(0, 1fr)); } }
        @media (max-width: 480px) { .grid-4 { grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 10px; } }

        .grid-2 {
            display: grid;
            grid-template-columns: repeat(2, minmax(0, 1fr));
            gap: 12px;
            margin-bottom: 16px;
        }
        @media (max-width: 768px) { .grid-2 { grid-template-columns: 1fr; } }

        /* Cards */
        .card {
            background: var(--card);
            border-radius: 18px;
            padding: 16px 18px;
            border: 1px solid var(--border);
            box-shadow: var(--shadow-sm);
            transition: transform 0.2s ease, box-shadow 0.2s ease;
            position: relative;
        }
        .card.interactive {
            cursor: pointer;
        }
        .card.interactive:hover {
            transform: translateY(-2px);
            box-shadow: var(--shadow-md);
            border-color: rgba(255,255,255,0.22);
        }
        .card-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 12px;
            gap: 10px;
        }
        @media (max-width: 600px) {
            .card-header {
                flex-direction: column;
                align-items: flex-start;
                gap: 8px;
            }
            .card-header .header-action-wrap {
                width: 100%;
                display: flex;
                justify-content: flex-end;
            }
            .card-header .header-action-wrap .pill-btn {
                padding: 6px 14px;
                font-size: 12px;
            }
        }
        .card-title {
            font-size: 15px;
            font-weight: 700;
            color: var(--text);
            display: flex;
            align-items: center;
            gap: 6px;
            letter-spacing: -0.01em;
        }
        .val-sub {
            font-size: 11px;
            color: var(--text-sec);
            font-weight: 600;
        }
        .val-big {
            font-size: 30px;
            font-weight: 800;
            letter-spacing: -0.03em;
            font-variant-numeric: tabular-nums;
            margin: 2px 0;
        }
        @media (max-width: 480px) {
            .val-big { font-size: 24px; }
            .card { padding: 12px 14px; border-radius: 14px; }
        }

        /* Filter Controls */
        .filter-row {
            display: flex;
            justify-content: space-between;
            align-items: center;
            gap: 10px;
            margin-bottom: 12px;
            flex-wrap: wrap;
        }
        .segmented-control {
            display: flex;
            background: var(--card-sec);
            padding: 3px;
            border-radius: 12px;
            gap: 2px;
            border: 1px solid var(--border-subtle);
            overflow-x: auto;
            max-width: 100%;
            -webkit-overflow-scrolling: touch;
        }
        .segment-btn {
            border: none;
            background: none;
            color: var(--text-sec);
            padding: 5px 12px;
            border-radius: 9px;
            font-size: 12px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.15s ease;
            white-space: nowrap;
        }
        .segment-btn.active {
            background: var(--card);
            color: var(--text);
            box-shadow: 0 2px 6px rgba(0,0,0,0.25);
        }
        .search-box {
            display: flex;
            align-items: center;
            background: var(--card-sec);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 0 10px;
            width: 240px;
        }
        @media (max-width: 600px) { .search-box { width: 100%; } }
        .search-box svg { width: 14px; height: 14px; fill: var(--text-sec); margin-right: 6px; flex-shrink: 0; }
        .search-box input {
            border: none;
            background: none;
            color: var(--text);
            font-size: 13px;
            outline: none;
            padding: 7px 0;
            width: 100%;
        }

        /* Tables & List View */
        .table-wrap {
            overflow-x: auto;
            border-radius: 14px;
            border: 1px solid var(--border-subtle);
            -webkit-overflow-scrolling: touch;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            text-align: left;
            font-size: 13px;
        }
        th {
            background: var(--card-sec);
            color: var(--text-sec);
            font-weight: 700;
            padding: 10px 14px;
            border-bottom: 1px solid var(--border);
            font-size: 11px;
            letter-spacing: 0.02em;
            white-space: nowrap;
        }
        td {
            padding: 12px 14px;
            border-bottom: 1px solid var(--border-subtle);
            color: var(--text);
            white-space: nowrap;
        }
        tr:hover td { background: var(--card-hover); }
        .ip-text {
            font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
            font-weight: 700;
            color: var(--accent);
            cursor: pointer;
            display: inline-flex;
            align-items: center;
            gap: 4px;
        }
        .ip-text:hover { text-decoration: underline; }

        /* Tags & Badges */
        .tag {
            display: inline-flex;
            align-items: center;
            padding: 3px 7px;
            border-radius: 6px;
            font-size: 11px;
            font-weight: 700;
            letter-spacing: -0.01em;
            white-space: nowrap;
        }
        .tag.danger { background: var(--danger-bg); color: var(--danger); }
        .tag.warning { background: var(--warning-bg); color: var(--warning); }
        .tag.success { background: var(--success-bg); color: var(--success); }
        .tag.accent { background: var(--accent-bg); color: var(--accent); }
        .tag.neutral { background: rgba(120,120,128,0.12); color: var(--text-sec); font-family: monospace; }

        /* Action Buttons */
        .action-btn {
            border: none;
            background: var(--card-sec);
            border: 1px solid var(--border);
            color: var(--text);
            padding: 5px 10px;
            border-radius: 8px;
            font-size: 12px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.15s ease;
            white-space: nowrap;
        }
        .action-btn:hover { background: var(--card-hover); border-color: rgba(255,255,255,0.25); }
        .action-btn.danger:hover { background: var(--danger-bg); color: var(--danger); border-color: var(--danger); }
        .action-btn.success:hover { background: var(--success-bg); color: var(--success); border-color: var(--success); }

        /* Bottom Spacer (防止 Dock 遮挡) */
        .bottom-spacer { height: 60px; width: 100%; }

        /* Floating Glass Dock (Abit 经典底栏) */
        .dock {
            position: fixed;
            bottom: calc(14px + env(safe-area-inset-bottom));
            left: 50%;
            transform: translateX(-50%);
            width: 94%;
            max-width: 480px;
            height: 62px;
            background: var(--dock);
            backdrop-filter: blur(28px) saturate(190%);
            -webkit-backdrop-filter: blur(28px) saturate(190%);
            border: 0.5px solid rgba(255, 255, 255, 0.22);
            border-radius: 31px;
            display: flex;
            justify-content: space-evenly;
            align-items: center;
            box-shadow: var(--shadow-lg);
            z-index: 1000;
            padding: 0 4px;
        }
        .dock-btn {
            border: none;
            background: none;
            min-width: 50px;
            height: 48px;
            border-radius: 14px;
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            gap: 2px;
            transition: all 0.2s cubic-bezier(0.1, 0.8, 0.25, 1);
            color: var(--text-sec);
            cursor: pointer;
            padding: 2px 4px;
        }
        .dock-btn:hover {
            color: var(--text);
            background: rgba(120, 120, 128, 0.08);
        }
        .dock-btn:active { transform: scale(0.92); }
        .dock-btn.active {
            color: var(--accent);
            background: var(--accent-bg);
        }
        .dock-btn svg { width: 18px; height: 18px; fill: currentColor; }
        .dock-btn span {
            font-size: 10px;
            font-weight: 700;
            letter-spacing: -0.01em;
        }

        /* Modal Sheets */
        .modal-overlay {
            position: fixed; top: 0; left: 0; right: 0; bottom: 0;
            background: rgba(0, 0, 0, 0.72); backdrop-filter: blur(16px);
            -webkit-backdrop-filter: blur(16px);
            display: none; align-items: center; justify-content: center; z-index: 2000;
            padding: 16px;
        }
        .modal-overlay.active {
            display: flex !important;
        }
        .modal-sheet {
            background: var(--modal-bg);
            border: 1px solid var(--border);
            border-radius: 20px;
            padding: 22px;
            width: 440px;
            max-width: 100%;
            box-shadow: var(--shadow-lg);
            animation: sheetIn 0.2s cubic-bezier(0.1, 0.9, 0.2, 1);
        }
        @keyframes sheetIn {
            from { opacity: 0; transform: scale(0.96) translateY(8px); }
            to { opacity: 1; transform: scale(1) translateY(0); }
        }
        .form-group { margin-bottom: 12px; }
        .form-label {
            display: block;
            font-size: 11px;
            color: var(--text-sec);
            font-weight: 700;
            margin-bottom: 5px;
            text-transform: uppercase;
            letter-spacing: 0.03em;
        }
        .form-control {
            width: 100%;
            background: var(--card-sec);
            border: 1px solid var(--border);
            border-radius: 10px;
            padding: 9px 12px;
            color: var(--text);
            font-size: 13px;
            outline: none;
        }
        .form-control:focus { border-color: var(--accent); }

        /* Progress Rank Bar */
        .rank-item {
            display: flex;
            align-items: center;
            justify-content: space-between;
            margin-bottom: 10px;
            font-size: 13px;
        }
        .rank-bar-bg {
            flex: 1;
            height: 6px;
            background: var(--card-sec);
            border-radius: 4px;
            margin: 0 10px;
            overflow: hidden;
        }
        .rank-bar-fill {
            height: 100%;
            background: var(--accent);
            border-radius: 4px;
        }
    </style>
</head>
<body>
<!-- Global Toast Container -->
<div class="toast-container" id="toast-container"></div>

<div class="container">
    <!-- Header Bar (Abit 移动端规范，绝不折行) -->
    <div class="header">
        <div class="header-left">
            <div class="date-badge">
                <span class="status-dot"></span>
                <span>PORTSENTRY · 内核防护中</span>
            </div>
            <h1 class="title" id="page-main-title">安全态势概览</h1>
        </div>
        <div class="header-actions">
            <button class="pill-btn" onclick="openSystemSettingsModal()" id="btn-settings-modal" title="系统防御与全局策略设置">
                <span>⚙️</span>
                <span class="btn-text-full">系统设置</span>
            </button>
            <button class="pill-btn" onclick="cycleTheme()" id="btn-theme-toggle" title="切换主题: 自动 (跟随系统) / 暗黑 / 明亮">
                <span id="theme-icon">🌓</span>
                <span id="theme-label" class="btn-text-full">自动</span>
            </button>
            <button class="pill-btn accent" onclick="toggleAutoRefresh()" id="btn-auto-refresh" title="点击开启或暂停 5 秒自动刷新">
                <span id="refresh-icon">⏱️</span>
                <span id="refresh-label" class="btn-text-full">5s 实时</span>
            </button>
        </div>
    </div>

    <!-- Page 1: 态势概览 (Overview) -->
    <div id="tab-overview">
        <!-- 4 核心统计卡 (支持交互点击跳转过滤) -->
        <div class="grid-4">
            <div class="card interactive" onclick="jumpToLogsFilter('all')" title="点击查看所有拦截记录">
                <div class="val-sub" style="color:var(--danger);">🚫 累计阻断 IP</div>
                <div class="val-big" id="stat-total" style="color: var(--danger);">--</div>
                <div class="val-sub">iptables + 路由黑洞</div>
            </div>
            <div class="card interactive" onclick="jumpToLogsFilter('all')" title="点击查看今日拦截记录">
                <div class="val-sub" style="color:var(--warning);">⚡ 今日捕获扫描</div>
                <div class="val-big" id="stat-today" style="color: var(--warning);">--</div>
                <div class="val-sub">毫秒级自动指纹识别</div>
            </div>
            <div class="card interactive" onclick="switchTab('traps')" title="点击管理蜜罐诱饵端口">
                <div class="val-sub" style="color:var(--accent);">🍯 活跃诱捕蜜罐</div>
                <div class="val-big" id="stat-traps" style="color: var(--accent);">--</div>
                <div class="val-sub">智能避让生产业务端口</div>
            </div>
            <div class="card interactive" onclick="switchTab('whitelist')" title="点击管理安全白名单">
                <div class="val-sub" style="color:var(--success);">🛡️ 安全信任白名单</div>
                <div class="val-big" id="stat-white" style="color: var(--success);">--</div>
                <div class="val-sub">运维专线防误封保护</div>
            </div>
        </div>

        <!-- 24小时攻击趋势与端口排行图 -->
        <div class="grid-2">
            <div class="card">
                <div class="card-header">
                    <div>
                        <div class="card-title">📈 24 小时扫描拦截趋势</div>
                        <div class="val-sub">触碰诱饵频次分布 (按小时)</div>
                    </div>
                </div>
                <div style="height: 200px;"><canvas id="trendChart"></canvas></div>
            </div>
            <div class="card">
                <div class="card-header">
                    <div>
                        <div class="card-title">🎯 诱饵命中排行 Top 5</div>
                        <div class="val-sub">高危服务探针类型分布</div>
                    </div>
                </div>
                <div style="height: 200px;"><canvas id="portChart"></canvas></div>
            </div>
        </div>

        <!-- 地域排行与近期威胁列表 -->
        <div class="grid-2">
            <div class="card">
                <div class="card-header">
                    <div class="card-title">🌍 攻击来源地域排行</div>
                </div>
                <div id="geo-rank-box" style="padding-top: 4px;">正在统计地域流量...</div>
            </div>
            <div class="card">
                <div class="card-header">
                    <div class="card-title">⚡ 实时最新拦截快报</div>
                    <button class="action-btn" onclick="switchTab('logs')">查看全部</button>
                </div>
                <div id="recent-threats-box">正在加载最新事件...</div>
            </div>
        </div>
        <div class="bottom-spacer"></div>
    </div>

    <!-- Page 2: 拦截审计日志 (Logs) -->
    <div id="tab-logs" style="display: none;">
        <div class="card">
            <div class="card-header">
                <div>
                    <div class="card-title">📋 蜜罐诱捕阻断日志</div>
                    <div class="val-sub">探测诱饵端口的公网恶意源</div>
                </div>
                <div class="header-action-wrap">
                    <button class="pill-btn" onclick="exportLogsCSV()">
                        <span>📥</span>
                        <span>导出 CSV</span>
                    </button>
                </div>
            </div>

            <div class="filter-row">
                <div class="segmented-control">
                    <button class="segment-btn active" id="seg-all" onclick="filterLogs('all', this)">全部 (<span id="cnt-log-all">0</span>)</button>
                    <button class="segment-btn" id="seg-rdp" onclick="filterLogs('rdp', this)">远程桌面 (3389/5900)</button>
                    <button class="segment-btn" id="seg-db" onclick="filterLogs('db', this)">数据库 (1433/6379/27017)</button>
                    <button class="segment-btn" id="seg-smb" onclick="filterLogs('smb', this)">高危共享 (445/135/139)</button>
                    <button class="segment-btn" id="seg-web" onclick="filterLogs('web', this)">控制台 (8888/9200)</button>
                </div>
                <div class="search-box">
                    <svg viewBox="0 0 24 24"><path d="M15.5 14h-.79l-.28-.27C15.41 12.59 16 11.11 16 9.5 16 5.91 13.09 3 9.5 3S3 5.91 3 9.5 5.91 16 9.5 16c1.61 0 3.09-.59 4.23-1.57l.27.28v.79l5 4.99L20.49 19l-4.99-5zm-6 0C7.01 14 5 11.99 5 9.5S7.01 5 9.5 5 14 7.01 14 9.5 11.99 14 9.5 14z"/></svg>
                    <input type="text" id="search-input" placeholder="过滤 IP / 国家 / 端口..." oninput="renderLogsTable()">
                </div>
            </div>

            <div class="table-wrap">
                <table>
                    <thead>
                        <tr>
                            <th>攻击拦截时间</th>
                            <th>攻击者 IP</th>
                            <th>归属地</th>
                            <th>命中诱饵端口</th>
                            <th>服务特征分类</th>
                            <th>威胁评级</th>
                            <th>防御处置</th>
                            <th>操作</th>
                        </tr>
                    </thead>
                    <tbody id="logs-tbody">
                        <tr><td colspan="8" style="text-align: center; color: var(--text-sec); padding: 30px;">正在载入审计日志...</td></tr>
                    </tbody>
                </table>
            </div>

            <!-- 拦截日志分页控制栏 (50条/页) -->
            <div style="display: flex; justify-content: space-between; align-items: center; padding: 14px 18px; border-top: 1px solid var(--border-subtle); flex-wrap: wrap; gap: 10px;">
                <div style="font-size: 12px; color: var(--text-sec);">
                    共 <b id="logs-total-cnt" style="color: var(--text);">0</b> 条记录 · 每页 50 条 · 当前第 <b id="logs-page-info" style="color: var(--accent);">1 / 1</b> 页
                </div>
                <div style="display: flex; gap: 6px; align-items: center;">
                    <button class="pill-btn" onclick="changeLogsPage(-1)" id="btn-logs-prev" style="padding: 5px 12px; font-size: 12px;">‹ 上一页</button>
                    <div id="logs-page-nums" style="display: flex; gap: 4px;"></div>
                    <button class="pill-btn" onclick="changeLogsPage(1)" id="btn-logs-next" style="padding: 5px 12px; font-size: 12px;">下一页 ›</button>
                </div>
            </div>
        </div>
        <div class="bottom-spacer"></div>
    </div>

    <!-- Page 3: 黑名单管理 (Blacklist) -->
    <div id="tab-blacklist" style="display: none;">
        <div class="card">
            <div class="card-header">
                <div>
                    <div class="card-title">🚫 内核黑名单池</div>
                    <div class="val-sub">iptables DROP 与路由黑洞阻断目标</div>
                </div>
                <div class="header-action-wrap">
                    <button class="pill-btn accent" onclick="batchBanAllProbes()" title="自动分析访问日志，将所有非白名单的历史扫描与探测 IP 批量拉黑并下发防火墙">
                        <span>⚡</span>
                        <span>一键拉黑历史探测IP</span>
                    </button>
                    <!-- 统一弹出式黑名单配置卡片按钮 -->
                    <div style="position: relative; display: inline-block;">
                        <button class="pill-btn danger" id="btn-blacklist-action-menu" onclick="toggleBlacklistActionMenu(event)" style="font-weight: 700;">
                            <span>⚙️ 黑名单管理与操作</span>
                            <span style="font-size: 10px; margin-left: 2px;">▾</span>
                        </button>
                        <div id="blacklist-action-popover" style="display: none; position: absolute; right: 0; top: calc(100% + 8px); background: var(--card); border: 1px solid var(--border); border-radius: 12px; box-shadow: 0 12px 36px rgba(0,0,0,0.3); min-width: 190px; z-index: 1000; padding: 6px; backdrop-filter: blur(25px);">
                            <div style="font-size: 11px; color: var(--text-sec); font-weight: 700; padding: 4px 8px 6px; text-transform: uppercase; letter-spacing: 0.5px;">🚫 黑名单操作配置</div>
                            <a href="javascript:void(0)" onclick="closeBlacklistActionMenu(); openManualBanModal();" style="display: flex; align-items: center; gap: 8px; padding: 8px 10px; color: var(--text); text-decoration: none; border-radius: 8px; font-size: 12px; font-weight: 600;" onmouseover="this.style.background='var(--card-sec)'" onmouseout="this.style.background='transparent'">
                                <span>➕</span><span>手动拉黑 IP</span>
                            </a>
                            <div style="height: 1px; background: var(--border-subtle); margin: 4px 0;"></div>
                            <a href="javascript:void(0)" onclick="closeBlacklistActionMenu(); openImportModal('blacklist');" style="display: flex; align-items: center; gap: 8px; padding: 8px 10px; color: var(--text); text-decoration: none; border-radius: 8px; font-size: 12px; font-weight: 600;" onmouseover="this.style.background='var(--card-sec)'" onmouseout="this.style.background='transparent'">
                                <span>📥</span><span>导入黑名单 (JSON)</span>
                            </a>
                            <a href="javascript:void(0)" onclick="closeBlacklistActionMenu(); exportBlacklistJSON();" style="display: flex; align-items: center; gap: 8px; padding: 8px 10px; color: var(--text); text-decoration: none; border-radius: 8px; font-size: 12px; font-weight: 600;" onmouseover="this.style.background='var(--card-sec)'" onmouseout="this.style.background='transparent'">
                                <span>📤</span><span>导出黑名单 (JSON)</span>
                            </a>
                        </div>
                    </div>
                </div>
            </div>

            <div class="table-wrap">
                <table>
                    <thead>
                        <tr>
                            <th>已阻断 IP 地址</th>
                            <th>拉黑原因 / 诱饵端口</th>
                            <th>归属地</th>
                            <th>处置动作</th>
                            <th>封禁时间</th>
                            <th>管理操作</th>
                        </tr>
                    </thead>
                    <tbody id="blacklist-tbody">
                        <tr><td colspan="6" style="text-align: center; color: var(--text-sec); padding: 30px;">正在载入黑名单...</td></tr>
                    </tbody>
                </table>
            </div>

            <!-- 黑名单分页控制栏 (50条/页) -->
            <div style="display: flex; justify-content: space-between; align-items: center; padding: 14px 18px; border-top: 1px solid var(--border-subtle); flex-wrap: wrap; gap: 10px;">
                <div style="font-size: 12px; color: var(--text-sec);">
                    共 <b id="blacklist-total-cnt" style="color: var(--text);">0</b> 条记录 · 每页 50 条 · 当前第 <b id="blacklist-page-info" style="color: var(--accent);">1 / 1</b> 页
                </div>
                <div style="display: flex; gap: 6px; align-items: center;">
                    <button class="pill-btn" onclick="changeBlacklistPage(-1)" id="btn-blacklist-prev" style="padding: 5px 12px; font-size: 12px;">‹ 上一页</button>
                    <div id="blacklist-page-nums" style="display: flex; gap: 4px;"></div>
                    <button class="pill-btn" onclick="changeBlacklistPage(1)" id="btn-blacklist-next" style="padding: 5px 12px; font-size: 12px;">下一页 ›</button>
                </div>
            </div>
        </div>
        <div class="bottom-spacer"></div>
    </div>

    <!-- Page 4: 蜜罐诱饵策略 (Traps) -->
    <div id="tab-traps" style="display: none;">
        <div class="card">
            <div class="card-header">
                <div>
                    <div class="card-title" id="traps-main-title">🍯 活跃蜜罐策略与诱饵端口</div>
                    <div class="val-sub" id="traps-main-sub">模拟高危服务静默监听，一旦连入即自动封禁</div>
                </div>
                <div class="header-action-wrap">
                    <!-- 模式切换分段按钮 -->
                    <div style="background: var(--card-sec); border: 1px solid var(--border); border-radius: 99px; padding: 2px; display: inline-flex; gap: 2px;">
                        <button class="pill-btn accent" id="btn-trap-tab-port" onclick="switchTrapTab('port')" style="padding: 4px 10px; font-size: 11px; border-radius: 99px; font-weight: 700;">🔌 端口策略</button>
                        <button class="pill-btn" id="btn-trap-tab-req" onclick="switchTrapTab('req')" style="padding: 4px 10px; font-size: 11px; border-radius: 99px; font-weight: 700; background: transparent;">🎯 请求特征</button>
                    </div>
                    <!-- 统一弹出式策略配置卡片按钮 -->
                    <div style="position: relative; display: inline-block;">
                        <button class="pill-btn accent" id="btn-trap-action-menu" onclick="toggleTrapActionMenu(event)" style="font-weight: 700;">
                            <span>⚙️ 策略管理与配置</span>
                            <span style="font-size: 10px; margin-left: 2px;">▾</span>
                        </button>
                        <div id="trap-action-popover" style="display: none; position: absolute; right: 0; top: calc(100% + 8px); background: var(--card); border: 1px solid var(--border); border-radius: 12px; box-shadow: 0 12px 36px rgba(0,0,0,0.3); min-width: 190px; z-index: 1000; padding: 6px; backdrop-filter: blur(25px);">
                            <div id="trap-popover-content"></div>
                        </div>
                    </div>
                </div>
            </div>

            <div class="table-wrap">
                <table>
                    <thead id="traps-thead">
                        <tr>
                            <th>诱饵端口</th>
                            <th>模拟服务描述</th>
                            <th>分类</th>
                            <th>威胁等级</th>
                            <th>当前状态</th>
                            <th>开关操作</th>
                        </tr>
                    </thead>
                    <tbody id="traps-tbody">
                        <tr><td colspan="6" style="text-align: center; color: var(--text-sec); padding: 30px;">正在载入策略...</td></tr>
                    </tbody>
                </table>
            </div>

            <!-- 蜜罐策略分页控制栏 (50条/页) -->
            <div style="display: flex; justify-content: space-between; align-items: center; padding: 14px 18px; border-top: 1px solid var(--border-subtle); flex-wrap: wrap; gap: 10px;">
                <div style="font-size: 12px; color: var(--text-sec);">
                    共 <b id="traps-total-cnt" style="color: var(--text);">0</b> 条策略 · 每页 50 条 · 当前第 <b id="traps-page-info" style="color: var(--accent);">1 / 1</b> 页
                </div>
                <div style="display: flex; gap: 6px; align-items: center;">
                    <button class="pill-btn" onclick="changeTrapsPage(-1)" id="btn-traps-prev" style="padding: 5px 12px; font-size: 12px;">‹ 上一页</button>
                    <div id="traps-page-nums" style="display: flex; gap: 4px;"></div>
                    <button class="pill-btn" onclick="changeTrapsPage(1)" id="btn-traps-next" style="padding: 5px 12px; font-size: 12px;">下一页 ›</button>
                </div>
            </div>
        </div>
        <div class="bottom-spacer"></div>
    </div>

    <!-- Page 5: 白名单管理 (Whitelist) -->
    <div id="tab-whitelist" style="display: none;">
        <div class="card">
            <div class="card-header">
                <div>
                    <div class="card-title">🛡️ 运维与安全信任白名单</div>
                    <div class="val-sub">白名单内的 IP 永不触发任何封禁拦截机制</div>
                </div>
                <div class="header-action-wrap">
                    <!-- 统一弹出式白名单配置卡片按钮 -->
                    <div style="position: relative; display: inline-block;">
                        <button class="pill-btn accent" id="btn-whitelist-action-menu" onclick="toggleWhitelistActionMenu(event)" style="font-weight: 700;">
                            <span>⚙️ 白名单管理与配置</span>
                            <span style="font-size: 10px; margin-left: 2px;">▾</span>
                        </button>
                        <div id="whitelist-action-popover" style="display: none; position: absolute; right: 0; top: calc(100% + 8px); background: var(--card); border: 1px solid var(--border); border-radius: 12px; box-shadow: 0 12px 36px rgba(0,0,0,0.3); min-width: 190px; z-index: 1000; padding: 6px; backdrop-filter: blur(25px);">
                            <div style="font-size: 11px; color: var(--text-sec); font-weight: 700; padding: 4px 8px 6px; text-transform: uppercase; letter-spacing: 0.5px;">🛡️ 白名单操作配置</div>
                            <a href="javascript:void(0)" onclick="closeWhitelistActionMenu(); openAddWhiteModal();" style="display: flex; align-items: center; gap: 8px; padding: 8px 10px; color: var(--text); text-decoration: none; border-radius: 8px; font-size: 12px; font-weight: 600;" onmouseover="this.style.background='var(--card-sec)'" onmouseout="this.style.background='transparent'">
                                <span>➕</span><span>添加信任 IP</span>
                            </a>
                            <div style="height: 1px; background: var(--border-subtle); margin: 4px 0;"></div>
                            <a href="javascript:void(0)" onclick="closeWhitelistActionMenu(); openImportModal('whitelist');" style="display: flex; align-items: center; gap: 8px; padding: 8px 10px; color: var(--text); text-decoration: none; border-radius: 8px; font-size: 12px; font-weight: 600;" onmouseover="this.style.background='var(--card-sec)'" onmouseout="this.style.background='transparent'">
                                <span>📥</span><span>导入白名单 (JSON)</span>
                            </a>
                            <a href="javascript:void(0)" onclick="closeWhitelistActionMenu(); exportWhitelistJSON();" style="display: flex; align-items: center; gap: 8px; padding: 8px 10px; color: var(--text); text-decoration: none; border-radius: 8px; font-size: 12px; font-weight: 600;" onmouseover="this.style.background='var(--card-sec)'" onmouseout="this.style.background='transparent'">
                                <span>📤</span><span>导出白名单 (JSON)</span>
                            </a>
                        </div>
                    </div>
                </div>
            </div>

            <div class="table-wrap">
                <table>
                    <thead>
                        <tr>
                            <th>信任 IP / 网段</th>
                            <th>备注说明</th>
                            <th>操作</th>
                        </tr>
                    </thead>
                    <tbody id="whitelist-tbody">
                        <tr><td colspan="3" style="text-align: center; color: var(--text-sec); padding: 30px;">正在载入白名单...</td></tr>
                    </tbody>
                </table>
            </div>

            <!-- 白名单分页控制栏 (50条/页) -->
            <div style="display: flex; justify-content: space-between; align-items: center; padding: 14px 18px; border-top: 1px solid var(--border-subtle); flex-wrap: wrap; gap: 10px;">
                <div style="font-size: 12px; color: var(--text-sec);">
                    共 <b id="whitelist-total-cnt" style="color: var(--text);">0</b> 条白名单 · 每页 50 条 · 当前第 <b id="whitelist-page-info" style="color: var(--accent);">1 / 1</b> 页
                </div>
                <div style="display: flex; gap: 6px; align-items: center;">
                    <button class="pill-btn" onclick="changeWhitelistPage(-1)" id="btn-whitelist-prev" style="padding: 5px 12px; font-size: 12px;">‹ 上一页</button>
                    <div id="whitelist-page-nums" style="display: flex; gap: 4px;"></div>
                    <button class="pill-btn" onclick="changeWhitelistPage(1)" id="btn-whitelist-next" style="padding: 5px 12px; font-size: 12px;">下一页 ›</button>
                </div>
            </div>
        </div>
        <div class="bottom-spacer"></div>
    </div>

    <!-- Page 6: 访问日志 (Access Logs) -->
    <div id="tab-access-logs" style="display: none;">
        <div class="card">
            <div class="card-header">
                <div>
                    <div class="card-title" id="access-logs-title">🍯 端口访问日志</div>
                    <div class="val-sub" id="access-logs-sub">实时记录所有外部客户端对本机各诱捕端口与网络端口的连接嗅探</div>
                </div>
                <div class="header-action-wrap">
                    <!-- 模式切换分段按钮 -->
                    <div style="background: var(--card-sec); border: 1px solid var(--border); border-radius: 99px; padding: 2px; display: inline-flex; gap: 2px;">
                        <button class="pill-btn accent" id="btn-access-mode-port" onclick="switchAccessLogMode('port')" style="padding: 4px 10px; font-size: 11px; border-radius: 99px; font-weight: 700;">🍯 端口访问</button>
                        <button class="pill-btn" id="btn-access-mode-web" onclick="switchAccessLogMode('web')" style="padding: 4px 10px; font-size: 11px; border-radius: 99px; font-weight: 700; background: transparent;">🌍 443访问</button>
                    </div>
                    <button class="pill-btn" onclick="exportAccessLogsCSV()">
                        <span>📥</span>
                        <span>导出 CSV</span>
                    </button>
                    <button class="pill-btn danger" onclick="clearAccessLogs()">
                        <span>🗑️</span>
                        <span>清空日志</span>
                    </button>
                </div>
            </div>

            <!-- 筛选与搜索工具栏 -->
            <div style="display: flex; justify-content: space-between; align-items: center; padding: 10px 18px; border-bottom: 1px solid var(--border-subtle); flex-wrap: wrap; gap: 10px;">
                <div class="segmented-control" id="access-action-segments">
                    <button class="segment-btn active" id="seg-acc-all" onclick="filterAccessLogs('all', this)">全部</button>
                    <button class="segment-btn" id="seg-acc-biz" onclick="filterAccessLogs('BUSINESS', this)">⚡ 正常业务</button>
                    <button class="segment-btn" id="seg-acc-white" onclick="filterAccessLogs('WHITELIST', this)">🛡️ 信任放行</button>
                    <button class="segment-btn" id="seg-acc-block" onclick="filterAccessLogs('INTERCEPTED', this)">🚫 诱捕阻断</button>
                    <button class="segment-btn" id="seg-acc-probe" onclick="filterAccessLogs('PROBE', this)">🔍 外部探测</button>
                </div>
                <div class="search-box">
                    <svg viewBox="0 0 24 24"><path d="M15.5 14h-.79l-.28-.27C15.41 12.59 16 11.11 16 9.5 16 5.91 13.09 3 9.5 3S3 5.91 3 9.5 5.91 16 9.5 16c1.61 0 3.09-.59 4.23-1.57l.27.28v.79l5 4.99L20.49 19l-4.99-5zm-6 0C7.01 14 5 11.99 5 9.5S7.01 5 9.5 5 14 7.01 14 9.5 11.99 14 9.5 14z"/></svg>
                    <input type="text" id="access-search-input" placeholder="过滤 IP / 端口 / 服务 / 路径 / 归属地..." oninput="renderAccessLogsTable()">
                </div>
            </div>

            <div class="table-wrap">
                <table>
                    <thead id="access-logs-thead">
                        <tr>
                            <th>访问时间</th>
                            <th>来源 IP</th>
                            <th>归属地</th>
                            <th>目标端口</th>
                            <th>服务说明</th>
                            <th>防御处置</th>
                        </tr>
                    </thead>
                    <tbody id="access-logs-tbody">
                        <tr><td colspan="6" style="text-align: center; color: var(--text-sec); padding: 30px;">正在载入访问日志...</td></tr>
                    </tbody>
                </table>
            </div>

            <!-- 分页控制栏 (50条/页) -->
            <div style="display: flex; justify-content: space-between; align-items: center; padding: 14px 18px; border-top: 1px solid var(--border-subtle); flex-wrap: wrap; gap: 10px;">
                <div style="font-size: 12px; color: var(--text-sec);">
                    共 <b id="access-log-total-cnt" style="color: var(--text);">0</b> 条记录 · 每页 50 条 · 当前第 <b id="access-log-page-info" style="color: var(--accent);">1 / 1</b> 页
                </div>
                <div style="display: flex; gap: 6px; align-items: center;">
                    <button class="pill-btn" onclick="changeAccessLogPage(-1)" id="btn-access-prev" style="padding: 5px 12px; font-size: 12px;">‹ 上一页</button>
                    <div id="access-log-page-nums" style="display: flex; gap: 4px;"></div>
                    <button class="pill-btn" onclick="changeAccessLogPage(1)" id="btn-access-next" style="padding: 5px 12px; font-size: 12px;">下一页 ›</button>
                </div>
            </div>
        </div>
        <div class="bottom-spacer"></div>
    </div>
</div>

<!-- Floating Glass Dock (Abit 经典底栏) -->
<div class="dock">
    <button class="dock-btn active" id="dock-btn-overview" onclick="switchTab('overview', this)">
        <svg viewBox="0 0 24 24"><path d="M3 13h8V3H3v10zm0 8h8v-6H3v6zm10 0h8V11h-8v10zm0-18v6h8V3h-8z"/></svg>
        <span>态势概览</span>
    </button>
    <button class="dock-btn" id="dock-btn-logs" onclick="switchTab('logs', this)">
        <svg viewBox="0 0 24 24"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm1 15h-2v-2h2v2zm0-4h-2V7h2v6z"/></svg>
        <span>拦截日志</span>
    </button>
    <button class="dock-btn" id="dock-btn-access-logs" onclick="switchTab('access-logs', this)">
        <svg viewBox="0 0 24 24"><path d="M19 3H5c-1.1 0-2 .9-2 2v14c0 1.1.9 2 2 2h14c1.1 0 2-.9 2-2V5c0-1.1-.9-2-2-2zm-5 14H7v-2h7v2zm3-4H7v-2h10v2zm0-4H7V7h10v2z"/></svg>
        <span>访问日志</span>
    </button>
    <button class="dock-btn" id="dock-btn-blacklist" onclick="switchTab('blacklist', this)">
        <svg viewBox="0 0 24 24"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zM4 12c0-4.42 3.58-8 8-8 1.85 0 3.55.63 4.9 1.69L5.69 16.9C4.63 15.55 4 13.85 4 12zm8 8c-1.85 0-3.55-.63-4.9-1.69L18.31 7.1c1.06 1.35 1.69 3.05 1.69 4.9 0 4.42-3.58 8-8 8z"/></svg>
        <span>黑名单池</span>
    </button>
    <button class="dock-btn" id="dock-btn-traps" onclick="switchTab('traps', this)">
        <svg viewBox="0 0 24 24"><path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4zm0 10.99h7c-.53 4.12-3.28 7.79-7 8.94V12H5V6.3l7-3.11v8.8z"/></svg>
        <span>蜜罐策略</span>
    </button>
    <button class="dock-btn" id="dock-btn-whitelist" onclick="switchTab('whitelist', this)">
        <svg viewBox="0 0 24 24"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-2 15l-5-5 1.41-1.41L10 14.17l7.59-7.59L19 8l-9 9z"/></svg>
        <span>信任白名单</span>
    </button>
</div>

<!-- Modal: 系统设置弹窗 -->
<div class="modal-overlay" id="modal-settings">
    <div class="modal-sheet" style="max-width: 620px;">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px;">
            <h3 style="font-size: 16px; font-weight: 700; display: flex; align-items: center; gap: 8px;">
                <span>⚙️</span>
                <span>系统防御参数与全局设置</span>
            </h3>
            <button class="action-btn" onclick="closeModals()" style="font-size: 16px; padding: 4px 8px;">✕</button>
        </div>

        <div style="display: flex; flex-direction: column; gap: 16px; max-height: 75vh; overflow-y: auto; padding-right: 4px;">
            <!-- 1. 封禁灵敏度与阈值 -->
            <div style="background: var(--card-sec); border: 1px solid var(--border); border-radius: 10px; padding: 14px;">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
                    <span style="font-weight: 700; font-size: 13px; color: var(--text);">🎯 诱捕探测判定与自动拉黑阈值</span>
                    <span class="badge badge-high" id="badge-threshold-status">主动严防</span>
                </div>
                <div style="font-size: 11px; color: var(--text-sec); margin-bottom: 10px; line-height: 1.4;">
                    外部 IP 在指定时间窗口内触碰蜜罐端口达到设定次数后，自动触发内核阻断并加入黑名单。
                </div>
                <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 10px;">
                    <div>
                        <label style="font-size: 11px; font-weight: 600; color: var(--text-sec);">触发封禁探测次数</label>
                        <select id="setting-trap-threshold" class="input-field" style="width: 100%; margin-top: 4px; padding: 8px 10px; font-size: 12px; font-weight: 600;">
                            <option value="1">1 次 (零容忍立即封禁)</option>
                            <option value="2">2 次 (严苛防御)</option>
                            <option value="3">3 次 (标准防误触)</option>
                            <option value="5">5 次 (宽松模式)</option>
                        </select>
                    </div>
                    <div>
                        <label style="font-size: 11px; font-weight: 600; color: var(--text-sec);">统计判定时间窗口</label>
                        <select id="setting-trap-window" class="input-field" style="width: 100%; margin-top: 4px; padding: 8px 10px; font-size: 12px; font-weight: 600;">
                            <option value="15">15 秒</option>
                            <option value="30">30 秒 (标准默认)</option>
                            <option value="60">60 秒 (长窗口感知)</option>
                            <option value="300">300 秒 (5分钟慢速感知)</option>
                            <option value="600">600 秒 (10分钟超长感知)</option>
                        </select>
                    </div>
                </div>
            </div>

            <!-- 2. 封禁时长与自动解封周期 -->
            <div style="background: var(--card-sec); border: 1px solid var(--border); border-radius: 10px; padding: 14px;">
                <div style="font-weight: 700; font-size: 13px; color: var(--text); margin-bottom: 6px;">⏳ 黑名单封禁周期与自动解封</div>
                <div style="font-size: 11px; color: var(--text-sec); margin-bottom: 10px; line-height: 1.4;">
                    被拉黑攻击 IP 的持续阻断天数。设为永久封禁时永不自动解封。
                </div>
                <div>
                    <label style="font-size: 11px; font-weight: 600; color: var(--text-sec);">自动解封周期</label>
                    <select id="setting-auto-clean" class="input-field" style="width: 100%; margin-top: 4px; padding: 8px 10px; font-size: 12px; font-weight: 600;">
                        <option value="7">7 天 (临时阻断)</option>
                        <option value="30">30 天 (标准推荐)</option>
                        <option value="90">90 天 (长期封锁)</option>
                        <option value="180">180 天 (半年封锁)</option>
                        <option value="0">永久封禁 (永不自动解封)</option>
                    </select>
                </div>
            </div>

            <!-- 3. 全局全端口零信任诱捕 -->
            <div style="background: var(--card-sec); border: 1px solid var(--border); border-radius: 10px; padding: 14px;">
                <div style="font-weight: 700; font-size: 13px; color: var(--text); margin-bottom: 6px;">⚡ 全端口零信任诱捕拉黑（全网全端口诱捕）</div>
                <div style="font-size: 11px; color: var(--text-sec); margin-bottom: 10px; line-height: 1.4;">
                    基于 Linux 原生网络层感知，外部非白名单 IP 探测服务器上的任何端口（包括开放、未开放、蜜罐或业务端口）时，立即毫秒级拉黑并下发内核防火墙。
                </div>
                <div style="display: flex; flex-direction: column; gap: 8px;">
                    <label style="display: flex; align-items: center; gap: 8px; font-size: 12px; color: var(--text); cursor: pointer;">
                        <input type="checkbox" id="setting-trap-all-ports" checked style="width: 16px; height: 16px; accent-color: var(--accent);">
                        <span><b>开启探测任何端口立即诱捕拉黑</b>（所有入站非白名单探测一律直接封禁）</span>
                    </label>
                    <label style="display: flex; align-items: center; gap: 8px; font-size: 12px; color: var(--text); cursor: pointer;">
                        <input type="checkbox" id="setting-trap-all-unopened" checked style="width: 16px; height: 16px; accent-color: var(--accent);">
                        <span><b>未开放端口隐蔽嗅探诱捕</b>（探测任意未开放端口立即拉黑阻断）</span>
                    </label>
                </div>
            </div>

            <!-- 4. 内核阻断机制 -->
            <div style="background: var(--card-sec); border: 1px solid var(--border); border-radius: 10px; padding: 14px;">
                <div style="font-weight: 700; font-size: 13px; color: var(--text); margin-bottom: 6px;">🛡️ Linux 内核底层阻断联动方式</div>
                <div style="display: flex; flex-direction: column; gap: 8px;">
                    <label style="display: flex; align-items: center; gap: 8px; font-size: 12px; color: var(--text); cursor: pointer;">
                        <input type="checkbox" id="setting-ban-iptables" checked style="width: 16px; height: 16px; accent-color: var(--accent);">
                        <span><b>iptables DROP 规则阻断</b>（在系统 INPUT 链顶层直接丢弃数据包）</span>
                    </label>
                    <label style="display: flex; align-items: center; gap: 8px; font-size: 12px; color: var(--text); cursor: pointer;">
                        <input type="checkbox" id="setting-ban-blackhole" checked style="width: 16px; height: 16px; accent-color: var(--accent);">
                        <span><b>Linux 内核路由黑洞 (blackhole)</b>（在路由选路阶段直接丢弃）</span>
                    </label>
                </div>
            </div>
        </div>

        <div style="display: flex; justify-content: flex-end; gap: 10px; margin-top: 18px;">
            <button class="pill-btn" onclick="closeModals()">取消</button>
            <button class="pill-btn accent" onclick="saveSystemSettings()" style="padding: 8px 20px; font-weight: 700;">💾 保存设置</button>
        </div>
    </div>
</div>

<!-- Modal: 手动拉黑 -->
<div class="modal-overlay" id="modal-ban">
    <div class="modal-sheet">
        <h3 style="font-size: 16px; font-weight: 700; margin-bottom: 14px;">🚫 手动添加永久黑名单</h3>
        <div class="form-group">
            <label class="form-label">目标 IP 地址 / CIDR 段</label>
            <input type="text" class="form-control" id="ban-ip-val" placeholder="例如 1.2.3.4">
        </div>
        <div class="form-group">
            <label class="form-label">拉黑原因</label>
            <input type="text" class="form-control" id="ban-reason-val" value="管理员手动全局拉黑">
        </div>
        <div style="display: flex; justify-content: flex-end; gap: 8px; margin-top: 18px;">
            <button class="pill-btn" onclick="closeModals()">取消</button>
            <button class="pill-btn danger" onclick="submitManualBan()">立即永久阻断</button>
        </div>
    </div>
</div>

<!-- Modal: 添加白名单 -->
<div class="modal-overlay" id="modal-white">
    <div class="modal-sheet">
        <h3 style="font-size: 16px; font-weight: 700; margin-bottom: 14px;">🛡️ 添加安全信任白名单</h3>
        <div class="form-group">
            <label class="form-label">信任 IP 地址 / 网段</label>
            <input type="text" class="form-control" id="white-ip-val" placeholder="例如 111.183.103.75">
        </div>
        <div class="form-group">
            <label class="form-label">备注说明</label>
            <input type="text" class="form-control" id="white-remark-val" placeholder="例如：办公室运维固定宽带">
        </div>
        <div style="display: flex; justify-content: flex-end; gap: 8px; margin-top: 18px;">
            <button class="pill-btn" onclick="closeModals()">取消</button>
            <button class="pill-btn accent" onclick="submitAddWhite()">确认添加</button>
        </div>
    </div>
</div>

<!-- Modal: 添加诱饵 -->
<div class="modal-overlay" id="modal-trap">
    <div class="modal-sheet">
        <h3 style="font-size: 16px; font-weight: 700; margin-bottom: 14px;">🍯 添加自定义诱饵端口</h3>
        <div class="form-group">
            <label class="form-label">端口号或端口范围 (例如 8088 或 1000-3000)</label>
            <input type="text" class="form-control" id="trap-port-val" placeholder="单个端口如 8088，或范围如 1000-3000">
        </div>
        <div class="form-group">
            <label class="form-label">模拟服务说明</label>
            <input type="text" class="form-control" id="trap-name-val" placeholder="例如：测试管理后台">
        </div>
        <div class="form-group">
            <label class="form-label">分类类型</label>
            <select class="form-control" id="trap-cat-val">
                <option value="web" selected>管理面板/Web</option>
                <option value="rdp">远程控制/RDP</option>
                <option value="db">数据库服务</option>
                <option value="smb">文件共享/SMB</option>
                <option value="custom">自定义服务</option>
            </select>
        </div>
        <div class="form-group">
            <label class="form-label">威胁等级评定</label>
            <select class="form-control" id="trap-level-val">
                <option value="极高危">极高危</option>
                <option value="高危" selected>高危</option>
                <option value="中危">中危</option>
            </select>
        </div>
        <div class="form-group">
            <label style="display: flex; align-items: center; gap: 8px; font-size: 12px; color: var(--text); cursor: pointer; background: var(--card-sec); padding: 10px 12px; border-radius: 10px; border: 1px solid var(--border);">
                <input type="checkbox" id="trap-is-business-val" style="width: 16px; height: 16px; accent-color: var(--danger);">
                <span><b>正常业务端口防护</b>（若该端口为当前运行的真实业务，勾选后将同步诱捕该端口的非白名单访问）</span>
            </label>
        </div>
        <div style="display: flex; justify-content: flex-end; gap: 8px; margin-top: 18px;">
            <button class="pill-btn" onclick="closeModals()">取消</button>
            <button class="pill-btn accent" onclick="submitAddTrap()">激活诱饵</button>
        </div>
    </div>
</div>

<!-- Modal: 编辑蜜罐诱饵策略 -->
<div class="modal-overlay" id="modal-trap-edit">
    <div class="modal-sheet">
        <h3 style="font-size: 16px; font-weight: 700; margin-bottom: 14px;">✏️ 编辑蜜罐诱饵策略</h3>
        <input type="hidden" id="edit-trap-orig-port">
        <div class="form-group">
            <label class="form-label">端口号或端口范围 (例如 8088 或 1000-3000)</label>
            <input type="text" class="form-control" id="edit-trap-port-val" placeholder="单个端口如 8088，或范围如 1000-3000">
        </div>
        <div class="form-group">
            <label class="form-label">模拟服务说明</label>
            <input type="text" class="form-control" id="edit-trap-name-val" placeholder="例如：测试管理后台">
        </div>
        <div class="form-group">
            <label class="form-label">分类类型</label>
            <select class="form-control" id="edit-trap-cat-val">
                <option value="web">管理面板/Web</option>
                <option value="rdp">远程控制/RDP</option>
                <option value="db">数据库服务</option>
                <option value="smb">文件共享/SMB</option>
                <option value="ftp">FTP 服务</option>
                <option value="telnet">Telnet 服务</option>
                <option value="custom">自定义服务</option>
            </select>
        </div>
        <div class="form-group">
            <label class="form-label">威胁等级评定</label>
            <select class="form-control" id="edit-trap-level-val">
                <option value="极高危">极高危</option>
                <option value="高危">高危</option>
                <option value="中危">中危</option>
            </select>
        </div>
        <div class="form-group">
            <label class="form-label">诱捕开关状态</label>
            <select class="form-control" id="edit-trap-enabled-val">
                <option value="true">● 启用监听诱捕 (Accept)</option>
                <option value="false">○ 停用监听 (Reject/Disabled)</option>
            </select>
        </div>
        <div class="form-group">
            <label style="display: flex; align-items: center; gap: 8px; font-size: 12px; color: var(--text); cursor: pointer; background: var(--card-sec); padding: 10px 12px; border-radius: 10px; border: 1px solid var(--border);">
                <input type="checkbox" id="edit-trap-is-business-val" style="width: 16px; height: 16px; accent-color: var(--danger);">
                <span><b>正常业务端口防护</b>（若该端口为当前运行的真实业务，勾选后将同步诱捕该端口的非白名单访问）</span>
            </label>
        </div>
        <div style="display: flex; justify-content: flex-end; gap: 8px; margin-top: 18px;">
            <button class="pill-btn" onclick="closeModals()">取消</button>
            <button class="pill-btn accent" onclick="submitEditTrap()">保存修改</button>
        </div>
    </div>
</div>

<!-- Modal: 添加请求特征策略 -->
<div class="modal-overlay" id="modal-http-trap">
    <div class="modal-sheet" style="max-width: 540px;">
        <h3 style="font-size: 16px; font-weight: 700; margin-bottom: 14px;">🎯 添加请求特征与防扫描策略</h3>
        <div class="form-group">
            <label class="form-label">策略名称</label>
            <input type="text" class="form-control" id="http-trap-name-val" placeholder="例如：敏感配置与密钥嗅探">
        </div>
        <div class="form-group">
            <label class="form-label">匹配类型</label>
            <select class="form-control" id="http-trap-type-val" onchange="onHttpTrapTypeChange('add')">
                <option value="path_keyword" selected>URL 路径特征 (关键词 / 正则)</option>
                <option value="ua_keyword">扫描工具 User-Agent 指纹</option>
                <option value="status_rate">404 / 403 异常高频熔断</option>
            </select>
        </div>
        <div class="form-group" id="http-trap-pattern-group">
            <label class="form-label" id="http-trap-pattern-label">特征规则表达式 (支持 | 分隔多个词或正则)</label>
            <input type="text" class="form-control" id="http-trap-pattern-val" placeholder="例如：\.env|\.git|config\.json">
        </div>
        <div class="form-group" id="http-trap-rate-group" style="display: none;">
            <div style="display: flex; gap: 12px;">
                <div style="flex: 1;">
                    <label class="form-label">时间窗口 (秒)</label>
                    <input type="number" class="form-control" id="http-trap-window-val" value="30" min="5" max="300">
                </div>
                <div style="flex: 1;">
                    <label class="form-label">熔断阈值 (次 404/403)</label>
                    <input type="number" class="form-control" id="http-trap-threshold-val" value="6" min="2" max="100">
                </div>
            </div>
        </div>
        <div class="form-group">
            <label class="form-label">威胁等级评定</label>
            <select class="form-control" id="http-trap-level-val">
                <option value="极高危" selected>极高危</option>
                <option value="高危">高危</option>
                <option value="中危">中危</option>
            </select>
        </div>
        <div class="form-group">
            <label class="form-label">策略描述与防护说明</label>
            <input type="text" class="form-control" id="http-trap-desc-val" placeholder="例如：探测系统关键配置文件与数据库备份">
        </div>
        <div style="display: flex; justify-content: flex-end; gap: 8px; margin-top: 18px;">
            <button class="pill-btn" onclick="closeModals()">取消</button>
            <button class="pill-btn accent" onclick="submitAddHttpTrap()">保存并生效</button>
        </div>
    </div>
</div>

<!-- Modal: 编辑请求特征策略 -->
<div class="modal-overlay" id="modal-http-trap-edit">
    <div class="modal-sheet" style="max-width: 540px;">
        <h3 style="font-size: 16px; font-weight: 700; margin-bottom: 14px;">✏️ 编辑请求特征与防扫描策略</h3>
        <input type="hidden" id="edit-http-trap-id">
        <div class="form-group">
            <label class="form-label">策略名称</label>
            <input type="text" class="form-control" id="edit-http-trap-name-val">
        </div>
        <div class="form-group">
            <label class="form-label">匹配类型</label>
            <select class="form-control" id="edit-http-trap-type-val" onchange="onHttpTrapTypeChange('edit')">
                <option value="path_keyword">URL 路径特征 (关键词 / 正则)</option>
                <option value="ua_keyword">扫描工具 User-Agent 指纹</option>
                <option value="status_rate">404 / 403 异常高频熔断</option>
            </select>
        </div>
        <div class="form-group" id="edit-http-trap-pattern-group">
            <label class="form-label" id="edit-http-trap-pattern-label">特征规则表达式 (支持 | 分隔多个词或正则)</label>
            <input type="text" class="form-control" id="edit-http-trap-pattern-val">
        </div>
        <div class="form-group" id="edit-http-trap-rate-group" style="display: none;">
            <div style="display: flex; gap: 12px;">
                <div style="flex: 1;">
                    <label class="form-label">时间窗口 (秒)</label>
                    <input type="number" class="form-control" id="edit-http-trap-window-val" min="5" max="300">
                </div>
                <div style="flex: 1;">
                    <label class="form-label">熔断阈值 (次 404/403)</label>
                    <input type="number" class="form-control" id="edit-http-trap-threshold-val" min="2" max="100">
                </div>
            </div>
        </div>
        <div class="form-group">
            <label class="form-label">威胁等级评定</label>
            <select class="form-control" id="edit-http-trap-level-val">
                <option value="极高危">极高危</option>
                <option value="高危">高危</option>
                <option value="中危">中危</option>
            </select>
        </div>
        <div class="form-group">
            <label class="form-label">策略描述与防护说明</label>
            <input type="text" class="form-control" id="edit-http-trap-desc-val">
        </div>
        <div style="display: flex; justify-content: flex-end; gap: 8px; margin-top: 18px;">
            <button class="pill-btn" onclick="closeModals()">取消</button>
            <button class="pill-btn accent" onclick="submitEditHttpTrap()">保存修改</button>
        </div>
    </div>
</div>

<!-- Modal: IP 属性与威胁情报详情 -->
<div class="modal-overlay" id="modal-ip-detail">
    <div class="modal-sheet" style="max-width: 520px;">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px;">
            <div style="display: flex; align-items: center; gap: 8px;">
                <span style="font-size: 20px;">🔍</span>
                <h3 style="font-size: 16px; font-weight: 700; margin: 0;">IP 属性与威胁情报详情</h3>
            </div>
            <button onclick="closeModals()" style="background:none; border:none; color:var(--text-sec); font-size:18px; cursor:pointer; padding: 4px 8px;">✕</button>
        </div>

        <div style="background: var(--card-sec); border-radius: 14px; padding: 16px; border: 1px solid var(--border); margin-bottom: 16px;">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 14px; border-bottom: 1px solid var(--border-subtle); padding-bottom: 12px;">
                <div>
                    <div style="font-size: 11px; color: var(--text-sec); font-weight: 600; text-transform: uppercase; margin-bottom: 2px;">目标 IP 地址</div>
                    <div style="font-family: monospace; font-size: 20px; font-weight: 800; color: var(--text);" id="ip-detail-ip">--</div>
                </div>
                <button class="pill-btn accent" onclick="copyIP(document.getElementById('ip-detail-ip').innerText)" style="padding: 5px 12px; font-size: 12px;">📋 复制 IP</button>
            </div>
            
            <div style="display: grid; grid-template-columns: repeat(2, 1fr); gap: 14px; font-size: 13px;">
                <div>
                    <span style="color: var(--text-sec); font-size: 12px;">归属国家/地区:</span>
                    <div style="font-weight: 700; color: var(--text); margin-top: 3px;" id="ip-detail-country">--</div>
                </div>
                <div>
                    <span style="color: var(--text-sec); font-size: 12px;">所在城市/省份:</span>
                    <div style="font-weight: 700; color: var(--text); margin-top: 3px;" id="ip-detail-region-city">--</div>
                </div>
                <div style="grid-column: span 2;">
                    <span style="color: var(--text-sec); font-size: 12px;">网络运营商 (ISP):</span>
                    <div style="font-weight: 600; color: var(--text); margin-top: 3px; word-break: break-all;" id="ip-detail-isp">--</div>
                </div>
                <div>
                    <span style="color: var(--text-sec); font-size: 12px;">威胁等级评定:</span>
                    <div style="margin-top: 4px;" id="ip-detail-level">--</div>
                </div>
                <div>
                    <span style="color: var(--text-sec); font-size: 12px;">当前防御处置:</span>
                    <div style="margin-top: 4px;" id="ip-detail-status">--</div>
                </div>
            </div>
        </div>

        <div style="display: flex; justify-content: flex-end; gap: 8px; flex-wrap: wrap;">
            <button class="pill-btn" onclick="closeModals()">关闭</button>
            <button class="pill-btn" onclick="addCurrentDetailIPToWhite()" id="btn-ip-detail-white">🛡️ 加入白名单</button>
            <button class="pill-btn danger" onclick="toggleCurrentDetailIPBan()" id="btn-ip-detail-ban">🚫 一键拉黑</button>
        </div>
    </div>
</div>

<!-- Modal: 通用智能导入 (蜜罐策略 / 黑名单 / 白名单) -->
<div class="modal-overlay" id="modal-import">
    <div class="modal-sheet" style="max-width: 580px;">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px;">
            <h3 style="font-size: 16px; font-weight: 700;" id="import-modal-title">📥 智能导入</h3>
            <button onclick="closeModals()" style="background:none; border:none; color:var(--text-sec); font-size:18px; cursor:pointer; padding: 4px 8px;">✕</button>
        </div>
        
        <div class="form-group" id="import-format-tip" style="background: var(--card-sec); border-radius: 10px; padding: 10px 12px; font-size: 12px; color: var(--text-sec); margin-bottom: 12px; border: 1px solid var(--border-subtle);">
            <div style="font-weight: 700; color: var(--text); margin-bottom: 4px;">📌 导入说明与格式规范：</div>
            <div id="import-tip-content" style="line-height: 1.5;"></div>
        </div>

        <div class="form-group">
            <label class="form-label" style="display: flex; justify-content: space-between;">
                <span>选择本地文件 (.json / .txt)</span>
                <span id="import-file-name" style="color: var(--accent); font-weight: 600;"></span>
            </label>
            <input type="file" id="import-file-input" accept=".json,.txt" class="form-control" onchange="handleImportFileSelect(event)" style="padding: 6px 10px;">
        </div>

        <div class="form-group">
            <label class="form-label" style="display: flex; justify-content: space-between;">
                <span>或直接在此粘贴内容 (JSON / 文本列表)</span>
                <a href="javascript:void(0)" onclick="insertImportTemplate()" id="btn-insert-sample" style="color: var(--accent); font-size: 12px; text-decoration: none; font-weight: 600;">填入格式示例</a>
            </label>
            <textarea class="form-control" id="import-text-val" rows="7" placeholder="在此粘贴 JSON 数组或文本数据..." style="font-family: monospace; font-size: 12px; line-height: 1.4;"></textarea>
        </div>

        <div class="form-group">
            <label class="form-label">导入模式</label>
            <div style="display: flex; gap: 16px; margin-top: 6px;">
                <label style="display: flex; align-items: center; gap: 6px; font-size: 13px; cursor: pointer; font-weight: 600;">
                    <input type="radio" name="import-mode" value="append" checked> 增量合并 (保留现有并更新)
                </label>
                <label style="display: flex; align-items: center; gap: 6px; font-size: 13px; cursor: pointer; font-weight: 600; color: var(--danger);">
                    <input type="radio" name="import-mode" value="replace"> 全量覆盖 (清空现有并重设)
                </label>
            </div>
        </div>

        <div style="display: flex; justify-content: flex-end; gap: 8px; margin-top: 18px;">
            <button class="pill-btn" onclick="closeModals()">取消</button>
            <button class="pill-btn accent" onclick="submitUniversalImport()" id="btn-submit-import">🚀 确认导入</button>
        </div>
    </div>
</div>

<script>
    const PAGE_SIZE = 50;
    let logsPage = 1;
    let blacklistPage = 1;
    let trapsPage = 1;
    let whitelistPage = 1;
    let accessLogPage = 1;

    function escapeHtml(s) {
        return String(s == null ? '' : s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
    }
    function jsEscape(s) {
        return String(s == null ? '' : s).replace(/\\/g, '\\\\').replace(/'/g, "\\'");
    }
    function csvEscape(s) {
        return String(s == null ? '' : s).replace(/"/g, '""');
    }
    const COUNTRY_CN_MAP = {
        "United States": "美国", "Canada": "加拿大", "Mexico": "墨西哥",
        "Brazil": "巴西", "Argentina": "阿根廷", "Chile": "智利", "Colombia": "哥伦比亚",
        "United Kingdom": "英国", "Germany": "德国", "France": "法国", "Italy": "意大利",
        "Spain": "西班牙", "Portugal": "葡萄牙", "Netherlands": "荷兰", "The Netherlands": "荷兰",
        "Belgium": "比利时", "Switzerland": "瑞士", "Austria": "奥地利", "Sweden": "瑞典",
        "Norway": "挪威", "Denmark": "丹麦", "Finland": "芬兰", "Poland": "波兰",
        "Czech Republic": "捷克", "Czechia": "捷克", "Hungary": "匈牙利", "Romania": "罗马尼亚",
        "Bulgaria": "保加利亚", "Greece": "希腊", "Croatia": "克罗地亚", "Serbia": "塞尔维亚",
        "Ukraine": "乌克兰", "Russia": "俄罗斯", "Belarus": "白俄罗斯", "Ireland": "爱尔兰",
        "China": "中国", "Japan": "日本", "South Korea": "韩国", "North Korea": "朝鲜",
        "Hong Kong": "中国香港", "Taiwan": "中国台湾", "Macau": "中国澳门",
        "India": "印度", "Pakistan": "巴基斯坦", "Singapore": "新加坡", "Malaysia": "马来西亚",
        "Indonesia": "印度尼西亚", "Philippines": "菲律宾", "Vietnam": "越南", "Thailand": "泰国",
        "Australia": "澳大利亚", "New Zealand": "新西兰", "South Africa": "南非", "Egypt": "埃及"
    };

    function formatGeoCN(item) {
        if (!item) return '未知节点';
        let country = item.country || '';
        if (country === '分析中...' || !country) return '分析中...';
        country = COUNTRY_CN_MAP[country] || country;
        let region = item.region || item.city || '';
        if (region && !country.includes(region)) {
            return `🌐 ${country} · ${region}`;
        }
        return `🌐 ${country}`;
    }

    let allEvents = [];
    let allPortLogs = [];
    let allWebLogs = [];
    let currentAccessLogMode = 'port';
    let allBlacklist = [];
    let allWhitelist = [];
    let allTraps = [];
    let currentTrapTab = 'port';
    let allHttpTraps = [];
    let httpTrapsPage = 1;
    let currentCategory = 'all';
    let trendChartInstance = null;
    let portChartInstance = null;

    const PAGE_TITLES = {
        'overview': '安全态势概览',
        'logs': '蜜罐拦截日志',
        'access-logs': '端口与控制台访问日志',
        'blacklist': '内核黑名单池',
        'traps': '蜜罐策略配置',
        'whitelist': '安全信任白名单'
    };

    const CATEGORY_LABELS = {
        'smb': '共享嗅探',
        'rdp': '远程桌面',
        'db': '数据库探针',
        'web': '管理控制台',
        'ftp': 'FTP 嗅探',
        'telnet': 'Telnet 弱口令',
        'custom': '自定义诱饵'
    };

    function showToast(msg, icon = '✓') {
        const container = document.getElementById('toast-container');
        const toast = document.createElement('div');
        toast.className = 'toast';
        toast.innerHTML = `<span>${icon}</span><span>${msg}</span>`;
        container.appendChild(toast);
        setTimeout(() => {
            toast.style.opacity = '0';
            toast.style.transform = 'translateY(-12px) scale(0.95)';
            toast.style.transition = 'all 0.2s ease';
            setTimeout(() => toast.remove(), 200);
        }, 2400);
    }

    function initCharts() {
        const isDark = document.documentElement.getAttribute('data-theme') !== 'light';
        const gridColor = isDark ? 'rgba(255,255,255,0.06)' : 'rgba(0,0,0,0.06)';
        const textColor = isDark ? '#98989d' : '#8e8e93';

        const ctxTrend = document.getElementById('trendChart').getContext('2d');
        trendChartInstance = new Chart(ctxTrend, {
            type: 'line',
            data: {
                labels: Array(24).fill(''),
                datasets: [{
                    label: '扫描探测频次',
                    data: Array(24).fill(0),
                    borderColor: '#007aff',
                    backgroundColor: 'rgba(0, 122, 255, 0.12)',
                    fill: true,
                    tension: 0.35,
                    borderWidth: 2.5,
                    pointRadius: 2.5,
                    pointBackgroundColor: '#007aff'
                }]
            },
            options: {
                responsive: true, maintainAspectRatio: false,
                plugins: { legend: { display: false } },
                scales: {
                    x: { grid: { color: gridColor }, ticks: { color: textColor, font: { size: 10 } } },
                    y: { beginAtZero: true, grid: { color: gridColor }, ticks: { color: textColor, font: { size: 10 } } }
                }
            }
        });

        const ctxPort = document.getElementById('portChart').getContext('2d');
        portChartInstance = new Chart(ctxPort, {
            type: 'doughnut',
            data: {
                labels: ['暂无数据'],
                datasets: [{
                    data: [1],
                    backgroundColor: ['#007aff', '#ff3b30', '#ff9500', '#34c759', '#af52de', '#5856d6'],
                    borderWidth: 0
                }]
            },
            options: {
                responsive: true, maintainAspectRatio: false,
                plugins: { legend: { position: 'right', labels: { color: textColor, font: { size: 11, weight: 600 } } } }
            }
        });
    }

    let currentTabKey = 'overview';
    function switchTab(tabKey, btn) {
        currentTabKey = tabKey;
        ['overview', 'logs', 'access-logs', 'blacklist', 'traps', 'whitelist'].forEach(t => {
            const el = document.getElementById(`tab-${t}`);
            if (el) el.style.display = (t === tabKey) ? 'block' : 'none';
        });
        document.querySelectorAll('.dock-btn').forEach(b => b.classList.remove('active'));
        const targetBtn = btn || document.getElementById(`dock-btn-${tabKey}`);
        if (targetBtn) targetBtn.classList.add('active');
        document.getElementById('page-main-title').innerText = PAGE_TITLES[tabKey] || '控制台';
        window.scrollTo({ top: 0, behavior: 'smooth' });
        fetchData(false);
    }

    function openSystemSettingsModal() {
        loadSystemSettings();
        const m = document.getElementById('modal-settings');
        if (m) {
            m.style.display = 'flex';
            m.classList.add('active');
        }
    }

    function jumpToLogsFilter(cat) {
        switchTab('logs');
        filterLogs(cat, document.getElementById(`seg-${cat}`) || document.getElementById('seg-all'));
    }

    let currentThemeMode = localStorage.getItem('portsentry_theme') || 'auto';
    let autoRefreshTimer = null;
    let isAutoRefreshEnabled = true;

    function applyTheme(mode, notify = false) {
        currentThemeMode = mode;
        localStorage.setItem('portsentry_theme', mode);
        const root = document.documentElement;
        let effectiveTheme = mode;
        if (mode === 'auto') {
            const systemDark = window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches;
            effectiveTheme = systemDark ? 'dark' : 'light';
        }
        root.setAttribute('data-theme', effectiveTheme);

        const iconEl = document.getElementById('theme-icon');
        const labelEl = document.getElementById('theme-label');
        if (iconEl && labelEl) {
            if (mode === 'auto') {
                iconEl.innerText = '🌓';
                labelEl.innerText = '自动';
            } else if (mode === 'dark') {
                iconEl.innerText = '🌙';
                labelEl.innerText = '暗黑';
            } else {
                iconEl.innerText = '☀️';
                labelEl.innerText = '明亮';
            }
        }

        if (trendChartInstance && portChartInstance) {
            trendChartInstance.destroy();
            portChartInstance.destroy();
            initCharts();
            fetchData(false);
        }
        if (notify) {
            const desc = mode === 'auto' ? '跟随系统 (自动)' : (mode === 'dark' ? '暗黑模式' : '明亮模式');
            showToast(`主题已设为: ${desc}`, mode === 'auto' ? '🌓' : (mode === 'dark' ? '🌙' : '☀️'));
        }
    }

    function cycleTheme() {
        if (currentThemeMode === 'auto') {
            applyTheme('dark', true);
        } else if (currentThemeMode === 'dark') {
            applyTheme('light', true);
        } else {
            applyTheme('auto', true);
        }
    }

    if (window.matchMedia) {
        window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', () => {
            if (currentThemeMode === 'auto') {
                applyTheme('auto', false);
            }
        });
    }

    function startAutoRefresh() {
        if (autoRefreshTimer) clearInterval(autoRefreshTimer);
        autoRefreshTimer = setInterval(() => {
            if (isAutoRefreshEnabled) {
                fetchData(false);
            }
        }, 5000);
    }

    function toggleAutoRefresh() {
        isAutoRefreshEnabled = !isAutoRefreshEnabled;
        const btn = document.getElementById('btn-auto-refresh');
        const icon = document.getElementById('refresh-icon');
        const label = document.getElementById('refresh-label');
        
        if (isAutoRefreshEnabled) {
            if (btn) btn.className = 'pill-btn accent';
            if (icon) icon.innerText = '⏱️';
            if (label) label.innerText = '5s 实时';
            showToast('已开启 5 秒自动实时刷新', '⚡');
            fetchData(false);
            startAutoRefresh();
        } else {
            if (btn) btn.className = 'pill-btn';
            if (icon) icon.innerText = '⏸️';
            if (label) label.innerText = '已暂停';
            showToast('已暂停自动刷新', '⏸️');
            if (autoRefreshTimer) {
                clearInterval(autoRefreshTimer);
                autoRefreshTimer = null;
            }
        }
    }

    function fetchData(showNotice = false) {
        fetch('/api/stats').then(res => res.json()).then(data => {
            document.getElementById('stat-total').innerText = data.total_banned;
            document.getElementById('stat-today').innerText = data.today_events;
            document.getElementById('stat-traps').innerText = data.active_traps;
            document.getElementById('stat-white').innerText = data.whitelist_count;

            if (data.hourly_trend && trendChartInstance) {
                trendChartInstance.data.labels = data.hourly_trend.labels;
                trendChartInstance.data.datasets[0].data = data.hourly_trend.data;
                trendChartInstance.update();
            }

            if (data.port_distribution && portChartInstance && data.port_distribution.length > 0) {
                portChartInstance.data.labels = data.port_distribution.map(p => `${p.port} (${p.name})`);
                portChartInstance.data.datasets[0].data = data.port_distribution.map(p => p.count);
                portChartInstance.update();
            }

            renderGeoRank(data.geo_rank || []);
            if (showNotice) showToast('态势数据已同步最新');
        });

        fetch('/api/events').then(res => res.json()).then(events => {
            allEvents = events;
            document.getElementById('cnt-log-all').innerText = events.length;
            renderLogsTable();
            renderRecentThreats(events.slice(0, 5));
        });

        fetch('/api/blacklist').then(res => res.json()).then(data => {
            allBlacklist = data;
            renderBlacklistTable();
        });

        fetch('/api/traps').then(res => res.json()).then(data => {
            allTraps = data;
            if (currentTrapTab === 'port') renderTrapsTable();
        });

        fetch('/api/http_traps').then(res => res.json()).then(data => {
            allHttpTraps = data;
            if (currentTrapTab === 'req') renderTrapsTable();
        });

        fetch('/api/whitelist').then(res => res.json()).then(data => {
            allWhitelist = data;
            renderWhitelistTable();
        });

        // 仅在当前处于审计日志选项卡时加载大体量审计日志，消除首屏与轮询网络阻塞
        if (currentTabKey === 'access-logs') {
            fetch(`/api/access_logs?type=${currentAccessLogMode}`).then(res => res.json()).then(data => {
                if (currentAccessLogMode === 'port') allPortLogs = data;
                else allWebLogs = data;
                renderAccessLogsTable();
            });
        }
    }

    function renderGeoRank(geoList) {
        const box = document.getElementById('geo-rank-box');
        if (!geoList || geoList.length === 0) {
            box.innerHTML = '<div style="color:var(--text-sec); padding:16px 0; font-size:13px;">暂无足够地域样本</div>';
            return;
        }
        const max = Math.max(...geoList.map(g => g.count), 1);
        let html = '';
        geoList.forEach(g => {
            const pct = ((g.count / max) * 100).toFixed(0);
            const countryCN = COUNTRY_CN_MAP[g.country] || g.country || '公网节点';
            html += `
            <div class="rank-item">
                <span style="width: 100px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; font-weight:600;">🌐 ${countryCN}</span>
                <div class="rank-bar-bg"><div class="rank-bar-fill" style="width: ${pct}%"></div></div>
                <span style="font-weight:700; width: 32px; text-align:right; font-variant-numeric:tabular-nums;">${g.count}</span>
            </div>
            `;
        });
        box.innerHTML = html;
    }

    let currentDetailIP = '';
    let currentDetailMeta = {};

    function showIPDetail(ip) {
        currentDetailIP = ip;
        let meta = null;
        if (allEvents) meta = allEvents.find(e => e.ip === ip);
        if (!meta && allPortLogs) meta = allPortLogs.find(l => l.ip === ip);
        if (!meta && allBlacklist) meta = allBlacklist.find(b => b.ip === ip);
        if (!meta && allWebLogs) meta = allWebLogs.find(w => w.ip === ip);
        
        currentDetailMeta = meta || { ip };
        
        document.getElementById('ip-detail-ip').innerText = ip;
        const countryCN = COUNTRY_CN_MAP[currentDetailMeta.country] || currentDetailMeta.country || '公网节点';
        document.getElementById('ip-detail-country').innerText = countryCN;
        document.getElementById('ip-detail-region-city').innerText = (currentDetailMeta.region || currentDetailMeta.city) ? `${currentDetailMeta.region || ''} ${currentDetailMeta.city || ''}`.trim() : '未知城市';
        document.getElementById('ip-detail-isp').innerText = currentDetailMeta.isp || '未知运营商 / 本地或专用网络';
        
        const level = currentDetailMeta.level || '高危';
        document.getElementById('ip-detail-level').innerHTML = `<span class="tag ${level === '极高危' ? 'danger' : (level === '高危' ? 'warning' : 'accent')}">${level}</span>`;
        
        const isBanned = allBlacklist && allBlacklist.some(b => b.ip === ip);
        const isWhite = allWhitelist && allWhitelist.some(w => w.ip === ip);
        
        let statusHtml = '<span class="tag warning">● 未封禁 (正常)</span>';
        if (isBanned) {
            statusHtml = '<span class="tag danger">🚫 内核黑名单 (已阻断)</span>';
        } else if (isWhite) {
            statusHtml = '<span class="tag success">🛡️ 信任白名单 (已放行)</span>';
        }
        document.getElementById('ip-detail-status').innerHTML = statusHtml;
        
        const banBtn = document.getElementById('btn-ip-detail-ban');
        if (banBtn) {
            if (isBanned) {
                banBtn.innerText = '🔓 从黑名单解封';
                banBtn.className = 'pill-btn success';
            } else {
                banBtn.innerText = '🚫 一键拉黑 IP';
                banBtn.className = 'pill-btn danger';
            }
        }
        
        document.getElementById('modal-ip-detail').style.display = 'flex';
    }

    function addCurrentDetailIPToWhite() {
        if (!currentDetailIP) return;
        fetch('/api/whitelist/add', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ip: currentDetailIP, remark: '详情卡片快速添加' })
        }).then(res => res.json()).then(res => {
            showToast(res.msg || `已将 ${currentDetailIP} 添加至白名单`, '🛡️');
            closeModals();
            fetchData(false);
        });
    }

    function toggleCurrentDetailIPBan() {
        if (!currentDetailIP) return;
        const isBanned = allBlacklist && allBlacklist.some(b => b.ip === currentDetailIP);
        if (isBanned) {
            unbanIP(currentDetailIP);
            closeModals();
        } else {
            fetch('/api/ban', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ ip: currentDetailIP, reason: '详情卡片快速拉黑' })
            }).then(res => res.json()).then(res => {
                showToast(res.msg || `已成功封禁 IP: ${currentDetailIP}`, '🚫');
                closeModals();
                fetchData(false);
            });
        }
    }

    function renderRecentThreats(threats) {
        const box = document.getElementById('recent-threats-box');
        if (!threats || threats.length === 0) {
            box.innerHTML = '<div style="color:var(--text-sec); padding:16px 0; font-size:13px;">暂无近期威胁快报</div>';
            return;
        }
        let html = '';
        threats.forEach(t => {
            const tagClass = (t.level === '极高危') ? 'danger' : (t.level === '高危' ? 'warning' : 'accent');
            const geoText = formatGeoCN(t);
            html += `
            <div style="display:flex; justify-content:space-between; align-items:center; padding:9px 0; border-bottom:1px solid var(--border-subtle);">
                <div>
                    <span class="ip-text" onclick="showIPDetail('${t.ip}')" title="点击查看 IP 详情">${t.ip}</span>
                    <span style="font-size:11px; color:var(--text-sec); margin-left:4px;">${geoText}</span>
                    <div style="font-size:11px; color:var(--text-sec); margin-top:2px;">探测端口: <b>TCP/${t.port}</b> · ${t.port_name || '未定义'}</div>
                </div>
                <div style="text-align:right;">
                    <span class="tag ${tagClass}">${t.level || '高危'}</span>
                    <div style="font-size:10px; color:var(--text-ter); margin-top:3px;">${t.attack_time.split(' ')[1] || t.attack_time}</div>
                </div>
            </div>
            `;
        });
        box.innerHTML = html;
    }

    function renderPaginationUI(totalCount, currentPage, pageSize, cntElId, infoElId, prevBtnId, nextBtnId, numsElId, changePageFnName) {
        const cntEl = document.getElementById(cntElId);
        if (cntEl) cntEl.innerText = totalCount;
        const totalPages = Math.max(1, Math.ceil(totalCount / pageSize));
        const infoEl = document.getElementById(infoElId);
        if (infoEl) infoEl.innerText = `${currentPage} / ${totalPages}`;
        const prevBtn = document.getElementById(prevBtnId);
        const nextBtn = document.getElementById(nextBtnId);
        if (prevBtn) prevBtn.disabled = (currentPage <= 1);
        if (nextBtn) nextBtn.disabled = (currentPage >= totalPages);
        const numsEl = document.getElementById(numsElId);
        if (numsEl) {
            let html = '';
            for (let p = Math.max(1, currentPage - 2); p <= Math.min(totalPages, currentPage + 2); p++) {
                const active = (p === currentPage);
                html += `<button class="pill-btn ${active ? 'accent' : ''}" onclick="${changePageFnName}(${p})" style="padding: 4px 10px; font-size: 11px; font-weight: 700; ${active ? 'background: var(--accent); color: #fff;' : ''}">${p}</button>`;
            }
            numsEl.innerHTML = html;
        }
    }

    function changeLogsPage(delta) {
        const query = (document.getElementById('search-input')?.value || '').toLowerCase();
        let filtered = allEvents;
        if (currentCategory === 'rdp') filtered = filtered.filter(e => [3389, 5900].includes(e.port));
        else if (currentCategory === 'db') filtered = filtered.filter(e => [1433, 6379, 27017, 9200].includes(e.port));
        else if (currentCategory === 'smb') filtered = filtered.filter(e => [445, 135, 139].includes(e.port));
        else if (currentCategory === 'web') filtered = filtered.filter(e => [8888, 8080, 8088].includes(e.port));
        if (query) filtered = filtered.filter(e => (e.ip && e.ip.toLowerCase().includes(query)) || (e.country && e.country.toLowerCase().includes(query)) || (e.port && String(e.port).includes(query)));
        
        const totalPages = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE));
        const target = logsPage + delta;
        if (target >= 1 && target <= totalPages) {
            logsPage = target;
            renderLogsTable();
        }
    }
    function setLogsPage(p) { logsPage = p; renderLogsTable(); }

    function renderLogsTable() {
        const tbody = document.getElementById('logs-tbody');
        const query = (document.getElementById('search-input')?.value || '').toLowerCase();

        let filtered = allEvents || [];
        if (currentCategory === 'rdp') {
            filtered = filtered.filter(e => [3389, 5900].includes(e.port));
        } else if (currentCategory === 'db') {
            filtered = filtered.filter(e => [1433, 6379, 27017, 9200].includes(e.port));
        } else if (currentCategory === 'smb') {
            filtered = filtered.filter(e => [445, 135, 139].includes(e.port));
        } else if (currentCategory === 'web') {
            filtered = filtered.filter(e => [8888, 8080, 8088].includes(e.port));
        }

        if (query) {
            filtered = filtered.filter(e =>
                (e.ip && e.ip.toLowerCase().includes(query)) ||
                (e.country && e.country.toLowerCase().includes(query)) ||
                (e.port && String(e.port).includes(query)) ||
                (e.port_name && e.port_name.toLowerCase().includes(query))
            );
        }

        const totalCount = filtered.length;
        const totalPages = Math.max(1, Math.ceil(totalCount / PAGE_SIZE));
        if (logsPage > totalPages) logsPage = totalPages;
        if (logsPage < 1) logsPage = 1;

        renderPaginationUI(totalCount, logsPage, PAGE_SIZE, 'logs-total-cnt', 'logs-page-info', 'btn-logs-prev', 'btn-logs-next', 'logs-page-nums', 'setLogsPage');

        if (totalCount === 0) {
            tbody.innerHTML = '<tr><td colspan="8" style="text-align: center; color: var(--text-sec); padding: 30px;">未发现匹配的拦截记录</td></tr>';
            return;
        }

        const startIdx = (logsPage - 1) * PAGE_SIZE;
        const endIdx = startIdx + PAGE_SIZE;
        const pageList = filtered.slice(startIdx, endIdx);

        let html = '';
        pageList.forEach(e => {
            const tagClass = (e.level === '极高危') ? 'danger' : (e.level === '高危' ? 'warning' : 'accent');
            const catName = CATEGORY_LABELS[e.category] || e.category || '服务探针';
            const geoText = formatGeoCN(e);
            const isWatch = (e.status === 'WATCH');
            const statusBadge = isWatch 
                ? '<span class="tag warning" style="font-size:11px; font-weight:700;">探测感知 (观察中)</span>' 
                : '<span class="tag danger" style="font-size:11px; font-weight:700;">已内核丢弃 (DROP)</span>';
            const actionBtn = isWatch
                ? `<button class="action-btn danger" onclick="quickBanIP('${jsEscape(e.ip)}', '手动封禁观察中IP')">立即封禁</button>`
                : `<button class="action-btn success" onclick="unbanIP('${jsEscape(e.ip)}')">一键解封</button>`;

            html += `
            <tr>
                <td style="font-size:12px; font-variant-numeric:tabular-nums; color:var(--text-sec);">${e.attack_time}</td>
                <td><span class="ip-text" onclick="showIPDetail('${jsEscape(e.ip)}')" title="点击查看 IP 详情">${escapeHtml(e.ip)}</span></td>
                <td><span style="font-size:12px; color:var(--text); font-weight:600;">${geoText}</span></td>
                <td><span class="tag neutral" style="font-size:12px; font-weight:700;">TCP / ${e.port}</span></td>
                <td><span style="color:var(--text); font-size:12px; font-weight:600; line-height:1.4; display:inline-block;">${escapeHtml(e.port_name || '自定义诱饵')}</span> <span class="tag accent" style="margin-left:4px; font-size:10px; padding:2px 6px;">${catName}</span></td>
                <td><span class="tag ${tagClass}" style="font-size:11px; font-weight:700;">${e.level || '高危'}</span></td>
                <td>${statusBadge}</td>
                <td>${actionBtn}</td>
            </tr>
            `;
        });
        tbody.innerHTML = html;
    }

    function changeBlacklistPage(delta) {
        const total = allBlacklist ? allBlacklist.length : 0;
        const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE));
        const target = blacklistPage + delta;
        if (target >= 1 && target <= totalPages) {
            blacklistPage = target;
            renderBlacklistTable();
        }
    }
    function setBlacklistPage(p) { blacklistPage = p; renderBlacklistTable(); }

    function renderBlacklistTable() {
        const tbody = document.getElementById('blacklist-tbody');
        const list = allBlacklist || [];
        const totalCount = list.length;
        const totalPages = Math.max(1, Math.ceil(totalCount / PAGE_SIZE));
        if (blacklistPage > totalPages) blacklistPage = totalPages;
        if (blacklistPage < 1) blacklistPage = 1;

        renderPaginationUI(totalCount, blacklistPage, PAGE_SIZE, 'blacklist-total-cnt', 'blacklist-page-info', 'btn-blacklist-prev', 'btn-blacklist-next', 'blacklist-page-nums', 'setBlacklistPage');

        if (totalCount === 0) {
            tbody.innerHTML = '<tr><td colspan="6" style="text-align: center; color: var(--text-sec); padding: 24px;">当前内核黑名单池为空</td></tr>';
            return;
        }

        const startIdx = (blacklistPage - 1) * PAGE_SIZE;
        const endIdx = startIdx + PAGE_SIZE;
        const pageList = list.slice(startIdx, endIdx);

        let html = '';
        pageList.forEach(b => {
            const geoText = formatGeoCN(b);
            html += `
            <tr>
                <td><span class="ip-text" onclick="showIPDetail('${jsEscape(b.ip)}')" title="点击查看 IP 详情">${escapeHtml(b.ip)}</span></td>
                <td><span style="color:var(--text); font-size:12px; font-weight:600; line-height:1.4; display:inline-block;">${escapeHtml(b.reason || '自动诱捕阻断')}</span></td>
                <td><span style="font-size:12px; color:var(--text); font-weight:600;">${geoText}</span></td>
                <td><span class="tag danger" style="font-size:11px; font-weight:700;">iptables + blackhole</span></td>
                <td style="font-size:12px; font-variant-numeric:tabular-nums; color:var(--text-sec);">${b.ban_time}</td>
                <td>
                    <button class="action-btn success" onclick="unbanIP('${jsEscape(b.ip)}')">解除封禁</button>
                </td>
            </tr>
            `;
        });
        tbody.innerHTML = html;
    }

    function toggleTrapActionMenu(e) {
        if (e) e.stopPropagation();
        closeBlacklistActionMenu();
        closeWhitelistActionMenu();
        const popover = document.getElementById('trap-action-popover');
        if (!popover) return;
        if (popover.style.display === 'block') {
            popover.style.display = 'none';
        } else {
            renderTrapPopoverContent();
            popover.style.display = 'block';
        }
    }

    function closeTrapActionMenu() {
        const popover = document.getElementById('trap-action-popover');
        if (popover) popover.style.display = 'none';
    }

    function toggleBlacklistActionMenu(e) {
        if (e) e.stopPropagation();
        closeTrapActionMenu();
        closeWhitelistActionMenu();
        const popover = document.getElementById('blacklist-action-popover');
        if (!popover) return;
        if (popover.style.display === 'block') {
            popover.style.display = 'none';
        } else {
            popover.style.display = 'block';
        }
    }

    function closeBlacklistActionMenu() {
        const popover = document.getElementById('blacklist-action-popover');
        if (popover) popover.style.display = 'none';
    }

    function toggleWhitelistActionMenu(e) {
        if (e) e.stopPropagation();
        closeTrapActionMenu();
        closeBlacklistActionMenu();
        const popover = document.getElementById('whitelist-action-popover');
        if (!popover) return;
        if (popover.style.display === 'block') {
            popover.style.display = 'none';
        } else {
            popover.style.display = 'block';
        }
    }

    function closeWhitelistActionMenu() {
        const popover = document.getElementById('whitelist-action-popover');
        if (popover) popover.style.display = 'none';
    }

    // 点击页面任意外部区域关闭弹出菜单
    document.addEventListener('click', function(e) {
        const trapPopover = document.getElementById('trap-action-popover');
        const trapBtn = document.getElementById('btn-trap-action-menu');
        if (trapPopover && trapPopover.style.display === 'block') {
            if (!trapPopover.contains(e.target) && (!trapBtn || !trapBtn.contains(e.target))) {
                trapPopover.style.display = 'none';
            }
        }

        const blPopover = document.getElementById('blacklist-action-popover');
        const blBtn = document.getElementById('btn-blacklist-action-menu');
        if (blPopover && blPopover.style.display === 'block') {
            if (!blPopover.contains(e.target) && (!blBtn || !blBtn.contains(e.target))) {
                blPopover.style.display = 'none';
            }
        }

        const wlPopover = document.getElementById('whitelist-action-popover');
        const wlBtn = document.getElementById('btn-whitelist-action-menu');
        if (wlPopover && wlPopover.style.display === 'block') {
            if (!wlPopover.contains(e.target) && (!wlBtn || !wlBtn.contains(e.target))) {
                wlPopover.style.display = 'none';
            }
        }
    });

    function renderTrapPopoverContent() {
        const container = document.getElementById('trap-popover-content');
        if (!container) return;
        if (currentTrapTab === 'port') {
            container.innerHTML = `
                <div style="font-size: 11px; color: var(--text-sec); font-weight: 700; padding: 4px 8px 6px; text-transform: uppercase; letter-spacing: 0.5px;">🔌 端口策略配置</div>
                <a href="javascript:void(0)" onclick="closeTrapActionMenu(); openAddTrapModal();" style="display: flex; align-items: center; gap: 8px; padding: 8px 10px; color: var(--text); text-decoration: none; border-radius: 8px; font-size: 12px; font-weight: 600;" onmouseover="this.style.background='var(--card-sec)'" onmouseout="this.style.background='transparent'">
                    <span>➕</span><span>添加端口诱饵</span>
                </a>
                <div style="height: 1px; background: var(--border-subtle); margin: 4px 0;"></div>
                <a href="javascript:void(0)" onclick="closeTrapActionMenu(); openImportModal('traps');" style="display: flex; align-items: center; gap: 8px; padding: 8px 10px; color: var(--text); text-decoration: none; border-radius: 8px; font-size: 12px; font-weight: 600;" onmouseover="this.style.background='var(--card-sec)'" onmouseout="this.style.background='transparent'">
                    <span>📥</span><span>导入策略 (JSON)</span>
                </a>
                <a href="javascript:void(0)" onclick="closeTrapActionMenu(); exportTrapsJSON();" style="display: flex; align-items: center; gap: 8px; padding: 8px 10px; color: var(--text); text-decoration: none; border-radius: 8px; font-size: 12px; font-weight: 600;" onmouseover="this.style.background='var(--card-sec)'" onmouseout="this.style.background='transparent'">
                    <span>📤</span><span>导出策略 (JSON)</span>
                </a>
            `;
        } else {
            container.innerHTML = `
                <div style="font-size: 11px; color: var(--text-sec); font-weight: 700; padding: 4px 8px 6px; text-transform: uppercase; letter-spacing: 0.5px;">🎯 请求特征配置</div>
                <a href="javascript:void(0)" onclick="closeTrapActionMenu(); openAddHttpTrapModal();" style="display: flex; align-items: center; gap: 8px; padding: 8px 10px; color: var(--text); text-decoration: none; border-radius: 8px; font-size: 12px; font-weight: 600;" onmouseover="this.style.background='var(--card-sec)'" onmouseout="this.style.background='transparent'">
                    <span>➕</span><span>添加特征策略</span>
                </a>
                <div style="height: 1px; background: var(--border-subtle); margin: 4px 0;"></div>
                <a href="javascript:void(0)" onclick="closeTrapActionMenu(); openImportModal('http_traps');" style="display: flex; align-items: center; gap: 8px; padding: 8px 10px; color: var(--text); text-decoration: none; border-radius: 8px; font-size: 12px; font-weight: 600;" onmouseover="this.style.background='var(--card-sec)'" onmouseout="this.style.background='transparent'">
                    <span>📥</span><span>导入特征策略 (JSON)</span>
                </a>
                <a href="javascript:void(0)" onclick="closeTrapActionMenu(); exportHttpTrapsJSON();" style="display: flex; align-items: center; gap: 8px; padding: 8px 10px; color: var(--text); text-decoration: none; border-radius: 8px; font-size: 12px; font-weight: 600;" onmouseover="this.style.background='var(--card-sec)'" onmouseout="this.style.background='transparent'">
                    <span>📤</span><span>导出特征策略 (JSON)</span>
                </a>
            `;
        }
    }

    function exportHttpTrapsJSON() {
        if (!allHttpTraps || allHttpTraps.length === 0) return showToast('暂无请求特征策略可导出', '⚠️');
        const exportList = allHttpTraps.map(r => ({
            name: r.name,
            match_type: r.match_type,
            pattern: r.pattern || '',
            threshold: r.threshold || 6,
            window: r.window || 30,
            level: r.level || '极高危',
            enabled: r.enabled !== false,
            description: r.description || ''
        }));
        const blob = new Blob([JSON.stringify(exportList, null, 2)], { type: 'application/json' });
        const link = document.createElement('a');
        link.href = URL.createObjectURL(blob);
        link.download = `portsentry_http_traps_${new Date().toISOString().slice(0, 10)}.json`;
        link.click();
        showToast('已开始导出请求特征策略 (JSON)', '📤');
    }

    function switchTrapTab(tab) {
        currentTrapTab = tab;
        const btnPort = document.getElementById('btn-trap-tab-port');
        const btnReq = document.getElementById('btn-trap-tab-req');
        const titleEl = document.getElementById('traps-main-title');
        const subEl = document.getElementById('traps-main-sub');
        const theadEl = document.getElementById('traps-thead');
        closeTrapActionMenu();

        if (tab === 'port') {
            if (btnPort) { btnPort.className = 'pill-btn accent'; btnPort.style.background = ''; }
            if (btnReq) { btnReq.className = 'pill-btn'; btnReq.style.background = 'transparent'; }
            if (titleEl) titleEl.innerText = '🍯 活跃蜜罐策略与诱饵端口';
            if (subEl) subEl.innerText = '模拟高危服务静默监听，一旦连入即自动封禁';
            if (theadEl) {
                theadEl.innerHTML = `
                    <tr>
                        <th>诱饵端口</th>
                        <th>模拟服务描述</th>
                        <th>分类</th>
                        <th>威胁等级</th>
                        <th>当前状态</th>
                        <th>开关操作</th>
                    </tr>
                `;
            }
        } else {
            if (btnReq) { btnReq.className = 'pill-btn accent'; btnReq.style.background = ''; }
            if (btnPort) { btnPort.className = 'pill-btn'; btnPort.style.background = 'transparent'; }
            if (titleEl) titleEl.innerText = '🎯 Web 请求特征与防扫描策略';
            if (subEl) subEl.innerText = '实时检测恶意 URL 路径嗅探、后台爆破、扫描工具指纹与高频 404 熔断';
            if (theadEl) {
                theadEl.innerHTML = `
                    <tr>
                        <th style="width: 180px;">特征策略名称</th>
                        <th style="width: 140px;">匹配类型</th>
                        <th>特征规则内容 / 阈值配置</th>
                        <th style="width: 100px;">威胁等级</th>
                        <th style="width: 110px;">当前状态</th>
                        <th style="width: 160px;">管理操作</th>
                    </tr>
                `;
            }
            if (!allHttpTraps || allHttpTraps.length === 0) {
                fetch('/api/http_traps').then(res => res.json()).then(data => {
                    allHttpTraps = data;
                    renderTrapsTable();
                });
            }
        }
        renderTrapsTable();
    }

    function changeTrapsPage(delta) {
        if (currentTrapTab === 'port') {
            const total = allTraps ? allTraps.length : 0;
            const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE));
            const target = trapsPage + delta;
            if (target >= 1 && target <= totalPages) {
                trapsPage = target;
                renderTrapsTable();
            }
        } else {
            const total = allHttpTraps ? allHttpTraps.length : 0;
            const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE));
            const target = httpTrapsPage + delta;
            if (target >= 1 && target <= totalPages) {
                httpTrapsPage = target;
                renderTrapsTable();
            }
        }
    }
    function setTrapsPage(p) {
        if (currentTrapTab === 'port') trapsPage = p;
        else httpTrapsPage = p;
        renderTrapsTable();
    }

    function renderTrapsTable() {
        const tbody = document.getElementById('traps-tbody');
        if (currentTrapTab === 'port') {
            const list = allTraps || [];
            const totalCount = list.length;
            const totalPages = Math.max(1, Math.ceil(totalCount / PAGE_SIZE));
            if (trapsPage > totalPages) trapsPage = totalPages;
            if (trapsPage < 1) trapsPage = 1;

            renderPaginationUI(totalCount, trapsPage, PAGE_SIZE, 'traps-total-cnt', 'traps-page-info', 'btn-traps-prev', 'btn-traps-next', 'traps-page-nums', 'setTrapsPage');

            if (totalCount === 0) {
                tbody.innerHTML = '<tr><td colspan="6" style="text-align:center; padding:24px;">暂无诱捕端口策略</td></tr>';
                return;
            }

            const startIdx = (trapsPage - 1) * PAGE_SIZE;
            const endIdx = startIdx + PAGE_SIZE;
            const pageList = list.slice(startIdx, endIdx);

            let html = '';
            pageList.forEach(t => {
                const isEnabled = (t.enabled === true || t.strategy === 'accept' || t.strategy === 'enabled' || t.strategy === '启用');
                const isBiz = (t.is_business === true || t.trap_business === true);
                const statusTag = isEnabled ? '<span class="tag success">● 诱捕就绪</span>' : '<span class="tag neutral">已停用</span>';
                const bizTag = isBiz ? '<span class="tag warning" style="margin-left:4px; font-size:10px;" title="同步诱捕该端口的正常业务">🌐 业务诱捕</span>' : '';
                const btnText = isEnabled ? '停用' : '启用';
                const btnClass = isEnabled ? 'danger' : 'success';
                const cat = t.category || 'custom';
                const catName = CATEGORY_LABELS[cat] || cat || '服务探针';
                const desc = t.description || t.name || (t.protocol ? `${t.protocol.toUpperCase()}/${t.port}` : `TCP/${t.port}`);
                const proto = (t.protocol || 'tcp').toUpperCase();
                const level = t.level || '高危';
                const portDisplay = String(t.port || (t.port_start === t.port_end ? t.port_start : `${t.port_start}-${t.port_end}`));
                const safePortParam = portDisplay.replace(/'/g, "\\'");
                html += `
                <tr>
                    <td><span class="tag neutral" style="font-size:12px; font-weight:700;">${proto} / ${portDisplay}</span></td>
                    <td><span style="color:var(--text); font-size:12px; font-weight:600; line-height:1.4; display:inline-block;">${escapeHtml(desc)}</span>${bizTag}</td>
                    <td><span class="tag accent">${catName}</span></td>
                    <td><span class="tag ${level === '极高危' ? 'danger' : 'warning'}">${level}</span></td>
                    <td>${statusTag}</td>
                    <td>
                        <div style="display: flex; gap: 6px; align-items: center;">
                            <button class="action-btn" onclick="openEditTrapModal('${safePortParam}')" style="background: var(--card-sec); color: var(--text); border: 1px solid var(--border);">✏️ 编辑</button>
                            <button class="action-btn ${btnClass}" onclick="toggleTrap('${safePortParam}', ${!isEnabled})">${btnText}</button>
                            <button class="action-btn danger" onclick="deleteTrap('${safePortParam}')" title="删除此策略">🗑️</button>
                        </div>
                    </td>
                </tr>
                `;
            });
            tbody.innerHTML = html;
        } else {
            // 请求特征模式
            const list = allHttpTraps || [];
            const totalCount = list.length;
            const totalPages = Math.max(1, Math.ceil(totalCount / PAGE_SIZE));
            if (httpTrapsPage > totalPages) httpTrapsPage = totalPages;
            if (httpTrapsPage < 1) httpTrapsPage = 1;

            renderPaginationUI(totalCount, httpTrapsPage, PAGE_SIZE, 'traps-total-cnt', 'traps-page-info', 'btn-traps-prev', 'btn-traps-next', 'traps-page-nums', 'setTrapsPage');

            if (totalCount === 0) {
                tbody.innerHTML = '<tr><td colspan="6" style="text-align:center; padding:24px;">暂无请求特征策略</td></tr>';
                return;
            }

            const startIdx = (httpTrapsPage - 1) * PAGE_SIZE;
            const endIdx = startIdx + PAGE_SIZE;
            const pageList = list.slice(startIdx, endIdx);

            const MATCH_LABELS = {
                'path_keyword': 'URL 敏感路径',
                'ua_keyword': '扫描工具指纹',
                'status_rate': '高频404熔断'
            };

            let html = '';
            pageList.forEach(rule => {
                const isEnabled = !!rule.enabled;
                const statusTag = isEnabled ? '<span class="tag success">● 防护生效中</span>' : '<span class="tag neutral">已停用</span>';
                const btnText = isEnabled ? '停用' : '启用';
                const btnClass = isEnabled ? 'danger' : 'success';
                const mtype = rule.match_type || 'path_keyword';
                const mtypeName = MATCH_LABELS[mtype] || mtype;
                const level = rule.level || '极高危';
                
                let ruleContentHtml = '';
                if (mtype === 'status_rate') {
                    ruleContentHtml = `<span style="font-size:12px; font-weight:600; color:var(--accent);">⚡ ${rule.window || 30} 秒内累计 404/403 ≥ ${rule.threshold || 6} 次即熔断封禁</span>`;
                } else {
                    const pat = rule.pattern || '';
                    ruleContentHtml = `<code style="background:var(--card-sec); padding:3px 8px; border-radius:6px; font-size:12px; color:var(--text); max-width:340px; display:inline-block; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; vertical-align:middle;" title="${escapeHtml(pat)}">${escapeHtml(pat)}</code>`;
                }
                
                if (rule.description) {
                    ruleContentHtml += `<div style="font-size:11px; color:var(--text-sec); margin-top:3px;">${escapeHtml(rule.description)}</div>`;
                }

                html += `
                <tr>
                    <td><span style="font-weight:700; font-size:13px; color:var(--text);">${escapeHtml(rule.name)}</span></td>
                    <td><span class="tag accent" style="font-weight:700;">${mtypeName}</span></td>
                    <td>${ruleContentHtml}</td>
                    <td><span class="tag ${level === '极高危' ? 'danger' : 'warning'}">${level}</span></td>
                    <td>${statusTag}</td>
                    <td>
                        <div style="display: flex; gap: 6px; align-items: center;">
                            <button class="action-btn" onclick="openEditHttpTrapModal('${rule.id || rule.rule_id}')" style="background: var(--card-sec); color: var(--text); border: 1px solid var(--border);">✏️ 编辑</button>
                            <button class="action-btn ${btnClass}" onclick="toggleHttpTrap('${rule.id || rule.rule_id}', ${!isEnabled})">${btnText}</button>
                            <button class="action-btn danger" onclick="deleteHttpTrap('${rule.id || rule.rule_id}')" title="删除此规则">🗑️</button>
                        </div>
                    </td>
                </tr>
                `;
            });
            tbody.innerHTML = html;
        }
    }

    function onHttpTrapTypeChange(prefix) {
        const typeEl = document.getElementById(`${prefix === 'edit' ? 'edit-' : ''}http-trap-type-val`);
        const patGroup = document.getElementById(`${prefix === 'edit' ? 'edit-' : ''}http-trap-pattern-group`);
        const rateGroup = document.getElementById(`${prefix === 'edit' ? 'edit-' : ''}http-trap-rate-group`);
        const labelEl = document.getElementById(`${prefix === 'edit' ? 'edit-' : ''}http-trap-pattern-label`);
        
        if (!typeEl) return;
        const val = typeEl.value;
        if (val === 'status_rate') {
            if (patGroup) patGroup.style.display = 'none';
            if (rateGroup) rateGroup.style.display = 'block';
        } else {
            if (patGroup) patGroup.style.display = 'block';
            if (rateGroup) rateGroup.style.display = 'none';
            if (labelEl) {
                labelEl.innerText = (val === 'ua_keyword') ? 'User-Agent 扫描工具指纹 (正则/关键词)' : 'URL 敏感路径特征表达式 (支持 | 分隔)';
            }
        }
    }

    function openAddHttpTrapModal() {
        document.getElementById('http-trap-name-val').value = '';
        document.getElementById('http-trap-type-val').value = 'path_keyword';
        document.getElementById('http-trap-pattern-val').value = '';
        document.getElementById('http-trap-window-val').value = 30;
        document.getElementById('http-trap-threshold-val').value = 6;
        document.getElementById('http-trap-level-val').value = '极高危';
        document.getElementById('http-trap-desc-val').value = '';
        onHttpTrapTypeChange('add');
        document.getElementById('modal-http-trap').style.display = 'flex';
    }

    function submitAddHttpTrap() {
        const name = document.getElementById('http-trap-name-val').value.trim();
        const match_type = document.getElementById('http-trap-type-val').value;
        const pattern = document.getElementById('http-trap-pattern-val').value.trim();
        const window = parseInt(document.getElementById('http-trap-window-val').value) || 30;
        const threshold = parseInt(document.getElementById('http-trap-threshold-val').value) || 6;
        const level = document.getElementById('http-trap-level-val').value;
        const description = document.getElementById('http-trap-desc-val').value.trim();

        if (!name) return showToast('请输入策略名称', '⚠️');
        if (match_type !== 'status_rate' && !pattern) return showToast('请输入特征表达式或关键词', '⚠️');

        fetch('/api/http_traps/add', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ name, match_type, pattern, window, threshold, level, description })
        }).then(res => res.json()).then(res => {
            if (res.success) {
                showToast(res.msg || '添加成功', '🎯');
                closeModals();
                fetchData(false);
            } else {
                showToast(res.msg || '添加失败', '❌');
            }
        });
    }

    function openEditHttpTrapModal(ruleId) {
        const rule = (allHttpTraps || []).find(r => String(r.id) === String(ruleId) || String(r.rule_id) === String(ruleId));
        if (!rule) return showToast('未找到该策略数据', '⚠️');

        document.getElementById('edit-http-trap-id').value = rule.id || rule.rule_id;
        document.getElementById('edit-http-trap-name-val').value = rule.name || '';
        document.getElementById('edit-http-trap-type-val').value = rule.match_type || 'path_keyword';
        document.getElementById('edit-http-trap-pattern-val').value = rule.pattern || '';
        document.getElementById('edit-http-trap-window-val').value = rule.window || 30;
        document.getElementById('edit-http-trap-threshold-val').value = rule.threshold || 6;
        document.getElementById('edit-http-trap-level-val').value = rule.level || '极高危';
        document.getElementById('edit-http-trap-desc-val').value = rule.description || '';
        
        onHttpTrapTypeChange('edit');
        document.getElementById('modal-http-trap-edit').style.display = 'flex';
    }

    function submitEditHttpTrap() {
        const id = document.getElementById('edit-http-trap-id').value;
        const name = document.getElementById('edit-http-trap-name-val').value.trim();
        const match_type = document.getElementById('edit-http-trap-type-val').value;
        const pattern = document.getElementById('edit-http-trap-pattern-val').value.trim();
        const window = parseInt(document.getElementById('edit-http-trap-window-val').value) || 30;
        const threshold = parseInt(document.getElementById('edit-http-trap-threshold-val').value) || 6;
        const level = document.getElementById('edit-http-trap-level-val').value;
        const description = document.getElementById('edit-http-trap-desc-val').value.trim();

        if (!name) return showToast('请输入策略名称', '⚠️');
        if (match_type !== 'status_rate' && !pattern) return showToast('请输入特征表达式或关键词', '⚠️');

        fetch('/api/http_traps/edit', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ id, name, match_type, pattern, window, threshold, level, description })
        }).then(res => res.json()).then(res => {
            if (res.success) {
                showToast(res.msg || '修改成功', '✓');
                closeModals();
                fetchData(false);
            } else {
                showToast(res.msg || '修改失败', '❌');
            }
        });
    }

    function toggleHttpTrap(ruleId, enabled) {
        fetch('/api/http_traps/toggle', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ id: ruleId, enabled })
        }).then(res => res.json()).then(res => {
            showToast(res.msg || '状态已更新', '⚙️');
            fetchData(false);
        });
    }

    function deleteHttpTrap(ruleId) {
        if (!confirm('确定要删除此请求特征与防扫描策略吗？')) return;
        fetch('/api/http_traps/delete', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ id: ruleId })
        }).then(res => res.json()).then(res => {
            if (res.success) {
                showToast(res.msg || '已删除策略', '🗑️');
                fetchData(false);
            } else {
                showToast(res.msg || '删除失败', '❌');
            }
        });
    }

    function changeWhitelistPage(delta) {
        const total = allWhitelist ? allWhitelist.length : 0;
        const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE));
        const target = whitelistPage + delta;
        if (target >= 1 && target <= totalPages) {
            whitelistPage = target;
            renderWhitelistTable();
        }
    }
    function setWhitelistPage(p) { whitelistPage = p; renderWhitelistTable(); }

    function renderWhitelistTable() {
        const tbody = document.getElementById('whitelist-tbody');
        const list = allWhitelist || [];
        const totalCount = list.length;
        const totalPages = Math.max(1, Math.ceil(totalCount / PAGE_SIZE));
        if (whitelistPage > totalPages) whitelistPage = totalPages;
        if (whitelistPage < 1) whitelistPage = 1;

        renderPaginationUI(totalCount, whitelistPage, PAGE_SIZE, 'whitelist-total-cnt', 'whitelist-page-info', 'btn-whitelist-prev', 'btn-whitelist-next', 'whitelist-page-nums', 'setWhitelistPage');

        if (totalCount === 0) {
            tbody.innerHTML = '<tr><td colspan="4" style="text-align: center; color: var(--text-sec); padding: 24px;">当前无白名单记录</td></tr>';
            return;
        }

        const startIdx = (whitelistPage - 1) * PAGE_SIZE;
        const endIdx = startIdx + PAGE_SIZE;
        const pageList = list.slice(startIdx, endIdx);

        let html = '';
        pageList.forEach(w => {
            const ipStr = (typeof w === 'object' && w !== null) ? (w.ip || '') : String(w);
            const remark = (typeof w === 'object' && w !== null) ? (w.remark || '信任IP') : '信任IP';
            const safeIpParam = ipStr.replace(/'/g, "\\'");
            html += `
            <tr>
                <td><span class="ip-text" onclick="showIPDetail('${safeIpParam}')" title="点击查看 IP 详情">${escapeHtml(ipStr)}</span></td>
                <td><span style="color:var(--text); font-size:12px; font-weight:600; line-height:1.4; display:inline-block;">${escapeHtml(remark)}</span></td>
                <td><span class="tag success" style="font-size:11px; font-weight:700;">● 白名单放行</span></td>
                <td>
                    <button class="action-btn danger" onclick="removeWhitelist('${safeIpParam}')">删除</button>
                </td>
            </tr>
            `;
        });
        tbody.innerHTML = html;
    }

    function changeAccessLogPage(delta) {
        const activeLogs = (currentAccessLogMode === 'port') ? allPortLogs : allWebLogs;
        const totalLogs = activeLogs ? activeLogs.length : 0;
        const totalPages = Math.max(1, Math.ceil(totalLogs / PAGE_SIZE));
        const target = accessLogPage + delta;
        if (target >= 1 && target <= totalPages) {
            accessLogPage = target;
            renderAccessLogsTable();
        }
    }

    function setAccessLogPage(p) {
        accessLogPage = p;
        renderAccessLogsTable();
    }

    function switchAccessLogMode(mode) {
        currentAccessLogMode = mode;
        accessLogPage = 1;
        
        const btnPort = document.getElementById('btn-access-mode-port');
        const btnWeb = document.getElementById('btn-access-mode-web');
        const titleEl = document.getElementById('access-logs-title');
        const subEl = document.getElementById('access-logs-sub');
        const theadEl = document.getElementById('access-logs-thead');
        const actionSegments = document.getElementById('access-action-segments');
        
        if (mode === 'port') {
            if (btnPort) { btnPort.className = 'pill-btn accent'; btnPort.style.background = ''; }
            if (btnWeb) { btnWeb.className = 'pill-btn'; btnWeb.style.background = 'transparent'; }
            if (titleEl) titleEl.innerText = '🍯 端口访问日志';
            if (subEl) subEl.innerText = '实时记录所有外部客户端对本机各诱捕端口与网络端口的连接嗅探';
            if (actionSegments) actionSegments.style.display = 'flex';
            if (theadEl) {
                theadEl.innerHTML = `
                    <tr>
                        <th style="width: 150px;">访问时间</th>
                        <th style="width: 150px;">来源 IP</th>
                        <th style="width: 150px;">归属地域</th>
                        <th style="width: 120px;">目标端口</th>
                        <th>服务说明</th>
                        <th style="width: 110px;">防御处置</th>
                    </tr>
                `;
            }
        } else {
            if (btnWeb) { btnWeb.className = 'pill-btn accent'; btnWeb.style.background = ''; }
            if (btnPort) { btnPort.className = 'pill-btn'; btnPort.style.background = 'transparent'; }
            if (titleEl) titleEl.innerText = '🌍 443访问日志';
            if (subEl) subEl.innerText = '实时采集并聚合 OpenResty / Nginx 业务站点的客户端域名、访问路径、状态码与设备信息';
            if (actionSegments) actionSegments.style.display = 'none';
            if (theadEl) {
                theadEl.innerHTML = `
                    <tr>
                        <th style="width: 150px;">访问时间</th>
                        <th style="width: 150px;">客户端 IP</th>
                        <th style="width: 150px;">归属地域</th>
                        <th style="width: 180px;">访问域名 (Host)</th>
                        <th>请求方法 & 访问路径 (URI)</th>
                        <th style="width: 100px;">状态码</th>
                        <th style="width: 200px;">客户端设备 (User-Agent)</th>
                    </tr>
                `;
            }
        }
        
        // 立即拉取对应模式数据
        fetch(`/api/access_logs?type=${currentAccessLogMode}`).then(res => res.json()).then(data => {
            if (currentAccessLogMode === 'port') allPortLogs = data;
            else allWebLogs = data;
            renderAccessLogsTable();
        });
    }

    let currentAccessActionFilter = 'all';

    function filterAccessLogs(act, btn) {
        currentAccessActionFilter = act;
        const container = document.getElementById('access-action-segments');
        if (container) {
            container.querySelectorAll('.segment-btn').forEach(b => b.classList.remove('active'));
        }
        if (btn) btn.classList.add('active');
        accessLogPage = 1;
        renderAccessLogsTable();
    }

    function renderAccessLogsTable() {
        const tbody = document.getElementById('access-logs-tbody');
        const activeLogs = (currentAccessLogMode === 'port') ? allPortLogs : allWebLogs;
        let list = activeLogs || [];
        
        // 动作过滤（仅针对端口模式）
        if (currentAccessLogMode === 'port' && currentAccessActionFilter !== 'all') {
            list = list.filter(l => (l.action || '') === currentAccessActionFilter);
        }
        
        // 搜索关键词过滤
        const searchInput = document.getElementById('access-search-input');
        const query = (searchInput ? searchInput.value : '').trim().toLowerCase();
        if (query) {
            list = list.filter(l => {
                const ip = (l.ip || '').toLowerCase();
                const port = String(l.port || '');
                const portName = (l.port_name || '').toLowerCase();
                const domain = (l.domain || '').toLowerCase();
                const path = (l.path || '').toLowerCase();
                const country = (l.country || '').toLowerCase();
                const region = (l.region || '').toLowerCase();
                const city = (l.city || '').toLowerCase();
                const isp = (l.isp || '').toLowerCase();
                const ua = (l.user_agent || '').toLowerCase();
                return ip.includes(query) || port.includes(query) || portName.includes(query) || domain.includes(query) || path.includes(query) || country.includes(query) || region.includes(query) || city.includes(query) || isp.includes(query) || ua.includes(query);
            });
        }

        const totalCount = list.length;
        const totalPages = Math.max(1, Math.ceil(totalCount / PAGE_SIZE));
        if (accessLogPage > totalPages) accessLogPage = totalPages;
        if (accessLogPage < 1) accessLogPage = 1;

        renderPaginationUI(totalCount, accessLogPage, PAGE_SIZE, 'access-log-total-cnt', 'access-log-page-info', 'btn-access-prev', 'btn-access-next', 'access-log-page-nums', 'setAccessLogPage');

        if (totalCount === 0) {
            const emptyColspan = (currentAccessLogMode === 'port') ? 6 : 7;
            tbody.innerHTML = `<tr><td colspan="${emptyColspan}" style="text-align:center; padding:24px; color:var(--text-sec);">未检索到匹配的${currentAccessLogMode === 'port' ? '端口访问' : '443访问'}记录</td></tr>`;
            return;
        }

        const startIdx = (accessLogPage - 1) * PAGE_SIZE;
        const endIdx = startIdx + PAGE_SIZE;
        const pageLogs = list.slice(startIdx, endIdx);

        let html = '';
        if (currentAccessLogMode === 'port') {
            pageLogs.forEach(l => {
                const geoText = formatGeoCN(l);
                let actionTag = '<span class="tag danger" style="font-weight:700; font-size:11px;">🚫 诱捕阻断</span>';
                if (l.action === 'WHITELIST' || l.action === '放行') {
                    actionTag = '<span class="tag success" style="font-weight:700; font-size:11px;">🛡️ 信任放行</span>';
                } else if (l.action === 'BUSINESS' || l.action === '业务') {
                    actionTag = '<span class="tag accent" style="font-weight:700; font-size:11px;">⚡ 正常业务</span>';
                } else if (l.action === 'PROBE' || l.action === '探测') {
                    actionTag = '<span class="tag warning" style="font-weight:700; font-size:11px;">🔍 外部探测</span>';
                }
                html += `
                <tr>
                    <td style="font-size:12px; font-variant-numeric:tabular-nums; color:var(--text-sec);">${l.access_time}</td>
                    <td><span class="ip-text" onclick="showIPDetail('${jsEscape(l.ip)}')" title="点击查看 IP 详情">${escapeHtml(l.ip)}</span></td>
                    <td><span style="font-size:12px; color:var(--text); font-weight:600;">${geoText}</span></td>
                    <td><span class="tag neutral" style="font-size:12px; font-weight:700;">${l.proto || 'TCP'} / ${l.port}</span></td>
                    <td><span style="color:var(--text); font-size:12px; font-weight:600; line-height:1.4; display:inline-block;">${escapeHtml(l.port_name || '网络连接')}</span></td>
                    <td>${actionTag}</td>
                </tr>
                `;
            });
        } else {
            pageLogs.forEach(l => {
                const methodTag = (l.method === 'POST') 
                    ? '<span class="tag warning" style="font-weight:700; font-size:10px; padding:2px 5px; flex-shrink:0;">POST</span>' 
                    : '<span class="tag success" style="font-weight:700; font-size:10px; padding:2px 5px; flex-shrink:0;">GET</span>';
                
                let statusTag = '<span class="tag success" style="font-weight:700; font-size:11px;">200 OK</span>';
                if (l.status_code >= 300 && l.status_code < 400) {
                    statusTag = `<span class="tag accent" style="font-weight:700; font-size:11px;">${l.status_code}</span>`;
                } else if (l.status_code >= 400 && l.status_code < 500) {
                    statusTag = `<span class="tag warning" style="font-weight:700; font-size:11px;">${l.status_code}</span>`;
                } else if (l.status_code >= 500) {
                    statusTag = `<span class="tag danger" style="font-weight:700; font-size:11px;">${l.status_code}</span>`;
                }
                const geoText = formatGeoCN(l);
                const domain = l.domain || '默认站点';
                const uaShort = (l.user_agent || 'Unknown').slice(0, 36);
                const rawPath = l.path || '/';
                const pathDisplay = (rawPath.length > 45) ? (rawPath.slice(0, 42) + '...') : rawPath;
                html += `
                <tr>
                    <td style="font-size:12px; font-variant-numeric:tabular-nums; color:var(--text-sec);">${l.access_time}</td>
                    <td><span class="ip-text" onclick="showIPDetail('${jsEscape(l.ip)}')" title="点击查看 IP 详情">${escapeHtml(l.ip)}</span></td>
                    <td><span style="font-size:12px; color:var(--text); font-weight:600;">${geoText}</span></td>
                    <td><span class="tag neutral" style="font-size:12px; font-weight:700; font-family:inherit; color:var(--accent); max-width:160px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; display:inline-block; vertical-align:middle;" title="${escapeHtml(domain)}">🌐 ${escapeHtml(domain)}</span></td>
                    <td>
                        <div style="display:inline-flex; align-items:center; gap:6px; max-width:320px;">
                            ${methodTag}
                            <code style="background:var(--card-sec); padding:2px 6px; border-radius:6px; font-size:12px; font-weight:600; color:var(--text); max-width:260px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; display:inline-block; vertical-align:middle; cursor:pointer;" title="${escapeHtml(rawPath)}">${escapeHtml(pathDisplay)}</code>
                        </div>
                    </td>
                    <td>${statusTag}</td>
                    <td><span style="font-size:11px; color:var(--text-sec); max-width:180px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; display:inline-block; vertical-align:middle;" title="${escapeHtml(l.user_agent || '')}">${escapeHtml(uaShort)}</span></td>
                </tr>
                `;
            });
        }
        tbody.innerHTML = html;
    }

    function exportAccessLogsCSV() {
        const activeLogs = (currentAccessLogMode === 'port') ? allPortLogs : allWebLogs;
        if (!activeLogs || activeLogs.length === 0) return showToast('暂无日志可导出', '⚠️');
        let csv = '';
        if (currentAccessLogMode === 'port') {
            csv = '\uFEFF访问时间,来源IP,国家/地区,网络运营商,协议,目标端口,服务说明,处置动作\n';
            activeLogs.forEach(l => {
                csv += `"${l.access_time}","${l.ip}","${l.country || ''} ${l.region || ''}","${l.isp || ''}","${l.proto || 'TCP'}","${l.port}","${(l.port_name || '').replace(/"/g, '""')}","${l.action || 'INTERCEPTED'}"\n`;
            });
        } else {
            csv = '\uFEFF访问时间,客户端IP,国家/地区,网络运营商,访问域名,请求方式,请求路径,响应状态码,客户端UserAgent\n';
            activeLogs.forEach(l => {
                csv += `"${l.access_time}","${l.ip}","${l.country || ''} ${l.region || ''}","${l.isp || ''}","${l.domain || ''}","${l.method}","${l.path}","${l.status_code}","${(l.user_agent || '').replace(/"/g, '""')}"\n`;
            });
        }
        const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
        const link = document.createElement('a');
        link.href = URL.createObjectURL(blob);
        link.download = `portsentry_${currentAccessLogMode}_access_logs_${new Date().toISOString().slice(0,10)}.csv`;
        link.click();
        showToast(`已开始下载${currentAccessLogMode === 'port' ? '端口访问' : '443访问'}审计报表 CSV`, '📥');
    }

    function clearAccessLogs() {
        const modeText = (currentAccessLogMode === 'port') ? '端口访问日志' : '443访问日志';
        if (!confirm(`确定要清空全部历史【${modeText}】吗？此操作不可恢复。`)) return;
        fetch('/api/access_logs/clear', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ type: currentAccessLogMode })
        }).then(res => res.json()).then(res => {
            showToast(res.msg || `${modeText}已清空`, '🗑️');
            fetchData(false);
        });
    }

    function filterLogs(cat, btn) {
        currentCategory = cat;
        document.querySelectorAll('.segment-btn').forEach(b => b.classList.remove('active'));
        if (btn) btn.classList.add('active');
        renderLogsTable();
    }

    function unbanIP(ip) {
        if (!confirm(`确定要从内核黑名单中解除对 ${ip} 的封禁吗？`)) return;
        fetch('/api/unban', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ip })
        }).then(res => res.json()).then(res => {
            showToast(res.msg || '解封成功', '🔓');
            fetchData(false);
        });
    }

    function openManualBanModal() { document.getElementById('modal-ban').style.display = 'flex'; }
    function openAddWhiteModal() { document.getElementById('modal-white').style.display = 'flex'; }
    function openAddTrapModal() { document.getElementById('modal-trap').style.display = 'flex'; }
    function closeModals() { 
        document.querySelectorAll('.modal-overlay').forEach(m => {
            m.style.display = 'none';
            m.classList.remove('active');
        });
    }

    function submitManualBan() {
        const ip = document.getElementById('ban-ip-val').value.trim();
        const reason = document.getElementById('ban-reason-val').value.trim();
        if (!ip) return showToast('请输入目标 IP', '⚠️');
        fetch('/api/ban', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ip, reason })
        }).then(res => res.json()).then(res => {
            showToast(res.msg, '🚫');
            closeModals();
            fetchData(false);
        });
    }

    function submitAddWhite() {
        const ip = document.getElementById('white-ip-val').value.trim();
        const remark = document.getElementById('white-remark-val').value.trim();
        if (!ip) return showToast('请输入信任 IP', '⚠️');
        fetch('/api/whitelist/add', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ip, remark })
        }).then(res => res.json()).then(res => {
            showToast(res.msg, '🛡️');
            closeModals();
            fetchData(false);
        });
    }

    function deleteWhitelist(ip) {
        if (!confirm(`确定要移除白名单 ${ip} 吗？`)) return;
        fetch('/api/whitelist/delete', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ip })
        }).then(res => res.json()).then(res => {
            showToast(res.msg, '🗑️');
            fetchData(false);
        });
    }

    function submitAddTrap() {
        const rawPort = document.getElementById('trap-port-val').value.trim();
        const name = document.getElementById('trap-name-val').value.trim();
        const category = document.getElementById('trap-cat-val').value;
        const level = document.getElementById('trap-level-val').value;
        const is_business = document.getElementById('trap-is-business-val') ? document.getElementById('trap-is-business-val').checked : false;
        if (!rawPort) return showToast('请输入端口号或端口范围 (例如 8088 或 1000-3000)', '⚠️');
        
        fetch('/api/traps/add', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ port: rawPort, name, level, category, enabled: true, is_business })
        }).then(res => res.json()).then(res => {
            if (res.success) {
                showToast(res.msg, '🍯');
                closeModals();
                if (document.getElementById('trap-is-business-val')) document.getElementById('trap-is-business-val').checked = false;
                fetchData(false);
            } else {
                showToast(res.msg || '添加失败，请检查端口格式', '❌');
            }
        });
    }

    function openEditTrapModal(portStr) {
        const item = allTraps.find(t => String(t.port) === String(portStr) || String(t.port_start) === String(portStr));
        if (!item) return showToast('未找到该策略数据', '⚠️');
        
        document.getElementById('edit-trap-orig-port').value = portStr;
        document.getElementById('edit-trap-port-val').value = item.port || portStr;
        document.getElementById('edit-trap-name-val').value = item.description || item.name || '';
        document.getElementById('edit-trap-cat-val').value = item.category || 'custom';
        document.getElementById('edit-trap-level-val').value = item.level || '高危';
        const isEnabled = (item.enabled === true || item.strategy === 'accept' || item.strategy === 'enabled' || item.strategy === '启用');
        document.getElementById('edit-trap-enabled-val').value = isEnabled ? 'true' : 'false';
        if (document.getElementById('edit-trap-is-business-val')) {
            document.getElementById('edit-trap-is-business-val').checked = !!(item.is_business || item.trap_business);
        }
        
        document.getElementById('modal-trap-edit').style.display = 'flex';
    }

    function submitEditTrap() {
        const orig_port = document.getElementById('edit-trap-orig-port').value.trim();
        const port = document.getElementById('edit-trap-port-val').value.trim();
        const name = document.getElementById('edit-trap-name-val').value.trim();
        const category = document.getElementById('edit-trap-cat-val').value;
        const level = document.getElementById('edit-trap-level-val').value;
        const enabled = (document.getElementById('edit-trap-enabled-val').value === 'true');
        const is_business = document.getElementById('edit-trap-is-business-val') ? document.getElementById('edit-trap-is-business-val').checked : false;
        
        if (!port) return showToast('端口号或范围不能为空', '⚠️');

        fetch('/api/traps/edit', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ orig_port, port, name, category, level, enabled, is_business })
        }).then(res => res.json()).then(res => {
            if (res.success) {
                showToast(res.msg || '策略已更新', '✓');
                closeModals();
                fetchData(false);
            } else {
                showToast(res.msg || '更新失败', '❌');
            }
        });
    }

    function deleteTrap(port) {
        if (!confirm(`确定要彻底删除诱饵策略 [${port}] 吗？`)) return;
        fetch('/api/traps/delete', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ port: String(port) })
        }).then(res => res.json()).then(res => {
            if (res.success) {
                showToast(res.msg || `已删除端口策略 ${port}`, '🗑️');
                fetchData(false);
            } else {
                showToast(res.msg || '删除失败', '❌');
            }
        });
    }

    function toggleTrap(port, enabled) {
        fetch('/api/traps/toggle', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ port: String(port), enabled: enabled })
        }).then(res => res.json()).then(res => {
            showToast(res.msg || `端口 ${port} 状态已更新`, '⚙️');
            fetchData(false);
        });
    }

    let currentImportType = 'traps';

    function openImportModal(type) {
        currentImportType = type;
        const modal = document.getElementById('modal-import');
        const titleEl = document.getElementById('import-modal-title');
        const tipEl = document.getElementById('import-tip-content');
        const fileInput = document.getElementById('import-file-input');
        const textVal = document.getElementById('import-text-val');
        const fileName = document.getElementById('import-file-name');

        fileInput.value = '';
        textVal.value = '';
        fileName.innerText = '';

        if (type === 'traps') {
            titleEl.innerText = '🍯 智能导入蜜罐策略';
            tipEl.innerHTML = `
                支持导入标准 JSON 策略数组，<b>向下兼容手输格式与端口范围</b>：<br>
                <code>[{"family":"ipv4","address":"","port":"1000-3000","protocol":"tcp","strategy":"accept","description":"自定义范围探针"}]</code><br>
                • <code>port/prot</code>: 单个端口号 (如 <code>"80"</code>) 或端口范围 (如 <code>"1000-3000"</code>)<br>
                • <code>protocol</code>: 协议 (tcp/udp)<br>
                • <code>strategy</code>: 开关状态 (accept/enabled/启用 ➔ 启用; reject/disabled/停用 ➔ 停用)<br>
                • <code>description/desc</code>: 模拟服务说明描述 (如 "网页", "高危探针段")<br>
                <i>系统会自动容错清洗末尾多余逗号 (<code>, ]</code>) 与宽松语法！</i>
            `;
            textVal.placeholder = `粘贴蜜罐策略 JSON 数组，例如：\n[\n  {\n    "family": "ipv4",\n    "address": "",\n    "port": "1000-3000",\n    "protocol": "tcp",\n    "strategy": "accept",\n    "description": "自定义高危端口段"\n  }\n]`;
        } else if (type === 'http_traps') {
            titleEl.innerText = '🎯 智能导入请求特征策略';
            tipEl.innerHTML = `
                支持导入 <b>JSON 格式策略数组</b>：<br>
                <code>[{"name":"敏感配置嗅探","match_type":"path_keyword","pattern":"\\\\.env|\\\\.git","level":"极高危","description":"探测关键敏感配置"}]</code><br>
                • <code>match_type</code>: 匹配类型 (<code>path_keyword</code>: URL路径特征 / <code>ua_keyword</code>: 工具指纹 / <code>status_rate</code>: 404频次熔断)<br>
                • <code>pattern</code>: 特征正则表达式或关键词 (支持 | 分隔)<br>
                • <code>threshold / window</code>: 熔断频次与时间窗口(秒)<br>
                • <code>level</code>: 威胁等级 (极高危 / 高危 / 中危)
            `;
            textVal.placeholder = `粘贴特征策略 JSON 数组，例如：\n[\n  {\n    "name": "敏感配置嗅探",\n    "match_type": "path_keyword",\n    "pattern": "\\\\.env|\\\\.git",\n    "level": "极高危",\n    "description": "探测配置文件"\n  }\n]`;
        } else if (type === 'blacklist') {
            titleEl.innerText = '🚫 批量导入内核黑名单';
            tipEl.innerHTML = `
                支持导入 <b>JSON 数组</b> 或 <b>纯文本逐行 IP 列表</b>：<br>
                • JSON 格式: <code>[{"ip": "1.2.3.4", "reason": "嗅探扫描", "level": "极高危"}]</code><br>
                • 文本格式: 每行一个 IP 地址（例如 <code>1.2.3.4 恶意扫描</code> 或纯 <code>1.2.3.4</code>）<br>
                导入后系统将自动下发内核 iptables DROP 规则与路由黑洞！
            `;
            textVal.placeholder = `粘贴 IP 列表或 JSON 数组，例如：\n1.2.3.4 恶意暴力破解\n5.6.7.8\n\n或 JSON 格式：\n[{"ip": "1.2.3.4", "reason": "嗅探扫描"}]`;
        } else if (type === 'whitelist') {
            titleEl.innerText = '🛡️ 批量导入安全信任白名单';
            tipEl.innerHTML = `
                支持导入 <b>JSON 数组</b> 或 <b>纯文本逐行 IP 列表</b>：<br>
                • JSON 格式: <code>[{"ip": "111.183.103.75", "remark": "办公室运维"}]</code><br>
                • 文本格式: 每行一个 IP / 网段（例如 <code>192.168.1.0/24 局域网</code> 或 <code>111.183.103.75</code>）<br>
                白名单内的 IP 永不触发任何诱捕封禁机制！
            `;
            textVal.placeholder = `粘贴白名单 IP 列表或 JSON 数组，例如：\n111.183.103.75 办公室固定IP\n192.168.1.0/24 局域网网段\n\n或 JSON 格式：\n[{"ip": "111.183.103.75", "remark": "办公室运维"}]`;
        }

        modal.style.display = 'flex';
    }

    function insertImportTemplate() {
        const textVal = document.getElementById('import-text-val');
        if (currentImportType === 'traps') {
            textVal.value = JSON.stringify([
                {
                    "family": "ipv4",
                    "address": "",
                    "port": "80",
                    "protocol": "tcp",
                    "strategy": "accept",
                    "description": "网页"
                },
                {
                    "family": "ipv4",
                    "address": "",
                    "port": "21",
                    "protocol": "tcp",
                    "strategy": "accept",
                    "description": "FTP 暴力破解诱饵"
                },
                {
                    "family": "ipv4",
                    "address": "",
                    "port": "3389",
                    "protocol": "tcp",
                    "strategy": "accept",
                    "description": "RDP 远程桌面探针"
                },
                {
                    "family": "ipv4",
                    "address": "",
                    "port": "8888",
                    "protocol": "tcp",
                    "strategy": "reject",
                    "description": "宝塔控制台探针(已停用)"
                }
            ], null, 2);
        } else if (currentImportType === 'http_traps') {
            textVal.value = JSON.stringify([
                {
                    "name": "敏感配置与备份嗅探",
                    "match_type": "path_keyword",
                    "pattern": "\\.env|\\.git|\\.svn|config\\.json|backup\\.zip|database\\.sql",
                    "level": "极高危",
                    "description": "探测系统关键配置文件与数据库备份"
                },
                {
                    "name": "黑客扫描器工具指纹",
                    "match_type": "ua_keyword",
                    "pattern": "sqlmap|nikto|dirsearch|gobuster|wpscan",
                    "level": "高危",
                    "description": "拦截自动化扫描工具探测"
                },
                {
                    "name": "高频 404 爆破熔断",
                    "match_type": "status_rate",
                    "threshold": 6,
                    "window": 30,
                    "level": "高危",
                    "description": "30秒内连续 6 次 404 熔断"
                }
            ], null, 2);
        } else if (currentImportType === 'blacklist') {
            textVal.value = JSON.stringify([
                { "ip": "198.51.100.1", "reason": "SSH 暴力破解源", "level": "极高危" },
                { "ip": "203.0.113.5", "reason": "全端口自动化扫描器", "level": "高危" }
            ], null, 2);
        } else if (currentImportType === 'whitelist') {
            textVal.value = JSON.stringify([
                { "ip": "192.168.1.0/24", "remark": "局域网管理网段" },
                { "ip": "111.183.103.75", "remark": "运维固定公网 IP" }
            ], null, 2);
        }
        showToast('已填入标准格式示例', '📝');
    }

    function handleImportFileSelect(event) {
        const file = event.target.files[0];
        if (!file) return;
        document.getElementById('import-file-name').innerText = file.name;
        const reader = new FileReader();
        reader.onload = (e) => {
            document.getElementById('import-text-val').value = e.target.result;
            showToast(`已加载文件: ${file.name}`, '📂');
        };
        reader.readAsText(file);
    }

    function submitUniversalImport() {
        const textVal = document.getElementById('import-text-val').value.trim();
        if (!textVal) return showToast('请先选择文件或粘贴导入内容', '⚠️');

        const modeRadio = document.querySelector('input[name="import-mode"]:checked');
        const mode = modeRadio ? modeRadio.value : 'append';

        const btn = document.getElementById('btn-submit-import');
        btn.disabled = true;
        btn.innerText = '正在导入中...';

        fetch(`/api/${currentImportType}/import`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ data: textVal, mode: mode })
        }).then(res => res.json()).then(res => {
            btn.disabled = false;
            btn.innerText = '🚀 确认导入';
            if (res.success) {
                showToast(res.msg || '导入成功！', '🎉');
                closeModals();
                fetchData(false);
            } else {
                showToast(res.msg || '导入失败，请检查格式', '❌');
            }
        }).catch(err => {
            btn.disabled = false;
            btn.innerText = '🚀 确认导入';
            showToast('请求发生网络异常: ' + err, '❌');
        });
    }

    function exportTrapsJSON() {
        fetch('/api/traps/export').then(res => res.json()).then(data => {
            downloadJSONFile(data, `portsentry_traps_strategy_${new Date().toISOString().slice(0,10)}.json`);
            showToast('蜜罐策略 JSON 已开始导出', '📤');
        }).catch(() => showToast('导出策略失败', '❌'));
    }

    function exportBlacklistJSON() {
        fetch('/api/blacklist/export').then(res => res.json()).then(data => {
            downloadJSONFile(data, `portsentry_blacklist_${new Date().toISOString().slice(0,10)}.json`);
            showToast('黑名单 JSON 已开始导出', '📤');
        }).catch(() => showToast('导出黑名单失败', '❌'));
    }

    function exportWhitelistJSON() {
        fetch('/api/whitelist/export').then(res => res.json()).then(data => {
            downloadJSONFile(data, `portsentry_whitelist_${new Date().toISOString().slice(0,10)}.json`);
            showToast('白名单 JSON 已开始导出', '📤');
        }).catch(() => showToast('导出白名单失败', '❌'));
    }

    function downloadJSONFile(dataObj, fileName) {
        const jsonStr = JSON.stringify(dataObj, null, 2);
        const blob = new Blob([jsonStr], { type: 'application/json;charset=utf-8;' });
        const link = document.createElement('a');
        link.href = URL.createObjectURL(blob);
        link.download = fileName;
        link.click();
    }

    function exportLogsCSV() {
        if (!allEvents || allEvents.length === 0) return showToast('当前暂无日志可导出', '⚠️');
        let csv = '\uFEFF攻击拦截时间,攻击者IP,国家,地区,ISP运营商,探测端口,服务名称,威胁等级,防护状态\n';
        allEvents.forEach(e => {
            csv += `"${csvEscape(e.attack_time)}","${csvEscape(e.ip)}","${csvEscape(e.country || '')}","${csvEscape(e.region || '')}","${csvEscape(e.isp || '')}","${e.port}","${csvEscape(e.port_name || '')}","${csvEscape(e.level || '高危')}","${csvEscape(e.status)}"\n`;
        });
        const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
        const link = document.createElement('a');
        link.href = URL.createObjectURL(blob);
        link.download = `portsentry_audit_logs_${new Date().toISOString().slice(0,10)}.csv`;
        link.click();
        showToast('已开始下载 CSV 审计报表', '📥');
    }

    function copyIP(text) {
        navigator.clipboard.writeText(text).then(() => showToast(`已复制 IP: ${text}`, '📋'));
    }

    async function loadSystemSettings() {
        try {
            const res = await fetch('/api/settings');
            const data = await res.json();
            if (document.getElementById('setting-trap-threshold')) {
                document.getElementById('setting-trap-threshold').value = String(data.trap_threshold || 1);
            }
            if (document.getElementById('setting-trap-window')) {
                document.getElementById('setting-trap-window').value = String(data.trap_window_seconds || 30);
            }
            if (document.getElementById('setting-auto-clean')) {
                document.getElementById('setting-auto-clean').value = String(data.auto_clean_days !== undefined ? data.auto_clean_days : 30);
            }
            if (document.getElementById('setting-trap-all-ports')) {
                document.getElementById('setting-trap-all-ports').checked = data.trap_all_ports !== false;
            }
            if (document.getElementById('setting-trap-all-unopened')) {
                document.getElementById('setting-trap-all-unopened').checked = data.trap_all_unopened_ports !== false;
            }
            if (document.getElementById('setting-ban-iptables')) {
                document.getElementById('setting-ban-iptables').checked = data.ban_action_iptables !== false;
            }
            if (document.getElementById('setting-ban-blackhole')) {
                document.getElementById('setting-ban-blackhole').checked = data.ban_action_blackhole !== false;
            }
            updateThresholdBadge();
        } catch (e) {
            console.error(e);
        }
    }

    function updateThresholdBadge() {
        const sel = document.getElementById('setting-trap-threshold');
        if (!sel) return;
        const val = parseInt(sel.value || '1');
        const badge = document.getElementById('badge-threshold-status');
        if (!badge) return;
        if (val === 1) {
            badge.innerText = '⚡ 零容忍立即封禁';
            badge.className = 'badge badge-high';
        } else if (val === 2) {
            badge.innerText = '🛡️ 严苛防御模式';
            badge.className = 'badge badge-high';
        } else {
            badge.innerText = '⚖️ 标准防误触模式';
            badge.className = 'badge badge-low';
        }
    }

    async function saveSystemSettings() {
        const threshold = parseInt(document.getElementById('setting-trap-threshold').value || '1');
        const windowSec = parseInt(document.getElementById('setting-trap-window').value || '30');
        const cleanDays = parseInt(document.getElementById('setting-auto-clean').value || '30');
        const trapAllPorts = document.getElementById('setting-trap-all-ports') ? document.getElementById('setting-trap-all-ports').checked : true;
        const trapAllUnopened = document.getElementById('setting-trap-all-unopened') ? document.getElementById('setting-trap-all-unopened').checked : true;
        const iptables = document.getElementById('setting-ban-iptables').checked;
        const blackhole = document.getElementById('setting-ban-blackhole').checked;

        try {
            showToast('正在保存系统设置...', '⏳');
            const res = await fetch('/api/settings', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    trap_threshold: threshold,
                    trap_window_seconds: windowSec,
                    auto_clean_days: cleanDays,
                    trap_all_ports: trapAllPorts,
                    trap_all_unopened_ports: trapAllUnopened,
                    ban_action_iptables: iptables,
                    ban_action_blackhole: blackhole
                })
            });
            const data = await res.json();
            if (data.success) {
                showToast(data.msg || '系统设置已成功保存并立即生效！', '🎉');
                updateThresholdBadge();
            } else {
                showToast(data.msg || '保存失败', '⚠️');
            }
        } catch (e) {
            showToast('请求异常: ' + e, '⚠️');
        }
    }

    async function batchBanAllProbes() {
        if (!confirm('确定要分析访问日志，将所有非白名单的历史扫描探测 IP 一键批量拉黑并下发防火墙阻断吗？')) {
            return;
        }
        try {
            showToast('正在批量分析与拉黑探测 IP...', '⏳');
            const res = await fetch('/api/blacklist/batch_ban_all', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({})
            });
            const data = await res.json();
            if (data.success) {
                showToast(data.msg || `批量拉黑完成！共拉黑 ${data.count || 0} 个恶意 IP`, '🎉');
                fetchData(false);
            } else {
                showToast(data.msg || '操作失败', '⚠️');
            }
        } catch (e) {
            showToast('请求异常: ' + e, '⚠️');
        }
    }

    document.addEventListener('DOMContentLoaded', () => {
        applyTheme(currentThemeMode, false);
        initCharts();
        fetchData(false);
        startAutoRefresh();
        const thresholdSelect = document.getElementById('setting-trap-threshold');
        if (thresholdSelect) {
            thresholdSelect.addEventListener('change', updateThresholdBadge);
        }
    });
</script>
</body>
</html>
"""

# 本地化 Chart.js：优先内嵌同目录 chart.min.js，文件缺失时保留 CDN 回退
try:
    _CHART_JS_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "chart.min.js")
    if os.path.exists(_CHART_JS_PATH):
        with open(_CHART_JS_PATH, "r", encoding="utf-8") as _cf:
            _CHART_SRC = _cf.read()
        HTML_TEMPLATE = HTML_TEMPLATE.replace(
            '<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>',
            "<script>" + _CHART_SRC + "</script>"
        )
except Exception:
    pass

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
        self.send_response(status)
        self.send_header('Content-Type', content_type)
        self.send_header('Access-Control-Allow-Origin', '*')
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

    def _send_json(self, data, status=200):
        payload = json.dumps(data, ensure_ascii=False).encode('utf-8')
        self._send_response_data(payload, content_type="application/json; charset=utf-8", status=status)

    def _send_html(self, html, status=200):
        global _GZIP_HTML_CACHE, _RAW_HTML_CACHE
        if _RAW_HTML_CACHE is None:
            _RAW_HTML_CACHE = html.encode('utf-8')
            _GZIP_HTML_CACHE = gzip.compress(_RAW_HTML_CACHE, compresslevel=6)
        
        accept_encoding = self.headers.get('Accept-Encoding', '')
        self.send_response(status)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
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

    def do_HEAD(self):
        self.send_response(200)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.end_headers()

    def do_GET(self):
        try:
            parsed = urlparse(self.path)
            path = parsed.path

            if path in ("/", "/index.html"):
                self._send_html(HTML_TEMPLATE)
                return

            if path == "/api/stats":
                conn = get_db()
                c = conn.cursor()
                
                c.execute("SELECT COUNT(DISTINCT ip) FROM blacklist")
                total_banned = c.fetchone()[0]
                
                today_prefix = time.strftime("%Y-%m-%d", time.localtime())
                c.execute("SELECT COUNT(*) FROM events WHERE attack_time LIKE ?", (f"{today_prefix}%",))
                today_events = c.fetchone()[0]
                
                c.execute("""
                SELECT port, port_name, COUNT(*) as cnt 
                FROM events 
                GROUP BY port 
                ORDER BY cnt DESC 
                LIMIT 5
                """)
                port_dist = [{"port": row["port"], "name": row["port_name"], "count": row["cnt"]} for row in c.fetchall()]
                
                # 国家排行 Top 5
                c.execute("""
                SELECT country, COUNT(*) as cnt 
                FROM events 
                WHERE country IS NOT NULL AND country != ''
                GROUP BY country 
                ORDER BY cnt DESC 
                LIMIT 5
                """)
                geo_rank = [{"country": row["country"], "count": row["cnt"]} for row in c.fetchall()]
                
                # 24小时趋势
                labels = []
                data_points = []
                now_ts = int(time.time())
                for i in range(23, -1, -1):
                    hour_start = now_ts - (i * 3600)
                    hour_end = hour_start + 3600
                    hour_label = time.strftime("%H:00", time.localtime(hour_start))
                    c.execute("SELECT COUNT(*) FROM events WHERE timestamp >= ? AND timestamp < ?", (hour_start, hour_end))
                    labels.append(hour_label)
                    data_points.append(c.fetchone()[0])
                    
                cfg = load_config()
                conn.close()
                
                raw_traps = cfg.get("trap_ports", DEFAULT_CONFIG["trap_ports"])
                active_traps = sum(1 for t in raw_traps if (t.get("enabled", True) if isinstance(t, dict) else True))
                whitelist_count = len(cfg.get("whitelist", []))
                
                self._send_json({
                    "total_banned": total_banned,
                    "today_events": today_events,
                    "active_traps": active_traps,
                    "whitelist_count": whitelist_count,
                    "port_distribution": port_dist,
                    "geo_rank": geo_rank,
                    "hourly_trend": {
                        "labels": labels,
                        "data": data_points
                    }
                })
                return
            if path == "/api/settings":
                cfg = load_config()
                self._send_json({
                    "trap_threshold": int(cfg.get("trap_threshold", 1) or 1),
                    "trap_window_seconds": int(cfg.get("trap_window_seconds", 30) or 30),
                    "auto_clean_days": int(cfg.get("auto_clean_days", 30) if cfg.get("auto_clean_days") is not None else 30),
                    "defense_mode": cfg.get("defense_mode", "strict"),
                    "trap_all_ports": bool(cfg.get("trap_all_ports", True)),
                    "trap_all_unopened_ports": bool(cfg.get("trap_all_unopened_ports", True)),
                    "trap_business_ports": bool(cfg.get("trap_business_ports", True)),
                    "ban_action_iptables": bool(cfg.get("ban_action_iptables", True)),
                    "ban_action_blackhole": bool(cfg.get("ban_action_blackhole", True)),
                    "web_port": int(cfg.get("web_port", 9099) or 9099)
                })
                return

            if path == "/api/events":
                conn = get_db()
                c = conn.cursor()
                c.execute("SELECT id, ip, port, proto, port_name, category, level, country, region, city, isp, attack_time, status FROM events ORDER BY id DESC LIMIT 200")
                rows = [dict(r) for r in c.fetchall()]
                conn.close()
                for r in rows:
                    if r.get("country") in ("分析中...", "", None):
                        cached = _GEO_CACHE.get(r["ip"])
                        if cached:
                            r["country"] = cached.get("country", "公网节点")
                            r["region"] = cached.get("region", "")
                            r["city"] = cached.get("city", "")
                            r["isp"] = cached.get("isp", "")
                        else:
                            _EXECUTOR.submit(resolve_ip_geo, r["ip"])
                self._send_json(rows)
                return

            if path == "/api/blacklist":
                conn = get_db()
                c = conn.cursor()
                c.execute("SELECT ip, reason, country, level, ban_time, timestamp FROM blacklist ORDER BY timestamp DESC")
                rows = [dict(r) for r in c.fetchall()]
                conn.close()
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
                c.execute("SELECT ip, reason, country, level, ban_time, timestamp FROM blacklist ORDER BY timestamp DESC")
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
                        c.execute("SELECT id, ip, domain, method, path, status_code, user_agent, country, region, city, isp, access_time, timestamp FROM access_logs WHERE domain = ? ORDER BY id DESC LIMIT ?", (domain_filter, limit_cnt))
                    else:
                        c.execute("SELECT id, ip, domain, method, path, status_code, user_agent, country, region, city, isp, access_time, timestamp FROM access_logs ORDER BY id DESC LIMIT ?", (limit_cnt,))
                    rows = [dict(r) for r in c.fetchall()]
                    for r in rows:
                        if (not r.get("country") or r.get("country") == "分析中...") and r.get("ip") in _GEO_CACHE:
                            g = _GEO_CACHE[r["ip"]]
                            r["country"] = g.get("country", "")
                            r["region"] = g.get("region", "")
                            r["city"] = g.get("city", "")
                            r["isp"] = g.get("isp", "")
                else:
                    c.execute("SELECT id, ip, port, proto, port_name, country, region, city, isp, action, access_time, timestamp FROM port_access_logs ORDER BY id DESC LIMIT ?", (limit_cnt,))
                    rows = [dict(r) for r in c.fetchall()]
                    if not rows:
                        c.execute("SELECT id, ip, port, proto, port_name, country, region, city, isp, status as action, attack_time as access_time, timestamp FROM events ORDER BY id DESC LIMIT ?", (limit_cnt,))
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
            self._send_json({"error": str(e)}, status=500)

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

                run_firewall_cmd("iptables", "-D", "INPUT", "-s", ip, "-j", "DROP")
                run_firewall_cmd("ip", "route", "del", "blackhole", f"{ip}/32")
                run_firewall_cmd("iptables-save")
                
                conn = get_db()
                c = conn.cursor()
                c.execute("DELETE FROM blacklist WHERE ip = ?", (ip,))
                c.execute("UPDATE events SET status = 'UNBANNED' WHERE ip = ?", (ip,))
                conn.commit()
                conn.close()
                
                self._send_json({"success": True, "msg": f"已成功解封 IP: {ip}"})
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

                run_firewall_cmd("iptables", "-C", "INPUT", "-s", ip, "-j", "DROP")
                run_firewall_cmd("iptables", "-I", "INPUT", "-s", ip, "-j", "DROP")
                run_firewall_cmd("ip", "route", "add", "blackhole", f"{ip}/32")
                run_firewall_cmd("iptables-save")
                
                now_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
                now_ts = int(time.time())
                
                conn = get_db()
                c = conn.cursor()
                c.execute("""
                INSERT OR REPLACE INTO blacklist (ip, reason, country, level, ban_time, timestamp)
                VALUES (?, ?, '手动添加', '极高危', ?, ?)
                """, (ip, reason, now_str, now_ts))
                c.execute("""
                INSERT INTO events (ip, port, proto, port_name, category, level, country, region, city, isp, attack_time, timestamp, status)
                VALUES (?, 0, 'MANUAL', ?, 'manual', '极高危', '手动添加', '', '', '', ?, ?, 'BANNED')
                """, (ip, reason, now_str, now_ts))
                conn.commit()
                conn.close()
                
                self._send_json({"success": True, "msg": f"已成功封禁 IP: {ip}"})
                return

            if path == "/api/settings":
                cfg = load_config()
                if "trap_threshold" in req_data:
                    cfg["trap_threshold"] = int(req_data["trap_threshold"])
                if "trap_window_seconds" in req_data:
                    cfg["trap_window_seconds"] = int(req_data["trap_window_seconds"])
                if "auto_clean_days" in req_data:
                    cfg["auto_clean_days"] = int(req_data["auto_clean_days"])
                if "ban_action_iptables" in req_data:
                    cfg["ban_action_iptables"] = bool(req_data["ban_action_iptables"])
                if "ban_action_blackhole" in req_data:
                    cfg["ban_action_blackhole"] = bool(req_data["ban_action_blackhole"])
                if "trap_business_ports" in req_data:
                    cfg["trap_business_ports"] = bool(req_data["trap_business_ports"])
                if "trap_all_unopened_ports" in req_data:
                    cfg["trap_all_unopened_ports"] = bool(req_data["trap_all_unopened_ports"])
                if "trap_all_ports" in req_data:
                    cfg["trap_all_ports"] = bool(req_data["trap_all_ports"])
                save_config(cfg)
                self._send_json({"success": True, "msg": "系统防御设置已成功保存并立即生效！"})
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
                    """, (v, f"未开放端口全网扫描 (端口 {port})", country, now_str, now_ts, ban_expire))
                    
                    c.execute("""
                    INSERT INTO events (ip, port, proto, port_name, category, level, country, region, city, isp, attack_time, timestamp, status)
                    VALUES (?, ?, 'TCP', '全网端口嗅探扫描', 'scan', '高危', ?, '', '', '', ?, ?, 'BANNED')
                    """, (v, port, country, now_str, now_ts))
                    
                    if not cached_geo:
                        _EXECUTOR.submit(resolve_ip_geo, v)
                    count += 1
                    
                conn.commit()
                conn.close()
                if cfg.get("ban_action_iptables", True):
                    run_firewall_cmd("iptables-save")
                self._send_json({"success": True, "count": count, "msg": f"已成功将 {count} 个历史探测 IP 批量拉黑并下发防火墙！"})
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
                        reason = str(item.get("reason", "批量导入拉黑")).strip()
                        country = str(item.get("country", "手动导入")).strip()
                        level = str(item.get("level", "极高危")).strip()
                        ban_time = str(item.get("ban_time", now_str)).strip()
                    elif isinstance(item, str):
                        parts = item.strip().split(maxsplit=1)
                        ip = parts[0].strip() if parts else ""
                        reason = parts[1].strip() if len(parts) > 1 else "批量导入拉黑"
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

                    c.execute("""
                    INSERT OR REPLACE INTO blacklist (ip, reason, country, level, ban_time, timestamp, ban_expire)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """, (ip, reason, country, level, ban_time, now_ts, None))
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
                cfg = load_config()
                whitelist = cfg.get("whitelist", [])
                if not any(w.get("ip") == ip if isinstance(w, dict) else w == ip for w in whitelist):
                    whitelist.append({"ip": ip, "remark": remark})
                    cfg["whitelist"] = whitelist
                    save_config(cfg)
                self._send_json({"success": True, "msg": f"已添加信任白名单: {ip}"})
                return

            if path == "/api/whitelist/delete":
                ip = req_data.get("ip", "").strip()
                cfg = load_config()
                cfg["whitelist"] = [w for w in cfg.get("whitelist", []) if (w.get("ip") if isinstance(w, dict) else w) != ip]
                save_config(cfg)
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
                        
                    current_map[ip] = {"ip": ip, "remark": remark}
                    success_count += 1
                    
                if success_count == 0:
                    self._send_json({"success": False, "msg": "未能提取到有效的 IP 白名单项"}, status=400)
                    return
                    
                cfg["whitelist"] = list(current_map.values())
                save_config(cfg)
                self._send_json({
                    "success": True,
                    "msg": f"信任白名单导入成功！共载入 {success_count} 条规则 (当前总计 {len(current_map)} 条)",
                    "count": success_count,
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

            self._send_json({"error": "Not Found"}, status=404)
        except Exception as e:
            self._send_json({"error": str(e)}, status=500)

def run_server():
    init_db()
    cfg = load_config()
    bind_ip = cfg.get("web_bind", "0.0.0.0")
    bind_port = int(cfg.get("web_port", 9099))

    ThreadingHTTPServer.allow_reuse_address = True
    httpd = ThreadingHTTPServer((bind_ip, bind_port), RequestHandler)
    print(f"[Portsentry-UI Full-Responsive] 控制台已就绪: http://{bind_ip}:{bind_port}")
    
    trap_instance.start()
    sniffer_instance.start()
    site_collector_instance.start()
    cleanup_expired_bans()

    # 后台平滑增量重放黑名单到 iptables / 黑洞路由（彻底杜绝进程风暴与 CPU 脉冲）
    def _async_replay_blacklist():
        try:
            existing_rules = set()
            try:
                p = subprocess.run(["iptables", "-S", "INPUT"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
                for line in (p.stdout or "").splitlines():
                    if "-j DROP" in line and "-s" in line:
                        parts = line.split()
                        if "-s" in parts:
                            idx = parts.index("-s")
                            if idx + 1 < len(parts):
                                existing_rules.add(parts[idx + 1].split("/")[0])
            except Exception:
                pass

            conn = get_db()
            c = conn.cursor()
            c.execute("SELECT ip FROM blacklist")
            rows = c.fetchall()
            conn.close()

            count = 0
            for (ip,) in rows:
                v = validate_ip(ip)
                if not v:
                    continue
                if v not in existing_rules:
                    run_firewall_cmd("iptables", "-I", "INPUT", "-s", v, "-j", "DROP")
                    run_firewall_cmd("ip", "route", "add", "blackhole", f"{v}/32")
                    count += 1
                    time.sleep(0.01)  # 10ms 间隔平滑 CPU 占用
            print(f"[Portsentry] 异步完成 {count} 条增量黑名单防火墙规则重放 (已存在 {len(existing_rules)} 条)")
        except Exception as e:
            print(f"[Portsentry] 黑名单重放失败: {e}")
    threading.Thread(target=_async_replay_blacklist, daemon=True).start()
    
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    sniffer_instance.stop()
    httpd.server_close()

if __name__ == "__main__":
    run_server()
