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
import urllib.request
import urllib.error
import urllib.parse
from urllib.parse import urlparse, parse_qs

_RAW_HTML_CACHE = None
_GZIP_HTML_CACHE = None
from sentry_daemon import (
    DB_PATH, CONFIG_PATH, load_config, save_config, get_db, init_db,
    trap_instance, sniffer_instance, site_collector_instance, DEFAULT_CONFIG, PORT_DESCRIPTIONS,
    DEFAULT_HTTP_TRAPS, get_http_traps, check_http_request_traps,
    normalize_trap_item, log_access_entry, validate_ip, run_firewall_cmd,
    cleanup_expired_bans, ip_in_whitelist, resolve_ip_geo, resolve_ip_geo_local, _GEO_CACHE, _EXECUTOR,
    get_hidden_ips, get_hidden_ips_set, add_hidden_ip, remove_hidden_ip, clear_hidden_ips,
    get_all_business_ports_info, get_active_system_ports, unban_ip_core,
    ban_ip_firewall, init_firewall_ipset, verify_cluster_token, generate_cluster_token, ban_ip,
    normalize_cluster_node, broadcast_cluster_whitelist, broadcast_cluster_ban,
    broadcast_cluster_unban, sync_cluster_mesh_state, start_cluster_autosync_worker
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
    <title>PortGuard · 智能主动诱捕防御系统</title>
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
        html, body {
            overflow-x: hidden;
            width: 100%;
            max-width: 100vw;
            touch-action: manipulation;
            -webkit-text-size-adjust: 100%;
            overscroll-behavior: none;
            overscroll-behavior-y: none;
            position: relative;
        }
        body {
            font-family: -apple-system, BlinkMacSystemFont, "SF Pro Text", "SF Pro Display", "PingFang SC", "Hiragino Sans GB", "Microsoft YaHei", sans-serif;
            background-color: var(--bg);
            color: var(--text);
            min-height: 100vh;
            padding: 12px 16px calc(100px + env(safe-area-inset-bottom)) 16px;
            -webkit-font-smoothing: antialiased;
            transition: background-color 0.3s ease, color 0.3s ease;
        }
        .container { max-width: 1100px; width: 100%; min-width: 0; margin: 0 auto; }

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

        /* Header (移动端与桌面自适应) */
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
        .status-dot.paused {
            background: var(--warning) !important;
            box-shadow: 0 0 8px rgba(255, 149, 0, 0.6) !important;
            animation: none !important;
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

        .btn-text-mobile { display: none; }
        .analytics-subtab-bar {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 14px;
            gap: 10px;
        }
        .analytics-filter-row {
            display: flex;
            align-items: center;
            gap: 8px;
        }
        @media (max-width: 768px) {
            .analytics-subtab-bar {
                flex-direction: column;
                align-items: flex-start;
                gap: 8px;
            }
            .analytics-filter-row {
                width: 100%;
                justify-content: space-between;
            }
            .analytics-filter-row .segmented-control {
                flex: 1;
            }
        }

        @media (max-width: 600px) {
            .header { margin: 2px 0 10px 0; min-height: 38px; }
            .title { font-size: 20px; line-height: 1.2; }
            .date-badge { font-size: 10px; }
            .pill-btn { padding: 5px 8px; font-size: 11px; gap: 4px; }
            .pill-btn .btn-text-full { display: none; }
            .pill-btn .btn-text-mobile { display: inline; }
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

        .grid-3 {
            display: grid;
            grid-template-columns: repeat(3, minmax(0, 1fr));
            gap: 12px;
            margin-bottom: 16px;
        }
        @media (max-width: 960px) { .grid-3 { grid-template-columns: 1fr; } }

        .grid-6 {
            display: grid;
            grid-template-columns: repeat(6, minmax(0, 1fr));
            gap: 12px;
            margin-bottom: 16px;
        }
        @media (max-width: 1100px) { .grid-6 { grid-template-columns: repeat(3, minmax(0, 1fr)); } }
        @media (max-width: 600px) { .grid-6 { grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 10px; } }

        /* Cards */
        .card {
            background: var(--card);
            border-radius: 18px;
            padding: 16px 18px;
            border: 1px solid var(--border);
            box-shadow: var(--shadow-sm);
            transition: transform 0.2s ease, box-shadow 0.2s ease;
            position: relative;
            max-width: 100%;
            min-width: 0;
            overflow: hidden;
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
            th {
                padding: 8px 10px;
                font-size: 11px;
            }
            td {
                padding: 10px 10px;
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
            .card { padding: 12px 10px; border-radius: 14px; }
            th { padding: 7px 8px; font-size: 10px; }
            td { padding: 8px 8px; font-size: 11px; }
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
        .geo-subline {
            font-size: 11px;
            color: var(--text-sec);
            margin-top: 2px;
            font-weight: 500;
            line-height: 1.3;
            max-width: 175px;
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
            cursor: default;
        }

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

        /* Web Diagnostics Fingerprints (Paths & UAs) */
        .diag-row-item {
            background: var(--card-sec);
            border: 1px solid var(--border-subtle);
            border-radius: 10px;
            padding: 8px 10px;
            transition: background 0.15s ease;
            width: 100%;
            min-width: 0;
            overflow: hidden;
            box-sizing: border-box;
        }
        .diag-row-item:hover {
            background: var(--card-hover);
        }
        .diag-row-header {
            display: flex;
            align-items: center;
            justify-content: space-between;
            margin-bottom: 5px;
            gap: 6px;
            width: 100%;
            min-width: 0;
        }
        .diag-row-left {
            display: flex;
            align-items: center;
            flex: 1;
            min-width: 0;
            gap: 5px;
            overflow: hidden;
        }
        .diag-rank-badge {
            font-size: 10px;
            font-weight: 800;
            color: var(--text-sec);
            background: rgba(120, 120, 128, 0.12);
            padding: 2px 5px;
            border-radius: 5px;
            flex-shrink: 0;
            font-family: inherit;
        }
        .diag-text-title {
            font-size: 12px;
            font-weight: 600;
            color: var(--text);
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
            flex: 1;
            min-width: 0;
            letter-spacing: -0.01em;
            font-family: inherit;
        }
        .diag-count-text {
            font-size: 11px;
            font-weight: 700;
            color: var(--accent);
            flex-shrink: 0;
            white-space: nowrap;
            font-family: inherit;
        }
        .diag-bar-track {
            height: 4px;
            background: rgba(120, 120, 128, 0.12);
            border-radius: 99px;
            overflow: hidden;
            width: 100%;
        }
        .diag-bar-fill {
            height: 100%;
            border-radius: 99px;
            transition: width 0.3s ease;
        }

        /* Bottom Spacer (防止 Dock 遮挡) */
        .bottom-spacer { height: 60px; width: 100%; }

        /* Floating Glass Dock (悬浮玻璃底栏) */
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
    <!-- Header Bar (顶部状态栏) -->
    <div class="header">
        <div class="header-left">
            <div class="date-badge">
                <span class="status-dot" id="header-status-dot"></span>
                <span id="header-status-text">PORTGUARD · 内核防护中</span>
            </div>
            <h1 class="title" id="page-main-title">安全态势分析</h1>
        </div>
        <div class="header-actions">
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

    <!-- Page 1: 态势分析 (Overview & Multi-dimensional Deep Analytics) -->
    <div id="tab-overview">
        <!-- 顶部子页切换分段控件与多维分析时间范围工具栏 -->
        <div class="analytics-subtab-bar">
            <!-- 模式切换分段按钮 (采用与访问日志一致的胶囊拟态设计) -->
            <div style="background: var(--card-sec); border: 1px solid var(--border); border-radius: 99px; padding: 2px; display: inline-flex; gap: 2px; width: fit-content; flex-shrink: 0;">
                <button class="pill-btn accent" id="subtab-btn-overview" onclick="switchOverviewSubTab('overview', this)" style="padding: 4px 12px; font-size: 11px; border-radius: 99px; font-weight: 700;">📊 全局概览</button>
                <button class="pill-btn" id="subtab-btn-analysis" onclick="switchOverviewSubTab('analysis', this)" style="padding: 4px 12px; font-size: 11px; border-radius: 99px; font-weight: 700; background: transparent;">🔬 多维度分析</button>
            </div>
            <div id="analytics-toolbar" class="analytics-filter-row" style="display: none;">
                <div class="segmented-control" style="background: var(--card); border: 1px solid var(--border);">
                    <button class="segment-btn" id="filter-range-24h" onclick="changeAnalyticsRange('24h', this)">24h</button>
                    <button class="segment-btn active" id="filter-range-7d" onclick="changeAnalyticsRange('7d', this)">7天</button>
                    <button class="segment-btn" id="filter-range-30d" onclick="changeAnalyticsRange('30d', this)">30天</button>
                    <button class="segment-btn" id="filter-range-all" onclick="changeAnalyticsRange('all', this)">全部</button>
                </div>
                <button class="pill-btn accent" onclick="exportAnalyticsJSON()" style="flex-shrink: 0;" title="导出当前多维态势分析完整数据集 (JSON)">
                    <span>📥</span>
                    <span class="btn-text-full">导出报告</span>
                    <span class="btn-text-mobile">导出</span>
                </button>
            </div>
        </div>

        <!-- 子页 1: 全局概览 (subview-overview) -->
        <div id="subview-overview">
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
        </div>

        <!-- 子页 2: 多维深度分析 (subview-analysis) -->
        <div id="subview-analysis" style="display: none;">
            <!-- 6 维度核心指标概览看板 -->
            <div class="grid-6">
                <div class="card">
                    <div class="val-sub" style="color: var(--accent);">🛡️ 捕获探测总量</div>
                    <div class="val-big" id="akpi-probes" style="color: var(--accent); font-size: 24px;">--</div>
                    <div class="val-sub">网络层 SYN 嗅探统计</div>
                </div>
                <div class="card">
                    <div class="val-sub" style="color: var(--danger);">🚫 核心拦截阻断</div>
                    <div class="val-big" id="akpi-intercepted" style="color: var(--danger); font-size: 24px;">--</div>
                    <div class="val-sub">黑洞路由与防火墙处置</div>
                </div>
                <div class="card">
                    <div class="val-sub" style="color: var(--warning);">🌐 独立攻击者 IP</div>
                    <div class="val-big" id="akpi-attackers" style="color: var(--warning); font-size: 24px;">--</div>
                    <div class="val-sub">非重叠威胁实体数</div>
                </div>
                <div class="card">
                    <div class="val-sub" style="color: var(--success);">🎯 威胁阻断转化率</div>
                    <div class="val-big" id="akpi-banrate" style="color: var(--success); font-size: 24px;">--</div>
                    <div class="val-sub">拦截数 / 探测总数</div>
                </div>
                <div class="card">
                    <div class="val-sub" style="color: #af52de;">🌍 涉及国家/地区</div>
                    <div class="val-big" id="akpi-countries" style="color: #af52de; font-size: 24px;">--</div>
                    <div class="val-sub">跨国境威胁来源广度</div>
                </div>
                <div class="card">
                    <div class="val-sub" style="color: #ff9500;">🚦 Web 异常请求</div>
                    <div class="val-big" id="akpi-webprobes" style="color: #ff9500; font-size: 24px;">--</div>
                    <div class="val-sub">4xx/5xx 与敏感探针</div>
                </div>
            </div>

            <!-- 时间与时序多维趋势 -->
            <div class="grid-2">
                <div class="card">
                    <div class="card-header">
                        <div>
                            <div class="card-title">📈 多维安全流量时序演进趋势</div>
                            <div class="val-sub">蜜罐拦截 vs 端口探测 vs Web访问 对比</div>
                        </div>
                    </div>
                    <div style="height: 220px;"><canvas id="analyticsTrendChart"></canvas></div>
                </div>
                <div class="card">
                    <div class="card-header">
                        <div>
                            <div class="card-title">⏰ 24 小时全天候攻击活跃时段分布</div>
                            <div class="val-sub">按每日 00:00~23:00 统计攻击活跃峰值区间</div>
                        </div>
                    </div>
                    <div style="height: 220px;"><canvas id="analyticsHourlyChart"></canvas></div>
                </div>
            </div>

            <!-- 地理空间与威胁源网络构成 -->
            <div class="grid-2">
                <div class="card">
                    <div class="card-header">
                        <div>
                            <div class="card-title">🌍 攻击来源国家与地区分布</div>
                            <div class="val-sub">TOP 8 全球威胁发源地理分布</div>
                        </div>
                    </div>
                    <div style="height: 220px;"><canvas id="analyticsGeoChart"></canvas></div>
                </div>
                <div class="card">
                    <div class="card-header">
                        <div>
                            <div class="card-title">🏢 恶意扫描源网络运营商 (ISP / ASN)</div>
                            <div class="val-sub">TOP 8 频繁发起探测的云计算或电信运营商</div>
                        </div>
                    </div>
                    <div style="height: 220px;"><canvas id="analyticsIspChart"></canvas></div>
                </div>
            </div>

            <!-- 端口特征与防护动作矩阵 (Grid 3) -->
            <div class="grid-3">
                <div class="card">
                    <div class="card-header">
                        <div>
                            <div class="card-title">🔌 高危服务分类构成</div>
                            <div class="val-sub">目标服务类型占比</div>
                        </div>
                    </div>
                    <div style="height: 210px;"><canvas id="analyticsCategoryChart"></canvas></div>
                </div>
                <div class="card">
                    <div class="card-header">
                        <div>
                            <div class="card-title">🛡️ 流量处置动作分布</div>
                            <div class="val-sub">阻断 / 探测 / 业务 / 放行</div>
                        </div>
                    </div>
                    <div style="height: 210px;"><canvas id="analyticsActionChart"></canvas></div>
                </div>
                <div class="card">
                    <div class="card-header">
                        <div>
                            <div class="card-title">🏷️ 威胁危险等级分布</div>
                            <div class="val-sub">极高危 / 高危 / 中危 / 低危</div>
                        </div>
                    </div>
                    <div style="height: 210px;"><canvas id="analyticsLevelChart"></canvas></div>
                </div>
            </div>

            <!-- Web 应用与探测特征多维分析 (Grid 2) -->
            <div class="grid-2">
                <div class="card">
                    <div class="card-header">
                        <div>
                            <div class="card-title">🚦 HTTP 响应状态码与健康度</div>
                            <div class="val-sub">正常访问 (200) vs 敏感探针/异常 (4xx/5xx)</div>
                        </div>
                    </div>
                    <div style="height: 210px; position: relative;">
                        <canvas id="analyticsHttpStatusChart"></canvas>
                        <div id="analyticsHttpStatusEmpty" style="display: none; position: absolute; inset: 0; align-items: center; justify-content: center; text-align: center; color: var(--text-sec); font-size: 12px;">
                            <div>
                                <div style="font-size: 24px; margin-bottom: 6px;">🚦</div>
                                <div>暂无 HTTP 访问状态码记录</div>
                            </div>
                        </div>
                    </div>
                </div>
                <div class="card">
                    <div class="card-header">
                        <div>
                            <div class="card-title">🔍 敏感文件探针 & 扫描工具指纹</div>
                            <div class="val-sub">Web 嗅探特征排行 TOP 10</div>
                        </div>
                        <div class="segmented-control" style="padding: 2px;">
                            <button class="segment-btn active" id="btn-webdiag-path" onclick="switchWebDiagTab('path')" style="padding: 4px 10px; font-size: 11px;">📁 敏感路径</button>
                            <button class="segment-btn" id="btn-webdiag-ua" onclick="switchWebDiagTab('ua')" style="padding: 4px 10px; font-size: 11px;">🤖 扫描器 UA</button>
                        </div>
                    </div>
                    <div id="web-diag-container" style="max-height: 210px; min-height: 210px; overflow-y: auto; padding-right: 4px;">
                        正在加载特征指纹...
                    </div>
                </div>
            </div>

            <!-- TOP 10 持续活跃威胁源情报档案 -->
            <div class="card" style="margin-top: 16px;">
                <div class="card-header">
                    <div>
                        <div class="card-title">🚨 TOP 10 持续活跃恶意威胁源档案</div>
                        <div class="val-sub">最高频次探测实体、嗅探端口组合及实时封禁状态</div>
                    </div>
                </div>
                <div class="table-wrap">
                    <table>
                        <thead>
                            <tr>
                                <th>威胁源 IP (及运营商)</th>
                                <th>嗅探目标端口集</th>
                                <th>累计触碰频次</th>
                                <th>危险等级</th>
                                <th>防护状态</th>
                                <th>最后活动时间</th>
                            </tr>
                        </thead>
                        <tbody id="analytics-attackers-tbody">
                            <tr><td colspan="6" style="text-align: center; color: var(--text-sec); padding: 24px;">正在分析威胁档案...</td></tr>
                        </tbody>
                    </table>
                </div>
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
                            <th>命中诱饵端口</th>
                            <th>服务特征分类</th>
                            <th>威胁评级</th>
                            <th>防御处置</th>
                            <th>操作</th>
                        </tr>
                    </thead>
                    <tbody id="logs-tbody">
                        <tr><td colspan="7" style="text-align: center; color: var(--text-sec); padding: 30px;">正在载入审计日志...</td></tr>
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

    <!-- Page 3: 黑白名单管理 (IP Lists: Blacklist & Whitelist) -->
    <div id="tab-iplists" style="display: none;">
        <!-- 顶部子页切换分段控件 (黑名单 / 白名单) -->
        <div style="margin-bottom: 14px; display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 10px;">
            <div style="background: var(--card-sec); border: 1px solid var(--border); border-radius: 99px; padding: 2px; display: inline-flex; gap: 2px; width: fit-content; flex-shrink: 0;">
                <button class="pill-btn accent" id="subtab-btn-blacklist" onclick="switchIpListSubTab('blacklist', this)" style="padding: 4px 14px; font-size: 11px; border-radius: 99px; font-weight: 700;">🚫 内核黑名单</button>
                <button class="pill-btn" id="subtab-btn-whitelist" onclick="switchIpListSubTab('whitelist', this)" style="padding: 4px 14px; font-size: 11px; border-radius: 99px; font-weight: 700; background: transparent;">🛡️ 信任白名单</button>
            </div>
        </div>

        <!-- SubView 1: 内核黑名单 -->
        <div id="subview-blacklist">
            <div class="card">
                <div class="card-header">
                    <div>
                        <div class="card-title">🚫 内核黑名单</div>
                        <div class="val-sub">iptables DROP 与路由黑洞阻断目标</div>
                    </div>
                    <div class="header-action-wrap">
                        <!-- 统一弹出式黑名单配置卡片按钮 -->
                        <div style="position: relative; display: inline-block;">
                            <button class="pill-btn danger" id="btn-blacklist-action-menu" onclick="toggleBlacklistActionMenu(event)" style="font-weight: 700;">
                                <span>⚙️ 黑名单管理</span>
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
                                <div style="height: 1px; background: var(--border-subtle); margin: 4px 0;"></div>
                                <a href="javascript:void(0)" onclick="closeBlacklistActionMenu(); syncAllMeshState();" style="display: flex; align-items: center; gap: 8px; padding: 8px 10px; color: var(--text); text-decoration: none; border-radius: 8px; font-size: 12px; font-weight: 600;" onmouseover="this.style.background='var(--card-sec)'" onmouseout="this.style.background='transparent'">
                                    <span>📡</span><span>全网协同双向全量对齐</span>
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
                                <th>来源服务器 / 节点</th>
                                <th>拉黑原因 / 诱饵端口</th>
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
        </div>

        <!-- SubView 2: 安全信任白名单 -->
        <div id="subview-whitelist" style="display: none;">
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
                                <span>⚙️ 白名单管理</span>
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
                                <div style="height: 1px; background: var(--border-subtle); margin: 4px 0;"></div>
                                <a href="javascript:void(0)" onclick="closeWhitelistActionMenu(); syncAllWhitelistToCluster();" style="display: flex; align-items: center; gap: 8px; padding: 8px 10px; color: var(--text); text-decoration: none; border-radius: 8px; font-size: 12px; font-weight: 600;" onmouseover="this.style.background='var(--card-sec)'" onmouseout="this.style.background='transparent'">
                                    <span>📡</span><span>全网协同白名单同步</span>
                                </a>
                            </div>
                        </div>
                    </div>
                </div>

                <div class="table-wrap">
                    <table>
                        <thead>
                            <tr>
                                <th style="width: 45%;">信任 IP / 网段</th>
                                <th style="width: 40%;">备注说明</th>
                                <th style="width: 15%; text-align: right;">操作</th>
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
        </div>
        <div class="bottom-spacer"></div>
    </div>

    <!-- Page 4: 蜜罐诱饵策略 (Traps) -->
    <div id="tab-traps" style="display: none;">
        <!-- 顶部子页切换分段控件 (端口策略 / 常规业务 / 行为特征) -->
        <div style="margin-bottom: 14px; display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 10px;">
            <div style="background: var(--card-sec); border: 1px solid var(--border); border-radius: 99px; padding: 2px; display: inline-flex; gap: 2px; width: fit-content; flex-shrink: 0;">
                <button class="pill-btn accent" id="btn-trap-tab-port" onclick="switchTrapTab('port')" style="padding: 4px 14px; font-size: 11px; border-radius: 99px; font-weight: 700;">🔌 端口策略</button>
                <button class="pill-btn" id="btn-trap-tab-biz" onclick="switchTrapTab('biz')" style="padding: 4px 14px; font-size: 11px; border-radius: 99px; font-weight: 700; background: transparent;">🏢 常规业务</button>
                <button class="pill-btn" id="btn-trap-tab-req" onclick="switchTrapTab('req')" style="padding: 4px 14px; font-size: 11px; border-radius: 99px; font-weight: 700; background: transparent;">🎯 行为特征</button>
            </div>
        </div>

        <div class="card">
            <div class="card-header">
                <div>
                    <div class="card-title" id="traps-main-title">🛡️ 全局威胁防御策略中心</div>
                    <div class="val-sub" id="traps-main-sub">精准识别威胁探针，保障正常业务放行</div>
                </div>
                <div class="header-action-wrap">
                    <!-- 统一弹出式策略配置卡片按钮 -->
                    <div style="position: relative; display: inline-block;">
                        <button class="pill-btn accent" id="btn-trap-action-menu" onclick="toggleTrapActionMenu(event)" style="font-weight: 700;">
                            <span>⚙️ 策略管理操作</span>
                            <span style="font-size: 10px; margin-left: 2px;">▾</span>
                        </button>
                        <div id="trap-action-popover" style="display: none; position: absolute; right: 0; top: calc(100% + 8px); background: var(--card); border: 1px solid var(--border); border-radius: 12px; box-shadow: 0 12px 36px rgba(0,0,0,0.3); min-width: 190px; z-index: 1000; padding: 6px; backdrop-filter: blur(25px);">
                            <div id="trap-popover-content"></div>
                        </div>
                    </div>
                </div>
            </div>

            <!-- SubTab 1/2/3: 表格区域 (端口策略 / 常规业务 / 行为特征) -->
            <div id="policy-pane-table-container">
                <!-- 业务列表顶部的正常业务保护横幅 -->
                <div id="banner-biz-defense" style="display: none; margin: 14px 18px 0 18px; background: var(--card-sec); border: 1px solid var(--border); border-radius: 12px; padding: 12px 14px; justify-content: space-between; align-items: center; gap: 12px; flex-wrap: wrap;">
                    <div style="display: flex; flex-direction: column; gap: 2px;">
                        <div style="display: flex; align-items: center; gap: 6px;">
                            <span style="font-weight: 700; font-size: 12px; color: var(--text);">🏢 正常生产业务端口与服务保护清单</span>
                            <span class="tag success">🟢 100% 内核级免封放行</span>
                        </div>
                        <span style="font-size: 11px; color: var(--text-sec); line-height: 1.3;">列表中的所有端口享受内核级绝对放行豁免保护，无论是系统动态侦测到的监听服务还是用户自定义添加的业务端口，外部正常访问 100% 顺畅连通，绝不误杀。</span>
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
                <div id="traps-pagination-bar" style="display: flex; justify-content: space-between; align-items: center; padding: 14px 18px; border-top: 1px solid var(--border-subtle); flex-wrap: wrap; gap: 10px;">
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

        </div>
        <div class="bottom-spacer"></div>
    </div>

    <!-- Page 5: 系统设置 (Settings: 响应参数与审计隐藏) -->
    <div id="tab-settings" style="display: none;">
        <!-- 顶部子页切换分段控件 (响应与封禁 / 审计隐藏) -->
        <div style="margin-bottom: 14px; display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 10px;">
            <div style="background: var(--card-sec); border: 1px solid var(--border); border-radius: 99px; padding: 2px; display: inline-flex; gap: 2px; width: fit-content; flex-shrink: 0;">
                <button class="pill-btn accent" id="btn-settings-tab-response" onclick="switchSettingsSubTab('response', this)" style="padding: 4px 14px; font-size: 11px; border-radius: 99px; font-weight: 700;">⚙️ 响应与封禁参数</button>
                <button class="pill-btn" id="btn-settings-tab-hidden" onclick="switchSettingsSubTab('hidden', this)" style="padding: 4px 14px; font-size: 11px; border-radius: 99px; font-weight: 700; background: transparent;">🚫 审计隐藏过滤</button>
            </div>
        </div>

        <div class="card">
            <div class="card-header">
                <div>
                    <div class="card-title" id="settings-main-title">⚙️ 系统防御与全局设置</div>
                    <div class="val-sub" id="settings-main-sub">配置防御响应机制、判定灵敏度阈值、自动解封周期与全局审计过滤</div>
                </div>
            </div>

            <!-- SubTab 1: 响应机制与封禁参数 -->
            <div id="settings-pane-response" style="padding: 18px; display: flex; flex-direction: column; gap: 14px;">
                <!-- 0. 一键暂停 / 恢复拦截服务 -->
                <div style="background: var(--card-sec); border: 1px solid var(--border); border-radius: 12px; padding: 14px;">
                    <div style="display: flex; justify-content: space-between; align-items: center; gap: 12px; flex-wrap: wrap;">
                        <div style="display: flex; flex-direction: column; gap: 3px; flex: 1; min-width: 200px;">
                            <div style="display: flex; align-items: center; gap: 8px;">
                                <span style="font-weight: 700; font-size: 13px; color: var(--text);">⏸️ 威胁防御与自动拦截服务总开关</span>
                                <span class="tag success" id="defense-policy-status-tag">🛡️ 拦截运行中</span>
                            </div>
                            <span style="font-size: 11px; color: var(--text-sec); line-height: 1.4;">一键暂停所有蜜罐诱捕阻断与黑洞封禁，并临时释放当前所有拦截规则，方便排查运维。</span>
                        </div>
                        <button type="button" id="btn-toggle-defense-policy-pause" onclick="toggleDefenseServicePause()" class="pill-btn danger" style="padding: 7px 16px; font-weight: 700; font-size: 12px; white-space: nowrap; cursor: pointer;">
                            ⏸️ 暂停所有拦截
                        </button>
                    </div>
                </div>

                <!-- 0.5 本机服务器节点名称 / 标识 -->
                <div style="background: var(--card-sec); border: 1px solid var(--border); border-radius: 10px; padding: 14px;">
                    <div style="font-weight: 700; font-size: 13px; color: var(--text); margin-bottom: 6px;">🏷️ 本机服务器节点标识名称</div>
                    <div style="font-size: 11px; color: var(--text-sec); margin-bottom: 10px; line-height: 1.4;">
                        用于在黑名单列表与多机集群联防中标记拦截来源（例如：<code>搬瓦工生产节点</code>、<code>腾讯云韩国测试机</code>、<code>阿里云韩国生产机</code>）。
                    </div>
                    <div style="display: flex; gap: 8px; align-items: center;">
                        <input type="text" id="setting-policy-node-name" class="input-field" placeholder="例如：搬瓦工生产机" style="flex: 1; padding: 8px 10px; font-size: 12px; font-weight: 600;" onkeydown="if(event.key==='Enter') saveNodeNameOnly()">
                        <button type="button" class="pill-btn primary" onclick="saveNodeNameOnly()" style="font-size: 12px; font-weight: 700; padding: 8px 18px; white-space: nowrap; cursor: pointer;">💾 保存名称</button>
                    </div>
                </div>

                <!-- 0.8 多机集群威胁情报联防 (Mesh Sync) -->
                <div style="background: var(--card-sec); border: 1px solid var(--border); border-radius: 12px; padding: 16px;">
                    <div style="display: flex; justify-content: space-between; align-items: center; gap: 12px; flex-wrap: wrap; margin-bottom: 12px;">
                        <div style="display: flex; flex-direction: column; gap: 4px; flex: 1; min-width: 220px;">
                            <div style="display: flex; align-items: center; gap: 8px;">
                                <span style="font-weight: 700; font-size: 14px; color: var(--text);">🌐 多机集群威胁情报联防 (Mesh Sync)</span>
                                <span class="tag" id="cluster-sync-status-badge" style="background: rgba(142, 142, 147, 0.15); color: var(--text-sec); font-weight: 700;">未启用</span>
                            </div>
                            <span style="font-size: 11px; color: var(--text-sec); line-height: 1.5;">
                                采用对等网格广播拓扑：任何一台服务器捕获到黑客扫描时，瞬间向所有协同服务器广播并下发防火墙阻断！
                            </span>
                        </div>
                        <div style="display: flex; align-items: center; gap: 10px;">
                            <label style="font-size: 12px; font-weight: 700; color: var(--text); display: flex; align-items: center; gap: 6px; cursor: pointer;">
                                <input type="checkbox" id="cluster-sync-enabled-toggle" onchange="toggleClusterSyncEnabled()" style="transform: scale(1.2); cursor: pointer;">
                                <span>启用网格联防</span>
                            </label>
                        </div>
                    </div>

                    <!-- 通信端口与鉴权密钥配置栏 -->
                    <div style="background: var(--bg); border: 1px solid var(--border-subtle); border-radius: 10px; padding: 14px; margin-bottom: 14px;">
                        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); gap: 14px; margin-bottom: 12px;">
                            <div>
                                <label style="font-size: 11px; font-weight: 700; color: var(--text-sec); display: block; margin-bottom: 6px;">🔌 本机集群通信监听端口 (Cluster Listen Port)</label>
                                <input type="number" id="cluster-sync-port-input" class="input-field" placeholder="默认: 9098 (与WebUI分离)" min="1" max="65535" style="width: 100%; font-family: monospace; font-size: 12px; font-weight: 600; padding: 8px 10px;">
                                <div style="font-size: 10px; color: var(--text-sec); margin-top: 5px; line-height: 1.4;">
                                    💡 独立于 Web UI 端口（如设置为 <code>9098</code>），仅处理节点加密联防协议，彻底与管理控制台解耦，避免向外暴露 Web 登录界面。
                                </div>
                            </div>
                            <div>
                                <label style="font-size: 11px; font-weight: 700; color: var(--text-sec); display: block; margin-bottom: 6px;">🔑 集群通信鉴权密钥 (Cluster Secret Key)</label>
                                <div style="display: flex; gap: 6px;">
                                    <input type="text" id="cluster-sync-secret-input" class="input-field" placeholder="输入或生成集群通信鉴权密钥" style="flex: 1; min-width: 140px; font-family: monospace; font-size: 12px; font-weight: 600; padding: 8px 10px;">
                                    <button type="button" class="pill-btn" onclick="generateRandomClusterSecret()" style="font-size: 11px; white-space: nowrap;">🎲 随机</button>
                                    <button type="button" class="pill-btn" onclick="copyClusterSecret()" style="font-size: 11px; white-space: nowrap;">📋 复制</button>
                                </div>
                                <div style="font-size: 10px; color: var(--text-sec); margin-top: 5px; line-height: 1.4;">
                                    💡 所有协同节点必须配置完全一致的通信密钥（基于 HMAC-SHA256 签名鉴权）。
                                </div>
                            </div>
                        </div>
                        <div style="display: flex; justify-content: flex-end;">
                            <button type="button" class="pill-btn primary" onclick="saveClusterSecretOnly()" style="font-size: 11px; font-weight: 700; padding: 6px 16px;">💾 保存集群网络设置</button>
                        </div>
                    </div>

                    <!-- 节点管理栏与表格 -->
                    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px; flex-wrap: wrap; gap: 8px;">
                        <div style="font-size: 12px; font-weight: 700; color: var(--text); display: flex; align-items: center; gap: 6px;">
                            <span>📡 协同对端服务器节点列表</span>
                            <span class="tag" id="cluster-nodes-count-badge" style="font-size: 10px; font-weight: 700;">0 个节点</span>
                        </div>
                        <div style="display: flex; gap: 8px;">
                            <button type="button" class="pill-btn primary" onclick="openAddClusterNodeModal()" style="font-size: 11px; font-weight: 700; padding: 5px 12px; cursor: pointer;">
                                ➕ 添加协同节点
                            </button>
                            <button type="button" class="pill-btn" onclick="testAllClusterNodes()" id="btn-test-all-cluster-nodes" style="font-size: 11px; font-weight: 700; padding: 5px 12px; border-color: var(--accent); color: var(--accent); cursor: pointer;">
                                ⚡ 全节点连接检测
                            </button>
                        </div>
                    </div>

                    <div class="table-wrap" style="border: 1px solid var(--border-subtle); border-radius: 8px; background: var(--bg); overflow-x: auto;">
                        <table style="width: 100%; text-align: left; border-collapse: collapse;">
                            <thead>
                                <tr style="border-bottom: 1px solid var(--border-subtle); background: var(--card-sec);">
                                    <th style="padding: 10px 12px; font-size: 11px;">节点 IP / 端口</th>
                                    <th style="padding: 10px 12px; font-size: 11px;">节点备注名称</th>
                                    <th style="padding: 10px 12px; font-size: 11px;">IP 归属地</th>
                                    <th style="padding: 10px 12px; font-size: 11px;">通联状态</th>
                                    <th style="padding: 10px 12px; font-size: 11px;">添加时间</th>
                                    <th style="padding: 10px 12px; font-size: 11px; text-align: right;">管理操作</th>
                                </tr>
                            </thead>
                            <tbody id="cluster-nodes-tbody">
                                <tr><td colspan="6" style="text-align: center; color: var(--text-sec); padding: 24px;">暂未添加任何协同节点，请点击上方「➕ 添加协同节点」</td></tr>
                            </tbody>
                        </table>
                    </div>
                </div>

                <!-- 1. 扫描与探测防御开关 -->
                <div style="background: var(--card-sec); border: 1px solid var(--border); border-radius: 10px; padding: 14px;">
                    <div style="font-weight: 700; font-size: 13px; color: var(--text); margin-bottom: 6px;">🔍 恶意端口扫描与探测行为识别设置</div>
                    <div style="font-size: 11px; color: var(--text-sec); margin-bottom: 10px; line-height: 1.4;">
                        当单个外部非白名单 IP 在指定时间窗口内连续探测多个未开放端口时，自动判定为恶意扫描工具（如 Nmap/Masscan）并拉黑。
                    </div>
                    <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 10px;">
                        <div>
                            <label style="font-size: 11px; font-weight: 600; color: var(--text-sec);">多端口扫描判定阈值</label>
                            <select id="setting-policy-scan-threshold" class="input-field" style="width: 100%; margin-top: 4px; padding: 8px 10px; font-size: 12px; font-weight: 600;">
                                <option value="2">探测 ≥2 个未开放端口 (极速敏感)</option>
                                <option value="3" selected>探测 ≥3 个未开放端口 (标准推荐)</option>
                                <option value="5">探测 ≥5 个未开放端口 (宽松模式)</option>
                            </select>
                        </div>
                        <div>
                            <label style="font-size: 11px; font-weight: 600; color: var(--text-sec);">扫描统计时间窗口</label>
                            <select id="setting-policy-scan-window" class="input-field" style="width: 100%; margin-top: 4px; padding: 8px 10px; font-size: 12px; font-weight: 600;">
                                <option value="10">10 秒</option>
                                <option value="15" selected>15 秒 (标准感知)</option>
                                <option value="30">30 秒</option>
                                <option value="60">60 秒 (慢速扫描感知)</option>
                            </select>
                        </div>
                    </div>
                </div>

                <!-- 2. 封禁灵敏度与阈值 -->
                <div style="background: var(--card-sec); border: 1px solid var(--border); border-radius: 10px; padding: 14px;">
                    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
                        <span style="font-weight: 700; font-size: 13px; color: var(--text);">🎯 诱捕探测判定与自动拉黑灵敏度</span>
                        <span class="badge badge-high" id="badge-policy-threshold-status">主动严防</span>
                    </div>
                    <div style="font-size: 11px; color: var(--text-sec); margin-bottom: 10px; line-height: 1.4;">
                        外部 IP 触碰高危蜜罐端口或触发 Web 规则时的频控判定阈值。
                    </div>
                    <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 10px;">
                        <div>
                            <label style="font-size: 11px; font-weight: 600; color: var(--text-sec);">触发封禁探测次数</label>
                            <select id="setting-policy-trap-threshold" class="input-field" style="width: 100%; margin-top: 4px; padding: 8px 10px; font-size: 12px; font-weight: 600;">
                                <option value="1">1 次 (零容忍立即封禁)</option>
                                <option value="2" selected>2 次 (严苛防御)</option>
                                <option value="3">3 次 (标准防误触)</option>
                                <option value="5">5 次 (宽松模式)</option>
                            </select>
                        </div>
                        <div>
                            <label style="font-size: 11px; font-weight: 600; color: var(--text-sec);">统计判定时间窗口</label>
                            <select id="setting-policy-trap-window" class="input-field" style="width: 100%; margin-top: 4px; padding: 8px 10px; font-size: 12px; font-weight: 600;">
                                <option value="15">15 秒</option>
                                <option value="30" selected>30 秒 (标准默认)</option>
                                <option value="60">60 秒 (长窗口感知)</option>
                                <option value="300">300 秒 (5分钟慢速感知)</option>
                            </select>
                        </div>
                    </div>
                </div>

                <!-- 3. 封禁时长与自动解封周期 -->
                <div style="background: var(--card-sec); border: 1px solid var(--border); border-radius: 10px; padding: 14px;">
                    <div style="font-weight: 700; font-size: 13px; color: var(--text); margin-bottom: 6px;">⏳ 黑名单封禁周期与自动解封</div>
                    <div style="font-size: 11px; color: var(--text-sec); margin-bottom: 10px; line-height: 1.4;">
                        被拉黑攻击 IP 的持续阻断天数。设为永久封禁时永不自动解封。
                    </div>
                    <div>
                        <label style="font-size: 11px; font-weight: 600; color: var(--text-sec);">自动解封周期</label>
                        <select id="setting-policy-auto-clean" class="input-field" style="width: 100%; margin-top: 4px; padding: 8px 10px; font-size: 12px; font-weight: 600;">
                            <option value="7">7 天 (临时阻断)</option>
                            <option value="30" selected>30 天 (标准推荐)</option>
                            <option value="90">90 天 (长期封锁)</option>
                            <option value="180">180 天 (半年封锁)</option>
                            <option value="0">永久封禁 (永不自动解封)</option>
                        </select>
                    </div>
                </div>

                <!-- 4. 内核阻断机制 -->
                <div style="background: var(--card-sec); border: 1px solid var(--border); border-radius: 10px; padding: 14px;">
                    <div style="font-weight: 700; font-size: 13px; color: var(--text); margin-bottom: 6px;">🛡️ Linux 内核底层阻断联动方式</div>
                    <div style="display: flex; flex-direction: column; gap: 8px;">
                        <label style="display: flex; align-items: center; gap: 8px; font-size: 12px; color: var(--text); cursor: pointer;">
                            <input type="checkbox" id="setting-policy-ban-iptables" checked style="width: 16px; height: 16px; accent-color: var(--accent);">
                            <span><b>iptables DROP 规则阻断</b>（在系统 INPUT 链顶层直接丢弃恶意数据包）</span>
                        </label>
                        <label style="display: flex; align-items: center; gap: 8px; font-size: 12px; color: var(--text); cursor: pointer;">
                            <input type="checkbox" id="setting-policy-ban-blackhole" checked style="width: 16px; height: 16px; accent-color: var(--accent);">
                            <span><b>Linux 内核路由黑洞 (blackhole)</b>（在路由选路阶段直接丢弃）</span>
                        </label>
                    </div>
                </div>

                <div style="display: flex; justify-content: flex-end; gap: 10px; margin-top: 8px;">
                    <button class="pill-btn accent" onclick="saveIntegratedPolicySettings()" style="padding: 10px 24px; font-weight: 700; font-size: 13px;">💾 保存全局设置</button>
                </div>
            </div>

            <!-- SubTab 2: IP 隐藏过滤规则 (集成隐藏列表) -->
            <div id="settings-pane-hidden" style="display: none; padding: 18px; flex-direction: column; gap: 14px;">
                <div style="background: var(--card-sec); border: 1px solid var(--border); border-radius: 10px; padding: 14px;">
                    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px; flex-wrap: wrap; gap: 8px;">
                        <div style="display: flex; align-items: center; gap: 8px;">
                            <span style="font-weight: 700; font-size: 13px; color: var(--text);">🚫 全局 IP 隐藏过滤规则</span>
                            <span style="font-size: 11px; color: var(--text-sec);">生效: 态势大盘 / 拦截日志 / 访问审计</span>
                        </div>
                        <div style="display: flex; gap: 6px; align-items: center;">
                            <button type="button" class="pill-btn" onclick="openImportModal('hidden_ips')" style="padding: 4px 10px; font-size: 11px; font-weight: 600;">📥 导入隐藏列表</button>
                            <button type="button" class="pill-btn" onclick="exportHiddenIPsJSON()" style="padding: 4px 10px; font-size: 11px; font-weight: 600;">📤 导出隐藏列表</button>
                        </div>
                    </div>
                    <div style="font-size: 11px; color: var(--text-sec); margin-bottom: 12px; line-height: 1.4;">
                        被加入隐藏列表的 IP 将在全站控制台中彻底隐藏其所有日志记录与统计数据，不影响系统底层的正常防御与拦截。
                    </div>
                    <div style="display: flex; gap: 8px; align-items: center;">
                        <input type="text" id="input-policy-hidden-ip" class="input-field" placeholder="输入需隐藏的 IP 地址 (如 1.2.3.4)" style="flex: 1; padding: 8px 12px; font-size: 12px; font-family: monospace;">
                        <button class="pill-btn accent" onclick="addCustomHiddenIPFromPolicy()" style="padding: 8px 16px; font-size: 12px; font-weight: 700; white-space: nowrap;">+ 添加隐藏</button>
                    </div>
                </div>

                <!-- 隐藏 IP 表格 -->
                <div style="background: var(--card-sec); border: 1px solid var(--border); border-radius: 10px; overflow: hidden;">
                    <div style="display: flex; justify-content: space-between; align-items: center; padding: 10px 14px; border-bottom: 1px solid var(--border-subtle); background: var(--card);">
                        <span style="font-size: 12px; font-weight: 700; color: var(--text);">已隐藏 IP 名单 (<span id="hidden-ips-policy-count">0</span>)</span>
                        <button class="pill-btn danger" onclick="clearAllHiddenIPs()" style="padding: 3px 8px; font-size: 11px;">🗑️ 清空全部隐藏</button>
                    </div>
                    <div style="max-height: 280px; overflow-y: auto;">
                        <table style="width: 100%; border-collapse: collapse; font-size: 12px; text-align: left;">
                            <thead>
                                <tr style="border-bottom: 1px solid var(--border-subtle); color: var(--text-sec); font-size: 11px; background: var(--card-sec);">
                                    <th style="padding: 8px 12px;">IP 地址 / 归属</th>
                                    <th style="padding: 8px 12px;">隐藏时间</th>
                                    <th style="padding: 8px 12px; text-align: right;">操作</th>
                                </tr>
                            </thead>
                            <tbody id="hidden-ips-policy-tbody">
                                <!-- JS 动态渲染 -->
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>

        </div>
        <div class="bottom-spacer"></div>
    </div>



    <!-- Page 6: 访问日志 (Access Logs) -->
    <div id="tab-access-logs" style="display: none;">
        <!-- 顶部子页切换分段控件 (端口访问 / Web 访问) -->
        <div style="margin-bottom: 14px; display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 10px;">
            <div style="background: var(--card-sec); border: 1px solid var(--border); border-radius: 99px; padding: 2px; display: inline-flex; gap: 2px; width: fit-content; flex-shrink: 0;">
                <button class="pill-btn accent" id="btn-access-mode-port" onclick="switchAccessLogMode('port')" style="padding: 4px 14px; font-size: 11px; border-radius: 99px; font-weight: 700;">🍯 端口访问日志</button>
                <button class="pill-btn" id="btn-access-mode-web" onclick="switchAccessLogMode('web')" style="padding: 4px 14px; font-size: 11px; border-radius: 99px; font-weight: 700; background: transparent;">🌍 443/Web 访问日志</button>
            </div>
        </div>

        <div class="card">
            <div class="card-header">
                <div>
                    <div class="card-title" id="access-logs-title">🍯 端口访问日志</div>
                    <div class="val-sub" id="access-logs-sub">实时记录所有外部客户端对本机各诱捕端口与网络端口的连接嗅探</div>
                </div>
                <div class="header-action-wrap">
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
                            <th>目标端口</th>
                            <th>服务说明</th>
                            <th>防御处置</th>
                        </tr>
                    </thead>
                    <tbody id="access-logs-tbody">
                        <tr><td colspan="5" style="text-align: center; color: var(--text-sec); padding: 30px;">正在载入访问日志...</td></tr>
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

<!-- Floating Glass Dock (悬浮底部导航栏) -->
<div class="dock">
    <button class="dock-btn active" id="dock-btn-overview" onclick="switchTab('overview', this)">
        <svg viewBox="0 0 24 24"><path d="M3 13h8V3H3v10zm0 8h8v-6H3v6zm10 0h8V11h-8v10zm0-18v6h8V3h-8z"/></svg>
        <span>态势分析</span>
    </button>
    <button class="dock-btn" id="dock-btn-logs" onclick="switchTab('logs', this)">
        <svg viewBox="0 0 24 24"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm1 15h-2v-2h2v2zm0-4h-2V7h2v6z"/></svg>
        <span>拦截日志</span>
    </button>
    <button class="dock-btn" id="dock-btn-access-logs" onclick="switchTab('access-logs', this)">
        <svg viewBox="0 0 24 24"><path d="M19 3H5c-1.1 0-2 .9-2 2v14c0 1.1.9 2 2 2h14c1.1 0 2-.9 2-2V5c0-1.1-.9-2-2-2zm-5 14H7v-2h7v2zm3-4H7v-2h10v2zm0-4H7V7h10v2z"/></svg>
        <span>访问日志</span>
    </button>
    <button class="dock-btn" id="dock-btn-iplists" onclick="switchTab('iplists', this)">
        <svg viewBox="0 0 24 24"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zM4 12c0-4.42 3.58-8 8-8 1.85 0 3.55.63 4.9 1.69L5.69 16.9C4.63 15.55 4 13.85 4 12zm8 8c-1.85 0-3.55-.63-4.9-1.69L18.31 7.1c1.06 1.35 1.69 3.05 1.69 4.9 0 4.42-3.58 8-8 8z"/></svg>
        <span>黑白名单</span>
    </button>
    <button class="dock-btn" id="dock-btn-traps" onclick="switchTab('traps', this)">
        <svg viewBox="0 0 24 24"><path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4zm0 10.99h7c-.53 4.12-3.28 7.79-7 8.94V12H5V6.3l7-3.11v8.8z"/></svg>
        <span>防御策略</span>
    </button>
    <button class="dock-btn" id="dock-btn-settings" onclick="switchTab('settings', this)">
        <svg viewBox="0 0 24 24"><path d="M19.14 12.94c.04-.3.06-.61.06-.94 0-.32-.02-.64-.07-.94l2.03-1.58c.18-.14.23-.41.12-.61l-1.92-3.32c-.12-.22-.37-.29-.59-.22l-2.39.96c-.5-.38-1.03-.7-1.62-.94l-.36-2.54c-.04-.24-.24-.41-.48-.41h-3.84c-.24 0-.43.17-.47.41l-.36 2.54c-.59.24-1.13.57-1.62.94l-2.39-.96c-.22-.08-.47 0-.59.22L2.74 8.87c-.12.21-.08.47.12.61l2.03 1.58c-.05.3-.09.63-.09.94s.02.64.07.94l-2.03 1.58c-.18.14-.23.41-.12.61l1.92 3.32c.12.22.37.29.59.22l2.39-.96c.5.38 1.03.7 1.62.94l.36 2.54c.05.24.24.41.48.41h3.84c.24 0 .44-.17.47-.41l.36-2.54c.59-.24 1.13-.56 1.62-.94l2.39.96c.22.08.47 0 .59-.22l1.92-3.32c.12-.22.07-.47-.12-.61l-2.01-1.58zM12 15.6c-1.98 0-3.6-1.62-3.6-3.6s1.62-3.6 3.6-3.6 3.6 1.62 3.6 3.6-1.62 3.6-3.6 3.6z"/></svg>
        <span>系统设置</span>
    </button>
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

<!-- Modal: 添加/编辑正常业务端口 -->
<div class="modal-overlay" id="modal-biz-port">
    <div class="modal-sheet" style="max-width: 500px;">
        <h3 style="font-size: 16px; font-weight: 700; margin-bottom: 14px;" id="modal-biz-title">🏢 添加正常业务端口</h3>
        <input type="hidden" id="biz-port-orig-val">
        <div class="form-group">
            <label class="form-label">业务端口号 (1-65535)</label>
            <input type="number" class="form-control" id="biz-port-val" placeholder="例如：8080 或 3000" min="1" max="65535">
        </div>
        <div class="form-group">
            <label class="form-label">业务服务名称 / 描述</label>
            <input type="text" class="form-control" id="biz-name-val" placeholder="例如：Keycloak 认证服务 / 商城后端 API">
        </div>
        <div class="form-group">
            <label class="form-label">业务分类类型</label>
            <select class="form-control" id="biz-cat-val">
                <option value="web" selected>Web 网站 / API 接口</option>
                <option value="db">数据库 / 存储服务</option>
                <option value="ssh">远程运维 / SSH</option>
                <option value="custom">自定义业务系统</option>
            </select>
        </div>
        <div class="form-group">
            <label class="form-label">备注说明</label>
            <input type="text" class="form-control" id="biz-remark-val" placeholder="例如：生产核心业务，绝对免封">
        </div>
        <div class="form-group" style="background: var(--card-sec); border: 1px solid var(--border); border-radius: 10px; padding: 12px; margin-top: 6px;">
            <label class="form-label" style="font-weight: 700; margin-bottom: 8px; color: var(--accent);">🛡️ 业务端口安全防护选项</label>
            <div style="display: flex; flex-direction: column; gap: 8px;">
                <label style="display: flex; align-items: center; gap: 8px; font-size: 13px; cursor: pointer;">
                    <input type="checkbox" id="biz-block-scanner-val" checked style="width: 16px; height: 16px; accent-color: var(--accent);">
                    <span><strong>🌐 拦截全网测绘引擎</strong> <span style="color: var(--text-sec); font-size: 11px;">(Censys/Shodan/Onyphe等探针直接拉黑，推荐)</span></span>
                </label>
                <label style="display: flex; align-items: center; gap: 8px; font-size: 13px; cursor: pointer;">
                    <input type="checkbox" id="biz-block-idc-val" style="width: 16px; height: 16px; accent-color: var(--accent);">
                    <span><strong>🛡️ 阻断云厂商/IDC机房探针</strong> <span style="color: var(--text-sec); font-size: 11px;">(仅允许民用宽带与移动网络，秒封机房肉鸡)</span></span>
                </label>
            </div>
        </div>
        <div style="display: flex; justify-content: flex-end; gap: 8px; margin-top: 18px;">
            <button class="pill-btn" onclick="closeModals()">取消</button>
            <button class="pill-btn accent" onclick="submitBizPortForm()">保存业务端口</button>
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
                <option value="survey_engine">网络空间测绘引擎 (Censys/Shodan/Onyphe)</option>
                <option value="direct_ip">禁止纯 IP 直连 Web 探测</option>
                <option value="status_rate">HTTP 响应状态码诱捕 / 频次熔断 (支持 302/404/500 等任意状态码)</option>
            </select>
        </div>
        <div class="form-group" id="http-trap-pattern-group">
            <label class="form-label" id="http-trap-pattern-label">特征规则表达式 (支持 | 分隔多个词或正则)</label>
            <input type="text" class="form-control" id="http-trap-pattern-val" placeholder="例如：\.env|\.git|config\.json">
        </div>
        <div class="form-group" id="http-trap-rate-group" style="display: none;">
            <div style="display: flex; gap: 12px;">
                <div style="flex: 1;">
                    <label class="form-label">统计时间窗口 (秒)</label>
                    <input type="number" class="form-control" id="http-trap-window-val" value="30" min="1" max="3600">
                </div>
                <div style="flex: 1;">
                    <label class="form-label">触发阈值 (设为 1 即刻秒封)</label>
                    <input type="number" class="form-control" id="http-trap-threshold-val" value="6" min="1" max="1000">
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
                <option value="survey_engine">网络空间测绘引擎 (Censys/Shodan/Onyphe)</option>
                <option value="direct_ip">禁止纯 IP 直连 Web 探测</option>
                <option value="status_rate">HTTP 响应状态码诱捕 / 频次熔断 (支持 302/404/500 等任意状态码)</option>
            </select>
        </div>
        <div class="form-group" id="edit-http-trap-pattern-group">
            <label class="form-label" id="edit-http-trap-pattern-label">特征规则表达式 (支持 | 分隔多个词或正则)</label>
            <input type="text" class="form-control" id="edit-http-trap-pattern-val">
        </div>
        <div class="form-group" id="edit-http-trap-rate-group" style="display: none;">
            <div style="display: flex; gap: 12px;">
                <div style="flex: 1;">
                    <label class="form-label">统计时间窗口 (秒)</label>
                    <input type="number" class="form-control" id="edit-http-trap-window-val" min="1" max="3600">
                </div>
                <div style="flex: 1;">
                    <label class="form-label">触发阈值 (设为 1 即刻秒封)</label>
                    <input type="number" class="form-control" id="edit-http-trap-threshold-val" min="1" max="1000">
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
            <button class="pill-btn" onclick="toggleCurrentDetailIPHide()" id="btn-ip-detail-hide" style="color: var(--warning); border-color: rgba(255, 149, 0, 0.4);" title="在全站控制台中全局隐藏此 IP 的所有日志记录与态势统计">🙈 隐藏此 IP 日志</button>
        </div>
    </div>
</div>

<!-- Modal: 单个添加协同服务器节点 -->
<div class="modal-overlay" id="modal-add-cluster-node">
    <div class="modal-sheet" style="max-width: 500px;">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 14px;">
            <h3 style="font-size: 15px; font-weight: 700; display: flex; align-items: center; gap: 8px;">
                <span>➕ 添加协同服务器节点</span>
            </h3>
            <button onclick="closeModals()" style="background:none; border:none; color:var(--text-sec); font-size:18px; cursor:pointer; padding: 4px 8px;">✕</button>
        </div>

        <div style="background: var(--card-sec); border-radius: 8px; padding: 10px 12px; font-size: 11px; color: var(--text-sec); margin-bottom: 14px; border: 1px solid var(--border-subtle); line-height: 1.4;">
            💡 只需要输入目标服务器的 IP 地址或域名，保存后系统将自动进行 IP 归属地识别与网络健康握手。
        </div>

        <div class="form-group">
            <label class="form-label" style="font-weight: 700;">服务器 IP 地址 或 域名 <span style="color: var(--danger);">*</span></label>
            <input type="text" id="cluster-node-add-ip" class="form-control" placeholder="输入服务器 IP (例如: 198.51.100.20) 或域名" style="font-family: monospace; font-size: 12px; font-weight: 600;">
        </div>

        <div class="form-group">
            <label class="form-label" style="font-weight: 700;">Web 控制台端口</label>
            <input type="number" id="cluster-node-add-port" class="form-control" value="9099" placeholder="9099" style="font-size: 12px;">
        </div>

        <div class="form-group">
            <label class="form-label" style="font-weight: 700;">节点备注名称</label>
            <input type="text" id="cluster-node-add-remark" class="form-control" placeholder="例如：腾讯云韩国测试机 或 阿里云生产节点" style="font-size: 12px; font-weight: 600;">
        </div>

        <div style="display: flex; justify-content: flex-end; gap: 8px; margin-top: 20px;">
            <button class="pill-btn" onclick="closeModals()">取消</button>
            <button class="pill-btn primary" onclick="submitAddClusterNode()" id="btn-submit-add-cluster-node">➕ 确认添加并检测</button>
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

    function getUATagInfo(ua) {
        if (!ua || ua === '-' || ua === 'null' || ua === 'None' || ua === 'undefined' || ua === 'Unknown') {
            return { tag: '未知指纹', cls: 'neutral', icon: '❓' };
        }
        const lower = ua.toLowerCase();
        if (/sqlmap|nmap|nikto|nuclei|fscan|acunetix|awvs|nessus|dirsearch|gobuster|ffuf|hydra|wpscan/.test(lower)) {
            return { tag: '漏洞扫描器', cls: 'danger', icon: '🔥' };
        }
        if (/censys|shodan|zoomeye|zgrab|masscan|netcraft|infrawatch|whatweb|httpx|probe|scan/.test(lower)) {
            return { tag: '资产测绘', cls: 'danger', icon: '📡' };
        }
        if (/libredtail|xmr|miner/.test(lower)) {
            return { tag: '恶意脚本', cls: 'danger', icon: '☠️' };
        }
        if (/python|requests|urllib|aiohttp|go-http|curl|wget|java|httpclient|axios/.test(lower)) {
            return { tag: '脚本工具', cls: 'accent', icon: '⚡' };
        }
        if (/gptbot|oai-searchbot|bytespider|googlebot|bingbot|baiduspider|yandex|bot|crawler|spider/.test(lower)) {
            return { tag: '网络爬虫', cls: 'accent', icon: '🕷️' };
        }
        if (/iphone|ipad|android|mobile/.test(lower)) {
            return { tag: '移动端', cls: 'neutral', icon: '📱' };
        }
        if (/macintosh|windows nt|linux|x11|chrome|safari|firefox|edge/.test(lower)) {
            return { tag: '桌面端', cls: 'neutral', icon: '💻' };
        }
        return { tag: '自定义UA', cls: 'neutral', icon: '🤖' };
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
        let isp = item.isp || '';
        let parts = [];
        if (country && country !== '未知地域') parts.push(country);
        if (region && !country.includes(region)) parts.push(region);
        if (isp && isp !== '0' && !country.includes(isp) && !region.includes(isp)) parts.push(isp);
        if (parts.length === 0) return '🌐 公网节点';
        return '🌐 ' + parts.join(' · ');
    }

    function formatTwoLineTime(timeStr) {
        if (!timeStr || timeStr === '--' || timeStr === '-') {
            return '<span style="color: var(--text-sec); font-size: 12px;">--</span>';
        }
        const str = String(timeStr).trim();
        const parts = str.split(/\s+/);
        if (parts.length >= 2) {
            return `
                <div style="line-height: 1.25; display: inline-flex; flex-direction: column; vertical-align: middle;">
                    <span style="font-size: 12px; font-variant-numeric: tabular-nums; font-weight: 600; color: var(--text);">${escapeHtml(parts[0])}</span>
                    <span style="font-size: 11px; font-variant-numeric: tabular-nums; color: var(--text-sec); margin-top: 2px;">${escapeHtml(parts.slice(1).join(' '))}</span>
                </div>
            `;
        }
        return `<span style="font-size: 12px; font-variant-numeric: tabular-nums; color: var(--text-sec);">${escapeHtml(str)}</span>`;
    }

    let allEvents = [];
    let allPortLogs = [];
    let allWebLogs = [];
    let currentAccessLogMode = 'port';
    let allBlacklist = [];
    let allWhitelist = [];
    let allHiddenIPs = [];
    let allTraps = [];
    let currentTrapTab = 'port';
    let allBusinessPorts = [];
    let bizPortsPage = 1;
    let allHttpTraps = [];
    let httpTrapsPage = 1;
    let currentCategory = 'all';
    let trendChartInstance = null;
    let portChartInstance = null;

    let currentOverviewSubTab = 'overview';
    let currentAnalyticsRange = '7d';
    let currentWebDiagTab = 'path';
    let analyticsDataCache = null;

    let analyticsTrendChartInstance = null;
    let analyticsHourlyChartInstance = null;
    let analyticsGeoChartInstance = null;
    let analyticsIspChartInstance = null;
    let analyticsCategoryChartInstance = null;
    let analyticsActionChartInstance = null;
    let analyticsLevelChartInstance = null;
    let analyticsHttpStatusChartInstance = null;

    const PAGE_TITLES = {
        'overview': '安全态势分析',
        'logs': '蜜罐拦截日志',
        'access-logs': '端口与控制台访问日志',
        'iplists': '黑白名单管理',
        'blacklist': '黑白名单管理',
        'whitelist': '黑白名单管理',
        'traps': '全局防御策略中心',
        'settings': '系统防御与全局设置'
    };

    const CATEGORY_LABELS = {
        'smb': '共享嗅探',
        'rdp': '远程桌面',
        'db': '数据库探针',
        'web': '管理控制台',
        'ftp': 'FTP 嗅探',
        'telnet': 'Telnet 弱口令',
        'scan': '未开放端口探测',
        'business': '生产业务端口',
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

    // 纯净图表调色板与不可变色彩引擎 (采用 Chart.js 原生 Scriptable Options 函数式驱动，从物理上杜绝任何颜色污染与状态滞留)
    const PALETTE_GLOBAL = ['#007aff', '#ff3b30', '#ff9500', '#34c759', '#af52de', '#5856d6', '#30b0c7', '#8e8e93', '#ffd60a', '#ff2d55'];

    function setChartAlpha(colorStr, alpha) {
        if (!colorStr) return `rgba(142, 142, 147, ${alpha})`;
        if (colorStr.startsWith('#')) {
            let c = colorStr.substring(1);
            if (c.length === 3) c = c.split('').map(x => x + x).join('');
            const num = parseInt(c, 16);
            return `rgba(${(num >> 16) & 255}, ${(num >> 8) & 255}, ${num & 255}, ${alpha})`;
        }
        if (colorStr.startsWith('rgba')) {
            return colorStr.replace(/[\d\.]+\)$/g, `${alpha})`);
        }
        if (colorStr.startsWith('rgb')) {
            return colorStr.replace('rgb', 'rgba').replace(')', `, ${alpha})`);
        }
        return colorStr;
    }

    function getPureColor(palette, index) {
        return palette[index % palette.length];
    }

    // 环形图 (Doughnut) 分类点击与图例联动聚焦动效 (函数式驱动)
    function applyDoughnutInteractive(chart, customPalette) {
        if (!chart) return;
        const palette = customPalette || PALETTE_GLOBAL;
        chart._selectedCategoryIndex = -1;
        chart._defaultPalette = palette;

        const dataset = chart.data.datasets[0];
        if (dataset) {
            // 采用函数式 backgroundColor 与 offset，每次渲染自动按 _selectedCategoryIndex 取值，绝不修改数据源
            dataset.backgroundColor = function(context) {
                const idx = context.dataIndex;
                const baseColor = getPureColor(palette, idx);
                if (chart._selectedCategoryIndex === -1 || chart._selectedCategoryIndex === undefined) {
                    return baseColor;
                }
                return (chart._selectedCategoryIndex === idx) ? baseColor : setChartAlpha(baseColor, 0.22);
            };

            dataset.offset = function(context) {
                const idx = context.dataIndex;
                return (chart._selectedCategoryIndex === idx) ? 16 : 0;
            };
        }

        chart.resetCategoryFocus = function() {
            chart._selectedCategoryIndex = -1;
            chart.update();
        };

        function toggleCategory(targetIdx) {
            const count = chart.data.datasets[0]?.data?.length || 0;
            if (count === 0) return;

            if (targetIdx >= 0 && targetIdx < count) {
                if (chart._selectedCategoryIndex === targetIdx) {
                    chart._selectedCategoryIndex = -1;
                } else {
                    chart._selectedCategoryIndex = targetIdx;
                }
            } else {
                chart._selectedCategoryIndex = -1;
            }
            chart.update();
        }

        const canvas = chart.canvas;
        if (canvas) {
            canvas.onclick = (e) => {
                const elements = chart.getElementsAtEventForMode(e, 'nearest', { intersect: true }, false);
                if (elements && elements.length > 0) {
                    toggleCategory(elements[0].index);
                } else {
                    chart.resetCategoryFocus();
                }
            };
        }

        if (chart.options.plugins && chart.options.plugins.legend) {
            chart.options.plugins.legend.onClick = (evt, legendItem) => {
                if (legendItem && legendItem.index !== undefined) {
                    toggleCategory(legendItem.index);
                }
            };
        }
    }

    // 柱状图 / 条形图 (Bar) 分类点击聚焦动效 (函数式驱动)
    function applyBarInteractive(chart, defaultColorOrPalette) {
        if (!chart) return;
        chart._selectedCategoryIndex = -1;
        chart._defaultBarPalette = defaultColorOrPalette;

        const dataset = chart.data.datasets[0];
        if (dataset) {
            dataset.backgroundColor = function(context) {
                const idx = context.dataIndex;
                let baseColor;
                if (Array.isArray(defaultColorOrPalette)) {
                    baseColor = getPureColor(defaultColorOrPalette, idx);
                } else {
                    baseColor = defaultColorOrPalette || '#007aff';
                }
                if (chart._selectedCategoryIndex === -1 || chart._selectedCategoryIndex === undefined) {
                    return baseColor;
                }
                return (chart._selectedCategoryIndex === idx) ? baseColor : setChartAlpha(baseColor, 0.18);
            };
        }

        chart.resetCategoryFocus = function() {
            chart._selectedCategoryIndex = -1;
            chart.update();
        };

        function toggleBarCategory(targetIdx) {
            const count = chart.data.datasets[0]?.data?.length || 0;
            if (count === 0) return;

            if (targetIdx >= 0 && targetIdx < count) {
                if (chart._selectedCategoryIndex === targetIdx) {
                    chart._selectedCategoryIndex = -1;
                } else {
                    chart._selectedCategoryIndex = targetIdx;
                }
            } else {
                chart._selectedCategoryIndex = -1;
            }
            chart.update();
        }

        const canvas = chart.canvas;
        if (canvas) {
            canvas.onclick = (e) => {
                const elements = chart.getElementsAtEventForMode(e, 'nearest', { intersect: true }, false);
                if (elements && elements.length > 0) {
                    toggleBarCategory(elements[0].index);
                } else {
                    chart.resetCategoryFocus();
                }
            };
        }
    }

    // 多数据集折线图 (Multi-Line) 分类曲线点击聚焦动效
    function applyMultiLineInteractive(chart, defaultLineConfigs) {
        if (!chart) return;
        chart._selectedDatasetIndex = -1;
        chart._defaultLineConfigs = defaultLineConfigs;

        function refreshLines() {
            if (!chart.data.datasets) return;
            chart.data.datasets.forEach((ds, i) => {
                const cfg = defaultLineConfigs[i] || {};
                if (chart._selectedDatasetIndex === -1) {
                    ds.borderColor = cfg.borderColor;
                    ds.backgroundColor = cfg.backgroundColor;
                    ds.borderWidth = cfg.borderWidth;
                    ds.pointRadius = cfg.pointRadius;
                } else if (chart._selectedDatasetIndex === i) {
                    ds.borderColor = cfg.borderColor;
                    ds.backgroundColor = cfg.backgroundColor;
                    ds.borderWidth = 3.6;
                    ds.pointRadius = 4;
                } else {
                    ds.borderColor = setChartAlpha(cfg.borderColor || '#999', 0.15);
                    ds.backgroundColor = 'transparent';
                    ds.borderWidth = 1.2;
                    ds.pointRadius = 0;
                }
            });
            chart.update();
        }

        chart.resetCategoryFocus = function() {
            chart._selectedDatasetIndex = -1;
            refreshLines();
        };

        function toggleLineCategory(targetDsIdx) {
            const count = chart.data.datasets?.length || 0;
            if (count === 0) return;

            if (targetDsIdx >= 0 && targetDsIdx < count) {
                if (chart._selectedDatasetIndex === targetDsIdx) {
                    chart._selectedDatasetIndex = -1;
                } else {
                    chart._selectedDatasetIndex = targetDsIdx;
                }
            } else {
                chart._selectedDatasetIndex = -1;
            }
            refreshLines();
        }

        const canvas = chart.canvas;
        if (canvas) {
            canvas.onclick = (e) => {
                const elements = chart.getElementsAtEventForMode(e, 'nearest', { intersect: true }, false);
                if (elements && elements.length > 0) {
                    toggleLineCategory(elements[0].datasetIndex);
                } else {
                    chart.resetCategoryFocus();
                }
            };
        }

        if (chart.options.plugins && chart.options.plugins.legend) {
            chart.options.plugins.legend.onClick = (evt, legendItem) => {
                if (legendItem && legendItem.datasetIndex !== undefined) {
                    toggleLineCategory(legendItem.datasetIndex);
                }
            };
        }
    }

    // 单线时序图 (Single-Line) 点位点击放大动效 (函数式驱动)
    function applySingleLineInteractive(chart) {
        if (!chart) return;
        chart._selectedPointIndex = -1;

        const dataset = chart.data.datasets[0];
        if (dataset) {
            dataset.pointRadius = function(context) {
                const idx = context.dataIndex;
                return (chart._selectedPointIndex === idx) ? 6 : 2.5;
            };
        }

        chart.resetCategoryFocus = function() {
            chart._selectedPointIndex = -1;
            chart.update();
        };

        const canvas = chart.canvas;
        if (canvas) {
            canvas.onclick = (e) => {
                const elements = chart.getElementsAtEventForMode(e, 'nearest', { intersect: true }, false);
                if (elements && elements.length > 0) {
                    const clickedIdx = elements[0].index;
                    if (chart._selectedPointIndex === clickedIdx) {
                        chart._selectedPointIndex = -1;
                    } else {
                        chart._selectedPointIndex = clickedIdx;
                    }
                } else {
                    chart._selectedPointIndex = -1;
                }
                chart.update();
            };
        }
    }

    function initCharts() {
        const isDark = document.documentElement.getAttribute('data-theme') !== 'light';
        const gridColor = isDark ? 'rgba(255,255,255,0.06)' : 'rgba(0,0,0,0.06)';
        const textColor = isDark ? '#98989d' : '#8e8e93';

        const ctxTrend = document.getElementById('trendChart')?.getContext('2d');
        if (ctxTrend) {
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
            applySingleLineInteractive(trendChartInstance);
        }

        const ctxPort = document.getElementById('portChart')?.getContext('2d');
        if (ctxPort) {
            const portPalette = ['#007aff', '#ff3b30', '#ff9500', '#34c759', '#af52de', '#5856d6'];
            portChartInstance = new Chart(ctxPort, {
                type: 'doughnut',
                data: {
                    labels: ['暂无数据'],
                    datasets: [{
                        data: [1],
                        backgroundColor: portPalette,
                        borderWidth: 0
                    }]
                },
                options: {
                    responsive: true, maintainAspectRatio: false,
                    plugins: { legend: { position: 'right', labels: { color: textColor, font: { size: 11, weight: 600 } } } }
                }
            });
            applyDoughnutInteractive(portChartInstance, portPalette);
        }
    }

    function initAnalyticsCharts() {
        const isDark = document.documentElement.getAttribute('data-theme') !== 'light';
        const gridColor = isDark ? 'rgba(255,255,255,0.06)' : 'rgba(0,0,0,0.06)';
        const textColor = isDark ? '#98989d' : '#8e8e93';

        destroyAnalyticsCharts();

        const ctxTrend = document.getElementById('analyticsTrendChart')?.getContext('2d');
        if (ctxTrend) {
            const trendConfigs = [
                { borderColor: '#007aff', backgroundColor: 'rgba(0, 122, 255, 0.12)', borderWidth: 2.2, pointRadius: 2 },
                { borderColor: '#af52de', backgroundColor: 'rgba(175, 82, 222, 0.08)', borderWidth: 2.2, pointRadius: 2 },
                { borderColor: '#ff9500', backgroundColor: 'rgba(255, 149, 0, 0.06)', borderWidth: 2.2, pointRadius: 2 }
            ];
            analyticsTrendChartInstance = new Chart(ctxTrend, {
                type: 'line',
                data: {
                    labels: [],
                    datasets: [
                        { label: '蜜罐拦截', data: [], ...trendConfigs[0], fill: true, tension: 0.35 },
                        { label: '端口嗅探', data: [], ...trendConfigs[1], fill: true, tension: 0.35 },
                        { label: 'Web访问', data: [], ...trendConfigs[2], fill: true, tension: 0.35 }
                    ]
                },
                options: {
                    responsive: true, maintainAspectRatio: false,
                    plugins: { legend: { position: 'top', labels: { color: textColor, font: { size: 10, weight: 600 }, boxWidth: 10 } } },
                    scales: {
                        x: { grid: { color: gridColor }, ticks: { color: textColor, font: { size: 10 } } },
                        y: { beginAtZero: true, grid: { color: gridColor }, ticks: { color: textColor, font: { size: 10 } } }
                    }
                }
            });
            applyMultiLineInteractive(analyticsTrendChartInstance, trendConfigs);
        }

        const ctxHourly = document.getElementById('analyticsHourlyChart')?.getContext('2d');
        if (ctxHourly) {
            analyticsHourlyChartInstance = new Chart(ctxHourly, {
                type: 'bar',
                data: {
                    labels: Array.from({length: 24}, (_, i) => `${String(i).padStart(2, '0')}:00`),
                    datasets: [{
                        label: '攻击触碰频次',
                        data: Array(24).fill(0),
                        backgroundColor: 'rgba(255, 59, 48, 0.8)',
                        hoverBackgroundColor: '#ff3b30',
                        borderRadius: 4
                    }]
                },
                options: {
                    responsive: true, maintainAspectRatio: false,
                    plugins: { legend: { display: false } },
                    scales: {
                        x: { grid: { display: false }, ticks: { color: textColor, font: { size: 9 }, maxRotation: 0 } },
                        y: { beginAtZero: true, grid: { color: gridColor }, ticks: { color: textColor, font: { size: 10 } } }
                    }
                }
            });
            applyBarInteractive(analyticsHourlyChartInstance, '#ff3b30');
        }

        const isNarrow = window.innerWidth <= 600;
        const doughnutLegendPos = isNarrow ? 'bottom' : 'right';
        const doughnutLegendLabels = {
            color: textColor,
            font: { size: isNarrow ? 9 : 10, weight: 600 },
            boxWidth: isNarrow ? 8 : 10,
            padding: isNarrow ? 4 : 8
        };

        const ctxGeo = document.getElementById('analyticsGeoChart')?.getContext('2d');
        if (ctxGeo) {
            const geoPalette = ['#007aff', '#ff3b30', '#ff9500', '#34c759', '#af52de', '#5856d6', '#30b0c7', '#8e8e93'];
            analyticsGeoChartInstance = new Chart(ctxGeo, {
                type: 'doughnut',
                data: { labels: ['暂无数据'], datasets: [{ data: [1], backgroundColor: geoPalette, borderWidth: 0 }] },
                options: {
                    responsive: true, maintainAspectRatio: false,
                    plugins: { legend: { position: doughnutLegendPos, labels: doughnutLegendLabels } }
                }
            });
            applyDoughnutInteractive(analyticsGeoChartInstance, geoPalette);
        }

        const ctxIsp = document.getElementById('analyticsIspChart')?.getContext('2d');
        if (ctxIsp) {
            analyticsIspChartInstance = new Chart(ctxIsp, {
                type: 'bar',
                data: { labels: [], datasets: [{ label: '威胁源实体', data: [], backgroundColor: '#007aff', borderRadius: 4 }] },
                options: {
                    indexAxis: 'y',
                    responsive: true, maintainAspectRatio: false,
                    plugins: { legend: { display: false } },
                    scales: {
                        x: { beginAtZero: true, grid: { color: gridColor }, ticks: { color: textColor, font: { size: 9 } } },
                        y: { grid: { display: false }, ticks: { color: textColor, font: { size: 10, weight: 600 } } }
                    }
                }
            });
            applyBarInteractive(analyticsIspChartInstance, '#007aff');
        }

        const ctxCat = document.getElementById('analyticsCategoryChart')?.getContext('2d');
        if (ctxCat) {
            const catPalette = ['#ff3b30', '#ff9500', '#af52de', '#007aff', '#34c759', '#5856d6', '#30b0c7'];
            analyticsCategoryChartInstance = new Chart(ctxCat, {
                type: 'bar',
                data: { labels: [], datasets: [{ label: '攻击拦截量', data: [], backgroundColor: catPalette, borderRadius: 4 }] },
                options: {
                    responsive: true, maintainAspectRatio: false,
                    plugins: { legend: { display: false } },
                    scales: {
                        x: { grid: { display: false }, ticks: { color: textColor, font: { size: 9 } } },
                        y: { beginAtZero: true, grid: { color: gridColor }, ticks: { color: textColor, font: { size: 10 } } }
                    }
                }
            });
            applyBarInteractive(analyticsCategoryChartInstance, catPalette);
        }

        const ctxAction = document.getElementById('analyticsActionChart')?.getContext('2d');
        if (ctxAction) {
            const actionPalette = ['#ff3b30', '#ff9500', '#007aff', '#34c759', '#8e8e93'];
            analyticsActionChartInstance = new Chart(ctxAction, {
                type: 'doughnut',
                data: { labels: [], datasets: [{ data: [], backgroundColor: actionPalette, borderWidth: 0 }] },
                options: {
                    responsive: true, maintainAspectRatio: false,
                    plugins: { legend: { position: doughnutLegendPos, labels: doughnutLegendLabels } }
                }
            });
            applyDoughnutInteractive(analyticsActionChartInstance, actionPalette);
        }

        const ctxLevel = document.getElementById('analyticsLevelChart')?.getContext('2d');
        if (ctxLevel) {
            const levelPalette = ['#ff3b30', '#ff9500', '#ffd60a', '#30b0c7'];
            analyticsLevelChartInstance = new Chart(ctxLevel, {
                type: 'doughnut',
                data: { labels: [], datasets: [{ data: [], backgroundColor: levelPalette, borderWidth: 0 }] },
                options: {
                    responsive: true, maintainAspectRatio: false,
                    plugins: { legend: { position: doughnutLegendPos, labels: doughnutLegendLabels } }
                }
            });
            applyDoughnutInteractive(analyticsLevelChartInstance, levelPalette);
        }

        const ctxHttp = document.getElementById('analyticsHttpStatusChart')?.getContext('2d');
        if (ctxHttp) {
            const httpPalette = ['#34c759', '#ff9500', '#ff3b30', '#af52de', '#8e8e93', '#007aff', '#ffd60a'];
            analyticsHttpStatusChartInstance = new Chart(ctxHttp, {
                type: 'doughnut',
                data: { labels: [], datasets: [{ data: [], backgroundColor: httpPalette, borderWidth: 0 }] },
                options: {
                    responsive: true, maintainAspectRatio: false,
                    plugins: { legend: { position: doughnutLegendPos, labels: doughnutLegendLabels } }
                }
            });
            applyDoughnutInteractive(analyticsHttpStatusChartInstance, httpPalette);
        }
    }

    function destroyAnalyticsCharts() {
        [
            analyticsTrendChartInstance,
            analyticsHourlyChartInstance,
            analyticsGeoChartInstance,
            analyticsIspChartInstance,
            analyticsCategoryChartInstance,
            analyticsActionChartInstance,
            analyticsLevelChartInstance,
            analyticsHttpStatusChartInstance
        ].forEach(inst => {
            if (inst) {
                try { inst.destroy(); } catch (e) {}
            }
        });
        analyticsTrendChartInstance = null;
        analyticsHourlyChartInstance = null;
        analyticsGeoChartInstance = null;
        analyticsIspChartInstance = null;
        analyticsCategoryChartInstance = null;
        analyticsActionChartInstance = null;
        analyticsLevelChartInstance = null;
        analyticsHttpStatusChartInstance = null;
    }

    function switchOverviewSubTab(subTab, btn) {
        currentOverviewSubTab = subTab;
        const subviewOverview = document.getElementById('subview-overview');
        const subviewAnalysis = document.getElementById('subview-analysis');
        const toolbar = document.getElementById('analytics-toolbar');
        const btnOverview = document.getElementById('subtab-btn-overview');
        const btnAnalysis = document.getElementById('subtab-btn-analysis');

        if (subTab === 'overview') {
            if (btnOverview) { btnOverview.className = 'pill-btn accent'; btnOverview.style.background = ''; }
            if (btnAnalysis) { btnAnalysis.className = 'pill-btn'; btnAnalysis.style.background = 'transparent'; }
            if (subviewOverview) subviewOverview.style.display = 'block';
            if (subviewAnalysis) subviewAnalysis.style.display = 'none';
            if (toolbar) toolbar.style.display = 'none';
            fetchData(false);
        } else {
            if (btnOverview) { btnOverview.className = 'pill-btn'; btnOverview.style.background = 'transparent'; }
            if (btnAnalysis) { btnAnalysis.className = 'pill-btn accent'; btnAnalysis.style.background = ''; }
            if (subviewOverview) subviewOverview.style.display = 'none';
            if (subviewAnalysis) subviewAnalysis.style.display = 'block';
            if (toolbar) toolbar.style.display = 'flex';
            
            // 确保在父容器 display: block 可见之后初始化或重算尺寸
            initAnalyticsCharts();
            fetchAnalyticsData(false);
        }
    }

    function changeAnalyticsRange(range, btn) {
        currentAnalyticsRange = range;
        ['24h', '7d', '30d', 'all'].forEach(r => {
            const b = document.getElementById(`filter-range-${r}`);
            if (b) b.classList.remove('active');
        });
        if (btn) btn.classList.add('active');
        fetchAnalyticsData(true);
    }

    function fetchAnalyticsData(showNotice = false) {
        fetch(`/api/analytics?range=${currentAnalyticsRange}`).then(res => res.json()).then(data => {
            analyticsDataCache = data;
            
            // 1. KPI Cards
            if (data.kpis) {
                const kp = data.kpis;
                const elProbes = document.getElementById('akpi-probes');
                const elInter = document.getElementById('akpi-intercepted');
                const elAttacker = document.getElementById('akpi-attackers');
                const elBanRate = document.getElementById('akpi-banrate');
                const elCountries = document.getElementById('akpi-countries');
                const elWeb = document.getElementById('akpi-webprobes');

                if (elProbes) elProbes.innerText = (kp.total_probes || 0).toLocaleString();
                if (elInter) elInter.innerText = (kp.total_intercepted || 0).toLocaleString();
                if (elAttacker) elAttacker.innerText = (kp.unique_attackers || 0).toLocaleString();
                if (elBanRate) elBanRate.innerText = `${kp.ban_rate || 0}%`;
                if (elCountries) elCountries.innerText = (kp.unique_countries || 0).toLocaleString();
                if (elWeb) elWeb.innerText = (kp.abnormal_web_requests || 0).toLocaleString();
            }

            // 2. Trend Multi-series Chart
            if (data.trend && analyticsTrendChartInstance) {
                analyticsTrendChartInstance.data.labels = data.trend.labels || [];
                analyticsTrendChartInstance.data.datasets[0].data = data.trend.events || [];
                analyticsTrendChartInstance.data.datasets[1].data = data.trend.probes || [];
                analyticsTrendChartInstance.data.datasets[2].data = data.trend.web || [];
                analyticsTrendChartInstance._baseLines = null;
                analyticsTrendChartInstance._selectedDatasetIndex = -1;
                analyticsTrendChartInstance.resize();
                analyticsTrendChartInstance.update();
            }

            // 3. Hourly Distribution Chart
            if (data.hourly_distribution && analyticsHourlyChartInstance) {
                analyticsHourlyChartInstance.data.labels = data.hourly_distribution.map(h => h.hour);
                analyticsHourlyChartInstance.data.datasets[0].data = data.hourly_distribution.map(h => h.count);
                analyticsHourlyChartInstance._selectedCategoryIndex = -1;
                analyticsHourlyChartInstance.resize();
                analyticsHourlyChartInstance.update();
            }

            // 4. Geo Countries
            if (data.geo_countries && analyticsGeoChartInstance && data.geo_countries.length > 0) {
                analyticsGeoChartInstance.data.labels = data.geo_countries.map(g => `${g.country} (${g.count})`);
                analyticsGeoChartInstance.data.datasets[0].data = data.geo_countries.map(g => g.count);
                analyticsGeoChartInstance._selectedCategoryIndex = -1;
                analyticsGeoChartInstance.resize();
                analyticsGeoChartInstance.update();
            }

            // 5. Geo ISPs
            if (data.geo_isps && analyticsIspChartInstance && data.geo_isps.length > 0) {
                analyticsIspChartInstance.data.labels = data.geo_isps.map(g => (g.isp.length > 18 ? g.isp.substring(0, 16) + '...' : g.isp));
                analyticsIspChartInstance.data.datasets[0].data = data.geo_isps.map(g => g.count);
                analyticsIspChartInstance._selectedCategoryIndex = -1;
                analyticsIspChartInstance.resize();
                analyticsIspChartInstance.update();
            }

            // 6. Categories
            if (data.category_distribution && analyticsCategoryChartInstance && data.category_distribution.length > 0) {
                analyticsCategoryChartInstance.data.labels = data.category_distribution.map(c => CATEGORY_LABELS[c.category] || c.category);
                analyticsCategoryChartInstance.data.datasets[0].data = data.category_distribution.map(c => c.count);
                analyticsCategoryChartInstance._selectedCategoryIndex = -1;
                analyticsCategoryChartInstance.resize();
                analyticsCategoryChartInstance.update();
            }

            // 7. Actions
            if (data.action_distribution && analyticsActionChartInstance && data.action_distribution.length > 0) {
                const actionNames = { 'INTERCEPTED': '诱捕阻断', 'PROBE': '外部探测', 'BUSINESS': '业务访问', 'WHITELIST': '白名单放行', 'WATCH': '持续观察' };
                analyticsActionChartInstance.data.labels = data.action_distribution.map(a => `${actionNames[a.action] || a.action} (${a.count})`);
                analyticsActionChartInstance.data.datasets[0].data = data.action_distribution.map(a => a.count);
                analyticsActionChartInstance._selectedCategoryIndex = -1;
                analyticsActionChartInstance.resize();
                analyticsActionChartInstance.update();
            }

            // 8. Levels
            if (data.threat_level_distribution && analyticsLevelChartInstance && data.threat_level_distribution.length > 0) {
                analyticsLevelChartInstance.data.labels = data.threat_level_distribution.map(l => `${l.level} (${l.count})`);
                analyticsLevelChartInstance.data.datasets[0].data = data.threat_level_distribution.map(l => l.count);
                analyticsLevelChartInstance._selectedCategoryIndex = -1;
                analyticsLevelChartInstance.resize();
                analyticsLevelChartInstance.update();
            }

            // 9. HTTP Status Codes (带自动自愈与resize)
            const httpEmptyEl = document.getElementById('analyticsHttpStatusEmpty');
            const httpCanvas = document.getElementById('analyticsHttpStatusChart');
            if (data.http_status_distribution && data.http_status_distribution.length > 0) {
                if (httpEmptyEl) httpEmptyEl.style.display = 'none';
                if (httpCanvas) {
                    httpCanvas.style.display = 'block';
                    if (!analyticsHttpStatusChartInstance) {
                        const ctxHttp = httpCanvas.getContext('2d');
                        if (ctxHttp) {
                            const isDark = document.documentElement.getAttribute('data-theme') !== 'light';
                            const textColor = isDark ? '#98989d' : '#8e8e93';
                            const httpPalette = ['#34c759', '#ff9500', '#ff3b30', '#af52de', '#8e8e93', '#007aff', '#ffd60a'];
                            analyticsHttpStatusChartInstance = new Chart(ctxHttp, {
                                type: 'doughnut',
                                data: { labels: [], datasets: [{ data: [], borderWidth: 0 }] },
                                options: {
                                    responsive: true, maintainAspectRatio: false,
                                    plugins: { legend: { position: 'right', labels: { color: textColor, font: { size: 10, weight: 600 } } } }
                                }
                            });
                            applyDoughnutInteractive(analyticsHttpStatusChartInstance, httpPalette);
                        }
                    }
                    if (analyticsHttpStatusChartInstance) {
                        analyticsHttpStatusChartInstance.data.labels = data.http_status_distribution.map(s => `HTTP ${s.code} (${s.count})`);
                        analyticsHttpStatusChartInstance.data.datasets[0].data = data.http_status_distribution.map(s => s.count);
                        analyticsHttpStatusChartInstance._selectedCategoryIndex = -1;
                        analyticsHttpStatusChartInstance.resize();
                        analyticsHttpStatusChartInstance.update();
                    }
                }
            } else {
                if (httpEmptyEl) httpEmptyEl.style.display = 'flex';
                if (httpCanvas) httpCanvas.style.display = 'none';
            }

            // 10. Web Diagnostics List (Paths / UAs)
            renderWebDiagList(data.top_sensitive_paths || [], data.top_user_agents || []);

            // 11. Top Attackers Table
            renderAnalyticsAttackersTable(data.top_attackers || []);

            if (showNotice) showToast(`已切换多维分析周期: ${currentAnalyticsRange}`, '🔬');
        }).catch(err => {
            console.error('Failed to load analytics data:', err);
        });
    }

    function switchWebDiagTab(tab) {
        currentWebDiagTab = tab;
        const btnPath = document.getElementById('btn-webdiag-path');
        const btnUa = document.getElementById('btn-webdiag-ua');
        if (btnPath) btnPath.classList.toggle('active', tab === 'path');
        if (btnUa) btnUa.classList.toggle('active', tab === 'ua');

        if (analyticsDataCache) {
            renderWebDiagList(analyticsDataCache.top_sensitive_paths || [], analyticsDataCache.top_user_agents || []);
        } else {
            fetchAnalyticsData(false);
        }
    }

    function renderWebDiagList(paths, uas) {
        const container = document.getElementById('web-diag-container');
        if (!container) return;
        const isPath = currentWebDiagTab === 'path';
        const list = Array.isArray(isPath ? paths : uas) ? (isPath ? paths : uas) : [];

        if (!list || list.length === 0) {
            container.innerHTML = '<div style="text-align: center; color: var(--text-sec); padding: 40px 10px; font-size: 12px; font-weight: 600;">暂无该维度的访问指纹记录</div>';
            return;
        }

        const counts = list.map(x => parseInt(x.count) || 0);
        const maxCount = Math.max(...counts, 1);
        let html = '<div style="display: flex; flex-direction: column; gap: 8px; padding-top: 2px;">';
        list.forEach((item, idx) => {
            const rawTitle = isPath ? `${item.method ? item.method + ' ' : ''}${item.path || ''}` : (item.display_name || item.ua || '未知指纹');
            const safeTitle = escapeHtml(rawTitle);
            const fullTitle = escapeHtml(isPath ? rawTitle : (item.ua || rawTitle));
            const count = parseInt(item.count) || 0;
            const pct = Math.min(100, Math.max(0, Math.round((count / maxCount) * 100)));
            const tagBadge = (!isPath && item.tag) ? `<span class="tag ${item.is_scanner ? 'danger' : 'accent'}" style="font-size: 9px; padding: 1px 5px; flex-shrink: 0;">${escapeHtml(item.tag)}</span>` : '';
            const barBg = isPath ? 'linear-gradient(90deg, #007aff, #5856d6)' : 'linear-gradient(90deg, #ff9500, #ff3b30)';

            html += `
                <div class="diag-row-item">
                    <div class="diag-row-header">
                        <div class="diag-row-left">
                            <span class="diag-rank-badge">#${idx + 1}</span>
                            ${tagBadge}
                            <span class="diag-text-title" title="${fullTitle}">${safeTitle}</span>
                        </div>
                        <span class="diag-count-text">${count.toLocaleString()} 次</span>
                    </div>
                    <div class="diag-bar-track">
                        <div class="diag-bar-fill" style="width: ${pct}%; background: ${barBg};"></div>
                    </div>
                </div>
            `;
        });
        html += '</div>';
        container.innerHTML = html;
    }

    function renderAnalyticsAttackersTable(attackers) {
        const tbody = document.getElementById('analytics-attackers-tbody');
        if (!tbody) return;
        if (!attackers || attackers.length === 0) {
            tbody.innerHTML = '<tr><td colspan="6" style="text-align: center; color: var(--text-sec); padding: 24px;">暂无持续攻击者记录</td></tr>';
            return;
        }

        let html = '';
        attackers.forEach(att => {
            const levelClass = (att.level === '极高危' || att.level === '高危') ? 'badge-danger' : 'badge-warning';
            const banStatusBadge = att.is_banned ?
                '<span class="badge badge-danger">🚫 已下发封禁</span>' :
                '<span class="badge badge-warning">👀 监控中</span>';
            const portsBadge = (att.ports || '').split(',').slice(0, 8).map(p => `<span style="display: inline-block; background: var(--card-sec); border: 1px solid var(--border); border-radius: 4px; padding: 1px 5px; font-size: 10px; font-family: monospace; margin: 1px;">${p}</span>`).join(' ');
            const geoSub = (att.country || att.isp) ? `🌐 ${(att.country || '公网节点')}${(att.isp && att.isp !== '0') ? ` · ${att.isp}` : ''}` : '🌐 公网节点';

            html += `
                <tr>
                    <td>
                        <div style="font-weight: 700; font-family: monospace; color: var(--text);">${escapeHtml(att.ip)}</div>
                        <div class="geo-subline" title="${escapeHtml(geoSub)}">${escapeHtml(geoSub)}</div>
                    </td>
                    <td>
                        <div style="max-width: 260px; line-height: 1.4;">${portsBadge}</div>
                    </td>
                    <td>
                        <b style="color: var(--danger); font-size: 13px;">${att.hit_count}</b> <span style="font-size: 10px; color: var(--text-sec);">次</span>
                    </td>
                    <td><span class="badge ${levelClass}">${att.level}</span></td>
                    <td>${banStatusBadge}</td>
                    <td>${formatTwoLineTime(att.last_seen)}</td>
                </tr>
            `;
        });
        tbody.innerHTML = html;
    }

    function exportAnalyticsJSON() {
        if (!analyticsDataCache) return showToast('暂无可导出的多维分析数据', '⚠️');
        const blob = new Blob([JSON.stringify(analyticsDataCache, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `portguard-analytics-${currentAnalyticsRange}-${Date.now()}.json`;
        a.click();
        URL.revokeObjectURL(url);
        showToast('态势分析完整数据集 (JSON) 导出成功', '📥');
    }

    let currentIpListSubTab = 'blacklist';
    function switchIpListSubTab(subTab, btn) {
        currentIpListSubTab = subTab;
        const subviewBlack = document.getElementById('subview-blacklist');
        const subviewWhite = document.getElementById('subview-whitelist');
        const btnBlack = document.getElementById('subtab-btn-blacklist');
        const btnWhite = document.getElementById('subtab-btn-whitelist');

        if (subTab === 'blacklist') {
            if (btnBlack) { btnBlack.className = 'pill-btn accent'; btnBlack.style.background = ''; }
            if (btnWhite) { btnWhite.className = 'pill-btn'; btnWhite.style.background = 'transparent'; }
            if (subviewBlack) subviewBlack.style.display = 'block';
            if (subviewWhite) subviewWhite.style.display = 'none';
            fetchBlacklist();
        } else {
            if (btnBlack) { btnBlack.className = 'pill-btn'; btnBlack.style.background = 'transparent'; }
            if (btnWhite) { btnWhite.className = 'pill-btn accent'; btnWhite.style.background = ''; }
            if (subviewBlack) subviewBlack.style.display = 'none';
            if (subviewWhite) subviewWhite.style.display = 'block';
            fetchWhitelist();
        }
    }

    let currentSettingsSubTab = 'response';
    function switchSettingsSubTab(subTab, btn) {
        currentSettingsSubTab = subTab;
        const paneResp = document.getElementById('settings-pane-response');
        const paneHidden = document.getElementById('settings-pane-hidden');
        const btnResp = document.getElementById('btn-settings-tab-response');
        const btnHidden = document.getElementById('btn-settings-tab-hidden');

        if (subTab === 'response') {
            if (btnResp) { btnResp.className = 'pill-btn accent'; btnResp.style.background = ''; }
            if (btnHidden) { btnHidden.className = 'pill-btn'; btnHidden.style.background = 'transparent'; }
            if (paneResp) paneResp.style.display = 'flex';
            if (paneHidden) paneHidden.style.display = 'none';
            loadSystemSettings();
        } else {
            if (btnResp) { btnResp.className = 'pill-btn'; btnResp.style.background = 'transparent'; }
            if (btnHidden) { btnHidden.className = 'pill-btn accent'; btnHidden.style.background = ''; }
            if (paneResp) paneResp.style.display = 'none';
            if (paneHidden) paneHidden.style.display = 'flex';
            loadHiddenIPsForPolicy();
        }
    }

    let currentTabKey = 'overview';
    function switchTab(tabKey, btn) {
        let actualTab = tabKey;
        let subTarget = null;
        if (tabKey === 'blacklist') {
            actualTab = 'iplists';
            subTarget = 'blacklist';
        } else if (tabKey === 'whitelist') {
            actualTab = 'iplists';
            subTarget = 'whitelist';
        }

        currentTabKey = actualTab;
        ['overview', 'logs', 'access-logs', 'iplists', 'traps', 'settings'].forEach(t => {
            const el = document.getElementById(`tab-${t}`);
            if (el) el.style.display = (t === actualTab) ? 'block' : 'none';
        });
        document.querySelectorAll('.dock-btn').forEach(b => b.classList.remove('active'));
        const targetBtn = btn || document.getElementById(`dock-btn-${actualTab}`);
        if (targetBtn) targetBtn.classList.add('active');
        document.getElementById('page-main-title').innerText = PAGE_TITLES[actualTab] || '控制台';

        if (subTarget) {
            switchIpListSubTab(subTarget);
        } else if (actualTab === 'iplists') {
            switchIpListSubTab(currentIpListSubTab);
        } else if (actualTab === 'settings') {
            switchSettingsSubTab(currentSettingsSubTab);
        }

        window.scrollTo({ top: 0, behavior: 'smooth' });
        fetchData(false);
    }

    function openSystemSettingsModal() {
        switchTab('settings');
        switchSettingsSubTab('response');
    }

    function jumpToLogsFilter(cat) {
        switchTab('logs');
        filterLogs(cat, document.getElementById(`seg-${cat}`) || document.getElementById('seg-all'));
    }

    let currentThemeMode = localStorage.getItem('portguard_theme') || localStorage.getItem('portsentry_theme') || 'auto';
    let autoRefreshTimer = null;
    let isAutoRefreshEnabled = true;

    function applyTheme(mode, notify = false) {
        currentThemeMode = mode;
        localStorage.setItem('portguard_theme', mode);
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
            if (currentOverviewSubTab === 'analysis') {
                fetchAnalyticsData(false);
            }
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
            if (data.defense_paused !== undefined) {
                updateDefensePauseUI(data.defense_paused);
            }
            document.getElementById('stat-total').innerText = data.total_banned;
            document.getElementById('stat-today').innerText = data.today_events;
            document.getElementById('stat-traps').innerText = data.active_traps;
            document.getElementById('stat-white').innerText = data.whitelist_count;

            if (data.hourly_trend && trendChartInstance) {
                trendChartInstance.data.labels = data.hourly_trend.labels;
                trendChartInstance.data.datasets[0].data = data.hourly_trend.data;
                trendChartInstance._selectedPointIndex = -1;
                trendChartInstance.update();
            }

            if (data.port_distribution && portChartInstance && data.port_distribution.length > 0) {
                portChartInstance.data.labels = data.port_distribution.map(p => `${p.port} (${p.name})`);
                portChartInstance.data.datasets[0].data = data.port_distribution.map(p => p.count);
                portChartInstance._selectedCategoryIndex = -1;
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

        fetch('/api/business_ports').then(res => res.json()).then(data => {
            allBusinessPorts = data;
            if (currentTrapTab === 'biz') renderTrapsTable();
        }).catch(() => {});

        fetch('/api/http_traps').then(res => res.json()).then(data => {
            allHttpTraps = data;
            if (currentTrapTab === 'req') renderTrapsTable();
        });

        fetch('/api/whitelist').then(res => res.json()).then(data => {
            allWhitelist = data;
            renderWhitelistTable();
        });

        fetch('/api/hidden-ips').then(res => res.json()).then(data => {
            allHiddenIPs = data || [];
            updateHiddenBadge(allHiddenIPs.length);
        }).catch(() => {});

        if (currentTabKey === 'access-logs') {
            fetch(`/api/access_logs?type=${currentAccessLogMode}`).then(res => res.json()).then(data => {
                if (currentAccessLogMode === 'port') allPortLogs = data;
                else allWebLogs = data;
                renderAccessLogsTable();
            });
        }

        if (currentTabKey === 'overview' && currentOverviewSubTab === 'analysis') {
            fetchAnalyticsData(false);
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

        // 异步向本地极速 IP 库拉取最新的实时归属地与网络运营商信息
        fetch(`/api/ip_info?ip=${encodeURIComponent(ip)}`).then(r => r.json()).then(geo => {
            if (geo && currentDetailIP === ip) {
                const cCN = COUNTRY_CN_MAP[geo.country] || geo.country || '公网节点';
                document.getElementById('ip-detail-country').innerText = cCN;
                document.getElementById('ip-detail-region-city').innerText = (geo.region || geo.city) ? `${geo.region || ''} ${geo.city || ''}`.trim() : '未知城市';
                document.getElementById('ip-detail-isp').innerText = geo.isp || '未知运营商 / 本地或专用网络';
            }
        }).catch(() => {});
        
        const level = currentDetailMeta.level || '高危';
        document.getElementById('ip-detail-level').innerHTML = `<span class="tag ${level === '极高危' ? 'danger' : (level === '高危' ? 'warning' : 'accent')}">${level}</span>`;
        
        const isBanned = allBlacklist && allBlacklist.some(b => b.ip === ip);
        const isWhite = allWhitelist && allWhitelist.some(w => w.ip === ip);
        const isHidden = allHiddenIPs && allHiddenIPs.some(h => h.ip === ip);
        
        let statusHtml = '<span class="tag warning">● 未封禁 (正常)</span>';
        if (isBanned) {
            statusHtml = '<span class="tag danger">🚫 内核黑名单 (已阻断)</span>';
        } else if (isWhite) {
            statusHtml = '<span class="tag success">🛡️ 信任白名单 (已放行)</span>';
        }
        if (isHidden) {
            statusHtml += ' <span class="tag" style="background: rgba(255, 149, 0, 0.15); color: var(--warning); border: 1px solid rgba(255, 149, 0, 0.3);">🙈 日志已隐藏</span>';
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

        const hideBtn = document.getElementById('btn-ip-detail-hide');
        if (hideBtn) {
            if (isHidden) {
                hideBtn.innerText = '👁️ 恢复显示此 IP 日志';
                hideBtn.className = 'pill-btn success';
                hideBtn.style.color = '';
                hideBtn.style.borderColor = '';
            } else {
                hideBtn.innerText = '🙈 隐藏此 IP 日志';
                hideBtn.className = 'pill-btn';
                hideBtn.style.color = 'var(--warning)';
                hideBtn.style.borderColor = 'rgba(255, 149, 0, 0.4)';
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
        const banBtn = document.getElementById('btn-ip-detail-ban');
        const isBanned = allBlacklist && allBlacklist.some(b => b.ip === currentDetailIP);
        if (isBanned) {
            if (banBtn) { banBtn.disabled = true; banBtn.innerText = '正在解封...'; }
            unbanIP(currentDetailIP);
            closeModals();
        } else {
            if (banBtn) { banBtn.disabled = true; banBtn.innerText = '正在封禁...'; }
            fetch('/api/ban', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ ip: currentDetailIP, reason: '详情卡片快速拉黑' })
            }).then(res => res.json()).then(res => {
                showToast(res.msg || `已成功封禁 IP: ${currentDetailIP}`, '🚫');
                if (!allBlacklist) allBlacklist = [];
                if (!allBlacklist.some(b => b.ip === currentDetailIP)) {
                    allBlacklist.unshift({
                        ip: currentDetailIP,
                        reason: '详情卡片快速拉黑',
                        country: currentDetailMeta.country || '手动添加',
                        level: '极高危',
                        ban_time: new Date().toISOString().replace('T', ' ').slice(0, 19),
                        source_node: '本机'
                    });
                }
                closeModals();
                fetchData(false);
            }).catch(err => {
                if (banBtn) { banBtn.disabled = false; banBtn.innerText = '🚫 一键拉黑 IP'; }
                showToast('封禁请求失败: ' + (err.message || '网络异常'), '⚠️');
            });
        }
    }

    function toggleCurrentDetailIPHide() {
        if (!currentDetailIP) return;
        const isHidden = allHiddenIPs && allHiddenIPs.some(h => h.ip === currentDetailIP);
        if (isHidden) {
            fetch('/api/hidden-ips/remove', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ ip: currentDetailIP })
            }).then(res => res.json()).then(res => {
                showToast(res.msg || `已恢复显示 IP: ${currentDetailIP} 的日志记录`, '👁️');
                closeModals();
                fetchData(false);
                loadHiddenIPs();
            });
        } else {
            fetch('/api/hidden-ips', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ ip: currentDetailIP, remark: '详情卡片快速隐藏' })
            }).then(res => res.json()).then(res => {
                showToast(res.msg || `已全局隐藏 IP: ${currentDetailIP} 的所有日志`, '🙈');
                closeModals();
                fetchData(false);
                loadHiddenIPs();
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
                    <span class="geo-subline" style="display:inline-block; vertical-align:middle; margin-left:4px; margin-top:0; max-width:150px;" title="${escapeHtml(geoText)}">${geoText}</span>
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

            const uaInfo = getUATagInfo(e.user_agent);
            let uaBadge = '';
            if (e.user_agent && uaInfo && uaInfo.tag !== '未知指纹') {
                uaBadge = `<span class="tag ${uaInfo.cls}" style="margin-left:4px; font-size:10px; padding:1px 6px; cursor:help; font-weight:700; display:inline-inline-flex; align-items:center; gap:2px;" title="扫描器/客户端指纹: ${escapeHtml(e.user_agent)}">${uaInfo.icon} ${escapeHtml(uaInfo.tag)}</span>`;
            }

            const pNum = parseInt(e.port) || 0;
            const pProto = (e.proto || 'TCP').toUpperCase();
            let portBadge = '';
            if (pNum === 0 || pProto === 'MANUAL') {
                portBadge = `<span class="tag neutral" style="font-size:11px; font-weight:700;">🌐 全局封禁</span>`;
            } else {
                portBadge = `<span class="tag neutral" style="font-size:12px; font-weight:700;">${escapeHtml(pProto)} / ${pNum}</span>`;
            }

            html += `
            <tr>
                <td>${formatTwoLineTime(e.attack_time)}</td>
                <td>
                    <span class="ip-text" onclick="showIPDetail('${jsEscape(e.ip)}')" title="点击查看 IP 详情">${escapeHtml(e.ip)}</span>
                    <div class="geo-subline" title="${escapeHtml(geoText)}">${geoText}</div>
                </td>
                <td>${portBadge}</td>
                <td><span style="color:var(--text); font-size:12px; font-weight:600; line-height:1.4; display:inline-block;">${escapeHtml(e.port_name || '自定义诱饵')}</span> <span class="tag accent" style="margin-left:4px; font-size:10px; padding:2px 6px;">${catName}</span>${uaBadge}</td>
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
            tbody.innerHTML = '<tr><td colspan="7" style="text-align: center; color: var(--text-sec); padding: 24px;">当前内核黑名单池为空</td></tr>';
            return;
        }

        const startIdx = (blacklistPage - 1) * PAGE_SIZE;
        const endIdx = startIdx + PAGE_SIZE;
        const pageList = list.slice(startIdx, endIdx);

        let html = '';
        pageList.forEach(b => {
            const geoText = formatGeoCN(b);
            const rawNode = (b.source_node || '本机').trim();
            let cleanNode = rawNode;
            while (cleanNode.startsWith('集群 (') && cleanNode.endsWith(')')) {
                cleanNode = cleanNode.slice(4, -1).trim();
            }
            cleanNode = cleanNode.replace(/集群\s*\(\s*/g, '').replace(/\)+$/g, '').trim() || rawNode;

            let nodeBadge = '';
            if (rawNode.includes('腾讯云') || cleanNode.includes('腾讯云')) {
                nodeBadge = `<span class="tag" style="background: rgba(0, 164, 255, 0.12); color: #0088ff; border: 1px solid rgba(0, 164, 255, 0.3); font-weight: 700; white-space: nowrap;">☁️ ${escapeHtml(cleanNode)}</span>`;
            } else if (rawNode.includes('阿里云') || cleanNode.includes('Ali') || cleanNode.includes('阿里')) {
                nodeBadge = `<span class="tag" style="background: rgba(255, 106, 0, 0.12); color: #ff6a00; border: 1px solid rgba(255, 106, 0, 0.3); font-weight: 700; white-space: nowrap;">⚡ ${escapeHtml(cleanNode)}</span>`;
            } else if (rawNode.includes('搬瓦工') || cleanNode.includes('BWH') || cleanNode.includes('搬瓦工')) {
                nodeBadge = `<span class="tag" style="background: rgba(175, 82, 222, 0.12); color: #af52de; border: 1px solid rgba(175, 82, 222, 0.3); font-weight: 700; white-space: nowrap;">🚀 ${escapeHtml(cleanNode)}</span>`;
            } else if (rawNode.includes('手动')) {
                nodeBadge = `<span class="tag" style="background: rgba(255, 149, 0, 0.12); color: #ff9500; border: 1px solid rgba(255, 149, 0, 0.3); font-weight: 700; white-space: nowrap;">👤 手动添加</span>`;
            } else if (rawNode.includes('联防') || rawNode.includes('集群')) {
                nodeBadge = `<span class="tag" style="background: rgba(88, 86, 214, 0.12); color: #5856d6; border: 1px solid rgba(88, 86, 214, 0.3); font-weight: 700; white-space: nowrap;">🌐 ${escapeHtml(cleanNode)}</span>`;
            } else {
                nodeBadge = `<span class="tag" style="background: rgba(52, 199, 89, 0.12); color: #34c759; border: 1px solid rgba(52, 199, 89, 0.3); font-weight: 700; white-space: nowrap;">📍 ${escapeHtml(rawNode)}</span>`;
            }

            html += `
            <tr>
                <td>
                    <span class="ip-text" onclick="showIPDetail('${jsEscape(b.ip)}')" title="点击查看 IP 详情">${escapeHtml(b.ip)}</span>
                    <div class="geo-subline" title="${escapeHtml(geoText)}">${geoText}</div>
                </td>
                <td>${nodeBadge}</td>
                <td><span style="color:var(--text); font-size:12px; font-weight:600; line-height:1.4; display:inline-block;">${escapeHtml(b.reason || '自动诱捕阻断')}</span></td>
                <td><span class="tag danger" style="font-size:11px; font-weight:700;">ipset + blackhole</span></td>
                <td>${formatTwoLineTime(b.ban_time)}</td>
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
        } else if (currentTrapTab === 'biz') {
            container.innerHTML = `
                <div style="font-size: 11px; color: var(--text-sec); font-weight: 700; padding: 4px 8px 6px; text-transform: uppercase; letter-spacing: 0.5px;">🏢 业务端口管理</div>
                <a href="javascript:void(0)" onclick="closeTrapActionMenu(); openAddBizPortModal();" style="display: flex; align-items: center; gap: 8px; padding: 8px 10px; color: var(--text); text-decoration: none; border-radius: 8px; font-size: 12px; font-weight: 600;" onmouseover="this.style.background='var(--card-sec)'" onmouseout="this.style.background='transparent'">
                    <span>➕</span><span>添加业务端口</span>
                </a>
                <div style="height: 1px; background: var(--border-subtle); margin: 4px 0;"></div>
                <a href="javascript:void(0)" onclick="closeTrapActionMenu(); openImportModal('business_ports');" style="display: flex; align-items: center; gap: 8px; padding: 8px 10px; color: var(--text); text-decoration: none; border-radius: 8px; font-size: 12px; font-weight: 600;" onmouseover="this.style.background='var(--card-sec)'" onmouseout="this.style.background='transparent'">
                    <span>📥</span><span>导入业务列表 (JSON)</span>
                </a>
                <a href="javascript:void(0)" onclick="closeTrapActionMenu(); exportBusinessPortsJSON();" style="display: flex; align-items: center; gap: 8px; padding: 8px 10px; color: var(--text); text-decoration: none; border-radius: 8px; font-size: 12px; font-weight: 600;" onmouseover="this.style.background='var(--card-sec)'" onmouseout="this.style.background='transparent'">
                    <span>📤</span><span>导出业务列表 (JSON)</span>
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

    function exportBusinessPortsJSON() {
        if (!allBusinessPorts || allBusinessPorts.length === 0) return showToast('暂无业务端口可导出', '⚠️');
        const exportList = allBusinessPorts.map(b => ({
            port: b.port,
            name: b.name || `业务端口 (${b.port})`,
            category: b.category || 'custom',
            remark: b.remark || ''
        }));
        const blob = new Blob([JSON.stringify(exportList, null, 2)], { type: 'application/json' });
        const link = document.createElement('a');
        link.href = URL.createObjectURL(blob);
        link.download = `portguard_business_ports_${new Date().toISOString().slice(0, 10)}.json`;
        link.click();
        showToast('已开始导出业务端口列表 (JSON)', '📤');
    }

    function exportHiddenIPsJSON() {
        if (!allHiddenIPs || allHiddenIPs.length === 0) return showToast('暂无隐藏 IP 可导出', '⚠️');
        const exportList = allHiddenIPs.map(h => ({
            ip: h.ip,
            country: h.country || '',
            region: h.region || '',
            city: h.city || '',
            isp: h.isp || '',
            remark: h.remark || '',
            create_time: h.create_time || ''
        }));
        const blob = new Blob([JSON.stringify(exportList, null, 2)], { type: 'application/json' });
        const link = document.createElement('a');
        link.href = URL.createObjectURL(blob);
        link.download = `portguard_hidden_ips_${new Date().toISOString().slice(0, 10)}.json`;
        link.click();
        showToast('已开始导出隐藏 IP 列表 (JSON)', '📤');
    }

    function openAddBizPortModal() {
        document.getElementById('modal-biz-title').innerText = '🏢 添加正常业务端口';
        document.getElementById('biz-port-orig-val').value = '';
        document.getElementById('biz-port-val').value = '';
        document.getElementById('biz-port-val').disabled = false;
        document.getElementById('biz-name-val').value = '';
        document.getElementById('biz-cat-val').value = 'web';
        document.getElementById('biz-remark-val').value = '';
        document.getElementById('biz-block-scanner-val').checked = true;
        document.getElementById('biz-block-idc-val').checked = false;
        document.getElementById('modal-biz-port').style.display = 'flex';
    }

    function openEditBizPortModal(port) {
        const item = (allBusinessPorts || []).find(b => Number(b.port) === Number(port));
        if (!item) return showToast('未找到该业务端口', '⚠️');
        document.getElementById('modal-biz-title').innerText = '✏️ 编辑正常业务端口';
        document.getElementById('biz-port-orig-val').value = item.port;
        document.getElementById('biz-port-val').value = item.port;
        document.getElementById('biz-port-val').disabled = true;
        document.getElementById('biz-name-val').value = item.name || '';
        document.getElementById('biz-cat-val').value = item.category || 'custom';
        document.getElementById('biz-remark-val').value = item.remark || '';
        document.getElementById('biz-block-scanner-val').checked = (item.block_scanner !== false);
        document.getElementById('biz-block-idc-val').checked = !!item.block_idc;
        document.getElementById('modal-biz-port').style.display = 'flex';
    }

    function submitBizPortForm() {
        const origPort = document.getElementById('biz-port-orig-val').value;
        const port = parseInt(document.getElementById('biz-port-val').value);
        const name = document.getElementById('biz-name-val').value.trim();
        const category = document.getElementById('biz-cat-val').value;
        const remark = document.getElementById('biz-remark-val').value.trim();
        const block_scanner = document.getElementById('biz-block-scanner-val').checked;
        const block_idc = document.getElementById('biz-block-idc-val').checked;

        if (!port || port < 1 || port > 65535) return showToast('请输入 1-65535 的有效端口号', '⚠️');
        if (!name) return showToast('请输入业务服务名称或描述', '⚠️');

        const isEdit = !!origPort;
        const apiUrl = isEdit ? '/api/business_ports/edit' : '/api/business_ports/add';

        fetch(apiUrl, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ port, name, category, remark, block_scanner, block_idc })
        }).then(res => res.json()).then(res => {
            if (res.success) {
                showToast(res.msg || '保存成功！', '🎉');
                closeModals();
                fetchData(false);
            } else {
                showToast(res.msg || '保存失败', '❌');
            }
        });
    }

    function deleteBizPort(port) {
        if (!confirm(`确定要从业务列表中移除端口 ${port} 吗？`)) return;
        fetch('/api/business_ports/delete', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ port: Number(port) })
        }).then(res => res.json()).then(res => {
            if (res.success) {
                showToast(res.msg || '已删除业务端口', '🗑️');
                allBusinessPorts = (allBusinessPorts || []).filter(b => Number(b.port) !== Number(port));
                renderTrapsTable();
                fetch('/api/business_ports').then(r => r.json()).then(data => {
                    allBusinessPorts = data;
                    renderTrapsTable();
                });
            } else {
                showToast(res.msg || '删除失败', '❌');
            }
        }).catch(err => {
            showToast('删除请求异常: ' + err, '❌');
        });
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
        link.download = `portguard_http_traps_${new Date().toISOString().slice(0, 10)}.json`;
        link.click();
        showToast('已开始导出请求特征策略 (JSON)', '📤');
    }

    function switchTrapTab(tab) {
        currentTrapTab = tab;
        const btnPort = document.getElementById('btn-trap-tab-port');
        const btnBiz = document.getElementById('btn-trap-tab-biz');
        const btnReq = document.getElementById('btn-trap-tab-req');
        const titleEl = document.getElementById('traps-main-title');
        const subEl = document.getElementById('traps-main-sub');
        const theadEl = document.getElementById('traps-thead');
        const tablePane = document.getElementById('policy-pane-table-container');
        const actionMenuBtn = document.getElementById('btn-trap-action-menu');
        const bannerBiz = document.getElementById('banner-biz-defense');
        closeTrapActionMenu();

        [btnPort, btnBiz, btnReq].forEach(b => {
            if (b) { b.className = 'pill-btn'; b.style.background = 'transparent'; }
        });
        if (tablePane) tablePane.style.display = 'block';
        if (bannerBiz) bannerBiz.style.display = 'none';
        if (actionMenuBtn) actionMenuBtn.style.display = 'inline-block';

        if (tab === 'port') {
            if (btnPort) { btnPort.className = 'pill-btn accent'; btnPort.style.background = ''; }
            if (titleEl) titleEl.innerText = '🔌 端口策略管理';
            if (subEl) subEl.innerText = '自动阻断探针扫描，系统业务端口默认放行';
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
            renderTrapsTable();
        } else if (tab === 'biz') {
            if (btnBiz) { btnBiz.className = 'pill-btn accent'; btnBiz.style.background = ''; }
            if (bannerBiz) bannerBiz.style.display = 'flex';
            if (titleEl) titleEl.innerText = '🏢 常规生产业务清单';
            if (subEl) subEl.innerText = '受内核级放行保护，正常访问 100% 连通';
            if (theadEl) {
                theadEl.innerHTML = `
                    <tr>
                        <th style="width: 140px;">业务端口</th>
                        <th>服务名称 / 业务描述</th>
                        <th style="width: 130px;">业务类型</th>
                        <th style="width: 140px;">来源属性</th>
                        <th style="width: 140px;">放行保护状态</th>
                        <th style="width: 150px;">管理操作</th>
                    </tr>
                `;
            }
            if (!allBusinessPorts || allBusinessPorts.length === 0) {
                fetch('/api/business_ports').then(res => res.json()).then(data => {
                    allBusinessPorts = data;
                    renderTrapsTable();
                });
            } else {
                renderTrapsTable();
            }
        } else if (tab === 'req') {
            if (btnReq) { btnReq.className = 'pill-btn accent'; btnReq.style.background = ''; }
            if (titleEl) titleEl.innerText = '🎯 行为特征防御';
            if (subEl) subEl.innerText = '检测路径嗅探、后台爆破与恶意指纹';
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
            } else {
                renderTrapsTable();
            }
        }
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
        } else if (currentTrapTab === 'biz') {
            const total = allBusinessPorts ? allBusinessPorts.length : 0;
            const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE));
            const target = bizPortsPage + delta;
            if (target >= 1 && target <= totalPages) {
                bizPortsPage = target;
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
        else if (currentTrapTab === 'biz') bizPortsPage = p;
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
        } else if (currentTrapTab === 'biz') {
            const list = allBusinessPorts || [];
            const totalCount = list.length;
            const totalPages = Math.max(1, Math.ceil(totalCount / PAGE_SIZE));
            if (bizPortsPage > totalPages) bizPortsPage = totalPages;
            if (bizPortsPage < 1) bizPortsPage = 1;

            renderPaginationUI(totalCount, bizPortsPage, PAGE_SIZE, 'traps-total-cnt', 'traps-page-info', 'btn-traps-prev', 'btn-traps-next', 'traps-page-nums', 'setTrapsPage');

            if (totalCount === 0) {
                tbody.innerHTML = '<tr><td colspan="6" style="text-align:center; padding:24px;">暂无业务端口记录</td></tr>';
                return;
            }

            const startIdx = (bizPortsPage - 1) * PAGE_SIZE;
            const endIdx = startIdx + PAGE_SIZE;
            const pageList = list.slice(startIdx, endIdx);

            const BIZ_CAT_LABELS = {
                'web': 'Web / API',
                'ssh': '远程运维',
                'db': '数据库',
                'system': '系统服务',
                'custom': '自定义业务'
            };

            let html = '';
            pageList.forEach(b => {
                const port = b.port;
                const name = b.name || `业务端口 (${port})`;
                const cat = b.category || 'custom';
                const catName = BIZ_CAT_LABELS[cat] || cat;
                const originTag = `<span class="tag accent" style="font-size:11px;">🛡️ ${catName}</span>`;
                
                let statusBadges = '<span class="tag success" style="font-weight:700;">🟢 正常业务放行</span>';
                if (b.block_scanner) {
                    statusBadges += '<span class="tag" style="background: rgba(99,102,241,0.15); color: #818cf8; border: 1px solid rgba(99,102,241,0.3); margin-left: 4px; font-size: 11px; font-weight: 600;">🌐 测绘拦截</span>';
                }
                if (b.block_idc) {
                    statusBadges += '<span class="tag" style="background: rgba(245,158,11,0.15); color: #f59e0b; border: 1px solid rgba(245,158,11,0.3); margin-left: 4px; font-size: 11px; font-weight: 600;">🛡️ 阻断IDC机房</span>';
                }
                
                let opHtml = `
                    <div style="display: flex; gap: 6px; align-items: center;">
                        <button class="action-btn" onclick="openEditBizPortModal(${port})" style="background: var(--card-sec); color: var(--text); border: 1px solid var(--border);">✏️ 编辑</button>
                        <button class="action-btn danger" onclick="deleteBizPort(${port})" title="移除业务端口">🗑️</button>
                    </div>
                `;

                html += `
                <tr>
                    <td><span class="tag neutral" style="font-size:13px; font-weight:800; font-family:monospace;">TCP / ${port}</span></td>
                    <td>
                        <span style="color:var(--text); font-size:13px; font-weight:700; line-height:1.4; display:inline-block;">${escapeHtml(name)}</span>
                        ${b.remark ? `<div style="font-size:11px; color:var(--text-sec); margin-top:2px;">${escapeHtml(b.remark)}</div>` : ''}
                    </td>
                    <td><span class="tag accent">${catName}</span></td>
                    <td>${originTag}</td>
                    <td>${statusBadges}</td>
                    <td>${opHtml}</td>
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
                'survey_engine': '测绘引擎识别',
                'direct_ip': '纯IP直连探测',
                'status_rate': '状态码诱捕/熔断'
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
                    const patDesc = rule.pattern ? rule.pattern : '400,403,404';
                    const th = parseInt(rule.threshold) || 1;
                    const win = parseInt(rule.window) || 30;
                    if (th <= 1) {
                        ruleContentHtml = `<span style="font-size:12px; font-weight:700; color:var(--accent);">⚡ 触发状态码 [<code>${escapeHtml(patDesc)}</code>] 立即秒级封禁</span>`;
                    } else {
                        ruleContentHtml = `<span style="font-size:12px; font-weight:700; color:var(--accent);">⚡ ${win} 秒内状态码 [<code>${escapeHtml(patDesc)}</code>] ≥ ${th} 次触发熔断封禁</span>`;
                    }
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
        const patInput = document.getElementById(`${prefix === 'edit' ? 'edit-' : ''}http-trap-pattern-val`);
        
        if (!typeEl) return;
        const val = typeEl.value;
        if (val === 'status_rate') {
            if (patGroup) patGroup.style.display = 'block';
            if (rateGroup) rateGroup.style.display = 'block';
            if (labelEl) labelEl.innerText = '目标状态码 (支持单个如 302、多状态码如 400,403,404 或 301|302 或范围如 500-599 或 4xx/5xx/all_error)';
            if (patInput) {
                patInput.placeholder = '例如：302 或 400,403,404 或 500-599 或 4xx';
                if (!patInput.value && prefix === 'add') patInput.value = '400,403,404';
            }
        } else if (val === 'direct_ip') {
            if (patGroup) patGroup.style.display = 'block';
            if (rateGroup) rateGroup.style.display = 'none';
            if (labelEl) labelEl.innerText = '纯 IP 直连访问防护标记 (自动生效)';
            if (patInput && !patInput.value) patInput.value = 'direct_ip';
        } else if (val === 'survey_engine') {
            if (patGroup) patGroup.style.display = 'block';
            if (rateGroup) rateGroup.style.display = 'none';
            if (labelEl) labelEl.innerText = '测绘引擎特征关键词 (正则 / 管道符 | 分隔)';
            if (patInput && !patInput.value) patInput.value = 'censys|onyphe|shodan|leakix|shadowserver|zoomeye';
        } else {
            if (patGroup) patGroup.style.display = 'block';
            if (rateGroup) rateGroup.style.display = 'none';
            if (labelEl) {
                labelEl.innerText = (val === 'ua_keyword') ? 'User-Agent 扫描工具指纹 (正则/关键词)' : 'URL 敏感路径特征表达式 (支持 | 分隔)';
            }
            if (patInput) {
                patInput.placeholder = (val === 'ua_keyword') ? '例如：sqlmap|nikto|dirsearch|wpscan' : '例如：\\.env|\\.git|config\\.json';
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
        let pattern = document.getElementById('http-trap-pattern-val').value.trim();
        const window = parseInt(document.getElementById('http-trap-window-val').value) || 30;
        const threshold = parseInt(document.getElementById('http-trap-threshold-val').value) || 1;
        const level = document.getElementById('http-trap-level-val').value;
        const description = document.getElementById('http-trap-desc-val').value.trim();

        if (!name) return showToast('请输入策略名称', '⚠️');
        if (match_type === 'status_rate' && !pattern) {
            pattern = '400,403,404';
        } else if (match_type !== 'status_rate' && !pattern) {
            return showToast('请输入特征表达式或关键词', '⚠️');
        }

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
        let pattern = document.getElementById('edit-http-trap-pattern-val').value.trim();
        const window = parseInt(document.getElementById('edit-http-trap-window-val').value) || 30;
        const threshold = parseInt(document.getElementById('edit-http-trap-threshold-val').value) || 1;
        const level = document.getElementById('edit-http-trap-level-val').value;
        const description = document.getElementById('edit-http-trap-desc-val').value.trim();

        if (!name) return showToast('请输入策略名称', '⚠️');
        if (match_type === 'status_rate' && !pattern) {
            pattern = '400,403,404';
        } else if (match_type !== 'status_rate' && !pattern) {
            return showToast('请输入特征表达式或关键词', '⚠️');
        }

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
            tbody.innerHTML = '<tr><td colspan="3" style="text-align: center; color: var(--text-sec); padding: 24px;">当前无白名单记录</td></tr>';
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
                <td style="text-align: right;">
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
                        <th style="width: 130px;">访问时间</th>
                        <th style="width: 220px;">来源 IP</th>
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
                        <th style="width: 130px;">访问时间</th>
                        <th style="width: 220px;">客户端 IP</th>
                        <th style="width: 180px;">访问域名 (Host)</th>
                        <th>请求方法 & 访问路径 (URI)</th>
                        <th style="width: 90px;">状态码</th>
                        <th style="width: 130px;">指纹标签 (UA)</th>
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
            const emptyColspan = (currentAccessLogMode === 'port') ? 5 : 6;
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
                    <td>${formatTwoLineTime(l.access_time)}</td>
                    <td>
                        <span class="ip-text" onclick="showIPDetail('${jsEscape(l.ip)}')" title="点击查看 IP 详情">${escapeHtml(l.ip)}</span>
                        <div class="geo-subline" title="${escapeHtml(geoText)}">${geoText}</div>
                    </td>
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
                const uaInfo = getUATagInfo(l.user_agent);
                const uaTagHtml = `<span class="tag ${uaInfo.cls}" style="font-size:11px; font-weight:700; cursor:help; display:inline-flex; align-items:center; gap:3px;" title="${escapeHtml(l.user_agent || '无详细 UA 标头')}">${uaInfo.icon} ${escapeHtml(uaInfo.tag)}</span>`;
                const rawPath = l.path || '/';
                const pathDisplay = (rawPath.length > 45) ? (rawPath.slice(0, 42) + '...') : rawPath;
                html += `
                <tr>
                    <td>${formatTwoLineTime(l.access_time)}</td>
                    <td>
                        <span class="ip-text" onclick="showIPDetail('${jsEscape(l.ip)}')" title="点击查看 IP 详情">${escapeHtml(l.ip)}</span>
                        <div class="geo-subline" title="${escapeHtml(geoText)}">${geoText}</div>
                    </td>
                    <td><span class="tag neutral" style="font-size:12px; font-weight:700; font-family:inherit; color:var(--accent); max-width:160px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; display:inline-block; vertical-align:middle;" title="${escapeHtml(domain)}">🌐 ${escapeHtml(domain)}</span></td>
                    <td>
                        <div style="display:inline-flex; align-items:center; gap:6px; max-width:320px;">
                            ${methodTag}
                            <code style="background:var(--card-sec); padding:2px 6px; border-radius:6px; font-size:12px; font-weight:600; color:var(--text); max-width:260px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; display:inline-block; vertical-align:middle; cursor:pointer;" title="${escapeHtml(rawPath)}">${escapeHtml(pathDisplay)}</code>
                        </div>
                    </td>
                    <td>${statusTag}</td>
                    <td>${uaTagHtml}</td>
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
        link.download = `portguard_${currentAccessLogMode}_access_logs_${new Date().toISOString().slice(0,10)}.csv`;
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
        if (!confirm(`确定要从内核黑名单中解除对 ${ip} 的封禁吗？\n（将自动联动所有协同节点同步解除封禁）`)) return;
        fetch('/api/unban', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ip })
        }).then(res => res.json()).then(res => {
            showToast(res.msg || '解封成功', '🔓');
            fetchData(false);
        }).catch(err => {
            showToast('解封请求失败: ' + err.message, '⚠️');
        });
    }

    function quickBanIP(ip, reason) {
        if (!confirm(`确定要立即将 ${ip} 下发至内核黑名单并同步全网封禁吗？`)) return;
        fetch('/api/ban', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ip, reason: reason || '手动封禁观察中IP' })
        }).then(res => res.json()).then(res => {
            showToast(res.msg || `已成功封禁 IP: ${ip}`, '🚫');
            fetchData(false);
        }).catch(err => {
            showToast('封禁请求失败: ' + err.message, '⚠️');
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
            fetch('/api/whitelist').then(r => r.json()).then(data => {
                allWhitelist = data || [];
                renderWhitelistTable();
                fetchData(false);
            });
        });
    }

    function removeWhitelist(ip) {
        if (!confirm(`确定要移除白名单 ${ip} 吗？`)) return;
        fetch('/api/whitelist/delete', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ip })
        }).then(res => res.json()).then(res => {
            showToast(res.msg || `已移除白名单: ${ip}`, '🗑️');
            allWhitelist = (allWhitelist || []).filter(w => (typeof w === 'object' ? w.ip : w) !== ip);
            renderWhitelistTable();
            fetch('/api/whitelist').then(r => r.json()).then(data => {
                allWhitelist = data || [];
                renderWhitelistTable();
                fetchData(false);
            });
        }).catch(err => {
            showToast('请求异常: ' + err, '⚠️');
        });
    }
    const deleteWhitelist = removeWhitelist;

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
        } else if (type === 'business_ports') {
            titleEl.innerText = '🏢 批量导入正常业务端口';
            tipEl.innerHTML = `
                支持导入 <b>JSON 数组</b> 或 <b>纯文本逐行端口列表</b>：<br>
                • JSON 格式: <code>[{"port": 8080, "name": "Keycloak", "category": "web", "remark": "认证服务"}]</code><br>
                • 文本格式: 每行一个端口（例如 <code>8080 Keycloak认证中心</code> 或纯 <code>8080</code>）<br>
                业务列表中的端口受内核级豁免保护，100% 免封绝对放行！
            `;
            textVal.placeholder = `粘贴业务端口列表或 JSON 数组，例如：\n8080 Keycloak认证\n3000 Node前端API\n\n或 JSON 格式：\n[{"port": 8080, "name": "Keycloak", "category": "web"}]`;
        } else if (type === 'hidden_ips') {
            titleEl.innerText = '🚫 批量导入审计隐藏 IP';
            tipEl.innerHTML = `
                支持导入 <b>JSON 数组</b> 或 <b>纯文本逐行 IP 列表</b>：<br>
                • JSON 格式: <code>[{"ip": "1.2.3.4", "remark": "测试节点"}]</code><br>
                • 文本格式: 每行一个 IP 地址（例如 <code>1.2.3.4 内部测试</code> 或纯 <code>1.2.3.4</code>）<br>
                隐藏列表中的 IP 在全站控制台日志中将被彻底隐藏，不影响底层正常防御！
            `;
            textVal.placeholder = `粘贴 IP 列表或 JSON 数组，例如：\n1.2.3.4 内部调试节点\n5.6.7.8\n\n或 JSON 格式：\n[{"ip": "1.2.3.4", "remark": "测试节点"}]`;
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
        } else if (currentImportType === 'business_ports') {
            textVal.value = JSON.stringify([
                { "port": 80, "name": "HTTP 网站服务", "category": "web", "remark": "主站 Web 服务" },
                { "port": 443, "name": "HTTPS 网站服务", "category": "web", "remark": "加密主站" },
                { "port": 8080, "name": "Keycloak 认证中心", "category": "web", "remark": "用户鉴权" },
                { "port": 3306, "name": "MySQL 业务数据库", "category": "db", "remark": "主库服务" }
            ], null, 2);
        } else if (currentImportType === 'hidden_ips') {
            textVal.value = JSON.stringify([
                { "ip": "198.51.100.8", "remark": "内部联调测试节点" },
                { "ip": "203.0.113.19", "remark": "第三方探针隐藏" }
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
            downloadJSONFile(data, `portguard_traps_strategy_${new Date().toISOString().slice(0,10)}.json`);
            showToast('蜜罐策略 JSON 已开始导出', '📤');
        }).catch(() => showToast('导出策略失败', '❌'));
    }

    function exportBlacklistJSON() {
        fetch('/api/blacklist/export').then(res => res.json()).then(data => {
            downloadJSONFile(data, `portguard_blacklist_${new Date().toISOString().slice(0,10)}.json`);
            showToast('黑名单 JSON 已开始导出', '📤');
        }).catch(() => showToast('导出黑名单失败', '❌'));
    }

    function exportWhitelistJSON() {
        fetch('/api/whitelist/export').then(res => res.json()).then(data => {
            downloadJSONFile(data, `portguard_whitelist_${new Date().toISOString().slice(0,10)}.json`);
            showToast('白名单 JSON 已开始导出', '📤');
        }).catch(() => showToast('导出白名单失败', '❌'));
    }

    async function syncAllWhitelistToCluster() {
        if (!confirm('确定要将本机的全部信任白名单立即广播同步至所有集群协同节点吗？')) return;
        showToast('正在向全网协同节点广播同步白名单...', '⏳');
        try {
            const res = await fetch('/api/cluster/sync_all_whitelist', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({})
            });
            const data = await res.json();
            if (data.success) {
                showToast(data.msg || '全网协同白名单同步完成！', '🎉');
                loadWhitelist();
            } else {
                showToast(data.msg || '同步失败', '⚠️');
            }
        } catch (e) {
            showToast('请求异常: ' + e, '⚠️');
        }
    }

    async function syncAllMeshState() {
        if (!confirm('确定要与全网所有协同节点进行黑名单与白名单的【双向全量对齐】吗？\n（双方将自动交换并吸纳补齐彼此缺失的全部拦截目标与信任规则）')) return;
        showToast('正在与全网协同节点进行双向全量对齐...', '⏳');
        try {
            const res = await fetch('/api/cluster/sync_all_mesh', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({})
            });
            const data = await res.json();
            if (data.success) {
                showToast(data.msg || '全网黑白名单双向对齐同步完成！', '🎉');
                loadBlacklist();
                loadWhitelist();
                loadStats();
            } else {
                showToast(data.msg || '对齐失败', '⚠️');
            }
        } catch (e) {
            showToast('请求异常: ' + e, '⚠️');
        }
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
        link.download = `portguard_audit_logs_${new Date().toISOString().slice(0,10)}.csv`;
        link.click();
        showToast('已开始下载 CSV 审计报表', '📥');
    }

    function copyIP(text) {
        navigator.clipboard.writeText(text).then(() => showToast(`已复制 IP: ${text}`, '📋'));
    }

    let isDefensePaused = false;

    async function toggleDefenseServicePause() {
        const targetAction = isDefensePaused ? 'resume' : 'pause';
        const confirmMsg = isDefensePaused 
            ? '确定要恢复威胁防御拦截服务吗？\n系统将重新启用内核防火墙与蜜罐实时阻断。' 
            : '确定要暂停所有防御拦截服务吗？\n暂停期间系统将不再执行任何 IP 封禁与黑洞阻断，并会临时释放当前所有内核拦截规则，便于运维排查。';
        if (!confirm(confirmMsg)) return;

        try {
            showToast('正在切换防御服务状态...', '⏳');
            const res = await fetch('/api/defense/toggle_pause', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ action: targetAction })
            });
            const data = await res.json();
            if (data.success) {
                isDefensePaused = !!data.paused;
                updateDefensePauseUI(isDefensePaused);
                showToast(data.msg, isDefensePaused ? '⏸️' : '🛡️');
                fetchData(false);
            } else {
                showToast(data.msg || '操作失败', '⚠️');
            }
        } catch (e) {
            showToast('请求异常: ' + e, '⚠️');
        }
    }

    function updateDefensePauseUI(paused) {
        isDefensePaused = !!paused;
        const btn = document.getElementById('btn-toggle-defense-policy-pause') || document.getElementById('btn-toggle-defense-pause');
        const tag = document.getElementById('defense-policy-status-tag') || document.getElementById('defense-service-status-tag');
        const headerDot = document.getElementById('header-status-dot');
        const headerText = document.getElementById('header-status-text');

        if (btn) {
            if (paused) {
                btn.className = 'pill-btn accent';
                btn.style.background = '#ff9500';
                btn.style.color = '#ffffff';
                btn.innerHTML = '▶️ 恢复拦截服务';
            } else {
                btn.className = 'pill-btn danger';
                btn.style.background = '';
                btn.style.color = '';
                btn.innerHTML = '⏸️ 暂停所有拦截';
            }
        }

        if (tag) {
            if (paused) {
                tag.className = 'tag warning';
                tag.style.background = 'rgba(255, 149, 0, 0.15)';
                tag.style.color = '#ff9500';
                tag.innerText = '⏸️ 拦截已暂停';
            } else {
                tag.className = 'tag success';
                tag.style.background = '';
                tag.style.color = '';
                tag.innerText = '🛡️ 拦截运行中';
            }
        }

        if (headerDot && headerText) {
            if (paused) {
                headerDot.className = 'status-dot paused';
                headerText.innerText = 'PORTGUARD · 防御已暂停';
            } else {
                headerDot.className = 'status-dot';
                headerText.innerText = 'PORTGUARD · 内核防护中';
            }
        }
    }

    async function saveNodeNameOnly() {
        const input = document.getElementById('setting-policy-node-name');
        const nodeName = input ? input.value.trim() : '';
        if (!nodeName) {
            showToast('节点标识名称不能为空', '⚠️');
            return;
        }
        try {
            showToast('正在保存节点标识名称...', '⏳');
            const res = await fetch('/api/settings', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ node_name: nodeName })
            });
            const data = await res.json();
            if (data.success) {
                showToast(`🏷️ 本机节点标识已更新为: ${nodeName}`, '🎉');
            } else {
                showToast(data.msg || '保存失败', '⚠️');
            }
        } catch (e) {
            showToast('保存异常: ' + e, '⚠️');
        }
    }

    async function loadSystemSettings() {
        try {
            const res = await fetch('/api/settings');
            const data = await res.json();
            if (data.defense_paused !== undefined) {
                updateDefensePauseUI(data.defense_paused);
            }
            // 策略中心页面控件同步
            const nodeInput = document.getElementById('setting-policy-node-name');
            if (nodeInput && document.activeElement !== nodeInput) {
                nodeInput.value = String(data.node_name || '本机节点');
            }
            if (document.getElementById('setting-policy-scan-threshold')) {
                document.getElementById('setting-policy-scan-threshold').value = String(data.port_scan_threshold || 3);
            }
            if (document.getElementById('setting-policy-scan-window')) {
                document.getElementById('setting-policy-scan-window').value = String(data.port_scan_window_seconds || 15);
            }
            if (document.getElementById('setting-policy-trap-threshold')) {
                document.getElementById('setting-policy-trap-threshold').value = String(data.trap_threshold || 2);
            }
            if (document.getElementById('setting-policy-trap-window')) {
                document.getElementById('setting-policy-trap-window').value = String(data.trap_window_seconds || 30);
            }
            if (document.getElementById('setting-policy-auto-clean')) {
                document.getElementById('setting-policy-auto-clean').value = String(data.auto_clean_days !== undefined ? data.auto_clean_days : 30);
            }
            if (document.getElementById('setting-policy-ban-iptables')) {
                document.getElementById('setting-policy-ban-iptables').checked = data.ban_action_iptables !== false;
            }
            if (document.getElementById('setting-policy-ban-blackhole')) {
                document.getElementById('setting-policy-ban-blackhole').checked = data.ban_action_blackhole !== false;
            }

            // 弹窗控件同步
            if (document.getElementById('setting-trap-threshold')) {
                document.getElementById('setting-trap-threshold').value = String(data.trap_threshold || 2);
            }
            if (document.getElementById('setting-trap-window')) {
                document.getElementById('setting-trap-window').value = String(data.trap_window_seconds || 30);
            }
            if (document.getElementById('setting-auto-clean')) {
                document.getElementById('setting-auto-clean').value = String(data.auto_clean_days !== undefined ? data.auto_clean_days : 30);
            }
            if (document.getElementById('setting-ban-iptables')) {
                document.getElementById('setting-ban-iptables').checked = data.ban_action_iptables !== false;
            }
            if (document.getElementById('setting-ban-blackhole')) {
                document.getElementById('setting-ban-blackhole').checked = data.ban_action_blackhole !== false;
            }

            // 集群联防状态卡片与节点列表同步
            if (data.cluster_sync) {
                currentClusterSync = data.cluster_sync;
                const isEnabled = Boolean(data.cluster_sync.enabled);
                const nodes = data.cluster_sync.cluster_nodes || [];
                const secret = data.cluster_sync.cluster_secret || '';

                const toggle = document.getElementById('cluster-sync-enabled-toggle');
                if (toggle) toggle.checked = isEnabled;

                const secretInput = document.getElementById('cluster-sync-secret-input');
                if (secretInput) secretInput.value = secret;

                const badge = document.getElementById('cluster-sync-status-badge');
                if (badge) {
                    if (isEnabled) {
                        badge.className = 'tag success';
                        badge.style.background = '';
                        badge.style.color = '';
                        badge.innerText = '🛡️ 联防同步运行中';
                    } else {
                        badge.className = 'tag';
                        badge.style.background = 'rgba(142, 142, 147, 0.15)';
                        badge.style.color = 'var(--text-sec)';
                        badge.innerText = '未启用';
                    }
                }

                renderClusterNodesTable();
            }

            updateThresholdBadge();
        } catch (e) {
            console.error(e);
        }
    }

    let currentClusterSync = { enabled: false, port: 9098, cluster_secret: '', cluster_nodes: [] };

    function renderClusterNodesTable() {
        const tbody = document.getElementById('cluster-nodes-tbody');
        const badge = document.getElementById('cluster-nodes-count-badge');
        if (!tbody) return;

        const nodes = currentClusterSync.cluster_nodes || [];
        if (badge) badge.innerText = `${nodes.length} 个节点`;

        if (nodes.length === 0) {
            tbody.innerHTML = '<tr><td colspan="6" style="text-align: center; color: var(--text-sec); padding: 24px;">暂未添加任何协同节点，请点击上方「➕ 添加协同节点」</td></tr>';
            return;
        }

        let html = '';
        nodes.forEach((n, idx) => {
            let statusTag = '';
            if (n.status === 'online') {
                statusTag = `<span class="tag success" style="font-size: 11px; font-weight: 700;">🟢 正常 · ${n.latency_ms || 0}ms</span>`;
            } else if (n.status === 'offline') {
                statusTag = `<span class="tag danger" style="font-size: 11px; font-weight: 700;">🔴 连接失败</span>`;
            } else if (n.status === 'testing') {
                statusTag = `<span class="tag warning" style="font-size: 11px; font-weight: 700;">⏳ 检测中...</span>`;
            } else {
                statusTag = `<span class="tag" style="background: rgba(142, 142, 147, 0.15); color: var(--text-sec); font-size: 11px;">⚪ 待检测</span>`;
            }

            html += `
            <tr style="border-bottom: 1px solid var(--border-subtle);">
                <td style="padding: 10px 12px; font-family: monospace; font-weight: 700; font-size: 12px; color: var(--text);">
                    ${escapeHtml(n.ip)}<span style="color: var(--text-sec); font-weight: normal;">:${n.port || 9098}</span>
                </td>
                <td style="padding: 10px 12px; font-size: 12px; font-weight: 600; color: var(--text);">
                    ${escapeHtml(n.remark || '-')}
                </td>
                <td style="padding: 10px 12px; font-size: 12px; color: var(--text);">
                    ${escapeHtml(n.country || '公网节点')}
                </td>
                <td style="padding: 10px 12px;">
                    ${statusTag}
                </td>
                <td style="padding: 10px 12px; font-size: 11px; color: var(--text-sec); font-variant-numeric: tabular-nums;">
                    ${escapeHtml(n.created_at || '-')}
                </td>
                <td style="padding: 10px 12px; text-align: right; white-space: nowrap;">
                    <button class="action-btn" onclick="editClusterNodeRemark('${jsEscape(n.ip)}', ${n.port || 9098}, '${jsEscape(n.remark || '')}')" style="margin-right: 6px; padding: 3px 8px; font-size: 11px;">✏️ 备注</button>
                    <button class="action-btn" onclick="testSingleClusterNode('${jsEscape(n.ip)}', ${n.port || 9098})" style="margin-right: 6px; padding: 3px 8px; font-size: 11px;">⚡ 测速</button>
                    <button class="action-btn danger" onclick="deleteClusterNode('${jsEscape(n.ip)}', ${n.port || 9098})" style="padding: 3px 8px; font-size: 11px;">🗑️ 删除</button>
                </td>
            </tr>
            `;
        });
        tbody.innerHTML = html;
    }

    async function loadClusterNodes() {
        try {
            const res = await fetch('/api/cluster/nodes');
            const data = await res.json();
            currentClusterSync.enabled = Boolean(data.enabled);
            currentClusterSync.port = data.port || 9098;
            currentClusterSync.cluster_secret = data.cluster_secret || '';
            currentClusterSync.cluster_nodes = data.nodes || [];

            const toggle = document.getElementById('cluster-sync-enabled-toggle');
            if (toggle) toggle.checked = currentClusterSync.enabled;

            const portInput = document.getElementById('cluster-sync-port-input');
            if (portInput) portInput.value = currentClusterSync.port;

            const secretInput = document.getElementById('cluster-sync-secret-input');
            if (secretInput) secretInput.value = currentClusterSync.cluster_secret;

            const badge = document.getElementById('cluster-sync-status-badge');
            if (badge) {
                if (currentClusterSync.enabled) {
                    badge.className = 'tag success';
                    badge.style.background = '';
                    badge.style.color = '';
                    badge.innerText = '🛡️ 联防同步运行中';
                } else {
                    badge.className = 'tag';
                    badge.style.background = 'rgba(142, 142, 147, 0.15)';
                    badge.style.color = 'var(--text-sec)';
                    badge.innerText = '未启用';
                }
            }

            renderClusterNodesTable();
        } catch (e) {
            console.error('加载集群节点失败:', e);
        }
    }

    async function toggleClusterSyncEnabled() {
        const toggle = document.getElementById('cluster-sync-enabled-toggle');
        const isEnabled = toggle ? toggle.checked : false;
        currentClusterSync.enabled = isEnabled;

        try {
            const res = await fetch('/api/settings', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    cluster_sync: currentClusterSync
                })
            });
            const data = await res.json();
            if (data.success) {
                showToast(isEnabled ? '已开启多机情报网格联防！' : '已关闭多机情报网格联防', isEnabled ? '🛡️' : '⏸️');
                loadClusterNodes();
            } else {
                showToast(data.msg || '更新失败', '⚠️');
            }
        } catch (e) {
            showToast('设置异常: ' + e, '⚠️');
        }
    }

    function generateRandomClusterSecret() {
        const arr = new Uint8Array(16);
        window.crypto.getRandomValues(arr);
        const sec = Array.from(arr).map(b => b.toString(16).padStart(2, '0')).join('');
        const secretInput = document.getElementById('cluster-sync-secret-input');
        if (secretInput) secretInput.value = sec;
        showToast('已随机生成 32 位安全通信密钥，请点击「保存设置」', '🎲');
    }

    function copyClusterSecret() {
        const sec = document.getElementById('cluster-sync-secret-input')?.value.trim();
        if (!sec) {
            showToast('密钥内容为空', '⚠️');
            return;
        }
        navigator.clipboard.writeText(sec).then(() => {
            showToast('集群通信密钥已复制到剪贴板', '📋');
        }).catch(() => {
            showToast('复制失败，请手动选择复制', '⚠️');
        });
    }

    async function saveClusterSecretOnly() {
        const sec = document.getElementById('cluster-sync-secret-input')?.value.trim() || '';
        const port = parseInt(document.getElementById('cluster-sync-port-input')?.value || '9098');
        currentClusterSync.cluster_secret = sec;
        currentClusterSync.port = port;
        try {
            showToast('正在保存集群通信网络设置...', '⏳');
            const res = await fetch('/api/settings', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    cluster_sync: currentClusterSync
                })
            });
            const data = await res.json();
            if (data.success) {
                showToast('集群通信端口与鉴权密钥保存成功！(需重启生效独立通信端口)', '🎉');
                loadClusterNodes();
            } else {
                showToast(data.msg || '保存失败', '⚠️');
            }
        } catch (e) {
            showToast('保存异常: ' + e, '⚠️');
        }
    }

    function openAddClusterNodeModal() {
        document.getElementById('cluster-node-add-ip').value = '';
        document.getElementById('cluster-node-add-port').value = currentClusterSync.port || 9098;
        document.getElementById('cluster-node-add-remark').value = '';
        document.getElementById('modal-add-cluster-node').style.display = 'flex';
        setTimeout(() => { document.getElementById('cluster-node-add-ip')?.focus(); }, 100);
    }

    async function submitAddClusterNode() {
        const ip = document.getElementById('cluster-node-add-ip')?.value.trim();
        const port = parseInt(document.getElementById('cluster-node-add-port')?.value || '9099');
        const remark = document.getElementById('cluster-node-add-remark')?.value.trim();

        if (!ip) {
            showToast('请输入服务器 IP 地址或域名', '⚠️');
            return;
        }

        const btn = document.getElementById('btn-submit-add-cluster-node');
        if (btn) { btn.disabled = true; btn.innerText = '⏳ 正在检测连通性并添加...'; }

        try {
            const res = await fetch('/api/cluster/nodes/add', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ ip: ip, port: port, remark: remark })
            });
            const data = await res.json();
            if (data.success) {
                showToast(data.msg || '协同节点添加成功！', '🎉');
                closeModals();
                loadClusterNodes();
            } else {
                showToast(data.msg || '添加失败', '⚠️');
            }
        } catch (e) {
            showToast('添加节点异常: ' + e, '⚠️');
        } finally {
            if (btn) { btn.disabled = false; btn.innerText = '➕ 确认添加并检测'; }
        }
    }

    async function deleteClusterNode(ip, port) {
        if (!confirm(`确定要移除协同服务器节点 ${ip}:${port} 吗？`)) return;
        try {
            showToast('正在移除节点...', '⏳');
            const res = await fetch('/api/cluster/nodes/delete', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ ip: ip, port: port })
            });
            const data = await res.json();
            if (data.success) {
                showToast(data.msg || '节点已成功移除', '🗑️');
                loadClusterNodes();
            } else {
                showToast(data.msg || '移除失败', '⚠️');
            }
        } catch (e) {
            showToast('移除异常: ' + e, '⚠️');
        }
    }

    async function editClusterNodeRemark(ip, port, currentRemark) {
        const newRemark = prompt(`请输入节点 [${ip}:${port}] 的备注标识名称:`, currentRemark || '');
        if (newRemark === null) return;
        const remarkVal = newRemark.trim();
        if (!remarkVal) {
            showToast('节点备注名称不能为空', '⚠️');
            return;
        }
        try {
            showToast('正在更新节点备注...', '⏳');
            const res = await fetch('/api/cluster/nodes/update_remark', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ ip: ip, port: port, remark: remarkVal })
            });
            const data = await res.json();
            if (data.success) {
                showToast(`🏷️ 节点备注已更新为: ${remarkVal}`, '🎉');
                loadClusterNodes();
            } else {
                showToast(data.msg || '更新失败', '⚠️');
            }
        } catch (e) {
            showToast('请求异常: ' + e, '⚠️');
        }
    }

    async function testSingleClusterNode(ip, port) {
        showToast(`正在探测节点 ${ip}:${port} 握手延迟...`, '⏳');
        // 临时标记状态
        const nodes = currentClusterSync.cluster_nodes || [];
        nodes.forEach(n => {
            if (n.ip === ip && (n.port || 9099) === port) n.status = 'testing';
        });
        renderClusterNodesTable();

        try {
            const res = await fetch('/api/cluster/nodes/test_single', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ ip: ip, port: port })
            });
            const data = await res.json();
            if (data.success) {
                showToast(`节点 ${ip}:${port} 连通正常 (延迟 ${data.latency_ms}ms)`, '✅');
            } else {
                showToast(`节点 ${ip}:${port} 握手失败，请检查端口与通信密钥`, '❌');
            }
            loadClusterNodes();
        } catch (e) {
            showToast('网络请求异常: ' + e, '⚠️');
            loadClusterNodes();
        }
    }

    async function testAllClusterNodes() {
        const btn = document.getElementById('btn-test-all-cluster-nodes');
        if (btn) { btn.disabled = true; btn.innerText = '⏳ 正在批量测速中...'; }
        showToast('正在向所有协同节点发送健康心跳...', '⚡');

        const nodes = currentClusterSync.cluster_nodes || [];
        nodes.forEach(n => n.status = 'testing');
        renderClusterNodesTable();

        try {
            const res = await fetch('/api/cluster/nodes/test_all', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({})
            });
            const data = await res.json();
            if (data.success) {
                currentClusterSync.cluster_nodes = data.nodes || [];
                renderClusterNodesTable();
                showToast('全节点连通性检测已完成！', '🎉');
            } else {
                showToast('全量检测失败', '⚠️');
                loadClusterNodes();
            }
        } catch (e) {
            showToast('检测异常: ' + e, '⚠️');
            loadClusterNodes();
        } finally {
            if (btn) { btn.disabled = false; btn.innerText = '⚡ 全节点连接检测'; }
        }
    }

    async function saveIntegratedPolicySettings() {
        const nodeName = document.getElementById('setting-policy-node-name')?.value.trim() || '本机节点';
        const scanThreshold = parseInt(document.getElementById('setting-policy-scan-threshold')?.value || '3');
        const scanWindow = parseInt(document.getElementById('setting-policy-scan-window')?.value || '15');
        const trapThreshold = parseInt(document.getElementById('setting-policy-trap-threshold')?.value || '2');
        const trapWindow = parseInt(document.getElementById('setting-policy-trap-window')?.value || '30');
        const autoClean = parseInt(document.getElementById('setting-policy-auto-clean')?.value || '30');
        const banIptables = document.getElementById('setting-policy-ban-iptables')?.checked !== false;
        const banBlackhole = document.getElementById('setting-policy-ban-blackhole')?.checked !== false;

        try {
            showToast('正在保存全局策略配置...', '⏳');
            const res = await fetch('/api/settings', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    node_name: nodeName,
                    enable_port_scan_defense: true,
                    port_scan_threshold: scanThreshold,
                    port_scan_window_seconds: scanWindow,
                    trap_threshold: trapThreshold,
                    trap_window_seconds: trapWindow,
                    auto_clean_days: autoClean,
                    ban_action_iptables: banIptables,
                    ban_action_blackhole: banBlackhole
                })
            });
            const data = await res.json();
            if (data.success) {
                showToast(data.msg || '全局防御策略已保存并立即生效！', '🎉');
                loadSystemSettings();
            } else {
                showToast(data.msg || '保存失败', '⚠️');
            }
        } catch (e) {
            showToast('保存策略异常: ' + e, '⚠️');
        }
    }

    async function loadHiddenIPsForPolicy() {
        try {
            const res = await fetch('/api/hidden-ips');
            const list = await res.json();
            const countEl = document.getElementById('hidden-ips-policy-count');
            const tbody = document.getElementById('hidden-ips-policy-tbody');
            if (countEl) countEl.innerText = list.length;
            if (!tbody) return;
            if (list.length === 0) {
                tbody.innerHTML = '<tr><td colspan="3" style="text-align: center; color: var(--text-sec); padding: 24px;">暂无隐藏过滤 IP</td></tr>';
                return;
            }
            let html = '';
            list.forEach(item => {
                const ipStr = typeof item === 'string' ? item : item.ip;
                const timeStr = typeof item === 'object' && item.created_at ? item.created_at : '--';
                html += `
                    <tr style="border-bottom: 1px solid var(--border-subtle);">
                        <td style="padding: 8px 12px; font-family: monospace; font-weight: 700; color: var(--text);">${escapeHtml(ipStr)}</td>
                        <td style="padding: 8px 12px; color: var(--text-sec); font-size: 11px;">${escapeHtml(timeStr)}</td>
                        <td style="padding: 8px 12px; text-align: right;">
                            <button class="action-btn danger" onclick="removeCustomHiddenIP('${jsEscape(ipStr)}')">取消隐藏</button>
                        </td>
                    </tr>
                `;
            });
            tbody.innerHTML = html;
        } catch (e) {
            console.error(e);
        }
    }

    async function removeCustomHiddenIP(ip) {
        if (!confirm(`确定要取消对 IP ${ip} 的审计隐藏吗？取消后该 IP 的访问日志将恢复显示。`)) return;
        try {
            const res = await fetch('/api/hidden-ips/remove', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ ip: ip })
            });
            const data = await res.json();
            if (data.success) {
                showToast(data.msg || `已恢复 IP ${ip} 的审计显示`, '✓');
                loadHiddenIPsForPolicy();
                fetch('/api/hidden-ips').then(r => r.json()).then(d => {
                    allHiddenIPs = d || [];
                    updateHiddenBadge(allHiddenIPs.length);
                    loadHiddenIPsForPolicy();
                    fetchData(false);
                });
            } else {
                showToast(data.msg || '取消隐藏失败', '⚠️');
            }
        } catch (e) {
            showToast('请求异常: ' + e, '⚠️');
        }
    }

    async function addCustomHiddenIPFromPolicy() {
        const input = document.getElementById('input-policy-hidden-ip');
        if (!input) return;
        const ip = input.value.trim();
        if (!ip) {
            showToast('请输入要隐藏的 IP 地址', '⚠️');
            return;
        }
        try {
            const res = await fetch('/api/hidden-ips/add', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ ip: ip })
            });
            const data = await res.json();
            if (data.success) {
                input.value = '';
                showToast(`已成功隐藏 IP: ${ip}`, '🚫');
                loadHiddenIPsForPolicy();
                fetchData(false);
            } else {
                showToast(data.msg || '添加隐藏失败', '⚠️');
            }
        } catch (e) {
            showToast('请求异常: ' + e, '⚠️');
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

    // 设置弹窗选项卡切换与隐藏 IP 列表管理
    let currentSettingsTab = 'defense';

    function switchSettingsTab(tabKey) {
        currentSettingsTab = tabKey;
        const btnDefense = document.getElementById('settings-tab-btn-defense');
        const btnHidden = document.getElementById('settings-tab-btn-hidden');
        const paneDefense = document.getElementById('settings-pane-defense');
        const paneHidden = document.getElementById('settings-pane-hidden');

        if (tabKey === 'defense') {
            if (btnDefense) {
                btnDefense.style.background = 'var(--card)';
                btnDefense.style.color = 'var(--text)';
                btnDefense.style.boxShadow = '0 1px 3px rgba(0,0,0,0.1)';
            }
            if (btnHidden) {
                btnHidden.style.background = 'transparent';
                btnHidden.style.color = 'var(--text-sec)';
                btnHidden.style.boxShadow = 'none';
            }
            if (paneDefense) paneDefense.style.display = 'flex';
            if (paneHidden) paneHidden.style.display = 'none';
        } else {
            if (btnHidden) {
                btnHidden.style.background = 'var(--card)';
                btnHidden.style.color = 'var(--text)';
                btnHidden.style.boxShadow = '0 1px 3px rgba(0,0,0,0.1)';
            }
            if (btnDefense) {
                btnDefense.style.background = 'transparent';
                btnDefense.style.color = 'var(--text-sec)';
                btnDefense.style.boxShadow = 'none';
            }
            if (paneDefense) paneDefense.style.display = 'none';
            if (paneHidden) paneHidden.style.display = 'flex';
            loadHiddenIPs();
        }
    }

    function updateHiddenBadge(count) {
        const badge = document.getElementById('badge-hidden-ips-count');
        if (badge) {
            badge.innerText = count || 0;
            if (count > 0) {
                badge.style.background = 'rgba(255, 149, 0, 0.2)';
                badge.style.color = 'var(--warning)';
            } else {
                badge.style.background = 'var(--card-sec)';
                badge.style.color = 'var(--text-sec)';
            }
        }
    }

    async function loadHiddenIPs() {
        try {
            const res = await fetch('/api/hidden-ips');
            const data = await res.json();
            allHiddenIPs = data || [];
            updateHiddenBadge(allHiddenIPs.length);
            renderHiddenIPsTable(allHiddenIPs);
        } catch (e) {
            console.error('加载隐藏 IP 失败:', e);
        }
    }

    function renderHiddenIPsTable(list) {
        const tbody = document.getElementById('hidden-ips-table-body');
        const countSpan = document.getElementById('hidden-ips-table-count');
        if (countSpan) countSpan.innerText = list.length;
        if (!tbody) return;

        if (!list || list.length === 0) {
            tbody.innerHTML = `
            <tr>
                <td colspan="3" style="text-align: center; padding: 28px 14px; color: var(--text-sec);">
                    <div style="font-size: 24px; margin-bottom: 6px;">🙈</div>
                    <div style="font-size: 13px; font-weight: 600;">暂无隐藏 IP</div>
                    <div style="font-size: 11px; margin-top: 2px;">在日志中点击任意 IP 详情卡片即可一键全局隐藏</div>
                </td>
            </tr>
            `;
            return;
        }

        let html = '';
        list.forEach(item => {
            const geoText = (item.country && item.country !== '未知地域') ? `${item.country} · ${item.city || item.region || item.isp || ''}` : (item.isp || '公网节点');
            html += `
            <tr style="border-bottom: 1px solid var(--border-subtle); transition: background 0.15s ease;" onmouseover="this.style.background='var(--card)'" onmouseout="this.style.background='transparent'">
                <td style="padding: 10px 12px;">
                    <div style="font-family: monospace; font-weight: 700; font-size: 13px; color: var(--text);">${escapeHtml(item.ip)}</div>
                    <div style="font-size: 11px; color: var(--text-sec); margin-top: 2px;">🌐 ${escapeHtml(geoText)}</div>
                </td>
                <td style="padding: 10px 12px; font-size: 11px; color: var(--text-sec); white-space: nowrap;">
                    ${escapeHtml(item.create_time || '--')}
                </td>
                <td style="padding: 10px 12px; text-align: right; white-space: nowrap;">
                    <button class="pill-btn danger" onclick="removeHiddenIP('${escapeHtml(item.ip)}')" style="padding: 4px 10px; font-size: 11px;" title="取消隐藏此 IP 并恢复其在前台全部日志与图表中的显示">
                        删除
                    </button>
                </td>
            </tr>
            `;
        });
        tbody.innerHTML = html;
    }

    async function addCustomHiddenIP() {
        const ipInput = document.getElementById('input-hidden-ip');
        const ip = (ipInput ? ipInput.value : '').trim();

        if (!ip) {
            showToast('请输入有效的 IP 地址', '⚠️');
            return;
        }

        try {
            const res = await fetch('/api/hidden-ips', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ ip, remark: '手动隐藏' })
            });
            const data = await res.json();
            if (data.success) {
                showToast(data.msg || `已全局隐藏 IP: ${ip}`, '🙈');
                if (ipInput) ipInput.value = '';
                loadHiddenIPs();
                fetchData(false);
            } else {
                showToast(data.msg || '添加隐藏失败', '⚠️');
            }
        } catch (e) {
            showToast('请求异常: ' + e, '⚠️');
        }
    }

    async function removeHiddenIP(ip) {
        try {
            const res = await fetch('/api/hidden-ips/remove', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ ip })
            });
            const data = await res.json();
            if (data.success) {
                showToast(data.msg || `已恢复显示 IP: ${ip} 的日志`, '👁️');
                loadHiddenIPs();
                fetchData(false);
            } else {
                showToast(data.msg || '移除失败', '⚠️');
            }
        } catch (e) {
            showToast('请求异常: ' + e, '⚠️');
        }
    }

    async function clearAllHiddenIPs() {
        if (!confirm('确定要清空全部隐藏 IP 规则吗？清空后所有被隐藏 IP 的日志和统计将全部恢复显示。')) {
            return;
        }
        try {
            const res = await fetch('/api/hidden-ips/clear', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({})
            });
            const data = await res.json();
            if (data.success) {
                showToast(data.msg || '已清空所有隐藏 IP 规则', '🎉');
                allHiddenIPs = [];
                updateHiddenBadge(0);
                loadHiddenIPsForPolicy();
                loadHiddenIPs();
                fetchData(false);
            } else {
                showToast(data.msg || '清空失败', '⚠️');
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

    // 全局禁止手势双指缩放、多指触控拖动及双击放大
    document.addEventListener('gesturestart', function(e) { e.preventDefault(); }, { passive: false });
    document.addEventListener('gesturechange', function(e) { e.preventDefault(); }, { passive: false });
    document.addEventListener('gestureend', function(e) { e.preventDefault(); }, { passive: false });

    document.addEventListener('touchmove', function(e) {
        if (e.touches && e.touches.length > 1) {
            e.preventDefault();
        }
    }, { passive: false });

    let _lastTouchEnd = 0;
    document.addEventListener('touchend', function(e) {
        const now = Date.now();
        if (now - _lastTouchEnd <= 300) {
            e.preventDefault();
        }
        _lastTouchEnd = now;
    }, { passive: false });

    document.addEventListener('DOMContentLoaded', () => {
        applyTheme(currentThemeMode, false);
        initCharts();
        fetchData(false);
        startAutoRefresh();
        const thresholdSelect = document.getElementById('setting-trap-threshold');
        if (thresholdSelect) {
            thresholdSelect.addEventListener('change', updateThresholdBadge);
        }

        // 点击页面任意空白背景或卡片外部空白时，自动还原所有图表的分类聚焦状态
        document.addEventListener('click', (e) => {
            if (e.target.tagName === 'CANVAS' || e.target.closest('button') || e.target.closest('input') || e.target.closest('select') || e.target.closest('a')) {
                return;
            }
            [
                trendChartInstance, portChartInstance, analyticsTrendChartInstance,
                analyticsHourlyChartInstance, analyticsGeoChartInstance, analyticsIspChartInstance,
                analyticsCategoryChartInstance, analyticsActionChartInstance, analyticsLevelChartInstance,
                analyticsHttpStatusChartInstance
            ].forEach(chart => {
                if (chart && (chart._selectedCategoryIndex >= 0 || chart._selectedDatasetIndex >= 0 || chart._selectedPointIndex >= 0)) {
                    if (typeof chart.resetCategoryFocus === 'function') {
                        chart.resetCategoryFocus();
                    }
                }
            });
        });
    });
</script>
<div style="position:absolute;left:-9999px;top:-9999px;width:1px;height:1px;overflow:hidden;" aria-hidden="true">
    <a href="/admin_internal_backup/" rel="nofollow" tabindex="-1">System Backup Archive</a>
    <a href="/system-debug-console/" rel="nofollow" tabindex="-1">Internal Debug Console</a>
    <a href="/backup_internal_2026.tar.gz" rel="nofollow" tabindex="-1">Production Database Dump</a>
</div>
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
                    "Disallow: /.env_backup\n"
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
                ban_ip(client_ip, reason=f"Web金丝雀蜜标命中: 爬虫嗅探隐藏诱饵 ({canary_desc})", category="canary", level="极高危")
                self.send_response(404)
                self.send_header('Content-Type', 'text/html; charset=utf-8')
                self.end_headers()
                self.wfile.write(b"<h1>404 Not Found</h1>")
                return

            if path in ("/", "/index.html"):
                self._send_html(HTML_TEMPLATE)
                return

            if path == "/api/stats":
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
                
                # 国家排行 Top 5
                c.execute("""
                SELECT country, COUNT(*) as cnt 
                FROM events 
                WHERE country IS NOT NULL AND country != '' AND ip NOT IN (SELECT ip FROM hidden_ips)
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
                    c.execute("SELECT COUNT(*) FROM events WHERE timestamp >= ? AND timestamp < ? AND ip NOT IN (SELECT ip FROM hidden_ips)", (hour_start, hour_end))
                    labels.append(hour_label)
                    data_points.append(c.fetchone()[0])
                    
                cfg = load_config()
                conn.close()
                
                raw_traps = cfg.get("trap_ports", DEFAULT_CONFIG["trap_ports"])
                active_traps = sum(1 for t in raw_traps if (t.get("enabled", True) if isinstance(t, dict) else True))
                whitelist_count = len(cfg.get("whitelist", []))
                hidden_ips_cnt = len(get_hidden_ips_set())
                
                self._send_json({
                    "total_banned": total_banned,
                    "today_events": today_events,
                    "active_traps": active_traps,
                    "whitelist_count": whitelist_count,
                    "hidden_count": hidden_ips_cnt,
                    "defense_paused": bool(cfg.get("defense_paused", False)),
                    "port_distribution": port_dist,
                    "geo_rank": geo_rank,
                    "hourly_trend": {
                        "labels": labels,
                        "data": data_points
                    }
                })
                return

            if path == "/api/analytics":
                query_params = parse_qs(parsed.query)
                range_param = query_params.get("range", ["7d"])[0]
                now_ts = int(time.time())

                if range_param == "24h":
                    cutoff_ts = now_ts - 86400
                    step_seconds = 3600
                    num_steps = 24
                    date_format = "%H:00"
                elif range_param == "30d":
                    cutoff_ts = now_ts - 30 * 86400
                    step_seconds = 86400
                    num_steps = 30
                    date_format = "%m/%d"
                elif range_param == "all":
                    cutoff_ts = 0
                    step_seconds = 86400
                    num_steps = 30
                    date_format = "%m/%d"
                else: # 7d
                    cutoff_ts = now_ts - 7 * 86400
                    step_seconds = 86400
                    num_steps = 7
                    date_format = "%m/%d"

                conn = get_db()
                c = conn.cursor()

                c.execute("SELECT COUNT(*) FROM port_access_logs WHERE timestamp >= ? AND ip NOT IN (SELECT ip FROM hidden_ips)", (cutoff_ts,))
                total_probes = c.fetchone()[0]

                c.execute("SELECT COUNT(*) FROM events WHERE timestamp >= ? AND ip NOT IN (SELECT ip FROM hidden_ips)", (cutoff_ts,))
                total_intercepted = c.fetchone()[0]

                c.execute("SELECT COUNT(DISTINCT ip) FROM events WHERE timestamp >= ? AND ip NOT IN (SELECT ip FROM hidden_ips)", (cutoff_ts,))
                unique_attackers = c.fetchone()[0]

                c.execute("SELECT COUNT(DISTINCT country) FROM events WHERE timestamp >= ? AND country NOT IN ('分析中...', '', '未知地域', 'Localhost', '本地回环') AND ip NOT IN (SELECT ip FROM hidden_ips)", (cutoff_ts,))
                unique_countries = c.fetchone()[0]

                c.execute("SELECT COUNT(*) FROM access_logs WHERE timestamp >= ? AND ip NOT IN (SELECT ip FROM hidden_ips)", (cutoff_ts,))
                total_web_requests = c.fetchone()[0]

                c.execute("SELECT COUNT(*) FROM access_logs WHERE timestamp >= ? AND (status_code >= 400 OR path LIKE '%.env%' OR path LIKE '%.git%' OR path LIKE '%php%' OR path LIKE '%admin%' OR path LIKE '%actuator%') AND ip NOT IN (SELECT ip FROM hidden_ips)", (cutoff_ts,))
                abnormal_web_requests = c.fetchone()[0]

                ban_rate = round((total_intercepted / total_probes * 100), 1) if total_probes > 0 else (100.0 if total_intercepted > 0 else 0.0)

                labels = []
                events_trend = []
                probes_trend = []
                web_trend = []
                for i in range(num_steps - 1, -1, -1):
                    s_ts = now_ts - ((i + 1) * step_seconds)
                    e_ts = now_ts - (i * step_seconds)
                    label = time.strftime(date_format, time.localtime(e_ts))
                    labels.append(label)

                    c.execute("SELECT COUNT(*) FROM events WHERE timestamp >= ? AND timestamp < ? AND ip NOT IN (SELECT ip FROM hidden_ips)", (s_ts, e_ts))
                    events_trend.append(c.fetchone()[0])

                    c.execute("SELECT COUNT(*) FROM port_access_logs WHERE timestamp >= ? AND timestamp < ? AND ip NOT IN (SELECT ip FROM hidden_ips)", (s_ts, e_ts))
                    probes_trend.append(c.fetchone()[0])

                    c.execute("SELECT COUNT(*) FROM access_logs WHERE timestamp >= ? AND timestamp < ? AND ip NOT IN (SELECT ip FROM hidden_ips)", (s_ts, e_ts))
                    web_trend.append(c.fetchone()[0])

                c.execute("SELECT strftime('%H', datetime(timestamp, 'unixepoch', 'localtime')) AS hr, COUNT(*) as cnt FROM events WHERE timestamp >= ? AND ip NOT IN (SELECT ip FROM hidden_ips) GROUP BY hr ORDER BY hr ASC", (cutoff_ts,))
                hourly_map = {row[0]: row[1] for row in c.fetchall() if row[0] is not None}
                hourly_dist = [{"hour": f"{h:02d}:00", "count": hourly_map.get(f"{h:02d}", 0)} for h in range(24)]

                c.execute("SELECT country, COUNT(*) as cnt FROM events WHERE timestamp >= ? AND country NOT IN ('分析中...', '', '未知地域', 'Localhost', '本地回环') AND ip NOT IN (SELECT ip FROM hidden_ips) GROUP BY country ORDER BY cnt DESC LIMIT 8", (cutoff_ts,))
                geo_countries = [{"country": row[0], "count": row[1]} for row in c.fetchall()]

                c.execute("SELECT isp, COUNT(*) as cnt FROM events WHERE timestamp >= ? AND isp NOT IN ('分析中...', '', 'Private LAN', 'Localhost', '未知') AND ip NOT IN (SELECT ip FROM hidden_ips) GROUP BY isp ORDER BY cnt DESC LIMIT 8", (cutoff_ts,))
                geo_isps = [{"isp": row[0], "count": row[1]} for row in c.fetchall()]

                c.execute("SELECT category, COUNT(*) as cnt FROM events WHERE timestamp >= ? AND ip NOT IN (SELECT ip FROM hidden_ips) GROUP BY category ORDER BY cnt DESC", (cutoff_ts,))
                category_dist = [{"category": row[0], "count": row[1]} for row in c.fetchall()]

                c.execute("SELECT port, port_name, COUNT(*) as cnt FROM events WHERE timestamp >= ? AND ip NOT IN (SELECT ip FROM hidden_ips) GROUP BY port ORDER BY cnt DESC LIMIT 8", (cutoff_ts,))
                port_dist = [{"port": row[0], "name": row[1] or f"端口 {row[0]}", "count": row[2]} for row in c.fetchall()]

                c.execute("SELECT action, COUNT(*) as cnt FROM port_access_logs WHERE timestamp >= ? AND ip NOT IN (SELECT ip FROM hidden_ips) GROUP BY action ORDER BY cnt DESC", (cutoff_ts,))
                action_dist = [{"action": row[0], "count": row[1]} for row in c.fetchall()]

                c.execute("SELECT level, COUNT(*) as cnt FROM events WHERE timestamp >= ? AND ip NOT IN (SELECT ip FROM hidden_ips) GROUP BY level ORDER BY cnt DESC", (cutoff_ts,))
                level_dist = [{"level": row[0], "count": row[1]} for row in c.fetchall()]

                c.execute("SELECT status_code, COUNT(*) as cnt FROM access_logs WHERE timestamp >= ? AND ip NOT IN (SELECT ip FROM hidden_ips) GROUP BY status_code ORDER BY cnt DESC", (cutoff_ts,))
                http_status_dist = [{"code": str(row[0]), "count": row[1]} for row in c.fetchall()]

                c.execute("""
                    SELECT path, method, COUNT(*) as cnt 
                    FROM access_logs 
                    WHERE timestamp >= ? AND ip NOT IN (SELECT ip FROM hidden_ips)
                    GROUP BY path 
                    ORDER BY 
                        (CASE WHEN status_code >= 400 OR path LIKE '%.env%' OR path LIKE '%.git%' OR path LIKE '%php%' OR path LIKE '%admin%' OR path LIKE '%actuator%' OR path LIKE '%api%' OR path LIKE '%.sql%' OR path LIKE '%swagger%' OR path LIKE '%shell%' THEN 1 ELSE 0 END) DESC,
                        cnt DESC 
                    LIMIT 10
                """, (cutoff_ts,))
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
                    WHERE timestamp >= ? 
                      AND user_agent IS NOT NULL 
                      AND TRIM(user_agent) NOT IN ('', '-', 'null', 'None', 'undefined')
                    GROUP BY user_agent 
                    ORDER BY cnt DESC 
                    LIMIT 300
                """, (cutoff_ts,))
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
                    WHERE timestamp >= ? AND ip NOT IN (SELECT ip FROM hidden_ips)
                    GROUP BY ip 
                    ORDER BY hits DESC 
                    LIMIT 10
                """, (cutoff_ts,))
                attacker_rows = c.fetchall()

                c.execute("SELECT DISTINCT ip FROM blacklist WHERE ip NOT IN (SELECT ip FROM hidden_ips)")
                banned_ips_set = set(r[0] for r in c.fetchall())

                top_attackers = []
                for row in attacker_rows:
                    top_attackers.append({
                        "ip": row[0],
                        "country": row[1] or "未知",
                        "isp": row[2] or "未知",
                        "level": row[3] or "极高危",
                        "hit_count": row[4],
                        "last_seen": row[5] or "--",
                        "ports": row[6] or "--",
                        "is_banned": row[0] in banned_ips_set
                    })

                conn.close()

                self._send_json({
                    "range": range_param,
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
            if path == "/api/settings":
                cfg = load_config()
                self._send_json({
                    "trap_threshold": int(cfg.get("trap_threshold", 2) or 2),
                    "trap_window_seconds": int(cfg.get("trap_window_seconds", 30) or 30),
                    "auto_clean_days": int(cfg.get("auto_clean_days", 30) if cfg.get("auto_clean_days") is not None else 30),
                    "defense_mode": cfg.get("defense_mode", "standard"),
                    "enable_port_scan_defense": bool(cfg.get("enable_port_scan_defense", True)),
                    "port_scan_threshold": int(cfg.get("port_scan_threshold", 3) or 3),
                    "port_scan_window_seconds": int(cfg.get("port_scan_window_seconds", 15) or 15),
                    "trap_all_ports": bool(cfg.get("trap_all_ports", False)),
                    "trap_all_unopened_ports": bool(cfg.get("trap_all_unopened_ports", False)),
                    "trap_business_ports": bool(cfg.get("trap_business_ports", False)),
                    "ban_action_iptables": bool(cfg.get("ban_action_iptables", True)),
                    "ban_action_blackhole": bool(cfg.get("ban_action_blackhole", True)),
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

            if path == "/api/cluster/nodes":
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
                self._send_json({
                    "enabled": bool(cluster_cfg.get("enabled", False)),
                    "port": int(cluster_cfg.get("port", 9098) or 9098),
                    "cluster_secret": cluster_cfg.get("cluster_secret", ""),
                    "nodes": norm_nodes
                })
                return

            if path in ("/api/hidden-ips", "/api/hidden_ips", "/api/hidden-ips/export", "/api/hidden_ips/export"):
                hidden_list = get_hidden_ips()
                self._send_json(hidden_list)
                return

            if path == "/api/events":
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

            if path == "/api/ip_info":
                query = parse_qs(parsed.query)
                ip = query.get("ip", [""])[0].strip()
                if not ip:
                    self._send_json({"country": "未知地域", "region": "", "city": "", "isp": ""})
                    return
                geo = resolve_ip_geo(ip)
                self._send_json(geo)
                return

            if path == "/api/blacklist":
                conn = get_db()
                c = conn.cursor()
                c.execute("SELECT ip, reason, country, level, ban_time, timestamp, source_node FROM blacklist WHERE ip NOT IN (SELECT ip FROM hidden_ips) ORDER BY timestamp DESC")
                rows = [dict(r) for r in c.fetchall()]
                conn.close()
                for r in rows:
                    ip_k = r["ip"]
                    geo = _GEO_CACHE.get(ip_k) or resolve_ip_geo_local(ip_k) or {}
                    if geo.get("country") and geo["country"] not in ("未知地域", "公网节点", "", None):
                        r["country"] = geo["country"]
                        r["region"] = geo.get("region", "")
                        r["city"] = geo.get("city", "")
                        r["isp"] = geo.get("isp", "")
                    else:
                        r["country"] = r.get("country") or "公网节点"
                        r["region"] = r.get("region", "")
                        r["city"] = r.get("city", "")
                        r["isp"] = r.get("isp", "")
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

            if path in ("/api/business_ports", "/api/business_ports/export"):
                biz_list = get_all_business_ports_info()
                self._send_json(biz_list)
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
                c.execute("SELECT ip, reason, country, level, ban_time, timestamp FROM blacklist WHERE ip NOT IN (SELECT ip FROM hidden_ips) ORDER BY timestamp DESC")
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

                cfg = load_config()
                node_name = cfg.get("node_name", "本机") or "本机"
                unban_ip_core(ip, status_event="UNBANNED", source_node=f"手动解封({node_name})")
                # 广播解封至全网集群协同节点
                broadcast_cluster_unban(ip)
                self._send_json({"success": True, "msg": f"已成功从内核黑名单与防火墙中解封 IP: {ip}（已同步全网集群协同解封）"})
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

                self._send_json({
                    "success": True,
                    "added_bans": added_bans,
                    "added_whites": added_whites,
                    "remote_blacklist": missing_for_remote_bans,
                    "remote_unbanned": local_unbanned_resp,
                    "remote_whitelist": missing_for_remote_whites
                })
                return

            if path in ("/api/cluster/sync_all_mesh", "/api/cluster/sync_all_blacklist"):
                res = sync_cluster_mesh_state()
                self._send_json(res)
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

            if path == "/api/cluster/sync_all_whitelist":
                cfg = load_config()
                cluster_cfg = cfg.get("cluster_sync", {})
                if not cluster_cfg.get("enabled", False):
                    self._send_json({"success": False, "msg": "集群联防协同功能未开启"}, status=400)
                    return
                nodes = cluster_cfg.get("cluster_nodes", [])
                if not nodes:
                    self._send_json({"success": False, "msg": "当前未配置任何集群协同节点"}, status=400)
                    return
                whitelist = cfg.get("whitelist", [])
                broadcast_cluster_whitelist("sync_all", whitelist, "全网协同全量同步")
                self._send_json({"success": True, "msg": f"已向 {len(nodes)} 个集群节点广播全量白名单 (共 {len(whitelist)} 条规则)"})
                return

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

            if path == "/api/cluster/test_node":
                node_url = req_data.get("node_url", "").strip().rstrip("/")
                secret = req_data.get("secret", "").strip()
                if not node_url:
                    self._send_json({"success": False, "msg": "节点地址不能为空"}, status=400)
                    return
                if not secret:
                    self._send_json({"success": False, "msg": "通信密钥不能为空"}, status=400)
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
                            self._send_json({
                                "success": True,
                                "node_name": res_data.get("node_name", "远程节点"),
                                "latency_ms": latency,
                                "msg": f"连接成功！节点响应正常 (延迟 {latency}ms)"
                            })
                        else:
                            self._send_json({
                                "success": False,
                                "msg": res_data.get("msg", "鉴权失败")
                            })
                except urllib.error.HTTPError as e:
                    self._send_json({"success": False, "msg": f"HTTP {e.code}: 鉴权失败或密钥不一致"})
                except Exception as e:
                    self._send_json({"success": False, "msg": f"连接超时或无法访问 ({e})"})
                return

            if path == "/api/cluster/nodes/add":
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
                    self._send_json({"success": False, "msg": "节点 IP 或域名不能为空"}, status=400)
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
                self._send_json({
                    "success": True, 
                    "msg": f"协同节点 {ip_raw}:{port} 已成功添加！" if not updated else f"协同节点 {ip_raw}:{port} 配置已更新！",
                    "node": node_obj,
                    "nodes": new_list
                })
                return

            if path == "/api/cluster/nodes/delete":
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
                self._send_json({"success": True, "msg": f"协同节点 {ip_raw} 已成功移除", "nodes": new_list})
                return

            if path == "/api/cluster/nodes/update_remark":
                ip_raw = str(req_data.get("ip", "")).strip()
                port = int(req_data.get("port", 9098) or 9098)
                new_remark = str(req_data.get("remark", "")).strip()
                if not new_remark:
                    self._send_json({"success": False, "msg": "节点备注名称不能为空"}, 400)
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
                    self._send_json({"success": True, "msg": f"节点 {ip_raw}:{port} 备注已更新为: {new_remark}", "nodes": existing})
                else:
                    self._send_json({"success": False, "msg": "未找到匹配的协同节点"}, 404)
                return

            if path == "/api/cluster/nodes/test_all":
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
                self._send_json({"success": True, "nodes": updated_nodes})
                return

            if path == "/api/cluster/nodes/test_single":
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
                    req = urllib.request.Request(target, data=b"{}", headers={
                        "Content-Type": "application/json",
                        "X-Cluster-Token": token,
                        "User-Agent": "PortGuardMesh/2.0"
                    })
                    t0 = time.time()
                    with urllib.request.urlopen(req, timeout=3.0) as resp:
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
                
                self._send_json({
                    "success": (status == "online"),
                    "status": status,
                    "latency_ms": latency_ms,
                    "node_name": node_name
                })
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

                ban_ip(ip, reason=reason, category="manual", level="极高危")
                self._send_json({"success": True, "msg": f"已成功封禁 IP: {ip}（已下发内核防火墙并同步全网集群阻断）"})
                return

            if path == "/api/defense/toggle_pause":
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
                    # 仅释放 PortGuard 自身添加的黑洞路由与黑名单拦截规则，绝不触碰系统全局防火墙与 Docker/宝塔规则！
                    run_firewall_cmd("ip", "route", "flush", "type", "blackhole")
                    try:
                        conn = get_db()
                        c = conn.cursor()
                        c.execute("SELECT ip FROM blacklist")
                        for row in c.fetchall():
                            b_ip = row[0]
                            if b_ip:
                                run_firewall_cmd("iptables", "-D", "INPUT", "-s", b_ip, "-j", "DROP")
                        conn.close()
                    except Exception:
                        pass
                    msg = "PortGuard 防御拦截已成功暂停！系统进入纯观察模式（Web控制台正常运行，系统iptables不受影响）。"
                else:
                    msg = "PortGuard 防御拦截已成功恢复！蜜罐嗅探与实时阻断已重新激活。"

                self._send_json({"success": True, "paused": is_paused, "msg": msg})
                return

            if path == "/api/settings":
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
                if "trap_business_ports" in req_data:
                    cfg["trap_business_ports"] = bool(req_data["trap_business_ports"])
                if "trap_all_unopened_ports" in req_data:
                    cfg["trap_all_unopened_ports"] = bool(req_data["trap_all_unopened_ports"])
                if "trap_all_ports" in req_data:
                    cfg["trap_all_ports"] = bool(req_data["trap_all_ports"])
                if "defense_paused" in req_data:
                    cfg["defense_paused"] = bool(req_data["defense_paused"])
                if "cluster_sync" in req_data and isinstance(req_data["cluster_sync"], dict):
                    cfg["cluster_sync"] = req_data["cluster_sync"]
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

                    cfg_import = load_config()
                    node_name = cfg_import.get("node_name", "本机") or "本机"
                    c.execute("""
                    INSERT OR REPLACE INTO blacklist (ip, reason, country, level, ban_time, timestamp, ban_expire, source_node)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """, (ip, reason, country, level, ban_time, now_ts, None, f"批量导入 ({node_name})"))
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
                
                valid_ip = validate_ip(ip)
                if not valid_ip:
                    self._send_json({"success": False, "msg": "IP 格式不合法"}, status=400)
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
                self._send_json({"success": True, "msg": f"已成功将 {ip} 加入信任白名单{extra_tip}！"})
                return

            if path == "/api/whitelist/delete":
                ip = req_data.get("ip", "").strip()
                cfg = load_config()
                cfg["whitelist"] = [w for w in cfg.get("whitelist", []) if (w.get("ip") if isinstance(w, dict) else w) != ip]
                save_config(cfg)
                # 广播至集群协同节点
                broadcast_cluster_whitelist("delete", ip)
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
                    self._send_json({"success": False, "msg": "未能提取到有效的 IP 白名单项"}, status=400)
                    return
                    
                new_whitelist = list(current_map.values())
                cfg["whitelist"] = new_whitelist
                save_config(cfg)
                # 广播批量导入至集群协同节点
                broadcast_cluster_whitelist("batch_add", new_whitelist, "批量导入同步")
                unban_tip = f"，并同步解除 {unbanned_count} 个原黑名单目标" if unbanned_count > 0 else ""
                self._send_json({
                    "success": True,
                    "msg": f"信任白名单导入成功！共载入 {success_count} 条规则{unban_tip} (当前总计 {len(current_map)} 条)",
                    "count": success_count,
                    "unbanned_count": unbanned_count,
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

            if path == "/api/business_ports/add":
                port_raw = req_data.get("port")
                if not port_raw:
                    self._send_json({"success": False, "msg": "端口号不能为空"}, status=400)
                    return
                try:
                    port = int(port_raw)
                    if port < 1 or port > 65535:
                        raise ValueError()
                except Exception:
                    self._send_json({"success": False, "msg": "端口号必须为 1-65535 的整数"}, status=400)
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
                        self._send_json({"success": False, "msg": f"业务端口 {port} 已存在，无需重复添加"}, status=400)
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
                self._send_json({"success": True, "msg": f"已成功添加正常业务端口: {port} ({name})"})
                return

            if path == "/api/business_ports/edit":
                port_raw = req_data.get("port")
                if not port_raw:
                    self._send_json({"success": False, "msg": "端口号不能为空"}, status=400)
                    return
                try:
                    port = int(port_raw)
                except Exception:
                    self._send_json({"success": False, "msg": "无效端口号"}, status=400)
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
                self._send_json({"success": True, "msg": f"已成功更新业务端口: {port}"})
                return

            if path == "/api/business_ports/delete":
                port_raw = req_data.get("port")
                if not port_raw:
                    self._send_json({"success": False, "msg": "端口号不能为空"}, status=400)
                    return
                try:
                    port = int(port_raw)
                except Exception:
                    self._send_json({"success": False, "msg": "无效端口号"}, status=400)
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
                self._send_json({"success": True, "msg": f"已成功删除业务端口: {port}"})
                return

            if path == "/api/business_ports/import":
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
                    self._send_json({"success": False, "msg": "未解析到有效的业务端口数据，请检查格式"}, status=400)
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
                    self._send_json({"success": False, "msg": "未能提取到任何合法业务端口（端口必须为 1-65535）"}, status=400)
                    return
                cfg["business_ports"] = list(current_map.values())
                # 导入的端口全部从 excluded_business_ports 解除排除
                excluded = set(int(p) for p in cfg.get("excluded_business_ports", []) if str(p).isdigit())
                for p in current_map.keys():
                    if p in excluded:
                        excluded.remove(p)
                cfg["excluded_business_ports"] = sorted(list(excluded))
                save_config(cfg)
                self._send_json({
                    "success": True,
                    "msg": f"业务端口列表导入成功！共载入 {count} 条 (当前自定义总计 {len(current_map)} 条)",
                    "count": count,
                    "total": len(current_map)
                })
                return

            if path in ("/api/hidden-ips", "/api/hidden_ips"):
                action = req_data.get("action", "add")
                ip = req_data.get("ip", "").strip()
                if not ip:
                    self._send_json({"success": False, "msg": "IP 不能为空"}, status=400)
                    return
                if action == "remove":
                    ok, msg = remove_hidden_ip(ip)
                else:
                    remark = req_data.get("remark", "").strip()
                    ok, msg = add_hidden_ip(ip, remark)
                self._send_json({"success": ok, "msg": msg})
                return

            if path in ("/api/hidden-ips/remove", "/api/hidden_ips/remove", "/api/hidden-ips/delete", "/api/hidden_ips/delete"):
                ip = req_data.get("ip", "").strip()
                if not ip:
                    self._send_json({"success": False, "msg": "IP 不能为空"}, status=400)
                    return
                ok, msg = remove_hidden_ip(ip)
                self._send_json({"success": ok, "msg": msg})
                return

            if path in ("/api/hidden-ips/clear", "/api/hidden_ips/clear"):
                ok, msg = clear_hidden_ips()
                self._send_json({"success": ok, "msg": msg})
                return

            if path in ("/api/hidden-ips/import", "/api/hidden_ips/import"):
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
                    self._send_json({"success": False, "msg": "未解析到有效的 IP 数据，请检查格式"}, status=400)
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
                self._send_json({"success": True, "msg": f"成功{'全量覆盖' if mode=='replace' else '增量导入'} {count} 条隐藏 IP 规则"})
                return

            self._send_json({"error": "Not Found"}, status=404)
        except Exception as e:
            self._send_json({"error": str(e)}, status=500)

    def do_DELETE(self):
        try:
            parsed = urlparse(self.path)
            path = parsed.path
            length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(length).decode('utf-8') if length > 0 else "{}"
            try:
                req_data = json.loads(body)
            except Exception:
                req_data = {}

            if path in ("/api/hidden-ips", "/api/hidden_ips"):
                ip = req_data.get("ip", "").strip()
                if not ip:
                    query = parse_qs(parsed.query)
                    ip = query.get("ip", [""])[0].strip()
                if not ip:
                    self._send_json({"success": False, "msg": "IP 不能为空"}, status=400)
                    return
                ok, msg = remove_hidden_ip(ip)
                self._send_json({"success": ok, "msg": msg})
                return

            self._send_json({"error": "Not Found"}, status=404)
        except Exception as e:
            self._send_json({"error": str(e)}, status=500)

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
