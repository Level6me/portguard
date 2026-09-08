# -*- coding: utf-8 -*-
import os
import re
import json
import threading

TEMPLATES_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "templates")

# 黑名单全局极速内存缓存（毫秒级响应，防全量离线库二次计算卡顿）
_BLACKLIST_CACHE = None
_BLACKLIST_CACHE_TIME = 0.0
_BLACKLIST_CACHE_LOCK = threading.Lock()

def invalidate_blacklist_cache():
    global _BLACKLIST_CACHE, _BLACKLIST_CACHE_TIME
    with _BLACKLIST_CACHE_LOCK:
        _BLACKLIST_CACHE = None
        _BLACKLIST_CACHE_TIME = 0.0

def get_blacklist_cache():
    global _BLACKLIST_CACHE, _BLACKLIST_CACHE_TIME
    with _BLACKLIST_CACHE_LOCK:
        return _BLACKLIST_CACHE, _BLACKLIST_CACHE_TIME

def set_blacklist_cache(data, cache_time):
    global _BLACKLIST_CACHE, _BLACKLIST_CACHE_TIME
    with _BLACKLIST_CACHE_LOCK:
        _BLACKLIST_CACHE = data
        _BLACKLIST_CACHE_TIME = cache_time

def load_report_template():
    report_path = os.path.join(TEMPLATES_DIR, "report.html")
    if not os.path.exists(report_path):
        alt_path = os.path.join(os.path.dirname(TEMPLATES_DIR), "report.html")
        if os.path.exists(alt_path):
            report_path = alt_path
    if os.path.exists(report_path):
        try:
            with open(report_path, "r", encoding="utf-8") as f:
                return f.read()
        except Exception:
            pass
    return ""

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
    cleaned = re.sub(r"//.*", "", cleaned)
    cleaned = re.sub(r"/\*[\s\S]*?\*/", "", cleaned)
    cleaned = re.sub(r",\s*([\]\}])", r"\1", cleaned)
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
        if not line or line.startswith("#") or line.startswith("//"):
            continue
        try:
            line_obj = json.loads(re.sub(r",\s*$", "", line))
            results.append(line_obj)
        except Exception:
            results.append(line)
    return results

def parse_post_json(req, body_bytes):
    if not body_bytes:
        return {}
    try:
        return json.loads(body_bytes.decode("utf-8"))
    except Exception:
        try:
            return json.loads(body_bytes.decode("latin1"))
        except Exception:
            return {}
