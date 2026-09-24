#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PortGuard Core Notification & Feishu Bot Alert Engine
飞书自定义机器人告警、交互式卡片渲染与多通道即时通知
"""
import base64
import hashlib
import hmac
import json
import socket
import threading
import time
import urllib.request
import urllib.error

# 颜色定义对照表（Feishu 官方卡片主题色）
# blue: 信息, turquoise: 业务/自愈放行, red/carmine: 高危拦截, orange: 警告
FEISHU_COLOR_MAP = {
    "info": "blue",
    "success": "turquoise",
    "warning": "orange",
    "danger": "carmine",
    "critical": "red"
}

_NOTIFY_EXECUTOR = None
_EXECUTOR_LOCK = threading.Lock()

def get_notify_executor():
    global _NOTIFY_EXECUTOR
    if _NOTIFY_EXECUTOR is None:
        with _EXECUTOR_LOCK:
            if _NOTIFY_EXECUTOR is None:
                from concurrent.futures import ThreadPoolExecutor
                _NOTIFY_EXECUTOR = ThreadPoolExecutor(max_workers=4, thread_name_prefix="NotifyWorker")
    return _NOTIFY_EXECUTOR

def generate_feishu_signature(secret, timestamp):
    """根据飞书开放平台规范计算加签密钥"""
    if not secret:
        return None
    string_to_sign = f"{timestamp}\n{secret}"
    hmac_code = hmac.new(string_to_sign.encode("utf-8"), digestmod=hashlib.sha256).digest()
    return base64.b64encode(hmac_code).decode("utf-8")

def send_feishu_webhook(webhook_url, secret=None, card_title="PortGuard 安全告警", content_text="", fields=None, color="blue", timeout=6):
    """
    向飞书自定义机器人发送交互式富文本卡片通知。
    支持 HMAC-SHA256 加签鉴权，返回 (success: bool, msg: str)。
    """
    if not webhook_url or not str(webhook_url).strip():
        return False, "未配置飞书机器人 Webhook URL"

    webhook_url = str(webhook_url).strip()
    if not (webhook_url.startswith("http://") or webhook_url.startswith("https://")):
        return False, "Webhook URL 格式不正确，必须以 http:// 或 https:// 开头"

    now_ts = int(time.time())
    template_color = FEISHU_COLOR_MAP.get(color, color)

    card = {
        "config": {
            "wide_screen_mode": True,
            "enable_forward": True
        },
        "header": {
            "title": {
                "tag": "plain_text",
                "content": card_title
            },
            "template": template_color
        },
        "elements": [
            {
                "tag": "div",
                "text": {
                    "tag": "lark_md",
                    "content": content_text or "PortGuard 安全守护事件通知"
                }
            }
        ]
    }

    if fields and isinstance(fields, (list, tuple)):
        field_elements = []
        for item in fields:
            if isinstance(item, (list, tuple)) and len(item) >= 2:
                k, v = str(item[0]), str(item[1])
                field_elements.append({
                    "is_short": True,
                    "text": {
                        "tag": "lark_md",
                        "content": f"**{k}**\n{v}"
                    }
                })
        if field_elements:
            card["elements"].append({"tag": "hr"})
            card["elements"].append({
                "tag": "div",
                "fields": field_elements
            })

    # 底部固定品牌标
    card["elements"].append({
        "tag": "note",
        "elements": [
            {
                "tag": "plain_text",
                "content": "🛡️ PortGuard 智能主动诱捕防御系统 · 实时安全审计"
            }
        ]
    })

    payload = {
        "msg_type": "interactive",
        "card": card
    }

    if secret and str(secret).strip():
        sec_str = str(secret).strip()
        sign = generate_feishu_signature(sec_str, now_ts)
        if sign:
            payload["timestamp"] = str(now_ts)
            payload["sign"] = sign

    data_bytes = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    req = urllib.request.Request(
        webhook_url,
        data=data_bytes,
        headers={
            "Content-Type": "application/json; charset=utf-8",
            "User-Agent": "PortGuard-Notify/2.0"
        }
    )

    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            resp_bytes = resp.read()
            resp_str = resp_bytes.decode("utf-8", errors="ignore")
            try:
                res_data = json.loads(resp_str)
                code = res_data.get("code") if "code" in res_data else res_data.get("StatusCode")
                if code == 0:
                    return True, "飞书消息发送成功"
                else:
                    err_msg = res_data.get("msg") or res_data.get("StatusMessage") or resp_str
                    return False, f"飞书接口返回错误 (code: {code}): {err_msg}"
            except Exception:
                if resp.status in (200, 204):
                    return True, "消息已发送"
                return False, f"HTTP 状态码异常: {resp.status} - {resp_str}"
    except urllib.error.HTTPError as e:
        try:
            err_body = e.read().decode("utf-8", errors="ignore")
        except Exception:
            err_body = str(e)
        return False, f"HTTP 请求失败 ({e.code}): {err_body}"
    except Exception as e:
        return False, f"网络请求异常: {e}"


def async_send_feishu_webhook(webhook_url, secret=None, card_title="PortGuard 安全告警", content_text="", fields=None, color="blue"):
    """异步非阻塞发送飞书卡片消息"""
    try:
        executor = get_notify_executor()
        executor.submit(send_feishu_webhook, webhook_url, secret, card_title, content_text, fields, color)
    except Exception as e:
        print(f"[Notify] 异步调度飞书通知异常: {e}")


def notify_new_listening_port(port, service_name, proc_name=None, pid=None, cfg=None):
    """
    内核新增监听端口时发出飞书报警通知
    """
    if cfg is None:
        try:
            from core.db import load_config
            cfg = load_config()
        except Exception:
            return False, "无法加载配置文件"

    feishu_cfg = cfg.get("feishu_bot", {})
    if not feishu_cfg.get("enabled"):
        return False, "飞书机器人未启用"

    webhook_url = feishu_cfg.get("webhook_url", "").strip()
    if not webhook_url:
        return False, "未配置 Webhook URL"

    if not feishu_cfg.get("notify_new_listen_port", True):
        return False, "未开启内核监听端口新增告警"

    secret = feishu_cfg.get("secret", "").strip()
    node_name = cfg.get("node_name", socket.gethostname()) or socket.gethostname()
    now_str = time.strftime("%Y-%m-%d %H:%M:%S")

    title = "🛡️ PortGuard 智能业务端口自动纳管告警"
    main_text = (
        f"**系统内核检测到新增活跃监听端口**\n"
        f"安全引擎已自动将其纳管至正常业务端口列表进行放行与防护，防止被蜜罐误拦截。"
    )

    proc_desc = f"{proc_name} (PID: {pid})" if proc_name and pid else (proc_name or "系统原生服务")

    fields = [
        ("🖥️ 服务器节点", node_name),
        ("🔌 新增监听端口", f"TCP {port}"),
        ("📦 识别服务名称", service_name or f"系统服务 ({port})"),
        ("⚙️ 监听宿主进程", proc_desc),
        ("🛡️ 执行处置动作", "已自动添加至业务端口列表 (放行)"),
        ("⏰ 发现感知时间", now_str)
    ]

    async_send_feishu_webhook(webhook_url, secret, title, main_text, fields, color="turquoise")
    return True, "已触发异步发送"


def notify_ban_alert(ip, port=None, reason="", geo="未知位置", level="高危", cfg=None):
    """
    高危攻击拦截封禁告警通知
    """
    if cfg is None:
        try:
            from core.db import load_config
            cfg = load_config()
        except Exception:
            return False, "无法加载配置文件"

    feishu_cfg = cfg.get("feishu_bot", {})
    if not feishu_cfg.get("enabled") or not feishu_cfg.get("notify_ban_ip", False):
        return False, "未开启封禁告警"

    webhook_url = feishu_cfg.get("webhook_url", "").strip()
    if not webhook_url:
        return False, "未配置 Webhook URL"

    secret = feishu_cfg.get("secret", "").strip()
    node_name = cfg.get("node_name", socket.gethostname()) or socket.gethostname()
    now_str = time.strftime("%Y-%m-%d %H:%M:%S")

    title = f"🚨 PortGuard 入侵防御实时封禁告警 [{level}]"
    main_text = f"**捕获外部恶意威胁入侵行为，已由 Linux 内核层阻断并拉黑该 IP**"

    fields = [
        ("🖥️ 告警节点", node_name),
        ("🎯 攻击源 IP", ip),
        ("🌐 地理位置", geo or "未知位置"),
        ("🔌 目标端口", f"端口 {port}" if port else "全端口/网络层"),
        ("⚠️ 威胁原因", reason or "触发蜜罐或扫描防御规则"),
        ("⚡ 处置策略", "内核 IPSet 封禁 + 黑洞路由阻断"),
        ("⏰ 拦截时间", now_str)
    ]

    color = "red" if level in ("极高危", "高危") else "orange"
    async_send_feishu_webhook(webhook_url, secret, title, main_text, fields, color=color)
    return True, "已触发异步发送"


def send_test_feishu_message(webhook_url, secret=None, cfg=None):
    """
    发送测试消息验证配置有效性
    """
    if cfg is None:
        try:
            from core.db import load_config
            cfg = load_config()
        except Exception:
            cfg = {}

    node_name = cfg.get("node_name", socket.gethostname()) or socket.gethostname()
    now_str = time.strftime("%Y-%m-%d %H:%M:%S")

    title = "🎉 PortGuard 飞书机器人配置测试成功"
    main_text = (
        f"**这是一条来自 PortGuard 智能主动诱捕防御系统的联通测试消息。**\n"
        f"当系统出现内核新增监听端口、恶意攻击拦截或配置变动时，将通过此机器人实时为您推送告警通知。"
    )

    fields = [
        ("🖥️ 发送节点", node_name),
        ("📶 连通状态", "✅ 通道畅通就绪"),
        ("🔐 加签验证", "已启用 HMAC-SHA256" if secret and str(secret).strip() else "未配置加签秘钥 (直接发送)"),
        ("⏰ 测试时间", now_str)
    ]

    return send_feishu_webhook(webhook_url, secret, title, main_text, fields, color="turquoise", timeout=8)
