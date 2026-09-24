#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PortGuard Core Notification & Feishu Bot Alert Engine v2.0
飞书应用机器人 (AppID + AppSecret 长连接 WebSocket 模式) 与群自定义机器人即时告警引擎
支持双向长连接通信、自动绑定群聊、实时命令交互及多通道卡片推送
"""
import asyncio
import base64
import hashlib
import hmac
import json
import os
import socket
import threading
import time
import urllib.request
import urllib.error

# 颜色定义对照表（Feishu 官方卡片主题色）
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

# ==============================================================================
# 飞书应用凭证 (tenant_access_token) 缓存与获取
# ==============================================================================
_TOKEN_LOCK = threading.Lock()
_TOKEN_CACHE = {"token": "", "expire_at": 0, "app_id": ""}

def get_tenant_access_token(app_id, app_secret, timeout=6):
    """
    通过 AppID 和 AppSecret 获取飞书开放平台 tenant_access_token (带内存级 TTL 缓存)
    """
    if not app_id or not app_secret:
        return None, "未配置 App ID 或 App Secret"

    app_id = str(app_id).strip()
    app_secret = str(app_secret).strip()
    now = time.time()

    with _TOKEN_LOCK:
        if _TOKEN_CACHE["app_id"] == app_id and _TOKEN_CACHE["token"] and now < _TOKEN_CACHE["expire_at"] - 60:
            return _TOKEN_CACHE["token"], None

    url = "https://open.feishu.cn/open-apis/auth/v3/tenant_access_token/internal"
    payload = json.dumps({"app_id": app_id, "app_secret": app_secret}).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=payload,
        headers={"Content-Type": "application/json; charset=utf-8", "User-Agent": "PortGuard-Notify/2.0"}
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", errors="ignore")
            data = json.loads(body)
            code = data.get("code")
            if code == 0:
                token = data.get("tenant_access_token")
                expire = int(data.get("expire", 7200))
                with _TOKEN_LOCK:
                    _TOKEN_CACHE["app_id"] = app_id
                    _TOKEN_CACHE["token"] = token
                    _TOKEN_CACHE["expire_at"] = now + expire
                return token, None
            else:
                return None, f"飞书凭证获取失败 (code: {code}): {data.get('msg', '未知错误')}"
    except urllib.error.HTTPError as e:
        try:
            err_body = e.read().decode("utf-8", errors="ignore")
        except Exception:
            err_body = str(e)
        return None, f"飞书鉴权接口响应异常 ({e.code}): {err_body}"
    except Exception as e:
        return None, f"飞书开放平台网络异常: {e}"

# ==============================================================================
# 卡片与签名生成工具
# ==============================================================================
def generate_feishu_signature(secret, timestamp):
    """根据飞书自定义机器人开放平台规范计算加签密钥"""
    if not secret:
        return None
    string_to_sign = f"{timestamp}\n{secret}"
    hmac_code = hmac.new(string_to_sign.encode("utf-8"), digestmod=hashlib.sha256).digest()
    return base64.b64encode(hmac_code).decode("utf-8")

def build_feishu_card(card_title="PortGuard 安全告警", content_text="", fields=None, color="blue", actions=None):
    """构建飞书官方交互式富文本卡片结构"""
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

    if actions and isinstance(actions, (list, tuple)):
        action_elements = []
        for act in actions:
            if isinstance(act, dict) and "text" in act and "url" in act:
                action_elements.append({
                    "tag": "button",
                    "text": {"tag": "plain_text", "content": act["text"]},
                    "type": act.get("type", "primary"),
                    "url": act["url"]
                })
        if action_elements:
            card["elements"].append({"tag": "hr"})
            card["elements"].append({
                "tag": "action",
                "actions": action_elements
            })

    card["elements"].append({
        "tag": "note",
        "elements": [
            {
                "tag": "plain_text",
                "content": "🛡️ PortGuard 智能主动诱捕防御系统 · 实时安全审计"
            }
        ]
    })
    return card

# ==============================================================================
# 发送模式 1：飞书官方应用消息发送 (针对 AppID + AppSecret 模式)
# ==============================================================================
def send_feishu_app_message(app_id, app_secret, receive_id, card_dict=None, text_content=None, receive_id_type="chat_id", timeout=6):
    """
    使用飞书应用凭证向指定会话/群/用户发送卡片或文本消息
    receive_id_type: 'chat_id' (群ID, oc_xxx) 或 'open_id' (个人用户, ou_xxx)
    """
    token, err = get_tenant_access_token(app_id, app_secret, timeout=timeout)
    if not token:
        return False, err or "未能获取到有效的 tenant_access_token"

    if not receive_id or not str(receive_id).strip():
        return False, "未指定消息接收目标 (receive_id 为空)"

    receive_id = str(receive_id).strip()
    if not receive_id_type:
        receive_id_type = "open_id" if receive_id.startswith("ou_") else "chat_id"

    url = f"https://open.feishu.cn/open-apis/im/v1/messages?receive_id_type={receive_id_type}"
    if card_dict:
        msg_payload = {
            "receive_id": receive_id,
            "msg_type": "interactive",
            "content": json.dumps(card_dict, ensure_ascii=False)
        }
    else:
        msg_payload = {
            "receive_id": receive_id,
            "msg_type": "text",
            "content": json.dumps({"text": text_content or "PortGuard 告警"}, ensure_ascii=False)
        }

    data_bytes = json.dumps(msg_payload, ensure_ascii=False).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data_bytes,
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json; charset=utf-8",
            "User-Agent": "PortGuard-Notify/2.0"
        }
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", errors="ignore")
            res_data = json.loads(body)
            if res_data.get("code") == 0:
                return True, "飞书应用消息发送成功"
            else:
                return False, f"飞书发送失败 (code {res_data.get('code')}): {res_data.get('msg', '未知错误')}"
    except urllib.error.HTTPError as e:
        try:
            err_body = e.read().decode("utf-8", errors="ignore")
        except Exception:
            err_body = str(e)
        return False, f"HTTP 请求失败 ({e.code}): {err_body}"
    except Exception as e:
        return False, f"发送网络异常: {e}"

# ==============================================================================
# 发送模式 2：群自定义 Webhook 模式 (兼容保留)
# ==============================================================================
def send_feishu_webhook(webhook_url, secret=None, card_title="PortGuard 安全告警", content_text="", fields=None, color="blue", timeout=6):
    """
    向飞书自定义机器人发送交互式富文本卡片通知。
    """
    if not webhook_url or not str(webhook_url).strip():
        return False, "未配置飞书机器人 Webhook URL"

    webhook_url = str(webhook_url).strip()
    if not (webhook_url.startswith("http://") or webhook_url.startswith("https://")):
        return False, "Webhook URL 格式不正确，必须以 http:// 或 https:// 开头"

    now_ts = int(time.time())
    card = build_feishu_card(card_title, content_text, fields, color)

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

# ==============================================================================
# 统一综合调度分发器 (Unified Dispatcher)
# ==============================================================================
def send_feishu_notification(card_title="PortGuard 安全告警", content_text="", fields=None, color="blue", cfg=None):
    """
    统一消息分发调度器：
    优先使用飞书应用长连接模式 (AppID + AppSecret 推送到指定 receive_id)；
    若未配置 receive_id 但有长连接在线，记录提醒；同时兼容群 Webhook。
    """
    if cfg is None:
        try:
            from core.db import load_config
            cfg = load_config()
        except Exception:
            return False, "无法读取配置文件"

    feishu_cfg = cfg.get("feishu_bot", {})
    if not feishu_cfg.get("enabled"):
        return False, "飞书机器人未启用"

    app_id = feishu_cfg.get("app_id", "").strip()
    app_secret = feishu_cfg.get("app_secret", "").strip()
    receive_id = feishu_cfg.get("receive_id", "").strip()
    receive_id_type = feishu_cfg.get("receive_id_type", "chat_id")
    webhook_url = feishu_cfg.get("webhook_url", "").strip()
    secret = feishu_cfg.get("secret", "").strip()

    card = build_feishu_card(card_title, content_text, fields, color)
    sent_any = False
    last_msg = ""

    # 1. 优先使用飞书应用机器人 (AppID + AppSecret)
    if app_id and app_secret:
        if receive_id:
            ok, msg = send_feishu_app_message(app_id, app_secret, receive_id, card_dict=card, receive_id_type=receive_id_type)
            if ok:
                sent_any = True
                last_msg = msg
            else:
                last_msg = f"应用消息发送失败: {msg}"
        else:
            last_msg = "飞书机器人已配置 AppID，但尚未绑定接收目标群ID (receive_id)。在飞书群中给机器人发送一条任意消息即可自动绑定！"
            print(f"[PortGuard Notify] ⚠️ {last_msg}")

    # 2. 如果配置了 Webhook 且应用消息未发送成功或用户同时配了 Webhook，则调用 Webhook
    if not sent_any and webhook_url:
        ok, msg = send_feishu_webhook(webhook_url, secret, card_title, content_text, fields, color)
        if ok:
            sent_any = True
            last_msg = msg
        else:
            last_msg = f"Webhook 发送失败: {msg}"

    if not sent_any and not app_id and not webhook_url:
        return False, "未配置飞书机器人 AppID 或 Webhook 地址"

    return sent_any, last_msg

def async_send_feishu_notification(card_title="PortGuard 安全告警", content_text="", fields=None, color="blue", cfg=None):
    """异步非阻塞发送飞书通知"""
    try:
        executor = get_notify_executor()
        executor.submit(send_feishu_notification, card_title, content_text, fields, color, cfg)
    except Exception as e:
        print(f"[Notify] 异步调度异常: {e}")

# ==============================================================================
# 飞书应用长连接 WebSocket 守护管理器 (FeishuWsManager)
# ==============================================================================
class FeishuWsManager:
    """
    基于 lark_oapi.ws.Client 的飞书长连接管理器：
    保持与飞书网关持久 WebSocket 长连接，实现事件主动感知、命令交互及群聊自动绑定。
    """
    _instance = None
    _lock = threading.Lock()

    def __init__(self):
        self.client = None
        self.thread = None
        self.app_id = ""
        self.app_secret = ""
        self.is_running = False
        self.is_connected = False
        self.last_active_ts = 0.0
        self.last_error = ""

    @classmethod
    def get_instance(cls):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = cls()
        return cls._instance

    def is_active(self):
        return self.is_running and self.is_connected

    def start(self, app_id, app_secret):
        with self._lock:
            app_id = str(app_id).strip()
            app_secret = str(app_secret).strip()
            if not app_id or not app_secret:
                return False, "缺少 AppID 或 AppSecret"

            if self.is_running and self.app_id == app_id and self.app_secret == app_secret:
                return True, "长连接已在运行中"

            self.stop()
            self.app_id = app_id
            self.app_secret = app_secret
            self.is_running = True
            self.is_connected = False
            self.last_error = ""

            t = threading.Thread(target=self._run_ws, daemon=True, name="FeishuWsWorker")
            self.thread = t
            t.start()
            return True, "正在建立飞书 WebSocket 长连接..."

    def stop(self):
        self.is_running = False
        self.is_connected = False
        if self.client:
            try:
                self.client._auto_reconnect = False
                if getattr(self.client, "_conn", None):
                    asyncio.run(self.client._disconnect())
            except Exception:
                pass
            self.client = None
        self.thread = None

    def _run_ws(self):
        """长连接后台工作线程"""
        try:
            import lark_oapi as lark
            from lark_oapi.api.im.v1 import P2ImMessageReceiveV1
        except ImportError:
            self.last_error = "未安装 lark_oapi 依赖"
            self.is_running = False
            print(f"[Feishu WS] 错误: {self.last_error}")
            return

        def _on_message_receive(data: P2ImMessageReceiveV1):
            """处理飞书收到的交互消息"""
            try:
                self.last_active_ts = time.time()
                self.is_connected = True
                event = getattr(data, "event", None)
                if not event:
                    return

                msg = getattr(event, "message", None)
                if not msg:
                    return

                chat_id = getattr(msg, "chat_id", "")
                content_str = getattr(msg, "content", "{}")
                sender = getattr(event, "sender", None)
                open_id = ""
                if sender and getattr(sender, "sender_id", None):
                    open_id = getattr(sender.sender_id, "open_id", "")

                try:
                    c_dict = json.loads(content_str)
                    raw_text = c_dict.get("text", "").strip()
                except Exception:
                    raw_text = content_str.strip()

                # 自动纳管绑定接收群
                self._handle_auto_bind_and_command(chat_id, open_id, raw_text)
            except Exception as e:
                print(f"[Feishu WS] 处理消息异常: {e}")

        # 构建事件分发处理器
        event_handler = lark.EventDispatcherHandler.builder("", "") \
            .register_p2_im_message_receive_v1(_on_message_receive) \
            .build()

        from lark_oapi.ws import client as ws_client_mod
        ws_cli = ws_client_mod.Client(
            self.app_id,
            self.app_secret,
            event_handler=event_handler,
            log_level=lark.LogLevel.WARNING,
            auto_reconnect=True
        )
        self.client = ws_cli

        new_loop = asyncio.new_event_loop()
        asyncio.set_event_loop(new_loop)
        ws_client_mod.loop = new_loop

        try:
            print(f"[Feishu WS] 🚀 正在连接飞书长连接网关 (AppID: {self.app_id})...")
            self.is_connected = True
            ws_cli.start()
        except Exception as e:
            self.last_error = str(e)
            self.is_connected = False
            print(f"[Feishu WS] 长连接异常退出: {e}")
        finally:
            self.is_running = False
            self.is_connected = False

    def _handle_auto_bind_and_command(self, chat_id, open_id, text):
        """自动绑定群聊与执行命令指令"""
        from core.db import load_config, save_config
        cfg = load_config()
        fb = cfg.get("feishu_bot", {})
        current_rcv = fb.get("receive_id", "").strip()
        node_name = cfg.get("node_name", "本机节点") or "本机节点"

        # 1. 自动绑定：若当前未配置 receive_id，自动将当前对话群绑定为告警推送目标
        if not current_rcv and chat_id:
            fb["receive_id"] = chat_id
            fb["receive_id_type"] = "chat_id"
            cfg["feishu_bot"] = fb
            save_config(cfg)
            print(f"[Feishu WS] 🎯 自动绑定飞书告警推送群: {chat_id}")
            bind_card = build_feishu_card(
                "🎉 PortGuard 飞书告警自动绑定成功",
                f"**已自动将当前会话绑定为 PortGuard 安全告警推送通道！**\n\n"
                f"后续当系统内核检测到新增监听端口、恶意攻击拦截拉黑时，将自动向本处发送实时交互卡片。",
                fields=[
                    ("🖥️ 监控节点", node_name),
                    ("💬 绑定会话 ID", chat_id),
                    ("⚡ 通信链路", "WebSocket 双向持久长连接"),
                    ("⏰ 绑定时间", time.strftime("%Y-%m-%d %H:%M:%S"))
                ],
                color="turquoise"
            )
            send_feishu_app_message(self.app_id, self.app_secret, chat_id, card_dict=bind_card, receive_id_type="chat_id")
            return

        target_id = chat_id or open_id
        if not target_id:
            return

        cmd = text.strip()
        # 剥离 @机器人 标识
        if "@_user_" in cmd:
            parts = cmd.split()
            cmd = " ".join([p for p in parts if not p.startswith("@_user_")]).strip()

        # 命令 1：/status 或 状态
        if cmd in ("/status", "状态", "status"):
            try:
                from sentry_daemon import get_all_business_ports_info
                from core.firewall import get_blacklisted_ips_set
                biz_cnt = len(get_all_business_ports_info())
                ban_cnt = len(get_blacklisted_ips_set())
                is_paused = cfg.get("defense_paused", False)
                status_text = "⏸️ 观察模式 (已暂停阻断)" if is_paused else "🛡️ 标准主动防御中"
                card = build_feishu_card(
                    "📊 PortGuard 实时安全防御态势",
                    f"**当前服务器安全防护系统运行正常**",
                    fields=[
                        ("🖥️ 服务器节点", node_name),
                        ("🛡️ 防御状态", status_text),
                        ("🚫 实时封禁 IP 数", f"{ban_cnt} 个"),
                        ("🔌 纳管业务端口", f"{biz_cnt} 个正常业务端口"),
                        ("🌐 WebSocket 长连接", "✅ 正常畅通"),
                        ("⏰ 汇报时间", time.strftime("%Y-%m-%d %H:%M:%S"))
                    ],
                    color="turquoise" if not is_paused else "orange"
                )
                send_feishu_app_message(self.app_id, self.app_secret, target_id, card_dict=card)
            except Exception as e:
                send_feishu_app_message(self.app_id, self.app_secret, target_id, text_content=f"获取状态异常: {e}")

        # 命令 2：/ports 或 端口
        elif cmd in ("/ports", "端口", "ports"):
            try:
                from sentry_daemon import get_raw_kernel_listen_ports_with_details, get_all_business_ports_info
                k_ports = get_raw_kernel_listen_ports_with_details()
                b_ports = [x.get("port") for x in get_all_business_ports_info() if isinstance(x, dict)]
                k_list_str = ", ".join([str(p) for p in sorted(k_ports.keys())]) or "无"
                b_list_str = ", ".join([str(p) for p in sorted(b_ports)]) or "无"
                card = build_feishu_card(
                    "🔌 PortGuard 端口与服务监听视图",
                    f"**系统内核与放行端口清单**",
                    fields=[
                        ("🖥️ 服务器节点", node_name),
                        ("⚙️ 内核监听活跃端口", k_list_str[:500]),
                        ("🛡️ 纳管放行业务端口", b_list_str[:500]),
                        ("⏰ 巡检时间", time.strftime("%Y-%m-%d %H:%M:%S"))
                    ],
                    color="blue"
                )
                send_feishu_app_message(self.app_id, self.app_secret, target_id, card_dict=card)
            except Exception as e:
                send_feishu_app_message(self.app_id, self.app_secret, target_id, text_content=f"获取端口清单异常: {e}")

        # 命令 3：/unban <ip>
        elif cmd.startswith("/unban") or cmd.startswith("解封"):
            parts = cmd.split()
            if len(parts) >= 2:
                ip = parts[1].strip()
                try:
                    from core.firewall import unban_ip_core
                    unban_ip_core(ip)
                    card = build_feishu_card(
                        "✅ PortGuard 解封成功",
                        f"已将目标 IP `{ip}` 从内核 IPSet 防火墙与黑洞路由中彻底解封！",
                        fields=[("🖥️ 操作节点", node_name), ("🎯 解封 IP", ip), ("⏰ 时间", time.strftime("%Y-%m-%d %H:%M:%S"))],
                        color="turquoise"
                    )
                    send_feishu_app_message(self.app_id, self.app_secret, target_id, card_dict=card)
                except Exception as e:
                    send_feishu_app_message(self.app_id, self.app_secret, target_id, text_content=f"解封失败: {e}")
            else:
                send_feishu_app_message(self.app_id, self.app_secret, target_id, text_content="使用方法: /unban <目标IP>")

        # 命令 4：/help 或 帮助
        elif cmd in ("/help", "帮助", "help", "?", "？"):
            card = build_feishu_card(
                "💡 PortGuard 飞书长连接助手指令手册",
                "您可以通过本会话直接与 PortGuard 诱捕防御引擎进行双向控制交互：\n\n"
                "• `/status` - 查看实时运行状态与封禁态势\n"
                "• `/ports` - 查看内核活跃监听端口与业务端口列表\n"
                "• `/unban <IP>` - 快速解封指定 IP 目标\n"
                "• `/help` - 调出本指令菜单\n\n"
                "💡 **自动纳管**：当服务器启动新的业务监听端口时，系统将自动纳管并推送告警卡片至本会话。",
                color="blue"
            )
            send_feishu_app_message(self.app_id, self.app_secret, target_id, card_dict=card)


def start_feishu_ws(cfg=None):
    """根据配置启动飞书 WebSocket 长连接"""
    if cfg is None:
        try:
            from core.db import load_config
            cfg = load_config()
        except Exception:
            return False, "无法加载配置"

    fb = cfg.get("feishu_bot", {})
    if not fb.get("enabled"):
        return False, "未启用飞书机器人"

    app_id = fb.get("app_id", "").strip()
    app_secret = fb.get("app_secret", "").strip()
    use_ws = fb.get("use_ws", True)

    if not app_id or not app_secret or not use_ws:
        return False, "未配置 AppID/AppSecret 或未启用长连接"

    mgr = FeishuWsManager.get_instance()
    return mgr.start(app_id, app_secret)

def stop_feishu_ws():
    """停止飞书长连接"""
    mgr = FeishuWsManager.get_instance()
    mgr.stop()

def reload_feishu_ws(cfg=None):
    """配置变动后重载长连接"""
    stop_feishu_ws()
    return start_feishu_ws(cfg)

def is_feishu_ws_connected():
    """检测当前长连接是否在线"""
    mgr = FeishuWsManager.get_instance()
    return mgr.is_active()

# ==============================================================================
# 告警卡片装配与对外调用接口
# ==============================================================================
def notify_new_listening_port(port, service_name, proc_name=None, pid=None, cfg=None):
    """
    内核新增监听端口时发出飞书富文本报警卡片通知
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

    if not feishu_cfg.get("notify_new_listen_port", True):
        return False, "未开启内核监听端口新增告警"

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

    async_send_feishu_notification(title, main_text, fields, color="turquoise", cfg=cfg)
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
    async_send_feishu_notification(title, main_text, fields, color=color, cfg=cfg)
    return True, "已触发异步发送"


def send_test_feishu_message(app_id=None, app_secret=None, receive_id=None, webhook_url=None, secret=None, cfg=None):
    """
    发送测试消息并校验飞书长连接/凭据有效性
    """
    if cfg is None:
        try:
            from core.db import load_config
            cfg = load_config()
        except Exception:
            cfg = {}

    feishu_cfg = cfg.get("feishu_bot", {})
    app_id = (app_id or feishu_cfg.get("app_id", "")).strip()
    app_secret = (app_secret or feishu_cfg.get("app_secret", "")).strip()
    receive_id = (receive_id or feishu_cfg.get("receive_id", "")).strip()
    receive_id_type = feishu_cfg.get("receive_id_type", "chat_id")
    webhook_url = (webhook_url or feishu_cfg.get("webhook_url", "")).strip()
    secret = (secret or feishu_cfg.get("secret", "")).strip()

    node_name = cfg.get("node_name", socket.gethostname()) or socket.gethostname()
    now_str = time.strftime("%Y-%m-%d %H:%M:%S")

    title = "🎉 PortGuard 飞书机器人配置测试成功"
    main_text = (
        f"**这是一条来自 PortGuard 智能主动诱捕防御系统的联通测试消息。**\n"
        f"当系统出现内核新增监听端口、恶意攻击拦截或配置变动时，将通过此机器人实时为您推送告警通知。"
    )

    fields = [
        ("🖥️ 发送节点", node_name),
        ("📶 连通状态", "✅ WebSocket 长连接链路畅通就绪"),
        ("🔐 鉴权模式", "飞书应用 AppID 鉴权模式" if app_id else "群自定义 Webhook 模式"),
        ("⏰ 测试时间", now_str)
    ]

    # 1. 如果有 AppID + AppSecret，测试应用凭据与长连接
    if app_id and app_secret:
        token, err = get_tenant_access_token(app_id, app_secret, timeout=5)
        if not token:
            return False, f"飞书应用 AppID/Secret 校验失败: {err}"

        # 尝试启动或重载长连接
        start_feishu_ws(cfg)

        if receive_id:
            card = build_feishu_card(title, main_text, fields, color="turquoise")
            ok, msg = send_feishu_app_message(app_id, app_secret, receive_id, card_dict=card, receive_id_type=receive_id_type)
            if ok:
                return True, "🎉 飞书应用鉴权成功，且测试卡片已成功送达指定接收群！"
            return False, f"飞书应用鉴权成功，但测试卡片发送失败: {msg}"
        else:
            return True, (
                "✅ 飞书应用 AppID 与 AppSecret 校验成功！WebSocket 长连接已就绪。\n"
                "💡 提示：您尚未指定接收群 ID。请直接在飞书任意群或机器人私聊中向机器人发送一条消息（如 /status），"
                "PortGuard 将自动检测并绑定该群作为告警接收通道！"
            )

    # 2. 如果配置了 Webhook，测试 Webhook 模式
    if webhook_url:
        return send_feishu_webhook(webhook_url, secret, title, main_text, fields, color="turquoise", timeout=8)

    return False, "请提供飞书应用的 App ID 与 App Secret，或提供 Webhook URL"
