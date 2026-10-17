"""
飞书 WebSocket 长连接客户端 (适配 Python 3.6+ / 零沉重依赖)
利用通用 websockets + protobuf 协议，直接接入飞书 OpenAPI 官方长连接网关。
无需安装官方庞大的 lark-oapi 包，兼容任何精简 Linux 发行版。
"""

import asyncio
import json
import logging
import ssl
import threading
import time
import urllib.parse
import urllib.request

logger = logging.getLogger("FeishuWS")

class FeishuWebSocketClient:
    def __init__(self, app_id, app_secret, message_callback=None, loop=None):
        self.app_id = str(app_id).strip()
        self.app_secret = str(app_secret).strip()
        self.message_callback = message_callback
        self.loop = loop or asyncio.get_event_loop()
        self.ws = None
        self.is_running = False
        self.is_connected = False
        self.last_active_ts = 0.0
        self.last_error = ""
        self._ping_task = None
        self._recv_task = None

    def _get_ws_endpoint(self):
        """向飞书开放平台请求 WebSocket 连接端点与会话参数"""
        url = "https://open.feishu.cn/callback/ws/endpoint"
        data = json.dumps({"AppID": self.app_id, "AppSecret": self.app_secret}).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=data,
            headers={"Content-Type": "application/json", "locale": "zh"}
        )
        ctx = ssl.create_default_context()
        with urllib.request.urlopen(req, context=ctx, timeout=15) as resp:
            res = json.loads(resp.read().decode("utf-8"))
            if res.get("code") != 0:
                raise Exception(f"获取端点失败: code={res.get('code')}, msg={res.get('msg')}")
            return res.get("data", {})

    async def _ping_loop(self, service_id, ping_interval=90):
        """定期发送 Protobuf Ping 心跳包维持网关存活"""
        from core.ws_pb import pbbp2_pb2
        while self.is_running and self.ws:
            try:
                await asyncio.sleep(ping_interval)
                if not self.ws or self.ws.closed:
                    break
                frame = pbbp2_pb2.Frame()
                frame.SeqID = 0
                frame.LogID = 0
                frame.service = service_id
                frame.method = 0  # CONTROL
                h = frame.headers.add()
                h.key = "type"
                h.value = "ping"
                await self.ws.send(frame.SerializeToString())
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.warning(f"[Feishu WS] Ping 心跳发送异常: {e}")

    async def _handle_message(self, raw_bytes):
        """解析接收到的飞书网关 Protobuf 帧"""
        from core.ws_pb import pbbp2_pb2
        try:
            frame = pbbp2_pb2.Frame()
            frame.ParseFromString(raw_bytes)
            headers = {h.key: h.value for h in frame.headers}
            msg_type = headers.get("type", "")

            # 处理服务端 Pong
            if msg_type == "pong":
                self.last_active_ts = time.time()
                return

            # 处理业务 Event
            if msg_type == "event":
                self.last_active_ts = time.time()
                payload_str = frame.payload.decode("utf-8")
                event_data = json.loads(payload_str)

                # 回复网关 ACK 确认包，防止网关重复投递
                try:
                    resp_frame = pbbp2_pb2.Frame()
                    resp_frame.SeqID = frame.SeqID
                    resp_frame.LogID = frame.LogID
                    resp_frame.service = frame.service
                    resp_frame.method = frame.method
                    for h in frame.headers:
                        new_h = resp_frame.headers.add()
                        new_h.key = h.key
                        new_h.value = h.value
                    resp_frame.payload = json.dumps({"code": 200}).encode("utf-8")
                    await self.ws.send(resp_frame.SerializeToString())
                except Exception as ack_err:
                    logger.warning(f"[Feishu WS] 回复 ACK 失败: {ack_err}")

                # 异步回调处理上层指令
                if self.message_callback:
                    if asyncio.iscoroutinefunction(self.message_callback):
                        await self.message_callback(event_data)
                    else:
                        self.loop.run_in_executor(None, self.message_callback, event_data)

        except Exception as e:
            logger.error(f"[Feishu WS] 消息帧解析异常: {e}")

    async def start(self):
        """主长连接循环与自动重连"""
        import websockets
        self.is_running = True
        logger.info(f"[Feishu WS] 正在启动长连接管理器 (AppID: {self.app_id})...")

        while self.is_running:
            try:
                endpoint_info = await self.loop.run_in_executor(None, self._get_ws_endpoint)
                ws_url = endpoint_info.get("URL")
                client_cfg = endpoint_info.get("ClientConfig", {})
                ping_interval = client_cfg.get("PingInterval", 90)

                u = urllib.parse.urlparse(ws_url)
                q = urllib.parse.parse_qs(u.query)
                service_id = int(q.get("service_id", [0])[0])

                logger.info(f"[Feishu WS] 🔗 正在握手连接飞书网关 (Service: {service_id})...")
                async with websockets.connect(ws_url, ping_interval=None) as ws:
                    self.ws = ws
                    self.is_connected = True
                    self.last_active_ts = time.time()
                    self.last_error = ""
                    logger.info("[Feishu WS] ✅ 飞书长连接网关握手成功，已建立持久双向信道！")

                    # 启动心跳守护
                    self._ping_task = self.loop.create_task(self._ping_loop(service_id, ping_interval))

                    # 接收循环
                    while self.is_running:
                        msg = await ws.recv()
                        self.loop.create_task(self._handle_message(msg))

            except asyncio.CancelledError:
                break
            except Exception as e:
                self.is_connected = False
                self.last_error = str(e)
                logger.warning(f"[Feishu WS] 连接断开或异常: {e}，5秒后自动重连...")
                if self._ping_task:
                    self._ping_task.cancel()
                await asyncio.sleep(5)
            finally:
                self.is_connected = False
                self.ws = None

    def stop(self):
        """停止长连接"""
        self.is_running = False
        self.is_connected = False
        if self._ping_task:
            self._ping_task.cancel()
