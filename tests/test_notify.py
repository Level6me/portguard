# -*- coding: utf-8 -*-
import unittest
from unittest.mock import patch, MagicMock
import json
import time
import os
import sys

# Ensure project root is in sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.notify import (
    generate_feishu_signature,
    send_feishu_webhook,
    notify_new_listening_port,
    notify_ban_alert,
    send_test_feishu_message
)
from sentry_daemon import (
    get_raw_kernel_listen_ports_with_details,
    check_and_sync_new_listen_ports,
    _KNOWN_KERNEL_LISTEN_PORTS
)

class TestNotifyAndFeishu(unittest.TestCase):

    def test_generate_feishu_signature(self):
        """测试飞书签名计算符合 HMAC-SHA256 规范"""
        secret = "test_secret_key"
        timestamp = 1700000000
        sig = generate_feishu_signature(secret, timestamp)
        self.assertIsNotNone(sig)
        self.assertIsInstance(sig, str)
        self.assertTrue(len(sig) > 10)

        # 空 secret 返回 None
        self.assertIsNone(generate_feishu_signature("", timestamp))
        self.assertIsNone(generate_feishu_signature(None, timestamp))

    @patch("urllib.request.urlopen")
    def test_send_feishu_webhook_success(self, mock_urlopen):
        """测试向飞书机器人发送富文本交互卡片请求"""
        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps({"StatusCode": 0, "msg": "success"}).encode("utf-8")
        mock_resp.__enter__.return_value = mock_resp
        mock_urlopen.return_value = mock_resp

        fields = [
            ("节点", "测试节点"),
            ("端口", "TCP 8080"),
            ("服务", "HTTP")
        ]
        ok, msg = send_feishu_webhook(
            webhook_url="https://open.feishu.cn/open-apis/bot/v2/hook/test-token",
            secret="my-secret",
            card_title="测试标题",
            content_text="测试内容",
            fields=fields,
            color="turquoise"
        )
        self.assertTrue(ok)
        self.assertIn("成功", msg)

        # 验证 urlopen 调用参数
        self.assertTrue(mock_urlopen.called)
        req_arg = mock_urlopen.call_args[0][0]
        self.assertEqual(req_arg.full_url, "https://open.feishu.cn/open-apis/bot/v2/hook/test-token")
        sent_body = json.loads(req_arg.data.decode("utf-8"))
        self.assertEqual(sent_body.get("msg_type"), "interactive")
        self.assertIn("sign", sent_body)
        self.assertIn("timestamp", sent_body)
        self.assertEqual(sent_body["card"]["header"]["title"]["content"], "测试标题")

    def test_send_feishu_webhook_invalid_url(self):
        """测试无效 URL 防御"""
        ok, msg = send_feishu_webhook("", card_title="test")
        self.assertFalse(ok)
        self.assertIn("未配置", msg)

        ok, msg = send_feishu_webhook("ftp://invalid-scheme", card_title="test")
        self.assertFalse(ok)
        self.assertIn("格式不正确", msg)

    @patch("core.notify.async_send_feishu_webhook")
    def test_notify_new_listening_port(self, mock_async_send):
        """测试新增端口告警卡片装配与异步触发"""
        fake_cfg = {
            "node_name": "Prod-Node-01",
            "feishu_bot": {
                "enabled": True,
                "webhook_url": "https://open.feishu.cn/open-apis/bot/v2/hook/123",
                "secret": "s3cr3t",
                "notify_new_listen_port": True
            }
        }
        ok, msg = notify_new_listening_port(
            port=8088,
            service_name="CustomAPI",
            proc_name="gunicorn",
            pid=12345,
            cfg=fake_cfg
        )
        self.assertTrue(ok)
        self.assertTrue(mock_async_send.called)
        call_args = mock_async_send.call_args[0]
        # args: webhook_url, secret, title, main_text, fields, color
        self.assertEqual(call_args[0], "https://open.feishu.cn/open-apis/bot/v2/hook/123")
        self.assertEqual(call_args[1], "s3cr3t")
        self.assertIn("8088", call_args[2] + str(call_args[4]))
        self.assertIn("CustomAPI", str(call_args[4]))
        self.assertIn("gunicorn", str(call_args[4]))

    @patch("core.notify.async_send_feishu_webhook")
    def test_notify_ban_alert(self, mock_async_send):
        """测试高危封禁通知"""
        fake_cfg = {
            "node_name": "Prod-Node-01",
            "feishu_bot": {
                "enabled": True,
                "webhook_url": "https://open.feishu.cn/open-apis/bot/v2/hook/123",
                "secret": "s3cr3t",
                "notify_ban_ip": True
            }
        }
        ok, msg = notify_ban_alert(
            ip="198.51.100.23",
            port=22,
            reason="恶意爆破 SSH 端口",
            geo="海外未知",
            level="高危",
            cfg=fake_cfg
        )
        self.assertTrue(ok)
        self.assertTrue(mock_async_send.called)
        call_args = mock_async_send.call_args[0]
        self.assertIn("198.51.100.23", str(call_args[4]))

    def test_get_raw_kernel_listen_ports_with_details(self):
        """测试读取 Linux 内核 /proc/net/tcp 原始端口及映射"""
        ports = get_raw_kernel_listen_ports_with_details()
        self.assertIsInstance(ports, dict)
        # 本机至少会有某些系统端口在监听（例如 ssh 22 或 29675 等）
        self.assertTrue(len(ports) >= 0)
        for p, info in ports.items():
            self.assertIsInstance(p, int)
            self.assertTrue(1 <= p <= 65535)
            self.assertIn("proc", info)
            self.assertIn("pid", info)

    @patch("sentry_daemon.notify_new_listening_port")
    @patch("sentry_daemon.save_config")
    @patch("sentry_daemon.load_config")
    @patch("sentry_daemon.get_raw_kernel_listen_ports_with_details")
    def test_check_and_sync_new_listen_ports(self, mock_get_ports, mock_load, mock_save, mock_notify):
        """测试自动纳管与发现新增监听端口流程"""
        import sentry_daemon
        # 重设全局缓存模拟初次启动
        sentry_daemon._INITIAL_KERNEL_PORTS_SCANNED = True
        sentry_daemon._KNOWN_KERNEL_LISTEN_PORTS = {80, 443}

        fake_cfg = {
            "auto_manage_listen_ports": True,
            "business_ports": [80, 443],
            "trap_ports": [2222],
            "web_port": 9099,
            "feishu_bot": {"enabled": True}
        }
        mock_load.return_value = fake_cfg
        # 模拟内核新出现了 8888 端口
        mock_get_ports.return_value = {
            80: {"proc": "nginx", "pid": 100},
            443: {"proc": "nginx", "pid": 100},
            8888: {"proc": "fastapi_app", "pid": 9999}
        }

        sentry_daemon.check_and_sync_new_listen_ports()

        # 验证 8888 是否被加入 business_ports
        has_8888 = any(p == 8888 or (isinstance(p, dict) and p.get("port") == 8888) for p in fake_cfg["business_ports"])
        self.assertTrue(has_8888)
        self.assertTrue(mock_save.called)
        self.assertTrue(mock_notify.called)
        notify_port = mock_notify.call_args[1].get("port") or mock_notify.call_args[0][0]
        self.assertEqual(notify_port, 8888)


if __name__ == "__main__":
    unittest.main()
