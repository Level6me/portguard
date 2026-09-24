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
    build_feishu_card,
    get_tenant_access_token,
    send_feishu_app_message,
    send_feishu_webhook,
    send_feishu_notification,
    notify_new_listening_port,
    notify_ban_alert,
    send_test_feishu_message,
    FeishuWsManager
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

    def test_build_feishu_card(self):
        """测试飞书富文本交互卡片构建"""
        fields = [("节点", "北京测试节点"), ("端口", "TCP 8080")]
        card = build_feishu_card("安全测试", "详细内容", fields, color="turquoise")
        self.assertEqual(card["header"]["title"]["content"], "安全测试")
        self.assertEqual(card["header"]["template"], "turquoise")
        self.assertTrue(len(card["elements"]) >= 3)

    @patch("urllib.request.urlopen")
    def test_get_tenant_access_token(self, mock_urlopen):
        """测试获取飞书开放平台应用凭证 (tenant_access_token)"""
        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps({
            "code": 0,
            "msg": "ok",
            "tenant_access_token": "t-g104mocktoken123",
            "expire": 7200
        }).encode("utf-8")
        mock_resp.__enter__.return_value = mock_resp
        mock_urlopen.return_value = mock_resp

        token, err = get_tenant_access_token("cli_test_app_id", "test_app_secret")
        self.assertEqual(token, "t-g104mocktoken123")
        self.assertIsNone(err)

    @patch("core.notify.get_tenant_access_token")
    @patch("urllib.request.urlopen")
    def test_send_feishu_app_message(self, mock_urlopen, mock_get_token):
        """测试通过飞书应用凭证向群聊/用户发送卡片消息"""
        mock_get_token.return_value = ("t-mock-token-abc", None)

        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps({"code": 0, "msg": "success"}).encode("utf-8")
        mock_resp.__enter__.return_value = mock_resp
        mock_urlopen.return_value = mock_resp

        card = build_feishu_card("应用卡片", "测试应用消息")
        ok, msg = send_feishu_app_message(
            app_id="cli_test",
            app_secret="sec_test",
            receive_id="oc_test_chat_id",
            card_dict=card,
            receive_id_type="chat_id"
        )
        self.assertTrue(ok)
        self.assertIn("成功", msg)

        # 验证 URL 与 Authorization 头
        self.assertTrue(mock_urlopen.called)
        req_arg = mock_urlopen.call_args[0][0]
        self.assertIn("open.feishu.cn/open-apis/im/v1/messages", req_arg.full_url)
        self.assertEqual(req_arg.headers.get("Authorization"), "Bearer t-mock-token-abc")
        sent_payload = json.loads(req_arg.data.decode("utf-8"))
        self.assertEqual(sent_payload.get("receive_id"), "oc_test_chat_id")
        self.assertEqual(sent_payload.get("msg_type"), "interactive")

    @patch("urllib.request.urlopen")
    def test_send_feishu_webhook_success(self, mock_urlopen):
        """测试向飞书自定义机器人发送富文本交互卡片请求"""
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

    @patch("core.notify.async_send_feishu_notification")
    def test_notify_new_listening_port(self, mock_async_send):
        """测试新增端口告警卡片装配与异步触发"""
        fake_cfg = {
            "node_name": "Prod-Node-01",
            "feishu_bot": {
                "enabled": True,
                "app_id": "cli_test",
                "app_secret": "sec_test",
                "receive_id": "oc_chat123",
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
        self.assertIn("PortGuard 智能业务端口自动纳管告警", call_args[0])
        fields_str = str(call_args[2])
        self.assertIn("8088", fields_str)
        self.assertIn("CustomAPI", fields_str)
        self.assertIn("gunicorn", fields_str)

    @patch("core.notify.async_send_feishu_notification")
    def test_notify_ban_alert(self, mock_async_send):
        """测试高危封禁通知"""
        fake_cfg = {
            "node_name": "Prod-Node-01",
            "feishu_bot": {
                "enabled": True,
                "app_id": "cli_test",
                "app_secret": "sec_test",
                "receive_id": "oc_chat123",
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
        self.assertIn("198.51.100.23", str(call_args[2]))

    def test_get_raw_kernel_listen_ports_with_details(self):
        """测试读取 Linux 内核 /proc/net/tcp 原始端口及映射"""
        ports = get_raw_kernel_listen_ports_with_details()
        self.assertIsInstance(ports, dict)
        self.assertTrue(len(ports) >= 0)
        for p, info in ports.items():
            self.assertIsInstance(p, int)
            self.assertTrue(1 <= p <= 65535)
            self.assertIn("process", info)
            self.assertIn("proc", info)
            self.assertIn("pid", info)

    @patch("sentry_daemon.notify_new_listening_port")
    @patch("sentry_daemon.save_config")
    @patch("sentry_daemon.load_config")
    @patch("sentry_daemon.get_raw_kernel_listen_ports_with_details")
    def test_check_and_sync_new_listen_ports(self, mock_get_ports, mock_load, mock_save, mock_notify):
        """测试自动纳管与发现新增监听端口流程"""
        import sentry_daemon
        sentry_daemon._INITIAL_KERNEL_PORTS_SCANNED = True
        sentry_daemon._KNOWN_KERNEL_LISTEN_PORTS = {80, 443}

        fake_cfg = {
            "auto_manage_listen_ports": True,
            "business_ports": [80, 443],
            "trap_ports": [2222],
            "web_port": 9099,
            "feishu_bot": {"enabled": True, "app_id": "cli_test", "app_secret": "sec"}
        }
        mock_load.return_value = fake_cfg
        mock_get_ports.return_value = {
            80: {"proc": "nginx", "process": "nginx", "pid": 100},
            443: {"proc": "nginx", "process": "nginx", "pid": 100},
            8888: {"proc": "fastapi_app", "process": "fastapi_app", "pid": 9999}
        }

        sentry_daemon.check_and_sync_new_listen_ports()

        # 验证 8888 是否被加入 business_ports
        has_8888 = any(p == 8888 or (isinstance(p, dict) and p.get("port") == 8888) for p in fake_cfg["business_ports"])
        self.assertTrue(has_8888)
        self.assertTrue(mock_save.called)
        self.assertTrue(mock_notify.called)
        notify_port = mock_notify.call_args[1].get("port") or mock_notify.call_args[0][0]
        self.assertEqual(notify_port, 8888)

    @patch("core.notify.get_tenant_access_token")
    @patch("core.notify.send_feishu_app_message")
    def test_send_test_feishu_message_app(self, mock_send_app, mock_token):
        """测试飞书应用长连接凭据测试接口"""
        mock_token.return_value = ("t-valid-token", None)
        mock_send_app.return_value = (True, "已发送测试卡片")

        # 1. 带 receive_id 测试
        ok, msg = send_test_feishu_message(app_id="cli_123", app_secret="sec_456", receive_id="oc_test")
        self.assertTrue(ok)
        self.assertIn("成功", msg)

        # 2. 不带 receive_id 测试，提示引导自动绑定
        ok, msg = send_test_feishu_message(app_id="cli_123", app_secret="sec_456", receive_id="")
        self.assertTrue(ok)
        self.assertIn("校验成功", msg)
        self.assertIn("自动检测并绑定", msg)


class TestFeishuCommands(unittest.TestCase):
    def setUp(self):
        self.mgr = FeishuWsManager()
        self.mgr.app_id = "cli_test"
        self.mgr.app_secret = "sec_test"
        self.cfg = {
            "node_name": "Test-Node",
            "feishu_bot": {
                "enabled": True,
                "app_id": "cli_test",
                "app_secret": "sec_test",
                "receive_id": "oc_test_chat_id",
                "receive_id_type": "chat_id"
            },
            "defense_paused": False,
            "whitelist": [{"ip": "10.0.0.1", "remark": "受信任运维机"}],
            "business_ports": [80, 443]
        }

    @patch("core.notify.send_feishu_app_message")
    @patch("core.db.save_config")
    @patch("core.db.load_config")
    def test_feishu_auto_bind(self, mock_load, mock_save, mock_send_app):
        """测试首次收到消息自动绑定 chat_id"""
        cfg_copy = dict(self.cfg)
        cfg_copy["feishu_bot"] = dict(self.cfg["feishu_bot"])
        cfg_copy["feishu_bot"]["receive_id"] = ""
        mock_load.return_value = cfg_copy

        self.mgr._handle_auto_bind_and_command("oc_new_group_123", "ou_sender", "你好")

        self.assertEqual(cfg_copy["feishu_bot"]["receive_id"], "oc_new_group_123")
        self.assertTrue(mock_save.called)
        self.assertTrue(mock_send_app.called)
        card = mock_send_app.call_args[1].get("card_dict")
        self.assertIn("自动绑定成功", card["header"]["title"]["content"])

    @patch("core.notify.send_feishu_app_message")
    @patch("core.firewall.get_blacklisted_ips_set")
    @patch("sentry_daemon.get_all_business_ports_info")
    @patch("core.db.load_config")
    def test_feishu_cmd_status(self, mock_load, mock_ports, mock_bans, mock_send_app):
        """测试 /status 查看实时安全防御态势看板"""
        mock_load.return_value = self.cfg
        mock_ports.return_value = [{"port": 80}, {"port": 443}]
        mock_bans.return_value = {"198.51.100.1", "198.51.100.2"}

        self.mgr._handle_auto_bind_and_command("oc_test_chat_id", "ou_sender", "/status")

        self.assertTrue(mock_send_app.called)
        card = mock_send_app.call_args[1].get("card_dict")
        self.assertIn("实时安全防御态势", card["header"]["title"]["content"])

    @patch("core.notify.send_feishu_app_message")
    @patch("sentry_daemon.ban_ip")
    @patch("core.db.load_config")
    def test_feishu_cmd_ban_and_whitelist_protect(self, mock_load, mock_ban, mock_send_app):
        """测试 /ban 封禁指令与核心白名单防自锁保护"""
        mock_load.return_value = self.cfg

        # 1. 正常封禁
        self.mgr._handle_auto_bind_and_command("oc_test_chat_id", "ou_sender", "/ban 198.51.100.99 恶意爆破")
        mock_ban.assert_called_with("198.51.100.99", port=0, reason="恶意爆破", trigger_type="feishu_manual")

        # 2. 白名单保护
        mock_ban.reset_mock()
        self.mgr._handle_auto_bind_and_command("oc_test_chat_id", "ou_sender", "/ban 10.0.0.1 尝试误封")
        mock_ban.assert_not_called()
        self.assertTrue(mock_send_app.called)
        last_text = mock_send_app.call_args[1].get("text_content") or ""
        self.assertIn("白名单", last_text)

    @patch("core.notify.send_feishu_app_message")
    @patch("sentry_daemon.unban_ip_core")
    @patch("core.db.load_config")
    def test_feishu_cmd_unban(self, mock_load, mock_unban, mock_send_app):
        """测试 /unban 解封指令"""
        mock_load.return_value = self.cfg

        self.mgr._handle_auto_bind_and_command("oc_test_chat_id", "ou_sender", "/unban 198.51.100.99")
        mock_unban.assert_called_with("198.51.100.99")
        self.assertTrue(mock_send_app.called)
        card = mock_send_app.call_args[1].get("card_dict")
        self.assertIn("解封成功", card["header"]["title"]["content"])

    @patch("core.notify.send_feishu_app_message")
    @patch("sentry_daemon.broadcast_cluster_whitelist")
    @patch("sentry_daemon.unban_ip_core")
    @patch("core.db.save_config")
    @patch("core.db.load_config")
    def test_feishu_cmd_white_and_unwhite(self, mock_load, mock_save, mock_unban, mock_broadcast, mock_send_app):
        """测试 /white 加白 与 /unwhite 删白 指令"""
        cfg_copy = dict(self.cfg)
        cfg_copy["whitelist"] = list(self.cfg["whitelist"])
        mock_load.return_value = cfg_copy

        # 加白
        self.mgr._handle_auto_bind_and_command("oc_test_chat_id", "ou_sender", "/white 192.168.10.5 办公机")
        self.assertTrue(any(w.get("ip") == "192.168.10.5" for w in cfg_copy["whitelist"]))
        self.assertTrue(mock_unban.called)
        self.assertTrue(mock_broadcast.called)

        # 删白
        self.mgr._handle_auto_bind_and_command("oc_test_chat_id", "ou_sender", "/unwhite 192.168.10.5")
        self.assertFalse(any(w.get("ip") == "192.168.10.5" for w in cfg_copy["whitelist"]))

    @patch("core.notify.send_feishu_app_message")
    @patch("sentry_daemon.init_firewall_ipset")
    @patch("sentry_daemon.flush_firewall_blocks")
    @patch("core.db.save_config")
    @patch("core.db.load_config")
    def test_feishu_cmd_pause_and_resume(self, mock_load, mock_save, mock_flush, mock_init, mock_send_app):
        """测试 /pause 暂停防御 与 /resume 恢复防御 指令"""
        cfg_copy = dict(self.cfg)
        mock_load.return_value = cfg_copy

        # 暂停防御
        self.mgr._handle_auto_bind_and_command("oc_test_chat_id", "ou_sender", "/pause")
        self.assertTrue(cfg_copy["defense_paused"])
        self.assertTrue(mock_flush.called)

        # 恢复防御
        self.mgr._handle_auto_bind_and_command("oc_test_chat_id", "ou_sender", "/resume")
        self.assertFalse(cfg_copy["defense_paused"])
        self.assertTrue(mock_init.called)

    @patch("core.notify.send_feishu_app_message")
    @patch("core.db.load_config")
    def test_feishu_cmd_check_and_help(self, mock_load, mock_send_app):
        """测试 /check 溯源画像与 /help 帮助指令"""
        mock_load.return_value = self.cfg

        # 查 IP
        self.mgr._handle_auto_bind_and_command("oc_test_chat_id", "ou_sender", "/check 8.8.8.8")
        self.assertTrue(mock_send_app.called)
        card1 = mock_send_app.call_args[1].get("card_dict")
        self.assertIn("威胁情报溯源画像", card1["header"]["title"]["content"])

        # 帮助手册
        self.mgr._handle_auto_bind_and_command("oc_test_chat_id", "ou_sender", "/help")
        card2 = mock_send_app.call_args[1].get("card_dict")
        self.assertIn("快捷控制指令手册", card2["header"]["title"]["content"])


if __name__ == "__main__":
    unittest.main()

