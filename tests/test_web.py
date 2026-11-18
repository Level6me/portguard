# -*- coding: utf-8 -*-
"""PortGuard Web 控制器与 API 端点自动化测试。"""
import os
import sys
import json
import unittest
from unittest import mock
from urllib.parse import urlparse

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from controllers import dispatch_get, dispatch_post, dispatch_delete, GET_ROUTES, POST_ROUTES, DELETE_ROUTES
from controllers.base import parse_loose_json_or_lines, invalidate_blacklist_cache

class MockRequest:
    def __init__(self):
        self.sent_status = None
        self.sent_json = None
        self.sent_html = None
        self.sent_headers = {}
        self.headers = {"User-Agent": "TestAgent/1.0", "Host": "127.0.0.1:9099"}
        self.client_address = ("127.0.0.1", 54321)
        self.wfile = mock.MagicMock()

    def _send_json(self, data, status=200):
        self.sent_status = status
        self.sent_json = data

    def _send_html(self, html, status=200):
        self.sent_status = status
        self.sent_html = html

    def send_response(self, status):
        self.sent_status = status

    def send_header(self, k, v):
        self.sent_headers[k] = v

    def end_headers(self):
        pass

class WebRoutesTest(unittest.TestCase):
    def test_routes_registered(self):
        self.assertIn("/api/stats", GET_ROUTES)
        self.assertIn("/api/analytics", GET_ROUTES)
        self.assertIn("/api/settings", GET_ROUTES)
        self.assertIn("/api/blacklist", GET_ROUTES)
        self.assertIn("/api/whitelist", GET_ROUTES)
        self.assertIn("/api/report/export", GET_ROUTES)

        self.assertIn("/api/unban", POST_ROUTES)
        self.assertIn("/api/ban", POST_ROUTES)
        self.assertIn("/api/settings", POST_ROUTES)
        self.assertIn("/api/defense/toggle_pause", POST_ROUTES)

        self.assertIn("/api/hidden-ips", DELETE_ROUTES)

    def test_dispatch_get_stats(self):
        req = MockRequest()
        parsed = urlparse("/api/stats")
        matched = dispatch_get(req, parsed)
        self.assertTrue(matched)
        self.assertEqual(req.sent_status, 200)
        self.assertIn("total_banned", req.sent_json)
        self.assertIn("hourly_trend", req.sent_json)

    def test_dispatch_get_analytics(self):
        req = MockRequest()
        parsed = urlparse("/api/analytics?range=24h")
        matched = dispatch_get(req, parsed)
        self.assertTrue(matched)
        self.assertEqual(req.sent_status, 200)
        self.assertIn("date_info", req.sent_json)
        self.assertIn("hourly_distribution", req.sent_json)

    def test_dispatch_get_settings(self):
        req = MockRequest()
        parsed = urlparse("/api/settings")
        matched = dispatch_get(req, parsed)
        self.assertTrue(matched)
        self.assertEqual(req.sent_status, 200)
        self.assertIn("trap_threshold", req.sent_json)
        self.assertIn("web_port", req.sent_json)

    def test_dispatch_post_unban_validation(self):
        req = MockRequest()
        parsed = urlparse("/api/unban")
        # Empty IP
        matched = dispatch_post(req, parsed, {"ip": ""})
        self.assertTrue(matched)
        self.assertEqual(req.sent_status, 400)
        self.assertFalse(req.sent_json["success"])

        # Invalid IP format
        matched = dispatch_post(req, parsed, {"ip": "not-an-ip; rm -rf /"})
        self.assertTrue(matched)
        self.assertEqual(req.sent_status, 400)
        self.assertFalse(req.sent_json["success"])

    def test_dispatch_not_found(self):
        req = MockRequest()
        parsed = urlparse("/api/non_existent_route")
        matched = dispatch_get(req, parsed)
        self.assertFalse(matched)

    def test_dispatch_get_blacklist_pagination(self):
        req = MockRequest()
        parsed = urlparse("/api/blacklist?limit=10")
        matched = dispatch_get(req, parsed)
        self.assertTrue(matched)
        self.assertEqual(req.sent_status, 200)
        self.assertIsInstance(req.sent_json, list)

    def test_dispatch_get_blacklist_search(self):
        req = MockRequest()
        parsed = urlparse("/api/blacklist?search=127.0.0.1&limit=5")
        matched = dispatch_get(req, parsed)
        self.assertTrue(matched)
        self.assertEqual(req.sent_status, 200)
        self.assertIsInstance(req.sent_json, list)

    def test_dispatch_get_blacklist_paged_structure(self):
        req = MockRequest()
        parsed = urlparse("/api/blacklist?page=1&page_size=10")
        matched = dispatch_get(req, parsed)
        self.assertTrue(matched)
        self.assertEqual(req.sent_status, 200)
        self.assertIsInstance(req.sent_json, dict)
        self.assertIn("total", req.sent_json)
        self.assertIn("items", req.sent_json)
        self.assertEqual(req.sent_json["page"], 1)
        self.assertEqual(req.sent_json["page_size"], 10)

    def test_auth_status_and_login(self):
        # 1. 状态查询
        req = MockRequest()
        parsed = urlparse("/api/auth/status")
        matched = dispatch_get(req, parsed)
        self.assertTrue(matched)
        self.assertEqual(req.sent_status, 200)
        self.assertIn("auth_enabled", req.sent_json)

        # 2. 模拟登录（在未开启密码时放行，在开启密码时验证）
        req_post = MockRequest()
        parsed_post = urlparse("/api/auth/login")
        matched_post = dispatch_post(req_post, parsed_post, {"password": "test"})
        self.assertTrue(matched_post)
        self.assertIn(req_post.sent_status, (200, 403))

        # 3. 登出
        req_out = MockRequest()
        parsed_out = urlparse("/api/auth/logout")
        matched_out = dispatch_post(req_out, parsed_out, {})
        self.assertTrue(matched_out)
        self.assertEqual(req_out.sent_status, 200)

    def test_cluster_management_requires_auth_and_backup_redacted(self):
        import io
        import web_server
        from core.db import hash_admin_password, verify_admin_password, sanitize_config_for_export

        # 1. 验证密码哈希与常数时间校验
        hashed = hash_admin_password("MyStr0ngP@ss!")
        self.assertTrue(hashed.startswith("pbkdf2_sha256$"))
        self.assertTrue(verify_admin_password("MyStr0ngP@ss!", hashed))
        self.assertFalse(verify_admin_password("wrong", hashed))

        # 2. 验证配置备份导出必须脱敏密钥
        redacted = sanitize_config_for_export({
            "admin_password": hashed,
            "cluster_sync": {"cluster_secret": "raw_cluster_sec"},
            "feishu_bot": {"app_secret": "raw_fb_sec", "webhook_url": "https://hook.example/x"}
        })
        self.assertEqual(redacted["admin_password"], "***REDACTED***")
        self.assertEqual(redacted["cluster_sync"]["cluster_secret"], "***REDACTED***")
        self.assertEqual(redacted["feishu_bot"]["app_secret"], "***REDACTED***")
        self.assertEqual(redacted["feishu_bot"]["webhook_url"], "***REDACTED***")

        # 3. 验证开启认证时 /api/cluster/nodes 与 /api/cluster/nodes/add 均不可绕过鉴权
        fake_cfg = {
            "auth_enabled": True,
            "admin_password": hashed,
            "cluster_sync": {"cluster_secret": "sec123"}
        }
        handler = web_server.RequestHandler.__new__(web_server.RequestHandler)
        handler.client_address = ("203.0.113.10", 12345)
        handler.headers = {"Host": "example.com:9099"}
        sent_responses = []
        handler._send_json = lambda data, status=200: sent_responses.append((status, data))

        with mock.patch("web_server.load_config", return_value=fake_cfg):
            handler.path = "/api/cluster/nodes"
            handler.do_GET()
            self.assertEqual(sent_responses[-1][0], 401)

            handler.path = "/api/cluster/nodes/add"
            handler.headers = {"Host": "example.com:9099", "Content-Length": "2"}
            handler.rfile = io.BytesIO(b"{}")
            handler.do_POST()
            self.assertEqual(sent_responses[-1][0], 401)

            # 同源校验：跨站 Origin 应被拦截
            handler.headers = {"Host": "example.com:9099", "Origin": "https://evil.attacker"}
            self.assertFalse(handler._verify_same_origin())
            handler.headers = {"Host": "example.com:9099", "Origin": "https://example.com:9099"}
            self.assertTrue(handler._verify_same_origin())

    def test_analytics_all_preserves_archived_history_beyond_30d(self):
        import time
        from core.db import get_db, init_db, rollup_analytics_before_cleanup
        from controllers.stats_controller import _ANALYTICS_CACHE, _ANALYTICS_CACHE_LOCK

        init_db(auto_heal=False)
        now_ts = int(time.time())
        old_ts = now_ts - 45 * 86400
        old_dt = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(old_ts))
        recent_ts = now_ts - 2 * 86400
        recent_dt = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(recent_ts))

        conn = get_db()
        c = conn.cursor()
        c.execute("DELETE FROM daily_analytics_summary")
        c.execute("DELETE FROM daily_analytics_dim")
        c.execute("INSERT INTO events (ip, port, proto, port_name, category, level, country, region, city, isp, attack_time, timestamp, status) VALUES ('198.51.100.201', 22, 'TCP', 'SSH', 'ssh', '高危', '测试古国', '', '', 'TestISP', ?, ?, 'EXPIRED')", (old_dt, old_ts))
        c.execute("INSERT INTO events (ip, port, proto, port_name, category, level, country, region, city, isp, attack_time, timestamp, status) VALUES ('198.51.100.202', 80, 'TCP', 'HTTP', 'web', '高危', '测试近国', '', '', 'TestISP2', ?, ?, 'BANNED')", (recent_dt, recent_ts))
        cutoff_mid = rollup_analytics_before_cleanup(conn, now_ts - 30 * 86400)
        c.execute("DELETE FROM events WHERE timestamp < ? AND status NOT IN ('BANNED')", (cutoff_mid,))
        conn.commit()
        conn.close()

        with _ANALYTICS_CACHE_LOCK:
            _ANALYTICS_CACHE.clear()

        req_30d = MockRequest()
        dispatch_get(req_30d, urlparse("/api/analytics?range=30d"))
        req_all = MockRequest()
        dispatch_get(req_all, urlparse("/api/analytics?range=all"))

        self.assertGreater(req_all.sent_json["kpis"]["total_intercepted"], req_30d.sent_json["kpis"]["total_intercepted"])
        self.assertGreater(sum(req_all.sent_json["trend"]["events"]), sum(req_30d.sent_json["trend"]["events"]))
        self.assertLess(req_all.sent_json["date_info"]["start_time"], req_30d.sent_json["date_info"]["start_time"])

        # 清理测试数据
        conn = get_db()
        c = conn.cursor()
        c.execute("DELETE FROM events WHERE ip IN ('198.51.100.201', '198.51.100.202')")
        c.execute("DELETE FROM daily_analytics_summary")
        c.execute("DELETE FROM daily_analytics_dim")
        conn.commit()
        conn.close()

if __name__ == "__main__":
    unittest.main()
