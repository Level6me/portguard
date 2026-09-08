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

    def test_parse_loose_json(self):
        self.assertEqual(parse_loose_json_or_lines(""), [])
        self.assertEqual(parse_loose_json_or_lines('["1.1.1.1", "2.2.2.2"]'), ["1.1.1.1", "2.2.2.2"])
        # trailing comma tolerance
        self.assertEqual(parse_loose_json_or_lines('["1.1.1.1", ]'), ["1.1.1.1"])
        # plain text line mode
        self.assertEqual(parse_loose_json_or_lines("1.1.1.1\n2.2.2.2"), ["1.1.1.1", "2.2.2.2"])

if __name__ == "__main__":
    unittest.main()
