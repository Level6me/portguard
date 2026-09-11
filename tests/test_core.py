#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PortGuard Core Architecture Modular Unit Tests
测试 core.db, core.firewall, core.mesh 及 core 包的直接导入与核心行为
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import core
from core.db import (
    get_db, init_db, load_config, save_config,
    DEFAULT_CONFIG, DEFAULT_HTTP_TRAPS, get_hidden_ips_set,
    get_http_traps, get_config_snapshots
)
from core.firewall import (
    validate_ip, is_infrastructure_or_cdn_ip,
    get_blacklisted_ips_set, ThreatScoreEngine, _THREAT_ENGINE,
    get_ip_threat_tags, is_survey_scanner_ip, is_idc_hosting_ip,
    ip_in_whitelist, get_local_ips
)
from core.mesh import (
    generate_cluster_token, verify_cluster_token,
    generate_cluster_response_token, verify_cluster_response_token,
    verify_cluster_response_strictly, validate_cluster_target,
    parse_cluster_host_port, format_http_target_url, format_host_header,
    normalize_cluster_node
)

class CorePackageTest(unittest.TestCase):
    def test_core_reexports(self):
        """测试 core/__init__.py 的直接导出"""
        self.assertTrue(callable(core.get_db))
        self.assertTrue(callable(core.init_db))
        self.assertTrue(callable(core.load_config))
        self.assertTrue(callable(core.save_config))
        self.assertTrue(callable(core.ban_ip_firewall))
        self.assertTrue(callable(core.unban_ip_core))
        self.assertTrue(callable(core.generate_cluster_token))
        self.assertTrue(callable(core.verify_cluster_token))
        self.assertIn("trap_ports", core.DEFAULT_CONFIG)

    def test_core_db_module(self):
        """测试 core.db 模块的配置加载与数据库接口"""
        cfg = load_config()
        self.assertIsInstance(cfg, dict)
        self.assertIn("web_port", cfg)
        self.assertIn("whitelist", cfg)
        
        traps = get_http_traps()
        self.assertIsInstance(traps, list)
        self.assertGreater(len(traps), 0)

        hidden = get_hidden_ips_set()
        self.assertIsInstance(hidden, set)

    def test_core_firewall_module(self):
        """测试 core.firewall 模块的 IP 校验与威胁研判"""
        self.assertEqual(validate_ip("192.168.1.1"), "192.168.1.1")
        self.assertEqual(validate_ip("::1"), "::1")
        self.assertIsNone(validate_ip("invalid-ip"))
        self.assertIsNone(validate_ip("1.1.1.1; ls"))

        self.assertTrue(is_infrastructure_or_cdn_ip("1.1.1.1"))
        self.assertTrue(is_infrastructure_or_cdn_ip("8.8.8.8"))
        self.assertTrue(is_infrastructure_or_cdn_ip("127.0.0.1"))
        self.assertFalse(is_infrastructure_or_cdn_ip("203.0.113.5"))

        self.assertTrue(is_survey_scanner_ip("198.20.69.1"))  # Shodan
        tags = get_ip_threat_tags("198.20.69.1")
        self.assertIsInstance(tags, list)

        engine = ThreatScoreEngine()
        score, cnt = engine.add_score("192.0.2.1", 10.0)
        self.assertGreaterEqual(score, 10.0)
        self.assertEqual(cnt, 1)

    def test_core_mesh_module(self):
        """测试 core.mesh 模块的签名验证与节点解析"""
        secret = "unit_test_secret_key"
        token = generate_cluster_token("test_target", secret, body=b"hello")
        self.assertTrue(verify_cluster_token("test_target", token, secret, body=b"hello"))
        self.assertFalse(verify_cluster_token("test_target", token, secret, body=b"tampered"))
        self.assertFalse(verify_cluster_token("wrong_target", token, secret, body=b"hello"))

        resp_token = generate_cluster_response_token(secret, body=b"resp", req_token=token)
        self.assertTrue(verify_cluster_response_token(resp_token, secret, body=b"resp", req_token=token))
        self.assertFalse(verify_cluster_response_token(resp_token, secret, body=b"wrong_body", req_token=token))

        # IPv6 解析与 URL 格式化
        host, port = parse_cluster_host_port("[2001:db8::1]:9098")
        self.assertEqual(host, "2001:db8::1")
        self.assertEqual(port, 9098)
        url = format_http_target_url(host, port, "/api/ping")
        self.assertEqual(url, "http://[2001:db8::1]:9098/api/ping")

        # SSRF 拦截
        ok, _, err = validate_cluster_target("127.0.0.1")
        self.assertFalse(ok)
        self.assertIn("SSRF", err)

if __name__ == "__main__":
    unittest.main()
