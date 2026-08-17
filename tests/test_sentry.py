#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Portsentry 核心逻辑单元测试（零外部依赖，不触碰真实数据库/防火墙）。"""
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sentry_daemon import (
    validate_ip,
    parse_port_range,
    normalize_trap_item,
    ip_in_whitelist,
    run_firewall_cmd,
)


class ValidateIpTest(unittest.TestCase):
    def test_valid_ipv4(self):
        self.assertEqual(validate_ip("8.8.8.8"), "8.8.8.8")

    def test_valid_ipv6(self):
        self.assertEqual(validate_ip("::1"), "::1")
        self.assertEqual(validate_ip("2001:db8::1"), "2001:db8::1")

    def test_reject_shell_metacharacters(self):
        for evil in ("1.1.1.1; id", "1.1.1.1 | shutdown", "1.1.1.1$(id)",
                     "1.1.1.1`id`", "1.1.1.1 & whoami", "127.0.0.1' && echo x",
                     '1.1.1.1" && echo x', "1.1.1.1\nid"):
            self.assertIsNone(validate_ip(evil), evil)

    def test_reject_urls_and_bogus(self):
        self.assertIsNone(validate_ip("http://1.1.1.1"))
        self.assertIsNone(validate_ip("1.1.1.1:80"))
        self.assertIsNone(validate_ip("999.1.1.1"))
        self.assertIsNone(validate_ip("not-an-ip"))
        self.assertIsNone(validate_ip(""))
        self.assertIsNone(validate_ip(None))


class ParsePortRangeTest(unittest.TestCase):
    def test_single(self):
        self.assertEqual(parse_port_range("8080"), (8080, 8080, 8080))
        self.assertEqual(parse_port_range(443), (443, 443, 443))

    def test_range(self):
        self.assertEqual(parse_port_range("1000-3000"), (1000, 3000, "1000-3000"))
        self.assertEqual(parse_port_range("3000:1000"), (1000, 3000, "1000-3000"))

    def test_invalid(self):
        self.assertIsNone(parse_port_range("0"))
        self.assertIsNone(parse_port_range("70000"))
        self.assertIsNone(parse_port_range("abc"))
        self.assertIsNone(parse_port_range(""))


class WhitelistTest(unittest.TestCase):
    def test_loopback_always_whitelisted(self):
        self.assertTrue(ip_in_whitelist("127.0.0.1", []))
        self.assertTrue(ip_in_whitelist("::1", []))

    def test_exact_and_cidr(self):
        items = [{"ip": "8.8.8.8"}, {"ip": "10.0.0.0/8"}]
        self.assertTrue(ip_in_whitelist("8.8.8.8", items))
        self.assertTrue(ip_in_whitelist("10.2.3.4", items))
        self.assertFalse(ip_in_whitelist("8.8.4.4", items))


class FirewallCmdTest(unittest.TestCase):
    def test_args_not_shell(self):
        with mock.patch("sentry_daemon.subprocess.run") as mocked:
            run_firewall_cmd("iptables", "-I", "INPUT", "-s", "1.2.3.4", "-j", "DROP")
            mocked.assert_called_once_with(
                ["iptables", "-I", "INPUT", "-s", "1.2.3.4", "-j", "DROP"],
                stdout=mock.ANY,
                stderr=mock.ANY,
            )
            # 断言没有 shell=True
            self.assertNotIn("shell", mocked.call_args.kwargs or {})


class NormalizeTrapTest(unittest.TestCase):
    def test_int_port(self):
        norm = normalize_trap_item({"port": 6379, "name": "Redis"})
        self.assertIsNotNone(norm)
        self.assertEqual(norm["port"], 6379)
        self.assertEqual(norm["protocol"], "tcp")

    def test_invalid(self):
        self.assertIsNone(normalize_trap_item({"port": "abc"}))
        self.assertIsNone(normalize_trap_item({}))


if __name__ == "__main__":
    unittest.main()
