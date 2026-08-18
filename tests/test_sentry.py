#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Portsentry 核心逻辑单元测试（零外部依赖，不触碰真实数据库/防火墙）。"""
import os
import sys
import socket
import struct
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sentry_daemon import (
    validate_ip,
    parse_port_range,
    normalize_trap_item,
    ip_in_whitelist,
    run_firewall_cmd,
    parse_packet,
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


class ParsePacketTest(unittest.TestCase):
    def _ipv4_packet(self, proto, src, dst, sport, dport, with_eth=True):
        eth = (b"\x00" * 14) if with_eth else b""
        ip = bytearray(20)
        ip[0] = 0x45
        ip[9] = proto
        ip[12:16] = socket.inet_aton(src)
        ip[16:20] = socket.inet_aton(dst)
        if proto == 6:
            l4 = struct.pack("!HHIIBBHHH", sport, dport, 0, 0, 0x50, 0x02, 65535, 0, 0)
        else:
            l4 = struct.pack("!HHHH", sport, dport, 8, 0)
        return eth + bytes(ip) + l4

    def _ipv6_packet(self, proto, src, dst, sport, dport, with_eth=True):
        eth = (b"\x00" * 14) if with_eth else b""
        ip = bytearray(40)
        ip[0] = 0x60
        ip[6] = proto
        ip[8:24] = socket.inet_pton(socket.AF_INET6, src)
        ip[24:40] = socket.inet_pton(socket.AF_INET6, dst)
        if proto == 6:
            l4 = struct.pack("!HHIIBBHHH", sport, dport, 0, 0, 0x50, 0x02, 65535, 0, 0)
        else:
            l4 = struct.pack("!HHHH", sport, dport, 8, 0)
        return eth + bytes(ip) + l4

    def test_ipv4_tcp_ethernet(self):
        pkt = self._ipv4_packet(6, "1.2.3.4", "5.6.7.8", 12345, 8080, with_eth=True)
        self.assertEqual(parse_packet(pkt), ("1.2.3.4", 8080, "TCP"))

    def test_ipv4_tcp_raw(self):
        # 针对带 0x41 字节的特殊 IP 测试 raw socket 模式下的 offset 判定
        pkt = self._ipv4_packet(6, "1.2.65.4", "43.108.18.47", 12345, 8085, with_eth=False)
        self.assertEqual(parse_packet(pkt), ("1.2.65.4", 8085, "TCP"))

    def test_ipv4_udp(self):
        pkt = self._ipv4_packet(17, "8.8.8.8", "1.1.1.1", 53, 5353)
        self.assertEqual(parse_packet(pkt), ("8.8.8.8", 5353, "UDP"))

    def test_ipv6_tcp(self):
        pkt = self._ipv6_packet(6, "2408:8222::1", "2409::1", 12345, 443)
        self.assertEqual(parse_packet(pkt), ("2408:8222::1", 443, "TCP"))

    def test_ipv6_udp(self):
        pkt = self._ipv6_packet(17, "2001:db8::99", "2001:db8::1", 40000, 53)
        self.assertEqual(parse_packet(pkt), ("2001:db8::99", 53, "UDP"))

    def test_non_tcp_udp_skipped(self):
        pkt = self._ipv4_packet(1, "1.2.3.4", "5.6.7.8", 0, 0)  # ICMP
        self.assertIsNone(parse_packet(pkt))

    def test_garbage(self):
        self.assertIsNone(parse_packet(b"\x00\x01\x02"))
        self.assertIsNone(parse_packet(None))


class IsTrapPortTest(unittest.TestCase):
    def test_business_trap_priority_over_broad_range(self):
        from sentry_daemon import is_trap_port
        cfg = {
            "web_port": 9099,
            "trap_business_ports": False,
            "trap_ports": [
                {"port": "1-60000", "is_business": False, "enabled": True},
                {"port": 22, "is_business": True, "enabled": True, "name": "SSH 业务诱捕"}
            ]
        }
        res = is_trap_port(22, cfg)
        self.assertIsNotNone(res)
        self.assertTrue(res.get("is_business"))
        self.assertEqual(res.get("port"), 22)

    def test_global_business_trap(self):
        from sentry_daemon import is_trap_port
        cfg = {
            "web_port": 9099,
            "trap_business_ports": True,
            "trap_ports": []
        }
        res = is_trap_port(8085, cfg)
        self.assertIsNotNone(res)
        self.assertTrue(res.get("is_business"))

    def test_site_log_collector_and_schema(self):
        from sentry_daemon import SiteLogCollector, site_collector_instance, get_db, init_db
        init_db()
        self.assertIsNotNone(site_collector_instance)
        collector = SiteLogCollector()
        targets = collector._discover_log_files()
        self.assertIsInstance(targets, list)
        
        # 验证 access_logs 数据表中包含 domain 字段
        conn = get_db()
        c = conn.cursor()
        c.execute("INSERT INTO access_logs (ip, domain, method, path, status_code, user_agent, country, region, city, isp, access_time, timestamp) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                  ("1.2.3.4", "test.example.com", "GET", "/api/test", 200, "curl/7.88.1", "CN", "Beijing", "Beijing", "Telecom", "2026-08-18 12:00:00", 1787035200))
        conn.commit()
        
        c.execute("SELECT ip, domain, method, path, status_code FROM access_logs WHERE ip = '1.2.3.4'")
        row = c.fetchone()
        self.assertIsNotNone(row)
        self.assertEqual(row[0], "1.2.3.4")
        self.assertEqual(row[1], "test.example.com")
        self.assertEqual(row[2], "GET")
        self.assertEqual(row[3], "/api/test")
        self.assertEqual(row[4], 200)
        
    def test_http_traps_and_scanner_defense(self):
        from sentry_daemon import get_http_traps, check_http_request_traps, init_db, ban_ip
        init_db()
        rules = get_http_traps()
        self.assertIsInstance(rules, list)
        self.assertTrue(len(rules) >= 4)
        
        # 测试敏感路径探测匹配 (如 /.env)
        with mock.patch("sentry_daemon.ban_ip") as mock_ban:
            # 正常请求不触发封禁
            res = check_http_request_traps("203.0.113.5", "example.com", "GET", "/index.html", 200, "Mozilla/5.0")
            self.assertFalse(res)
            mock_ban.assert_not_called()
            
            # 高危敏感路径探测触发封禁
            res_env = check_http_request_traps("203.0.113.6", "example.com", "GET", "/.env", 404, "curl/7.88")
            self.assertTrue(res_env)
            mock_ban.assert_called_once()
            
        # 测试扫描器工具指纹匹配 (如 sqlmap)
        with mock.patch("sentry_daemon.ban_ip") as mock_ban_ua:
            res_sqlmap = check_http_request_traps("203.0.113.7", "example.com", "GET", "/api/test", 200, "sqlmap/1.5.2#stable")
            self.assertTrue(res_sqlmap)
            mock_ban_ua.assert_called_once()


if __name__ == "__main__":
    unittest.main()

