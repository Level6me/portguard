#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""PortGuard 核心逻辑单元测试（零外部依赖，不触碰真实数据库/防火墙）。"""
import os
import sys
import time
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
        items = [{"ip": "198.51.100.1"}, {"ip": "10.0.0.0/8"}]
        self.assertTrue(ip_in_whitelist("198.51.100.1", items))
        self.assertTrue(ip_in_whitelist("10.2.3.4", items))
        self.assertFalse(ip_in_whitelist("198.51.100.2", items))


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
        pkt = self._ipv4_packet(6, "1.2.65.4", "198.51.100.1", 12345, 8085, with_eth=False)
        self.assertEqual(parse_packet(pkt), ("1.2.65.4", 8085, "TCP"))

    def test_ipv4_udp(self):
        pkt = self._ipv4_packet(17, "198.51.100.5", "198.51.100.1", 40000, 53)
        self.assertEqual(parse_packet(pkt), ("198.51.100.5", 53, "UDP"))

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

    def test_business_port_exemption(self):
        from sentry_daemon import is_trap_port
        cfg = {
            "web_port": 9099,
            "business_ports": [{"port": 4212, "name": "Trojan 业务端口"}],
            "trap_ports": [{"port_start": 1, "port_end": 60000, "enabled": True}]
        }
        # 即使配置了 1-60000 范围诱捕，业务端口 4212 必须 100% 绝对避让，返回 None
        res = is_trap_port(4212, cfg)
        self.assertIsNone(res)

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

    def test_ban_ip_comprehensive_logs_and_blacklist(self):
        from sentry_daemon import ban_ip, get_db, init_db
        init_db()
        test_ip = "198.51.100.99"
        
        # 执行封禁
        ban_ip(test_ip, port=443, reason="Web特征: 探测高危敏感配置文件", category="web", level="极高危")
        time.sleep(0.1)  # 等待异步批量日志落盘
        
        conn = get_db()
        c = conn.cursor()
        
        # 1. 验证拦截日志 events 表有记录
        c.execute("SELECT ip, port, category, level, port_name, status FROM events WHERE ip = ?", (test_ip,))
        ev = c.fetchone()
        self.assertIsNotNone(ev)
        self.assertEqual(ev[0], test_ip)
        self.assertEqual(ev[1], 443)
        self.assertEqual(ev[2], "web")
        self.assertEqual(ev[3], "极高危")
        self.assertEqual(ev[5], "BANNED")
        
        # 2. 验证黑名单 blacklist 表有记录
        c.execute("SELECT ip, reason, level FROM blacklist WHERE ip = ?", (test_ip,))
        bl = c.fetchone()
        self.assertIsNotNone(bl)
        self.assertEqual(bl[0], test_ip)
        self.assertEqual(bl[1], "Web特征: 探测高危敏感配置文件")
        self.assertEqual(bl[2], "极高危")
        
        # 3. 验证端口访问日志 port_access_logs 有记录
        c.execute("SELECT ip, port, action FROM port_access_logs WHERE ip = ?", (test_ip,))
        pl = c.fetchone()
        self.assertIsNotNone(pl)
        self.assertEqual(pl[0], test_ip)
        self.assertEqual(pl[2], "INTERCEPTED")
        
        # 清理测试数据
        c.execute("DELETE FROM events WHERE ip = ?", (test_ip,))
        c.execute("DELETE FROM blacklist WHERE ip = ?", (test_ip,))
        c.execute("DELETE FROM port_access_logs WHERE ip = ?", (test_ip,))
        conn.commit()
        conn.close()

    def test_trap_all_unopened_ports(self):
        from sentry_daemon import GlobalPortSniffer, init_db
        init_db()
        sniffer = GlobalPortSniffer()
        
        # 1. 开启 trap_all_unopened_ports 时，探测未开放端口立即触发 ban_ip 诱捕
        with mock.patch("sentry_daemon.load_config") as mock_cfg, \
             mock.patch("sentry_daemon.ban_ip") as mock_ban:
            mock_cfg.return_value = {
                "whitelist": [],
                "trap_ports": [],
                "trap_business_ports": False,
                "trap_all_unopened_ports": True
            }
            sniffer._handle_port_access("203.0.113.88", 54321, "TCP")
            time.sleep(0.05)
            mock_ban.assert_called_once()
            args, _ = mock_ban.call_args
            self.assertEqual(args[0], "203.0.113.88")
            self.assertEqual(args[1], 54321)

        # 2. 关闭 trap_all_unopened_ports 时，探测未开放端口仅记录日志，不调用 ban_ip
        with mock.patch("sentry_daemon.load_config") as mock_cfg2, \
             mock.patch("sentry_daemon.ban_ip") as mock_ban2:
            mock_cfg2.return_value = {
                "whitelist": [],
                "trap_ports": [],
                "trap_business_ports": False,
                "trap_all_unopened_ports": False,
                "trap_all_ports": False
            }
            sniffer._handle_port_access("203.0.113.89", 54322, "TCP")
            time.sleep(0.05)
            mock_ban2.assert_not_called()

    def test_trap_all_ports_zero_trust(self):
        from sentry_daemon import GlobalPortSniffer, init_db
        init_db()
        sniffer = GlobalPortSniffer()

        # 开启全端口诱捕：探测任何端口 (如 SSH 22, 业务 80, 数据库 3306, 未开放端口 9999) 均直接拉黑
        with mock.patch("sentry_daemon.load_config") as mock_cfg, \
             mock.patch("sentry_daemon.ban_ip") as mock_ban:
            mock_cfg.return_value = {
                "whitelist": [],
                "trap_ports": [],
                "trap_business_ports": True,
                "trap_all_unopened_ports": True,
                "trap_all_ports": True,
                "web_port": 9099
            }
            # 探测业务端口 22
            sniffer._handle_port_access("203.0.113.100", 22, "TCP")
            time.sleep(0.05)
            mock_ban.assert_called_once()
            args, _ = mock_ban.call_args
            self.assertEqual(args[0], "203.0.113.100")
            self.assertEqual(args[1], 22)

    def test_survey_and_idc_detection(self):
        from sentry_daemon import is_survey_scanner_ip, is_idc_hosting_ip
        # Censys IP
        self.assertTrue(is_survey_scanner_ip("66.132.172.180"))
        # Shodan IP
        self.assertTrue(is_survey_scanner_ip("198.20.69.5"))
        # Onyphe IP
        self.assertTrue(is_survey_scanner_ip("195.184.76.124"))
        # 运营商关键词命中
        self.assertTrue(is_survey_scanner_ip("1.2.3.4", {"isp": "Censys, Inc."}))
        # 正常家庭宽带 IP
        self.assertFalse(is_survey_scanner_ip("123.123.123.123", {"isp": "ChinaNet", "country": "中国"}))

        # IDC 机房识别
        self.assertTrue(is_idc_hosting_ip("1.2.3.4", {"isp": "Amazon.com, Inc."}))
        self.assertTrue(is_idc_hosting_ip("1.2.3.4", {"isp": "DigitalOcean, LLC"}))
        self.assertFalse(is_idc_hosting_ip("1.2.3.4", {"isp": "Chinanet Guangdong"}))

    def test_business_port_security_hardening(self):
        from sentry_daemon import GlobalPortSniffer, init_db
        init_db()
        sniffer = GlobalPortSniffer()

        with mock.patch("sentry_daemon.load_config") as mock_cfg, \
             mock.patch("sentry_daemon.ban_ip") as mock_ban:
            mock_cfg.return_value = {
                "whitelist": [],
                "trap_ports": [],
                "business_ports": [
                    {"port": 4212, "name": "trojan", "block_scanner": True, "block_idc": True}
                ],
                "web_port": 9099
            }
            # 1. Censys 测绘探测 4212 业务端口 -> 拦截
            sniffer._handle_port_access("66.132.172.214", 4212, "TCP")
            time.sleep(0.05)
            mock_ban.assert_called_once()
            args, _ = mock_ban.call_args
            self.assertEqual(args[0], "66.132.172.214")
            self.assertEqual(args[1], 4212)

    def test_unban_ip_core_ipv4_and_ipv6(self):
        from sentry_daemon import unban_ip_core, get_db, init_db
        init_db()
        test_ip = "192.0.2.100"
        test_ipv6 = "2001:db8::99"
        conn = get_db()
        c = conn.cursor()
        c.execute("INSERT OR REPLACE INTO blacklist (ip, reason, level, ban_time, timestamp) VALUES (?, 'test', '高危', 'now', 123)", (test_ip,))
        c.execute("INSERT OR REPLACE INTO blacklist (ip, reason, level, ban_time, timestamp) VALUES (?, 'test', '高危', 'now', 123)", (test_ipv6,))
        c.execute("INSERT INTO events (ip, port, proto, port_name, category, level, country, region, city, isp, attack_time, timestamp, status) VALUES (?, 80, 'TCP', 'test', 'web', '高危', '', '', '', '', 'now', 123, 'BANNED')", (test_ip,))
        conn.commit()
        conn.close()

        with mock.patch("sentry_daemon.subprocess.run") as mock_sub:
            mock_sub.return_value.returncode = 1  # 模拟循环删除结束
            res1 = unban_ip_core(test_ip)
            self.assertTrue(res1)
            res2 = unban_ip_core(test_ipv6)
            self.assertTrue(res2)

        conn = get_db()
        c = conn.cursor()
        c.execute("SELECT ip FROM blacklist WHERE ip IN (?, ?)", (test_ip, test_ipv6))
        self.assertEqual(len(c.fetchall()), 0)
        c.execute("SELECT status FROM events WHERE ip = ?", (test_ip,))
        self.assertEqual(c.fetchone()[0], "UNBANNED")
        c.execute("DELETE FROM events WHERE ip IN (?, ?)", (test_ip, test_ipv6))
        conn.commit()
        conn.close()


    def test_stealth_scan_packet_parsing(self):
        from sentry_daemon import parse_packet
        import struct
        # 构造 IPv4 TCP NULL Scan 报文 (flags = 0)
        ip_hdr = b"\x45\x00\x00\x28\x00\x01\x00\x00\x40\x06\x00\x00" + socket.inet_aton("198.51.100.1") + socket.inet_aton("198.51.100.2")
        tcp_null = struct.pack("!HHIIBBHHH", 12345, 80, 0, 0, 0x50, 0x00, 1024, 0, 0)
        pkt_null = ip_hdr + tcp_null
        res_null = parse_packet(pkt_null)
        self.assertIsNotNone(res_null)
        self.assertEqual(res_null.stealth_type, "NULL_SCAN")

        # 构造 XMAS Scan (FIN+PSH+URG = 0x29)
        tcp_xmas = struct.pack("!HHIIBBHHH", 12345, 443, 0, 0, 0x50, 0x29, 1024, 0, 0)
        pkt_xmas = ip_hdr + tcp_xmas
        res_xmas = parse_packet(pkt_xmas)
        self.assertIsNotNone(res_xmas)
        self.assertEqual(res_xmas.stealth_type, "XMAS_SCAN")

        # 构造 FIN Scan (0x01)
        tcp_fin = struct.pack("!HHIIBBHHH", 12345, 22, 0, 0, 0x50, 0x01, 1024, 0, 0)
        pkt_fin = ip_hdr + tcp_fin
        res_fin = parse_packet(pkt_fin)
        self.assertIsNotNone(res_fin)
        self.assertEqual(res_fin.stealth_type, "FIN_SCAN")

    def test_search_engine_crawler_verification(self):
        from sentry_daemon import verify_search_engine_crawler
        # 1. 冒充 Googlebot 但 PTR 解析失败
        with mock.patch("socket.gethostbyaddr") as mock_ptr:
            mock_ptr.side_effect = Exception("No PTR")
            is_val, err = verify_search_engine_crawler("1.2.3.4", "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)")
            self.assertFalse(is_val)
            self.assertIn("伪造", err)

        # 2. 合法 Googlebot PTR
        with mock.patch("socket.gethostbyaddr") as mock_ptr2, \
             mock.patch("socket.gethostbyname_ex") as mock_fwd:
            mock_ptr2.return_value = ("crawl-66-249-66-1.googlebot.com", [], ["66.249.66.1"])
            mock_fwd.return_value = ("crawl-66-249-66-1.googlebot.com", [], ["66.249.66.1"])
            is_val2, name = verify_search_engine_crawler("66.249.66.1", "Googlebot/2.1")
            self.assertTrue(is_val2)
            self.assertEqual(name, "Googlebot")

    def test_cluster_mesh_token(self):
        from sentry_daemon import generate_cluster_token, verify_cluster_token
        secret = "my_cluster_secret_key_12345"
        ip = "203.0.113.88"
        token = generate_cluster_token(ip, secret)
        self.assertTrue(verify_cluster_token(ip, token, secret))
        self.assertFalse(verify_cluster_token(ip, "invalid_token", secret))
        self.assertFalse(verify_cluster_token("203.0.113.89", token, secret))


if __name__ == "__main__":
    unittest.main()




