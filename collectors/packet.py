# -*- coding: utf-8 -*-
"""PortGuard 网络数据报文与端口解析器 (零外部依赖)。"""
import socket
import struct
import re

class ParsedPacket(tuple):
    """兼具 3 元组兼容性与隐蔽扫描属性扩展的数据包解析结果"""
    def __new__(cls, src_ip, dst_port, proto_str, stealth_type=None, dst_ip=None):
        return super(ParsedPacket, cls).__new__(cls, (src_ip, dst_port, proto_str))

    def __init__(self, src_ip, dst_port, proto_str, stealth_type=None, dst_ip=None):
        self.src_ip = src_ip
        self.dst_port = dst_port
        self.proto = proto_str
        self.stealth_type = stealth_type
        self.dst_ip = dst_ip


def parse_packet(raw_data):
    """解析以太网帧 / SLL 帧 / 原始 IP 报文 (IPv4 / IPv6) 中的 TCP/UDP 报文与隐蔽畸形扫描标志位。

    返回 ParsedPacket(src_ip, dst_port, proto_str, stealth_type, dst_ip) 或 None。
    """
    try:
        if not raw_data or len(raw_data) < 20:
            return None

        offset = 0
        # 1. 优先判定 offset=0 (原始 IP 报文，Linux SOCK_RAW 绝大多数形态)
        if (raw_data[0] >> 4) in (4, 6):
            offset = 0
        elif len(raw_data) >= 34 and ((raw_data[14] >> 4) in (4, 6)):
            offset = 14
        elif len(raw_data) >= 36 and ((raw_data[16] >> 4) in (4, 6)):
            offset = 16
        else:
            return None

        version = raw_data[offset] >> 4
        if version == 4:
            if len(raw_data) < offset + 20:
                return None
            ip_hdr = raw_data[offset:offset + 20]
            proto_num = ip_hdr[9]
            ihl = (ip_hdr[0] & 0x0F) * 4
            if ihl < 20 or len(raw_data) < offset + ihl + 4:
                return None
            src_ip = socket.inet_ntoa(ip_hdr[12:16])
            dst_ip = socket.inet_ntoa(ip_hdr[16:20])
        elif version == 6:
            if len(raw_data) < offset + 40:
                return None
            ip_hdr = raw_data[offset:offset + 40]
            proto_num = ip_hdr[6]  # next header
            ihl = 40
            if len(raw_data) < offset + ihl + 4:
                return None
            src_ip = socket.inet_ntop(socket.AF_INET6, ip_hdr[8:24])
            dst_ip = socket.inet_ntop(socket.AF_INET6, ip_hdr[24:40])
        else:
            return None

        if proto_num not in (6, 17):  # 仅 TCP / UDP
            return None
        proto_str = "TCP" if proto_num == 6 else "UDP"

        stealth_type = None
        if proto_num == 6 and len(raw_data) >= offset + ihl + 14:
            tcp_flags = raw_data[offset + ihl + 13]
            # 深度检测 Nmap 隐蔽逃逸扫描标志位 (NULL, FIN, XMAS, SYN-FIN, SYN-RST)
            if tcp_flags == 0:
                stealth_type = "NULL_SCAN"
            elif tcp_flags == 0x01:  # 仅 FIN
                stealth_type = "FIN_SCAN"
            elif (tcp_flags & 0x29) == 0x29:  # FIN(1) + PSH(8) + URG(32)
                stealth_type = "XMAS_SCAN"
            elif (tcp_flags & 0x03) == 0x03:  # SYN(2) + FIN(1)
                stealth_type = "SYN_FIN_SCAN"
            elif (tcp_flags & 0x06) == 0x06:  # SYN(2) + RST(4)
                stealth_type = "SYN_RST_SCAN"
            elif (tcp_flags & 0x02) and not (tcp_flags & 0x10):
                stealth_type = None  # 正常标准 TCP SYN 入站请求探测 (SYN=1, ACK=0)
            else:
                # 过滤出站握手回包 (SYN-ACK: 0x12)、已建立连接的数据流 (ACK/PSH-ACK)
                return None

        l4_hdr = raw_data[offset + ihl:offset + ihl + 4]
        if len(l4_hdr) < 4:
            return None
        src_port, dst_port = struct.unpack("!HH", l4_hdr[:4])

        # 若为 UDP 协议：必须严格过滤所有出站回包与代理转发流量！
        if proto_num == 17:
            # 1. 常见公共服务源端口返回流量（DNS 53/853/5353, NTP 123, HTTPS/QUIC 443/80, OpenVPN 1194 等）直接丢弃
            if src_port in (53, 123, 853, 5353, 443, 80, 1194, 51820):
                return None
            # 2. 目标端口属于出站临时随机回包端口 (ephemeral ports >= 1024) 彻底忽略
            if dst_port >= 1024:
                return None

        return ParsedPacket(src_ip, dst_port, proto_str, stealth_type=stealth_type, dst_ip=dst_ip)
    except Exception:
        return None

def parse_port_range(port_val):
    """解析单个端口或端口范围，返回 (start_port, end_port, display_str) 或 None"""
    if isinstance(port_val, int):
        if 1 <= port_val <= 65535:
            return (port_val, port_val, port_val)
        return None
    s = str(port_val).strip()
    if not s:
        return None
    if s.isdigit():
        p = int(s)
        if 1 <= p <= 65535:
            return (p, p, p)
        return None
    m = re.match(r'^(\d+)\s*[-:~]\s*(\d+)$', s)
    if m:
        p1 = int(m.group(1))
        p2 = int(m.group(2))
        start = min(p1, p2)
        end = max(p1, p2)
        if 1 <= start <= 65535 and 1 <= end <= 65535:
            if start == end:
                return (start, end, start)
            return (start, end, f"{start}-{end}")
    return None
