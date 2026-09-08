
import io

GEO_COUNTRY_CN = {
    "United States": "美国", "United Kingdom": "英国", "Germany": "德国", "France": "法国",
    "Japan": "日本", "South Korea": "韩国", "China": "中国", "Russia": "俄罗斯",
    "Canada": "加拿大", "Australia": "澳大利亚", "Brazil": "巴西", "India": "印度",
    "Singapore": "新加坡", "Hong Kong": "中国香港", "Taiwan": "中国台湾", "Netherlands": "荷兰",
    "The Netherlands": "荷兰", "Italy": "意大利", "Spain": "西班牙", "Vietnam": "越南", "Thailand": "泰国",
    "Indonesia": "印度尼西亚", "Malaysia": "马来西亚", "Philippines": "菲律宾", "Turkey": "土耳其",
    "Ukraine": "乌克兰", "Poland": "波兰", "Sweden": "瑞典", "Switzerland": "瑞士",
    "South Africa": "南非", "Egypt": "埃及", "Mexico": "墨西哥", "Argentina": "阿根廷",
    "Chile": "智利", "Colombia": "哥伦比亚", "Iran": "伊朗", "Israel": "以色列",
    "Saudi Arabia": "沙特阿拉伯", "United Arab Emirates": "阿联酋", "Pakistan": "巴基斯坦",
    "Belgium": "比利时", "Finland": "芬兰", "Bulgaria": "保加利亚", "Romania": "罗马尼亚",
    "Seychelles": "塞舌尔", "Norway": "挪威", "Denmark": "丹麦", "Austria": "奥地利",
    "Czech Republic": "捷克", "Hungary": "匈牙利", "Greece": "希腊", "Portugal": "葡萄牙"
}

def translate_country_cn(name):
    if not name:
        return "未知地域"
    return GEO_COUNTRY_CN.get(name.strip(), name.strip())
# -*- coding: utf-8 -*-
"""PortGuard GeoIP 离线全球高精度定位与运营商解析引擎 (MaxMind MMDB + IP2Region xdb)"""
import os
import sys
import time
import struct
import socket
import re
import ipaddress
import urllib.request
import urllib.error
import json
import threading
from concurrent.futures import ThreadPoolExecutor

class XdbSearcher:
    HEADER_INFO_LENGTH = 256
    VECTOR_INDEX_ROWS = 256
    VECTOR_INDEX_COLS = 256
    VECTOR_INDEX_SIZE = 8
    SEGMENT_INDEX_SIZE = 14

    def __init__(self, dbfile=None, contentBuff=None):
        self.dbfile = dbfile
        self.contentBuff = contentBuff
        self.handle = None
        if not self.contentBuff and self.dbfile:
            self.handle = io.open(self.dbfile, "rb")

    def close(self):
        if self.handle:
            self.handle.close()
            self.handle = None

    @staticmethod
    def loadContentFromFile(dbfile):
        with io.open(dbfile, "rb") as f:
            return f.read()

    @staticmethod
    def ip_to_long(ip_str):
        parts = ip_str.split(".")
        if len(parts) != 4:
            return 0
        try:
            return (int(parts[0]) << 24) | (int(parts[1]) << 16) | (int(parts[2]) << 8) | int(parts[3])
        except Exception:
            return 0

    def searchByIPStr(self, ip_str):
        ip = self.ip_to_long(ip_str)
        if ip == 0:
            return None
        il0 = (ip >> 24) & 0xFF
        il1 = (ip >> 16) & 0xFF
        v_idx = il0 * self.VECTOR_INDEX_COLS * self.VECTOR_INDEX_SIZE + il1 * self.VECTOR_INDEX_SIZE
        v_offset = self.HEADER_INFO_LENGTH + v_idx

        if self.contentBuff:
            if v_offset + 8 > len(self.contentBuff):
                return None
            s_ptr, e_ptr = struct.unpack("<II", self.contentBuff[v_offset:v_offset + 8])
        else:
            self.handle.seek(v_offset)
            s_ptr, e_ptr = struct.unpack("<II", self.handle.read(8))

        if s_ptr == 0:
            return None

        low = 0
        high = (e_ptr - s_ptr) // self.SEGMENT_INDEX_SIZE
        data_len = 0
        data_ptr = 0

        while low <= high:
            mid = (low + high) >> 1
            pos = s_ptr + mid * self.SEGMENT_INDEX_SIZE
            if self.contentBuff:
                buffer = self.contentBuff[pos:pos + self.SEGMENT_INDEX_SIZE]
            else:
                self.handle.seek(pos)
                buffer = self.handle.read(self.SEGMENT_INDEX_SIZE)

            sip, eip, d_len, d_ptr = struct.unpack("<IIHI", buffer)

            if ip < sip:
                high = mid - 1
            elif ip > eip:
                low = mid + 1
            else:
                data_len = d_len
                data_ptr = d_ptr
                break

        if data_len == 0:
            return None

        if self.contentBuff:
            region_bytes = self.contentBuff[data_ptr:data_ptr + data_len]
        else:
            self.handle.seek(data_ptr)
            region_bytes = self.handle.read(data_len)

        return region_bytes.decode("utf-8", errors="ignore")

class MMDBReader:
    """轻量级、零外部依赖的高性能纯 Python MaxMind DB (MMDB) 离线解析器"""
    METADATA_START = b"\xab\xcd\xefMaxMind.com"

    def __init__(self, filepath):
        with open(filepath, "rb") as f:
            self.buf = f.read()
        
        meta_idx = self.buf.rfind(self.METADATA_START)
        if meta_idx == -1:
            raise ValueError("Invalid MMDB file: metadata marker not found")
        
        meta_offset = meta_idx + len(self.METADATA_START)
        self.data_section_start = 0
        meta, _ = self._decode(meta_offset, is_meta=True)
        self.metadata = meta or {}
        
        self.node_count = self.metadata.get("node_count", 0)
        self.record_size = self.metadata.get("record_size", 0)
        self.ip_version = self.metadata.get("ip_version", 4)
        self.tree_size = (self.node_count * self.record_size * 2) // 8
        self.data_section_start = self.tree_size + 16
        
        self.ipv4_start_node = 0
        if self.ip_version == 6:
            node = 0
            for _ in range(96):
                if node >= self.node_count:
                    break
                node = self._read_left_record(node)
            self.ipv4_start_node = node

    def _read_left_record(self, node_idx):
        rs = self.record_size
        buf = self.buf
        if rs == 24:
            offset = node_idx * 6
            return (buf[offset] << 16) | (buf[offset + 1] << 8) | buf[offset + 2]
        elif rs == 28:
            offset = node_idx * 7
            return ((buf[offset + 3] & 0xF0) << 20) | (buf[offset] << 16) | (buf[offset + 1] << 8) | buf[offset + 2]
        elif rs == 32:
            offset = node_idx * 8
            return (buf[offset] << 24) | (buf[offset + 1] << 16) | (buf[offset + 2] << 8) | buf[offset + 3]
        raise ValueError(f"Unsupported record size: {rs}")

    def _read_right_record(self, node_idx):
        rs = self.record_size
        buf = self.buf
        if rs == 24:
            offset = node_idx * 6
            return (buf[offset + 3] << 16) | (buf[offset + 4] << 8) | buf[offset + 5]
        elif rs == 28:
            offset = node_idx * 7
            return ((buf[offset + 3] & 0x0F) << 24) | (buf[offset + 4] << 16) | (buf[offset + 5] << 8) | buf[offset + 6]
        elif rs == 32:
            offset = node_idx * 8
            return (buf[offset + 4] << 24) | (buf[offset + 5] << 16) | (buf[offset + 6] << 8) | buf[offset + 7]
        raise ValueError(f"Unsupported record size: {rs}")

    def _decode(self, offset, is_meta=False):
        buf = self.buf
        base = 0 if is_meta else self.data_section_start
        ctrl = buf[offset]
        offset += 1
        type_code = ctrl >> 5
        
        if type_code == 1: # Pointer
            size = (ctrl >> 3) & 0x03
            if size == 0:
                ptr = ((ctrl & 0x07) << 8) | buf[offset]
                offset += 1
            elif size == 1:
                ptr = 2048 + (((ctrl & 0x07) << 16) | (buf[offset] << 8) | buf[offset + 1])
                offset += 2
            elif size == 2:
                ptr = 526336 + (((ctrl & 0x07) << 24) | (buf[offset] << 16) | (buf[offset + 1] << 8) | buf[offset + 2])
                offset += 3
            else:
                ptr = (buf[offset] << 24) | (buf[offset + 1] << 16) | (buf[offset + 2] << 8) | buf[offset + 3]
                offset += 4
            val, _ = self._decode(base + ptr, is_meta=is_meta)
            return val, offset

        if type_code == 0: # Extended
            type_code = 7 + buf[offset]
            offset += 1

        length = ctrl & 0x1F
        if length == 29:
            length = 29 + buf[offset]
            offset += 1
        elif length == 30:
            length = 285 + ((buf[offset] << 8) | buf[offset + 1])
            offset += 2
        elif length == 31:
            length = 65821 + ((buf[offset] << 16) | (buf[offset + 1] << 8) | buf[offset + 2])
            offset += 3

        if type_code == 2: # UTF-8 String
            val = buf[offset:offset + length].decode("utf-8", "replace")
            return val, offset + length
        elif type_code == 3: # Double
            val = struct.unpack_from(">d", buf, offset)[0]
            return val, offset + 8
        elif type_code == 4: # Bytes
            val = buf[offset:offset + length]
            return val, offset + length
        elif type_code in (5, 6, 9, 10): # Unsigned ints
            val = int.from_bytes(buf[offset:offset + length], "big") if length else 0
            return val, offset + length
        elif type_code == 8: # Signed int32
            val = int.from_bytes(buf[offset:offset + length], "big", signed=True) if length else 0
            return val, offset + length
        elif type_code == 7: # Map
            m = {}
            for _ in range(length):
                k, offset = self._decode(offset, is_meta=is_meta)
                v, offset = self._decode(offset, is_meta=is_meta)
                m[k] = v
            return m, offset
        elif type_code == 11: # Array
            arr = []
            for _ in range(length):
                el, offset = self._decode(offset, is_meta=is_meta)
                arr.append(el)
            return arr, offset
        elif type_code == 14: # Bool
            return (length != 0), offset
        elif type_code == 15: # Float
            val = struct.unpack_from(">f", buf, offset)[0]
            return val, offset + 4
        
        return None, offset + length

    def get(self, ip_str):
        try:
            if ":" in ip_str:
                ip_bytes = socket.inet_pton(socket.AF_INET6, ip_str)
                node = 0
            else:
                ip_bytes = socket.inet_pton(socket.AF_INET, ip_str)
                node = self.ipv4_start_node if self.ip_version == 6 else 0
        except Exception:
            return None

        node_count = self.node_count
        for byte in ip_bytes:
            for bit_pos in (7, 6, 5, 4, 3, 2, 1, 0):
                bit = (byte >> bit_pos) & 1
                node = self._read_right_record(node) if bit else self._read_left_record(node)
                if node >= node_count:
                    break
            if node >= node_count:
                break
        
        if node == node_count:
            return None
        if node > node_count:
            data_offset = self.data_section_start + (node - node_count - 16)
            data, _ = self._decode(data_offset)
            return data
        return None

_GLOBAL_MMDB_CITY = None
_GLOBAL_MMDB_ASN = None
_MMDB_LOCK = threading.Lock()
_MMDB_LAST_TRY = 0

def get_mmdb_readers():
    """获取全局常驻内存的 MaxMind GeoLite2 (City + ASN) 离线引擎实例"""
    global _GLOBAL_MMDB_CITY, _GLOBAL_MMDB_ASN, _MMDB_LAST_TRY
    if _GLOBAL_MMDB_CITY is not None and _GLOBAL_MMDB_ASN is not None:
        return _GLOBAL_MMDB_CITY, _GLOBAL_MMDB_ASN
    now = time.time()
    if now - _MMDB_LAST_TRY < 10.0 and (_GLOBAL_MMDB_CITY is not None or _GLOBAL_MMDB_ASN is not None):
        return _GLOBAL_MMDB_CITY, _GLOBAL_MMDB_ASN
    with _MMDB_LOCK:
        if _GLOBAL_MMDB_CITY is not None and _GLOBAL_MMDB_ASN is not None:
            return _GLOBAL_MMDB_CITY, _GLOBAL_MMDB_ASN
        _MMDB_LAST_TRY = now

        city_candidates = [
            "/opt/portguard/GeoLite2-City.mmdb",
            "/opt/portsentry-ui/GeoLite2-City.mmdb",
            os.path.join(os.path.dirname(os.path.abspath(__file__)), "GeoLite2-City.mmdb"),
            os.path.join(os.getcwd(), "GeoLite2-City.mmdb"),
            "/tmp/GeoLite2-City.mmdb"
        ]
        asn_candidates = [
            "/opt/portguard/GeoLite2-ASN.mmdb",
            "/opt/portsentry-ui/GeoLite2-ASN.mmdb",
            os.path.join(os.path.dirname(os.path.abspath(__file__)), "GeoLite2-ASN.mmdb"),
            os.path.join(os.getcwd(), "GeoLite2-ASN.mmdb"),
            "/tmp/GeoLite2-ASN.mmdb"
        ]

        if _GLOBAL_MMDB_CITY is None:
            for p in city_candidates:
                if os.path.isfile(p) and os.path.getsize(p) > 1024 * 1024:
                    try:
                        _GLOBAL_MMDB_CITY = MMDBReader(p)
                        print(f"[PortGuard GeoIP] ⚡ 成功载入 MaxMind GeoLite2-City 全球离线城市库: {p}")
                        break
                    except Exception as e:
                        print(f"[PortGuard GeoIP] MaxMind City 库载入异常 ({p}): {e}")

        if _GLOBAL_MMDB_ASN is None:
            for p in asn_candidates:
                if os.path.isfile(p) and os.path.getsize(p) > 1024 * 1024:
                    try:
                        _GLOBAL_MMDB_ASN = MMDBReader(p)
                        print(f"[PortGuard GeoIP] ⚡ 成功载入 MaxMind GeoLite2-ASN 全球离线运营商库: {p}")
                        break
                    except Exception as e:
                        print(f"[PortGuard GeoIP] MaxMind ASN 库载入异常 ({p}): {e}")

        return _GLOBAL_MMDB_CITY, _GLOBAL_MMDB_ASN

_GLOBAL_XDB_SEARCHER = None
_GLOBAL_XDB_LOCK = threading.Lock()
_XDB_LAST_TRY = 0

def get_xdb_searcher():
    """获取全局常驻内存的 IP2Region 本地离线引擎实例"""
    global _GLOBAL_XDB_SEARCHER, _XDB_LAST_TRY
    if _GLOBAL_XDB_SEARCHER is not None:
        return _GLOBAL_XDB_SEARCHER
    now = time.time()
    if now - _XDB_LAST_TRY < 10.0:
        return _GLOBAL_XDB_SEARCHER
    with _GLOBAL_XDB_LOCK:
        if _GLOBAL_XDB_SEARCHER is not None:
            return _GLOBAL_XDB_SEARCHER
        _XDB_LAST_TRY = now

        candidate_paths = [
            "/opt/portguard/ip2region.xdb",
            "/opt/portguard/ip2region_v4.xdb",
            "/opt/portsentry-ui/ip2region.xdb",
            os.path.join(os.path.dirname(os.path.abspath(__file__)), "ip2region.xdb"),
            os.path.join(os.path.dirname(os.path.abspath(__file__)), "ip2region_v4.xdb"),
            os.path.join(os.getcwd(), "ip2region.xdb"),
            os.path.join(os.getcwd(), "ip2region_v4.xdb")
        ]

        for p in candidate_paths:
            if os.path.isfile(p) and os.path.getsize(p) > 1024 * 1024:
                try:
                    c_buff = XdbSearcher.loadContentFromFile(p)
                    _GLOBAL_XDB_SEARCHER = XdbSearcher(contentBuff=c_buff)
                    print(f"[PortGuard GeoIP] ⚡ 成功载入本地 IP2Region 离线数据库: {p} (全内存高速检索模式)")
                    return _GLOBAL_XDB_SEARCHER
                except Exception as e:
                    print(f"[PortGuard GeoIP] 本地 IP 库载入异常 ({p}): {e}")
        return None

COMMON_ISP_MAP = {
    "电信": "中国电信",
    "联通": "中国联通",
    "移动": "中国移动",
    "铁通": "中国铁通",
    "广电": "中国广电",
    "阿里": "阿里云",
    "腾讯": "腾讯云",
    "华为": "华为云",
    "百度": "百度云",
    "金山云": "金山云",
    "京东云": "京东云",
    "教育网": "中国教育科研网",
    "科技网": "中国科技网",
    "Alibaba (US) Technology Co., Ltd.": "阿里云 (Alibaba Cloud)",
    "Alibaba.com Singapore E-Commerce Private Limited": "阿里云 (国际站)",
    "Tencent Building, Kejizhongyi Avenue": "腾讯云 (Tencent Cloud)",
    "Tencent Cloud": "腾讯云",
    "IT7 Networks Inc": "IT7 Networks (搬瓦工/BWH)",
    "Amazon.com, Inc.": "Amazon AWS",
    "Google LLC": "Google LLC",
    "Microsoft Corporation": "Microsoft Azure",
    "Cloudflare, Inc.": "Cloudflare",
    "DigitalOcean, LLC": "DigitalOcean",
    "Oracle Corporation": "Oracle Cloud",
    "Hetzner Online GmbH": "Hetzner Online",
    "OVH SAS": "OVHcloud",
    "Zenlayer Inc": "Zenlayer",
    "Ucloud": "UCloud",
    "Huawei Cloud": "华为云",
    "Akamai Technologies, Inc.": "Akamai / Linode",
    "Vultr Holdings, LLC": "Vultr",
    "Choopa, LLC": "Vultr / Choopa",
    "Linode, LLC": "Linode"
}

def format_isp_name(raw_isp):
    if not raw_isp or raw_isp == "0":
        return ""
    clean_isp = raw_isp.strip()
    if clean_isp in COMMON_ISP_MAP:
        return COMMON_ISP_MAP[clean_isp]
    for k, v in COMMON_ISP_MAP.items():
        if len(k) >= 4 and k.lower() in clean_isp.lower():
            return v
    return clean_isp

_GEO_CACHE = {}
_GEO_CACHE_LOCK = threading.Lock()

def resolve_ip_geo_local(ip):
    """双引擎融合本地极速解析：MaxMind GeoLite2 (City+ASN) 全球高精 + IP2Region 国内省市 (0ms 延时)"""
    if not ip or ip in ("127.0.0.1", "::1", "localhost") or ip.startswith("127."):
        return {"country": "本地回环", "region": "", "city": "", "isp": "Localhost"}
    with _GEO_CACHE_LOCK:
        if ip in _GEO_CACHE and _GEO_CACHE[ip].get("country") not in ("未知地域", "公网节点", "分析中...", "", "None", None):
            return _GEO_CACHE[ip]

    city_reader, asn_reader = get_mmdb_readers()
    xdb_searcher = get_xdb_searcher()

    if not city_reader and not asn_reader and not xdb_searcher:
        return None

    mmdb_city_res = city_reader.get(ip) if city_reader else None
    mmdb_asn_res = asn_reader.get(ip) if asn_reader else None

    # 从 MaxMind City 提取国家、省份、城市
    mm_country = ""
    mm_region = ""
    mm_city = ""
    if mmdb_city_res:
        country_obj = mmdb_city_res.get("country", {}) or mmdb_city_res.get("registered_country", {})
        names = country_obj.get("names", {}) if isinstance(country_obj, dict) else {}
        mm_country = names.get("zh-CN") or names.get("en", "")

        subs = mmdb_city_res.get("subdivisions", [])
        if subs and isinstance(subs, list) and isinstance(subs[0], dict):
            s_names = subs[0].get("names", {})
            mm_region = s_names.get("zh-CN") or s_names.get("en", "")

        city_obj = mmdb_city_res.get("city", {})
        if isinstance(city_obj, dict):
            c_names = city_obj.get("names", {})
            mm_city = c_names.get("zh-CN") or c_names.get("en", "")

    # 从 MaxMind ASN 提取组织与运营商
    mm_asn_org = ""
    if mmdb_asn_res and isinstance(mmdb_asn_res, dict):
        mm_asn_org = mmdb_asn_res.get("autonomous_system_organization", "") or ""

    # 从 IP2Region 提取国内精准省市与运营商
    xdb_country = ""
    xdb_region = ""
    xdb_city = ""
    xdb_isp = ""
    if xdb_searcher:
        try:
            raw = xdb_searcher.searchByIPStr(ip)
            if raw:
                parts = raw.split("|")
                if parts and parts[0] != "0": xdb_country = parts[0].strip()
                if len(parts) > 1 and parts[1] != "0": xdb_region = parts[1].strip()
                if len(parts) > 2 and parts[2] != "0": xdb_city = parts[2].strip()
                if len(parts) > 3 and parts[3] != "0": xdb_isp = parts[3].strip()
        except Exception:
            pass

    # 智能融合决议：以全球权威 MaxMind 为主，ip2region 为国内细化辅助
    country = mm_country or translate_country_cn(xdb_country)
    region = mm_region or xdb_region
    city = mm_city or xdb_city
    isp = format_isp_name(mm_asn_org or xdb_isp)

    # 仅当确认国家为中国时，优先采用 ip2region 的国内精细地级市与三大运营商
    if (country in ("中国", "China") or xdb_country == "中国") and mm_country in ("中国", "China", "", None):
        country = "中国"
        if xdb_region: region = xdb_region
        if xdb_city: city = xdb_city
        if xdb_isp: isp = format_isp_name(xdb_isp)
        elif mm_asn_org: isp = format_isp_name(mm_asn_org)

    if country or region or city or isp:
        res = {
            "country": country or "公网节点",
            "region": region,
            "city": city,
            "isp": isp
        }
        with _GEO_CACHE_LOCK:
            _GEO_CACHE[ip] = res
        return res
    return None

def resolve_ip_geo(ip):
    # 结果缓存：同一 IP 且解析成功过只查一次，降低外部 API 压力
    with _GEO_CACHE_LOCK:
        if ip in _GEO_CACHE and _GEO_CACHE[ip].get("country") not in ("公网节点", "公网探测", "未知地域", "", None):
            return _GEO_CACHE[ip]
            
    # 过滤本地与私网 IP
    if not ip or ip in ("127.0.0.1", "::1", "localhost") or ip.startswith("127."):
        return {"country": "本地回环", "region": "", "city": "", "isp": "Localhost"}
    if ip.startswith("10.") or ip.startswith("192.168.") or (ip.startswith("172.") and len(ip.split(".")) > 1 and ip.split(".")[1].isdigit() and 16 <= int(ip.split(".")[1]) <= 31):
        return {"country": "局域私网", "region": "", "city": "", "isp": "Private LAN"}

    # 1. 🚀 第一级：本地 IP2Region 离线库极速检索 (0ms 延时、零外网依赖、无频控)
    local_geo = resolve_ip_geo_local(ip)
    if local_geo and local_geo.get("country") not in ("未知地域", "", None):
        with _GEO_CACHE_LOCK:
            _GEO_CACHE[ip] = local_geo
        return local_geo

    # 2. 🌐 第二级备选源：ipwho.is (原生支持简体中文返回，数据精准)
    try:
        url = f"http://ipwho.is/{ip}?lang=zh-CN"
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"})
        with urllib.request.urlopen(req, timeout=3) as resp:
            data = json.loads(resp.read().decode('utf-8'))
            if data.get("success"):
                country = data.get("country", "").strip()
                if country:
                    result = {
                        "country": translate_country_cn(country),
                        "region": data.get("region", "").strip(),
                        "city": data.get("city", "").strip(),
                        "isp": data.get("connection", {}).get("isp", "").strip()
                    }
                    with _GEO_CACHE_LOCK:
                        _GEO_CACHE[ip] = result
                    return result
    except Exception:
        pass

    # 3. 🌐 第三级备选源：ip-api.com HTTP 接口
    try:
        url2 = f"http://ip-api.com/json/{ip}?lang=zh-CN&fields=status,country,regionName,city,isp"
        req2 = urllib.request.Request(url2, headers={"User-Agent": "PortGuardUI/2.0"})
        with urllib.request.urlopen(req2, timeout=3) as resp2:
            data2 = json.loads(resp2.read().decode('utf-8'))
            if data2.get("status") == "success":
                country = data2.get("country", "").strip()
                if country:
                    result = {
                        "country": translate_country_cn(country),
                        "region": data2.get("regionName", "").strip(),
                        "city": data2.get("city", "").strip(),
                        "isp": data2.get("isp", "").strip()
                    }
                    with _GEO_CACHE_LOCK:
                        _GEO_CACHE[ip] = result
                    return result
    except Exception:
        pass

    # 4. 🌐 第四级备选源：api.ip.sb
    try:
        url3 = f"https://api.ip.sb/geoip/{ip}"
        req3 = urllib.request.Request(url3, headers={"User-Agent": "PortGuardUI/2.0"})
        with urllib.request.urlopen(req3, timeout=3) as resp3:
            data3 = json.loads(resp3.read().decode('utf-8'))
            country = data3.get("country", "").strip()
            if country:
                result = {
                    "country": translate_country_cn(country),
                    "region": data3.get("region", "").strip(),
                    "city": data3.get("city", "").strip(),
                    "isp": data3.get("isp", data3.get("organization", "")).strip()
                }
                with _GEO_CACHE_LOCK:
                    _GEO_CACHE[ip] = result
                return result
    except Exception:
        pass

    return {"country": "公网探测", "region": "", "city": "", "isp": ""}

