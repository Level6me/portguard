#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import unittest
from unittest.mock import patch, MagicMock
import time
import ipaddress

from core.firewall import (
    compile_whitelist_rules,
    get_compiled_whitelist,
    ip_in_whitelist,
    get_active_ssh_client_ips,
    batch_ban_ip_firewall
)
from core.mesh import _MESH_CLIENT_SYNC_LOCK, sync_cluster_mesh_state

class TestSyncOptimization(unittest.TestCase):
    def test_compile_whitelist_rules(self):
        items = [
            {"ip": "1.2.3.4", "remark": "Test IP"},
            {"ip": "10.0.0.0/24", "remark": "Test Subnet"},
            "8.8.8.8"
        ]
        exact, nets = compile_whitelist_rules(items)
        self.assertIn("1.2.3.4", exact)
        self.assertIn("8.8.8.8", exact)
        self.assertEqual(len(nets), 1)
        self.assertEqual(str(nets[0]), "10.0.0.0/24")

    def test_ip_in_whitelist_fast_path(self):
        items = [{"ip": "192.168.100.1"}, {"ip": "10.10.0.0/16"}]
        self.assertTrue(ip_in_whitelist("192.168.100.1", whitelist_items=items))
        self.assertTrue(ip_in_whitelist("10.10.1.5", whitelist_items=items))
        self.assertFalse(ip_in_whitelist("192.168.100.2", whitelist_items=items))

    def test_ssh_client_ips_cache_empty_set_retained(self):
        import core.firewall as fw
        fw._DYNAMIC_SSH_IPS_CACHE = set()
        fw._DYNAMIC_SSH_IPS_LAST_CHECK = time.time()
        with patch("subprocess.run") as mock_sub:
            res = get_active_ssh_client_ips()
            self.assertEqual(res, set())
            mock_sub.assert_not_called()

    def test_batch_ban_ip_firewall_handles_empty(self):
        # Should not raise exception
        batch_ban_ip_firewall([])
        batch_ban_ip_firewall(None)

    def test_mesh_client_sync_lock_concurrency(self):
        # When lock is already held, second call returns immediately
        acquired = _MESH_CLIENT_SYNC_LOCK.acquire(blocking=False)
        self.assertTrue(acquired)
        try:
            res = sync_cluster_mesh_state()
            self.assertTrue(res.get("success"))
            self.assertIn("跳过冗余并发", res.get("msg", ""))
        finally:
            _MESH_CLIENT_SYNC_LOCK.release()

if __name__ == '__main__':
    unittest.main()
