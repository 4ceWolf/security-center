import unittest
from unittest.mock import patch
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'securityd'))
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'policies'))
import adapters

class AdapterTests(unittest.TestCase):
    def test_network_management_removed(self):
        self.assertNotIn('opensnitch', adapters.ADAPTERS)
        self.assertFalse(hasattr(adapters, 'opensnitch'))

    def test_absent_not_secure(self):
        with patch.object(adapters,'command',return_value='LoadState=not-found\nActiveState=inactive\n'):
            self.assertEqual(adapters.usbguard()['status'],'unknown')

    def test_loopback_ipv4_ipv6_and_exposed(self):
        with patch.object(adapters,'command',return_value='LISTEN 0 10 127.0.0.1:9090 0.0.0.0:*\nLISTEN 0 10 [::1]:53 [::]:*\n'):
            self.assertEqual(adapters.listeners()['status'],'secure')
        with patch.object(adapters,'command',return_value='LISTEN 0 10 0.0.0.0:22 0.0.0.0:*\n'):
            self.assertEqual(adapters.listeners()['status'],'attention')

if __name__=='__main__': unittest.main()
