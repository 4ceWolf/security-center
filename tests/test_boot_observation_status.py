import pathlib
import sys
import unittest
from unittest.mock import patch
ROOT=pathlib.Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'securityd'),str(ROOT/'initramfs'),str(ROOT/'policies')]
import boot_observation_status as status
from boot_observer import build
BOOT='11111111-2222-3333-4444-555555555555'

class StatusTests(unittest.TestCase):
    def test_missing_invalid_and_denied_are_never_secure(self):
        for error in (FileNotFoundError(), ValueError(), PermissionError()):
            with patch.object(status,'consume',side_effect=error):
                data=status.configuration()
            self.assertNotEqual(data['status'],'secure')
            self.assertFalse(data['details']['can_authorize_actions'])
            self.assertEqual(data['details']['unlock_method'],'Unknown')
    def test_missing_record_distinguishes_installed_marker(self):
        for installed, expected in ((False, 'not_installed'), (True, 'unavailable')):
            with patch.object(status,'consume',side_effect=FileNotFoundError()), patch.object(pathlib.Path,'is_file',return_value=installed):
                result=status.configuration()
            self.assertEqual(result['details']['observation_state'],expected)
            self.assertNotEqual(result['status'],'secure')
    def test_observed_and_incomplete_keep_explicit_limits(self):
        for errors in ([],['input must not be echoed']):
            data=build(b'{"schema_version":1,"internal":[],"trusted_external":[]}', 'a'*64,
                BOOT,1,2,{'devices':[],'errors':errors},{'pci':[],'thunderbolt':[],'errors':[]})
            with patch.object(status,'consume',return_value=data):result=status.configuration()
            self.assertNotEqual(result['status'],'secure')
            self.assertEqual(result['details']['device_enforcement'],'Not enabled')
            self.assertNotIn('input must not be echoed',str(result))
if __name__=='__main__':unittest.main()
