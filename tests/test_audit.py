import copy
import pathlib
import stat
import sys
import unittest
from types import SimpleNamespace
from unittest.mock import patch
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]/'securityd'))
import audit
import history

class AuditTests(unittest.TestCase):
    def test_sysctl_unknown_never_passes(self):
        for value, expected in [('1','secure'), ('0','attention'), ('999','attention'), ('invalid','unavailable')]:
            with patch.object(pathlib.Path, 'read_text', return_value=value):
                self.assertEqual(audit.assess_sysctl(*audit.SYSCTLS[0])['status'], expected)
        with patch.object(pathlib.Path, 'read_text', side_effect=PermissionError):
            self.assertEqual(audit.assess_sysctl(*audit.SYSCTLS[0])['status'], 'unavailable')

    def test_file_and_ancestors_reviewed(self):
        def metadata(path):
            return SimpleNamespace(st_uid=0, st_gid=0,
                st_mode=(stat.S_IFREG | 0o644) if str(path)=='/safe/file' else (stat.S_IFDIR | 0o755))
        with patch.object(pathlib.Path, 'lstat', metadata):
            self.assertEqual(audit.assess_path('/safe/file')['status'],'secure')
        for bad_mode in (stat.S_IFDIR | 0o777, stat.S_IFLNK | 0o777):
            def bad_parent(path):
                return SimpleNamespace(st_uid=0, st_gid=0, st_mode=bad_mode) if str(path)=='/safe' else metadata(path)
            with patch.object(pathlib.Path, 'lstat', bad_parent):
                self.assertNotEqual(audit.assess_path('/safe/file')['status'],'secure')
        def wrong_owner(path):
            result=metadata(path); result.st_uid=1000; return result
        with patch.object(pathlib.Path, 'lstat', wrong_owner):
            self.assertEqual(audit.assess_path('/safe/file')['status'],'attention')
        with patch.object(pathlib.Path, 'lstat', side_effect=FileNotFoundError):
            self.assertEqual(audit.assess_path('/safe/file')['status'],'unavailable')

    def test_incomplete_audit_not_green(self):
        with patch.object(audit,'assess_sysctl',return_value={'status':'secure'}), patch.object(audit,'assess_path',return_value={'status':'unavailable'}):
            self.assertEqual(audit.configuration()['status'],'unknown')

    def test_same_count_different_findings_changes_history(self):
        first={'id':'audit','status':'attention','summary':'1 finding','details':{'checks':[{'id':'a','status':'attention'}]}}
        second=copy.deepcopy(first);second['details']['checks'][0]['id']='b'
        self.assertNotEqual(history.fingerprint(first),history.fingerprint(second))

if __name__ == '__main__': unittest.main()
