import copy
import contextlib
import fcntl
import os
import types
from unittest.mock import patch
import importlib.util
import json
import pathlib
import subprocess
import sys
import tempfile
import unittest
ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'policies'))
from trust_store import Store
from trust_policy import device_id
spec = importlib.util.spec_from_file_location('trust_helper', ROOT / 'tools/device-trust-helper.py')
helper = importlib.util.module_from_spec(spec); spec.loader.exec_module(helper)

class TrustHelperTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='security-center-trust-test-')
        self.addCleanup(self.temp.cleanup)
        self.store = Store(fixture=self.temp.name)
        self.seed = json.loads((ROOT / 'policies/normal-devices.candidate.json').read_text())
        self.device = copy.deepcopy(self.seed['trusted_external'][1]); self.device['port'] += '.1'
        self.inv = {'usb_observation_complete': True, 'errors': [], 'devices': [self.device]}
    def call(self, request):
        return helper.dispatch(request, self.store, self.seed, lambda: copy.deepcopy(self.inv), actor=0)
    def test_end_to_end_list_review_save_remove_and_reopen(self):
        self.assertFalse(self.call({'operation':'list'})['connected'][0]['saved'])
        selected = device_id(self.device)
        proposal = self.call({'operation':'propose','action':'add','device_id':selected})
        saved = self.call({'operation':'apply','proposal':proposal})
        self.assertTrue(saved['connected'][0]['saved'])
        self.assertEqual(saved['activation']['preboot'], 'outside_scope')
        self.inv['devices'] = []
        removal = self.call({'operation':'propose','action':'remove','device_id':selected})
        result = self.call({'operation':'apply','proposal':removal})
        self.assertEqual(len(result['saved']), 2)
        self.assertEqual(Store(fixture=self.temp.name).read(self.seed), self.seed)
    def test_never_accept_browser_device_or_path_or_arbitrary_operation(self):
        for request in ({'operation':'shell'}, {'operation':'list','path':'/etc/shadow'}, {'operation':'propose','action':'add','device_id':device_id(self.device),'device':self.device}, {'operation':[]}, []):
            with self.assertRaises(ValueError): self.call(request)
    def test_reobserve_changed_interfaces_between_review_and_apply(self):
        proposal = self.call({'operation':'propose','action':'add','device_id':device_id(self.device)})
        self.inv['devices'][0]['interfaces'].append('03:01:01')
        with self.assertRaises(ValueError): self.call({'operation':'apply','proposal':proposal})
        self.assertEqual(self.store.read(self.seed), self.seed)

    def test_post_commit_observation_failure_preserves_success_receipt(self):
        proposal = self.call({'operation':'propose','action':'add','device_id':device_id(self.device)})
        observations = iter([self.inv, None])
        def collect():
            result = next(observations)
            if result is None: raise OSError('device disappeared')
            return result
        result = helper.dispatch({'operation':'apply','proposal':proposal}, self.store,
                                 self.seed, collect, actor=0)
        self.assertEqual(result['observation_status'], 'unavailable')
        self.assertTrue(any(d['id'] == device_id(self.device) for d in result['saved']))
        self.assertEqual(len(self.store.read(self.seed)['trusted_external']), 3)

    def test_helper_shared_guard_blocks_installer_and_refuses_active_update(self):
        root=pathlib.Path(self.temp.name)
        updates=root/'var/lib/security-center-updates';updates.mkdir(parents=True)
        lock=updates/'update.lock';lock.write_bytes(b'');lock.chmod(0o600)
        original_open=os.open;original_stat=os.fstat
        def open_fixture(path,*args,**kwargs):
            return original_open(root if path=='/' else path,*args,**kwargs)
        def root_stat(fd):
            value=original_stat(fd)
            return types.SimpleNamespace(st_uid=0,st_mode=value.st_mode,st_nlink=value.st_nlink)
        exclusive=original_open(lock,os.O_RDWR)
        self.addCleanup(lambda:os.close(exclusive))
        with patch.object(helper.os,'open',open_fixture),patch.object(helper.os,'fstat',root_stat):
            with helper.update_guard():
                with self.assertRaises(BlockingIOError):fcntl.flock(exclusive,fcntl.LOCK_EX|fcntl.LOCK_NB)
            fcntl.flock(exclusive,fcntl.LOCK_EX|fcntl.LOCK_NB)
            with self.assertRaises(BlockingIOError):
                with helper.update_guard():self.fail('Active installer must block helper imports')
            fcntl.flock(exclusive,fcntl.LOCK_UN)

if __name__ == '__main__': unittest.main()
