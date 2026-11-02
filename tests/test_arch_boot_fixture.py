import hashlib
import json
import pathlib
import sys
import tempfile
import unittest
ROOT=pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools'))
from arch_boot_fixture import select

class FixtureTests(unittest.TestCase):
    def setUp(self):
        self.base=tempfile.TemporaryDirectory(prefix='arch-observer-build-test-',dir=ROOT/'work')
        self.guest=tempfile.TemporaryDirectory(prefix='luks-vm-test-',dir=ROOT/'work')
        self.addCleanup(self.base.cleanup);self.addCleanup(self.guest.cleanup)
        self.folder=pathlib.Path(self.base.name)
        self.root=pathlib.Path(self.guest.name)/'root';self.root.mkdir()
        (self.root/'init').write_text('#!/bin/sh\nset -E -e\nexec /usr/lib/systemd/systemd --system\n')
        raw=b'fixed-test-input'
        (self.folder/'guest-initramfs.img').write_bytes(raw)
        (self.folder/'generated-manifest.json').write_bytes(b'{}')
        report={'passed':True,'signed':False,'image_sha256':hashlib.sha256(raw).hexdigest(),
                'generated_manifest_sha256':hashlib.sha256(b'{}').hexdigest()}
        (self.folder/'report.json').write_text(json.dumps(report))
    def test_unreviewed_base_change_refused(self):
        (self.folder/'guest-initramfs.img').write_bytes(b'changed')
        with self.assertRaises(ValueError):select(self.folder,self.root)
    def test_invalid_host_paths_refused_before_reading(self):
        for folder,root in ((ROOT,self.root),(self.folder,ROOT),(self.folder,self.root.parent)):
            with self.assertRaises(ValueError):select(folder,root)
    def test_no_native_init_replacement_or_unused_root_helpers(self):
        (self.root/'unreviewed-unlock.py').write_text('raise SystemExit(0)')
        _,items,_=select(self.folder,self.root)
        names={item[0] for item in items}
        self.assertIn('arch-provision',names)
        self.assertNotIn('init',names)
        self.assertNotIn('unreviewed-unlock.py',names)
    def test_native_payload_substitution_refused(self):
        member='usr/lib/security-center-observation/entry.py'
        raw=json.dumps({member:{'type':'file','sha256':hashlib.sha256(b'reviewed').hexdigest()}}).encode()
        (self.folder/'generated-manifest.json').write_bytes(raw)
        report=json.loads((self.folder/'report.json').read_text())
        report['generated_manifest_sha256']=hashlib.sha256(raw).hexdigest()
        (self.folder/'report.json').write_text(json.dumps(report))
        file=self.root/member;file.parent.mkdir(parents=True);file.write_bytes(b'changed')
        with self.assertRaises(ValueError):select(self.folder,self.root)
if __name__=='__main__':unittest.main()
