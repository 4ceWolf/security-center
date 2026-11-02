import copy
import json
import os
from unittest.mock import patch
import pathlib
import sys
import tempfile
import unittest
ROOT=pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools'))
import observation_package as package

class PackageTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(dir=ROOT/'work',prefix='observation-package-test-')
        self.addCleanup(self.temp.cleanup)
        self.folder=pathlib.Path(self.temp.name)
        self.tree=self.folder/'root';self.tree.mkdir()
        self.member=self.tree/'usr/lib/example.py';self.member.parent.mkdir(parents=True)
        self.member.write_bytes(b'# captured\n');self.member.chmod(0o644)
        member={'sha256':package.sha(self.member.read_bytes()),'size':11,'mode':0o644}
        files={'usr/lib/example.py':member}
        raw=json.dumps({'schema_version':1,'approved':False,'scope':'observer_inputs_only','mapping':'root','files':files}).encode()
        (self.folder/'inputs.json').write_bytes(raw)
        digest=(package.sha(raw)+'\n').encode()
        source=self.tree/'etc/security-center-observation/source.sha256'
        source.parent.mkdir(parents=True);source.write_bytes(digest);source.chmod(0o644)
        files['etc/security-center-observation/source.sha256']={'sha256':package.sha(digest),'size':len(digest),'mode':0o644}
        self.manifest={'schema_version':1,'approved':False,'installed':False,'inputs_sha256':package.sha(raw),'files':files}
        (self.folder/'package.json').write_text(json.dumps(self.manifest))
    def test_fifo_members_and_metadata_refused_without_blocking(self):
        for path in (self.member, self.folder/'package.json', self.folder/'inputs.json'):
            original=path.read_bytes();mode=path.stat().st_mode & 0o777
            path.unlink();os.mkfifo(path)
            try:
                with self.assertRaises(ValueError):package.verify(self.folder)
            finally:
                path.unlink();path.write_bytes(original);path.chmod(mode)

    def test_total_bound_enforced(self):
        with patch.object(package,'MAX_TOTAL',1):
            with self.assertRaises(ValueError):package.verify(self.folder)

    def test_member_count_bound_enforced(self):
        self.manifest['files']={str(i):{} for i in range(4097)}
        (self.folder/'package.json').write_text(json.dumps(self.manifest))
        with self.assertRaises(ValueError):package.verify(self.folder)

    def test_exact_capture(self):
        self.assertFalse(package.verify(self.folder)['approved'])
    def test_member_tamper_mode_extra_missing_refused(self):
        for change in ('bytes','mode','extra','missing'):
            original=self.member.read_bytes()
            if change=='bytes':self.member.write_bytes(b'changed')
            elif change=='mode':self.member.chmod(0o600)
            elif change=='extra':(self.tree/'extra').write_text('extra')
            else:self.member.unlink()
            with self.assertRaises(ValueError):package.verify(self.folder)
            if change=='extra':(self.tree/'extra').unlink()
            self.member.write_bytes(original);self.member.chmod(0o644)
    def test_symlink_metadata_and_root_refused(self):
        for name in ('package.json','inputs.json','root'):
            path=self.folder/name;backup=self.folder/(name+'-saved');path.rename(backup);path.symlink_to(backup)
            with self.assertRaises(ValueError):package.verify(self.folder)
            path.unlink();backup.rename(path)
    def test_source_manifest_mismatch_refused(self):
        (self.folder/'inputs.json').write_bytes(b'{}')
        with self.assertRaises(ValueError):package.verify(self.folder)
    def test_invalid_mapping_refused_before_capture(self):
        for mapping in ('../../etc','root\nExecStart=/bin/sh','',True,'x'*65):
            with self.assertRaises(ValueError):package.build(mapping)
    def test_unsafe_destinations_refused(self):
        for name in ('relative','/usr/../etc','/usr//lib'):
            with self.assertRaises(ValueError):package.destination(name)
if __name__=='__main__':unittest.main()
