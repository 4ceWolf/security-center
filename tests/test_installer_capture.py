import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
ROOT=Path(__file__).resolve().parents[1]
def module(name):
 spec=importlib.util.spec_from_file_location(name,ROOT/'tools'/name)
 obj=importlib.util.module_from_spec(spec);spec.loader.exec_module(obj);return obj
bootstrap=module('installer-bootstrap.py')

class InstallerCaptureTests(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
  self.path=Path(self.temp.name)/'runtime.json'
  self.files={name:(ROOT/name).read_text() for name in bootstrap.NAMES}
 def write(self,files=None):
  raw=json.dumps(dict(schema=1,files=self.files if files is None else files)).encode();self.path.write_bytes(raw)
  return hashlib.sha256(raw).hexdigest()
 def test_exact_bytes_capture_survives_later_source_change(self):
  sha=self.write();captured=bootstrap.capture(self.path,sha);self.path.write_text('{}')
  self.assertEqual(captured,self.files)
  with self.assertRaises(ValueError):bootstrap.capture(self.path,sha)
 def test_missing_or_extra_member_and_mismatched_digest_rejected(self):
  for files in ({**self.files,'../escape.py':'pass'}, {k:v for k,v in self.files.items() if k!='securityd/integrity.py'}):
   sha=self.write(files)
   with self.assertRaises(ValueError):bootstrap.capture(self.path,sha)
  self.write()
  with self.assertRaises(ValueError):bootstrap.capture(self.path,'0'*64)
 def test_symlink_runtime_file_refused(self):
  sha=self.write();other=self.path.with_suffix('.saved');self.path.rename(other);self.path.symlink_to(other)
  with self.assertRaises(OSError):bootstrap.capture(self.path,sha)
 def test_duplicate_json_member_rejected_even_with_matching_digest(self):
  raw=b'{"schema":1,"schema":1,"files":{}}';self.path.write_bytes(raw)
  with self.assertRaises(ValueError):bootstrap.capture(self.path,hashlib.sha256(raw).hexdigest())

if __name__=='__main__':unittest.main()
