import contextlib, hashlib, io, json, pathlib, runpy, sys, tempfile, unittest
from unittest.mock import patch
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]/'securityd'))
import integrity
SCRIPT=pathlib.Path(__file__).resolve().parents[1]/'tools/approve-file-baseline.py'

class ApprovalTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
  self.base=pathlib.Path(self.tmp.name);self.review=self.base/'baseline-review';self.review.mkdir()
  self.files={'/test':{'state':'present','sha256':'a'*64,'uid':0,'gid':0,'mode':420,'size':1,'mtime_ns':1}}
  self.raw=json.dumps({'schema_version':1,'approved':False,'files':self.files}).encode()
  self.digest=hashlib.sha256(self.raw).hexdigest()
  self.candidate=self.review/(self.digest+'.json');self.candidate.write_bytes(self.raw);self.candidate.chmod(0o600)
 def execute(self, files=None, previous=None):
  original=integrity.open_fixed
  def open_candidate(path):
   name=pathlib.Path(path).name
   return original(str((self.base if name=='approved.json' else self.review)/name))
  original_fstat=integrity.os.fstat
  def root_stat(fd):
   from types import SimpleNamespace
   value=original_fstat(fd);return SimpleNamespace(st_uid=0,st_mode=value.st_mode)
  with patch.object(integrity,'BASELINE',str(self.base/'approved.json')),patch.object(integrity,'scan',return_value=self.files if files is None else files),patch.object(integrity,'open_fixed',open_candidate),patch('os.geteuid',return_value=0),patch('os.fstat',root_stat),patch.object(integrity,'load_baseline',return_value=self.files),patch.object(sys,'argv',[str(SCRIPT),'--approved-candidate-sha256',self.digest]+(['--approved-previous-baseline-sha256',previous] if previous else [])),contextlib.redirect_stdout(io.StringIO()):
   runpy.run_path(str(SCRIPT),run_name='__main__')
 def test_exact_candidate_only_and_no_overwrite(self):
  self.execute();target=self.base/'approved.json';prior=target.read_bytes()
  self.assertTrue(json.loads(prior)['approved'])
  self.assertEqual(target.stat().st_mode & 0o777,0o600)
  with self.assertRaises(FileExistsError):self.execute()
  self.assertEqual(target.read_bytes(),prior)
 def test_changed_files_rejected(self):
  with self.assertRaises(SystemExit):self.execute({'/test':{'state':'missing'}})
  self.assertFalse((self.base/'approved.json').exists())
 def test_candidate_tampering_rejected(self):
  self.candidate.write_bytes(self.raw+b' ')
  with self.assertRaises(SystemExit):self.execute()
  self.assertFalse((self.base/'approved.json').exists())

 def replacement(self, prior):
  self.raw=json.dumps({'schema_version':1,'approved':False,'files':self.files,'replaces_baseline_sha256':hashlib.sha256(prior).hexdigest()}).encode()
  self.digest=hashlib.sha256(self.raw).hexdigest()
  self.candidate=self.review/(self.digest+'.json');self.candidate.write_bytes(self.raw);self.candidate.chmod(0o600)
 def test_replacement_requires_exact_prior_approval_and_archives(self):
  self.execute();target=self.base/'approved.json';prior=target.read_bytes()
  self.replacement(prior)
  with self.assertRaises(SystemExit):self.execute()
  self.assertEqual(target.read_bytes(),prior)
  digest=hashlib.sha256(prior).hexdigest();self.execute(previous=digest)
  self.assertEqual((self.base/('integrity-baseline-'+digest+'.json')).read_bytes(),prior)
  self.assertEqual(json.loads(target.read_bytes())['approved_candidate_sha256'],self.digest)
 def test_replacement_rejects_changed_prior_reference(self):
  self.execute();target=self.base/'approved.json';prior=target.read_bytes()
  self.replacement(prior);target.write_bytes(prior+b' ')
  with self.assertRaises(SystemExit):self.execute(previous=hashlib.sha256(prior).hexdigest())
  self.assertEqual(target.read_bytes(),prior+b' ')

 def test_scope_expansion_does_not_require_old_reference_to_match_new_scope(self):
  self.execute();prior=(self.base/'approved.json').read_bytes()
  self.files['/new-file']=dict(self.files['/test'])
  self.replacement(prior)
  self.execute(previous=hashlib.sha256(prior).hexdigest())
  self.assertEqual(set(json.loads((self.base/'approved.json').read_bytes())['files']),{'/test','/new-file'})

if __name__=='__main__':unittest.main()
