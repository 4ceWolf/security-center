import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools'))
from protected_files import ProtectedFiles
from protected_transaction import TransactionStore

class TransactionTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory(prefix='security-center-protected-');self.addCleanup(self.tmp.cleanup)
  self.root=Path(self.tmp.name);(self.root/'.fixture').write_text('DISPOSABLE SECURITY CENTER TEST\n')
  (self.root/'var/lib').mkdir(parents=True)
  self.a='/usr/local/lib/security-center/collector.py';self.b='/usr/local/lib/security-center/daemon.py'
  self.file=self.root/self.a.lstrip('/');self.file.parent.mkdir(parents=True)
  self.file.write_bytes(b'original');self.file.chmod(0o644)
  self.fs=ProtectedFiles.fixture(self.root);self.addCleanup(self.fs.close)
  self.tx=TransactionStore(self.fs);self.addCleanup(lambda:self.tx.close())
  self.before={p:self.fs.read(p)[0] for p in (self.a,self.b)}
 def prepare(self):return self.tx.prepare({self.a:b'updated',self.b:b'added'},self.before,'a'*64)
 def test_apply_restartable_and_exact_rollback(self):
  token=self.prepare();self.assertEqual(self.tx.run(token)['phase'],'applied')
  self.assertEqual(self.tx.run(token)['phase'],'applied')
  self.assertEqual(self.tx.run(token,rollback=True)['phase'],'rolled_back')
  for path,value in self.before.items():self.assertEqual(self.fs.read(path)[0],value)
  with self.assertRaises(ValueError):self.tx.run(token)
 def test_exclusive_lock(self):
  with self.assertRaises(BlockingIOError):TransactionStore(self.fs)
 def test_preparation_conflict_does_not_write_installed_files(self):
  self.file.write_bytes(b'external')
  with self.assertRaises(ValueError):self.prepare()
  self.assertEqual(self.file.read_bytes(),b'external')
  self.assertFalse((self.root/self.b.lstrip('/')).exists())
 def test_payload_tamper_refuses_all_mutation(self):
  token=self.prepare();(self.root/'var/lib/security-center-updates'/token/'1.new').write_bytes(b'tampered')
  with self.assertRaises(ValueError):self.tx.run(token)
  self.assertEqual(self.file.read_bytes(),b'original')
 def test_rollback_later_change_preflight_does_not_restore_other_files(self):
  token=self.prepare();self.tx.run(token);self.file.write_bytes(b'later')
  with self.assertRaises(ValueError):self.tx.run(token,rollback=True)
  self.assertEqual((self.root/self.b.lstrip('/')).read_bytes(),b'added')
 def test_directory_symlink_refused(self):
  self.tx.close();folder=self.root/'var/lib/security-center-updates'
  folder.rename(folder.with_name('saved'));folder.symlink_to(folder.with_name('saved'),target_is_directory=True)
  with self.assertRaises(OSError):TransactionStore(self.fs)
 def test_path_token_escape_refused(self):
  for token in ('../escape','txn-x','/tmp'):
   with self.assertRaises(ValueError):self.tx.run(token)
 def test_child_crash_resume_and_rollback(self):
  runner='''import os,sys
sys.path.insert(0,sys.argv[1])
from protected_files import ProtectedFiles
from protected_transaction import TransactionStore
fs=ProtectedFiles.fixture(sys.argv[2]);tx=TransactionStore(fs)
tx.run(sys.argv[3],rollback=sys.argv[5]=='rollback',checkpoint=lambda stage:os._exit(72) if stage==sys.argv[4] else None)
'''
  # Separate transaction for each crash boundary, restoring original state each time.
  for phase in ('intent_saved','0:payload_synced','0:published','1:verified'):
   token=self.prepare();self.tx.close()
   child=subprocess.run([sys.executable,'-I','-c',runner,str(ROOT/'tools'),str(self.root),token,phase,'apply'],timeout=5)
   self.assertEqual(child.returncode,72)
   self.tx=TransactionStore(self.fs);self.tx.run(token);self.tx.run(token,rollback=True)
   for path,value in self.before.items():self.assertEqual(self.fs.read(path)[0],value)
  token=self.prepare();self.tx.run(token);self.tx.close()
  child=subprocess.run([sys.executable,'-I','-c',runner,str(ROOT/'tools'),str(self.root),token,'0:published','rollback'],timeout=5)
  self.assertEqual(child.returncode,72)
  self.tx=TransactionStore(self.fs);self.tx.run(token,rollback=True)
  for path,value in self.before.items():self.assertEqual(self.fs.read(path)[0],value)

if __name__=='__main__':unittest.main()
