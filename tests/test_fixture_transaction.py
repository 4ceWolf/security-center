import os,pathlib,sys,tempfile,unittest
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]/'tools'))
from fixture_transaction import Transaction
class TransactionTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory(prefix='security-center-fixture-');self.addCleanup(self.tmp.cleanup)
  self.root=pathlib.Path(self.tmp.name);(self.root/'.fixture').write_text('DISPOSABLE SECURITY CENTER TEST\n')
  (self.root/'existing').write_bytes(b'original');(self.root/'existing').chmod(0o640)
  self.tx=Transaction(self.root);self.before=self.tx.inspect(self.root/'existing')
  self.tx.prepare({'existing':b'updated','new':b'added'})
 def test_apply_and_exact_restore(self):
  self.tx.run();self.assertEqual((self.root/'existing').read_bytes(),b'updated')
  self.tx.run(rollback=True)
  self.assertEqual(self.tx.inspect(self.root/'existing'),self.before)
  self.assertFalse((self.root/'new').exists())
 def test_crash_resume_each_file(self):
  for boundary in (0,1):
   # Each fixture uses a fresh independent transaction.
   with tempfile.TemporaryDirectory(prefix='security-center-fixture-') as folder:
    root=pathlib.Path(folder);(root/'.fixture').write_text('DISPOSABLE SECURITY CENTER TEST\n')
    tx=Transaction(root);tx.prepare({'a':b'one','b':b'two'})
    pid=os.fork()
    if pid==0:
     def crash(index):
      if index==boundary:os._exit(77)
     try:tx.run(checkpoint=crash)
     except BaseException:os._exit(78)
     os._exit(79)
    _,status=os.waitpid(pid,0);self.assertEqual(os.waitstatus_to_exitcode(status),77)
    Transaction(root).run();self.assertEqual((root/'b').read_bytes(),b'two')
    Transaction(root).run(rollback=True)
    self.assertFalse((root/'a').exists());self.assertFalse((root/'b').exists())
 def test_crash_during_rollback_resumes(self):
  self.tx.run()
  pid=os.fork()
  if pid==0:
   def crash(index):os._exit(77)
   try:self.tx.run(rollback=True,checkpoint=crash)
   except BaseException:os._exit(78)
   os._exit(79)
  _,status=os.waitpid(pid,0);self.assertEqual(os.waitstatus_to_exitcode(status),77)
  reopened=Transaction(self.root)
  with self.assertRaises(ValueError):reopened.run()
  reopened.run(rollback=True)
  self.assertEqual(reopened.inspect(self.root/'existing'),self.before)
  self.assertFalse((self.root/'new').exists())
 def test_conflict_refuses_all_rollback(self):
  self.tx.run();(self.root/'new').write_bytes(b'owner edit')
  with self.assertRaises(ValueError):self.tx.run(rollback=True)
  self.assertEqual((self.root/'existing').read_bytes(),b'updated')
 def test_corrupt_backup_refuses_before_mutation(self):
  (self.root/'.transaction/0.old').write_bytes(b'corrupt')
  with self.assertRaises(ValueError):self.tx.run()
  self.assertEqual((self.root/'existing').read_bytes(),b'original')
 def test_symlink_target_rejected(self):
  (self.root/'new').symlink_to(self.root/'existing')
  with self.assertRaises(ValueError):self.tx.run()
 def test_rollback_not_reapplied(self):
  self.tx.run();self.tx.run(rollback=True)
  with self.assertRaises(ValueError):self.tx.run()
 def test_host_root_refused(self):
  with self.assertRaises(ValueError):Transaction('/')
if __name__=='__main__':unittest.main()
