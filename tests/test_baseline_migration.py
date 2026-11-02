import copy,json,pathlib,sys,unittest
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]/'tools'))
import baseline_migration as m
class MigrationTests(unittest.TestCase):
 def setUp(self):
  self.item={'state':'present','sha256':'a'*64,'uid':0,'gid':0,'mode':0o644,'size':1,'mtime_ns':1}
  self.old={'/boot/config':copy.deepcopy(self.item),'/lib/collector':copy.deepcopy(self.item)}
  self.previous=json.dumps({'schema_version':1,'approved':True,'files':self.old}).encode()
  self.release=json.dumps({'schema_version':1,'fim_paths':list(self.old)+['/lib/new'],
   'files':[{'destination':'/lib/collector','sha256':'b'*64},{'destination':'/lib/new','sha256':'b'*64}]}).encode()
  self.before=copy.deepcopy(self.old);self.before['/lib/new']={'state':'missing'}
  self.after=copy.deepcopy(self.old)
  for name in ('/lib/collector','/lib/new'):self.after[name]=dict(self.item,sha256='b'*64,mtime_ns=2)
 def prepare(self):return m.prepare(self.previous,m.digest(self.previous),self.release,m.digest(self.release),self.before,self.after)
 def test_addition_preserves_reference_and_is_unapproved(self):
  out=self.prepare();self.assertFalse(out['candidate']['approved'])
  self.assertEqual(out['candidate']['scope_change']['added'],['/lib/new'])
  self.assertEqual(out['previous_count'],2);self.assertEqual(out['new_count'],3)
  out['candidate']['files']['/boot/config']['mode']=0
  self.assertEqual(self.after['/boot/config']['mode'],0o644)
 def test_preexisting_drift_cannot_be_blessed(self):
  self.before['/boot/config']['sha256']='c'*64
  with self.assertRaises(ValueError):self.prepare()
 def test_unrelated_change_rejected(self):
  self.after['/boot/config']['mtime_ns']=99
  with self.assertRaises(ValueError):self.prepare()
 def test_new_path_must_be_absent_before(self):
  self.before['/lib/new']=copy.deepcopy(self.item)
  with self.assertRaises(ValueError):self.prepare()
 def test_wrong_release_content_or_permissions_rejected(self):
  for key,value in [('sha256','c'*64),('mode',0o666),('uid',1000)]:
   with self.subTest(key=key):
    original=self.after['/lib/new'][key];self.after['/lib/new'][key]=value
    with self.assertRaises(ValueError):self.prepare()
    self.after['/lib/new'][key]=original
 def test_missing_scan_coverage_rejected(self):
  del self.after['/boot/config']
  with self.assertRaises(ValueError):self.prepare()
 def test_document_tamper_rejected(self):
  with self.assertRaises(ValueError):m.document(self.previous+b' ',m.digest(self.previous))
 def test_rollback_removes_only_new_and_restores_old(self):
  plan=m.rollback_plan(self.before,self.after,self.after,['/lib/collector','/lib/new'])
  self.assertEqual([p['operation'] for p in plan],['restore_backup','remove_added_file'])
 def test_rollback_conflict_refuses_all(self):
  current=copy.deepcopy(self.after);current['/lib/new']['mtime_ns']=3
  with self.assertRaises(ValueError):m.rollback_plan(self.before,self.after,current,['/lib/collector','/lib/new'])
if __name__=='__main__':unittest.main()
