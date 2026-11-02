import copy,pathlib,sys,tempfile,unittest
from unittest.mock import patch
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]/'securityd'))
import adapters as a,history
class ProcessTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
  self.root=pathlib.Path(self.tmp.name);p=patch.object(a,'PROCESS_ROOT',self.root);p.start();self.addCleanup(p.stop)
 def process(self,pid=1,deleted=False):
  p=self.root/str(pid);p.mkdir()
  (p/'stat').write_text(f'{pid} (process with )) S '+'0 '*18+'123 0')
  (p/'comm').write_text('testprocess')
  (p/'status').write_text('Uid:\t1000\t0\t0\t0\n')
  (p/'exe').symlink_to('/example'+(' (deleted)' if deleted else ''))
  (p/'cmdline').write_text('SECRET_COMMAND');(p/'environ').write_text('SECRET_ENV')
  return p
 def test_observation_without_credentials(self):
  self.process();data=a.process_observations()
  self.assertEqual(data['details']['effective_root'],1);self.assertNotIn('SECRET',str(data))
  self.assertTrue(data['details']['complete']);self.assertEqual(data['status'],'unknown')
 def test_deleted_is_review_finding(self):
  self.process(deleted=True);data=a.process_observations()
  self.assertEqual(data['status'],'attention');self.assertEqual(len(data['details']['findings']),1)
  self.assertIn('no malware verdict',data['details']['note'])
 def test_missing_executable_is_incomplete(self):
  p=self.process();(p/'exe').unlink()
  self.assertFalse(a.process_observations()['details']['complete'])
 def test_zombie_metadata_without_executable(self):
  p=self.process();(p/'exe').unlink();path=p/'stat';path.write_text(path.read_text().replace(' S ',' Z '))
  data=a.process_observations()['details']
  self.assertEqual(data['zombies'],1);self.assertEqual(data['observed'],1);self.assertFalse(data['complete'])
 def test_reused_pid_rejected(self):
  self.process()
  with patch.object(a,'start_time',side_effect=[123,124]):data=a.process_observations()
  self.assertEqual(data['details']['observed'],0)
 def test_enumeration_bound(self):
  self.process(1);self.process(2)
  with patch.object(a,'PROCESS_LIMIT',1):data=a.process_observations()
  self.assertTrue(data['details']['truncated'])
 def test_history_ignores_count_churn_but_tracks_findings(self):
  self.process();one=a.process_observations();one['id']='processes'
  two=copy.deepcopy(one);two['summary']='Another count';two['details']['observed']=999
  self.assertEqual(history.fingerprint(one),history.fingerprint(two))
  two['details']['findings']=[{'pid':2,'finding':'Executable link reports deleted'}]
  self.assertNotEqual(history.fingerprint(one),history.fingerprint(two))
if __name__=='__main__':unittest.main()
