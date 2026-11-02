import pathlib,sys,tempfile,unittest
from unittest.mock import patch
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]/'securityd'))
import confinement as c

class ConfinementTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
  self.root=pathlib.Path(self.tmp.name)
  self.enabled=self.root/'enabled';self.enabled.write_text('Y\n')
  self.profiles=self.root/'profiles';self.profiles.write_text('/usr/bin/test (enforce)\n')
  self.proc=self.root/'proc';self.proc.mkdir()
  for key,value in [('ENABLED',self.enabled),('PROFILES',self.profiles),('PROC',self.proc)]:
   patcher=patch.object(c,key,value);patcher.start();self.addCleanup(patcher.stop)
 def process(self,pid=1,name='firefox',mode='unconfined'):
  directory=self.proc/str(pid);(directory/'attr/apparmor').mkdir(parents=True)
  (directory/'comm').write_text(name+'\n')
  (directory/'stat').write_text(f'{pid} (test name)) S '+'0 '*18+'123 0\n')
  (directory/'attr/apparmor/current').write_text(mode+'\n')
  return directory
 def test_single_enforcing_profile_never_means_complete_coverage(self):
  data=c.configuration();self.assertEqual(data['status'],'unknown')
  self.assertFalse(data['details']['coverage_verified'])
 def test_disabled_and_missing_are_distinct(self):
  self.enabled.write_text('N');self.assertEqual(c.configuration()['status'],'attention')
  self.enabled.unlink();self.assertEqual(c.configuration()['status'],'unavailable')
 def test_mixed_modes(self):
  data=c.profiles('a (enforce)\nb (complain)\nc (kill)\nd (future)')
  self.assertEqual(data['total'],4);self.assertEqual(data['counts']['unknown'],1)
  self.profiles.write_text('a (enforce)\nb (complain)')
  self.assertEqual(c.configuration()['status'],'attention')
 def test_bad_and_oversized_profiles_unavailable(self):
  for text in ('malformed','x'*1048577):
   self.profiles.write_text(text);self.assertEqual(c.configuration()['status'],'unavailable')
 def test_unconfined_application_and_no_secrets(self):
  directory=self.process();(directory/'cmdline').write_text('SECRET_ARGUMENT')
  data=c.configuration();self.assertEqual(data['status'],'attention')
  self.assertNotIn('SECRET_ARGUMENT',str(data))
  self.assertEqual(data['details']['applications']['observed'][0]['mode'],'unconfined')
 def test_fallback_provenance(self):
  directory=self.process(mode='browser (enforce)')
  (directory/'attr/apparmor/current').unlink();(directory/'attr/current').write_text('browser (enforce)')
  self.assertEqual(c.processes()['observed'][0]['source'],'generic-attribute')
 def test_pid_reuse_rejected(self):
  self.process()
  with patch.object(c,'start_time',side_effect=[123,124]):data=c.processes()
  self.assertEqual(data['observed'],[]);self.assertFalse(data['complete'])
 def test_process_bound_and_disappearing_label(self):
  self.process(1);directory=self.process(2);(directory/'attr/apparmor/current').unlink()
  data=c.processes();self.assertFalse(data['complete'])
  with patch.object(c,'MAX_PROCESSES',1):self.assertTrue(c.processes()['truncated'])
 def test_stat_name_parentheses(self):
  self.assertEqual(c.start_time(self.process()),123)

if __name__=='__main__':unittest.main()
