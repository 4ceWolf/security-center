import json,pathlib,sys,tempfile,unittest
from unittest.mock import patch
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]/'securityd'))
import adapters as a
class OpenSnitchTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
  self.root=pathlib.Path(self.tmp.name)
  p=patch.object(a,'OPENSNITCH_RULES',str(self.root));p.start();self.addCleanup(p.stop)
  self.rule={'name':'SECRET_ARGUMENT','description':'SECRET_DESCRIPTION','enabled':True,'precedence':False,'action':'deny',
    'operator':{'type':'regexp','operand':'process.command','data':'SECRET_MATCH'}}
 def write(self,name='rule.json',data=None):
  (self.root/name).write_text(json.dumps(self.rule if data is None else data))
 def test_secrets_never_exported(self):
  self.write('SECRET_FILENAME.json');data=a.opensnitch_inventory()
  self.assertTrue(data['complete']);self.assertNotIn('SECRET',json.dumps(data))
  self.assertEqual(data['rules'][0]['action'],'deny')
 def test_symlink_and_special_file_rejected(self):
  (self.root/'link.json').symlink_to('/etc/passwd')
  (self.root/'directory.json').mkdir()
  self.assertEqual(a.opensnitch_inventory()['unreadable_or_invalid'],2)
 def test_bad_types_and_duplicate_fields(self):
  for raw in (b'{"enabled":true,"enabled":false}',json.dumps(dict(self.rule,enabled='false')).encode(),b'[]'):
   with self.assertRaises(ValueError):a.opensnitch_rule(raw)
 def test_bound_and_malformed(self):
  (self.root/'huge.json').write_bytes(b'x'*65537)
  self.assertFalse(a.opensnitch_inventory()['complete'])
 def test_disabled_rule_counted_without_becoming_active(self):
  self.write(data=dict(self.rule,enabled=False))
  with patch.object(a,'command',return_value='LoadState=loaded\nActiveState=inactive\n'):
   data=a.opensnitch()
  self.assertEqual(data['status'],'attention');self.assertEqual(data['details']['counts']['disabled'],1)
  self.assertFalse(data['details']['policy_verified'])
 def test_absent_skips_inventory(self):
  with patch.object(a,'command',return_value='LoadState=not-found\n'),patch.object(a,'opensnitch_inventory') as scan:
   self.assertEqual(a.opensnitch()['status'],'unknown');scan.assert_not_called()
 def test_active_but_unreadable_reports_unavailable(self):
  with patch.object(a,'command',return_value='LoadState=loaded\nActiveState=active\n'),patch.object(a,'opensnitch_inventory',side_effect=PermissionError):
   self.assertEqual(a.opensnitch()['status'],'unavailable')
 def test_unsupported_operator_not_interpreted(self):
  self.rule['operator']['type']='future-code';self.write()
  self.assertEqual(a.opensnitch_inventory()['rules'][0]['operator_type'],'unknown')
if __name__=='__main__':unittest.main()
