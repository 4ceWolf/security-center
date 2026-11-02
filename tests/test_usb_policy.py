import copy,json,pathlib,sys,unittest,tempfile
from unittest import mock
ROOT=pathlib.Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'policies'),str(ROOT/'securityd')]
import usb_policy as p

class NativePolicyTests(unittest.TestCase):
 def setUp(self):
  receipt=json.loads((ROOT/'tests/fixtures/usb-native-policy.json').read_text())
  self.state={'policy_sha256':p.INITIAL,'rules':p.parse(receipt['usb_rules']),
              'devices':p.parse(receipt['usb_devices']),'boot_id':'test'}
  self.external=next(item for item in self.state['rules'] if '046d:c542' in item['rule'])
 def test_saved_external_receivers_only_removable(self):
  removable=[r for r in self.state['rules'] if p.external(r['rule'])]
  self.assertEqual(len(removable),2)
  for r in self.state['rules']:
   if r not in removable:
    with self.assertRaises(ValueError):p.propose(self.state,'remove',r['id'])
 def test_exact_remove_preserves_internal_and_block(self):
  review=p.propose(self.state,'remove',self.external['id'],1000)
  self.assertEqual(len(review['after_rules']),len(self.state['rules'])-1)
  self.assertEqual(review['after_rules'][-1],'block')
  p.validate(review,self.state,now=1100)
 def test_add_from_native_observation_only(self):
  sample=copy.deepcopy(next(d for d in self.state['devices'] if p.external(d['rule'])))
  sample['id']=100;sample['rule']=sample['rule'].replace('046d:c542','abcd:1234')
  self.state['devices'].append(sample)
  review=p.propose(self.state,'add',100,1000)
  self.assertIn('hash ',review['rule']);self.assertIn('parent-hash ',review['rule'])
  self.assertIn('via-port ',review['rule']);self.assertIn('with-interface ',review['rule'])
  self.assertEqual(review['after_rules'][-2],review['rule']);self.assertEqual(review['after_rules'][-1],'block')
  sample['rule']=sample['rule'].replace(' hash ', ' missing-hash ')
  with self.assertRaises(ValueError):p.propose(self.state,'add',100)
 def test_keyboard_warning_and_canonical_equals(self):
  a4=next(r for r in self.state['rules'] if '09da:0025' in r['rule'])
  self.assertTrue(p.propose(self.state,'remove',a4['id'])['keyboard'])
  self.assertEqual(p.normalize('allow name "with-interface equals " with-interface equals { 03:01:01 }'),
                   'allow name "with-interface equals " with-interface { 03:01:01 }')
 def test_changed_policy_device_boot_or_proposal_rejected(self):
  review=p.propose(self.state,'remove',self.external['id'],1000)
  for key,value in [('policy_sha256','b'*64),('boot_id','new'),('devices',[])]:
   changed=copy.deepcopy(self.state);changed[key]=value
   with self.assertRaises(ValueError):p.validate(review,changed,now=1050)
  review['rule']='allow'
  with self.assertRaises(ValueError):p.validate(review,self.state,now=1050)
 def test_expired_future_and_command_injection_rejected(self):
  review=p.propose(self.state,'remove',self.external['id'],1000)
  for now in [999,1121]:
   with self.assertRaises(ValueError):p.validate(review,self.state,now=now)
  for key in ['5; id',True,-1]:
   with self.assertRaises(ValueError):p.propose(self.state,'remove',key)
 def test_duplicate_ids_unknown_target_and_bounds_rejected(self):
  for raw in ['1: allow\n1: block\n','1: authorize id abcd:1234','x'*65537]:
   with self.assertRaises(ValueError):p.parse(raw)
 def test_quoted_metadata_cannot_fake_external_attributes(self):
  self.assertFalse(p.external('allow id abcd:1234 name "via-port \\"3-1\\""'))
  self.assertFalse(p.external('allow id abcd:1234 via-port "usb3" with-connect-type ""'))
  self.assertFalse(p.external('allow id abcd:1234 via-port "3-1" with-connect-type "hardwired"'))
 def test_keyboard_like_device_name_is_not_an_interface(self):
  self.assertFalse(p.has_keyboard('allow id abcd:1234 name \"03:01:01\" with-interface 03:01:02'))
 def test_already_trusted_device_refused(self):
  observed=next(d for d in self.state['devices'] if '046d:c542' in d['rule'])
  with self.assertRaises(ValueError):p.propose(self.state,'add',observed['id'])
 def test_failed_integrity_stops_capture_before_native_commands(self):
  with mock.patch.object(p,'check_integrity',return_value={'policy_verified':False}),mock.patch.object(p,'command') as command:
   with self.assertRaises(ValueError):p.capture()
   command.assert_not_called()

class ApplyTests(unittest.TestCase):
 setUp=NativePolicyTests.setUp
 def transaction(self,fail=False,bad_after=False):
  fixture=json.loads((ROOT/'tests/fixtures/usb-native-policy.json').read_text())
  raw=fixture['policy'].encode();commands=[];current=copy.deepcopy(self.state)
  review=p.propose(self.state,'remove',self.external['id'])
  def native(args):
   nonlocal raw
   commands.append(args)
   if args[1]=='remove-rule':
    if fail:raise RuntimeError('IPC disconnected')
    current['rules']=[r for r in current['rules'] if r['id']!=review['selected_id']]
    if bad_after:current['rules'].pop(0)
    raw=('\n'.join(r['rule'] for r in current['rules'])+'\n').encode()
    return ''
   return '\n'.join(str(r['id'])+': '+r['rule'] for r in current['rules'])
  def read(path):return raw if path==p.RULES else b'config'
  with tempfile.TemporaryDirectory(prefix='security-center-usb-test-') as temp:
   state=pathlib.Path(temp)
   with mock.patch.object(p,'STATE',state),mock.patch.object(p,'capture',return_value=copy.deepcopy(self.state)),mock.patch.object(p,'read',side_effect=read),mock.patch.object(p,'command',side_effect=native),mock.patch.object(p,'CONFIG_SHA',p.sha(b'config')):
    if fail or bad_after:
     with self.assertRaises(RuntimeError):p.apply(review)
     reference=json.loads((state/'reference.json').read_text());self.assertEqual(reference['phase'],'pending')
    else:
     result=p.apply(review);self.assertEqual(result['phase'],'committed');self.assertFalse(result['current_devices_changed'])
     self.assertEqual(json.loads((state/'reference.json').read_text())['policy_sha256'],p.sha(raw))
    self.assertTrue(list(state.glob('before-*.json')))
   self.assertEqual(commands[0],['/usr/bin/usbguard','remove-rule',str(self.external['id'])])
   self.assertFalse(any(any(op in cmd for op in ('allow-device','block-device','reject-device')) for cmd in commands))
 def test_persistent_native_removal_journal_and_exact_verification(self):self.transaction()
 def test_native_ipc_failure_leaves_pending_reference(self):self.transaction(fail=True)
 def test_unexpected_mutation_leaves_pending_reference(self):self.transaction(bad_after=True)

if __name__=='__main__':unittest.main()
