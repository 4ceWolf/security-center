import copy,pathlib,sys,unittest
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]/'policies'))
from device_gate import evaluate
class DeviceGateTests(unittest.TestCase):
 def setUp(self):
  self.device={'transport':'usb','vendor':'1234','product':'5678','serial':'example','port':'1-2','interfaces':['03:01:01']}
  self.policy={'schema_version':1,'internal':[],'trusted_external':[self.device]}
  self.inventory={'schema_version':1,'complete':True,'transports_checked':['usb','thunderbolt','pci-external'],'devices':[]}
 def test_empty_and_explicit_trusted(self):
  self.assertTrue(evaluate(self.inventory,self.policy)['allow_tpm_attempt'])
  self.inventory['devices']=[self.device]
  self.assertTrue(evaluate(self.inventory,self.policy)['allow_tpm_attempt'])
 def test_identity_changes_do_not_inherit_trust(self):
  for field,value in [('serial','different'),('port','2-1'),('interfaces',['03:01:01','08:06:50']),('product','9999')]:
   changed=copy.deepcopy(self.device);changed[field]=value;self.inventory['devices']=[changed]
   self.assertFalse(evaluate(self.inventory,self.policy)['allow_tpm_attempt'])
 def test_failures_and_unknown_transports_deny(self):
  for field,value in [('complete',False),('transports_checked',['usb']),('devices',[{}]),('devices',None)]:
   inventory=copy.deepcopy(self.inventory);inventory[field]=value
   self.assertTrue(evaluate(inventory,self.policy)['manual_recovery_required'])
 def test_distress_never_allows_tpm(self):
  self.assertFalse(evaluate(self.inventory,self.policy,'distress')['allow_tpm_attempt'])
  self.inventory['devices']=[self.device]
  self.assertEqual(evaluate(self.inventory,self.policy,'distress')['rejected_indexes'],[0])
 def test_duplicates_and_policy_conflict_deny(self):
  self.inventory['devices']=[self.device,self.device]
  self.assertFalse(evaluate(self.inventory,self.policy)['allow_tpm_attempt'])
  self.inventory['devices']=[];self.policy['internal']=[self.device]
  self.assertFalse(evaluate(self.inventory,self.policy)['allow_tpm_attempt'])
if __name__=='__main__': unittest.main()

class LogitechCandidateTests(unittest.TestCase):
    def test_authorized_receiver_exact_match_only(self):
        import json
        import pathlib
        from device_gate import evaluate
        root=pathlib.Path(__file__).resolve().parents[1]
        policy=json.loads((root/'policies/normal-devices.candidate.json').read_text())
        receiver=next(d for d in policy['trusted_external'] if d['vendor']=='046d' and d['product']=='c542')
        inventory={'schema_version':1,'complete':True,'transports_checked':['usb','thunderbolt','pci-external'],'devices':[dict(receiver)]}
        self.assertTrue(evaluate(inventory,policy)['allow_tpm_attempt'])
        self.assertFalse(evaluate(inventory,policy,mode='distress')['allow_tpm_attempt'])
        inventory['devices']=[dict(receiver,port=receiver['port']+'.1')]
        self.assertFalse(evaluate(inventory,policy)['allow_tpm_attempt'])
        inventory['devices']=[dict(receiver,interfaces=receiver['interfaces']+['03:01:01'])]
        self.assertFalse(evaluate(inventory,policy)['allow_tpm_attempt'])
        self.assertTrue(any(d['vendor']=='09da' and d['product']=='0025' for d in policy['trusted_external']))
