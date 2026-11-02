import copy,pathlib,sys,unittest
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]/'initramfs'))
from handover import validate
BOOT='11111111-2222-3333-4444-555555555555'
class HandoverTests(unittest.TestCase):
 def setUp(self):
  self.data={'schema_version':1,'boot_id':BOOT,'producer':'security-center-observer-v1','observed_boottime':1,'unlock':{'unlocked':True,'method':'manual','attempts':['manual']},'device_decision':'manual','attested':False}
 def test_observation_not_attestation(self):self.assertFalse(validate(self.data,BOOT,10)['attested'])
 def test_replayed_or_future_records_rejected(self):
  with self.assertRaises(ValueError):validate(self.data,'aaaaaaaa-2222-3333-4444-555555555555',10)
  for value in (-1,100,float('nan'),float('inf'),True):
   data=copy.deepcopy(self.data);data['observed_boottime']=value
   with self.assertRaises(ValueError):validate(data,BOOT,10)
 def test_claim_escalation_and_inconsistent_unlock_rejected(self):
  data=copy.deepcopy(self.data);data['attested']=True
  with self.assertRaises(ValueError):validate(data,BOOT,10)
  for result in ({'unlocked':True,'method':'tpm','attempts':['manual']},{'unlocked':False,'method':'manual','attempts':['manual']},{'unlocked':True,'method':'tpm','attempts':['tpm']}):
   data=copy.deepcopy(self.data);data['unlock']=result
   with self.assertRaises(ValueError):validate(data,BOOT,10)
 def test_tpm_failure_then_manual_is_observed_correctly(self):
  data=copy.deepcopy(self.data);data['device_decision']='allow';data['unlock']['attempts']=['tpm','manual']
  self.assertEqual(validate(data,BOOT,10)['unlock']['method'],'manual')
if __name__=='__main__':unittest.main()
