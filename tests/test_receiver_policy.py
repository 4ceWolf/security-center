import copy,json,pathlib,sys,unittest
ROOT=pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'policies'))
from device_gate import evaluate
class ReceiverTests(unittest.TestCase):
 def setUp(self):
  self.policy=json.loads((ROOT/'policies/normal-devices.candidate.json').read_text())
  self.receiver=self.policy['trusted_external'][0]
  self.inventory={'schema_version':1,'complete':True,'transports_checked':['usb','thunderbolt','pci-external'],'devices':[self.receiver]}
 def test_receiver_both_interfaces_accepted_normally(self):
  self.assertEqual(self.receiver['interfaces'],['03:01:01','03:01:02'])
  self.assertTrue(evaluate(self.inventory,self.policy)['allow_tpm_attempt'])
 def test_port_or_interface_change_requires_manual(self):
  for field,value in [('port','pci:0000:00:14.0/usb:2'),('interfaces',['03:01:02']),('interfaces',['03:01:01','03:01:02','08:06:50'])]:
   inventory=copy.deepcopy(self.inventory);inventory['devices'][0][field]=value
   self.assertTrue(evaluate(inventory,self.policy)['manual_recovery_required'])
 def test_receiver_not_allowed_during_distress(self):
  result=evaluate(self.inventory,self.policy,'distress')
  self.assertFalse(result['allow_tpm_attempt']);self.assertEqual(result['rejected_indexes'],[0])
if __name__=='__main__':unittest.main()
