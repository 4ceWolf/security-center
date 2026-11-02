import copy,json,pathlib,sys,unittest
from unittest.mock import patch
ROOT=pathlib.Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT/'securityd'),str(ROOT/'policies')]
import network_policy as p
class NetworkEvidenceTests(unittest.TestCase):
 def setUp(self):
  self.proof={'schema_version':1,'functional_test_passed':True,'scoped_test_program_blocked':True,
   'connectivity_recovered':True,'original_firewall_preserved':True,
   'configuration_sha256':{x:p.EXPECTED[x] for x in (p.CONFIG,p.SYSTEM)},'override_sha256':p.EXPECTED[p.OVERRIDE],
   'test_at_unix':123456,'unused_private_field':'SECRET_NOT_EXPORTED'}
 def verify(self,drift=False):
  def read(path):return json.dumps(self.proof).encode() if path==p.PROOF else path.encode()
  def sha(raw):return 'bad' if drift and raw==p.CONFIG.encode() else p.EXPECTED[raw.decode()]
  with patch.object(p,'read',side_effect=read),patch.object(p,'sha',side_effect=sha):return p.verify()
 def test_saved_test_and_current_configuration_are_separate(self):
  data=self.verify();self.assertTrue(data['configuration_verified']);self.assertTrue(data['saved_functional_test_passed'])
  self.assertFalse(data['unknown_applications_blocked']);self.assertNotIn('SECRET',json.dumps(data))
  data=self.verify(True);self.assertFalse(data['configuration_verified']);self.assertTrue(data['saved_functional_test_passed'])
 def test_failed_or_unrelated_evidence_never_reused(self):
  for field in ('functional_test_passed','scoped_test_program_blocked','connectivity_recovered','original_firewall_preserved'):
   before=copy.deepcopy(self.proof);self.proof[field]=False;self.assertFalse(self.verify()['saved_functional_test_passed']);self.proof=before
  self.proof['configuration_sha256']={};self.assertFalse(self.verify()['saved_functional_test_passed'])
if __name__=='__main__':unittest.main()
