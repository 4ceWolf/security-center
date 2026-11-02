import pathlib,sys,unittest
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]/'initramfs'))
from unlock_dispatch import unlock
class DispatchTests(unittest.TestCase):
 def test_malformed_decision_never_calls_tpm(self):
  for value in (None,{}, {'allow_tpm_attempt':1,'manual_recovery_required':False}, {'allow_tpm_attempt':True,'manual_recovery_required':True}):
   calls=[]
   out=unlock(lambda:value,lambda:calls.append('tpm'),lambda:True)
   self.assertFalse(calls);self.assertEqual(out['method'],'manual')
 def test_failed_manual_never_claims_unlock(self):
  out=unlock(lambda:{},lambda:True,lambda:False)
  self.assertFalse(out['unlocked']);self.assertEqual(out['method'],'none')
 def test_timeout_falls_back_but_no_false_success(self):
  def timeout():raise TimeoutError()
  out=unlock(lambda:{'allow_tpm_attempt':True,'manual_recovery_required':False},timeout,timeout)
  self.assertFalse(out['unlocked']);self.assertEqual(out['attempts'],['tpm','manual'])
if __name__=='__main__':unittest.main()
