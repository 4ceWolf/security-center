import pathlib,sys,unittest
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]/'policies'))
from distress import State, transition, permits_tpm

class DistressTests(unittest.TestCase):
 def setUp(self):self.digest='a'*64;self.normal=State('NORMAL','boot-a',self.digest)
 def step(self,s,event,boot='boot-a',**evidence):
  return transition(s,event,boot_id=boot,policy_digest=self.digest,**evidence)
 def recovery(self):
  s=self.step(self.normal,'trigger')
  s=self.step(s,'boot_observed','boot-b')
  return self.step(s,'owner_recovered','boot-b',manual_unlock=True,owner_authenticated=True,power_only=True)
 def test_full_cycle_requires_subsequent_boot(self):
  s=self.recovery();self.assertFalse(permits_tpm(s))
  s=self.step(s,'normal_reboot_requested','boot-b',owner_authenticated=True)
  self.assertFalse(permits_tpm(s))
  with self.assertRaises(ValueError):self.step(s,'boot_observed','boot-b',restoration_verified=True)
  s=self.step(s,'boot_observed','boot-c',restoration_verified=True)
  self.assertTrue(permits_tpm(s));self.assertEqual(s.policy_digest,self.digest)
 def test_power_loss_at_each_phase_retains_manual(self):
  for phase in ('TRIGGERED','BOOT_REQUIRED','RECOVERY_SESSION','RESTORE_PENDING'):
   s=self.step(State(phase,'boot-a',self.digest),'boot_observed','boot-b')
   self.assertFalse(permits_tpm(s));self.assertEqual(s.phase,'BOOT_REQUIRED')
 def test_each_recovery_condition_required(self):
  required={'manual_unlock':True,'owner_authenticated':True,'power_only':True}
  for key in required:
   evidence=dict(required);evidence[key]=False
   with self.assertRaises(ValueError):self.step(State('BOOT_REQUIRED','boot-a',self.digest),'owner_recovered',**evidence)
  with self.assertRaises(ValueError):self.step(State('BOOT_REQUIRED','boot-a',self.digest),'owner_recovered',manual_unlock=1,owner_authenticated=True,power_only=True)
 def test_policy_conflict_prevents_restore(self):
  s=State('RESTORE_PENDING','boot-a',self.digest)
  out=transition(s,'boot_observed',boot_id='boot-b',policy_digest='b'*64,restoration_verified=True)
  self.assertFalse(permits_tpm(out));self.assertEqual(out.policy_digest,self.digest)
 def test_illegal_events_and_replay_do_not_mutate(self):
  s=State('BOOT_REQUIRED','boot-a',self.digest)
  for event in ('normal_reboot_requested','restore','unknown','shutdown_prepared'):
   with self.assertRaises(ValueError):self.step(s,event)
  self.assertEqual(s.sequence,0);self.assertFalse(permits_tpm(s))
 def test_missing_corrupt_state_denies(self):
  for s in (None,{},State('INVALID','boot-a',self.digest),State('NORMAL','',self.digest),State('NORMAL','boot-a','bad')):
   self.assertFalse(permits_tpm(s))
 def test_retrigger_and_sequence(self):
  s=self.recovery();old=s.sequence
  s=self.step(s,'trigger','boot-b')
  self.assertEqual(s.phase,'TRIGGERED');self.assertEqual(s.sequence,old+1)
  self.assertFalse(permits_tpm(s))

if __name__=='__main__':unittest.main()
