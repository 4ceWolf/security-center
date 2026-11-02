import pathlib
import sys
import unittest
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]/'initramfs'))
from manual_recovery import recover

class ManualTests(unittest.TestCase):
 def test_immediate_success_never_prompts_retry(self):
  out=recover(lambda:True,lambda count:self.fail('Retry on success'))
  self.assertTrue(out['unlocked']);self.assertEqual(out['attempts'],1)
 def test_failed_then_correct(self):
  attempts=iter((False,True));prompts=[]
  out=recover(lambda:next(attempts),lambda count:prompts.append(count) or True)
  self.assertTrue(out['unlocked']);self.assertEqual(out['attempts'],2);self.assertEqual(prompts,[1])
 def test_bounded_exhaustion(self):
  attempts=[];prompts=[]
  out=recover(lambda:attempts.append(1),lambda count:prompts.append(count) or True)
  self.assertFalse(out['unlocked']);self.assertEqual(len(attempts),3);self.assertEqual(prompts,[1,2])
 def test_retry_requires_explicit_true(self):
  for consent in (False,None,1,'yes'):
   out=recover(lambda:False,lambda count:consent)
   self.assertFalse(out['unlocked']);self.assertEqual(out['attempts'],1)
 def test_unexpected_failure_is_not_masked(self):
  def broken():raise RuntimeError('adapter failure')
  with self.assertRaises(RuntimeError):recover(broken,lambda count:True)
 def test_strict_limit_and_success(self):
  for limit in (0,4,True,'3'):
   with self.assertRaises(ValueError):recover(lambda:True,lambda count:True,limit)
  out=recover(lambda:1,lambda count:False)
  self.assertFalse(out['unlocked'])

if __name__=='__main__':unittest.main()
