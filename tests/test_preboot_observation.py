import pathlib,sys,unittest
from unittest.mock import patch
ROOT=pathlib.Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'securityd'),str(ROOT/'initramfs')]
import collector
class PrebootObservationTests(unittest.TestCase):
 def record(self,method):
  return {'unlock':{'unlocked':method!='none','method':method,'attempts':['manual'] if method!='tpm' else ['tpm']},
          'device_decision':'manual' if method!='tpm' else 'allow','observed_boottime':1,'producer':'security-center-observer-v1'}
 def test_missing_record_not_secure(self):
  with patch.object(collector,'consume_handover',side_effect=FileNotFoundError):data=collector.preboot()
  self.assertEqual(data['status'],'unknown');self.assertFalse(data['details']['record_current_boot'])
 def test_tpm_report_never_attestation(self):
  with patch.object(collector,'consume_handover',return_value=self.record('tpm')) as consume:data=collector.preboot()
  self.assertEqual(consume.call_args.args[0],'/run/security-center-boot')
  self.assertEqual(data['status'],'unknown');self.assertEqual(data['details']['boot_trust'],'Not attested')
  self.assertFalse(data['details']['can_authorize_actions'])
 def test_manual_report_is_distinct(self):
  with patch.object(collector,'consume_handover',return_value=self.record('manual')):data=collector.preboot()
  self.assertIn('Manual recovery',data['summary']);self.assertTrue(data['details']['record_current_boot'])
 def test_invalid_or_stale_attention(self):
  with patch.object(collector,'consume_handover',side_effect=ValueError('private detail')):data=collector.preboot()
  self.assertEqual(data['status'],'attention');self.assertNotIn('private detail',str(data))
 def test_permissions_unavailable(self):
  with patch.object(collector,'consume_handover',side_effect=PermissionError):self.assertEqual(collector.preboot()['status'],'unavailable')
 def test_failed_unlock_not_healthy(self):
  with patch.object(collector,'consume_handover',return_value=self.record('none')):self.assertEqual(collector.preboot()['status'],'attention')
if __name__=='__main__':unittest.main()
