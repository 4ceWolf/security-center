import pathlib,sys,unittest
from unittest.mock import patch
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]/'securityd'))
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]/'policies'))
import usb_policy
import adapters as a
class USBGuardTests(unittest.TestCase):
 def test_receiver_interfaces_kept_as_data(self):
  text='3: allow id 09da:0025 serial "" name "Receiver" with-interface { 03:01:01 03:01:02 }'
  item=a.parse_usbguard_devices(text)[0]
  self.assertEqual(item['authorization'],'allow');self.assertEqual(item['trust'],'Not assessed')
  self.assertIn('03:01:01',item['attributes_text']);self.assertIn('03:01:02',item['attributes_text'])
 def test_active_with_decisions_not_automatically_secure(self):
  with patch.object(a,'command',return_value='LoadState=loaded\nActiveState=active\n'),patch.object(a,'bounded_command',return_value='1: block id 1234:5678 name "phone"') as command,patch.object(usb_policy,'check_integrity',return_value={'policy_verified':True}):
   data=a.usbguard()
  self.assertEqual(command.call_args.args[0],['/usr/bin/usbguard','list-devices'])
  self.assertEqual(data['status'],'unknown');self.assertEqual(data['details']['counts']['block'],1)
 def test_unexpected_native_policy_drift_never_green(self):
  with patch.object(a,'command',return_value='LoadState=loaded\nActiveState=active\n'),patch.object(a,'bounded_command',return_value='1: allow id 1234:5678'),patch.object(usb_policy,'check_integrity',return_value={'policy_verified':False}):
   self.assertEqual(a.usbguard()['status'],'action_required')
 def test_active_access_failure_unavailable(self):
  with patch.object(a,'command',return_value='LoadState=loaded\nActiveState=active\n'),patch.object(a,'bounded_command',side_effect=RuntimeError):
   self.assertEqual(a.usbguard()['status'],'unavailable')
 def test_inactive_never_queries_devices(self):
  with patch.object(a,'command',return_value='LoadState=loaded\nActiveState=inactive\n'),patch.object(a,'bounded_command') as command:
   self.assertEqual(a.usbguard()['status'],'attention');command.assert_not_called()
 def test_invalid_duplicate_and_oversized_rejected(self):
  for text in ('1: match id 1234:5678','1: allow id 1234:5678\n1: block id 1234:5678','9: reject id 1234:5678 '+('x'*8192),'4294967296: allow id 1234:5678'):
   with self.subTest(text=text[:35]),self.assertRaises(ValueError):a.parse_usbguard_devices(text)
 def test_device_enumeration_order_is_stable(self):
  one='1: allow id 1234:5678';two='2: block id abcd:1234'
  self.assertEqual(a.parse_usbguard_devices(one+'\n'+two),a.parse_usbguard_devices(two+'\n'+one))
 def test_empty_is_no_devices_not_enforcement_proof(self):
  self.assertEqual(a.parse_usbguard_devices(''),[])
 def test_markup_and_command_text_is_opaque(self):
  text='1: allow id 1234:5678 name "<script>$(touch unsafe)</script>"'
  self.assertIn('$(touch unsafe)',a.parse_usbguard_devices(text)[0]['attributes_text'])
 def test_command_output_bounded(self):
  with self.assertRaises(ValueError):a.bounded_command([sys.executable,'-c','print("x"*5000)'],limit=100)
 def test_command_timeout(self):
  with self.assertRaises(TimeoutError):a.bounded_command([sys.executable,'-c','import time;time.sleep(10)'],timeout=.05)
 def test_command_success_and_failure(self):
  self.assertEqual(a.bounded_command([sys.executable,'-c','print("ok")']),'ok\n')
  with self.assertRaises(RuntimeError):a.bounded_command([sys.executable,'-c','raise SystemExit(1)'])
if __name__=='__main__':unittest.main()
