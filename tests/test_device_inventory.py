import pathlib,sys,tempfile,unittest
from unittest.mock import patch
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]/'policies'))
import device_inventory as inv
from device_gate import identity,evaluate
class InventoryTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
  root=pathlib.Path(self.tmp.name);self.bus=root/'bus';self.bus.mkdir()
  self.device=root/'0000:00:14.0'/'usb3'/'3-1';self.device.mkdir(parents=True)
  (self.bus/'3-1').symlink_to(self.device)
  for name,value in {'devpath':'1','idVendor':'09da','idProduct':'0025','bNumInterfaces':'02'}.items():(self.device/name).write_text(value)
  for i,protocol in enumerate(('01','02')):
   d=self.device/f'3-1:1.{i}';d.mkdir()
   for name,value in {'bInterfaceClass':'03','bInterfaceSubClass':'01','bInterfaceProtocol':protocol}.items():(d/name).write_text(value)
 def test_canonical_receiver_and_incomplete_overall(self):
  data=inv.collect(self.bus)
  self.assertTrue(data['usb_observation_complete']);self.assertFalse(data['complete'])
  self.assertEqual(data['devices'][0]['port'],'pci:0000:00:14.0/usb:1')
  self.assertEqual(data['devices'][0]['serial'],'')
  self.assertFalse(evaluate(data,{'schema_version':1,'internal':[],'trusted_external':data['devices']})['allow_tpm_attempt'])
 def test_missing_interface_and_long_attribute_fail(self):
  (self.device/'bNumInterfaces').write_text('03')
  self.assertFalse(inv.collect(self.bus)['usb_observation_complete'])
  (self.device/'bNumInterfaces').write_text('02');(self.device/'serial').write_text('x'*257)
  self.assertFalse(inv.collect(self.bus)['usb_observation_complete'])
 def test_change_between_samples_and_enumeration_limit(self):
  with patch.object(inv,'sample',side_effect=[([],[]),([{'port':'changed'}],[])]):
   self.assertFalse(inv.collect(self.bus)['usb_observation_complete'])
  with self.assertRaises(ValueError):inv.entries(self.device,1)
 def test_duplicate_interface_classes_preserve_count(self):
  d=inv.observe(self.device);d['interfaces']=['e0:01:01','e0:01:01']
  first=identity(d);d['interfaces'].pop()
  self.assertNotEqual(first,identity(d))
if __name__=='__main__':unittest.main()
