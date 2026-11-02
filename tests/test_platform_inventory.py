import pathlib,sys,tempfile,unittest
from unittest.mock import patch
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]/'policies'))
import platform_inventory as platform
class PlatformTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
  root=pathlib.Path(self.tmp.name);self.pci=root/'pci';self.pci.mkdir();self.tb=root/'tb';self.tb.mkdir()
  self.device=self.pci/'0000:00:14.0';self.device.mkdir()
  for key,value in {'vendor':'0x8086','device':'0x51ed','class':'0x0c0330'}.items():(self.device/key).write_text(value)
 def test_empty_registered_tb_does_not_approve_platform(self):
  result=platform.collect(self.pci,self.tb)
  self.assertTrue(result['observation_complete']);self.assertFalse(result['platform_policy_approved'])
  self.assertFalse(result['pci'][0]['iommu_group_present'])
 def test_missing_bus_and_malformed_attribute_not_clean(self):
  self.assertFalse(platform.collect(self.pci,self.tb/'missing')['observation_complete'])
  (self.device/'vendor').write_text('broken')
  self.assertFalse(platform.collect(self.pci,self.tb)['observation_complete'])
 def test_topology_change_and_unclassified_router(self):
  with patch.object(platform,'pci_sample',side_effect=[([],[]),([{'address':'new'}],[])]):
   self.assertFalse(platform.collect(self.pci,self.tb)['observation_complete'])
  (self.tb/'domain0').mkdir()
  self.assertEqual(platform.collect(self.pci,self.tb)['thunderbolt'],[{'entry':'domain0'}])
if __name__=='__main__':unittest.main()
