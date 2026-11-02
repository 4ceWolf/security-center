import pathlib
import sys
import unittest
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]/'tools'))
from cold_boot_fixture import build

class ColdFixtureTests(unittest.TestCase):
 def test_host_paths_are_refused_before_any_copy(self):
  calls=[]
  for root in ('/','/etc','/tmp/root','/home/user/Projects/security-center/root'):
   with self.subTest(root=root),self.assertRaises(ValueError):
    build(pathlib.Path(root),'',lambda *a:calls.append(a),lambda *a:calls.append(a),'','observe')
  self.assertEqual(calls,[])

if __name__=='__main__':unittest.main()
