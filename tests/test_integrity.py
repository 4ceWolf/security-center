import os
import pathlib
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]/'securityd'))
import integrity

class IntegrityTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
  self.path=pathlib.Path(self.tmp.name)/'file';self.path.write_text('original')
 def test_content_and_metadata_changes(self):
  baseline={str(self.path):integrity.inspect(str(self.path))}
  with patch.object(integrity,'PATHS',(str(self.path),)):
   self.assertEqual(integrity.compare(integrity.scan(),baseline),([],[]))
   self.path.write_text('changed')
   self.assertEqual(len(integrity.compare(integrity.scan(),baseline)[0]),1)
   self.path.unlink()
   self.assertEqual(integrity.compare(integrity.scan(),baseline)[0][0]['kind'],'deleted')
 def test_symlinks_in_file_or_ancestor_and_fifo_refused(self):
  self.path.unlink();self.path.symlink_to('/etc/passwd')
  self.assertEqual(integrity.inspect(str(self.path))['state'],'unavailable')
  self.path.unlink();os.mkfifo(self.path)
  self.assertEqual(integrity.inspect(str(self.path))['state'],'unavailable')
  link=pathlib.Path(self.tmp.name)/'link';link.symlink_to('/etc')
  self.assertEqual(integrity.inspect(str(link/'passwd'))['state'],'unavailable')
 def test_size_bound(self):
  with patch.object(integrity,'MAX_BYTES',3):
   self.assertEqual(integrity.inspect(str(self.path))['state'],'unavailable')
 def test_replacement_detected(self):
  original=integrity.open_fixed;calls=[]
  def replaced(path):
   calls.append(path)
   if len(calls)==2:
    self.path.unlink();self.path.write_text('replacement')
   return original(path)
  with patch.object(integrity,'open_fixed',replaced):
   self.assertEqual(integrity.inspect(str(self.path))['state'],'unavailable')
 def test_missing_baseline_does_not_become_green(self):
  with patch.object(integrity,'scan',return_value={}),patch.object(integrity,'load_baseline',side_effect=FileNotFoundError):
   self.assertEqual(integrity.configuration()['status'],'unknown')
 def test_unreadable_is_not_deleted_or_clean(self):
  with patch.object(integrity,'PATHS',('/test',)):
   changes,unknown=integrity.compare({'/test':{'state':'unavailable'}},{'/test':{'state':'present'}})
   self.assertFalse(changes);self.assertEqual(unknown,['/test'])

if __name__=='__main__':unittest.main()
