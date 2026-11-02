import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools'))
from protected_files import ProtectedFiles,TARGETS


class ProtectedFileTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory(prefix='security-center-protected-');self.addCleanup(self.tmp.cleanup)
  self.root=Path(self.tmp.name);(self.root/'.fixture').write_text('DISPOSABLE SECURITY CENTER TEST\n')
  self.path='/usr/local/lib/security-center/collector.py';self.file=self.root/self.path.lstrip('/')
  self.file.parent.mkdir(parents=True);self.file.write_bytes(b'old');self.file.chmod(0o644)
  self.fs=ProtectedFiles.fixture(self.root);self.addCleanup(self.fs.close)
 def test_replace_and_restore_preserves_content_mode_mtime(self):
  old,raw=self.fs.read(self.path)
  new=self.fs.replace(self.path,b'new',old)
  self.assertEqual(self.file.read_bytes(),b'new')
  restored=self.fs.replace(self.path,raw,new,mode=old['mode'],mtime_ns=old['mtime_ns'])
  self.assertEqual(restored,old)
 def test_add_and_remove(self):
  self.file.unlink();before,_=self.fs.read(self.path)
  after=self.fs.replace(self.path,b'new',before)
  self.fs.remove_added(self.path,after);self.assertFalse(self.file.exists())
 def test_refuses_later_change_on_write_and_remove(self):
  before,_=self.fs.read(self.path);self.file.write_bytes(b'later change')
  with self.assertRaises(ValueError):self.fs.replace(self.path,b'new',before)
  with self.assertRaises(ValueError):self.fs.remove_added(self.path,before)
  self.assertEqual(self.file.read_bytes(),b'later change')
 def test_race_before_publication_preserves_concurrent_content(self):
  before,_=self.fs.read(self.path)
  def race(stage):
   if stage=='payload_synced':self.file.write_bytes(b'other writer')
  with self.assertRaises(ValueError):self.fs.replace(self.path,b'new',before,checkpoint=race)
  self.assertEqual(self.file.read_bytes(),b'other writer')
  self.assertEqual(list(self.file.parent.glob('.security-center-*')),[])
 def test_symlink_and_hardlink_refused(self):
  self.file.unlink();self.file.symlink_to('/dev/null')
  with self.assertRaises(OSError):self.fs.read(self.path)
  self.file.unlink();self.file.write_bytes(b'old');os.link(self.file,self.file.parent/'other')
  with self.assertRaises(ValueError):self.fs.read(self.path)
 def test_symlink_ancestor_refused(self):
  self.file.parent.rename(self.file.parent.with_name('renamed'))
  self.file.parent.symlink_to(self.file.parent.with_name('renamed'),target_is_directory=True)
  with self.assertRaises(OSError):self.fs.read(self.path)
 def test_group_writable_directory_and_file_refused(self):
  self.file.parent.chmod(0o775)
  with self.assertRaises(ValueError):self.fs.read(self.path)
  self.file.parent.chmod(0o755);self.file.chmod(0o666)
  with self.assertRaises(ValueError):self.fs.read(self.path)
 def test_allowlist_excludes_boot_and_baseline(self):
  for path in ('/etc/miku-boot/zen.cmdline','/var/lib/security-center-monitor/integrity-baseline.json','/usr/local/lib/security-center/../collector.py'):
   with self.assertRaises(ValueError):self.fs.read(path)
 def test_allowlist_exactly_matches_release(self):
  spec=importlib.util.spec_from_file_location('release',ROOT/'tools/build-monitor-release.py')
  mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod)
  self.assertEqual(TARGETS,set(mod.FILES.values()))
 def test_real_child_exit_has_only_old_or_new_complete_file(self):
  runner='''import sys,os
sys.path.insert(0,sys.argv[1])
from protected_files import ProtectedFiles
fs=ProtectedFiles.fixture(sys.argv[2]);path=sys.argv[3];before,_=fs.read(path)
fs.replace(path,b'new',before,checkpoint=lambda stage:os._exit(71) if stage==sys.argv[4] else None)
'''
  for stage,expected in [('payload_synced',b'old'),('published',b'new')]:
   self.file.write_bytes(b'old')
   child=subprocess.run([sys.executable,'-I','-c',runner,str(ROOT/'tools'),str(self.root),self.path,stage],timeout=5)
   self.assertEqual(child.returncode,71);self.assertEqual(self.file.read_bytes(),expected)

 def test_new_trust_seed_directory_is_narrowly_created_and_checked(self):
  (self.root/'etc').mkdir()
  path='/etc/security-center/normal-devices.candidate.json'
  self.assertEqual(self.fs.read(path),({'state':'missing'},None))
  after=self.fs.replace(path,b'{}',{'state':'missing'})
  self.assertEqual(self.fs.read(path)[1],b'{}')
  self.assertEqual((self.root/'etc/security-center').stat().st_mode&0o777,0o755)
  self.fs.remove_added(path,after)
  self.assertTrue((self.root/'etc/security-center').is_dir())
 def test_other_missing_parent_is_not_created(self):
  with self.assertRaises(FileNotFoundError):self.fs.replace('/usr/local/share/cockpit/security_center/app.js',b'new',{'state':'missing'})
  self.assertFalse((self.root/'usr/local/share').exists())

if __name__=='__main__':unittest.main()
