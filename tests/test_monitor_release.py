import importlib.util,json,pathlib,tempfile,unittest
ROOT=pathlib.Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('release',ROOT/'tools/build-monitor-release.py')
r=importlib.util.module_from_spec(spec);spec.loader.exec_module(r)
class ReleaseTests(unittest.TestCase):
 def setUp(self):
  self.contents={name:(ROOT/name).read_bytes() for name in r.FILES}
 def test_all_dependencies_and_fim_coverage(self):
  self.assertIn('/usr/local/lib/security-center/confinement.py',r.validate(self.contents))
 def test_missing_dependency(self):
  self.contents['securityd/collector.py']+=b'\nimport missing_security_dependency\n'
  with self.assertRaises(ValueError):r.validate(self.contents)
 def test_missing_bundle_member(self):
  del self.contents['securityd/confinement.py']
  with self.assertRaises(ValueError):r.validate(self.contents)
 def test_missing_fim_coverage(self):
  self.contents['securityd/integrity.py']=self.contents['securityd/integrity.py'].replace(b"'/usr/local/lib/security-center/confinement.py',",b'')
  with self.assertRaises(ValueError):r.validate(self.contents)
 def bundle(self):
  temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup)
  root=pathlib.Path(temp.name)
  for name,raw in self.contents.items():
   path=root/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(raw)
  return r.build(root)
 def test_frozen_bundle_verification_and_tamper(self):
  folder=self.bundle();manifest=r.verify(folder)
  self.assertFalse(manifest['deployment_approved']);self.assertFalse(manifest['baseline_approved'])
  (folder/'securityd/confinement.py').write_bytes(b'# changed')
  with self.assertRaises(ValueError):r.verify(folder)
 def test_manifest_cannot_select_new_destination(self):
  folder=self.bundle();path=folder/'release.json';data=json.loads(path.read_text())
  data['files'][0]['destination']='/etc/shadow';path.write_text(json.dumps(data))
  with self.assertRaises(ValueError):r.verify(folder)
 def test_symlink_member_rejected(self):
  folder=self.bundle();member=folder/'securityd/confinement.py'
  member.unlink();member.symlink_to(ROOT/'securityd/confinement.py')
  with self.assertRaises(ValueError):r.verify(folder)
if __name__=='__main__':unittest.main()
