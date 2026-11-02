import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools'))
import release_binding as b

class BindingTests(unittest.TestCase):
 def setUp(self):
  self.contents={name:(ROOT/name).read_bytes() for name in b.release.FILES}
  self.manifest={'schema_version':1,'fim_paths':b.release.validate(self.contents),
                 'files':[{'source':s,'destination':d,'sha256':b.digest(self.contents[s])} for s,d in b.release.FILES.items()]}
  self.added={p for p in b.TARGETS if any(p.endswith('/'+n) for n in ('boot_observation.py','boot_observation_status.py','confinement.py','handover.py','telemetry.py','telemetry_worker.py','telemetry_health.py','telemetry_query.py','security-center-telemetry.service','device_gate.py','device_inventory.py','trust_policy.py','trust_store.py','device-trust-helper.py','normal-devices.candidate.json','telemetry-helper.py','telemetry_export.py','telemetry_actions.py','telemetry-controls.js','tpm-unlock-helper.py','unlock-controls.js','usb_policy.py','network_policy.py','usb-controls.js','security-center-apparmor.service'))}
  item=dict(state='present',sha256='a'*64,uid=0,gid=0,mode=0o644,size=1,mtime_ns=1)
  self.before={p:({'state':'missing'} if p in self.added else dict(item)) for p in b.SCOPE}
  self.baseline={'schema_version':1,'approved':True,'files':{p:dict(v) for p,v in self.before.items() if p not in self.added}}
 def bind(self):
  old=json.dumps(self.baseline).encode();new=json.dumps(self.manifest).encode()
  return b.bind(old,b.digest(old),new,b.digest(new),self.contents,self.before)
 def test_exact_binding_keeps_approval_false(self):
  bound=self.bind()
  self.assertEqual(len(bound['scope_additions']),25);self.assertEqual(len(bound['target_contents']),37)
  self.assertFalse(bound['baseline_approval_granted'])
 def test_payload_substitution_rejected(self):
  self.contents['securityd/client.py']+=b'\n# substitution'
  with self.assertRaises(ValueError):self.bind()
 def test_identical_installed_file_is_not_scheduled_for_replacement(self):
  path='/usr/local/lib/security-center/client.py';raw=self.contents['securityd/client.py']
  for item in (self.before[path],self.baseline['files'][path]):item.update(sha256=b.digest(raw),size=len(raw))
  self.assertNotIn(path,self.bind()['writes'])
 def test_destination_and_duplicate_rejected(self):
  original=copy.deepcopy(self.manifest)
  self.manifest['files'][0]['destination']='/etc/shadow'
  with self.assertRaises(ValueError):self.bind()
  self.manifest=original;self.manifest['files'][0]=self.manifest['files'][1]
  with self.assertRaises(ValueError):self.bind()
 def test_installed_drift_rejected(self):
  path=next(iter(self.baseline['files']));self.before[path]['mtime_ns']=2
  with self.assertRaises(ValueError):self.bind()
 def test_private_unchanged_boot_configuration_keeps_approved_permissions(self):
  path='/etc/miku-boot/zen-uki.conf'
  self.before[path]['mode']=0o600;self.baseline['files'][path]['mode']=0o600
  bound=self.bind()
  self.assertNotIn(path,bound['target_contents'])
  self.assertEqual(bound['scope_before'][path]['mode'],0o600)
 def test_preexisting_addition_rejected(self):
  self.before[next(iter(self.added))]=dict(next(iter(self.baseline['files'].values())))
  with self.assertRaises(ValueError):self.bind()
 def test_unapproved_baseline_and_scope_rejected(self):
  self.baseline['approved']=False
  with self.assertRaises(ValueError):self.bind()
  self.baseline['approved']=True;self.manifest['fim_paths'].append('/etc/shadow')
  with self.assertRaises(ValueError):self.bind()
 def test_changed_review_digest_rejected(self):
  old=json.dumps(self.baseline).encode();new=json.dumps(self.manifest).encode()
  with self.assertRaises(ValueError):b.bind(old,'0'*64,new,b.digest(new),self.contents,self.before)
 def test_captured_bytes_remain_verified_after_source_changes(self):
  with tempfile.TemporaryDirectory() as temp:
   folder=Path(temp)
   for name,raw in self.contents.items():
    path=folder/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(raw)
   raw=json.dumps(self.manifest).encode();(folder/'release.json').write_bytes(raw)
   _,captured=b.capture_bundle(folder,b.digest(raw))
   (folder/'securityd/client.py').write_bytes(b'changed after capture')
   self.assertEqual(captured['securityd/client.py'],self.contents['securityd/client.py'])
   with self.assertRaises(ValueError):b.capture_bundle(folder,b.digest(raw))

if __name__=='__main__':unittest.main()
