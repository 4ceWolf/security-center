import copy
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'tools'))
import monitor_deployment as deployment
from baseline_migration import digest
from release_binding import release, SCOPE
from monitor_services import UNITS
from monitor_services import validate_snapshot

# Root metadata and service actions are simulated here. Actual protected-file,
# journal and SQLite crash behavior are exercised by their separate fixture tests.
class Tx:
 def __init__(self, directory, current):
  self.fd=os.open(directory,os.O_RDONLY|os.O_DIRECTORY);self.current=current;self.data={};self.record=None
 def _folder(self, token):
  if token!='txn-'+'a'*32:raise ValueError('Unexpected token')
  return os.dup(self.fd)
 def _write(self, folder, name, raw):self.data[name]=raw
 def _read(self, folder, name, limit=1048576):
  if name not in self.data:raise FileNotFoundError(name)
  raw=self.data[name]
  if len(raw)>limit:raise ValueError('oversized')
  return raw
 def _load(self, folder):return copy.deepcopy(self.record)
 def prepare(self, contents, before, sha):
  self.record={'schema':1,'phase':'prepared','reviewed_release_sha':sha,'entries':[]}
  for path,raw in contents.items():
   self.record['entries'].append({'path':path,'before':copy.deepcopy(before[path]),'after':dict(state='present',sha256=digest(raw),uid=0,gid=0,mode=420,size=len(raw),mtime_ns=2)})
  return 'txn-'+'a'*32
 def run(self, token, rollback=False):
  for entry in self.record['entries']:self.current[entry['path']]=copy.deepcopy(entry['before' if rollback else 'after'])
  return self.record

class Services:
 def __init__(self):self.running={UNITS[0]:True,UNITS[1]:False};self.actions=[]
 def states(self):return dict(self.running)
 def stop(self):self.actions.append('stop');self.running={u:False for u in UNITS}
 def reload(self):self.actions.append('reload')
 def restore(self, desired):self.actions.append('restore');self.running=dict(desired)
 def health(self, required, not_before=0):return {'modules':list(deployment.REQUIRED)}

class Trust:
 def __init__(self):self.mode='create';self.initialized=False;self.calls=0;self.fail=False
 def prepare(self):return self.mode
 def initialize(self, seed):
  self.calls+=1
  if self.fail:raise RuntimeError('fixture init failure')
  self.initialized=True
 def verify(self):
  if not self.initialized:raise ValueError('Not initialized')

class DeploymentTests(unittest.TestCase):
 def test_removed_preboot_checks_not_required_but_retained_boot_checks_are(self):
  import datetime
  now=1000
  self.assertNotIn('preboot',deployment.REQUIRED)
  self.assertNotIn('boot_observation',deployment.REQUIRED)
  data={'schema_version':1,'read_only':True,'boot_id':'boot',
        'generated_at':datetime.datetime.fromtimestamp(now,datetime.timezone.utc).isoformat(),
        'history_status':'available','modules':[{'id':name} for name in deployment.REQUIRED]}
  validate_snapshot(data,deployment.REQUIRED,'boot',now)
  data['modules']=[m for m in data['modules'] if m['id']!='tpm']
  with self.assertRaises(ValueError):validate_snapshot(data,deployment.REQUIRED,'boot',now)
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
  root=Path(__file__).resolve().parents[1]
  self.contents={n:(root/n).read_bytes() for n in release.FILES}
  manifest={'schema_version':1,'fim_paths':release.validate(self.contents),'files':[dict(source=n,destination=p,sha256=digest(self.contents[n])) for n,p in release.FILES.items()]}
  self.manifest=json.dumps(manifest).encode()
  self.before={p:dict(state='present',sha256='c'*64,uid=0,gid=0,mode=420,size=3,mtime_ns=1) for p in SCOPE}
  self.current=copy.deepcopy(self.before)
  self.prior=json.dumps(dict(schema_version=1,approved=True,files=self.before)).encode()
  self.tx=Tx(self.temp.name,self.current);self.addCleanup(lambda:os.close(self.tx.fd))
  self.services=Services();self.trust=Trust()
  self.flow=deployment.Deployment(self.tx,self.services,lambda:copy.deepcopy(self.current),self.trust,lambda:self.prior)
 def prepare(self):return self.flow.prepare(self.prior,digest(self.prior),self.manifest,digest(self.manifest),self.contents)
 def test_success_produces_unapproved_exact_candidate_and_preserves_inactive_recorder(self):
  token=self.prepare();result=self.flow.run(token)
  self.assertEqual(result['phase'],'awaiting_baseline_approval');self.assertFalse(result['baseline_approved'])
  self.assertEqual(result['scope_count'],42);self.assertEqual(self.trust.calls,1)
  candidate=self.tx.data['candidate-baseline.json'];self.assertEqual(digest(candidate),result['candidate_sha256'])
  self.assertFalse(json.loads(candidate)['approved']);self.assertFalse(self.services.running[UNITS[1]])
  self.flow.run(token);self.assertEqual(self.trust.calls,1)
 def test_capture_tampering_and_readonly_drift_refused_before_services(self):
  token=self.prepare();self.tx.data['release-0.bytes']+=b'changed'
  with self.assertRaises(ValueError):self.flow.run(token)
  self.assertEqual(self.services.actions,[])
 def test_readonly_drift_blocks_apply(self):
  token=self.prepare();self.current['/etc/miku-boot/zen.cmdline']['mtime_ns']=99
  with self.assertRaises(ValueError):self.flow.run(token)
  self.assertEqual(self.services.actions,[])
 def test_changed_baseline_blocks_resume_and_rollback(self):
  token=self.prepare();self.prior+=b' '
  for rollback in (False,True):
   with self.assertRaises(ValueError):self.flow.run(token,rollback=rollback)
  self.assertEqual(self.services.actions,[])
 def test_initialization_failure_rolls_back_files_and_service_state(self):
  token=self.prepare();self.trust.fail=True;result=self.flow.run(token)
  self.assertEqual(result['phase'],'rolled_back');self.assertEqual(self.current,self.before)
  self.assertNotIn('candidate-baseline.json',self.tx.data)
  self.assertEqual(self.trust.calls,1)
 def test_interrupted_initialization_is_not_silently_retried(self):
  token=self.prepare()
  def crash(phase):
   if phase=='trust_initializing':raise KeyboardInterrupt()
  with self.assertRaises(KeyboardInterrupt):self.flow.run(token,checkpoint=crash)
  self.assertEqual(self.flow.run(token)['phase'],'rolled_back');self.assertEqual(self.trust.calls,0)
 def test_existing_trust_is_verified_and_never_reinitialized(self):
  self.trust.mode='preserve';self.trust.initialized=True
  token=self.prepare();self.flow.run(token);self.assertEqual(self.trust.calls,0)
 def test_preapproval_rollback_restores_files_and_preserves_candidate_database(self):
  token=self.prepare();self.flow.run(token);result=self.flow.run(token,rollback=True)
  self.assertEqual(result['phase'],'rolled_back');self.assertEqual(self.current,self.before)
  self.assertTrue(self.trust.initialized)

if __name__=='__main__':unittest.main()
