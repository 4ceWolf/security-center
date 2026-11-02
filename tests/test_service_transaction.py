import datetime
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
from protected_files import ProtectedFiles
from protected_transaction import TransactionStore
from service_transaction import ServiceTransaction
from monitor_services import MonitorServices,UNITS,validate_snapshot

class FakeServices:
 def __init__(self):self.running={UNITS[0]:True,UNITS[1]:False};self.fail=False;self.operations=[]
 def states(self):return dict(self.running)
 def stop(self):self.operations.append('stop');self.running={u:False for u in UNITS}
 def reload(self):self.operations.append('reload')
 def restore(self,state):
  self.operations.append('restore')
  if self.fail:self.fail=False;raise RuntimeError('start failure')
  self.running=dict(state)
 def health(self,required,not_before=0):return {'modules':['old']}

class ServiceTransactionTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory(prefix='security-center-protected-');self.addCleanup(self.tmp.cleanup)
  self.root=Path(self.tmp.name);(self.root/'.fixture').write_text('DISPOSABLE SECURITY CENTER TEST\n')
  (self.root/'var/lib').mkdir(parents=True)
  self.path='/usr/local/lib/security-center/collector.py';self.file=self.root/self.path.lstrip('/')
  self.file.parent.mkdir(parents=True);self.file.write_bytes(b'old');self.file.chmod(0o644)
  self.fs=ProtectedFiles.fixture(self.root);self.addCleanup(self.fs.close)
  self.tx=TransactionStore(self.fs);self.addCleanup(self.tx.close)
  self.token=self.tx.prepare({self.path:b'new'},{self.path:self.fs.read(self.path)[0]},'a'*64)
  self.services=FakeServices();self.coordinator=ServiceTransaction(self.tx,self.services);self.coordinator.prepare(self.token)
 def test_success_preserves_disabled_telemetry_and_idempotent_receipt(self):
  self.assertEqual(self.coordinator.run(self.token,['new'])['phase'],'healthy')
  self.assertEqual(self.file.read_bytes(),b'new');self.assertFalse(self.services.running[UNITS[1]])
  operations=list(self.services.operations);self.coordinator.run(self.token,['new'])
  self.assertEqual(operations,self.services.operations)
 def test_start_failure_rolls_back_and_restores_prior_running_state(self):
  self.services.fail=True
  result=self.coordinator.run(self.token,['new'])
  self.assertEqual(result['phase'],'rolled_back');self.assertEqual(result['last_failure'],'RuntimeError')
  self.assertEqual(self.file.read_bytes(),b'old');self.assertTrue(self.services.running[UNITS[0]])
 def test_interruption_after_install_resumes(self):
  def interrupt(phase):
   if phase=='starting':raise KeyboardInterrupt()
  with self.assertRaises(KeyboardInterrupt):self.coordinator.run(self.token,['new'],checkpoint=interrupt)
  self.assertEqual(self.file.read_bytes(),b'new');self.assertFalse(self.services.running[UNITS[0]])
  self.assertEqual(self.coordinator.run(self.token,['new'])['phase'],'healthy')
 def test_interruption_during_rollback_resumes_rollback(self):
  self.coordinator.run(self.token,['new'])
  def interrupt(phase):
   if phase=='restoring_services':raise KeyboardInterrupt()
  with self.assertRaises(KeyboardInterrupt):self.coordinator.run(self.token,['new'],rollback=True,checkpoint=interrupt)
  self.assertEqual(self.file.read_bytes(),b'old')
  self.assertEqual(self.coordinator.run(self.token,['new'])['phase'],'rolled_back')
 def test_saved_service_state_cannot_be_recaptured(self):
  with self.assertRaises(ValueError):self.coordinator.prepare(self.token)

class ServiceAdapterTests(unittest.TestCase):
 def test_unprivileged_mutation_refused_before_command(self):
  def forbidden(*a,**k):self.fail('Must not run a command')
  service=MonitorServices(forbidden)
  with patch('monitor_services.os.geteuid',return_value=1000):
   for call in (service.stop,service.reload,lambda:service.restore({u:False for u in UNITS})):
    with self.assertRaises(PermissionError):call()
 def test_health_rejects_stale_wrong_boot_duplicate_and_missing_modules(self):
  data=dict(schema_version=1,read_only=True,boot_id='boot',generated_at=datetime.datetime.fromtimestamp(100,datetime.timezone.utc).isoformat(),modules=[{'id':'old'}],history_status='available')
  self.assertEqual(validate_snapshot(data,['old'],'boot',110)['modules'],['old'])
  for required,boot,now in [(['absent'],'boot',110),(['old'],'other',110),(['old'],'boot',300)]:
   with self.assertRaises(ValueError):validate_snapshot(data,required,boot,now)
  data['modules']*=2
  with self.assertRaises(ValueError):validate_snapshot(data,['old'],'boot',110)

if __name__=='__main__':unittest.main()
